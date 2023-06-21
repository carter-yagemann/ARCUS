#!/usr/bin/env python
#
# Copyright 2019 Carter Yagemann
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import json
import logging
from optparse import OptionParser, OptionGroup
import os
import shutil
import sys
import tempfile
import traceback

import capstone
import keystone
import lief

PROGRAM_VERSION = "%prog 1.0.0"
PROGRAM_USAGE = "Usage: %prog <path_to_binary> <hook_json>"

log = logging.getLogger("rewriter")


class Transformer(object):
    record_ptwrite_64 = """
void record() {
    // input:    rax - value to encode
    // clobbers: none
    asm("ptwrite %rax");
}

"""

    record_ptwrite_32 = """
void record() {
    // input:    rax - value to encode
    // clobbers: none
    asm("ptwrite %eax");
}

"""

    record_compat_64 = """
void record() {
    // input:    rax - value to encode
    // clobbers: rbx, rcx, rdx
    asm("push %rbx");
    asm("push %rcx");
    asm("push %rdx");
    // store address of return block
    // it's immediately after this function
    asm("call record_next");
    asm("record_next:");
    asm("pop %rdx");
    asm("add $44, %rdx");
    // encode value
    asm("mov $64, %rcx");
    asm("record_loop:");
        asm("mov %rax, %rbx");
        asm("sub $16, %rcx");
        asm("shr %cl, %rbx");
        // add 1 because loopne will subtract 1
        asm("add $1, %rcx");
        asm("and $0xffff, %rbx");
        asm("add %rdx, %rbx");
        asm("call *%rbx");
        asm("loopne record_loop");
    asm("pop %rdx");
    asm("pop %rcx");
    asm("pop %rbx");
}

"""

    record_compat_32 = """
void record() {
    // input:    eax - value to encode
    // clobbers: ebx, ecx, edx
    asm("push %ebx");
    asm("push %ecx");
    asm("push %edx");
    // store address of return block
    // it's immediately after this function
    asm("call record_next");
    asm("record_next:");
    asm("pop %edx");
    asm("add $44, %edx");
    // encode value
    asm("mov $32, %ecx");
    asm("record_loop:");
        asm("mov %eax, %ebx");
        asm("sub $16, %ecx");
        asm("shr %cl, %ebx");
        // add 1 because loopne will subtract 1
        asm("add $1, %ecx");
        asm("and $0xffff, %ebx");
        asm("add %edx, %ebx");
        asm("call *%ebx");
        asm("loopne record_loop");
    asm("pop %edx");
    asm("pop %ecx");
    asm("pop %ebx");
}

"""

    def __init__(self, bin_path, ptwrite=False):
        """Initialize a transformer, which is used to place hooks.

        Keyword Args:
        bin_path - Path to binary to rewrite.
        ptwrite - Whether to use PTWRITE version of the record function
        """
        self.elf = lief.parse(bin_path)
        self.bin_path = bin_path
        self.hooks = dict()
        self.jmp_size = 5
        self.hook_section_size = 128
        self.ptwrite = ptwrite

        self.arch = self.elf.header.machine_type
        if self.arch == lief.ELF.ARCH.x86_64:
            self.capstone = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            self.keystone = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
            self.word_size = 8
            if ptwrite:
                self.record_function = self.record_ptwrite_64
            else:
                self.record_function = self.record_compat_64
        elif self.arch == lief.ELF.ARCH.i386:
            self.capstone = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            self.keystone = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
            self.work_size = 4
            if ptwrite:
                self.record_function = self.record_ptwrite_32
            else:
                self.record_function = self.record_compat_32
        else:
            raise AttributeError("Transformer does not support %s" % str(arch))

        # we use AT&T syntax for easier comparison with tools like objdump
        self.capstone.syntax = capstone.CS_OPT_SYNTAX_ATT
        self.keystone.syntax = keystone.KS_OPT_SYNTAX_ATT

    def add_hook(self, addr, src):
        """Hook an address.

        Keyword Args:
        addr - The address to hook.
        src - What to record. Can be register name (e.g. 'rax') or memory address).
        """
        if isinstance(src, int):
            log.info(
                "Adding hook at %#x to capture the value stored at %#x" % (addr, src)
            )
        else:
            log.info("Adding hook at %#x to capture the value in %s" % (addr, src))

        # figure out how many instructions to overwrite for trampoline
        raw_ints = self.elf.get_content_from_virtual_address(addr, 32)
        raw_bytes = bytes(raw_ints)
        trampoline_size = 0
        for address, size, mnemonic, op_str in self.capstone.disasm_lite(
            raw_bytes, addr
        ):
            trampoline_size += size
            if trampoline_size >= self.jmp_size:
                break
        log.debug("Trampoline size: %d" % trampoline_size)

        # section may move during rewrite, record address as section base + offset
        section = self.elf.section_from_virtual_address(addr)
        offset = addr - section.virtual_address
        log.debug("Original section base VA: %#x" % section.virtual_address)
        log.debug("Original hook offset: %#x" % offset)
        # if src is a memory location, we also need its section base + offset
        if isinstance(src, int):
            src_sec = self.elf.section_from_virtual_address(src)
            src_off = src - src_sec.virtual_address
            src_sec_name = src_sec.name
        else:
            src_sec_name = None
            src_off = None

        self.hooks[addr] = {
            "src": src,
            "orig_code": raw_ints[:trampoline_size],
            "trampoline_size": trampoline_size,
            "idx": None,
            "section": section.name,
            "offset": offset,
            "src_sec": src_sec_name,
            "src_off": src_off,
        }

    def compile(self, new_bin):
        """Compile all the hooks and write a new binary.

        Keyword Args:
        new_bin - Path that the new binary should be written to.
        """
        log.info("Compiling %d hook(s)" % len(self.hooks))
        tempdir = tempfile.mkdtemp(prefix="rewriter-")

        try:
            # create new segment for placing hooks
            hooks_c_file = os.path.join(tempdir, "hooks.c")
            hooks_so_file = os.path.join(tempdir, "hooks.so")
            with open(hooks_c_file, "w") as cfile:
                # first we create a record function
                cfile.write(self.record_function)
                if not self.ptwrite:
                    log.info("Inserting return block for record function")
                    # the compat record needs a 2^16 ret block
                    cfile.write("__attribute__((noreturn)) void ret_block() {\n")
                    for _ in range(2**16):
                        cfile.write('    asm("ret");\n')
                    cfile.write("__builtin_unreachable();\n}\n")
                # then we create a big sequence of nops that'll be overwritten later
                cfile.write("__attribute__((noreturn)) void hook() {\n")
                for _ in range(self.hook_section_size):
                    cfile.write('    asm("nop");\n')
                cfile.write("__builtin_unreachable();\n}\n")

            # compile and insert hooks
            ret = os.WEXITSTATUS(
                os.system(
                    'gcc -Os -nostdlib -nodefaultlibs -fPIC -Wl,-shared "%s" -o "%s"'
                    % (hooks_c_file, hooks_so_file)
                )
            )
            if ret != 0:
                raise Exception("GCC exited with status %d" % ret)
            hook_so = lief.parse(hooks_so_file)
            hooks_so_section = hook_so.get_section(".text")
            for segment in hooks_so_section.segments:
                log.debug(
                    "Adding segment to be loaded at VA %#x"
                    % self.elf.next_virtual_address
                )
                self.elf.add(segment, self.elf.next_virtual_address)
            hooks_elf_section = self.elf.add(hooks_so_section)
            hooks_elf_section.name = ".hooks"

            # locate where record() and hook() were placed
            record_sym = hook_so.get_symbol("record")
            record_addr = (
                record_sym.value
                - hooks_so_section.virtual_address
                + hooks_elf_section.virtual_address
            )
            log.debug("record() function VA: %#x" % record_addr)
            hook_sym = hook_so.get_symbol("hook")
            hook_section_addr = (
                hook_sym.value
                - hooks_so_section.virtual_address
                + hooks_elf_section.virtual_address
            )
            log.debug("start of hook() functions: %#x" % hook_section_addr)

            total_hook_bytes = 0
            for addr in self.hooks:
                hook_bytes = list()

                # sections may have been relocated when hooks.so was added so addr may be stale
                section_va = self.elf.get_section(
                    self.hooks[addr]["section"]
                ).virtual_address
                new_addr = section_va + self.hooks[addr]["offset"]
                log.debug("Address to hook after adding new sections: %#x" % new_addr)

                # locate added hook using the original share object's symbol
                new_hook_addr = hook_section_addr + total_hook_bytes
                log.debug("Placing hook code at %#x" % new_hook_addr)

                # write trampoline
                jmp_target = new_hook_addr - new_addr
                trampoline, _ = self.keystone.asm(b"jmp %#x" % (jmp_target))
                # if jump instruction is somehow not the size we expected, something went wrong
                if len(trampoline) != self.jmp_size:
                    raise Exception(
                        "Unsupported trampoline instruction size: %d" % len(trampoline)
                    )
                # pad remaining bytes with nops
                nop, _ = self.keystone.asm(b"nop")
                # we're going to pad assuming a nop is 1 byte, so if it's not, something went wrong
                if len(nop) != 1:
                    raise Exception(
                        "Expected nop to be 1 byte, instead it's %d" % len(nop)
                    )
                trampoline += nop * (
                    self.hooks[addr]["trampoline_size"] - len(trampoline)
                )
                self.elf.patch_address(new_addr, trampoline)

                # if the code being moved to the hook contains operands with displacements, we need to fix them
                self.capstone.detail = True
                instrs = [
                    instr
                    for instr in self.capstone.disasm(
                        bytes(self.hooks[addr]["orig_code"]), addr
                    )
                ]
                insn_offset = 0
                new_instrs = list()
                for insn in instrs:
                    new_asm = insn.mnemonic + " " + insn.op_str
                    for op in insn.operands:
                        if (
                            op.type == capstone.x86.X86_OP_MEM
                            and op.value.mem.disp != 0
                        ):
                            log.debug("Fixing displacement in: %s" % new_asm)
                            new_disp = op.value.mem.disp + (
                                new_addr - new_hook_addr + insn_offset
                            )
                            new_asm = new_asm.replace(
                                "%#x" % op.value.mem.disp, "%#x" % new_disp
                            )
                            log.debug("Fixed to:               %s" % new_asm)
                    new_instrs.append(new_asm)
                    insn_offset += insn.size
                self.capstone.detail = False

                # assemble fixed code
                fixed_orig_code, num_insn = self.keystone.asm("; ".join(new_instrs))
                if num_insn != len(new_instrs):
                    raise Exception(
                        "Keystone only assembled %d out of %d instructions"
                        % (num_insn, len(new_instrs))
                    )
                hook_bytes += fixed_orig_code

                # assemble call to record()
                # if src is a str, we assume it's a register, otherwise it's a memory address
                hook_src = self.hooks[addr]["src"]
                if isinstance(hook_src, str):
                    if self.arch == lief.ELF.ARCH.x86_64:
                        # preamble to calling record()
                        hook_bytes += self.keystone.asm(
                            "push %%rax; mov %%%s,%%rax" % hook_src
                        )[0]
                        # the actual call and postamble
                        call_target = record_addr - (new_hook_addr + len(hook_bytes))
                        hook_bytes += self.keystone.asm(
                            "call %#x; pop %%rax" % call_target
                        )[0]
                    else:
                        # preamble to calling record()
                        hook_bytes += self.keystone.asm(
                            "push %%eax; mov %%%s,%%eax" % hook_src
                        )[0]
                        # the actual call and postamble
                        call_target = record_addr - (new_hook_addr + len(hook_bytes))
                        hook_bytes += self.keystone.asm(
                            "call %#x; pop %%eax" % call_target
                        )[0]
                else:
                    if self.arch == lief.ELF.ARCH.x86_64:
                        # hook_src may be stale too
                        src_sec_va = self.elf.get_section(
                            self.hooks[addr]["src_sec"]
                        ).virtual_address
                        new_hook_src = src_sec_va + self.hooks[addr]["src_off"]
                        # preamble to calling record()
                        hook_bytes += self.keystone.asm("push %rax")[0]
                        # subtract 7 to account for instruction length
                        mov_target = (
                            new_hook_src - (new_hook_addr + len(hook_bytes)) - 7
                        )
                        hook_bytes += self.keystone.asm(
                            "lea %#x(%%rip),%%rax" % mov_target
                        )[0]
                        # the actual call and postamble
                        call_target = record_addr - (new_hook_addr + len(hook_bytes))
                        hook_bytes += self.keystone.asm(
                            "call %#x; pop %%rax" % call_target
                        )[0]
                    else:
                        # hook_src may be stale too
                        src_sec_va = self.elf.get_section(
                            self.hooks[addr]["src_sec"]
                        ).virtual_address
                        new_hook_src = src_sec_va + self.hooks[addr]["src_off"]
                        # preamble to calling record()
                        hook_bytes += self.keystone.asm("push %eax")[0]
                        # subtract 7 to account for instruction length
                        mov_target = (
                            new_hook_src - (new_hook_addr + len(hook_bytes)) - 7
                        )
                        hook_bytes += self.keystone.asm(
                            "lea %#x(%%eip),%%eax" % mov_target
                        )[0]
                        # the actual call and postamble
                        call_target = record_addr - (new_hook_addr + len(hook_bytes))
                        hook_bytes += self.keystone.asm(
                            "call %#x; pop %%eax" % call_target
                        )[0]

                # assemble jump at end of hook to resume normal execution
                jmp_back_site = new_hook_addr + len(hook_bytes)
                jmp_back_target = (
                    new_addr + self.hooks[addr]["trampoline_size"] - jmp_back_site
                )
                jmp_back, _ = self.keystone.asm(b"jmp %#x" % (jmp_back_target))
                hook_bytes += jmp_back

                # write newly assembled hook
                if (total_hook_bytes + len(hook_bytes)) > self.hook_section_size:
                    raise Exception("Hook section's size exceeded")
                self.elf.patch_address(new_hook_addr, hook_bytes)
                total_hook_bytes += len(hook_bytes)

                log.info("New executable written to %s" % new_bin)

        except Exception as ex:
            log.error("Failed to compile new binary: %s" % str(ex))
            log.error("Stack Trace:\n%s" % traceback.format_exc())
        finally:
            shutil.rmtree(tempdir, ignore_errors=True)

        # write new binary and give it the same permissions as the original
        self.elf.write(new_bin)
        os.chmod(new_bin, os.stat(self.bin_path).st_mode)


def parse_args():
    """Parses sys.argv."""
    parser = OptionParser(usage=PROGRAM_USAGE, version=PROGRAM_VERSION)
    parser.add_option(
        "-l", "--log", action="store", type=int, default=20, help="Set log level"
    )
    parser.add_option(
        "-p",
        "--ptwrite",
        action="store_true",
        default=False,
        help="Record using PTWRITE instruction instead of jump encoding",
    )
    options, args = parser.parse_args()
    if len(args) != 2:
        parser.usage()
        sys.exit(1)
    return (options, args)


def main():
    """The main method."""
    options, args = parse_args()
    bin_path = args[0]
    hooks_json = args[1]

    # initialize logging
    log.setLevel(options.log)
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)-15s [%(levelname)s][%(name)s] %(message)s")
    )
    log.addHandler(handler)

    # load provided JSON file
    try:
        with open(hooks_json, "r") as ifile:
            hooks_dict = json.load(ifile)
    except Exception as ex:
        log.error("Failed to parse %s: %s" % (hooks_json, str(ex)))
        sys.exit(2)
    if not "hooks" in hooks_dict or not isinstance(hooks_dict["hooks"], list):
        log.error("Hooks JSON doesn't have the expected format")
        sys.exit(2)

    # add hooks and compile new binary
    transformer = Transformer(bin_path, options.ptwrite)
    for hook in hooks_dict["hooks"]:
        if not isinstance(hook, dict) or not "addr" in hook or not "src" in hook:
            log.warning("Hook doesn't have expected format, skipping: %s" % str(hook))
            continue
        transformer.add_hook(hook["addr"], hook["src"])
    transformer.compile(bin_path + ".new")


if __name__ == "__main__":
    main()
