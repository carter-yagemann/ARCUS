#!/usr/bin/env python
#
# Copyright 2021 Carter Yagemann
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

import gzip
import os
import re
import shutil
import subprocess
import sys
import tempfile

BRANCH_MNEMONICS = {
    "jb",
    "jbe",
    "jl",
    "jle",
    "jmp",
    "jmpq",
    "jnb",
    "jnbe",
    "jnl",
    "jnle",
    "jns",
    "jnz",
    "jo",
    "jp",
    "js",
    "jz",
    "bnd jmp",
    "loop",
    "jno",
    "jnp",
    "jnae",
    "jc",
    "jae",
    "jnc",
    "jna",
    "ja",
    "jnge",
    "jge",
    "jng",
    "jg",
    "jpe",
    "jpo",
    "jcxz",
    "jecxz",
}

CALL_MNEMONICS = {"callq", "bnd callq"}

RET_MNEMONICS = {"retq", "bnd retq"}

SYSCALL_MNEMONICS = {"syscall", "sysenter"}

# change of flow
COF_MNEMONICS = BRANCH_MNEMONICS | CALL_MNEMONICS | SYSCALL_MNEMONICS | RET_MNEMONICS

PTXED = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), "../pt/build/bin/ptxed"
)
IPT_SCRIPTS = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), "../pt/libipt/script"
)
AUX_REGEX = re.compile("perf.data-aux-idx(?P<idx>[0-9]+).bin")


class DisasmError(Exception):
    pass


class Disasm(object):

    CONTEXT_REGEX = re.compile("\[context: pid-(?P<pid>[0-9a-f]+)\]")
    ADDR_REGEX = re.compile(
        "(?P<time>[0-9a-f]+)  (?P<addr>[0-9a-f]+)  (?P<mnemonic>[a-z ]+)"
    )

    def __init__(self, perf_fp, aux_fp, sideband_fp, vdso_fp=None):
        """A class for managing ptxed as it disassembles a perf PT trace.

        Keyword Arguments:
        perf_fp -- Filepath to perf.data file.
        aux_fp -- Filepath to Perf aux file.
        sideband_fp -- Filepath to Perf sideband file.
        vdso_fp -- Filepath to vDSO file.

        Raises:
        AssertError if filepaths do not exist.
        subprocess.CalledProcessError if opts cannot be extracted from sideband.
        """
        assert os.path.isfile(perf_fp)
        assert os.path.isfile(aux_fp)
        assert os.path.isfile(sideband_fp)

        # libipt getopts script
        ipt_getopts = os.path.join(IPT_SCRIPTS, "perf-get-opts.bash")
        assert os.path.isfile(ipt_getopts)

        self.perf = perf_fp
        self.aux = aux_fp
        self.sideband = sideband_fp

        # get opts
        self.opts = (
            subprocess.run(
                ["/bin/bash", ipt_getopts, "-m", os.path.basename(self.sideband)],
                capture_output=True,
                check=True,
            )
            .stdout.decode("ascii")
            .split(" ")[1:]
        )

        # start disassembly
        cmd = [PTXED, "--att", "--time", "--sb:switch"]
        if not vdso_fp is None:
            cmd += ["--pevent:vdso-x64", vdso_fp]
        cmd += self.opts
        cmd += ["--event:tick", "--pt", self.aux]

        self.ptxed = subprocess.Popen(
            cmd, bufsize=-1, stdout=subprocess.PIPE, universal_newlines=True
        )

        self.stdout = self.ptxed.stdout
        self.new_block = False
        self.next_event()

    def next_event(self):
        while True:
            line = self.stdout.readline()

            if len(line) < 1:
                # disassembly is done
                self.pid = None
                self.time = None
                self.addr = None
                return

            res = self.CONTEXT_REGEX.match(line)
            if res:
                self.pid = int(res.group("pid"), 16)
                continue

            res = self.ADDR_REGEX.match(line)
            if res:
                # update time and location
                self.time = int(res.group("time"), 16)
                self.addr = int(res.group("addr"), 16)

                # is this the start of a new block?
                curr_new_block = self.new_block

                # will the next instruction be the start of a new block?
                mnemonic = res.group("mnemonic").rstrip()
                if mnemonic in COF_MNEMONICS:
                    self.new_block = True
                else:
                    self.new_block = False

                if curr_new_block:
                    return

            elif "error" in line:
                # print error message
                sys.stderr.write(line)


def dump_vdso(output_fp):
    """Dump the system's current vDSO to output_fp."""
    # it's the same across all processes, so we can just dump our own, starting
    # by finding where it's mapped in memory
    start_addr = None

    with open("/proc/self/maps", "r") as ifile:
        for line in ifile:
            if "[vdso]" in line:
                tokens = line.split(" ", 1)[0].split("-")
                start_addr = int(tokens[0], 16)
                end_addr = int(tokens[1], 16)
                size = end_addr - start_addr
                break

    if start_addr is None:
        return

    mem = open("/proc/self/mem", "rb")
    mem.seek(start_addr)
    with open(output_fp, "wb") as ofile:
        ofile.write(mem.read(size))


def disasm_perf(perf_fp, output_fp):
    """Disassemble a perf.data file into per-thread basic block sequences.

    Keyword Arguments:
    perf_fp -- Filepath to the perf.data file.
    output_fp -- Filepath to write the decoded trace into.

    Raises:
    AssertionError if necessary scripts, programs, inputs, or outputs are missing or invalid.
    DisasmError if disassembly fails.
    """
    assert os.path.isfile(perf_fp)
    perf_fp = os.path.realpath(perf_fp)
    assert not os.path.exists(output_fp)
    output_fp = os.path.realpath(output_fp)

    # libipt aux extraction script
    ipt_aux = os.path.join(IPT_SCRIPTS, "perf-read-aux.bash")
    assert os.path.isfile(ipt_aux)

    # libipt sideband extraction script
    ipt_sideband = os.path.join(IPT_SCRIPTS, "perf-read-sideband.bash")
    assert os.path.isfile(ipt_sideband)

    temp = tempfile.mkdtemp(prefix="aperf-")
    old_cwd = os.getcwd()
    os.chdir(temp)

    # we need to symlink perf.data into the temp directory because some of the
    # libipt scripts don't work correctly if perf.data isn't in the CWD
    os.symlink(perf_fp, "perf.data")

    # Setup for ptxed
    #   1) extract per-core perf aux data (the PT trace data)
    ret = subprocess.run(["/bin/bash", ipt_aux])
    if ret.returncode != 0:
        shutil.rmtree(temp)
        os.chdir(old_cwd)
        raise DisasmError("Failed to extract aux data")
    #   2) extract per-core sideband data
    ret = subprocess.run(["/bin/bash", ipt_sideband])
    if ret.returncode != 0:
        shutil.rmtree(temp)
        os.chdir(old_cwd)
        raise DisasmError("Failed to extract sideband data")
    #   3) dump vDSO
    vdso_fp = os.path.join(temp, "vdso")
    dump_vdso(vdso_fp)

    # disassemble each core's trace
    workers = list()
    for entry in os.listdir("."):
        res = AUX_REGEX.match(entry)
        if res:
            idx = res.group("idx")
            sideband = "perf.data-sideband-cpu%s.pevent" % idx
            if os.path.isfile(sideband):
                workers.append(Disasm("perf.data", entry, sideband, vdso_fp))

    with gzip.open(output_fp, "wt") as ofile:
        curr_pid = None
        while True:
            # prune finished workers
            done = [w for w in workers if w.time is None]
            for w in done:
                workers.remove(w)
            if len(workers) < 1:
                break

            # determine which core has the next event
            timestamps = sorted(
                list(enumerate([w.time for w in workers])), key=lambda w: w[1]
            )
            # record next event
            next_worker = workers[timestamps[0][0]]
            if next_worker.pid != curr_pid:
                # we've switched PIDs
                ofile.write("[pid: %d]\n" % next_worker.pid)
                curr_pid = next_worker.pid
            ofile.write("%x\n" % next_worker.addr)
            # advance worker
            next_worker.next_event()

    # cleanup
    shutil.rmtree(temp)
    os.chdir(old_cwd)


def get_pid_list(trace_fp):
    """Given a filepath to an output trace from disasm_perf, return
    a list of PIDs it contains."""
    pids = set()
    with gzip.open(trace_fp, "rt") as ifile:
        for line in ifile:
            if line.startswith("[pid:"):
                pids.add(int(line[6:-2]))
    return list(pids)


def get_bbs_for_pid(trace_fp, pid):
    """Return the basic block trace for PID."""
    trace = list()
    curr_pid = None
    with gzip.open(trace_fp, "rt") as ifile:
        for line in ifile:
            if line.startswith("[pid:"):
                curr_pid = int(line[6:-2])
            else:
                addr = int(line, 16)
                if curr_pid == pid:
                    trace.append(addr)
    return trace


if __name__ == "__main__":

    if len(sys.argv) != 3:
        print("Usage: perf.py <perf.data> <output_file>")
        sys.exit(1)

    disasm_perf(sys.argv[1], sys.argv[2])
