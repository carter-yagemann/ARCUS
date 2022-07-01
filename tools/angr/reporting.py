#!/usr/bin/env python
#
# Copyright 2020 Carter Yagemann
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

from copy import deepcopy
import logging
import json

from angr.sim_state import SimState
from cle.address_translator import AT

log = logging.getLogger(name=__name__)

class BugReport(object):
    """Standardizes bug reports for further analysis, comparison, de-duplication, etc.

    Reports are initialized from the buggy state, yielding a standard set of
    info (e.g., state of stack, type of bug) and can then be augmented with
    additional details.

    Internally, this class maintains a dictionary suitable for being serialized
    into JSON for storage.
    """

    required_fields = ['hash', 'stack', 'registers', 'type', 'plugin',
                       'arch', 'details']

    def __init__(self, state=None, init_dict=None):
        """Initialization

        Keyword Args:
        state -- Initialize from provided state.
        init_dict -- Initialize from provided dictionary. For example, by reading
        a saved bug report using json.dumps().
        """
        if isinstance(init_dict, dict):
            for field in self.required_fields:
                if not field in init_dict:
                    raise ValueError("Missing required field: %s" % field)
            self.report = init_dict
        elif isinstance(state, SimState):
            self.init_from_state(state)
        else:
            raise ValueError("Must provide a state or a dictionary to BugReport")

    def set_type(self, value):
        if not isinstance(value, str):
            raise ValueError("Bug type must be a string")
        self.report['type'] = value

    def set_plugin(self, value):
        if not isinstance(value, str):
            raise ValueError("Plugin must be a string")
        self.report['plugin'] = value

    def set_hash(self, value):
        if not isinstance(value, str):
            raise ValueError("Hash must be a string")
        self.report['hash'] = value

    def get_hash(self):
        return self.report['hash']

    def add_detail(self, key, value):
        """Add detail to report to better describe the bug"""
        self.report['details'][key] = value

    def to_dict(self):
        """Return a dictionary representing this report"""
        return deepcopy(self.report)

    def to_json(self):
        """Return a JSON string representing this report"""
        return json.dumps(self.report)

    def init_from_state(self, state):
        """Parses a state and creates an initial report with some standard info"""
        self.state = state
        self.solver = state.solver
        self.loader = state.project.loader

        # basic info about the bug report
        self.report = {'hash': self.generic_hash(state, self.loader),
                       'stack': list(),
                       'registers': {
                           'ip': [None, 0],
                           'sp': [None, 0],
                           'bp': [None, 0],
                       },
                       'type': 'Unknown',
                       'plugin': None,
                       'arch': state.project.arch.name,
                       'details': dict()}

        # assert that we didn't forget any required fields
        for field in self.required_fields:
            assert field in self.report

        # parse the stack and registers
        self.parse_stack_and_regs(state)

    def generic_hash(self, state, loader):
        """Generate a generic hash for this state.

        A hash can be any string. We simply take the last few addresses
        leading up to the buggy state, filtered and converted to RVAs to
        account for ASLR and simprocs added by angr, and then XOR them
        in a similar way to how AFL hashes paths.

        Plugins can then later replace this hash with something more
        bug specific via the set_hash() method.
        """
        prev_addrs = list()
        for addr in state.history.bbl_addrs.hardcopy[::-1]:
            # only use RVAs for addresses in mapped, non-extern objects,
            # otherwise hashes will not be comparable due to ASLR
            obj = loader.find_object_containing(addr)
            if not obj is None and not obj is loader.extern_object:
                prev_addrs.append(AT.from_va(addr, obj).to_rva())
            if len(prev_addrs) >= 5:
                break

        # create a generic hash by XOR'ing the last few RVAs, shifted,
        # like how AFL hashes code paths
        hash = 0
        for idx, addr in enumerate(prev_addrs):
            hash ^= (addr << idx)
        return '%x' % hash

    def eval_bv(self, bv, solver):
        """Evaluates a bitvector, returning a tuple.

        First element is a boolean: whether the value is symbolic.
        Second element is one possible value, or None if the BV
        cannot be evaluated.
        Third element is a description of the value if it points
        to a mapped object and a loader object is available.
        """
        is_sym = solver.symbolic(bv)
        try:
            bv = solver.eval(bv, cast_to=int)
        except:
            bv = None
        desc = self.describe_addr(bv)
        return (is_sym, bv, desc)

    def describe_addr(self, addr):
        if addr is None:
            return None

        if self.loader and self.loader.find_object_containing(addr):
            return self.loader.describe_addr(addr)
        return None

    def parse_stack_and_regs(self, state, max_words=35):
        """Parse the state's stack (and also some registers).

        Keyword Arguments:
        max_words -- The max number of words to read, starting from stack pointer (SP).
        """
        state = state.copy()  # avoid messing up original stack
        arch = state.project.arch
        reg_load = lambda offset: state.registers.load(offset, size=state.arch.bits // 8)

        self.report['registers']['ip'] = self.eval_bv(reg_load(arch.ip_offset), state.solver)
        self.report['registers']['sp'] = self.eval_bv(reg_load(arch.sp_offset), state.solver)
        self.report['registers']['bp'] = self.eval_bv(reg_load(arch.bp_offset), state.solver)

        for _ in range(max_words):
            self.report['stack'].append(self.eval_bv(state.stack_pop(), state.solver))

    def log_state(self, max_words=10):
        """Prints the state's stack in a human readable format.

        Keyword Arguments:
        max_words -- The max number of stack words to print.
        """
        log.info("  Hash: %s" % self.get_hash())
        # instruction pointer
        is_sym, ip_bv, desc = self.report['registers']['ip']
        if is_sym:  # symbolic
            log.info("  Addr: (Symbolic) %#x" % ip_bv)
        elif desc:  # concrete, mapped
            log.info("  Addr: %#x => %s" % (ip_bv, desc))
        else:       # concrete, unmapped
            log.info("  Addr: %#x" % ip_bv)

        # base pointer
        is_sym, bp_bv, desc = self.report['registers']['bp']
        if is_sym:
            log.info("  RBP: (Symbolic) %#x" % bp_bv)
        else:
            log.info("  RBP: %#x" % bp_bv)

        # stack pointer
        is_sym, sp_bv, desc = self.report['registers']['sp']
        if is_sym:
            log.info("  RBP: (Symbolic) %#x" % sp_bv)
        else:
            log.info("  RBP: %#x" % sp_bv)

        # stack words
        total_words = len(self.report['stack'])
        for is_sym, word, desc in self.report['stack'][:min(total_words, max_words)]:
            if is_sym and not word is None:
                log.info("    (Symbolic) %#x" % word)
            elif is_sym:
                log.info("    (Symbolic) (Unsolvable)")
            elif desc:
                log.info("    %#x => %s" % (word, desc))
            else:
                log.info("    %#x" % word)
