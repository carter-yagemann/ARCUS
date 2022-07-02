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

import gc
import logging
import platform

import angr

log = logging.getLogger(name=__name__)


class AnalysisGC(object):
    def __init__(self, simgr):
        self.simgr = simgr

        imp = platform.python_implementation()
        if imp == "PyPy":
            self.reap_predecessors = self.reap_predecessors_pypy
        elif imp == "CPython":
            self.reap_predecessors = self.reap_predecessors_cpython
        else:
            log.warning(
                "Unknown implementation '%s', fallback to CPython management" % imp
            )
            self.reap_predecessors = self.reap_predecessors_cpython

    def enable(self):
        self.tech = self.simgr._techniques[0]
        self.hwm = None
        self.gc_enter_state = gc.isenabled()

        assert hasattr(self.tech, "predecessors")

        return self

    def disable(self):
        if self.gc_enter_state and not gc.isenabled():
            gc.enable()
            log.debug("Re-enabled automatic garbage collection")

    def do_reap(self):
        # drop half the predecessors list
        num_preds = len(self.tech.predecessors)
        cutoff_idx = num_preds // 2
        log.warning("Reaping %d predecessors" % cutoff_idx)
        if cutoff_idx < 1:
            # we're down to 1 predecessor, no more can be dropped
            raise angr.errors.AngrTracerError("Memory limit exceeded, halting")
        self.tech.predecessors = self.tech.predecessors[cutoff_idx:]

        gc.collect()

    def reap_predecessors_cpython(self):
        """Attempt to free up memory by reaping the oldest predecessors."""
        if gc.isenabled():
            gc.disable()
            log.debug("Disabled automatic garbage collection")

        gc_count = gc.get_count()[0]
        log.debug("GC Count: %d" % gc_count)

        if self.hwm is None:
            self.hwm = float(gc_count)

        if gc_count / self.hwm >= 0.95:
            self.do_reap()

    def reap_predecessors_pypy(self):
        """Attempt to free up memory by reaping the oldest predecessors."""
        if gc.isenabled():
            gc.disable()
            log.debug("Disabled automatic garbage collection")

        mem_stats = gc.get_stats()
        mem_usage = mem_stats._s.total_gc_memory
        mem_usage_str = mem_stats.total_gc_memory
        log.debug("Total GC Memory: %s" % mem_usage_str)

        if self.hwm is None:
            self.hwm = float(mem_usage)

        if mem_usage / self.hwm >= 0.95:
            self.do_reap()
