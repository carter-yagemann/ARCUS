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

import os
import re
import subprocess
import tempfile
from threading import Timer, Event

returncode = 0

class PTNotFound(Exception):
    pass

class DisasmError(Exception):
    pass

def find_pt():
    """Searches a couple of places for pt. This search assumes Linux."""
    if os.path.isfile('../pt/pt'):  # This can happen if someone follows the README closely
        return '../pt/pt'
    candidate = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../pt/pt')
    if os.path.isfile(candidate):
        return candidate
    path_dirs = os.environ['PATH'].split(':')
    for path_dir in path_dirs:
        candidate = os.path.join(path_dir, 'pt')
        if os.path.isfile(candidate):
            return candidate
    return '' # Failed to find a match

# Each event has a RE for extracting data and a lambda for encoding it
disasm_events = {
    'block':   (re.compile('^  block: ([0-9a-f]+)'),
                lambda x: int(x[0], 16)),
    'icall':   (re.compile('^  icall: ([0-9a-f]+)'),
                lambda x: int(x[0], 16)),
    'syscall': (re.compile('^  syscall: ([0-9a-f]+)'),
                lambda x: int(x[0], 16)),
    'process': (re.compile('^process: tgid=([0-9]+), cmd=(.*)'),
                lambda x: (int(x[0], 10), x[1])),
    'thread':  (re.compile('^thread: tgid=([0-9]+), pid=([0-9]+)'),
                lambda x: (int(x[0], 10), int(x[1], 10))),
    'image':   (re.compile('^image: tgid=([0-9]+), base=([0-9a-f]+), size=([0-9a-f]+), name=(.*)'),
                lambda x: (int(x[0], 10), int(x[1], 16), int(x[2], 16), x[3])),
    'xpage':   (re.compile('^xpage: tgid=([0-9]+), base=([0-9a-f]+), size=([0-9a-f]+)'),
                lambda x: (int(x[0], 10), int(x[1], 16), int(x[2], 16))),
    'buffer':  (re.compile('^buffer: pid=([0-9]+), size=([0-9a-f]+)'),
                lambda x: (int(x[0], 10), int(x[1], 16))),
}

def _disasm_pt_file_iter(trace_path, event='block', pids=None):
    """Disassembles a PT trace, yielding event info tuples.

    This should not be called directly, use disasm_pt_file() instead.

    Raises PTNotFound if pt cannot be located and DisasmError if something goes wrong.

    Yields event info tuples.
    """
    global returncode

    if not event in disasm_events:
        raise DisasmError("Unknown event type: %s" % event)
    event_regex, event_encoder = disasm_events[event]
    pid_regex, pid_encoder = disasm_events['thread']

    # Input validation
    if isinstance(pids, int):
        pids = [pids]
    if not pids is None and not isinstance(pids, list):
        raise DisasmError("Expected pids to be None, int, or list of ints")

    pt_path = find_pt()
    if pt_path == '':
        raise PTNotFound("Cannot find pt")

    if not os.path.isfile(trace_path):
        raise DisasmError("Trace filepath does not exist or is not a file: %s" % trace_path)

    # Use pt to disasmble
    command = [pt_path, trace_path]

    pt = subprocess.Popen(command, stdout=subprocess.PIPE, bufsize=1)

    curr_pid = -1
    for line in pt.stdout:
        # Update current PID if trace switched
        res = pid_regex.match(line.decode())
        if res:
            curr_pid = pid_encoder(res.groups())[1]

        if not pids is None and not curr_pid in pids:
            continue  # PID filter

        res = event_regex.match(line.decode())
        if res:
            yield event_encoder(res.groups())

    pt.wait()
    returncode = pt.returncode

def disasm_pt_file(trace_path, event='block', pids=None):
    """Disassembles a PT trace, returning a list of events.

    By default, block events are yielded. See disasm_events for other possible events.
    For events that contain multiple values (e.g. xpage), the resulting list will contain
    tuples. Values are automatically encoded into sane representations. For example, numbers
    will be ints, not strs.

    By default, events for all PIDs are returned. Passing an int or list of ints as pids will
    filter inclusively.

    Raises PTNotFound if pt cannot be located and DisasmError if something goes wrong.

    Returns a list of event values.
    """
    return [bb for bb in _disasm_pt_file_iter(trace_path, event, pids)]
