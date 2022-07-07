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

import gzip
import os
import tempfile

from construct import Int32ul, Int64ul, CString, Bytes
from construct.core import Struct, Const, Peek, StreamError
import pefile

MAGIC = 0x51C0FFEE

SUPPORTED_VERSIONS = [1]

pt_logfile_header = Struct(
    "magic" / Const(MAGIC, Int32ul),
    "version" / Int32ul,
)

pt_logitem_header = Struct(
    "kind" / Int32ul,
    "size" / Int32ul,
)

pt_logitem_buffer = Struct(
    "header" / pt_logitem_header,
    "tgid" / Int64ul,
    "pid" / Int64ul,
    "sequence" / Int64ul,
    "size" / Int64ul,
    "buffer" / Bytes(lambda this: this.size),
)

pt_logitem_process = Struct(
    "header" / pt_logitem_header,
    "tgid" / Int64ul,
    "cmd_size" / Int64ul,
    "cmd" / CString("utf-8"),
)

pt_logitem_thread = Struct(
    "header" / pt_logitem_header,
    "tgid" / Int64ul,
    "pid" / Int64ul,
)

pt_logitem_image = Struct(
    "header" / pt_logitem_header,
    "tgid" / Int64ul,
    "base" / Int64ul,
    "size" / Int32ul,
    "timestamp" / Int32ul,
    "image_name_length" / Int64ul,
    "image_name" / CString("utf-8"),
)

pt_logitem_xpage = Struct(
    "header" / pt_logitem_header,
    "tgid" / Int64ul,
    "base" / Int64ul,
    "size" / Int64ul,
    "xpage" / Bytes(lambda this: this.size),
)

pt_logitem_unmap = Struct(
    "header" / pt_logitem_header,
    "tgid" / Int64ul,
    "base" / Int64ul,
)

pt_logitem_fork = Struct(
    "header" / pt_logitem_header,
    "parent_tgid" / Int64ul,
    "parent_pid" / Int64ul,
    "child_tgid" / Int64ul,
    "child_pid" / Int64ul,
)

pt_logitem_lookup = [
    pt_logitem_buffer,
    pt_logitem_process,
    pt_logitem_thread,
    pt_logitem_image,
    pt_logitem_xpage,
    pt_logitem_unmap,
    pt_logitem_fork,
]
pt_kind_lookup = [
    "buffer",
    "process",
    "thread",
    "image",
    "xpage",
    "unmap",
    "fork",
]
pt_logitem_lookup_max = len(pt_logitem_lookup)
assert len(pt_kind_lookup) == len(pt_logitem_lookup)


def get_kind(packet):
    """Returns a str representing the kind of the packet. Possible kinds:

    'buffer'
    'process'
    'thread'
    'image'
    'xpage'
    'unmap'
    'fork'
    'unknown'
    """
    kind = packet.header.kind
    if kind < pt_logitem_lookup_max:
        return pt_kind_lookup[kind]
    return "unknown"


def parse_stream(stream):
    """Parse a stream, such as an open file descriptor, yielding each packet.
    Stream should be opened in binary mode (e.g., open(filepath, 'rb')) and
    must be seekable. In other words, sockets and pipes will need to be
    buffered.

    Yields Griffin packets.

    Raises StreamError or ConstructError if stream or packet is corrupt.
    """
    trace_header = pt_logfile_header.parse_stream(stream)
    if not trace_header.version in SUPPORTED_VERSIONS:
        raise StreamError("Unsupported trace version: " + str(trace_header.version))
    while True:
        packet_header = Peek(pt_logitem_header).parse_stream(stream)
        if not packet_header:
            break
        if packet_header.kind >= pt_logitem_lookup_max:
            raise StreamError("Invalid item kind: " + str(packet_header.kind))
        yield pt_logitem_lookup[packet_header.kind].parse_stream(stream)


def parse_file(filepath):
    """Parses a Griffin trace file. See parse_stream() for more info."""
    if filepath.endswith(".gz"):
        ifile = gzip.open(filepath, "rb")
    else:
        ifile = open(filepath, "rb")
    for packet in parse_stream(ifile):
        yield packet
    ifile.close()


def init_mem_layout(source, scan_full=True):
    """Takes a string representing a filepath or an already opened stream to
    a Griffin trace and returns a list representing the initial memory layout
    of the traced process. Each item is a dictionary containing:

        filepath -- The full path to the library or executable.
        base_va  -- The base virtual address the file was loaded into.

    If scan_full is True, parsing will not stop at the first PT buffer.
    """
    if isinstance(source, str):
        generator = parse_file
    else:
        generator = parse_stream

    layout = list()

    for packet in generator(source):
        packet_kind = get_kind(packet)
        if packet_kind == "buffer" and not scan_full:
            break
        elif packet_kind == "image":
            layout.append({"filepath": packet.image_name, "base_va": packet.base})

    return layout


def resolve_filepaths(mem_layout, search_dir=None):
    """Resolve all filepaths in memory layout to existing file, searching search_dir if provided.
    Unresolved filepaths will be set to None.
    """
    resolved_layout = list()
    for old_item in mem_layout:
        item = old_item.copy()  # Do not modify original item

        # Search directory always takes priority if provided
        if search_dir:
            # Is the file sitting at the base of the directory?
            candidate = os.path.join(search_dir, os.path.basename(item["filepath"]))
            if os.path.isfile(candidate):
                item["filepath"] = candidate
                resolved_layout.append(item)
                continue
            # Is the search directory like a mount point?
            if (
                item["filepath"][0] == "/"
            ):  # Watch out for absolute paths, they can't be appended in a join()
                candidate = os.path.join(search_dir, item["filepath"][1:])
            else:
                candidate = os.path.join(search_dir, item["filepath"])
            if os.path.isfile(candidate):
                item["filepath"] = candidate
                resolved_layout.append(item)
                continue

        # search_dir failed or wasn't provided, check encoded filepath
        if os.path.isfile(item["filepath"]):
            resolved_layout.append(item)
            continue

        # encoded filepath also doesn't exist, search environment variable paths
        paths = list()
        if "PATH" in os.environ:
            paths += os.environ["PATH"].split(":")
        if "LD_LIBRARY_PATH" in os.environ:
            paths += os.environ["LD_LIBRARY_PATH"].split(":")
        for path in paths:
            candidate = os.path.join(path, os.path.basename(item["filepath"]))
            if os.path.isfile(candidate):
                item["filepath"] = candidate
                resolved_layout.append(item)
                continue

        # We're out of places to search, give up!
        item["filepath"] = None
        resolved_layout.append(item)

    return resolved_layout


def expand_filepaths(mem_layout):
    """For each file in mem_layout, expand the file into a temporary file and update 'filepath'.
    A new key 'end_va' will also be created with the ending virtual address for each file.
    If a file cannot be found, 'filepath' will be set to None.
    It is the caller's job to cleanup all created temporary files.
    """
    new_layout = list()

    for old_item in mem_layout:
        item = old_item.copy()

        if not os.path.isfile(item["filepath"]):
            item["filepath"] = None
            new_layout.append(item)
            continue

        with open(item["filepath"], "rb") as ifile:
            magic = ifile.read(3)
        if magic == b"MZ\x90":  # PE files need to be expanded
            bin_data = pefile.PE(item["filepath"]).get_memory_mapped_image()
        else:
            with open(item["filepath"], "rb") as ifile:
                bin_data = ifile.read()

        temp = tempfile.mkstemp()
        with os.fdopen(temp[0], "wb") as ofile:
            ofile.write(bin_data)
        item["filepath"] = temp[1]
        item["end_va"] = item["base_va"] + len(bin_data)
        new_layout.append(item)

    return new_layout


def get_pid_list(source):
    """Get the list of PIDs contained in a trace, in the order they first appear."""
    if isinstance(source, str):
        generator = parse_file
    else:
        generator = parse_stream

    pids = list()

    for packet in generator(source):
        packet_kind = get_kind(packet)
        if packet_kind == "thread" and not packet.pid in pids:
            pids.append(packet.pid)

    return pids


def find_vdso(source):
    """Uses heuristics to find where the vDSO was probably located.

    Note: vDSO is always exactly 0x2000 bytes (8KB).

    Returns the base virtual address if found, otherwise None.
    """
    if isinstance(source, str):
        generator = parse_file
    else:
        generator = parse_stream

    candidates = list()

    for packet in generator(source):
        packet_kind = get_kind(packet)
        if packet_kind == "xpage" and packet.size == 0x2000:
            candidates.append(packet.base)

    if len(candidates) > 0:
        return candidates[0]
    return None
