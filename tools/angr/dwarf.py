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

import logging
import os
import sys

from elftools.dwarf.descriptions import describe_form_class
from elftools.elf.elffile import ELFFile

log = logging.getLogger(name=__name__)


class DwarfException(Exception):
    pass


class DwarfDebugInfo(object):
    """Class for accessing DWARF debug information in ELF objects (if available)"""

    def __init__(self, filepath):
        """Parse ELF object to create DwarfDebugInfo.

        Raises DwarfException if no DWARF info is available.
        """
        log.debug("Loading DWARF info from: %s" % filepath)
        self.filepath = filepath
        self.filename = os.path.basename(filepath)

        with open(self.filepath, "rb") as ifile:
            elffile = ELFFile(ifile)

            if not elffile.has_dwarf_info():
                err_msg = "%s has no DWARF info" % self.filename
                log.error(err_msg)
                raise DwarfException(err_msg)

            self.dwarfinfo = elffile.get_dwarf_info()

    def get_function(self, address):
        """Given a relative virtual address (RVA), return the name of the function
        it belongs to. Returns None if address is invalid."""
        for CU in self.dwarfinfo.iter_CUs():
            for DIE in CU.iter_DIEs():
                try:
                    if DIE.tag == "DW_TAG_subprogram":
                        lowpc = DIE.attributes["DW_AT_low_pc"].value

                        # DWARF v4 in section 2.17 describes how to interpret the
                        # DW_AT_high_pc attribute based on the class of its form.
                        # For class 'address' it's taken as an absolute address
                        # (similarly to DW_AT_low_pc); for class 'constant', it's
                        # an offset from DW_AT_low_pc.
                        highpc_attr = DIE.attributes["DW_AT_high_pc"]
                        highpc_attr_class = describe_form_class(highpc_attr.form)
                        if highpc_attr_class == "address":
                            highpc = highpc_attr.value
                        elif highpc_attr_class == "constant":
                            highpc = lowpc + highpc_attr.value
                        else:
                            log.error(
                                "Invalid DW_AT_high_pc class: %s"
                                % str(highpc_attr_class)
                            )
                            continue

                        if lowpc <= address <= highpc:
                            return DIE.attributes["DW_AT_name"].value.decode("utf8")
                except KeyError:
                    continue

        log.error(
            "Failed to get function name for %#x in %s" % (address, self.filename)
        )
        return None

    def get_src_line(self, address):
        """Given a relative virtual address (RVA), return the source filename and line
        number it belongs to.

        Returns:
        Tuple (filename, line_number) on success, otherwise (None, None).
        """
        for CU in self.dwarfinfo.iter_CUs():
            # First, look at line programs to find the file/line for the address
            lineprog = self.dwarfinfo.line_program_for_CU(CU)
            prevstate = None
            for entry in lineprog.get_entries():
                # We're interested in those entries where a new state is assigned
                if entry.state is None:
                    continue
                if entry.state.end_sequence:
                    # if the line number sequence ends, clear prevstate.
                    prevstate = None
                    continue
                # Looking for a range of addresses in two consecutive states that
                # contain the required address.
                if prevstate and prevstate.address <= address < entry.state.address:
                    filename = lineprog["file_entry"][prevstate.file - 1].name.decode(
                        "utf8"
                    )
                    line = prevstate.line
                    return (filename, line)
                prevstate = entry.state

        log.error("Failed to find line number for %#x in %s" % (address, self.filename))
        return (None, None)
