#!/bin/bash
#
# Lists the jobs contained in a trace directory.
#
# Arguments:
#    $1: Path to an ARCUS trace directory.
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
# along with this program. If not, see <https://www.gnu.org/licenses/>.

# command line parsing
if [ $# -lt 1 ]; then
    echo "Usage: $(basename $0) <traces_dir>"
    exit 1
fi

if [ -f "/tmp/griffin-trace-names.txt" ]; then
    rm "/tmp/griffin-trace-names.txt"
fi
if [ -f "/tmp/griffin-snap-names.txt" ]; then
    rm "/tmp/griffin-snap-names.txt"
fi

for TRACE in $(find "$1" -mindepth 1 -maxdepth 1 -type d); do
    TRACE_NAME=$(basename "$TRACE")
    if [ -d "${TRACE}/api" ]; then
        # trace contains api snapshots, need 1 job per snapshot
        for API in $(find "${TRACE}/api" -mindepth 1 -maxdepth 1 -type d); do
            API_NAME="$(basename $API)"
            if [ "$API_NAME" != "blobs" ]; then
                echo "${TRACE_NAME}" >> "/tmp/griffin-trace-names.txt"
                echo "${API_NAME}" >> "/tmp/griffin-snap-names.txt"
            fi
        done
    else
        echo "${TRACE_NAME}" >> "/tmp/griffin-trace-names.txt"
        echo "base" >> "/tmp/griffin-snap-names.txt"
    fi
done
