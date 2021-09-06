#!/bin/bash
#
# A hacky little script to invoke analysis.py on each API snapshot in
# a trace captured with the --snapshot-api argument.
#
# Arguments:
#    $1: Path to trace
#    $2: Directory to output analysis logs into, one per snapshot
#    $@: Any extra arguments to pass to analysis.py, this script will
#        always set the arguments for saving reports and examples
#        automatically.
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
if [ $# -lt 2 ]; then
    echo "Usage: $(basename $0) <trace> <output_directory>"
    exit 1
fi

EXTRA_ARGS="${@:3}"

ANALYSIS="$(dirname $0)/../analysis.py"
if [ ! -f "$ANALYSIS" ]; then
    echo "Cannot locate analysis.py"
    exit 1
fi

SNAPSHOTS_DIR="$1/api"
if [ ! -d "$SNAPSHOTS_DIR" ]; then
    echo "Cannot find $SNAPSHOTS_DIR"
    exit 1
fi

EXAMPLES_DIR="${2}/examples"
REPORTS_DIR="${2}/reports"

for SNAP_NAME in $(ls "$SNAPSHOTS_DIR"); do
    if [ "$SNAP_NAME" = "blobs" ]; then
        # not actually a snapshot, used to save storage space
        continue
    fi

    "$ANALYSIS" --api-snapshot "$SNAP_NAME" --save-reports "$REPORTS_DIR" \
        ${EXTRA_ARGS} "$1" |& tee "${2}/${SNAP_NAME}.log"
done
