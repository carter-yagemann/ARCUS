#!/bin/bash
#
# Dropped on each host, performs the analysis and tarballs the results.
#
# Arguments:
#    $1: Job ID
#    $2: trace name
#    $3: snapshot name (keyword 'base' means analyze the whole trace)
#    ${@:4}: Arguments to run analysis with
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

# activate the virtualenv for running analysis
source ~/griffin-angr/env/bin/activate
if [ $? -ne 0 ]; then
    echo "Failed to activate virtual environment"
    exit 1
fi

# command line parsing
JOB="$1"
TRACE="$2"
SNAP="$3"

# locations of various things
NAME="${TRACE}-${SNAP}"
OUT_DIR="${NAME}"
LOG="${OUT_DIR}/analysis.log"
EXAMPLES="${OUT_DIR}/examples"
REPORTS="${OUT_DIR}/reports"

# directory for storing results
mkdir "$OUT_DIR"

# run the analysis
if [ "$SNAP" = "base" ]; then
    timeout -k 1h 24h                         \
        ~/griffin-angr/tools/angr/analysis.py \
            --save-examples "$EXAMPLES"       \
            --save-reports "$REPORTS"         \
            ${@:4}                            \
            "/tmp/griffin-data/${TRACE}" &> "$LOG"
else
    timeout -k 1h 24h                         \
        ~/griffin-angr/tools/angr/analysis.py \
            --save-examples "$EXAMPLES"       \
            --save-reports "$REPORTS"         \
            --api-snapshot "$SNAP"            \
            ${@:4}                            \
            "/tmp/griffin-data/${TRACE}" &> "$LOG"
fi

# compress log and then tarball the results
gzip "$LOG"
tar -czf "output-${JOB}.tgz" "$OUT_DIR"
