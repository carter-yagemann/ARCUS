#!/bin/bash
#
# The main script to turn a directory of ARCUS traces into jobs, run
# the analysis across all the hosts, and store the results in the current
# working directory.
#
# Arguments:
#    $1: Path to directory of ARCUS traces.
#    $2: Git branch to checkout on analysis hosts (ex: master).
#    ${@:3}: Any extra arguments to pass to analysis.py, this script will
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

CURR_DIR="$PWD"

# command line parsing
if [ $# -lt 2 ]; then
    echo "Usage: $(basename $0) <traces_dir> <git_branch> [extra_analysis_args ...]"
    exit 1
fi

TRACES_DIR="$1"
GIT_BRANCH="$2"
EXTRA_ARGS="${@:3}"

# we require a hosts file in the same directory as this script to
# define the inventory of analysis hosts and how to connect
if [ ! -f $(dirname $0)/hosts ]; then
    echo "[-] Must create a host file at: $(dirname $0)/hosts"
    exit 1
fi

# prepare analysis hosts by setting each ARCUS repo to the correct branch
# and making sure it's up to date
echo "[+] Preparing hosts to run jobs..."
"$(dirname $0)/set-branch.sh" "$GIT_BRANCH"
if [ $? -ne 0 ]; then
    echo "[-] Failed while preparing hosts"
    exit 1
fi

# We define a job as 1 invocation of the analysis. For traces that only
# have a base snapshot, 1 job is created to analyze the entire trace. For
# traces with API snapshots, 1 job is created per API snapshot.
#
# Historically, we created 1 tarball per job, but once API snapshots were
# introduced, this started consuming a lot of temporary storage host-side.
# Specifically, there were cases where a 2 GB trace of GIMP would contain over
# 600 API snapshots, requiring 600 tarballs all containing the same 2 GB trace.
# Since we were creating all the tarballs upfront and not doing host-side
# cleanup until all jobs finished, it was taking over 20 minutes to prepare
# and required over 70 GB of temporary host-side storage.
#
# We considered whether we could create tarballs on demand since GNU parallel's
# default behavior is to read arguments as jobs are launched. This has several
# problems: 1) there is no feedback to tell us when a job is finished, so we
# still end up with a host-side temporary directory full of job tarballs,
# 2) we lose the ability to use GNU parallel's ETA/progress features, which
# requires it to read all the arguments in advance.
#
# Ultimately, the solution we picked is to transfer the entire trace directory
# to all the remote hosts before issuing jobs. This has the downside of
# requiring remote hosts to temporarily store traces they may never need (and
# they must have space to hold the entire trace directory), but the upsides
# are: 1) we can use ETA/progress, 2) traces containing API snapshots are sent
# once instead of hundreds of times as redundant tarballs, and 3) host-side
# temporary storage requirements are significantly reduced.
#
# If the host has significantly larger storage capacity than the workers and
# the traces directory is too big, we recommend splitting it into smaller
# chunks. This is Good Enough™ in all cases except when one host controls
# *many* (read: hundreds or more) workers, in which case a chunk may not
# contain enough jobs to efficiently engage the entire cluster. In such cases,
# run more host sessions with fewer workers per host.

# transfer traces directory to remote workers
echo "[+] Transferring traces to remote hosts..."
TMP_DATA="/tmp/griffin-data.tar"
tar -C "$TRACES_DIR" -cf "$TMP_DATA" .
cp "$(dirname $0)/prepare-data.sh" /tmp/prepare-data.sh
parallel --bar --sshdelay 0.2 --slf "$(dirname $0)/hosts"                  \
             --nonall --bf "$TMP_DATA" --bf /tmp/prepare-data.sh --cleanup \
             /tmp/prepare-data.sh
EXIT_CODE=$?
rm "$TMP_DATA"
rm /tmp/prepare-data.sh
if [ $EXIT_CODE -ne 0 ]; then
    echo "[-] Failed to transfer traces to remote hosts"
    exit 1
fi

# run jobs on the remote hosts, it is not recommended to include the
# control host as a remote worker because the analysis can exhaust
# memory and result in processes getting reaped
echo "[+] Running jobs..."
"$(dirname $0)/list-jobs.sh" "$TRACES_DIR"
cp "$(dirname $0)/analysis.sh" /tmp/analysis.sh
parallel --bar --sshdelay 0.2 --slf "$(dirname $0)/hosts"       \
         --retries 0 --memfree 1G --cleanup                     \
         --wd ... --bf /tmp/analysis.sh --return output-{#}.tgz \
         --link -a /tmp/griffin-trace-names.txt                 \
         -a /tmp/griffin-snap-names.txt                         \
         /tmp/analysis.sh {#} {} ${EXTRA_ARGS}
rm /tmp/analysis.sh
rm /tmp/griffin-trace-names.txt
rm /tmp/griffin-snap-names.txt

# untar the result tarballs into the current working directory
echo "[+] Retrieving results..."
find -name "output-*.tgz" -type f | \
    parallel -n 1 -P $(nproc) --bar tar -xzf {}
find -mindepth 1 -maxdepth 1 -name "output-*.tgz" -type f -exec rm {} \;

# cleanup remote hosts
echo "[+] Cleaning up remote hosts..."
parallel --bar --sshdelay 0.2 --slf "$(dirname $0)/hosts" --nonall \
             rm -r /tmp/griffin-data

echo "[+] 🎉 Finished 🎉"
