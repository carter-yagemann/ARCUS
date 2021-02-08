#!/bin/bash
#
# Set the correct ARCUS git repo branch in each analysis host.
#
# Arguments:
#    $1: Git branch.
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

if (( $# != 1 )); then
    echo "Usage: $(basename $0) <git_branch>"
    exit 1
fi

# we require a hosts file
if [ ! -f $(dirname $0)/hosts ]; then
    echo "[-] Must create a host file at: $(dirname $0)/hosts"
    exit 1
fi

# set each host
for host in $(cat $(dirname $0)/hosts | sed 's/^[0-9]\+\///'); do
    echo "[+] Checking $host"
    ssh -A "$host" /bin/bash << EOF
        if [ ! -d ~/griffin-angr ]; then
            echo "[-] Cannot find ~/griffin-angr on this host, did you run setup-host.sh?"
            exit 1
        fi
        if [ ! -d ~/griffin-angr/env ]; then
            echo "[-] Cannot find ~/griffin-angr/env on this host, did you run setup-host.sh?"
            exit 1
        fi
        cd ~/griffin-angr

        set -e
        GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no" git fetch
        GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no" git checkout -f $1
        GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no" git pull

        exit 0
EOF

    if [ $? -ne 0 ]; then
        echo "[-] Failed while checking $host"
        exit 1
    fi
done
