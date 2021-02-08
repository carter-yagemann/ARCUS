#!/bin/bash
#
# Prepare trace data on remote host.
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

DATA_FILE="/tmp/griffin-data.tar"

if [ ! -f "$DATA_FILE" ]; then
    echo "[-] Cannot find $DATA_FILE"
    exit 1
fi

if [ -d /tmp/griffin-data ]; then
    echo "[-] Host already has trace data, cannot run multiple sessions"
    echo "[-] If this is a mistake, manually delete /tmp/griffin-data from remote host"
    exit 1
fi

mkdir /tmp/griffin-data
tar -C /tmp/griffin-data -xf "$DATA_FILE"
