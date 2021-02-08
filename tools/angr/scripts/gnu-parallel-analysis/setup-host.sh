#!/bin/bash
#
# Setup a remote host for use in running ARCUS analysis jobs.
#
# Arguments:
#    $1: Host to SSH into (ex: arcus@10.0.0.1).
#    $2: SSH URL for cloning the ARCUS repo.
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

# we use PyPy because it's faster than CPython, the angr devs recommend it too
# these variables define the version
PYPY_DL_URL="https://bitbucket.org/pypy/pypy/downloads/pypy3.6-v7.3.1-linux64.tar.bz2"
PYPY_VERSION="PyPy 7.3.1"

# basename of the saved PyPy release tarball
PYPY_BASENAME=$(basename "$PYPY_DL_URL")

if (( $# != 2 )); then
    echo "Usage: $(basename $0) <ssh_host> <git_repo>"
    exit 1
fi

# make sure the host has required packages
# you should also make sure the zlib1g-dev package is installed (or its equivalent)
ssh "$1" /bin/bash << EOF
    which rsync
    if [ \$? -eq 1 ]; then
        exit 1
    fi
    which wget
    if [ \$? -eq 1 ]; then
        exit 1
    fi
    which pip
    if [ \$? -eq 1 ]; then
        exit 1
    fi
    pkg-config --libs zlib
    if [ \$? -eq 1 ]; then
        exit 1
    fi

    exit 0
EOF
if [ $? -eq 1 ]; then
    echo "rsync, wget, and pip are required to setup host. Please have an admin install them."
    echo "ARCUS also requires the development package for zlib (zlib1g-dev on Debian)."
    exit 1
fi

# setup or upgrade portable PyPy3 if it's not already on the host
ssh "$1" /bin/bash << EOF
    if [ -d ~/griffin-pypy ]; then
        ~/griffin-pypy/bin/pypy3 --version | grep -Fq "${PYPY_VERSION}"
        if [ \$? -ne 0 ]; then
            echo "PyPy already installed, but out of date, removing..."
            rm -rf ~/griffin-pypy
            # we also want to nuke the project virtual environment
            if [ -d ~/griffin-angr/env ]; then
                rm -rf ~/griffin-angr/env
            fi
        else
            echo "PyPy already installed and up to date"
            exit 0
        fi
    fi

    echo "Installing ${PYPY_VERSION}..."
    wget -q "$PYPY_DL_URL"
    TLD=\$(tar -tf $PYPY_BASENAME | head -n 1 | cut -d / -f 1)
    tar -xf $PYPY_BASENAME
    mv \$TLD griffin-pypy
    rm $PYPY_BASENAME
EOF

# setup project repo and virtual environment
ssh -A "$1" /bin/bash << EOF
    if [ ! -d ~/griffin-angr ]; then
        # blank installation, clone repo
        echo "Cloning git repo..."
        GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no" git clone "$2" ~/griffin-angr
        if [ \$? -ne 0 ]; then
            echo "Failed to clone git repo"
            exit 1
        fi
    fi

    if [ ! -d ~/griffin-angr/env ]; then
        # create virtual environment
        echo "Creating virtual environment..."
        which virtualenv
        if [ \$? -eq 1 ]; then
            pip install --user virtualenv
            ~/.local/bin/virtualenv -p ~/griffin-pypy/bin/pypy3 ~/griffin-angr/env
        else
            virtualenv -p ~/griffin-pypy/bin/pypy3 ~/griffin-angr/env
        fi
    fi

    # make sure repo is up to date
    cd ~/griffin-angr
    GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no" git checkout -f master
    GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no" git pull

    # activate virtual environment
    source ~/griffin-angr/env/bin/activate
    if [ \$? -ne 0 ]; then
        echo "Failed to activate virtual environment"
        exit 1
    fi

    # ensure all Python package are installed and up to date
    echo "Updating Python packages..."
    pip install -Ur ~/griffin-angr/tools/angr/requirements/analysis.txt

    # compile PT tools
    cd ~/griffin-angr/tools/pt
    make
    if [ \$? -ne 0 ]; then
        echo "Failed to compile PT tools"
        exit 1
    fi

    # run an end-to-end test to make sure analysis is working
    echo "Testing analysis functionality..."
    cd ~/griffin-angr/tools/angr
    ./test/run-tests.py TestAnalysis.test_ovf_01_poc
    if [ \$? -ne 0 ]; then
        echo "Functionality test failed!"
        exit 1
    fi

    echo "Number of cores on host: \$(nproc)"
    echo "🎉 Ready to go 🎉"
EOF
