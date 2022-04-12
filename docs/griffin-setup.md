# Griffin Setup

**Note:** Griffin is a modified Linux 4.2.0 kernel that is no longer maintained. 
It has been verified to compile, install, and run correctly on Debian Stretch 
and Buster. It does *not* work on Debian Bullseye or newer. For newer kernels, 
consider using [Perf](perf.md) instead.

The `linux` directory contains a modified version of [Griffin](https://github.com/TJAndHisStudents/Griffin-Trace)
designed to work with angr. It enables the collection of Intel Processor Trace (Intel PT) traces with appropriate
side-band data.

Griffin is a modified Linux kernel that can be compiled and installed like any other. Below
is one such way of doing so:

```shell
cd linux
cp config .config
make INSTALL_MOD_STRIP=1 -j$(nproc)
sudo make INSTALL_MOD_STRIP=1 modules_install
sudo make INSTALL_MOD_STRIP=1 install
```

Tracer (`tools/angr/tracer.py`) is the all-in-one program for interacting with this kernel. Install its Python
module requirements:

    pip install -r tools/angr/requirements/tracer.txt

**Note:** You *must* run this command from the root directory of the repo.
