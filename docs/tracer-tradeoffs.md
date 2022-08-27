# Trade-Offs Between Supported Tracing Interfaces

At the time of writing, ARCUS supports tracing via Perf or a modified Linux kernel called 
Griffin. *Perf is the recommended tracing interface at this time* and Griffin is kept only for 
legacy purposes.

Below are the known trade-offs between the supported tracing interfaces.

## Perf

**Pros:**

* Easier to setup (no custom kernel).

* Works on newer Linux kernels (maintained by Linux developers).

**Cons:**

* While Intel PT traces are never guaranteed to be complete (see the OVF packet definition in the 
[Intel ASDM](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html))
Perf introduces additional potential sources of data loss due to how it buffers data.

## Griffin

**Pros:**

* Guarantees no software level data loss of traces. Note that hardware
level data loss is always possible due to Intel PT's design.

**Cons:**

* Requires compiling and installing a custom Linux kernel.

* Kernel will not work on newer systems. Griffin is currently verified
to work on Debian Stretch and Buster. It will _not_ work on Debian
Bullseye or newer.
