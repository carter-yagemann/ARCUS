# Trade-Offs Between Supported Tracing Interfaces

At the time of writing, ARCUS supports tracing via Griffin (a modified
Linux kernel) and Perf. The trade-offs are:

## Griffin

**Pros:**

* Guarantees no software level data loss of traces. Note, hardware
level data loss is always possible due to Intel PT's design.

**Cons:**

* Requires compiling and installing a custom Linux kernel.

* Kernel will not work on newer systems. Griffin is currently verified
to work on Debian Stretch and Buster. It will _not_ work on Debian
Bullseye or newer.

## Perf

**Pros:**

* Easier to setup (no custom kernel).

* Works on newer Linux kernels.

**Cons:**

* When the traced program ends with a crash (e.g., when tracing a PoC
exploit), Perf may lose the tail-end of the trace, leading to incomplete
analysis results. This behavior seems intrinsic to Perf's design.
