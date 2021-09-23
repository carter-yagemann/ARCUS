For users who don't want to compile the custom Griffin Linux kernel, ARCUS
now supports interfacing with Linux Perf.

Support is currently **experimental** and may yield incomplete analysis results!

# Perf Setup

If you have not already done so, install Linux Perf. For Debian:

```shell
sudo apt install linux-perf
```

**Note:** You may need to restart your system after installing.

Verify that you have installed Perf and it supports Intel PT:

```text
$ perf list | grep intel
  intel_pt//                                         [Kernel PMU event]
```

Tracer (`tools/angr/tracer.py`) is the all-in-one program for tracing. Install
its Python module requirements:

    pip install -r tools/angr/requirements/tracer.txt

**Note:** You *must* run this command from the root directory of the repo.

You're ready to go!

# Perf Tracing

Tracing with Perf works exactly like Griffin. Tracer will automatically pick
the best available interface. See the [Griffin Tracing](griffin-tracing.md)
document for more info on using Tracer.
