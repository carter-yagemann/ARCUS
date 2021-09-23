Analyzing Root Cause Using Symbex (ARCUS)
=========================================

This project finds and explains low-level binary vulnerabilities (overflows, use-after-free,
etc.) by symbolically analyzing program execution traces:

```text
$ ./tools/angr/analysis.py ./tools/angr/test/test-data/traces/cve-2018-12327-poc
INFO    | 2021-03-26 08:53:39,389 | analysis | Disassembling PT trace for PID: 8159
INFO    | 2021-03-26 08:53:42,689 | analysis | Loading state from: ./tools/angr/test/test-data/traces/cve-2018-12327-poc/state.json
INFO    | 2021-03-26 08:53:42,696 | analysis | Loading regs from: ./tools/angr/test/test-data/traces/cve-2018-12327-poc/regs.json
INFO    | 2021-03-26 08:53:42,696 | analysis | No filesystem info provided
INFO    | 2021-03-26 08:53:42,697 | analysis | Loading misc from: ./tools/angr/test/test-data/traces/cve-2018-12327-poc/misc.json
INFO    | 2021-03-26 08:53:43,673 | analysis | Starting symbolic analysis
INFO    | 2021-03-26 08:53:43,686 | angrpt | Trace: 84971/374830 __libc_start_main+0x0 in extern-address space (0x358)
INFO    | 2021-03-26 08:53:43,920 | angrpt | Trace: 84991/374830 __libc_csu_init+0x0 in 55857a272000-ntpq (0x2ee00)
INFO    | 2021-03-26 08:53:43,939 | angrpt | Trace: 84992/374830 _init+0x0 in 55857a272000-ntpq (0x9b70)
INFO    | 2021-03-26 08:53:43,950 | angrpt | Trace: 84993/374830 _init+0x12 in 55857a272000-ntpq (0x9b82)
INFO    | 2021-03-26 08:53:43,958 | angrpt | Trace: 84994/374830 __libc_csu_init+0x31 in 55857a272000-ntpq (0x2ee31)
INFO    | 2021-03-26 08:53:43,967 | angrpt | Trace: 84995/374830 __libc_csu_init+0x36 in 55857a272000-ntpq (0x2ee36)
[... 30 seconds later ...]
INFO    | 2021-03-26 08:54:13,425 | angrpt | Trace: 296837/374830 openhost+0x2a4 in 55857a272000-ntpq (0xbae4)
INFO    | 2021-03-26 08:54:13,429 | angrpt | Trace: 296838/374830 openhost+0x218 in 55857a272000-ntpq (0xba58)
INFO    | 2021-03-26 08:54:13,456 | angrpt | Trace: 296839/374830 openhost+0x3bc in 55857a272000-ntpq (0xbbfc)
INFO    | 2021-03-26 08:54:13,465 | angrpt | Trace: 296840/374830 PLT.__stack_chk_fail+0x0 in 55857a272000-ntpq (0x9ca8)
INFO    | 2021-03-26 08:54:13,468 | angrpt | Trace: 296840/374830 __stack_chk_fail+0x0 in extern-address space (0x28)
INFO    | 2021-03-26 08:54:13,469 | plugins.detectors.vuln_hook | Reached __stack_chk_fail, which is an aborting error handler; we've triggered a bug
INFO    | 2021-03-26 08:54:13,470 | analysis | Updating reports with root cause analysis
INFO    | 2021-03-26 08:54:13,924 | plugins.detectors.symbolic_ip | Symbolic IP detected. Analyzing state...
INFO    | 2021-03-26 08:54:13,925 | plugins.detectors.symbolic_ip | Analyzing exit at openhost+0x218 in 55857a272000-ntpq (0xba58)
INFO    | 2021-03-26 08:55:21,283 | plugins.detectors.symbolic_ip | Blaming for unconstrained value: openhost+0x2dd in 55857a272000-ntpq (0xbb1d)
INFO    | 2021-03-26 08:55:21,285 | plugins.detectors.symbolic_ip | Analyzing root cause for behavior of openhost+0x2dd in 55857a272000-ntpq (0xbb1d)
INFO    | 2021-03-26 08:55:26,241 | plugins.detectors.symbolic_ip | Recommendation: Add [<SAO <Bool argv_21_2416[239:232] == 93>>] to <CFGENode openhost+0x2d8 0x55857a27db18[5]>
```

# Setup

The general setup steps are:

1. Install a trace interface: Griffin or Perf (only required if you want to record your own traces)

2. Install angr

3. Install project specific packages

## Details

1. [Griffin Setup](docs/griffin-setup.md) (Alternative: [Perf Setup](docs/perf.md))

2. [angr Setup](docs/angr-setup.md)

3. [ARCUS Setup](docs/arcus-setup.md)

# Usage

* [Tracing with Griffin](docs/griffin-tracing.md)

* [Tracing with Perf](docs/perf.md)

* [Analyzing with ARCUS](docs/arcus.md)

* [Analyzing With ARCUS At Scale](docs/scaling-arcus.md)

* [Miscellaneous Tools](docs/misc-tools.md)

## Datasets

* [ARCUS Paper Evaluation](https://super.gtisc.gatech.edu/arcus-dataset-public.tgz)

* [Bunkerbuster Paper Evaluation](https://super.gtisc.gatech.edu/bunkerbuster-dataset-public.tgz)

## Unit Tests

If you make contributions to the repository, please try to keep `tools/angr/test/test.py` up-to-date. For non-unit tests,
create a new script in `tools/angr/test`. We currently do not have a unified framework for non-unit tests.

## Publications

* C. Yagemann, S. Chung, B. Saltaformaggio, W. Lee,
*Automated Bug Hunting With Data-Driven Symbolic Root Cause Analysis.*
Appeared in the 2021 ACM Conference on Computer and Communications Security (CCS’21).
Seoul, Republic of Korea. November 15--19, 2021.

* C. Yagemann, M. Pruett, S. P. Chung, K. Bittick, B. Saltaformaggio, W. Lee,
*ARCUS: Symbolic Root Cause Analysis of Exploits in Production Systems.*
Appeared in the 30th USENIX Security Symposium (USENIX'21).
August 11--13, 2021.

## Related Work

* Barnum [Tracer](https://github.com/carter-yagemann/barnum-tracer) & [Learner](https://github.com/carter-yagemann/barnum-learner):
An end-to-end system for program control-flow anomaly detection.
