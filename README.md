Symbolic Execution Over Processor Traces
========================================

This repository contains various tools to facilitate performing symbolic execution over processor traces.

# Setup

The general setup steps are:

1. (optional) Install a processor tracing hypervisor/kernel/framework

2. Install angr

3. Install project specific packages

## Details

1. Processor Tracing Frameworks:

    * [Griffin Setup](docs/griffin-setup.md)

2. [angr Setup](docs/angr-setup.md)

3. Projects:

    * [ARCUS Setup](docs/arcus-setup.md)

# Usage

* [Tracing With Griffin](docs/griffin-tracing.md)

* [Analyzing Root Cause Using Symbex (ARCUS)](docs/arcus.md)

* [Analyzing With ARCUS At Scale](docs/scaling-arcus.md)

* [Miscellaneous Tools](docs/misc-tools.md)

## Datasets

* [ARCUS Paper Evaluation](https://super.gtisc.gatech.edu/arcus-dataset-public.tgz)

## Unit Tests

If you make contributions to the repository, please try to keep `tools/angr/test/test.py` up-to-date. For non-unit tests,
create a new script in `tools/angr/test`. We currently do not have a unified framework for non-unit tests.

## Publications

* C. Yagemann, M. Pruett, S. P. Chung, K. Bittick, B. Saltaformaggio, W. Lee, *ARCUS: Symbolic Root Cause Analysis of Exploits
in Production Systems.* To appear in the 30th USENIX Security Symposium (USENIX'21). August 11--13, 2021.

## Related Work

* Barnum [Tracer](https://github.com/carter-yagemann/barnum-tracer) & [Learner](https://github.com/carter-yagemann/barnum-learner):
An end-to-end system for program control-flow anomaly detection.
