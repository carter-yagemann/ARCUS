# Simulator

In cases where a trace interface is unavailable (e.g., extending ARCUS to 
support a new architecture or device), ARCUS now offers a Tracer simulator
(`tools/angr/simulator.py`)  that can produce a pseudo-trace that's compatible 
with Analysis.

**Disclaimer:** Simulator uses unguided angr exploration to simulate recording 
an execution trace. The whole reason ARCUS was created in the first place is 
because unguided angr can run into state explosion and never finish, exhaust 
memory, etc. This is a developer tool to help in the early states of adding 
support for new architectures to ARCUS. It should **not** be used as a 
substitute for Tracer for any serious bug hunting or vulnerability analysis.

# Simulator Tracing

Simulator accepts similar arguments to Tracer:

    ./tools/angr/simulator.py trace-output /usr/bin/pwd

See `--help` for more details.
