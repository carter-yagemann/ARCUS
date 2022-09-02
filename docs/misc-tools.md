# Miscellaneous Tools

Here's a list of other tools provided and their purpose:

* `tools/angr/memlayout.py` - Takes a trace and prints the memory layout.
* `tools/angr/decode.py` - Decodes a GRIFFIN trace (usually named `trace.griffin`) and prints out the sequence
of executed basic blocks along with some other details.
* `tools/angr/rewriter.py` - Instruments program to record run-time data in PT trace. Explained in more detail
in a following subsection.
* `tools/pt/cmppath` - Compares traces using hashmaps and checksums.
* `tools/angr/simulator.py` - A Tracer simulator to help developers. See this [document](simulator.md) for more details.

## Instrumenting Programs

Processor traces usually only record control flow, so for analysis that requires data flow, the program has to be rewritten
to encode the data of interest. This can be done with `tools/angr/rewriter.py`. See `-h` for more details.

The JSON file provided to this tool is used to specify where to place hooks and what to record at those
places. For example, to capture the contents of the `rax` register at the code located at relative virtual
address `0x839`:

```
{"hooks": [
    {"addr": 2105, "src": "rax"}
]}
```

And if we want to record the value at a memory location instead:

```
{"hooks": [
    {"addr": 2105, "src": 123456}
]}
```

## Comparing Traces

The tool `cmppath` uses hashmaps and checksums to compare traces. Setup is as easy as:

```shell
cd tools/pt
make
```

For optimal performance, use a version of `gcc` that supports [OpenMP](https://gcc.gnu.org/wiki/openmp).

Running it on a single trace will produce an output like so:

```
$ ./cmppath /trace.griffin
aff172c7  11608  /trace.griffin
```

The first column is a checksum for the trace and the last is the absolute path of the trace file.
To understand the second column, let's take multiple traces of a program doing the same task:

```
$ for i in $(seq 15); do sudo ./tracer.py -u 1000 -g 1000 --trace $i $(which ls) -lht / > /dev/null; done
```

Now let's compare them:

```
$ ./cmppath $(find -name trace.griffin)
f2c7f1b3   6837  /tmp/tmp.5GKbyooMOH/7/trace.griffin
8a54e8dd     10  /tmp/tmp.5GKbyooMOH/17/trace.griffin
f2c7f1b3      0  /tmp/tmp.5GKbyooMOH/98/trace.griffin
8a54e8dd      0  /tmp/tmp.5GKbyooMOH/97/trace.griffin
2b6ac080      3  /tmp/tmp.5GKbyooMOH/26/trace.griffin
ca85ec2d      6  /tmp/tmp.5GKbyooMOH/77/trace.griffin
8a54e8dd      0  /tmp/tmp.5GKbyooMOH/34/trace.griffin
f2c7f1b3      0  /tmp/tmp.5GKbyooMOH/81/trace.griffin
6b6a2fb0      1  /tmp/tmp.5GKbyooMOH/27/trace.griffin
9ad3e5ef      2  /tmp/tmp.5GKbyooMOH/62/trace.griffin
8a54e8dd      0  /tmp/tmp.5GKbyooMOH/87/trace.griffin
2feed18b      0  /tmp/tmp.5GKbyooMOH/50/trace.griffin
ca85ec2d      0  /tmp/tmp.5GKbyooMOH/3/trace.griffin
f65a38ea      0  /tmp/tmp.5GKbyooMOH/32/trace.griffin
8a54e8dd      0  /tmp/tmp.5GKbyooMOH/13/trace.griffin
```

In short, the number in the second column represents how "new" a trace is compared to all prior traces.
It does this using a hashmap to track edge-based code coverage in a similar manner to fuzzers like AFL.
Since we recorded the same task multiple times in the example above, the score converges to 0. We can
even see that some of the traces are identical, based on the checksums.
