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

**Note:** You *must* run this command from the root directory of the repo. Also, depending on 
your Perf settings, you may need to run Tracer as root to record traces, so make sure you install 
the packages for the right user and environment (e.g., if using `virtualenv`)!

You're ready to trace 🎉

# Perf Tracing

Traces are recorded using Tracer (`tracer.py`):

    sudo ./tools/angr/tracer.py trace-output /bin/ls -lht

In the above example, `ls` will be ran with the user's UID and GID (because `sudo` was used) and
all possible inputs will be symbolized (e.g., argv, env, files). See `--help` for more options.

## Understanding Tracer's Output

Consider again the example:

    sudo ./tools/angr/tracer.py trace-output /bin/ls -lht

This will create a new directory named `trace-output` and fill it with everything needed by the analysis.
The layout is under active development, but here's the important parts as of the time of writing:

* `bin/` - This contains copies of initially loaded objects (executable, shared objects, etc.) as
they are stored on disk. They're passed to CLE during analysis to initialize the angr project.
* `files/` - Tracer will make a best effort attempt to infer which files were touched by the tracee and
save copies of those files here. Files are named based on the SHA256 hash of their starting content.
* `files.json` - Describes where collected files should be placed in angr's virtual file system and whether
the analysis should symbolize the content.
* `mem/` - Contains raw dumps of the tracee's starting memory layout. We use this in combination with CLE's
loading to create the true starting state for analysis.
* `misc.json` - Contains miscellaneous details for the analysis, like which binary is the main program object.
* `regs.json` - Contains the starting values for CPU registers.
* `state.json` - Contains the starting values (concrete or symbolic, depending on the options given to `tracer.py`)
of command line arguments and environment variables.
* `trace.perf.gz` or `trace.griffin.gz` - The Intel PT trace, gzip compressed. Exact contents depends on which
tracing interface was used.

## File Symbolization

When tracer records files, it creates entries in `files.json` inside the output directory like so:

```
"files": {
  "/foobar.txt": {
    "symbolic": true,
    "data": "files/90a3653b27239045410ecfac467e57018a9639a20a0a578274521fb1cd4e3df6"
  }
}
```

Adding `--concrete-fs` to `tracer.py` will tell the analysis not to symbolize this file:

```
"files": {
  "/foobar.txt": {
    "symbolic": false,
    "data": "files/90a3653b27239045410ecfac467e57018a9639a20a0a578274521fb1cd4e3df6"
  }
}
```
