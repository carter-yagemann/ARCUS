# Analyzing Root Cause Using Symbex (ARCUS)

## Analyzing Traces

See `tools/angr/analysis.py --help` for usage. To continue the example from the tracing [documentation](perf.md):

    sudo chown -R $(whoami) trace-output
    ./tools/angr/analysis.py trace-output

**Note:** If the user performing analysis does not own the trace output, you will get a permission denied error message.

In the trace example, we symbolized command line arguments (among other inputs), so the analysis will try to
follow the trace, checking along the way for signs of vulnerabilities. For example, if the program counter
ever becomes symbolic, that's very bad because it means input provided by the user via the command line
can propagate into control over the program execution.

Upon detecting a vulnerability, the analysis will attempt to look backwards to find a state to blame for
introducing the problem along with a root cause for the misbehavior. Currently, this will appear as part
of the logging output.

## Exploration

With the release of exploration plugins (codename: Bunkerbuster), ARCUS can now explore nearby paths to
find more bugs. Simply add the `--explore` flag to `analysis.py`.

**Note:** Exploration is significantly slower and more memory expensive than simply following the trace.

The "Explore Options" section in `analysis.py --help` contains additional advanced settings. For example,
you can configure the analysis to switch to exploration after a timeout, regardless of whether the end
of the trace has been reached. You can also use a Redis database to record which paths were explored so
other analysis sessions won't re-explore the same stuff.

## Snapshots

Also new in the Bunkerbuster release is the ability for Tracer to break traces down into snapshots. This
is useful for programs that are too big to analyze symbolically from start to finish. Passing `tracer.py`
the flag `--snapshot-api` will cause it to snapshot invocations of imported functions. If you really know
what you're doing, you can use `--snapshot-rva` to give a virtual address (relative to the main object's
base address) to snapshot.

**Note:** When using `--snapshot-rva`, results may be unstable if the address is not the start of a function.

For each snapshot, the analysis will attempt to symbolize its parameters, using either a prototype definition
(if one is available in `tools/angr/plugins/prototypes`) or by analyzing the memory accesses from the trace.

**Note:** This is an under-constrained symbolic analysis, so bugs found under these conditions may not be
reachable in real executions. However, since snapshots are taken at API entry points, bugs found this way
are typically of relevance to the API's developers.

It is possible to generate more prototypes for the `tools/angr/plugins/prototypes` directory using C/C++
headers. See `tools/prototype-parser/parse_function.py --help` for more details.

# Development

This section is for developers who want to contribute to the project.

## Methodology for Developing Analysis

The analysis (`analysis.py`) is constantly being updated with new heuristics and bug fixes to detect additional
types of vulnerabilities, keep tracing on track, etc. The recommended steps for developing are:

1. Collect a trace of a known vulnerability being triggered (PoC is fine).
2. Get the analysis to successfully follow the whole trace with all data concrete.
3. Symbolize the data that may trigger vulnerabilities and ensure analysis can still replay the whole trace.
4. Finally, ensure analysis can detect the vulnerability and diagnose the root cause.

## Plugins

The analysis uses a plugin system to make extending easy. There are currently four kinds of plugins: **hooks**,
**detectors**, **explorers**, and **prototypes**:

* Hooks provide angr `SimProcedure` classes to speed up analysis.

* Detectors scan each state for vulnerabilities and then analyze detections at the end.

* Explorers guide the analysis down interesting nearby paths.

* Prototypes define the parameters to functions captured as snapshots.

Adding plugins is as simple as creating a Python file to the appropriate directory. The `__init__.py` script in
each plugin directory will automatically handle loading and validating the plugins. You should not need to modify
these scripts (unless you're changing the plugin specification).

### Logging in Plugins

Plugins should place at the top of their code:

    log = logging.getLogger(__name__)

And write any and all messages to this. **Please do not use `print()`, `sys.stdout`, `sys.stderr`, etc. directly.**

### Adding Hooks

Hook plugins are placed in `tools/angr/plugins/hooks`. Each plugin placed in this directory should
only provide hooks for one object and must have:

1. `is_main_object`, which is `True` if the hooks are for a main executable object (e.g. `ntpq`, `ls`) or `False` for shared
objects like libraries (e.g. `libc`).

2. `hook_condition` is a tuple containing two items. The first is a regular expression string. If the pattern matches
an object's name, it will be hooked using the second item, which is a dictionary. Its keys are function symbol names
to hook and the values are classes that extend `angr.SimProcedure`. See the existing plugins for examples.

3. The `angr.SimProcedure` hooks themselves.

Note, this system does not support multiple hook plugins hooking the same object. If this occurs, it will produce
undefined behavior.

Hook plugins have access to a special exception type: `HookVulnException`. This was introduced because some compilers
add checks (e.g. stack canaries) that will halt the program before a vulnerability manifests into an exploit. An example
is `__stack_chk_fail()` inserted by `gcc`. If you still want to analyze these, hook the appropriate function and raise
the `HookVulnException` exception (note: `from plugins.hooks import HookVulnException`).

### Adding Detectors

Detector plugins are placed in `tools/angr/plugins/detectors`. Each detector should focus on one type of vulnerability
and must have:

1. `stash_name`, a simple name for the stash this detector places detected states in (e.g. `sip`).

2. `pretty_name`, a name for this stash used for pretty printing (e.g. `Symbolic IP`).

3. `handles_vuln_hooks`, which is `True` if this detector wants to analyze states that caused a `HookVulnException`
exception, otherwise `False`.

4. `check_for_vulns(angr.sim_manager.SimulationManager, angr.project.Project)`.
This function should check the state in the active stash for indicators of a vulnerability. Upon detection, it should
either copy the state into its own stash (`stash_name`) if angr should continue replay or move the original if it should
not. You should prevent further replay by moving the state when you know continuing will crash angr. For example,
if you detect that the program is about to allocate a buffer that vastly exceeds the total available memory of your
system. This function should return `True` if it wants to check future states, or `False` if its done for the
session. **Forgetting to return a boolean will result in your detector being disabled.**

5. `analyze_state(angr.sim_manager.SimulationManager, list, angr.sim_state.SimState, reporting.BugReport)`.
The `list` is the entire basic block sequence (virtual addresses, not normalized) of the original trace (i.e. without
any hooks). The analysis will invoke this function for each state in your detector's stash. This is where you should
find a state to blame for introducing the vulnerability and diagnose the root cause for its misbehavior. Place your
findings into the `BugReport`.

## Definition of "Root Cause"

The ultimate goal of the analysis is not only to detect that a piece of code may contain a vulnerability, but to
then identify the code we should blame for introducing it and the root cause for its misbehavior. Deciding what
to blame and what counts as root cause is up to some interpretation, so
here's some anecdotal guidelines:

* If the vulnerability is a memory corruption, we should blame the instructions that wrote the corrupted memory
values, *not* the code that accessed said memory and led to undesired behavior. For example, it is reasonable to
blame `mempy` for a stack overflow. It is also reasonable to blame the caller of `memcpy` for passing an incorrect
size parameter. As for root cause, it could be a missing or inadequate check that allowed a loop to iterate too
many times or failed to prevent `memcpy` from receiving a bogus size.

## Debugging Analysis

Suppose we have an analysis that ends prematurely:

```
INFO    | 2020-06-18 09:15:36,293 | angrpt | Trace: 89164/101011 print_line+0x0 in 564f73833000-dmitry (0x28b0)
INFO    | 2020-06-18 09:15:36,304 | angrpt | Trace: 89165/101011 print_line+0x1a in 564f73833000-dmitry (0x28ca)
INFO    | 2020-06-18 09:15:36,314 | angrpt | Trace: 89166/101011 PLT.printf+0x0 in 564f73833000-dmitry (0x20b0)
INFO    | 2020-06-18 09:15:36,344 | angrpt | Trace: 89166/101011 printf+0x0 in extern-address space (0x50)
ERROR   | 2020-06-18 09:15:37,605 | analysis | Angr stopped early: Could not find successor for address 0x564f74000050
ERROR   | 2020-06-18 09:15:37,612 | analysis | Stopped here: 0x564f74000050 printf+0x0 in extern-address space (0x50)
INFO    | 2020-06-18 09:15:37,612 | analysis | Updating reports with root cause analysis
INFO    | 2020-06-18 09:15:37,612 | analysis | ** Analysis complete, final results **
INFO    | 2020-06-18 09:15:37,612 | analysis | Reached Trace End: False
INFO    | 2020-06-18 09:15:37,612 | analysis |               Active: 1
```

Note how it stopped 88% through the trace, inside a simproc. This is clearly a bug, but the logs don't
show any errors. What do we do?

ARCUS' analysis includes debug options that allow us to embed a Python shell for further investigation:

```
./analysis.py --embed-idx 89166 trace
```

Here we use "trace index" because we have a particular spot we want to debug. There's also
`--trace-addr` if we want to embed a shell anytime a particular virtual address is reached.

Executing the above command drops us into a shell:

```
INFO    | 2020-06-18 09:23:56,948 | angrpt | Trace: 89164/101011 print_line+0x0 in 564f73833000-dmitry (0x28b0)
INFO    | 2020-06-18 09:23:56,960 | angrpt | Trace: 89165/101011 print_line+0x1a in 564f73833000-dmitry (0x28ca)
INFO    | 2020-06-18 09:23:56,971 | angrpt | Trace: 89166/101011 PLT.printf+0x0 in 564f73833000-dmitry (0x20b0)
INFO    | 2020-06-18 09:23:56,971 | analysis | Embedding debug shell at requested trace index: 89166

In [1]:
```

In this shell, the current state is stored in the variable `state`:

```
In [1]: state.project.loader.describe_addr(state.addr)
Out[1]: 'PLT.printf+0x0 in 564f73833000-dmitry (0x20b0)'
```

Note that we're in the [PLT](https://stackoverflow.com/questions/20486524/what-is-the-purpose-of-the-procedure-linkage-table),
immediately before the simproc is invoked. Let's step into the simproc:

```
In [2]: printf_state = state.step().successors[0]

In [3]: printf_state.project.loader.describe_addr(printf_state.addr)
Out[3]: 'printf+0x0 in extern-address space (0x50)'
```

Now let's see what happens when the simproc executes:

```
In [4]: printf_state.step()
---------------------------------------------------------------------------
SimProcedureError                         Traceback (most recent call last)
~/griffin-angr/tools/angr/analysis.py in <module>
----> 1 printf_state.step()

~/griffin-angr/env/site-packages/angr/sim_state.py in step(self, **kwargs)
    532         :return: A SimSuccessors object categorizing the results of the step.
    533         """
--> 534         return self.project.factory.successors(self, **kwargs)
    535
    536     def block(self, *args, **kwargs):

~/griffin-angr/env/site-packages/angr/factory.py in successors(self, engine, *args, **kwargs)
     52         if engine is not None:
     53             return engine.process(*args, **kwargs)
---> 54         return self.default_engine.process(*args, **kwargs)
     55
     56     def blank_state(self, **kwargs):

~/griffin-angr/env/site-packages/angr/engines/vex/light/slicing.py in process(self, skip_stmts, last_stmt, whitelist, *args, **kwargs)
     17         self._last_stmt = last_stmt
     18         self._whitelist = whitelist
---> 19         return super().process(*args, **kwargs)
     20
     21     def handle_vex_block(self, irsb):

~/griffin-angr/env/site-packages/angr/engines/engine.py in process(***failed resolving arguments***)
    141         self.successors = new_state._inspect_getattr('sim_successors', self.successors)
    142         try:
--> 143             self.process_successors(self.successors, **kwargs)
    144         except SimException:
    145             if o.EXCEPTION_HANDLING not in old_state.options:

~/griffin-angr/env/site-packages/angr/engines/failure.py in process_successors(self, successors, **kwargs)
     19             return self.process_procedure(state, successors, terminator, **kwargs)
     20
---> 21         return super().process_successors(successors, **kwargs)
     22
     23 from ..errors import AngrExitError

~/griffin-angr/env/site-packages/angr/engines/syscall.py in process_successors(self, successors, **kwargs)
     16         # we have at this point entered the next step so we need to check the previous jumpkind
     17         if not state.history or not state.history.parent or not state.history.parent.jumpkind or not state.history.parent.jumpkind.startswith('Ijk_Sys'):
---> 18             return super().process_successors(successors, **kwargs)
     19
     20         l.debug("Invoking system call handler")

~/griffin-angr/env/site-packages/angr/engines/hook.py in process_successors(self, successors, procedure, **kwargs)
     59             l.debug("Running %s (originally at %s)", repr(procedure), procedure.addr if procedure.addr is None else hex(procedure.addr))
     60
---> 61         return self.process_procedure(state, successors, procedure, **kwargs)

~/griffin-angr/env/site-packages/angr/engines/procedure.py in process_procedure(self, state, successors, procedure, ret_to, **kwargs)
     35
     36         # do it
---> 37         inst = procedure.execute(state, successors, ret_to=ret_to)
     38         successors.artifacts['procedure'] = inst
     39

~/griffin-angr/env/site-packages/angr/sim_procedure.py in execute(self, state, successors, arguments, ret_to)
    228             # run it
    229             l.debug("Executing %s%s%s%s%s with %s, %s", *(inst._describe_me() + (sim_args, inst.kwargs)))
--> 230             r = getattr(inst, inst.run_func)(*sim_args, **inst.kwargs)
    231
    232         state._inspect(

~/griffin-angr/env/site-packages/angr/procedures/libc/printf.py in run(self)
     12
     13         # The format str is at index 0
---> 14         fmt_str = self._parse(0)
     15         out_str = fmt_str.replace(1, self.arg)
     16

~/griffin-angr/env/site-packages/angr/procedures/stubs/format_parser.py in _parse(self, fmt_idx)
    563             all_lengths = self.state.solver.eval_upto(length, 2)
    564             if len(all_lengths) != 1:
--> 565                 raise SimProcedureError("Symbolic (format) string, game over :(")
    566             length = all_lengths[0]
    567

SimProcedureError: Symbolic (format) string, game over :(
```

And here's the hidden exception that was silently raised. We can now exit the analysis and proceed
to debug why the symbolic format string detector didn't detect this:

```
In [5]: quit

INFO    | 2020-06-18 09:30:50,207 | angrpt | Trace: 89166/101011 printf+0x0 in extern-address space (0x50)
ERROR   | 2020-06-18 09:30:52,090 | analysis | Angr stopped early: Could not find successor for address 0x564f74000050
ERROR   | 2020-06-18 09:30:52,100 | analysis | Stopped here: 0x564f74000050 printf+0x0 in extern-address space (0x50)
INFO    | 2020-06-18 09:30:52,100 | analysis | Updating reports with root cause analysis
INFO    | 2020-06-18 09:30:52,100 | analysis | ** Analysis complete, final results **
INFO    | 2020-06-18 09:30:52,100 | analysis | Reached Trace End: False
INFO    | 2020-06-18 09:30:52,100 | analysis |               Active: 1
```
