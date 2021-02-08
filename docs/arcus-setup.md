ARCUS Setup
===========

You should have already setup the Griffin tracer during [Griffin setup](griffin-setup.md)
and installed the required Python modules for analysis during [angr setup](angr-setup.md).

If you didn't:

    pip install -r tools/angr/requirements/tracer.txt
    pip install -r tools/angr/requirements/analysis.txt

**Note:** You *must* run `pip` from the root directory of the repo for some requirement
files to parse correctly.

If you want to use the miscellaneous tools provided in `tools/angr/`:

    pip install -r tools/angr/requirements/misc.txt

You can test your ARCUS setup by running one of the analysis unit tests. This will take about
30 seconds:

    cd tools/angr
    python test/run-tests.py TestAnalysis.test_uaf_01_poc
