# ARCUS Setup

**Note:** We highly recommend using [PyPy](https://pypy.org/), [as do the angr developers](https://docs.angr.io/advanced-topics/speed).

Install the Python modules required by the analysis code:

    pip install -r tools/angr/requirements/analysis.txt

Next compile the disassembler:

    sudo apt install zlib1g-dev
    cd tools/pt
    make

All the tools for working with angr are located in `tools/angr/`.

## Verifying Your Setup

You can test the basic functionality of your setup by running the quick unit tests.
This should only take a few seconds:

    cd tools/angr
    python test/run_tests.py TestGriffinParser TestXed TestPTCFG

You can also run one of the analysis unit tests. This will take about
30 seconds:

    cd tools/angr
    python test/run_tests.py TestAnalysis.test_uaf_01_poc

## Miscellaneous Tools

If you want to use the miscellaneous tools provided in `tools/angr/`:

    pip install -r tools/angr/requirements/misc.txt
