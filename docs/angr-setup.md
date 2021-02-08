# angr Setup

**Note:** We highly recommend using [PyPy](https://pypy.org/), [as do the angr developers](https://docs.angr.io/advanced-topics/speed).

Install the minimum set of required Python modules, which includes angr:

    pip install -r tools/angr/requirements/analysis.txt

Next compile the disassembler:

    sudo apt install zlib1g-dev
    cd tools/pt
    make

You can test the basic functionality of your setup by running the quick unit tests.
This should only take a few seconds:

    cd tools/angr
    python test/run-tests.py TestGriffinParser TestXed TestPTCFG

All the tools for working with angr are located in `tools/angr/`.
