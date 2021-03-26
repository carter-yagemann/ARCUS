# Analyzing ARCUS At Scale

## Batching over Remote Hosts

The scripts in `tools/angr/scripts/gnu-parallel-analysis` let you run ARCUS's `analysis.py` over
one or more remote hosts using [GNU Parallel](https://www.gnu.org/software/parallel/).

Guide:

1. Make sure the "master" host you're running these scripts on can access all the
remote hosts via SSH.

2. Run `setup-host.sh` for each host. Ex: `./setup-host.sh server.example.org git@git.repo.com:user/my-repo.git`

3. Write a hosts file at `tools/angr/scripts/gnu-parallel-analysis/hosts`. See GNU Parallel's documentation
for more details.

4. Place all the traces you want to analyze in one directory and then navigate to
where you want the results to be stored (ideally, another empty directory). **Note:**
you may want to use `tools/pt/cmppath` to filter out similar traces.

5. Run `run.sh`.

### Run Script Usage

    run.sh <traces_dir> <git_branch> [extra_analysis_args ...]
    
    EXAMPLES:
    
    # basic run
    ./run.sh /path/to/traces-dir master
    
    # pass additional arguments to analysis.py
    ./run.sh /path/to/traces-dir master --logging=40
