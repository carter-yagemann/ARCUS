

To build the examples, a relatively recent version of python 3.8 is required.

================================
STATIC LIBRARY XED BUILD:
================================

  Linux or Mac:

    % ./mfile.py

  Windows:

   % C:/python3/python mfile.py

================================
DYNAMIC  LIBRARY XED BUILD:
================================

If you have a a shared-object (or DLL build on windows) you must also include
"--shared" on the command line:

  Linux or Mac:

    % ./mfile.py --shared

  Windows:

   % C:/python3/python mfile.py --shared
 
Add "--help" (no quotes) for more build options.
