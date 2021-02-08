from setuptools import setup, find_packages, Extension

extos_module = Extension('pyptrace.ext.os._os',
    define_macros = [('MAJOR_VERSION', '2'), ('MINOR_VERSION', '00')],
    sources=['pyptrace/ext/os/os.c'])

setup(
    name = 'pyptrace',
    description = 'Python wrapper for Linux ptrace system call.',
    author = 'Carter Yagemann',
    author_email = 'yagemann@gatech.edu',
    url = 'https://carteryagemann.com',
    version = '2.00',
    packages = find_packages(),
    package_dir = {'':'.'},
    ext_modules = [extos_module],
    keywords = 'linux ptrace',
)
