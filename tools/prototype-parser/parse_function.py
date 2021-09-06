#!/usr/bin/env python
#
# Copyright 2020 Carter Yagemann
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import json
import logging
import os
import platform
import sys

import pycparser

# exit codes
EXIT_SUCCESS          = 0
EXIT_INVALID_ARGUMENT = 1
EXIT_RUNTIME_ERROR    = 2

# basic data type sizes
with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                       'config.json'), 'r') as ifile:
    CONFIG = json.load(ifile)
BASIC_TYPES = CONFIG['basic_types']
PTR_SIZE = CONFIG['ptr_size']

def check_cpp():
    """Check if cpp is installed."""
    path_dirs = os.environ['PATH'].split(':')
    for path_dir in path_dirs:
        candidate = os.path.join(path_dir, 'cpp')
        if os.path.isfile(candidate):
            return True
    return False

def parse_size(param_ast, file_ast, size=0):
    """Given the AST and a global file AST, return the size of the type defined by the AST."""
    if isinstance(param_ast, pycparser.c_ast.IdentifierType):
        param_name = param_ast.names[0]
        if param_name in BASIC_TYPES:
            return BASIC_TYPES[param_name]
        else:
            # find the declaration for this type
            for child in file_ast.ext:
                if isinstance(child, pycparser.c_ast.Typedef) and child.name == param_name:
                    return parse_size(child, file_ast, size)
            raise Exception("Failed to find declaration for %s, if it is a basic type, "
                            "add it to the BASIC_TYPES dictionary." % param_name)

    elif isinstance(param_ast, (pycparser.c_ast.TypeDecl, pycparser.c_ast.Decl,
                                pycparser.c_ast.Typedef)):
        # no useful info at this level, keep digging
        return parse_size(param_ast.type, file_ast, size)

    else:
        raise Exception("Unhandled type in parse_size, erroring AST: %s" % str(param_ast))

def parse_param(param_ast, file_ast, parent=None):
    """Given the AST for a function parameter and the global file AST, return a generic
    prototype definition. See tools/angr/analysis.py:symbolize_api for format details."""
    if hasattr(param_ast, 'name'):
        print("Parsing: %s" % param_ast.name)

    if isinstance(param_ast, (pycparser.c_ast.IdentifierType, pycparser.c_ast.Constant)):
        if isinstance(param_ast, pycparser.c_ast.IdentifierType):
            param_name = param_ast.names[0]
        else:  # constant
            param_name = param_ast.type

        if param_name in BASIC_TYPES:
            prototype = {"value_type": 'Int', "value_data": None,
                         "value_size": BASIC_TYPES[param_name]}
            if not parent is None and not parent['value_type'] == 'Struct':
                # parent is a data pointer
                parent['value_type'] = 'Ptr_Data'

            return prototype

        else:
            # find the declaration for this type
            for child in file_ast.ext:
                if isinstance(child, pycparser.c_ast.Typedef) and child.name == param_name:
                    return parse_param(child, file_ast, parent)
            raise Exception("Failed to find declaration for %s, if it is a basic type, "
                            "add it to the BASIC_TYPES dictionary." % param_name)

    elif isinstance(param_ast, pycparser.c_ast.PtrDecl):
        # is this pointer to a struct, code or data?
        prototype = {"value_type": None, "value_data": None, "value_size": PTR_SIZE}
        # the recursive call will fill in value_type and value_data
        parse_param(param_ast.type, file_ast, prototype)
        if not parent is None and not parent['value_type'] == 'Struct':
            # pointer to a pointer is a Struct with 1 element
            parent['value_type']     = 'Struct'
            prototype['offset_type'] = 'RVA'
            prototype['offset']      = 0
            parent['value_data']     = [prototype]

        return prototype

    elif isinstance(param_ast, (pycparser.c_ast.Struct, pycparser.c_ast.Union)):
        if parent is None:
            raise Exception("Prototype format does not support pass-by-value for Structs")

        parent['value_size'] = None  # pointers don't need value_size

        if param_ast.decls is None:
            print("Warning: %s is an anonymous struct" % param_ast.name, file=sys.stderr)
            # anonymous struct, just treat it like a code pointer
            parent['value_type'] = 'Ptr_Code'
            parent['value_data'] = None
        else:
            if not parent['value_data'] == 'Struct':
                # new struct
                parent['value_type'] = 'Struct'
                parent['value_data'] = list()
            for decl in param_ast.decls:
                parent['value_data'].append(parse_param(decl.type, file_ast, parent))
            # fill in RVAs
            rva_off = 0
            for element in parent["value_data"]:
                element['offset_type'] = 'RVA'
                element['offset'] = rva_off
                if element['value_type'] in ['Ptr_Data', 'Ptr_Code', 'Struct']:
                    rva_off += PTR_SIZE  # pointer
                else:
                    rva_off += element['value_size']

        return

    elif isinstance(param_ast, pycparser.c_ast.ArrayDecl):
        if param_ast.dim is None or not isinstance(param_ast.dim, pycparser.c_ast.Constant):
            raise Exception("Cannot handle arrays of unknown size")
        if not param_ast.dim.type in BASIC_TYPES:
            raise Exception("Array has an unsupported size type: %s" % param_ast.dim.type)

        array_size = BASIC_TYPES[param_ast.dim.type] * parse_size(param_ast.type, file_ast)

        return {'value_type': 'Int', 'value_data': None, 'value_size': array_size}

    elif isinstance(param_ast, pycparser.c_ast.FuncDecl):
        # parent should be a code pointer
        if parent is None:
            raise Exception("Reached FuncDecl inside a parameter, but no parent pointer?")
        parent['value_type'] = 'Ptr_Code'
        return

    elif isinstance(param_ast, (pycparser.c_ast.TypeDecl, pycparser.c_ast.Decl,
                                pycparser.c_ast.Typedef, pycparser.c_ast.Typename)):
        # no useful info at this level, keep digging
        return parse_param(param_ast.type, file_ast, parent)

    elif isinstance(param_ast, pycparser.c_ast.Enum):
        # all values in an enum should be the same type, picking any of them should work
        return parse_param(param_ast.values.enumerators[0].value, file_ast, parent)

    else:
        raise Exception("Unhandled type in parse_param, erroring AST: %s" % str(param_ast))

    raise Exception("parse_param reached condition that should be unreachable")

def find_func(file_ast, func_name):
    """Given an AST and function name, return its AST, or None if it cannot
    be found."""
    for child in file_ast.ext:
        if isinstance(child, pycparser.c_ast.FuncDef) and child.decl.name == func_name:
            return child
        elif isinstance(child, pycparser.c_ast.Decl) and child.name == func_name:
            return child
    return None

def main():
    """Main method."""
    if len(sys.argv) < 4:
        print('Usage: %s <c_header_file> <function_name> <output_directory> '
              '[cpp args...]' % os.path.basename(__file__), file=sys.stderr)
        return EXIT_INVALID_ARGUMENT

    # input validation
    input_file = sys.argv[1]
    func_name = sys.argv[2]
    output_dir = sys.argv[3]
    cpp_args = sys.argv[4:]

    if not os.path.isfile(input_file):
        print('Error: File does not exist: %s' % input_file, file=sys.stderr)
        return EXIT_INVALID_ARGUMENT

    if not os.path.isdir(output_dir):
        print('Error: Output directory does not exist: %s' % output_dir, file=sys.stderr)
        return EXIT_INVALID_ARGUMENT

    ofilepath = os.path.join(output_dir, '%s.json' % func_name)
    if os.path.exists(ofilepath):
        print('Error: File already exists, refusing to overwrite: %s' % ofilepath,
              file=sys.stderr)
        return EXIT_RUNTIME_ERROR

    # parser requires cpp
    if not check_cpp():
        print('Error: cpp does not appear to be installed, please install it. (on Debian, '
              'run: sudo apt install cpp)', file=sys.stderr)
        return EXIT_RUNTIME_ERROR

    # fake libc headers makes parsing faster and more stable
    fake_libc = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             'fake_libc_include')
    if not os.path.isdir(fake_libc):
        print('Error: Cannot find required directory (should have been included with this '
              'program): %s' % fake_libc, file=sys.stderr)
        return EXIT_RUNTIME_ERROR

    # note: we nullify compiler extensions like __attribute__ because pycparser cannot
    # handle them and we don't need them since we aren't compiling to machine code
    cpp_args = ['-I%s' % fake_libc,
                '-D', '__attribute__(x)=',
                '-D', '__extension__=',
                '-D', '__restrict=',
               ] + cpp_args

    try:
        file_ast = pycparser.parse_file(input_file, use_cpp=True, cpp_args=cpp_args)
    except Exception as ex:
        print('Error: Failed to parse input C file: %s' % str(ex), file=sys.stderr)
        return EXIT_RUNTIME_ERROR

    # find function declaration
    func_ast = find_func(file_ast, func_name)
    if func_ast is None:
        print('Error: Failed to find function declaration: %s' % func_name, file=sys.stderr)
        return EXIT_RUNTIME_ERROR

    prototype = list()
    # find_func can return a FuncDef or a Decl directly
    if isinstance(func_ast, pycparser.c_ast.FuncDef):
        func_params = func_ast.decl.type.args.params
    else:
        func_params = func_ast.type.args.params

    for param_ast in func_params:
        if isinstance(param_ast, pycparser.c_ast.EllipsisParam):
            # function takes a variable number of parameters, we can't handle this
            print("Warning: Ellipsis function, only defining explicit parameters", file=sys.stderr)
            continue

        try:
            prototype.append(parse_param(param_ast, file_ast))
        except Exception as ex:
            print("Error: Failed to parse function parameter: %s" % str(ex), file=sys.stderr)
            return EXIT_RUNTIME_ERROR

    try:
        with open(ofilepath, 'w') as ofile:
            json.dump(prototype, ofile)
    except Exception as ex:
        print('Error: Failed to save output: %s' % str(ex), file=sys.stderr)
        return EXIT_RUNTIME_ERROR

    return EXIT_SUCCESS

if __name__ == '__main__':
    sys.exit(main())
