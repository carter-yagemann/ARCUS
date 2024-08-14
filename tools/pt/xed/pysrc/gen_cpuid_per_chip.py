#!/usr/bin/env python
# -*- python -*-
#BEGIN_LEGAL
#
#Copyright (c) 2023 Intel Corporation
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#  
#END_LEGAL
from __future__ import print_function
import json
import sys
import read_xed_db
import gen_setup
import cpuid_rdr
from typing import Dict, List

def msgj(b,s=''):
    sys.stdout.write("# [{0}] {1}\n".format(b,s))


def work(args):  # main function
    msgj("READING XED DB")
    xeddb: read_xed_db.xed_reader_t = gen_setup.read_db(args)
    chips, chipdb = gen_setup.read_chips(args)
    
    data: Dict[str, dict] = {} # DB for future json print

    xeddb.recs.sort(key=lambda x:x.iclass)
    for chip in chips:
        data[chip]: Dict[str, dict] = {}  # isa-set as a key
        for r in xeddb.recs:
            if r.isa_set in chipdb[chip] and r.cpuid_groups:
                data[chip][r.isa_set]: Dict[str, List[str]] = {}
                group : cpuid_rdr.group_record_t
                for group in r.cpuid_groups:
                    group_k = group.get_kind_name()
                    data[chip][r.isa_set][group_k]: List[str] = [str(rec) for rec in group.get_records()]
    
    jsonString = json.dumps(data, indent=4)
    print(jsonString)


if __name__ == "__main__":
    args = gen_setup.setup('Generate cpuid info in json format')
    work(args)
    sys.exit(0)

