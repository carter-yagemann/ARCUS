#!/usr/bin/env python
#
# Copyright 2019 Carter Yagemann
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
import subprocess
import sys
import tempfile
import unittest
import warnings

# hack so unit tests work from any directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

import dwarf
import griffin
import ptcfg
import xed

from angr import Project

class TestGriffinParser(unittest.TestCase):

    test_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'test-data'))
    test_file = os.path.join(test_dir, 'griffin/last.griffin')
    test_file_gzip = os.path.join(test_dir, 'griffin/last.griffin.gz')
    test_bins_dir = os.path.join(test_dir, 'bins')
    ground_truth = ['process', 'thread', 'image', 'xpage', 'image', 'xpage', 'xpage', 'image',
                    'xpage', 'image', 'xpage', 'buffer', 'buffer', 'image', 'xpage', 'buffer',
                    'image', 'xpage', 'image', 'xpage', 'buffer', 'buffer', 'image', 'xpage',
                    'image', 'xpage', 'buffer', 'buffer', 'buffer']
    mem_layout = [{'filepath': '/usr/bin/last',                       'base_va': 0x55ea6c4fc000},
                  {'filepath': '/lib/x86_64-linux-gnu/ld-2.24.so',    'base_va': 0x7f126ebf9000},
                  {'filepath': '/lib/x86_64-linux-gnu/librt-2.24.so', 'base_va': 0x7f126e9f1000},
                  {'filepath': '/lib/x86_64-linux-gnu/libc-2.24.so',  'base_va': 0x7f126e652000}]
    pids = [1378]

    def setUp(self):
        if not os.path.isfile(self.test_file):
            self.skipTest("Cannot find test file " + self.test_file + ", are you running in the correct directory?")
        warnings.simplefilter("ignore", ResourceWarning)

    def test_parse_file(self):
        count = 0
        trace_len = len(self.ground_truth)
        for packet in griffin.parse_file(self.test_file):
            count += 1
            self.assertLessEqual(count, trace_len)
            self.assertEqual(griffin.get_kind(packet), self.ground_truth[count - 1])
        self.assertEqual(count, trace_len)

    def test_parse_file_compressed(self):
        count = 0
        trace_len = len(self.ground_truth)
        for packet in griffin.parse_file(self.test_file_gzip):
            count += 1
            self.assertLessEqual(count, trace_len)
            self.assertEqual(griffin.get_kind(packet), self.ground_truth[count - 1])
        self.assertEqual(count, trace_len)

    def test_parse_stream(self):
        count = 0
        trace_len = len(self.ground_truth)
        with open(self.test_file, 'rb') as ifile:
            for packet in griffin.parse_stream(ifile):
                count += 1
                self.assertLessEqual(count, trace_len)
                self.assertEqual(griffin.get_kind(packet), self.ground_truth[count - 1])
        self.assertEqual(count, trace_len)

    def test_mem_layout(self):
        layout = griffin.init_mem_layout(self.test_file, False)
        self.assertEqual(len(layout), len(self.mem_layout))
        for item, truth in zip(layout, self.mem_layout):
            self.assertEqual(item['filepath'], truth['filepath'])
            self.assertEqual(item['base_va'], truth['base_va'])

    def test_resolve_filepaths(self):
        layout = griffin.init_mem_layout(self.test_file, False)
        resolved = griffin.resolve_filepaths(layout, self.test_bins_dir)
        self.assertEqual(len(layout), len(resolved))
        for orig, item in zip(layout, resolved):
            self.assertTrue(os.path.isfile(item['filepath']))
            self.assertEqual(len(item.keys()), 2)
            self.assertNotEqual(orig['filepath'], item['filepath'])
            self.assertEqual(orig['base_va'], item['base_va'])

    def test_expand_filepaths(self):
        layout = griffin.init_mem_layout(self.test_file, False)
        resolved = griffin.resolve_filepaths(layout, self.test_bins_dir)
        expanded = griffin.expand_filepaths(resolved)
        self.assertEqual(len(resolved), len(expanded))
        for orig, item in zip(resolved, expanded):
            self.assertTrue(os.path.isfile(item['filepath']))
            self.assertEqual(len(item.keys()), 3)
            self.assertNotEqual(orig['filepath'], item['filepath'])
            self.assertEqual(orig['base_va'], item['base_va'])
            self.assertLess(item['base_va'], item['end_va'])
            os.remove(item['filepath'])

    def test_get_pid_list(self):
        pids = griffin.get_pid_list(self.test_file)
        self.assertEqual(pids, self.pids)

    def test_find_vdso(self):
        vdso_va = griffin.find_vdso(self.test_file)
        self.assertIsInstance(vdso_va, int)

class TestXed(unittest.TestCase):

    test_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'test-data'))
    test_file = os.path.join(test_dir, 'griffin/last.griffin')
    test_file_gzip = os.path.join(test_dir, 'griffin/last.griffin.gz')

    def setUp(self):
        if not os.path.isfile(self.test_file):
            self.skipTest("Cannot find test file " + self.test_file + ", are you running in the correct directory?")
        warnings.simplefilter("ignore", ResourceWarning)

    def test_find_pt(self):
        pt_path = xed.find_pt()
        self.assertIsInstance(pt_path, str)
        self.assertGreater(len(pt_path), 0)

    def test_disasm_pt_file_block(self):
        blocks = xed.disasm_pt_file(self.test_file)
        self.assertEqual(len(blocks), 406903)
        for block in blocks:
            self.assertIsInstance(block, int)

    def test_disasm_pt_file_block_compressed(self):
        blocks = xed.disasm_pt_file(self.test_file_gzip)
        self.assertEqual(len(blocks), 406903)
        for block in blocks:
            self.assertIsInstance(block, int)

    def test_disasm_pt_file_icall(self):
        icalls = xed.disasm_pt_file(self.test_file, 'icall')
        self.assertGreater(len(icalls), 0)
        for icall in icalls:
            self.assertIsInstance(icall, int)

    def test_disasm_pt_file_syscall(self):
        syscalls = xed.disasm_pt_file(self.test_file, 'syscall')
        self.assertGreater(len(syscalls), 0)
        for call in syscalls:
            self.assertIsInstance(call, int)

    def test_disasm_pt_file_process(self):
        processes = xed.disasm_pt_file(self.test_file, 'process')
        self.assertEqual(len(processes), 1)
        for process in processes:
            self.assertEqual(len(process), 2)
            self.assertIsInstance(process[0], int)
            self.assertIsInstance(process[1], str)

    def test_disasm_pt_file_thread(self):
        threads = xed.disasm_pt_file(self.test_file, 'thread')
        self.assertGreater(len(threads), 0)
        for thread in threads:
            self.assertEqual(len(thread), 2)
            self.assertIsInstance(thread[0], int)
            self.assertIsInstance(thread[1], int)

    def test_disasm_pt_file_image(self):
        images = xed.disasm_pt_file(self.test_file, 'image')
        self.assertGreater(len(images), 0)
        for img in images:
            self.assertEqual(len(img), 4)
            self.assertIsInstance(img[0], int)
            self.assertIsInstance(img[1], int)
            self.assertIsInstance(img[2], int)
            self.assertIsInstance(img[3], str)

    def test_disasm_pt_file_xpage(self):
        xpages = xed.disasm_pt_file(self.test_file, 'xpage')
        self.assertGreater(len(xpages), 0)
        for page in xpages:
            self.assertEqual(len(page), 3)
            self.assertIsInstance(page[0], int)
            self.assertIsInstance(page[1], int)
            self.assertIsInstance(page[2], int)

    def test_disasm_pt_file_buffer(self):
        buffers = xed.disasm_pt_file(self.test_file, 'buffer')
        self.assertGreater(len(buffers), 0)
        for buff in buffers:
            self.assertEqual(len(buff), 2)
            self.assertIsInstance(buff[0], int)
            self.assertIsInstance(buff[1], int)

class TestPTCFG(unittest.TestCase):

    test_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'test-data'))
    test_bin = os.path.join(test_dir, 'bins/hello')
    test_trace = os.path.join(test_dir, 'griffin/hello.griffin')

    def setUp(self):
        if not os.path.isfile(self.test_bin) or not os.path.isfile(self.test_trace):
            self.skipTest("Cannot find a PTCFG test file, are you in the correct directory?")

        # supress angr warnings
        logging.getLogger('angr').setLevel(40)

        bin_name = os.path.basename(self.test_bin)
        mem_info = [item for item in griffin.init_mem_layout(self.test_trace)]
        mem_info = [item for item in mem_info if os.path.basename(item['filepath']) == bin_name]
        assert(len(mem_info) == 1)
        p = Project(self.test_bin, load_options={'auto_load_libs': False}, main_opts={'base_addr': mem_info[0]['base_va']})
        self.cfg = p.analyses.CFGFast()

    def test_prune_cfg_file(self):
        cfg = self.cfg.copy()
        node_count = len(cfg.graph.nodes())
        edge_count = len(cfg.graph.edges())

        pruned = ptcfg.prune_cfg(cfg, self.test_trace)

        # something was traced, so graph should still have at least a node and edge in it
        self.assertGreater(len(cfg.graph.nodes()), 0)
        self.assertGreater(len(cfg.graph.edges()), 0)
        # there's an untaken branch in the trace, so something should have been removed
        self.assertLess(len(cfg.graph.nodes()), node_count)
        self.assertLess(len(cfg.graph.edges()), edge_count)
        # pruned nodes + remaining nodes should equal the original list of nodes
        self.assertEqual(len(cfg.graph.nodes()) + len(pruned), node_count)

    def test_prune_cfg_list(self):
        cfg = self.cfg.copy()
        node_count = len(cfg.graph.nodes())
        edge_count = len(cfg.graph.edges())

        trace = xed.disasm_pt_file(self.test_trace)
        pruned = ptcfg.prune_cfg(cfg, trace)

        # something was traced, so graph should still have at least a node and edge in it
        self.assertGreater(len(cfg.graph.nodes()), 0)
        self.assertGreater(len(cfg.graph.edges()), 0)
        # there's an untaken branch in the trace, so something should have been removed
        self.assertLess(len(cfg.graph.nodes()), node_count)
        self.assertLess(len(cfg.graph.edges()), edge_count)
        # pruned nodes + remaining nodes should equal the original list of nodes
        self.assertEqual(len(cfg.graph.nodes()) + len(pruned), node_count)

class TestDwarf(unittest.TestCase):

    test_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'test-data'))
    test_file = os.path.join(test_dir, 'bins/ntpq')
    ground_truth = {
        0x0a54d: {'filename': 'ntpq.c',   'line': 2931, 'function': 'atoascii'},
        0x2e0b6: {'filename': 'result.c', 'line': 163,  'function': 'initialize_action'},
    }

    def setUp(self):
        if not os.path.isfile(self.test_file):
            self.skipTest("Cannot find test file " + self.test_file + ", are you running in the correct directory?")

    def test_dwarf_ntpq(self):
        ntpq_dwarf = dwarf.DwarfDebugInfo(self.test_file)

        for addr in self.ground_truth:
            gt = self.ground_truth[addr]

            func_name = ntpq_dwarf.get_function(addr)
            self.assertEqual(func_name, gt['function'])

            filename, line = ntpq_dwarf.get_src_line(addr)
            self.assertEqual(filename, gt['filename'])
            self.assertEqual(line, gt['line'])

class TestAnalysis(unittest.TestCase):

    run_script = os.path.join(os.path.dirname(__file__), '../analysis.py')
    traces_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'test-data/traces'))
    test_traces = {
        'uaf-01-poc': {'explore': False,
                       'timeout': 60,
                       'reports': [{'count': 1, 'prefix': 'alloc'}]},
        'uaf-02-poc': {'explore': False,
                       'timeout': 60,
                       'reports': [{'count': 1, 'prefix': 'alloc'}]},
        'uaf-03-poc': {'explore': False,
                       'timeout': 60,
                       'reports': [{'count': 1, 'prefix': 'alloc'}]},
        'uaf-04-ben': {'explore': True,
                       'plugins': 'uaf_explore',
                       'max-arg': '1024',
                       'timeout': 120,
                       'reports': [{'count': 1, 'prefix': 'alloc'}]},
        'uaf-05-poc': {'explore': False,
                       'timeout': 60,
                       'reports': [{'count': 2, 'prefix': 'alloc'}]},
        'uaf-05-ben': {'explore': True,
                       'plugins': 'uaf_explore',
                       'max-arg': '1024',
                       'timeout': 120,
                       'reports': [{'count': 1, 'prefix': 'alloc'}]},
        'df-01-poc':  {'explore': False,
                       'timeout': 60,
                       'reports': [{'count': 1, 'prefix': 'alloc'}]},
        'dp-01-poc':  {'explore': False,
                       'timeout': 60,
                       'reports': [{'count': 1, 'prefix': 'alloc'}]},
        'ovf-01-poc':  {'explore': False,
                        'timeout': 60,
                        'reports': [{'count': 1, 'prefix': 'sip'}]},
        'ovf-02-poc':  {'explore': False,
                        'timeout': 60,
                        'reports': [{'count': 1, 'prefix': 'sip'}]},
        'ovf-03-poc':  {'explore': False,
                        'timeout': 60,
                        'reports': [{'count': 1, 'prefix': 'sip'}]},
        'ovf-04-poc':  {'explore': False,
                        'timeout': 60,
                        'reports': [{'count': 1, 'prefix': 'sip'}]},
        'ovf-05-poc':  {'explore': False,
                        'timeout': 60,
                        'reports': [{'count': 1, 'prefix': 'neg'}]},
        'ovf-06-poc':  {'explore': False,
                        'timeout': 60,
                        'reports': [{'count': 1, 'prefix': 'fmt'}]},
        'ovf-07-poc':  {'explore': False,
                        'timeout': 60,
                        'reports': [{'count': 1, 'prefix': 'sip'}]},
        'ovf-08-poc':  {'explore': False,
                        'timeout': 60,
                        'reports': [{'count': 1, 'prefix': 'sip'}]},
        'ovf-09-poc':  {'explore': False,
                        'timeout': 60,
                        'reports': [{'count': 1, 'prefix': 'sip'}]},
        'ovf-01-ben':  {'explore': True,
                        'plugins': 'loop_bounds,arg_max',
                        'max-arg': '1024',
                        'timeout': 120,
                        'reports': [{'count': 1, 'prefix': 'sip'}]},
        'ovf-02-ben':  {'explore': True,
                        'plugins': 'loop_bounds,arg_max',
                        'max-arg': '1024',
                        'timeout': 120,
                        'reports': [{'count': 1, 'prefix': 'sip'}]},
        'ovf-03-ben':  {'explore': True,
                        'plugins': 'loop_bounds,arg_max',
                        'max-arg': '1024',
                        'timeout': 120,
                        'reports': [{'count': 1, 'prefix': 'sip'}]},
        'ovf-04-ben':  {'explore': True,
                        'plugins': 'loop_bounds,arg_max',
                        'max-arg': '128',
                        'timeout': 120,
                        'reports': [{'count': 1, 'prefix': 'sip'}]},
        'ovf-05-ben':  {'explore': True,
                        'plugins': 'loop_bounds,arg_max',
                        'max-arg': '1024',
                        'timeout': 120,
                        'reports': [{'count': 2, 'prefix': 'neg'}]},
        'ovf-06-ben':  {'explore': True,
                        'plugins': 'loop_bounds,arg_max',
                        'max-arg': '1024',
                        'timeout': 120,
                        'reports': [{'count': 1, 'prefix': 'fmt'}]},
        'ovf-07-ben':  {'explore': True,
                        'plugins': 'loop_bounds,arg_max',
                        'max-arg': '1024',
                        'timeout': 120,
                        'reports': [{'count': 1, 'prefix': 'sip'}]},
        'ovf-08-ben':  {'explore': True,
                        'plugins': 'loop_bounds,arg_max',
                        'max-arg': '1024',
                        'timeout': 120,
                        'reports': [{'count': 1, 'prefix': 'sip'}]},
        'ovf-09-ben':  {'explore': True,
                        'plugins': 'loop_bounds,arg_max',
                        'max-arg': '1024',
                        'timeout': 120,
                        'reports': [{'count': 1, 'prefix': 'sip'}]},
        'cve-2018-12327-poc':  {'explore': False,
                                'timeout': 300,
                                'reports': [{'count': 1, 'prefix': 'vuln'}]},
        'cve-2018-12327-ben':  {'explore': True,
                                'plugins': 'loop_bounds,arg_max',
                                'max-arg': '1024',
                                'timeout': 900,
                                'reports': [{'count': 1, 'prefix': 'vuln'}]},
        'cve-2005-0105-poc':   {'explore': False,
                                'timeout': 300,
                                'reports': [{'count': 1, 'prefix': 'fmt'}]},
        'ovf-01-poc-perf':  {'explore': False,
                             'timeout': 60,
                             'reports': [{'count': 1, 'prefix': 'sip'}]},
        'cve-2018-12327-ben-perf':  {'explore': True,
                                     'plugins': 'loop_bounds,arg_max',
                                     'max-arg': '1024',
                                     'timeout': 900,
                                     'reports': [{'count': 1, 'prefix': 'vuln'}]},
        'cve-2004-0597-poc': {'explore': False,
                              'timeout': 300,
                              'reports': [{'count': 1, 'prefix': 'sip'}]},
        }

    def setUp(self):
        # make sure we have all the expected traces
        for trace_name in self.test_traces:
            if not os.path.exists(os.path.join(self.traces_dir, trace_name)):
                self.skipTest("Missing trace: %s" % trace_name)

    def get_reports(self, reports_dir):
        reports = dict()

        for item in os.listdir(reports_dir):
            item_path = os.path.join(reports_dir, item)
            if not os.path.isfile(item_path) or not item.endswith('.json'):
                continue

            with open(item_path, 'r') as ifile:
                reports[item] = json.load(ifile)

        return reports

    def do_analysis_test(self, trace_name):
        trace_info = self.test_traces[trace_name]
        trace_path = os.path.join(self.traces_dir, trace_name)

        # run analysis and get reports
        with tempfile.TemporaryDirectory(prefix='analysis-unittest') as tmpdir:
            cmd = [sys.executable, self.run_script, '--save-reports', tmpdir]
            if trace_info['explore']:
                cmd += ['--explore', '--override-max-argv', trace_info['max-arg'],
                        '--explore-plugins', trace_info['plugins']]
            if 'apisnap' in trace_info:
                cmd += ['--api-snapshot', trace_info['apisnap'], '--api-inference']
            cmd += [trace_path]

            ret = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=trace_info['timeout'])

            self.assertEqual(ret.returncode, 0)
            reports = self.get_reports(tmpdir)

        # verify reports
        for criteria in trace_info['reports']:
            prefix_cnt = len([name for name in reports
                    if name.startswith(criteria['prefix'])])
            self.assertEqual(criteria['count'], prefix_cnt)

    def test_uaf_01_poc(self):
        self.do_analysis_test('uaf-01-poc')

    def test_uaf_02_poc(self):
        self.do_analysis_test('uaf-02-poc')

    def test_uaf_03_poc(self):
        self.do_analysis_test('uaf-03-poc')

    def test_uaf_04_ben(self):
        self.do_analysis_test('uaf-04-ben')

    def test_uaf_05_poc(self):
        self.do_analysis_test('uaf-05-poc')

    def test_uaf_05_ben(self):
        self.do_analysis_test('uaf-05-ben')

    def test_df_01_poc(self):
        self.do_analysis_test('df-01-poc')

    def test_dp_01_poc(self):
        self.do_analysis_test('dp-01-poc')

    def test_ovf_01_poc(self):
        self.do_analysis_test('ovf-01-poc')

    def test_ovf_02_poc(self):
        self.do_analysis_test('ovf-02-poc')

    def test_ovf_03_poc(self):
        self.do_analysis_test('ovf-03-poc')

    def test_ovf_04_poc(self):
        self.do_analysis_test('ovf-04-poc')

    def test_ovf_05_poc(self):
        self.do_analysis_test('ovf-05-poc')

    def test_ovf_06_poc(self):
        self.do_analysis_test('ovf-06-poc')

    def test_ovf_07_poc(self):
        self.do_analysis_test('ovf-07-poc')

    def test_ovf_08_poc(self):
        self.do_analysis_test('ovf-08-poc')

    def test_ovf_09_poc(self):
        self.do_analysis_test('ovf-09-poc')

    def test_ovf_01_ben(self):
        self.do_analysis_test('ovf-01-ben')

    def test_ovf_02_ben(self):
        self.do_analysis_test('ovf-02-ben')

    def test_ovf_03_ben(self):
        self.do_analysis_test('ovf-03-ben')

    def test_ovf_04_ben(self):
        self.do_analysis_test('ovf-04-ben')

    def test_ovf_05_ben(self):
        self.do_analysis_test('ovf-05-ben')

    def test_ovf_06_ben(self):
        self.do_analysis_test('ovf-06-ben')

    def test_ovf_07_ben(self):
        self.do_analysis_test('ovf-07-ben')

    def test_ovf_08_ben(self):
        self.do_analysis_test('ovf-08-ben')

    def test_ovf_09_ben(self):
        self.do_analysis_test('ovf-09-ben')

    def test_cve_2005_0105_poc(self):
        self.do_analysis_test('cve-2005-0105-poc')

    def test_cve_2018_12327_poc(self):
        self.do_analysis_test('cve-2018-12327-poc')

    def test_cve_2018_12327_ben(self):
        self.do_analysis_test('cve-2018-12327-ben')

    def test_ovf_01_poc_perf(self):
        self.do_analysis_test('ovf-01-poc-perf')

    def test_cve_2018_12327_ben_perf(self):
        self.do_analysis_test('cve-2018-12327-ben-perf')

    def test_cve_2004_0597_poc(self):
        self.do_analysis_test('cve-2004-0597-poc')

if __name__ == '__main__':
    unittest.main()
