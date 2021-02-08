from angr.sim_state import SimState
from angr.project import Project
from angr.analyses.cfg.cfg_emulated import CFGEmulated
import IPython # noqa
import networkx as nx
from copy import deepcopy
from angr.sim_variable import SimRegisterVariable
from angr.analyses.code_location import CodeLocation
import pyvex
from typing import List, Tuple, Dict, Optional
from networkx.classes.digraph import DiGraph


class MemTrack:
    """
    Class to contain results of a slice on a single CFG.
    """
    def __init__(self, rw: str, last_node: CodeLocation, reg: str):
        """

        """
        self.state = None
        self._rw = rw
        self._last_node = last_node
        self._reg = reg

    @property
    def desc(self) -> Tuple[str, int, str]:
        return (self._rw, self.inst_addr, self._reg)

    @property
    def inst_addr(self) -> int:
        return self._last_node.ins_addr

    @property
    def block_addr(self) -> int:
        return self._last_node.block_addr

    @property
    def stmt_idx(self) -> int:
        return self._last_node.stmt_idx

    def check_sat(self, concrete_value: int) -> bool:
        if self.state is None:
            raise Exception("State cannot be None")
        solver = self.state.solver
        reg = self.state.regs.get(self._reg)
        return solver.satisfiable([reg == concrete_value])


class MemTrackHolder:
    def __init__(self, memTrackObjects: List[MemTrack]):
        self._track_list = memTrackObjects

    def __contains__(self, item):
        """
        :param item: The block address to find
        :return: True if _track_list contains a MemTrack item from that block
        """
        for obj in self._track_list:
            if item == obj.block_addr:
                return True
        return False

    def indexes(self, block: int) -> List[int]:
        """

        :param block: Address of basic block
        :return: List of indexes in block
        """
        return [obj.stmt_idx for obj in self._track_list if obj.block_addr == block]

    @property
    def desc(self) -> List[Tuple[str, int, str]]:
        return [obj.desc for obj in self._track_list]

    def _get_by_inst_addr(self, addr: int) -> MemTrack:
        for obj in self._track_list:
            if obj.inst_addr == addr:
                return obj
        raise Exception("Invalid instruction address for MemTrack")

    def _get_by_block_idx(self, block: int, idx: int) -> MemTrack:
        for obj in self._track_list:
            if obj.block_addr == block and obj.stmt_idx == idx:
                return obj
        raise Exception("Invalid instruction address for MemTrack")

    def add_state(self, state: SimState, block_addr: Optional[int] = None,
                  stmt_idx: Optional[int] = None, inst_addr: Optional[int] = None):
        if (block_addr is None or stmt_idx is None) and inst_addr is None:
            raise Exception("Not enough arguments")

        if inst_addr is not None:
            obj = self._get_by_inst_addr(inst_addr)
            obj.state = state
        else:
            obj = self._get_by_block_idx(block_addr, stmt_idx)
            obj.state = state

    def validate(self, desc: List[Tuple[str, int, str, int]]) -> bool:
        """
        Validate the desc passed back during monitoring.
        :param desc: The new desc with the value appended to each Tuple
        :return: True if valid, False otherwise
        """
        for rw, addr, reg, value in desc:
            obj = self._get_by_inst_addr(addr)
            if not obj.check_sat(value):
                return False
        return True


class SliceStatement:
    def __init__(self, cl: CodeLocation, irsb: pyvex.block.IRSB):
        self.stmt = irsb.statements[cl.stmt_idx]
        self.cl = cl


class SliceConstraints:
    """
    Analyze paths in CFG and store MemTrack for each
    indirect control flow transfer.
    """
    def __init__(self, project: Project, cfg: CFGEmulated, target_addr: int):
        """
        Initialize a SliceConstraints object.
        :param project: angr project initialized with binary
        :param cfg: Control Flow Graph
        :param target_addr: Address of instruction with control flow transfer
        """
        self.p = project
        self._mem_manager = None
        self._final_state = None

        self._analyze(cfg, target_addr)

    def _analyze(self, cfg: CFGEmulated, target_addr: int):
        """
        Analyze a CFG containing a control flow transfer.
        :param cfg: Control Flow Graph
        :param target_addr: Address of instruction with control flow transfer
        """
        ddg = self.p.analyses.DDG(cfg)
        target_node = cfg.model.get_any_node(target_addr, anyaddr=True)
        stmtId = self._getStmtId(target_node.addr)

        # Get data dependency predicates
        cl = CodeLocation(target_node.addr, stmtId)

        # Handle DDG analyses
        dep_graph = ddg.graph
        final_deps, pruned_ddg = self._prune_ddg(dep_graph, cl)
        slice_stmts, tyenv = self._process_slice(final_deps)
        bb_order, tracking = self._analyze_ddg(pruned_ddg)
        self._mem_manager = MemTrackHolder(tracking)

        # Create new state for symbolic execution
        slice_state = self.p.factory.blank_state()
        self.final_state = self._symbolic_exec(slice_state, bb_order, tyenv, slice_stmts)

    def get_descriptor(self) -> List[Tuple[str, int, str, int]]:
        """
        Get a descriptor of the reads/writes in the slice.
        :return: Read/write addresses and register names
        """
        return self._mem_manager.desc

    def test_values(self, new_desc: List[Tuple[str, int, str, int]]) -> bool:
        """
        Validate the desc passed back during monitoring.
        :param new_desc: The new desc with the value appended to each Tuple
        :return: True if valid, False otherwise
        """
        return self._mem_manager.validate(new_desc)

    @property
    def constraints(self):
        raise Exception("Not implemented")

    def _getStmtId(self, address: int) -> int:
        # Get vex representation of block
        bb_vex = self.p.factory.block(address, opt_level=0).vex

        # Get the stmt id of the statement beyond the last
        return len(bb_vex.statements)

    def _prune_ddg(self, dep_graph: DiGraph, cl: CodeLocation) -> Tuple[List[CodeLocation],
                                                                        DiGraph]:
        pruned_ddg = deepcopy(dep_graph)

        # Remove rbp, rsp, and __libc_start_main__ edges in pruned_ddg
        rbp = SimRegisterVariable(56, 8)
        rsp = SimRegisterVariable(48, 8)

        for src, dst, data in dep_graph.edges(data=True):
            if data['type'] == 'reg':
                if str(type(src.sim_procedure)) == "class <angr.procedures.glibc" \
                                                   ".__libc_start_main.__libc_start_main'>":
                    start_edge = True
                else:
                    start_edge = False
                if data['data'] == rbp or data['data'] == rsp or start_edge:
                    # Remove edge
                    if src.sim_procedure is not None:
                        src = self._find_sim_proc_node(src, pruned_ddg)
                    if dst.sim_procedure is not None:
                        dst = self._find_sim_proc_node(dst, pruned_ddg)
                    pruned_ddg.remove_edge(src, dst)

        # Remove non-dependency nodes from pruned_ddg
        all_preds = nx.ancestors(dep_graph, cl)
        all_preds.add(cl)

        for node in dep_graph:
            if node not in all_preds:
                # Equality check does not work for copies of
                # CodeLocations that represent SimProcedures
                if node.sim_procedure is not None:
                    to_prune = self._find_sim_proc_node(node, pruned_ddg)
                    pruned_ddg.remove_node(to_prune)
                else:
                    pruned_ddg.remove_node(node)

        # Get final dependency list
        # TODO: Remove vex at target address
        final_deps = nx.ancestors(pruned_ddg, cl)

        # TODO: Remove this
        for node in dep_graph:
            if node not in final_deps:
                # Equality check does not work for copies of
                # CodeLocations that represent SimProcedures
                if node.sim_procedure is not None:
                    to_prune = self._find_sim_proc_node(node, pruned_ddg)
                    try:
                        pruned_ddg.remove_node(to_prune)
                    except nx.NetworkXError:
                        pass
                else:
                    try:
                        pruned_ddg.remove_node(node)
                    except nx.NetworkXError:
                        pass

        return final_deps, pruned_ddg

    def _get_imark_for_vex_idx(self, irsb: pyvex.block.IRSB, cl: CodeLocation) -> SliceStatement:
        last_imark = None
        for i, stmt in enumerate(irsb.statements):
            if isinstance(stmt, pyvex.IRStmt.IMark):
                imark_cl = CodeLocation(cl.block_addr, i, ins_addr=stmt.addr)
                last_imark = SliceStatement(imark_cl, irsb)
            if i == cl.stmt_idx:
                return last_imark

    def _process_slice(self, final_deps: List[CodeLocation]) ->\
            Tuple[Dict[int, List[SliceStatement]], Dict[int, pyvex.block.IRTypeEnv]]:
        # Get sliced vex statements and tyenv per irsb
        slice_stmts = {}
        tyenv = {}

        imark_list = []

        for dep in sorted(final_deps, key=lambda x: x.stmt_idx):
            irsb = self.p.factory.block(dep.block_addr, opt_level=0).vex
            stmt = SliceStatement(dep, irsb)

            # Handle IMarks
            imark = self._get_imark_for_vex_idx(irsb, dep)
            if imark.stmt.addr not in imark_list:
                imark_list.append(imark.stmt.addr)
            else:
                imark = None

            # Append results
            if dep.block_addr in slice_stmts:
                if imark is not None:
                    slice_stmts[dep.block_addr].append(imark)
                slice_stmts[dep.block_addr].append(stmt)
            else:
                if imark is not None:
                    slice_stmts[dep.block_addr] = [imark, stmt]
                else:
                    slice_stmts[dep.block_addr] = [stmt]
                tyenv[dep.block_addr] = irsb.tyenv

        return slice_stmts, tyenv

    def _get_reg(self, node):
        irsb = self.p.factory.block(node.block_addr, opt_level=0).vex
        stmt = irsb.statements[node.stmt_idx]
        register = irsb.arch.translate_register_name(stmt.offset,
                                                     stmt.data.result_size(irsb.tyenv) // 8)
        return register

    def _read_pattern(self, edge_1, edge_2, edge_3, reg_node):
        # Pattern:
        # 1 - Data: X, Subtype: mem_addr, Type: tmp
        # 2 - Data: X, Subtype: None, Type: tmp
        # 3 - Data: X, Subtype: None, Type: reg
        if edge_1 is None or edge_2 is None or edge_3 is None:
            return False, None

        matches = [False, False, False]

        if 'subtype' in edge_1.keys():
            if edge_1['type'] == 'tmp':
                if 'mem_addr' in edge_1['subtype']:
                    matches[0] = True

        if edge_2['type'] == 'tmp':
            matches[1] = True

        if edge_3['type'] == 'reg':
            matches[2] = True

        result = matches[0] and matches[1] and matches[2]

        if result:
            register = self._get_reg(reg_node)
        else:
            register = None

        return result, register

    def _write_pattern(self, edge_1, edge_2, reg_node):
        # Pattern:
        # 1 - Data: X, Subtype: None, Type: reg
        # 2 - Data: X, Subtype: mem_data, Type: tmp
        if edge_1 is None or edge_2 is None:
            return False, None

        matches = [False, False]

        if edge_1['type'] == 'reg':
            matches[0] = True

        if 'subtype' in edge_2.keys():
            if edge_2['type'] == 'tmp':
                if 'mem_data' in edge_2['subtype']:
                    matches[1] = True

        result = matches[0] and matches[1]

        if result:
            register = self._get_reg(reg_node)
        else:
            register = None

        return result, register

    def _analyze_path(self, ddg: DiGraph, first_node: CodeLocation) -> Tuple[List[int],
                                                                             List[MemTrack]]:
        curr_node = first_node
        curr_edge = None
        prev_node = None
        bb_order = []
        edge_history = [None, None, None]
        node_history = [None, None]
        tracking = []

        # Iterate through nodes in path
        while True:
            # print(curr_node)
            # Track basic block visit order
            if curr_node.block_addr not in bb_order:
                bb_order.append(curr_node.block_addr)

            # Pattern matching
            edge_history[0] = edge_history[1]
            edge_history[1] = edge_history[2]
            edge_history[2] = curr_edge

            node_history[0] = node_history[1]
            node_history[1] = prev_node

            is_write, write_reg = self._write_pattern(edge_history[1], edge_history[2],
                                                      node_history[0])
            is_read, read_reg = self._read_pattern(edge_history[0], edge_history[1],
                                                   edge_history[2], node_history[1])

            if is_write:
                # print('Write', write_reg, 'at', hex(prev_node.ins_addr), 'on path', first_node)
                write = MemTrack('write', prev_node, write_reg)
                tracking.append(write)
            if is_read:
                # print('Read', read_reg, 'at', hex(prev_node.ins_addr), 'on path', first_node)
                read = MemTrack('read', prev_node, read_reg)
                tracking.append(read)

            # Get next node and edge if not at end of graph
            try:
                prev_node = curr_node
                curr_node = next(ddg.successors(prev_node))
                curr_edge = ddg.edges[prev_node, curr_node]
            except StopIteration:
                break

        return bb_order, tracking

    def _merge_bb_orders(self, order_1, order_2):
        if len(order_1) == 0:
            return order_2

        new_bb_order = []
        new_bb_order.extend(order_1)

        last_merge = -1
        for i in range(len(order_2)):
            if order_2[i] in order_1:
                if i > last_merge+1:
                    pos = new_bb_order.index(order_2[i])
                    for j in range(last_merge+1, i):
                        new_bb_order.insert(pos, order_2[j])
                        pos += 1
                last_merge = i

        return new_bb_order

    def _analyze_ddg(self, ddg: DiGraph) -> Tuple[List[int], List[MemTrack]]:
        # Find starting nodes
        starting_nodes = []
        for node, degree in ddg.in_degree():
            if degree == 0:
                starting_nodes.append(node)

        bb_order = []
        track_data = []

        # Traverse graph from start to end
        for node in starting_nodes:
            path_bb_order, path_tracking = self._analyze_path(ddg, node)
            bb_order = self._merge_bb_orders(bb_order, path_bb_order)
            track_data.extend(path_tracking)

        return bb_order, track_data

    def _step_irsb(self, stmts: List[pyvex.block.IRSB],
                   tyenv: pyvex.block.IRTypeEnv, state: SimState) -> SimState:
        custom_irsb = pyvex.IRSB.empty_block(self.p.arch, 0x500000,
                                             statements=stmts,
                                             size=len(stmts))

        # Make tyenv from previous tyenv data
        custom_irsb.tyenv = tyenv

        # Need to whitelist all statements if no exit specified
        whitelist = list(range(len(stmts)))

        # Custom stepping with new IRSB
        successors = state.step(irsb=custom_irsb, whitelist=whitelist)

        if len(successors.flat_successors) != 1:
            raise Exception("Too many states")

        return successors[0]

    def _symbolic_exec(self, slice_state: SimState, bb_order, tyenv,
                       slice_stmts: Dict[int, List[SliceStatement]]):
        # Concretize rbp and rsp since their actual values don't matter
        slice_state.regs.rbp = 0x600000
        slice_state.regs.rsp = 0x700000

        new_state = slice_state

        # Get successors of states for each irsb and generate intermediate states
        # using "step iteration"
        for block in bb_order:
            split_idx = self._mem_manager.indexes(block)
            for idx in split_idx:
                statements = [obj.stmt for obj in slice_stmts[block] if obj.cl.stmt_idx <= idx]
                saved_state = self._step_irsb(statements, tyenv[block], new_state)
                self._mem_manager.add_state(saved_state, block_addr=block, stmt_idx=idx)
            all_statements = [obj.stmt for obj in slice_stmts[block]]
            new_state = self._step_irsb(all_statements, tyenv[block], new_state)

        return new_state

    def _find_sim_proc_node(self, cl, graph):
        sim_proc_node = None
        for node in graph:
            if str(node) == str(cl):
                sim_proc_node = node
        return sim_proc_node
