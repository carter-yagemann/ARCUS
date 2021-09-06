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
import logging

import angr
import networkx

log = logging.getLogger(name=__name__)

def rewind(preds, condition):
    """Rewind trace until a condition becomes true.

    Keyword Args:
    preds -- A list of predecessor states to rewind.
    condition -- Keep rewinding until this is true. Can be either an integer
    address or a lambda function that takes a state and returns a boolean.

    Returns:
    A tuple containing the state where the condition became true and a list
    of its predecessors. If no states satisfy the condition, returns (None, []).
    The returned list of predecessors is always a strict prefix of the original.
    """
    if isinstance(condition, int):
        target = int(condition)
        condition = lambda state: state.addr == target
    if not callable(condition):
        log.error("Condition isn't callable")
        return (None, [])

    preds = preds.copy()  # avoid modifying original list
    while len(preds) > 0:
        next = preds.pop()
        if condition(next):
            return (next, preds)

    # if this point is reached, we failed to find a state
    # that satisfies the condition
    return (None, [])

def forward(preds, condition):
    """Similar to rewind, except starts at the beginning and iterates forward
    until a condition becomes true.

    Keyword Args:
    preds -- A list of predecessor states to fast-forward.
    condition -- Keep forwarding until this is true. Can be either an integer
    address or a lambda function that takes a state and returns a boolean.

    Returns:
    A tuple containing the state where the condition became true and a list
    of its predecessors. If no states satisfy the condition, returns (None, []).
    The returned list of predecessors is always a strict prefix of the original.
    """
    if isinstance(condition, int):
        target = int(condition)
        condition = lambda state: state.addr == target
    if not callable(condition):
        log.error("Condition isn't callable")
        return (None, [])

    new_preds = list()
    for next in preds:
        if condition(next):
            return (next, new_preds)

        new_preds.append(next)

    # if this point is reached, we failed to find a state
    # that satisfies the condition
    return (None, [])

def find_all_preds(preds, condition):
    """Similar to rewind, except returns a list of (state, preds) tuples
    for all states that satisfy the condition.

    Keyword Args:
    preds -- A list of predecessor states to search.
    condition -- Condition to satisfy. Can be either an integer address or a
    lambda function that takes a state and returns a boolean.

    Returns:
    A list of tuples where each tuple is a state and its predecessors.
    """
    if isinstance(condition, int):
        target = int(condition)
        condition = lambda state: state.addr == target
    if not callable(condition):
        log.error("Condition isn't callable")
        return (None, [])

    matches = list()
    curr_preds = list()
    for next in preds:
        if condition(next):
            matches.append([next, curr_preds.copy()])

        curr_preds.append(next)

    return matches

def simple_cfg(addrs):
    """Create a simple CFG from a linear sequence of addresses.

    This is just a simple networkx graph without any of the fancy
    state appending, metadata, or context sensitivity associated
    with a full angr CFG.

    Keyword Args:
    addrs -- A list of addresses.

    Returns:
    A networkx directed graph with attributes "start" and "end"
    to mark the starting and ending nodes based on the list. If
    list is empty, returns None.
    """
    if len(addrs) < 1:
        return None

    graph = networkx.DiGraph(start=addrs[0], end=addrs[-1])
    for idx, addr in enumerate(addrs):
        if not addr in graph.nodes:
            graph.add_node(addr)
        if idx > 0:  # first node has no predecessor
            graph.add_edge(addrs[idx - 1], addr)

    return graph
