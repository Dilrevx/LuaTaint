"""Module for finding vulnerabilities based on a definitions file."""

from lua_parser import ast
import json
from collections import defaultdict

from analysis.definition_chains import build_def_use_chain
from analysis.lattice import Lattice
from core.node_types import (
    AssignmentNode,
    BBorBInode,
    IfNode,
    TaintedNode
)
from helper_visitors import (
    CallVisitor,
    RHSVisitor,
    VarsVisitor
)
from .trigger_definitions_parser import parse, Source
from .vulnerability_helper import (
    Sanitiser,
    TriggerNode,
    Triggers,
    vuln_factory,
    VulnerabilityType
)


def identify_triggers(
    cfg,
    sources,
    sinks,
    lattice,
    nosec_lines
):
    """Identify sources, sinks and sanitisers in a CFG.

    Args:
        cfg(CFG): CFG to find sources, sinks and sanitisers in.
        sources(tuple): list of sources, a source is a (source, sanitiser) tuple.
        sinks(tuple): list of sources, a sink is a (sink, sanitiser) tuple.
        nosec_lines(set): lines with # nosec whitelisting

    Returns:
        Triggers tuple with sink and source nodes and a sanitiser node dict.
    """
    assignment_nodes = filter_cfg_nodes(cfg, AssignmentNode)
    tainted_nodes = filter_cfg_nodes(cfg, TaintedNode)
    tainted_trigger_nodes = [
        TriggerNode(
            Source('Framework function URL parameter'),
            cfg_node=node
        ) for node in tainted_nodes
    ]
    sources_in_file = find_triggers(assignment_nodes, sources, nosec_lines)
    sources_in_file.extend(tainted_trigger_nodes)

    find_secondary_sources(assignment_nodes, sources_in_file, lattice)

    sinks_in_file = find_triggers(cfg.nodes, sinks, nosec_lines)

    sanitiser_node_dict = build_sanitiser_node_dict(cfg, sinks_in_file)

    return Triggers(sources_in_file, sinks_in_file, sanitiser_node_dict)


def filter_cfg_nodes(
    cfg,
    cfg_node_type
):
    return [node for node in cfg.nodes if isinstance(node, cfg_node_type)]


def find_secondary_sources(
    assignment_nodes,
    sources,
    lattice
):
    """
        Sets the secondary_nodes attribute of each source in the sources list.

        Args:
            assignment_nodes([AssignmentNode])
            sources([tuple])
            lattice(Lattice): the lattice we're analysing.
    """
    for source in sources:
        source.secondary_nodes = find_assignments(assignment_nodes, source, lattice)


def find_assignments(
    assignment_nodes,
    source,
    lattice
):
    old = list()
    # propagate reassignments of the source node
    new = [source.cfg_node]

    while new != old:
        update_assignments(new, assignment_nodes, source.cfg_node, lattice)
        old = new

    # remove source node from result
    del new[0]

    return new

class Index:
    def __init__(self, idx, value):
        self.idx = idx
        self.value = value

def access_innermost_index(node):
    """Recursively access the innermost idx and value of an Index type."""
    # Base case: if both idx and value are not of Index type, return them as is
    if not isinstance(node.idx, ast.Index) and not isinstance(node.value, ast.Index):
        return node.idx, node.value
    # Recursive case: if idx is of Index type, dive deeper
    if isinstance(node.idx, ast.Index):
        idx_id, _ = access_innermost_index(node.idx)
    else:
        idx_id = node.idx  # idx is already at the innermost id
    # Recursive case: if value is of Index type, dive deeper
    if isinstance(node.value, ast.Index):
        _, value_id = access_innermost_index(node.value)
    else:
        value_id = node.value  # value is already at the innermost id
    return idx_id, value_id

def trace_tablevariable_idx(node):
    taint_id = list()
    if not isinstance(node, ast.Return):
        if hasattr(node, "values") and isinstance(node.values, list) and len(node.values)!=0 and isinstance(node.values[0], ast.Table):
            if isinstance(node.targets, list) and len(node.targets)!=0:
                if isinstance(node.targets[0], ast.Name):
                    taint_id.append(node.targets[0].id)
                elif isinstance(node.targets[0], ast.Index):
                    idx_id, value_id = access_innermost_index(node.targets[0])
                    taint_id.append(idx_id)
                    taint_id.append(value_id)
            for field in node.values[0].fields:
                if not isinstance(field.value, ast.String) and isinstance(field.key, ast.Name):
                    taint_id.append(field.key.id)
                if not isinstance(field.value, ast.String) and isinstance(field.key, ast.Number):
                    taint_id.append(field.key.n)
                return taint_id
    return None

def update_assignments(
    assignment_list,
    assignment_nodes,
    source,
    lattice
):
    table_tainted_id=list()
    for node in assignment_nodes:
        for other in assignment_list:
            if node not in assignment_list and lattice.in_constraint(other, node):
                tainted_id=trace_tablevariable_idx(node.ast_node)
                if tainted_id != None:
                    table_tainted_id.append(tainted_id) 
                append_node_if_reassigned(assignment_list, other, node, table_tainted_id)


def append_node_if_reassigned(
    assignment_list,
    secondary,
    node,
    table_tainted_id
):
    if secondary.left_hand_side in node.right_hand_side_variables:
        if secondary.left_hand_side == node.right_hand_side_variables[-1] and len(node.right_hand_side_variables)>1:
            for i in node.right_hand_side_variables[:-1]:
                if any(i in sublist for sublist in node.right_hand_side_variables[1:]):
                    assignment_list.append(node)
        else: assignment_list.append(node)
    elif secondary.left_hand_side == node.left_hand_side:
        assignment_list.append(node)


def find_triggers(
    nodes,
    trigger_words,
    nosec_lines
):
    """Find triggers from the trigger_word_list in the nodes.

    Args:
        nodes(list[Node]): the nodes to find triggers in.
        trigger_word_list(list[Union[Sink, Source]]): list of trigger words to look for.
        nosec_lines(set): lines with # nosec whitelisting

    Returns:
        List of found TriggerNodes
    """
    trigger_nodes = list()
    for node in nodes:
        if node.line_number not in nosec_lines:
            trigger_nodes.extend(iter(label_contains(node, trigger_words)))
    return trigger_nodes


def label_contains(
    node,
    triggers
):
    """Determine if node contains any of the trigger_words provided.

    Args:
        node(Node): CFG node to check.
        trigger_words(list[Union[Sink, Source]]): list of trigger words to look for.

    Returns:
        Iterable of TriggerNodes found. Can be multiple because multiple
        trigger_words can be in one node.
    """
    for trigger in triggers:
        if trigger.trigger_word in node.label:
            yield TriggerNode(trigger, node)


def build_sanitiser_node_dict(
    cfg,
    sinks_in_file
):
    """Build a dict of string -> TriggerNode pairs, where the string
       is the sanitiser and the TriggerNode is a TriggerNode of the sanitiser.

    Args:
        cfg(CFG): cfg to traverse.
        sinks_in_file(list[TriggerNode]): list of TriggerNodes containing
                                          the sinks in the file.

    Returns:
        A string -> TriggerNode dict.
    """
    sanitisers = list()
    for sink in sinks_in_file:
        sanitisers.extend(sink.sanitisers)

    sanitisers_in_file = list()
    for sanitiser in sanitisers:
        for cfg_node in cfg.nodes:
            if sanitiser in cfg_node.label:
                sanitisers_in_file.append(Sanitiser(sanitiser, cfg_node))

    sanitiser_node_dict = dict()
    for sanitiser in sanitisers:
        sanitiser_node_dict[sanitiser] = list(find_sanitiser_nodes(
            sanitiser,
            sanitisers_in_file
        ))
    return sanitiser_node_dict


def find_sanitiser_nodes(
    sanitiser,
    sanitisers_in_file
):
    """Find nodes containing a particular sanitiser.

    Args:
        sanitiser(string): sanitiser to look for.
        sanitisers_in_file(list[Node]): list of CFG nodes with the sanitiser.

    Returns:
        Iterable of sanitiser nodes.
    """
    for sanitiser_tuple in sanitisers_in_file:
        if sanitiser == sanitiser_tuple.trigger_word:
            yield sanitiser_tuple.cfg_node


def get_sink_args(cfg_node):
    if isinstance(cfg_node.ast_node, ast.Call):
        rhs_visitor = RHSVisitor()
        rhs_visitor.visit(cfg_node.ast_node)
        return rhs_visitor.result
    elif isinstance(cfg_node.ast_node, ast.Assign):
        return cfg_node.right_hand_side_variables
    elif isinstance(cfg_node, BBorBInode):
        return cfg_node.args
    else:
        vv = VarsVisitor()
        vv.visit(cfg_node.ast_node)
        return vv.result


def get_sink_args_which_propagate(sink, ast_node):
    sink_args_with_positions = CallVisitor.get_call_visit_results(sink.trigger.call, ast_node)
    sink_args = []
    kwargs_present = set()

    for i, vars in enumerate(sink_args_with_positions.args):
        kwarg = sink.trigger.get_kwarg_from_position(i)
        if kwarg:
            kwargs_present.add(kwarg)
        if sink.trigger.kwarg_propagates(kwarg):
            sink_args.extend(vars)

    for keyword, vars in sink_args_with_positions.kwargs.items():
        kwargs_present.add(keyword)
        if sink.trigger.kwarg_propagates(keyword):
            sink_args.extend(vars)

    if (
        # Either any unspecified kwarg propagates
        not sink.trigger.arg_list_propagates or
        # or there are some propagating kwargs which have not been passed by keyword
        sink.trigger.kwarg_list - kwargs_present
    ):
        sink_args.extend(sink_args_with_positions.unknown_args)
        sink_args.extend(sink_args_with_positions.unknown_kwargs)

    return sink_args


def get_vulnerability_chains(current_node, sink, def_use, chain=[], visited=None):
    """Traverses the def-use graph to find all paths from source to sink that cause a vulnerability.

    Args:
        current_node()
        sink()
        def_use(dict):
        chain(list(Node)): A path of nodes between source and sink.
    """
    if visited is None:
        visited = set()  # Initialize visited set in the first call
    visited.add(current_node)

    for use in def_use[current_node]:
        if use == sink:
            yield chain + [use]
        elif use not in visited:  # Only recurse if we haven't visited the node yet
            vuln_chain = list(chain)
            vuln_chain.append(use)
            yield from get_vulnerability_chains(
                use,
                sink,
                def_use,
                vuln_chain,
                visited.copy()  # Pass a copy of visited to the recursive call
            )


def how_vulnerable(
    chain,
    blackbox_mapping,
    sanitiser_nodes,
    potential_sanitiser,
    blackbox_assignments,
    interactive,
    vuln_deets
):
    """Iterates through the chain of nodes and checks the blackbox nodes against the blackbox mapping and sanitiser dictionary.

    Note: potential_sanitiser is the only hack here, it is because we do not take p-use's into account yet.
    e.g. we can only say potentially instead of definitely sanitised in the path_traversal_sanitised_2.py test.

    Args:
        chain(list(Node)): A path of nodes between source and sink.
        blackbox_mapping(dict): A map of blackbox functions containing whether or not they propagate taint.
        sanitiser_nodes(set): A set of nodes that are sanitisers for the sink.
        potential_sanitiser(Node): An if or elif node that can potentially cause sanitisation.
        blackbox_assignments(set[AssignmentNode]): set of blackbox assignments, includes the ReturnNode's of BBorBInode's.
        interactive(bool): determines if we ask the user about blackbox functions not in the mapping file.
        vuln_deets(dict): vulnerability details.

    Returns:
        A VulnerabilityType depending on how vulnerable the chain is.
    """
    for i, current_node in enumerate(chain):
        if current_node in sanitiser_nodes:
            vuln_deets['sanitiser'] = current_node
            vuln_deets['confident'] = True
            return VulnerabilityType.SANITISED, interactive

        if isinstance(current_node, BBorBInode):
            if current_node.func_name in blackbox_mapping['propagates']:
                continue
            elif current_node.func_name in blackbox_mapping['does_not_propagate']:
                return VulnerabilityType.FALSE, interactive
            elif interactive:
                user_says = input(
                    'Is the return value of {} with tainted argument "{}" vulnerable? ([Y]es/[N]o/[S]top asking)'.format(
                        current_node.label,
                        chain[i - 1].left_hand_side
                    )
                ).lower()
                if user_says.startswith('s'):
                    interactive = False
                    vuln_deets['unknown_assignment'] = current_node
                    return VulnerabilityType.UNKNOWN, interactive
                if user_says.startswith('n'):
                    blackbox_mapping['does_not_propagate'].append(current_node.func_name)
                    return VulnerabilityType.FALSE, interactive
                blackbox_mapping['propagates'].append(current_node.func_name)
            else:
                vuln_deets['unknown_assignment'] = current_node
                return VulnerabilityType.UNKNOWN, interactive

    if potential_sanitiser:
        vuln_deets['sanitiser'] = potential_sanitiser
        vuln_deets['confident'] = False
        return VulnerabilityType.SANITISED, interactive

    return VulnerabilityType.TRUE, interactive


def get_tainted_node_in_sink_args(
    sink_args,
    nodes_in_constraint
):
    if not sink_args:
        return None
    # Starts with the node closest to the sink
    for node in nodes_in_constraint:
        if node.left_hand_side in sink_args:
            return node


def get_vulnerability(
    source,
    sink,
    triggers,
    lattice,
    cfg,
    interactive,
    blackbox_mapping
):
    """Get vulnerability between source and sink if it exists.

    Uses triggers to find sanitisers.

    Note: When a secondary node is in_constraint with the sink
              but not the source, the secondary is a save_N_LHS
              node made in process_function in expr_visitor.

    Args:
        source(TriggerNode): TriggerNode of the source.
        sink(TriggerNode): TriggerNode of the sink.
        triggers(Triggers): Triggers of the CFG.
        lattice(Lattice): the lattice we're analysing.
        cfg(CFG): .blackbox_assignments used in is_unknown, .nodes used in build_def_use_chain
        interactive(bool): determines if we ask the user about blackbox functions not in the mapping file.
        blackbox_mapping(dict): A map of blackbox functions containing whether or not they propagate taint.

    Returns:
        A Vulnerability if it exists, else None
    """
    nodes_in_constraint = [
        secondary
        for secondary in reversed(source.secondary_nodes)
        if lattice.in_constraint(
            secondary,
            sink.cfg_node
        )
    ]
    nodes_in_constraint.append(source.cfg_node)
    if sink.trigger.all_arguments_propagate_taint:
        sink_args = get_sink_args(sink.cfg_node)
    else:
        sink_args = get_sink_args_which_propagate(sink, sink.cfg_node.ast_node)

    tainted_node_in_sink_arg = get_tainted_node_in_sink_args(
        sink_args,
        nodes_in_constraint,
    )

    if tainted_node_in_sink_arg:
        vuln_deets = {
            'source': source.cfg_node,
            'source_trigger_word': source.trigger_word,
            'sink': sink.cfg_node,
            'sink_trigger_word': sink.trigger_word
        }

        sanitiser_nodes = set()
        potential_sanitiser = None
        if sink.sanitisers:
            for sanitiser in sink.sanitisers:
                for cfg_node in triggers.sanitiser_dict[sanitiser]:
                    if isinstance(cfg_node, AssignmentNode):
                        sanitiser_nodes.add(cfg_node)
                    elif isinstance(cfg_node, IfNode):
                        potential_sanitiser = cfg_node

        def_use = build_def_use_chain(
            cfg.nodes,
            lattice
        )

        for chain in get_vulnerability_chains(
            source.cfg_node,
            sink.cfg_node,
            def_use
        ):
            vulnerability_type, interactive = how_vulnerable(
                chain,
                blackbox_mapping,
                sanitiser_nodes,
                potential_sanitiser,
                cfg.blackbox_assignments,
                interactive,
                vuln_deets
            )
            if vulnerability_type == VulnerabilityType.FALSE:
                continue

            vuln_deets['reassignment_nodes'] = chain

            return vuln_factory(vulnerability_type)(**vuln_deets), interactive

    return None, interactive


def find_vulnerabilities_in_cfg(
    cfg,
    definitions,
    lattice,
    blackbox_mapping,
    vulnerabilities_list,
    interactive,
    nosec_lines
):
    """Find vulnerabilities in a cfg.

    Args:
        cfg(CFG): The CFG to find vulnerabilities in.
        definitions(trigger_definitions_parser.Definitions): Source and sink definitions.
        lattice(Lattice): the lattice we're analysing.
        blackbox_mapping(dict): A map of blackbox functions containing whether or not they propagate taint.
        vulnerabilities_list(list): That we append to when we find vulnerabilities.
        interactive(bool): determines if we ask the user about blackbox functions not in the mapping file.
    """
    triggers = identify_triggers(
        cfg,
        definitions.sources,
        definitions.sinks,
        lattice,
        nosec_lines[cfg.filename]
    )
    for sink in triggers.sinks:
        for source in triggers.sources:
            vulnerability, interactive = get_vulnerability(
                source,
                sink,
                triggers,
                lattice,
                cfg,
                interactive,
                blackbox_mapping
            )
            if vulnerability:
                vulnerabilities_list.append(vulnerability)


def find_vulnerabilities(
    cfg_list,
    blackbox_mapping_file,
    sources_and_sinks_file,
    interactive=False,
    nosec_lines=defaultdict(set)
):
    """Find vulnerabilities in a list of CFGs from a trigger_word_file.

    Args:
        cfg_list(list[CFG]): the list of CFGs to scan.
        blackbox_mapping_file(str)
        sources_and_sinks_file(str)
        interactive(bool): determines if we ask the user about blackbox functions not in the mapping file.
    Returns:
        A list of vulnerabilities.
    """
    vulnerabilities = list()
    definitions = parse(sources_and_sinks_file)

    with open(blackbox_mapping_file) as infile:
        blackbox_mapping = json.load(infile)
    for cfg in cfg_list:
        find_vulnerabilities_in_cfg(
            cfg,
            definitions,
            Lattice(cfg.nodes),
            blackbox_mapping,
            vulnerabilities,
            interactive,
            nosec_lines
        )

    if interactive:
        with open(blackbox_mapping_file, 'w') as outfile:
            json.dump(blackbox_mapping, outfile, indent=4)

    return vulnerabilities
