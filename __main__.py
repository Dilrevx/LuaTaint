"""The comand line module of LuaTaint."""
import logging
import os
import sys
import time
import re
import psutil
from collections import defaultdict
import tqdm

from analysis.constraint_table import initialize_constraint_table
from analysis.fixed_point import analyse
from cfg import make_cfg
from core.ast_helper import generate_ast
from core.project_handler import (
    get_directory_modules,
    get_modules
)
from usage import parse_args
from vulnerabilities import (
    find_vulnerabilities,
    get_vulnerabilities_not_in_baseline,
    filter_non_external_inputs
)
from vulnerabilities.vulnerability_helper import SanitisedVulnerability
from web_frameworks import (
    FrameworkAdaptor,
    is_django_view_function,
    is_luci_route_function,
    is_function,
    is_function_without_leading_
)
log = logging.getLogger(__name__)

def discover_files(targets, excluded_files, recursive=False):
    included_files = list()
    excluded_list = excluded_files.split(",")
    for target in targets:
        if os.path.isdir(target):
            for root, _, files in os.walk(target):
                for file in files:
                    if file.endswith('.lua') and file not in excluded_list:
                        fullpath = os.path.join(root, file)
                        included_files.append(fullpath)
                        log.debug('Discovered file: %s', fullpath)
                if not recursive:
                    break
        else:
            if target not in excluded_list:
                included_files.append(target)
                log.debug('Discovered file: %s', target)
    return included_files

def retrieve_nosec_lines(
    path
):
    file = open(path, 'r',encoding='utf-8', errors = 'ignore')
    lines = file.readlines()


    return set(
        lineno for
        (lineno, line) in enumerate(lines, start=1)
        if '#nosec' in line or '# nosec' in line
    )

def main(command_line_args=sys.argv[1:]):  # noqa: C901
    args = parse_args(command_line_args)
    logging_level = (
        logging.ERROR if not args.verbose else
        logging.WARN if args.verbose == 1 else
        logging.INFO if args.verbose == 2 else
        logging.DEBUG
    )
    logging.basicConfig(level=logging_level, format='[%(levelname)s] %(name)s: %(message)s')

    files = discover_files(
        args.targets,
        args.excluded_paths,
        True
    )

    nosec_lines = defaultdict(set)

    if args.project_root:
        directory = os.path.normpath(args.project_root)
        project_modules = get_modules(directory, prepend_module_root=args.prepend_module_root)
        #print(project_modules)
    
    cfg_list = list()
    results = list()
    for path in tqdm.tqdm(sorted(files)):
        #cfg_list = list()
        log.info("Processing %s", path)
        if not args.ignore_nosec:
            nosec_lines[path] = retrieve_nosec_lines(path)

        if not args.project_root:
            directory = os.path.dirname(path)
            project_modules = get_modules(directory, prepend_module_root=args.prepend_module_root)

        local_modules = get_directory_modules(directory)
        tree = generate_ast(path,args.project_root)
        
        cfg = make_cfg(
            tree,
            project_modules,
            local_modules,
            path,
            args.project_root,
            allow_local_directory_imports=args.allow_local_imports
        )
        cfg_list = [cfg]
        
        framework_entry_criteria = is_luci_route_function

        # Add all the route functions to the cfg_list
        FrameworkAdaptor(
            cfg_list,
            project_modules,
            local_modules,
            framework_entry_criteria,
            args.project_root
        )
        print(len(cfg_list))
    #'''
        initialize_constraint_table(cfg_list)
        log.info("Analysing")
        analyse(cfg_list)
        log.info("Finding vulnerabilities")
    
        vulnerabilities = find_vulnerabilities(
            cfg_list,
            args.blackbox_mapping_file,
            args.trigger_word_file,
            args.interactive,
            nosec_lines
        )
        filter_non_external_inputs(vulnerabilities)
        print(vulnerabilities)
        results.extend(vulnerabilities)

    if args.baseline:
        results = get_vulnerabilities_not_in_baseline(
            results,
            args.baseline
        )
        
    args.formatter.report(results, args.output_file, args.only_unsanitised)
    #'''

    '''has_unsanitised_vulnerabilities = any(
        not isinstance(v, SanitisedVulnerability)
        for v in vulnerabilities
    )
    
    if has_unsanitised_vulnerabilities:
        sys.exit(1)'''


if __name__ == '__main__':
    main()
