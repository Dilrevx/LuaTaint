"""This module contains helper function.
Useful when working with the ast module."""

from lua_parser import ast
import logging
import os
import re
import subprocess
from functools import lru_cache

#from .transformer import PytTransformer

log = logging.getLogger(__name__)
#BLACK_LISTED_CALL_NAMES = ['self']
recursive = False
line_mapping = dict()

def remove_escape_chars(lua_code):
    # Define a regular expression pattern to match unnecessary and incorrect escape characters
    pattern = r'(?<!\\)(?:\\\\)*\\(?![\nnrtfb\'"\\])'
    #pattern = r'(?<!\\)\\(?![\nnrtfb\'"\\])'
    '''To explain the regular expression pattern used in this function:
    (?<!\\) is a negative lookbehind assertion that matches any position that is not preceded by a backslash character.
    (?:\\\\)* is a non-capturing group that matches zero or more occurrences of two backslash characters (i.e. an escaped backslash).
    \\ matches a single backslash character.
    (?![nrt\'"\\]) is a negative lookahead assertion that matches any position that is not followed by one of the characters n, r, t, ', ", or \.'''
    # Use the re.sub() function to replace all matches of the pattern with an empty string
    cleaned_code = re.sub(pattern, '', lua_code)
    return cleaned_code
@lru_cache()
def generate_ast(path,project_root):
    """Generate an Abstract Syntax Tree using the ast module.

        Args:
            path(str): The path to the file e.g. example/foo/bar.py
    """
    if os.path.isfile(path):
        with open(path, 'r',encoding='utf-8', errors = 'ignore') as f:
            txt = f.read()
            cleaned_code = remove_escape_chars(txt)
            rendered_mapping=dict()
            def replace_render(match):
                template_path = match.group(1)
                parameters = match.group(2)
                #print(template_path)
                content=''
                if os.path.isfile(os.path.join(project_root,"luci/view",template_path+'.htm')):
                    with open(os.path.join(project_root,"luci/view",template_path+'.htm'), 'r',encoding='utf-8', errors = 'ignore') as f:
                        mapping=dict()
                        txt = f.read()
                        pattern = r'<%:?=?\-?(?![#\+])(.*?)\-?%>'
                        matches = re.findall(pattern, txt, re.DOTALL)
                        start = 0
                        for match in matches:
                            start = txt.find(match,start)
                            startline = txt.count('\n',0,start)+1
                            code_block = remove_escape_chars(match.strip())
                            params = re.findall(r'(\w+)\s*=\s*(\w+)', parameters)
                            for k,v in params:
                                if k in code_block:
                                    code_block = code_block.replace(k,v)
                            for l,v in enumerate(code_block.split('\n')):
                                mapping[v]=startline+l
                            content+=code_block+'\n'
                            rendered_mapping["luci/view/"+template_path+'.htm']=mapping
                #print(content)
                return content
            if project_root:
                pattern = r'luci\.template\.render\(\s*"(.*?)"\s*,\s*\{(.+?)\}\)'
                cleaned_code_new = re.sub(pattern, replace_render, cleaned_code)
                pattern = r'[Tt]emplate\("([^"]+)"\)'
                matches = re.findall(pattern, cleaned_code_new)
                #print("Extracted Strings:")
                for match in matches:
                    if os.path.isfile(os.path.join(project_root,"luci/view",match+'.htm')):
                        with open(os.path.join(project_root,"luci/view",match+'.htm'), 'r',encoding='utf-8', errors = 'ignore') as f:
                            mapping = dict()
                            txt = f.read()
                            pattern = r'<%:?=?\-?(?![#\+])(.*?)\-?%>'
                            matches = re.findall(pattern, txt, re.DOTALL)
                            content='function '+match.replace('/','_')+'()\n'
                            start = 0
                            for match1 in matches:
                                start = txt.find(match1,start)
                                startline = txt.count('\n',0,start)+1
                                code_block = remove_escape_chars(match1.strip())
                                for l,v in enumerate(code_block.split('\n')):
                                    mapping[v]=startline+l
                                #print(code_block)
                                content+=code_block+'\n'
                            content+='end\n'
                            #print(content)
                            cleaned_code_new +=content
                            rendered_mapping["luci/view/"+match+'.htm']=mapping
                try:
                    #print(cleaned_code_new)
                    tree = ast.parse(cleaned_code_new)
                    mapping = dict()
                    count=1
                    for k,v in enumerate(cleaned_code_new.split('\n')):
                        if v in cleaned_code:
                            mapping[k+1]=count
                            count+=1
                        else:
                            for i in rendered_mapping:
                                if v in rendered_mapping[i]:
                                    mapping[k+1]=(i,rendered_mapping[i][v])
                                    break
                    line_mapping[os.path.abspath(path)]=mapping
                    return tree
                except:
                    logging.error('The ast module can not parse the file after rendering')
            try:
                tree = ast.parse(cleaned_code)
                return tree
                #return PytTransformer().visit(tree)
            except SyntaxError:  # pragma: no cover
                global recursive
                raise SyntaxError('The ast module can not parse the file')
    raise IOError('Input needs to be a file. Path: ' + path)

def _get_call_names_helper(node):
    """Recursively finds all function names."""
    if isinstance(node, ast.Name):
        yield node.id
    elif isinstance(node, ast.String):
        yield node.s
    elif isinstance(node, ast.Index):
        yield from _get_call_names_helper(node.idx)
        yield from _get_call_names_helper(node.value)

def get_call_names(node):
    """Get a list of call names."""
    return reversed(list(_get_call_names_helper(node)))


def _list_to_dotted_string(list_of_components):
    """Convert a list to a string seperated by a dot."""
    return '.'.join(list_of_components)


def get_call_names_as_string(node):
    """Get a list of call names as a string."""
    return _list_to_dotted_string(get_call_names(node))


class Arguments():
    """Represents arguments of a function."""

    def __init__(self, args):
        """Argument container class.

        Args:
            args(list(ast.args): The arguments in a function AST node.
        """
        self.args = args

        self.arguments = list()
        if self.args:
            self.arguments.extend([x.id for x in self.args if not isinstance(x,ast.Varargs)])
            self.arguments.extend(['Varargs' for x in self.args if isinstance(x,ast.Varargs)])

    def __getitem__(self, key):
        return self.arguments.__getitem__(key)

    def __len__(self):
        return self.args.__len__()
