import argparse
from collections import OrderedDict
import os
import re
import sys

from avi_objects.logger import logger

from jinja2 import Environment, PackageLoader, select_autoescape
from robot.api import TestData
from robot.errors import DataError
from robot.libraries.BuiltIn import BuiltIn
from robot.parsing.model import ResourceFile

env = Environment(loader=PackageLoader('avi_tools.jinja', 'templates'),
                  autoescape=select_autoescape(['html', 'xml']))

#template = env.get_template('robot_to_pytest.py.template')
template = env.get_template('basic.template')

ROBOT_LIBS = ['Collections', 'OperatingSystem', 'String'] # TODO all others

# TODO: refactor/standardize all variable extraction logic

suite_keywords = []

def parse_step(step, function_args=None):
    """ Subroutine to handle conversion of a robot step (keyword call) """
    if step.is_for_loop():
        vars = step.vars
        sequence = step.items

        # REVIEW for now assume simple single non-recursive ${var}, else need to use the recursive logic
        var = str(vars[0])[2:-1]
        if sequence[0][0] in ['$', '@', '&']: # variable prefix
            sequence = str(sequence[0])[2:-1] # variable, else use as list
            if function_args and sequence in function_args:
                pass
            else: # REVIEW but maybe locally assigned?
                sequence = 'self.' + sequence
        else:
            sequence = [str(item) for item in sequence]
        step_name = 'for %s in %s:' %(var, sequence)
        argv = []
        if function_args is None:
            function_args = []
        function_args.append(var)
        for loop_step in step.steps:
            loop_step_name, loop_step_argv = parse_step(loop_step, function_args)
            argv.append(loop_step_name + '(' + loop_step_argv + ')')
        return step_name, argv
    elif not step.name: # it is a comment
        step_name = str('    '.join(step.comment._comment))
    else:
        step_name = '_'.join(step.name.lower().split())
    if step_name in suite_keywords:
        logger.debug('step %s found in suite keywords, calling it' %step_name)
        step_name = 'self.' + step_name

    # check for robot builtins...
    is_eval = False
    is_print = False
    is_list = False
    is_dict = False
    unsupported_builtin = False
    if step_name == 'evaluate':
        step_name = 'eval' # Evaluate    a+b => eval(a+b)
        is_eval = True
    if step_name == 'convert_to_boolean':
        step_name = 'eval'
        is_eval = True
    if step_name == 'should_be_true':
        step_name = 'assert eval'
        is_eval = True
    if step_name == 'log':
        step_name = 'print'
        is_print = True
    if step_name == 'create_list':
        step_name = 'list'
        is_list = True # hack to signal the args need to be as list
    if step_name == 'create_dictionary':
        step_name = 'dict'
        is_dict = True # hack to signal the args need to be as dict
    elif step_name in dir(BuiltIn): # unimplemented robot builtin
        step_name = 'FIXME.' + step_name
        unsupported_builtin = True
    # REVIEW can we also do a similar warning for constants like BLANK/EMPTY/TRUE/etc?

    if step.assign: # variable assignment: ${var}=    something
        step_assign = str(step.assign[0]) # REVIEW are multiple assigns possible?
        step_assign_var = step_assign.rstrip('=') # ${var}=   val # note not all assignments have =
        step_assign_var = step_assign_var.strip().lstrip('${').rstrip('}') # strip ${}
        step_assign_var = re.sub('[^0-9a-zA-Z_]', '_', step_assign_var) # python naming
        if step_assign_var[0].isdigit():
            step_assign_var = 'FIXME' + step_assign_var
        step_name = 'self.' + step_assign_var + ' = ' + step_name # REVIEW should this be global?!

    args = []
    for arg in step.args:
        # Convert ${variables} to the global var
        # REVIEW can this be cleaner with regex?
        k = ''
        v = arg
        if '=' in arg and not '==' in arg:
            k,v = arg.split('=', 1)
        v = str(v) # convert the unicode
        # REVIEW this maintains behavior where all args are strings; do we fix?
        if v.startswith('${'): # FIXME what if it's a${var}?
            v_split = v[2:].split('}')
            if function_args and v_split[0] in function_args: # treat var as a function arg
                v_var = v_split[0]
            else: # assume the class var exists
                v_var = 'self.' + v_split[0]
            if v_split[1]: # ${var}something_after_closing_bracket
                if v_split[1].startswith('=='): # ${var}==value
                    v = repr(v_var + v_split[1])
                else: # ${var}-0 variable name mutation
                    v = v_var + '+' + repr(v_split[1])
            elif is_eval: # eval('${var}')
                v = repr(v_var)
            else: # ${var}
                v = v_var
            if is_print:
                v = 'eval(' + repr(v) + ')'
            if is_list or is_dict: # list(${var})
                # convert the var string to var itself
                v = 'eval(' + repr(v) + ')'
        else:
            if not is_list and not is_dict: # REVIEW don't add quotes for list/dict args
                v = repr(v)
        if k:
            k = str(k)
            if is_dict:
                args.append((k, v))
            else:
                args.append(k + '=' + v)
        else:
            args.append(v)

    if is_list or is_dict:
        step_argv = args
    else:
        step_argv = ', '.join(args)
        if unsupported_builtin:
            step_argv += ') # FIXME: unsupported Robot BuiltIn. Replace with appropriate code'
    return step_name, step_argv

def convert(input_file, output_file):
    """
    Take a robot text input file and convert it into pytest formatted output file.
    Tightly coupled with the template specified.
    """
    # read input file and build up robot_info
    logger.info('Converting robot test file %s to pytest %s' %(input_file, output_file))

    robot_info = {}
    robot_info['source'] = input_file
    suite_name = ''
    try:
        suite = TestData(source=input_file)
        suite_name = 'Test_' + suite.name.replace(' ', '_')
    except DataError:
        suite = ResourceFile(source=input_file).populate()
        suite_name = suite.name.replace(' ', '_')

    robot_info[suite_name] = OrderedDict()

    # TODO suite/test setup and teardown?
    
    # REVIEW can we handle the imports without importing *?
    robot_info[suite_name]['imports'] = []
    robot_info[suite_name]['parents'] = []
    for import_data in suite.imports.data:
        lib_name = import_data.name.replace('.py','').replace('../', '').replace('/', '.')
        if import_data.type == 'Resource':
            logger.debug('processing resource: %s' %lib_name)
            robot_info[suite_name]['parents'].append(lib_name) # REVIEW what to do with this
        if lib_name in ROBOT_LIBS:
            logger.debug('skipping import of robot internal library %s' %lib_name)
            continue
        logger.debug('importing library: %s' %lib_name)
        robot_info[suite_name]['imports'].append(lib_name)

    robot_info[suite_name]['variables'] = []
    skip_vars = ['deploy', 'config_file'] # TODO
    for global_var in suite.variable_table:
        if not global_var.name: # comment
            var = str('    '.join(global_var.comment._comment))
            robot_info[suite_name]['variables'].append((var, ''))
            continue
        var = global_var.name[2:-1]
        var = re.sub('[^0-9a-zA-Z_]', '_', var.lower()) # convert to valid python name by changing to underscore
        if var in skip_vars:
            logger.debug('skipping porting of variable: %s' %var)
            continue
        if var[0].isdigit():
            var = 'FIXME' + var

        val = str(global_var.value[0]) # convert unicode
        val = val.replace('\'', '').replace('"', '') # REVIEW assume that all string vars are plain strings? i.e. no '"hello"'
        # recursive vars
        recursive_var = ''
        if '${' in val:
            val_split = val.split('${')
            if val_split[0]: # string${var} -> accumulate the first string
                recursive_var += repr(val_split[0])
            for val_split_part in val_split[1:]:
                val_sps = val_split_part.split('}')
                if recursive_var:
                    recursive_var += '+'
                recursive_var += 'str('+val_sps[0]+')' + '+' + repr(val_sps[1]) # ${var}string -> str(var)+string
            val = recursive_var
        try:
            val = int(val) # REVIEW any other val types to try?
        except ValueError:  # pythonic?
            val = repr(val)
            if recursive_var:
                val = 'eval(' + val + ')'
        logger.debug('processing variable %s with value %s' %(var, val))
        robot_info[suite_name]['variables'].append((var, val))
    
    robot_info[suite_name]['keywords'] = OrderedDict()
    for keyword in suite.keywords:
        keyword_name = re.sub('[^0-9a-zA-Z_]', '_', keyword.name.lower()) # convert to valid python name by changing to underscore
        if keyword_name[0].isdigit():
            keyword_name = 'FIXME' + keyword_name
        suite_keywords.append(keyword_name)
        # assume args can only be for keywords and not testcases
        keyword_args = keyword.args.value
        keyword_args = [str(arg).replace('${', '').replace('@{', '').replace('}', '') for arg in keyword_args]
        keyword_args = ['self'] + keyword_args
        argstring = ', '.join(keyword_args)
        robot_info[suite_name]['keywords'][(keyword_name, argstring)] = []
        if keyword.doc.value:
            docstring = '"""' + str(keyword.doc.value) + '"""'
            robot_info[suite_name]['keywords'][(keyword_name, argstring)].append((docstring, []))
        for step in keyword.steps:
            if step.is_for_loop():
                step_name = step.as_list()
            else:
                step_name = step.name
            logger.debug('processing keyword step %s.%s ' %(keyword_name, step_name))
            keyword_args = [arg.split('=')[0] for arg in keyword_args] # just keep the names of any kwargs
            step_name, step_argv = parse_step(step, keyword_args)
            robot_info[suite_name]['keywords'][(keyword_name, argstring)].append((step_name, step_argv))

    robot_info[suite_name]['testcases'] = OrderedDict()
    for test in suite.testcase_table:
        test_name = re.sub('[^0-9a-zA-Z_]', '_', test.name.lower()) # convert to valid python name by changing to underscore
        # REVIEW should strip leading numbers too, but we'll assume we're going to append 'test_'
        robot_info[suite_name]['testcases'][test_name] = []
        if test.doc.value:
            docstring = '""" ' + str(test.doc.value) + ' """'
            robot_info[suite_name]['testcases'][test_name].append((docstring, []))
        if test.tags.value: # for future use?
            tagstring = str(', '.join(test.tags.value))
            robot_info[suite_name]['testcases'][test_name].append(('# Tags:  ' + tagstring, []))
        for step in test.steps:
            if step.is_for_loop():
                step_name = step.as_list()
            else:
                step_name = step.name
            logger.debug('processing test step %s.%s ' %(test_name, step_name))
            step_name, step_argv = parse_step(step)
            robot_info[suite_name]['testcases'][test_name].append((step_name, step_argv))

    # write to desired output file
    content = template.render(robot_info=robot_info)
    #content = str(robot_info)

    output_dir = os.path.dirname(output_file)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    with open(output_file, 'w') as f:
        f.write(content)
        logger.info('wrote pytest file %s' %output_file)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('robot', nargs='*',
            help='robot text file(s) or directory')
    parser.add_argument('-o', '--pytest',
            help = 'pytest .py file or directory (for multiple or directory inputs)', default='')
    args = parser.parse_args()
    if not args.robot:
        parser.print_help()
        parser.exit()
    return args

def main(input_ext, output_ext):
    args = parse_args()
    input_name = args.robot
    output_name = args.pytest
    output_path = os.path.expanduser(os.path.expandvars(output_name))
    output_path = os.path.normpath(os.path.abspath(output_path))

    if len(input_name) > 1:
        logger.info('Converting multiple inputs %s' %input_name)
        if os.path.isfile(output_path):
            raise RuntimeError('A directory must be specified as the output for multiple inputs')
        for one_input in input_name:
            input_path = os.path.expanduser(os.path.expandvars(one_input))
            input_path = os.path.normpath(os.path.abspath(input_path))
            file_name = os.path.basename(input_path)
            file_name = os.path.splitext(file_name)[0]
            _output_path = os.path.join(output_path, file_name + output_ext)
            convert(input_path, _output_path)
    else:
        input_name = args.robot[0]
        input_path = os.path.expanduser(os.path.expandvars(input_name))
        input_path = os.path.normpath(os.path.abspath(input_path))
        if os.path.isdir(input_path):
            logger.info('Converting input dir %s' %input_path)
            if os.path.isfile(output_path):
                raise RuntimeError('A directory must be specified as the output for directory inputs')
            for path, subdirs, files in os.walk(input_path):
                for name in files:
                    if name.endswith(input_ext):
                        input_filename = os.path.join(path, name)
                        output_filename = os.path.splitext(name)[0]
                        output_filename = output_filename + output_ext
                        rel_path = os.path.relpath(path, input_path) # maintain the relative folder structure
                        output_filename = os.path.join(output_path, rel_path, output_filename)
                        output_filename = os.path.normpath(os.path.abspath(output_filename))
                        output_dir = os.path.dirname(output_filename)
                        if not os.path.exists(output_dir):
                            logger.debug('Creating output folder %s' %output_dir)
                            os.makedirs(output_dir)
                        convert(input_filename, output_filename)
        else:
            logger.info('Converting single input %s' %input_path)
            if not output_name:
                file_name = os.path.splitext(input_path)[0]
                output_path = file_name + output_ext
            else:
                ext = os.path.splitext(output_name)[1]
                if ext and ext != output_ext:
                    raise RuntimeError('Unsupported output filename %s (should be %s file)' %(output_name, output_ext))
                if not ext: # assume folder
                    file_name = os.path.basename(input_path)
                    file_name = os.path.splitext(file_name)[0]
                    output_path = os.path.join(output_path, file_name + output_ext)
            convert(input_path, output_path)

if __name__ == '__main__':
    main(('.txt', '.robot'), '.py')
