import avi_objects.logger_utils as logger_utils
from avi_objects.suite_vars import suite_vars
import avi_objects.infra_utils as infra_utils
from avi_objects.logger import logger
from avi_objects.suite_vars import suite_vars
import uuid
import string
import subprocess
import os


def run_commands(cli_instructs, ctlr_vm, **kwargs):
    config = infra_utils.get_config()
    cli_exe_path = suite_vars.workspace + ("/python/bin/cli/bin/shell_client.py --user %s --password %s " %
                                           (ctlr_vm.user, ctlr_vm.password))

    cli_instructs_path = '/tmp/%s' % uuid.uuid1()
    with open(cli_instructs_path, 'w') as fh:
        fh.write(string.join(cli_instructs, '\n'))
    cli_exec = '%s --address %s' % (cli_exe_path, ctlr_vm.ip)
    env = {}
    env['PYTHONPATH'] = suite_vars.workspace + '/python/lib'
    try:
        cat_proc = subprocess.Popen(['cat', cli_instructs_path],
                                    stdout=subprocess.PIPE, env=env)
        cli_proc = subprocess.Popen(cli_exec.split(),
                                    stdin=cat_proc.stdout,
                                    stdout=subprocess.PIPE, env=env)
        cat_proc.stdout.close()
        output = cli_proc.communicate()[0]
        logger.info(output)
    except OSError:
        logger_utils.fail('Could not open the shell at %s' % cli_exe_path)
    except subprocess.CalledProcessError:
        raise
    os.system('rm %s' % cli_instructs_path)
