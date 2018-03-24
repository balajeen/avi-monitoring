import pytest
from py.xml import html
import re
import os
from os.path import dirname
import subprocess
from avi_objects.suite_vars import suite_vars
from avi_objects.logger import logger
from avi_objects.avi_config import AviConfig
from avi_objects.infra_utils import initialize_testbed, get_vm_of_type
from avi_objects.logger_utils import fail

def pytest_addoption(parser):
    parser.addoption("--testbed", help="Testbed for the tests to run on",
            action='append', default = [])
    parser.addoption("--api_version", help="Default Api Version for the tests to run on",
            default = None)
    parser.addoption("--jenkins_run", help="Config file for the tests to run on",
            action='store_true')
    parser.addoption("--loglevel", help="Set Log Level for the logger", default = 'INFO')
    parser.addoption("--skip_cloud_config", help="Skips cloud config with setup cloud",
            action='store_true')
    parser.addoption("--skip_create_config", help="Skips create config.",
            action='store_true')
    parser.addoption("--skip_delete_config", help="Skips delete config",
            action='store_true')
    parser.addoption("--log_dir", help="Log directory ", default = '')
    parser.addoption("--platform",help="Platform for running the test",default="")

pytest_plugins = 'robot_xml.plugin'

def get_core_filenames():
    # N/A
    return {}
    se_list = get_vm_of_type('se', state="OPER_UP")
    ctrlr_list = get_vm_of_type('controller')
    all_vms = se_list + ctrlr_list
    if all_vms:
        result={}
        for vm in all_vms:
            try:
                file_list = vm.execute_command('sudo ls -l /var/lib/avi/archive/*.tar.gz', log_error=False)
            except Exception as e:
                logger.info("Unable to execute command on VM. Vm may be down %s" % str(e.msg))
                if not vm.ip:
                    logger.warning('vm is not there , vm name: %s' % vm.name)
                    return {}
                if vm in ctrlr_list and vm.ip:
                    fail("Controller not in right state")
            if file_list:
                result[vm.ip] = str(file_list).splitlines()
    else:
        result = {}
    return result

def warn_if_new_cores(old_cores, new_cores):
    for host, host_new_cores in new_cores.iteritems():
        prefix = '[%s] ' % host
        host_old_cores = old_cores.get(host, ())
        host_added_cores = list(set(host_new_cores) - set(host_old_cores))
        # host_removed_cores = ... # We don't care about removed cores
        if host_old_cores:
            logger.info(prefix + 'Existing cores found on host at beginning of test: %s' % str(host_old_cores))
            host_old_cores_strs = [prefix + '   ' + filename for filename in host_old_cores]
            printstr = '\n'.join(host_old_cores_strs)
            logger.info(printstr)
        if host_added_cores:
            logger.info (prefix + '** NEW CORES FOUND ON HOST: **')
            host_added_cores_strs = [prefix + '   ' + filename for filename in host_added_cores]
            printstr = '\n'.join(host_added_cores_strs)
            logger.info(prefix + 'Please look at these cores %s stored in ' \
                  'host %s.' % (str(host_added_cores), host))

@pytest.fixture(scope='session', autouse=True)
def avi_setup(request):
    suite_vars.initialize_vars()
    suite_vars.workspace = set_workspace()
    if not suite_vars.log_dir:
        suite_vars.log_dir = str(suite_vars.workspace)
    logger._init_file_handler(log_dir=suite_vars.log_dir)
    logger.setlevel(suite_vars.loglevel)
    config = AviConfig()
    initialize_testbed()
    old_cores = get_core_filenames()
    if old_cores:
        logger.info("Existing core files "+str(old_cores))
    def fin():
        new_cores = get_core_filenames()
        warn_if_new_cores(old_cores, new_cores)
        #TODO: Need to integrate eporting by e-mail and move the cores to bug folder if the run is on Jenkins
    request.addfinalizer(fin)
    return config

@pytest.fixture(scope='module', autouse=True)
def avi_module_setup(request):
    suite_vars.module_path = request.module.__file__
    logger.skip_tc = False

@pytest.fixture(scope='function', autouse=True)
def avi_test_setup(request):
    if logger.skip_tc:
        pytest.skip()
    pre_process_avitest_markers(request)
    logger.info('suite_vars.log_dir %s' %suite_vars.log_dir)
    logger._init_tc_file_handler(log_dir=suite_vars.log_dir)
    logger._init_robot_file_handler(log_dir=suite_vars.log_dir)
    sep = 20 * "="
    logger.info(sep + "TEST CASE START: " + request.function.__name__ + sep)
    def fin():
        logger.info('*' * 5 + " TEST CASE TEARDOWN: " + request.function.__name__ + '*' * 5)
        logger.report_errors()
        logger.info(sep + "TEST CASE END: " + request.function.__name__ + sep)
        logger.logger.removeHandler(logger.file_tc_handle)
        logger.logger.removeHandler(logger.file_robot_handle)
        #logger.file_tc_handle.close()
    request.addfinalizer(fin)

def set_workspace():
    workspace = ''
    thispath = os.path.realpath(__file__)
    workspace = dirname(dirname(dirname(thispath))) # $workspace/test/avitest/conftest.py
    #workspace = subprocess.check_output(
    #    'git rev-parse --show-toplevel', shell=True)
    #workspace = workspace.strip(' \n\t')
    if not workspace:
        raise Exception('ERROR! Could not setup workspace')
    logger.debug('Setting workspace:: %s' % workspace)
    return workspace

@pytest.mark.hookwrapper
def pytest_runtest_makereport(item, call):
    pytest_html = item.config.pluginmanager.getplugin('html')
    outcome = yield
    report = outcome.get_result()
    # REVIEW is this going to be slow? writing and reading from the file to get the log messages
    # ...can we pass directly?
    extra = getattr(report, 'extra', [])
    log_file = os.path.join(suite_vars.log_dir, "avitest_tc.log")
    dashboardv2_log_file = ''
    if suite_vars.platform != None:
        dashboardv2_log_file = os.path.join(suite_vars.log_dir , "_"+suite_vars.platform+"_dashboardv2_tc.log")
    else:
        dashboardv2_log_file = os.path.join(suite_vars.log_dir , "dashboardv2_tc.log")
    with open(dashboardv2_log_file,'ab+') as dashboardv2_tc_log_file:
        import pickle
        pickle.dump(report,dashboardv2_tc_log_file,pickle.HIGHEST_PROTOCOL)
    if os.path.isfile(log_file):
        with open(log_file) as f:
            lines = f.readlines()
        lines = ''.join(lines)
        os.system("echo '' > %s" %log_file)
        extra.append(pytest_html.extras.html('<table id="log-table"> {0} </table>'.format(lines)))
        report.extra = extra
    robot_extra = getattr(report, 'robot_extra', [])
    log_file = os.path.join(suite_vars.log_dir, "avitest_robot.log")
    if os.path.isfile(log_file):
        with open(log_file) as f:
            lines = f.readlines()
        lines = ''.join(lines)
        os.system("echo '' > %s" %log_file)
        robot_extra.append(lines)
        report.robot_extra = robot_extra
    post_process_avitest_markers(item, call, report)

def pre_process_avitest_markers(request):
    logger.info("Pre Processing Avitest Markers")
    from avi_objects.infra_utils import get_cloud_context_type
    cloud_type = get_cloud_context_type()
    # Exclude option
    exclude_marker = str(cloud_type) + "_exclude"
    if not logger.skip_tc and exclude_marker in request.keywords:
        pytest.skip(msg="Skipping with respect to exclude markers. Match=%s" %exclude_marker)
    # Include Option
    include_marker = str(cloud_type) + "_include"
    if not logger.skip_tc:
        skip = False
        for keyword in request.keywords:
            if re.search('_include', str(keyword)):
                if include_marker != keyword:
                    skip = True
                else:
                    skip = False
                    break
        if skip:
            pytest.skip(msg="Skipping with respect to include markers.No Match=%s" %include_marker)

def post_process_avitest_markers(item, call, report):
    logger.info("Post Processing Avitest Markers")
    if "mandatory" in item.keywords and report.when == 'call':
        if report.outcome != 'passed':
            logger.info("Mandatory Test Case failed. Skipping Rest Test Cases")
            logger.skip_tc = True

@pytest.mark.optionalhook
def pytest_html_results_table_html(report, data):
    if report.passed:
        del data[1:]

def pytest_make_parametrize_id(config, val):
    return str(val)
