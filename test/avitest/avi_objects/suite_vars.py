import pytest

class SuiteVars(object):

    def __init__(self):

        self.jenkins_run = False
        self.break_point = ''
        self.dns = False
        self.auto_gateway = False
        self.exit_on_failure = False
        self.skip_cloud_config = False
        self.skip_create_config = False
        self.skip_delete_config = False
        self.api_version = None
        self.loglevel = 'TRACE'
        self.log_dir = None
        self.workspace = None
        self.platform = None

    def initialize_vars(self):
        self.api_version = pytest.config.getoption("--api_version")
        self.jenkins_run = pytest.config.getoption("--jenkins_run")
        self.loglevel = pytest.config.getoption("--loglevel")
        self.skip_cloud_config = pytest.config.getoption("--skip_cloud_config")
        self.skip_create_config = pytest.config.getoption("--skip_create_config")
        self.skip_delete_config = pytest.config.getoption("--skip_delete_config")
        self.log_dir = pytest.config.getoption("--log_dir")
        self.platform = pytest.config.getoption("--platform")
        print "\n"

suite_vars = SuiteVars()
