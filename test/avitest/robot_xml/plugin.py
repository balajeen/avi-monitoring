from codecs import open # for encoding support in python 2.7
from collections import OrderedDict
import datetime
import re
import os

from robot import rebot
from xml.sax.saxutils import escape, quoteattr

ROBOT_TIME_FORMAT = '%Y%m%d %H:%M:%S.%f'

def pytest_addoption(parser):
    group = parser.getgroup('terminal reporting')
    group.addoption('--robot_xml', action='store', dest='robotxmlpath',
                    metavar='path', default=None,
                    help='create robot formatted xml file at given path.')
    group.addoption('--robot_html', action='store', dest='robothtmlpath',
                    metavar='path', default=None,
                    help='create robot formatted html file at given path.')

def pytest_configure(config):
    xmlpath = config.option.robotxmlpath
    if config.option.robothtmlpath and not xmlpath:
        xmlpath = config.option.robothtmlpath.replace('.html', '.xml')
    # prevent opening xmlpath on slave nodes (xdist)
    if xmlpath and not hasattr(config, 'slaveinput'):
        config._robotxml = RobotXmlReport(xmlpath, config)
        config.pluginmanager.register(config._robotxml)

def pytest_unconfigure(config):
    robotxml = getattr(config, '_robotxml', None)
    if robotxml:
        del config._robotxml
        config.pluginmanager.unregister(robotxml)

def _robot_formatted_date_time(date_time):
    return date_time.strftime(ROBOT_TIME_FORMAT)[:-3]

class RobotXmlReport(object):
    """
    Implements a pytest plugin that generates xml from the run logs based on robot xml format
    https://github.com/robotframework/robotframework/blob/master/doc/schema/robot-xsd11.xsd
    Will also optionally run rebot to create the robot html of the logs
    """

    def __init__(self, logfile, config):
        logfile = os.path.expanduser(os.path.expandvars(logfile))
        self.logfile = os.path.normpath(os.path.abspath(logfile))
        self.config = config
        self.logs = OrderedDict()
        self.errors = self.failed = 0
        self.passed = self.skipped = 0
        self.xfailed = self.xpassed = 0
        self.suite_times = {}

    def append_result(self, outcome, report):
        """
        Take the result and logs and add log entries to the 2 dimensional
        OrderedDict of [(testsuite info)][testcase]
        
        They will be converted to robot messages under a keyword for this logging
        
        Relies on report having a field "robot_extra" containing the log messages that were
        written to a file during test execution (by AviLogger) and read back out after
        (by contest.pytest_runtest_makereport)
        """
        duration = getattr(report, 'duration', 0.0)
        delta = datetime.timedelta(seconds=duration)
        now = datetime.datetime.now()
        start_time = now - delta
        end_time = now
        status = '<status status="%s" starttime="%s" endtime="%s" />' %(outcome, _robot_formatted_date_time(start_time), _robot_formatted_date_time(end_time))

        kw_type = None
        try:
            if report.when != 'call':
                kw_type = report.when
        except:
            pass

        # nodeid format like avitest/test_logger.py::TestLogger::()::test_error
        suite_info = report.nodeid.split('::')
        if len(suite_info) > 0:
            suite_source = suite_info[0]
        else:
            raise Exception('failed to parse test nodeid %s' %report.nodeid)

        if len(suite_info) == 2:
            suite_name = 'noclass' # special token for test cases outside of classes
            testcase_name = suite_info[1]
        elif len(suite_info) > 3:
            suite_name = suite_info[1]
            testcase_name = suite_info[3]

        # setup OrderedDict if it is the first time we are parsing this entry
        if not self.logs.get((suite_source, suite_name)):
            self.logs[(suite_source, suite_name)] = OrderedDict()
            self.suite_times[(suite_source, suite_name)] = [start_time, end_time]
        if not self.logs[(suite_source, suite_name)].get(testcase_name):
            self.logs[(suite_source, suite_name)][testcase_name] = []

        if start_time < self.suite_times[(suite_source, suite_name)][0]:
            self.suite_times[(suite_source, suite_name)][0] = start_time
        if end_time > self.suite_times[(suite_source, suite_name)][1]:
            self.suite_times[(suite_source, suite_name)][1] = end_time

        # start the keyword
        log_index = len(self.logs[(suite_source, suite_name)][testcase_name])
        source_lib = suite_source.split('/')[-1].split('.py')[0]
        kw_str = '<kw library="%s" name=%s' %(source_lib, quoteattr(testcase_name))
        if kw_type:
            kw_str += ' type="%s"' %kw_type
        kw_str += '><arguments><arg>log-messages-%d</arg></arguments>' %log_index
        self.logs[(suite_source, suite_name)][testcase_name].append(kw_str)
        
        test_index = hasattr(report, 'rerun') and report.rerun + 1 or 0

        # REVIEW this is what is redirected from the console when -s -v is not used; i.e. suppressed stdout and stderr
        # REVIEW should this be its own keyword rather than being in the other_logs?
        other_logs = []
        for section in report.sections:
            header, content = map(escape, section)
            ansi_escape = re.compile(r'\x1b[^m]*m')  
            content = ansi_escape.sub('', content)
            other_logs.append(' {0} '.format(header).center(80, '-'))
            other_logs.append('\n')
            other_logs.append(content)

        level = 'INFO'
        if report.longrepr:
            #print 'longrepr'
            for line in report.longreprtext.splitlines():
                separator = line.startswith('_ ' * 10)
                if separator:
                    other_logs.append(line[:80])
                else:
                    if line.startswith("E   "): # error
                        level = 'FAIL'
                    other_logs.append(line)
                other_logs.append('\n')

        if len(other_logs) == 0:
            #extra_log.append('No log output captured.')
            pass

        other_logs_str = ''
        for entry in other_logs:
            other_logs_str += entry
        other_logs_str = escape(other_logs_str)
        
        # append other logs messages
        if other_logs_str.strip():
            message_start = '<msg timestamp="%s" level="%s">' %(_robot_formatted_date_time(start_time), level)
            self.logs[(suite_source, suite_name)][testcase_name].append(message_start + other_logs_str + '</msg>')

        if self.config.getoption('-s') != 'fd' or self.config.getoption('-v'):
            for extra_index, extra in enumerate(getattr(report, 'robot_extra', [])):
                self.logs[(suite_source, suite_name)][testcase_name].append(extra)

        # close off logger kw with status
        self.logs[(suite_source, suite_name)][testcase_name].append(status)
        self.logs[(suite_source, suite_name)][testcase_name].append('</kw>')
        self.logs[(suite_source, suite_name)][testcase_name].append(status)

    def append_passed(self, report):
        if report.when == 'call':
            if hasattr(report, "wasxfail"): # REVIEW ???
                self.xpassed += 1
                self.append_result('PASS', report)
            else:
                self.passed += 1
                self.append_result('PASS', report)

    def append_failed(self, report):
        if report.when == "call":
            if hasattr(report, "wasxfail"):
                # pytest < 3.0 marked xpasses as failures
                self.xpassed += 1
                self.append_result('PASS', report)
            else:
                self.failed += 1
                self.append_result('FAIL', report)
        else:
            self.errors += 1
            self.append_result('FAIL', report)

    # TODO: how to treat skips?
    def append_skipped(self, report):
        if hasattr(report, "wasxfail"):
            self.xfailed += 1
            self.append_result('PASS', report)
        else:
            self.skipped += 1
            self.append_result('PASS', report)

    # TODO: what about this 
    '''
    def append_other(self, report):
        # For now, the only "other" the plugin give support is rerun
        self.rerun += 1
        self.append_result('Rerun', report)
    '''

    def _generate_report(self, session):
        ''' Writes out the accumulated logs to string format
            Hierarchy:
            - suite: folder or test file
                - suite: test file (if folder)
                    - suite: class name
                        - test: method name
                            -kw
                    - test: functions without class
        
        '''
        dir_name = os.path.dirname(self.logfile)
        if not os.path.exists(dir_name):
            os.makedirs(dir_name)
        f = open(self.logfile, 'w', encoding='utf-8')
        # REVIEW can we use some xml util to dump it directly?
        suite_stop_time = _robot_formatted_date_time(datetime.datetime.now())
        suite_start_time = _robot_formatted_date_time(self.suite_start_time)
        #suite_time_delta = time.time() - self.suite_start_time
        
        # write headers
        result_str = '<?xml version="1.0" encoding="UTF-8"?>\n'
        result_str += '<robot generated="%s" generator="Pytest robot_xml plugin v0.1" >\n' %suite_stop_time

        # assumes logs are already xml formatted msg string
        suite_file_index = 0
        suite_class_index = 0
        test_index = 0
        # REVIEW is config.args[0] always the pytest suite path?
        # REVIEW seems the start time is not used in the suite/test tags but rather calculated from the statuses
        result_str += '  <suite name="%s">\n' % (self.config.args[0])
        result_str += '  <status starttime="%s" endtime="%s"/>\n' % (suite_start_time, suite_stop_time)
        run_is_dir = os.path.isdir(self.config.args[0])
        current_suite_file = None
        previous_suite_file = None
        suite_id = 's1'
        for (suite_source, suite_name), testlogs in self.logs.iteritems():
            current_suite_file = suite_source
            if run_is_dir and current_suite_file != previous_suite_file:
                # start a new suite tag for the new file
                if previous_suite_file:
                    result_str += '    </suite>\n' # close out previous test file's suite tag if there was one
                suite_file_index += 1
                suite_id = 's1-s%d' %(suite_file_index)
                result_str += '    <suite source="%s" id="%s" name="%s">\n' %(suite_source, suite_id, suite_source.split('/')[-1])
            if suite_name != 'noclass':
                # start a new suite tag for the new class
                suite_class_index += 1
                suite_id = 's1-s%d-s%d' %(suite_file_index, suite_class_index)
                result_str += '    <suite source="%s" id="%s" name="%s">\n' %(suite_source, suite_id, suite_name)
            result_str += '  <status starttime="%s" endtime="%s"/>\n' % (
                _robot_formatted_date_time(self.suite_times[(suite_source, suite_name)][0]),
                _robot_formatted_date_time(self.suite_times[(suite_source, suite_name)][1]),
            )
            for testcase_name, messages in testlogs.iteritems():
                test_index += 1
                test_id = 't%d' %test_index
                result_str += ('      <test id="%s-%s" name=%s>\n'
                               %(suite_id, test_id, quoteattr(testcase_name)))
                for message in messages:
                    result_str += '        %s\n' %message
                result_str += '      </test>\n'
            if suite_name != 'noclass':
                result_str += '    </suite>\n' # close out test class
            previous_suite_file = suite_source
            # Flush out result_str on each iteration to stop it from accumulating in memory
            f.write(result_str)
            result_str = ''
        if run_is_dir:
            result_str += '  </suite>\n' # close out test file (since the logic above won't run for the last file)
        result_str += '  </suite>\n' # close out folder
        result_str += '</robot>\n'
        f.write(result_str)
        f.close()

    def _generate_robot_html(self):
        numtests = self.passed + self.failed + self.xpassed + self.xfailed + self.errors
        if numtests == 0:
            print 'No tests ran, skipping rebot'
            return
        htmlpath = self.config.option.robothtmlpath
        if not htmlpath:
            htmlpath = self.config.option.robotxmlpath.replace('.xml', '.html')
            print '--robothtmlpath path not specified, defaulting to %s' %htmlpath

        htmlfile = os.path.expanduser(os.path.expandvars(htmlpath))
        htmlfile = os.path.normpath(os.path.abspath(htmlfile))
        print '\n--- rebot xml from %s to %s ---' %(self.logfile, htmlfile)
        re = rebot(self.logfile, log=htmlfile, report=htmlfile.replace('.html', '_report.html'))
        if re > 251: # REVIEW don't understand how these codes work but seems like 252 means failed
            raise Exception('rebot failed with status %s' %re)

    def pytest_runtest_logreport(self, report):
        """ Pytest hook that gets a report for each test case result """
        if report.passed:
            self.append_passed(report)
        elif report.failed:
            self.append_failed(report)
        elif report.skipped:
            self.append_skipped(report)
        else:
            # self.append_other(report)
            self.append_passed(report)

    def pytest_sessionstart(self, session):
        self.suite_start_time = datetime.datetime.now()

    def pytest_sessionfinish(self, session):
        self._generate_report(session)
        self._generate_robot_html()

    def pytest_terminal_summary(self, terminalreporter):
        terminalreporter.write_sep('-', 'generated xml file: {0}'.format(
            self.logfile))
