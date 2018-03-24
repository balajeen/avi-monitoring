import sys
import code
import logging
import copy
import datetime
import re
import inspect
import pytest
import os
from suite_vars import suite_vars

ABORT_LEVEL_NUM = 44
FAIL_LEVEL_NUM = 42
TRACE_LEVEL_NUM = 5

_MSG_FMT = """
<tr id="log-table">
<td id="log-table">%(time)s</td>
<td id="log-table" class="%(class)s">%(level)s</td>
<td id="log-table"><pre>%(msg)s</pre></td>
</tr>
"""

class FailError(Exception):
    def __init__(self,msg=''):
        self.name  = 'FAIL'
        self.msg = msg
    def __str__(self):
        return str(self.name + ': ' + self.msg)

class ForcedFailError(Exception):
    def __init__(self,msg=''):
        self.name  = 'FAIL'
        self.msg = msg
    def __str__(self):
        return str(self.name + ': ' + self.msg)


class AbortError(Exception):
    def __init__(self,msg=''):
        self.name = 'ABORT'
        self.msg = msg
    def __str__(self):
        return str(self.name + ': ' + self.msg)

class ErrorError(Exception):
    def __init__(self,msg=''):
        self.name = 'ERROR'
        self.msg = msg
    def __str__(self):
        return str(self.name + ': ' + self.msg)

class ColoredFormatter(logging.Formatter):

    CODE={
            'ENDC':0,  # RESET COLOR
            'BOLD':1,
            'UNDERLINE':4,
            'BLINK':5,
            'INVERT':7,
            'CONCEALD':8,
            'STRIKE':9,
            'GREY30':90,
            'GREY40':2,
            'GREY65':37,
            'GREY70':97,
            'GREY20_BG':40,
            'GREY33_BG':100,
            'GREY80_BG':47,
            'GREY93_BG':107,
            'DARK_RED':31,
            'RED':91,
            'RED_BG':41,
            'LIGHT_RED_BG':101,
            'DARK_YELLOW':33,
            'YELLOW':93,
            'YELLOW_BG':43,
            'LIGHT_YELLOW_BG':103,
            'DARK_BLUE':34,
            'BLUE':94,
            'BLUE_BG':44,
            'LIGHT_BLUE_BG':104,
            'DARK_MAGENTA':35,
            'PURPLE':95,
            'MAGENTA_BG':45,
            'LIGHT_PURPLE_BG':105,
            'DARK_CYAN':36,
            'AQUA':96,
            'CYAN_BG':46,
            'LIGHT_AUQA_BG':106,
            'DARK_GREEN':32,
            'GREEN':92,
            'GREEN_BG':42,
            'LIGHT_GREEN_BG':102,
            'BLACK':30,
    }

    LEVELCOLOR = {
        'TRACE': 'GREEN',
        'DEBUG': 'DARK_MAGENTA',
        'WARNING': 'DARK_CYAN',
        'ERROR': 'RED',
        'FAIL': 'DARK_RED',
        'ABORT': 'DARK_RED'
        }

    def __init__(self, msg):
        logging.Formatter.__init__(self, msg,"%Y-%m-%d %H:%M:%S")

    def format(self, record):
        record = copy.copy(record)
        levelname = record.levelname
        if levelname in self.LEVELCOLOR:
            record.levelname = self.colorstr(levelname,self.LEVELCOLOR[levelname])
            record.name = self.colorstr(record.name,'BOLD')
            record.msg = self.colorstr(str(record.msg).encode('utf-8'),self.LEVELCOLOR[levelname])
            record.fl_name = self.colorstr(record.fl_name,self.LEVELCOLOR[levelname])
            record.ln_no = self.colorstr(record.ln_no,self.LEVELCOLOR[levelname])
            record.fn_name = self.colorstr(record.fn_name,self.LEVELCOLOR[levelname])

        return logging.Formatter.format(self, record)

    def termcode(self,num):
        return '\033[%sm'%num

    def colorstr(self,astr,color):
        return self.termcode(self.CODE[color]) + str(astr) + self.termcode(self.CODE['ENDC'])

class HTMLFormatter(logging.Formatter):

    CSS_CLASSES = {'WARNING': 'warning',
                   'INFO': 'info',
                   'DEBUG': 'debug',
                   'TRACE': 'trace',
                   'CRITICAL': 'err',
                   'ERROR': 'err',
                   'FAIL': 'err',
                   'ABORT': 'err'}
    
    def __init__(self, msg):
        logging.Formatter.__init__(self, msg,"%Y-%m-%d %H:%M:%S")

    def format(self, record):
        record = copy.copy(record)
        try:
            class_name = self.CSS_CLASSES[record.levelname]
        except KeyError:
            class_name = "info"
        msg = record.msg
        if type(msg) == type(''):
            msg = msg.replace("<", "&#60")
            msg = msg.replace(">", "&#62")
        t = record.asctime
        return _MSG_FMT % {"class": class_name, "level": record.levelname, "time": t, "msg": msg} 


class RobotXMLFormatter(logging.Formatter):
    def __init__(self, msg):
        logging.Formatter.__init__(self, msg, datefmt="%Y%m%d %H:%M:%S.%f")

    def format(self, record):
        record = copy.copy(record)
        timestamp = datetime.datetime.now().strftime("%Y%m%d %H:%M:%S.%f")
        level = record.levelname
        if level == 'WARNING':
            level = 'WARN' # robot has warn instead of warning
        if level == 'ABORT': # robot does not have abort
            level = 'ERROR' # REVIEW should this be FAIL instead?
        from xml.sax.saxutils import escape
        msg = escape(str(str(record.msg).encode('utf-8')))
        return ('<msg timestamp="%s" level="%s">[%s %s:%s] %s</msg>'
                %(timestamp, level, record.fl_name, record.fn_name, record.ln_no, msg))

class AviLogger():

    colorformatter = ColoredFormatter('[%(asctime)s] :%(levelname)s: [%(fl_name)s %(fn_name)s:%(ln_no)s] %(message)s')
    consoleHandle = logging.StreamHandler()
    consoleHandle.setFormatter(colorformatter)
    error_list = []
    skip_tc = False
    _log = True
    
    def __init__(self):
        self.loglevel = "DEBUG"
        logging.addLevelName(ABORT_LEVEL_NUM, "ABORT")
        logging.addLevelName(FAIL_LEVEL_NUM, "FAIL")
        logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")
    
        self.logger = logging.getLogger("AviLogger")

        self.level = {
                 'TRACE': TRACE_LEVEL_NUM,
                 'DEBUG': logging.DEBUG,
                 'INFO': logging.INFO,
                 'WARNING': logging.WARNING,
                 'ERROR': logging.ERROR,
                 'FAIL': FAIL_LEVEL_NUM,
                 'ABORT': ABORT_LEVEL_NUM}
        numeric_level = self.level.get(self.loglevel.upper(),None)
        self.logger.setLevel(self.level['TRACE'])

        self.consoleHandle.setLevel(numeric_level)
        self.logger.addHandler(self.consoleHandle)

    def _init_file_handler(self, log_dir):
        """ Initialize file handler to log the messages  """
        log_file = str(log_dir) +"/avitest_debug.log"
        self.file_handle = logging.FileHandler(log_file, mode='w')
        normalformatter = logging.Formatter('[%(asctime)s] :%(levelname)s: [%(fl_name)s %(fn_name)s:%(ln_no)s] %(message)s',"%Y-%m-%d %H:%M:%S")
        self.file_handle.setFormatter(normalformatter)
        self.logger.addHandler(self.file_handle)

    def _init_tc_file_handler(self, log_dir):
        """ Initialize file handler to log the messages  """
        log_file = str(log_dir) +"/avitest_tc.log"
        self.file_tc_handle = logging.FileHandler(log_file)
        htmlformatter = HTMLFormatter('[%(asctime)s] :%(levelname)s: [%(fl_name)s %(fn_name)s:%(ln_no)s] %(message)s')
        self.file_tc_handle.setFormatter(htmlformatter)
        self.logger.addHandler(self.file_tc_handle)
        numeric_level = self.level.get(self.loglevel,None)
        self.file_tc_handle.setLevel(numeric_level)

    def _init_robot_file_handler(self, log_dir):
        """ Initialize robot formatter to log the messages  """
        log_file = str(log_dir) +"/avitest_robot.log"
        self.file_robot_handle = logging.FileHandler(log_file)
        robotformatter = RobotXMLFormatter('[%(asctime)s] :%(levelname)s: [%(fl_name)s %(fn_name)s:%(ln_no)s] %(message)s')
        self.file_robot_handle.setFormatter(robotformatter)
        self.logger.addHandler(self.file_robot_handle)
        numeric_level = self.level.get(self.loglevel,None)
        self.file_robot_handle.setLevel(numeric_level)

    def setlevel(self,level):
        numeric_level = self.level.get(level.upper(),None)
        self.consoleHandle.setLevel(numeric_level)
        self.file_handle.setLevel(numeric_level)
        self.loglevel = level.upper()

    def resolve_message(self, msg, *args, **kwargs):
        if args:
            return msg % args
        else:
            return msg
        
    def write(self, msg, *args, **kwargs):
        level = kwargs.pop('level', 'INFO')
        if level in ['ERROR', 'FAIL', 'ABORT']:
            index = 4
        else:
            index = 3
        caller_details = self.__get_caller(index)
        custom_log={}
        custom_log.update(caller_details)
        self.logger.log(self.level[level], msg, extra = custom_log, *args, **kwargs)

    def trace(self, msg, *args, **kwargs):
         """Writes the message to the log file using the ``TRACE`` level."""
         self.write(msg, level='TRACE', *args, **kwargs)

    def debug(self, msg, *args, **kwargs):
        """Writes the message to the log file using the 'DEBUG' level."""
        self.write(msg, level='DEBUG', *args, **kwargs)
    
    def info(self, msg, *args, **kwargs):
        """Writes the message to the log file using the 'INFO' level.
        """
        self.write(msg, level='INFO', *args, **kwargs)
    
    def warning(self, msg, *args, **kwargs):
        """Writes the message to the log file using the 'WARNING' level."""
        self.write(msg, level='WARNING', *args, **kwargs)

    def _error(self, msg, *args, **kwargs):
        """Writes the message to the log file using the 'ERROR' level.
    
        """
        if self._log:
            self.write(msg, level='ERROR', *args, **kwargs)
        # Resolve the msg with args here?
        raise ErrorError(self.resolve_message(msg, *args, **kwargs))

    def _fail(self, msg, *args, **kwargs):
        """Writes the message to the log file using the 'FAIL' level.

        """
        force = kwargs.pop('force', False)
        __tracebackhide__ = True
        if self._log:
            self.write(msg, level='FAIL', *args, **kwargs)
        if force:
            # Resolve the msg with args here?
            raise ForcedFailError(self.resolve_message(msg, *args, **kwargs))
        raise FailError(self.resolve_message(msg, *args, **kwargs))
        
    def _abort(self, msg, *args, **kwargs):
        """Writes the message to the log file using the 'ABORT' level.

        """
        __tracebackhide__ = True
        if self._log:
            self.write(msg, level='ABORT', *args, **kwargs)
            self.skip_tc = True
        # Resolve the msg with args here?
        raise AbortError(self.resolve_message(msg, *args, **kwargs))

    def report_errors(self):
        __tracebackhide__ = True
        if self.error_list:
            msg = '\n'.join(self.error_list)
            self.error_list = []
            pytest.fail(msg)

    def _assert(self, expression, *args, **kwargs):
        msg = kwargs.pop('msg', None)
        if not expression:
            self._error(msg, *args, **kwargs)

    def __get_caller(self, index):
        """ Returns the Caller function name of aiLog """
        (filename, line, funcname, contextlist) =  inspect.stack()[index][1:5]
        filename = os.path.split(filename)[1]
        caller_details = {'fl_name': filename, 
                          'ln_no': line, 
                          'fn_name': funcname}
        return caller_details
    
def adb():
    """Interactive Shell invocation"""
    copy_stdout = copy.copy(sys.stdout)
    copy_stderr = copy.copy(sys.stderr)
    code.sys.stdout = sys.__stdout__
    code.sys.stderr = sys.__stderr__
    sys.ps1 = 'avitest>>>'
    sys.ps2 = 'avitest...'
    import readline
    import rlcompleter
    readline.parse_and_bind("tab: complete")
    avi_banner = '\n' + '*' * 50
    avi_banner = avi_banner + '\n' + 'Welcome to avitest debug shell'.center(50) + '\n'
    avi_banner = avi_banner + '*' * 50 + '\n'
    try: 
        frame = inspect.currentframe()
        caller = inspect.getouterframes(frame,2)
        if caller[1][3] == 'write':
            called_frame = caller[3][0]
        else:
            called_frame = caller[1][0]
        code.interact(banner=avi_banner, local=dict(called_frame.f_globals, **called_frame.f_locals))
    except SystemExit:
        pass
    sys.stdout = copy_stdout
    sys.stderr = copy_stderr
    return

logger = AviLogger()
