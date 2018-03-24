import time
from logger import logger, ErrorError, FailError, AbortError
import decorator

def fail(msg, *args, **kwargs):
    __tracebackhide__ = True
    logger._fail(msg, *args, **kwargs)

def error(msg, *args, **kwargs):
    if logger._log:
        try:
            logger._error(msg, *args, **kwargs)
        except ErrorError:
            # Resolve msg with args here?
            logger.error_list.append(logger.resolve_message(msg, *args, **kwargs))
    else:
       logger._error(msg, *args, **kwargs)

def abort(msg, *args, **kwargs):
    __tracebackhide__ = True
    logger._abort(msg, *args, **kwargs)

def verify(expression, msg, *args, **kwargs):
    try:
        logger._assert(expression, msg=msg, *args, **kwargs)
    except ErrorError:
        # Resolve msg with args here?
        logger.error_list.append(logger.resolve_message(msg, *args, **kwargs))

def calc_exc_time(func):
    def timed(func, *args, **kwargs):
        ts = time.time()
        result = func(*args, **kwargs)
        te = time.time()
        logger.info('calc_exc_time: %r - %2.2f sec' % (
                func.__name__, te - ts))
        return result
    return decorator.decorator(timed, func)

def asleep(msg='', delay = 15, period = 5):
    ''' 
    Sleeps for delay, periodically printing an update message. 

    :Parameters:
         - msg      - Update message printed periodically.
         - delay    - Total sleep time.
         - peiord   - Time period between update message.
    '''
    elapsed = 0
    remain = delay
    logmsg = msg + ' delay=%s elapsed=%s remain=%s' %(delay, elapsed, remain)
    logger.info(msg=logmsg)
    while 1:
        if remain <= 0:
            break

        if elapsed:
            logmsg = msg + ' elapsed=%s remain=%s' %(elapsed, remain)
            logger.info(msg=logmsg)
        if remain > period:
           time.sleep(period)
        else:
           time.sleep(remain)
        elapsed = elapsed + period
        remain = remain - period       

def aretry(retry = 1, delay = 15, period = 5, exceptions=None, maxtime=None):
    '''
    A decorator which allows a TestScript to execute a command without marking a failure, even if the command fails. 
    Meant to be used for retries and is applicable to only FailError and AbortError.

    :Parameters:
        - retry  - Number of Retries
        - delay  - Sleep between each retry
        - period - Time period between update message.
        - exceptions - exception classes to catch. The defaults to (ErrorError, AbortError, FailError)
        - maxtime - Maximun time(in seconds) retries should happend. This help to prevent long nested retries. 
    '''
    if exceptions is None:
        exceptions = (ErrorError, AbortError, FailError)
    def outer(func):
        def inner(*args, **kwargs):
            time_start = time.time()
            timeout = False
            try_num = 1
            while 1:
                try:
                    logger._log = False
                    return func(*args, **kwargs)
                except exceptions as e:
                    time_now = time.time()
                    if maxtime:
                        if (time_now - time_start) > maxtime:
                            timeout = True
                    try_num = try_num + 1
                    if try_num <= retry and not timeout:
                        logger.info(str(e))
                        logger.info(msg="Will retry try_num=%s retry=%s" %(try_num, retry))
                        asleep(msg="Waiting before retry attempt.", delay=delay,period=period)
                    else:
                        if timeout:
                            logger.warning("Timeout Occured. maxtime = %s" %maxtime)
                        raise
                except:
                    raise
                finally:
                    logger._log = True    
        return inner
    return outer        
