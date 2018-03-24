import time
import urllib

from avi_objects.vm import Se
from avi_objects.logger import logger
from avi_objects import infra_utils

import lib.vs_lib as vs_lib
import avi_objects.rest as rest
import avi_objects.logger_utils as logger_utils
import lib.json_utils as json_utils
import lib.se_lib as se_lib
import lib.placement_lib as placement_lib


def get_event_id_based_log_v2(event_id, log_type=2, page_size='20', vs_name='', duration=1, start_time=None):

    params = {}
    params['type'] = log_type
    params['filter'] = 'eq(event_id,%s)' % event_id 
    params['page_size'] = page_size 
    if vs_name:
        vs_uuid = rest.get_uuid_by_name('virtualservice', name=vs_name)
        params['filter'] = 'co(all,"%s")' % vs_uuid
    if start_time:
        params['start'] = start_time.split('+')[0]
    else:
        params['duration'] = str(duration)
    while True:
        resp_code, resp = rest.get('analytics', path='logs', params=params)
        if resp['percent_remaining'] == 0.0:    # if percent_remaining is zero then break
            break
    logger.info('event id : %s  Count: %s' % (event_id, resp['count']))
    return resp


def get_event_id_based_log_should_not_increase_v2(event_id, prev_event, log_type=2, page_size='20', retry_count=3,
                                                  vs_name=None, start_time=None):
    if not start_time:
        start_time = prev_event['start']
    resp = get_event_id_based_log_v2(event_id, log_type, page_size,
                                     vs_name, start_time=start_time)
    t_diff = abs(json_utils.json_diff(prev_event, resp, 'count'))
    logger.info("T-diff : %d " % t_diff)
    if t_diff > 0:
        logger.info('vs[%s] event[%s] error, count expected[0] != got[%d]' % (
            vs_name, event_id, t_diff))
        logger_utils.fail('vs[%s] event[%s] error, count expected[0] != got[%d]' % (vs_name, event_id, t_diff))
    return resp

def validate_event_description(resp):
    """ This API helps to validate the event description from event log resutls

    Args:
        parms resp : log event results
        type  resp : list
    Raises:
        ValueError, AttributeError, KeyError
    """ 
    for ev in resp['results']:
        if not ev['event_description']:
            logger_utils.fail("Event %s does not have event description" % ev)

def get_event_id_based_log_should_increase_v2(event_id, prev_event, log_type=2, page_size='20', retry_count=6,
                                              increase_count_by=1, vs_name=None, start_time=None):
    if not start_time:
        start_time = prev_event['start']
    for count in range(0, int(retry_count)):
        resp = get_event_id_based_log_v2(event_id, log_type, page_size,
                                         vs_name, start_time=start_time)
        t_diff = abs(json_utils.json_diff(prev_event, resp, 'count'))
        if t_diff == int(increase_count_by): break
    logger.info("T-diff : %d " % t_diff)
    if t_diff != int(increase_count_by):
        logger.info('vs[%s] event[%s] error, count expected[%d] != got[%d] after retrying %d times' % \
              (vs_name, event_id, int(increase_count_by), t_diff, int(retry_count)))
        logger_utils.fail('vs[%s] event[%s] error, count expected[%d] != got[%d] after retrying %d times' %
                                      (vs_name, event_id, int(increase_count_by), t_diff, int(retry_count)))
    validate_event_description(resp)
    return resp

def get_event_id_based_log_should_increase(event_id, prev_event,
                                           log_type=2, retry_count=3,
                                           retry_interval=1, page_size='20',
                                           increase_count_by=None,
                                           vs_name=''):
    for count in range(0, int(retry_count)):
        resp = get_event_id_based_log(event_id, log_type, page_size, vs_name)
        try:
            t_diff = abs(json_utils.json_diff(prev_event, resp, 'count'))
        except Exception:
            logger_utils.fail("Last Event Check Failed Already")
        logger.info("T-diff : %s " % t_diff)
        if t_diff > 0:
            validate_event_description(resp)
            if increase_count_by and t_diff != int(increase_count_by):
                logger_utils.fail('Event count for event %s was expected to increase by %s, but instead increased by %s' %
                    (event_id, increase_count_by, t_diff))
            return resp
        time.sleep(int(retry_interval))
    if t_diff == 0:
        logger_utils.fail('ERROR! No Event %s Generated!' % event_id)
    return resp

def get_event_id_based_log(event_id, log_type=2, page_size='20', vs_name=''):
    url = 'analytics/logs?type=%s&filter=eq(event_id,%s)&page_size=%s' % (
        log_type, event_id, page_size)
    if vs_name:
        vs_obj = vs_lib.get_vs(vs_name)
        vs_uuid = vs_obj['uuid']
        url += '&filter=co(all,"%s")' % vs_uuid
    stime = time.time()
    while time.time() - stime < 400:
        try:
            resp_code, resp = rest.get(url)
            break
        except:
            if "Error" in resp and "search system is down" in resp['Error'].lower():
                logger_utils.asleep(delay=5)
                continue
            logger_utils.fail('ERROR! Analytics server api returned %s:%s' % (resp_code, resp))
    logger.info('event id : %s , count : %s ' % (event_id, resp['count']))
    return resp

def get_event_id_based_log_should_not_increase(event_id, prev_event,
                                               log_type=2,
                                               retry_count=3, retry_interval=1,
                                               page_size='20'):
    for count in range(0, int(retry_count)):
        resp = get_event_id_based_log(event_id, log_type, page_size=page_size)
        t_diff = abs(json_utils.json_diff(prev_event, resp, 'count'))
        logger.info("T-diff : %s " % t_diff)
        time.sleep(int(retry_interval))
    if t_diff > 0:
        logger_utils.fail('ERROR! At least one event Generated!')
    return resp


def get_se_ip_for_vs(vs_name):
    '''
    Gets SE for VS
    '''
    logger.info('se-ip lookup for VS name: %s' % vs_name)
    se_uuid = placement_lib.placement_get_vs_primary_se_uuid(vs_name)
    logger.info('se-uuid: %s' % se_uuid)
    se_ip = se_lib.map_se_uuid_to_ip(str(se_uuid))
    logger.info('se-ip: %s' % se_ip)
    return se_ip


def get_time_in_iso_from_a_vm(a_vm):
    cmd = "python -c 'from datetime import datetime; print datetime.utcnow().isoformat()'"
    out = a_vm.execute_command(cmd)
    logger.info('get_time_in_iso_from_a_vm: %s' %out[0])
    return out[0].rstrip('\n')


# Note: This method is applicable only to SE VM.
# See the Se object instantiation used in the function.
def get_time_in_iso(an_ip):
    # TODO: get_cloud_type, platform type, deployment type
    deployment = 'vm'
    platform = 'vcenter'
    a_vm = Se(ip=an_ip, deployment=deployment, platform=platform)
    return get_time_in_iso_from_a_vm(a_vm)


def get_time_in_iso_from_controller():
    for vm in infra_utils.get_vm_of_type('controller'):
        out = get_time_in_iso_from_a_vm(vm)
        return out


def get_log_type(vs_name):
    vs_type = vs_lib.get_vs_type(vs_name)
    logger.info('vs_type: %s' % vs_type)
    if vs_type == "APPLICATION_PROFILE_TYPE_L4" or vs_type == "APPLICATION_PROFILE_TYPE_DNS":
        log_type = 0
    else:
        log_type = 1
    return log_type


def get_log(vs_name, **kwargs):
    '''
    Returns the connection log for l4 proxy or application log for l7 proxy
    Log type can be overridden with kwarg log_type:
      0 = connection logs
      1 = application logs
      2 = event logs
    '''
    query = kwargs.get('query', '')
    log_type = kwargs.get('log_type')

    if log_type:
        log_type = int(log_type)
    else:
        log_type = get_log_type(vs_name)

    url = 'analytics/logs?virtualservice=%s&type=%s' % (vs_name, log_type)
    if query:
        url += '&%s' % query
    url = urllib.quote(url, "?=&:")
    resp_code, resp = rest.get(url)
    return resp


def get_log_count(vs_name, **kwargs):
    '''
    Helper method to get log and return the count
    '''
    query = kwargs.get("query", "")
    if "page_size" not in query:
        query += "&page_size=1"
        kwargs["query"] = query
    log = get_log(vs_name, **kwargs)
    count = get_log_count_from_log(log)
    return int(count)


def get_log_count_from_log(log):
    '''
    Given a log dictionary, returns the count
    '''
    return log['count']


def has_log_count_increased_by(vs_name, initial_log_count, expected_log_count,
                               **kwargs):
    '''
    Internal use only
    '''
    initial_log_count = int(initial_log_count)
    expected_log_count = int(expected_log_count)
    atleast = int(kwargs.get('atleast', 0))
    query = kwargs.get("query", "")
    if("page_size" not in query):
        query += "&page_size=1"
        kwargs["query"] = query
    log = get_log(vs_name, **kwargs)
    current_log_count = get_log_count_from_log(log)
    logger.info('current_log_count: %s' % current_log_count)
    if atleast == 1:
        if (current_log_count - initial_log_count) >= expected_log_count:
            return log
        else:
            return False

    if (current_log_count - initial_log_count) == expected_log_count:
        return log
    else:
        if (current_log_count - initial_log_count) > expected_log_count:
            query += "&page_size=100"
            pquery = kwargs.get("query", None)
            kwargs["query"] = query
            get_log(vs_name, **kwargs)
            if(pquery is not None):
                kwargs["query"] = pquery
                logger_utils.fail("log count increased beyond specified value")
        # use the end value returned in the response for future queries
        if log.get('percent_remaining', 0.0) > 0.0:
            pquery = kwargs.get("query", "")
            if "&end" not in pquery and "end" in log:
                kwargs["query"] = pquery + "&end=" + log['end']
        return False


@logger_utils.aretry(retry=2, delay=0.1, period=10)
def log_count_should_increase_by(vs_name, initial_log_count, expected_increase_log_count,
                                 **kwargs):
    '''
    Blocks until log count has increased by expected_log_count or retry_timeout
    time is reached
    '''
    logger.info('initial_log_count: %s' % initial_log_count)
    logger.info('expected_increase_log_count: %s' % expected_increase_log_count)
    resp = has_log_count_increased_by(vs_name, initial_log_count,
                                      expected_increase_log_count, **kwargs)

    if not resp:
        logger_utils.error('Log count did not increase by expected value vs %s' % vs_name)
    else:
        return resp


def check_log_per(vs_logs, se_list):
    se_logs = {}
    for se in se_list:
        se_logs[se] = 0
    vs_logs_list = vs_logs.get("results")
    len_of_logs =  len(vs_logs_list)
    for vs_log in vs_logs_list:
        se_uuid = vs_log.get("service_engine")
        se_logs[se_uuid] = se_logs[se_uuid] + 1
    if len_of_logs and len(se_list) > 1:
        round_log = len_of_logs / float(len(se_list))
        round_per = round_log / len_of_logs * 100
        if round(round_per) in range(1, 11):
            plus_minus_per = 1
        elif round(round_per) in range(11, 21):
            plus_minus_per = 2
        elif round(round_per) in range(21, 31):
            plus_minus_per = 3
        elif round(round_per) in range(31, 41):
            plus_minus_per = 4
        elif round(round_per) in range(41, 51):
            plus_minus_per = 5
        for se in se_list:
            get_se_percentage = float(se_logs[se])/float(len_of_logs) * 100
            assert round(get_se_percentage) > (round_per - plus_minus_per) and round(get_se_percentage) < (round_per + plus_minus_per)
