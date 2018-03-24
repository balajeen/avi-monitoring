import avi_objects.rest as rest
import avi_objects.logger_utils as logger_utils
from avi_objects.logger import logger


def vinfra_request_api(obj_type, **kwargs):
    name = kwargs.get("name", None)
    if name:
        resp_code, resp_data = rest.get(obj_type, name=name)
    else:
        resp_code, resp_data = rest.get(obj_type, **kwargs)

    return resp_data


def vimgrhostruntime(**kwargs):
    obj_type = "vimgrhostruntime"
    return vinfra_request_api(obj_type, **kwargs)


def host_should_be_in_state_in_runtime(host_name, host_quarantine_state):
    resp_data = vimgrhostruntime(name=host_name)
    resp_data = resp_data['results'][0] if resp_data.get('results', None) else resp_data
    host_state = resp_data['quarantined']
    if host_state == host_quarantine_state:
        return True
    else:
        return False


def get_host_runtime_and_wait_till_expected_status(host_name, host_quarantine_state, **kwargs):
    retry_timeout = int(kwargs.get('retry_timeout', 1))
    retry_interval = int(kwargs.get('retry_interval', 1))

    @logger_utils.aretry(delay=retry_interval, period=retry_timeout)
    def retry_action():
        return host_should_be_in_state_in_runtime(host_name, host_quarantine_state)

    return retry_action()
