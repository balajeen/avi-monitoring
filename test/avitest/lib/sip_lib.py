from avi_objects import logger_utils
from avi_objects.logger import logger

def get_asterisk_peer_info(server_vm, user):
    info = server_vm.execute_command("asterisk -rx 'sip show peer %s'" % user)
    parsed_info = {}
    for ele in info:
        if len(ele.split(":")) > 1:
            parsed_info[ele.split(":")[0].strip()] = ele.split(":")[1].strip()
    return parsed_info

def verify_user_registration(server_vm, user, expected_key, expected_value):
    info = get_asterisk_peer_info(server_vm, user)
    logger.info("expected key:%s and value: %s. Actual value: %s" 
            % (expected_key, expected_value, info[expected_key]))
    assert info[expected_key] == expected_value
