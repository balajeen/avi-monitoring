import json

import avi_objects.infra_utils as infra_utils
import avi_objects.rest as rest
from avi_objects.infra_utils import get_vm_of_type
from avi_objects.logger import logger


def disable_rpf_on_clients():
    """

    :return:
    """
    local_path = '/tmp/disable_rpf.sh'
    remote_path = '/tmp/disable_rpf_script.sh'
    with open(local_path, 'w') as f:
        f.write('for i in $(find /proc/sys/net/ipv4 -name rp_filter);'
                'do echo 0 > $i;done')

    for vm in get_vm_of_type('client'):
        vm.scp_file(local_path, remote_path)
        vm.execute_command('chmod 0777 %s' % remote_path)
        vm.execute_command(remote_path)


def call_faultinject_api(action, count_num, status_str):
    """
    :param action:
    :param count_num:
    :param status_str:
    :return:
    """
    data = dict()
    data['api'] = str(action)
    data['status'] = str(status_str)
    data['count'] = int(count_num)
    logger.info('POST:: %s' %data)
    status_code, result = rest.post('vimgrvcenterruntime/fault/inject', data=json.dumps(data), check_status_code=False)
    logger.info('REST Result: %s\nStatus Code: %d' % (result, status_code))


def get_server_vm():
    return infra_utils.get_vm_of_type('server')


def cloud_get_all_az():
    config = infra_utils.get_config()
    # Todo for openstack
    #if config.cloud.type == 'openstack':
    #    return config.cloud.az_dict.keys()
    return []


def reboot_vm_by_name(vm_name):
    vm = infra_utils.get_vm_by_id(vm_name)
    vm.reboot()


def power_off_vm_by_name(vm_name):
    vm = infra_utils.get_vm_by_id(vm_name)
    vm.disconnect()


def power_on_vm_by_name(vm_name):
    vm = infra_utils.get_vm_by_id(vm_name)
    vm.connect()


def cloud_supports_multiple_az():
    config = infra_utils.get_config()
    # Todo for openstack
    #if config.cloud.type == 'openstack':
    #    return config.cloud.multi_az()
    return []
