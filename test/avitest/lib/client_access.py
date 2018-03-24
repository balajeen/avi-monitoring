import json
import avi_objects.infra_utils as infra_utils
import avi_objects.logger_utils as logger_utils
import avi_objects.rest as rest
import xmltodict
from avi_objects.logger import logger
from netaddr import (IPSet, IPRange)


def get_system_configuration(**kwargs):
    '''
    Get management IP acces control config
    :param kwargs:
    :return:
    '''
    _, json_systemconfiguration_data = rest.get('systemconfiguration')
    return json_systemconfiguration_data


def get_mgmt_access_objects(access):
    '''

    :param access:
    :return:
    '''
    systemconfiguration = get_system_configuration()
    mgmt_ip_access_control = systemconfiguration.get('mgmt_ip_access_control')
    if not access or not mgmt_ip_access_control:
        access_object = None
    elif access in ('shell_server_access', 'snmp_access', 'api_access',
                    'ssh_access'):
        if mgmt_ip_access_control:
            access_object = mgmt_ip_access_control.get(access)
    return access_object, systemconfiguration, mgmt_ip_access_control


def flush_iptables_rules_and_system_configuration(**kwargs):
    '''

    :param kwargs:
    :return:
    '''
    controllers = infra_utils.get_vm_of_type('controller')
    for each_controller in controllers:
        cmd = "iptables  -F AVI_INPUT"
        each_controller.execute_command(cmd)
        cmd = "ipset destroy"
        each_controller.execute_command(cmd)
    access_object, systemconfiguration, mgmt_ip_access_control = \
        get_mgmt_access_objects(None)
    if mgmt_ip_access_control:
        del systemconfiguration['mgmt_ip_access_control']
    rest.put('systemconfiguration', data=systemconfiguration)


def update_ip_addr_ranges(start, end, access, **kwargs):
    '''

    :param start:
    :param end:
    :param access:
    :param kwargs:
    :return:
    '''
    access_object, systemconfiguration, mgmt_ip_access_control = \
        get_mgmt_access_objects(access)
    mgmt_ip_access_control = systemconfiguration.get('mgmt_ip_access_control')
    if not mgmt_ip_access_control:
        systemconfiguration['mgmt_ip_access_control'] = {}
    access_object = systemconfiguration.get('mgmt_ip_access_control').get(access)
    if not access_object:
        access_object = {}
    access_object['match_criteria'] = 0
    access_object['ranges'] = []
    access_object['ranges'].append({'begin': {'type': 0, 'addr': start}, 'end': {'type': 0, 'addr': end}})
    systemconfiguration['mgmt_ip_access_control'][access] = access_object
    rest.put('systemconfiguration', data=systemconfiguration)


def cleanup_and_parse_xml(xml_string):
    '''
    Cleanups xml string which is unwanted. e.g with docker it adds up
    You have new mail in /var/spool/mail/root in output.
    :param xml_string:
    :return:
    '''
    if xml_string:
        return xmltodict.parse(xml_string[:xml_string.rfind('>')+1])
    return None


def get_elements_set(ip_set_output):
    '''

    :param ip_set_output:
    :return:
    '''
    ip_set_elements = set()
    ip_set = cleanup_and_parse_xml(ip_set_output)
    if ip_set and 'ipsets' in ip_set:
        ip_sets = ip_set['ipsets']
        if ip_sets and 'ipset' in ip_sets:
            ipsets_set = ip_sets['ipset']
            if ipsets_set and 'members' in ipsets_set:
                members = ipsets_set['members']
                if members and 'member' in members:
                    member = members['member']
                    if member:
                        # it doesnt loop through for single element
                        if len(member) > 1:
                            for elem in member:
                                ip_set_elements.add(elem['elem'])
                        else:
                            ip_set_elements.add(member['elem'])
    logger.info("Elements::" + str(ip_set_elements))
    return ip_set_elements


def append_rules_to_rules_ipset(ip_addrs, input_type):
    '''
    Add rules to IPSet for comparison
    :param ip_addrs:
    :param input_type:
    :return:
    '''
    rules_set = IPSet()
    if input_type == 'address':
        rules_set.add(ip_addrs)
    elif input_type == 'range':
        rules_set.add(IPRange(ip_addrs.split('-')[0], ip_addrs.split('-')[1]))
    elif input_type == 'prefix':
        rules_set.add(ip_addrs)
    logger.info("Rules set: " + str(rules_set))
    return rules_set


def verify_iptables_rules(access, ip_address, type, **kwargs):
    '''

    :param access:
    :param ip_address:
    :param type:
    :param kwargs:
    :return:
    '''
    controllers = infra_utils.get_vm_of_type('controller')
    for each_controller in controllers:
        cmd = "iptables -L AVI_INPUT"
        output = each_controller.execute_command(cmd)
        if access not in str(output) and 'DROP' not in str(output):
            logger_utils.fail('IP Tables Rules not configured Properly')
        cmd = "ipset --list %s -o xml" % access
        ip_set_output = each_controller.execute_command(cmd)

        if ip_set_output:
            ip_set_list = get_elements_set("".join(ip_set_output))
            system_ip_set = IPSet(ip_set_list)
            input_ip_set = append_rules_to_rules_ipset(ip_address, type)
            if input_ip_set.issubset(system_ip_set):
                return True
        logger_utils.fail('IP Set Rules not configured Properly for Controller '
                         '%s' % each_controller.ip)


def update_ip_addr_prefix(start, prefix, access, **kwargs):
    '''

    :param start:
    :param prefix:
    :param access:
    :param kwargs:
    :return:
    '''
    access_object, systemconfiguration, mgmt_ip_access_control = \
        get_mgmt_access_objects(access)
    mgmt_ip_access_control = systemconfiguration.get('mgmt_ip_access_control')
    if not mgmt_ip_access_control:
        systemconfiguration['mgmt_ip_access_control'] = {}
    access_object = systemconfiguration.get('mgmt_ip_access_control').get(access)
    if not access_object:
        access_object = {}
    access_object['match_criteria'] = 0
    access_object['prefixes'] = []
    access_object['prefixes'].append({'ip_addr' : {'type': 0, 'addr': start}, 'mask': int(prefix)})
    systemconfiguration['mgmt_ip_access_control'][access] = access_object
    rest.put('systemconfiguration', data=systemconfiguration)


def get_local_ip_client_access(**kwargs):
    '''

    :param kwargs:
    :return:
    '''
    from subprocess import check_output
    cmd = "hostname -I |  awk 'NR==1{print $1}'"
    p = check_output(cmd, shell=True)
    return p.strip()


def create_ip_addr_group(name, ip, prefix, **kwargs):
    '''
    Creates IP address group
    :param name:
    :param ip:
    :param kwargs:
    :return:
    '''
    ip_addr = {}
    ip_addr['name'] = name
    ip_addr['prefixes'] = []

    for each_ip in ip:
        new_ip_addr = {}
        new_ip_addr['addr'] = each_ip
        new_ip_addr['type'] = 0 #For type V4
        ip_addr['prefixes'].append({'ip_addr': new_ip_addr, 'mask': int(prefix)})
        # TODO need to check for mask to IP address group

    ip_addr['description'] = "Created for testing"
    rest.post('ipaddrgroup', data=ip_addr)


def update_ip_addr_group(name, access, **kwargs):
    '''

    :param name:
    :param access:
    :param kwargs:
    :return:
    '''
    access_object, systemconfiguration, mgmt_ip_access_control = \
        get_mgmt_access_objects(access)
    mgmt_ip_access_control = systemconfiguration.get('mgmt_ip_access_control')
    if not mgmt_ip_access_control:
        systemconfiguration['mgmt_ip_access_control'] = {}
    access_object = systemconfiguration.get('mgmt_ip_access_control').get(
        access)
    status_code, response = rest.get('ipaddrgroup', name=name)
    if not access_object:
        access_object = {}

    access_object['match_criteria'] = 0
    if not access_object.get('group_refs'):
        access_object['group_refs'] = []
    access_object['group_refs'].append(response.get('url'))
    systemconfiguration['mgmt_ip_access_control'][access] = access_object
    rest.put('systemconfiguration', data=systemconfiguration)


def delete_ip_addr_group(name, **kwargs):
    '''

    :param name:
    :param kwargs:
    :return:
    '''
    rest.delete('ipaddrgroup', name=name)


def remove_ip_addr_group(name, access, **kwargs):
    '''

    :param name:
    :param access:
    :param kwargs:
    :return:
    '''
    access_object, systemconfiguration, mgmt_ip_access_control = \
        get_mgmt_access_objects(access)
    mgmt_ip_access_control = systemconfiguration.get('mgmt_ip_access_control')
    if not mgmt_ip_access_control:
        systemconfiguration['mgmt_ip_access_control'] = {}
    access_object = systemconfiguration.get('mgmt_ip_access_control').get(
        access)
    status_code, response = rest.get('ipaddrgroup', name=name)
    if status_code >= 300:
        logger_utils.fail('Error in retrieving IP address group')

    ip_addr_group_ref = response.get("url")
    for group_ref in access_object['group_refs']:
        if ip_addr_group_ref == group_ref:
            access_object['group_refs'].remove(group_ref)

    rest.put('systemconfiguration', data=systemconfiguration)


def update_ssh_ciphers_and_hmac(ciphers, hmacs, **kwargs):
    '''

    :param ciphers:
    :param hmacs:
    :param kwargs:
    :return:
    '''
    systemconfiguration = get_system_configuration()

    if ciphers:
        # append if exist
        for cipher in ciphers:
            ssh_ciphers = systemconfiguration.get('ssh_ciphers', None)
            if not ssh_ciphers:
                systemconfiguration['ssh_ciphers'] = []
            systemconfiguration['ssh_ciphers'].append(cipher)

    if hmacs:
        # append if exist
        for hmac in hmacs:
            ssh_hmacs = systemconfiguration.get('ssh_hmacs', None)
            if not ssh_hmacs:
                systemconfiguration['ssh_hmacs'] =[]
            systemconfiguration['ssh_hmacs'].append(hmac)

    rest.put('systemconfiguration', data = systemconfiguration)


def _verify_output(output, type, list, vm, vm_type):
    '''

    :param output: /etc/ssh/sshd_config content
    :param type: Ciphers, MACs
    :param list: ciphers or hmacs
    :param vm:
    :param vm_type:
    :return:
    '''
    if list:
        ssh_ciphers_structure = ",".join(list)
        cipher_format = "%s %s" % (type, ssh_ciphers_structure)
        if cipher_format not in str(output):
            logger_utils.fail('SSH %s not configured Properly for %s %s ' % (
                type, vm_type, vm.ip))
    else:
        if type in str(output):
            logger_utils.fail('SSH %s not configured Properly for %s %s' % (
                type, vm_type, vm.ip))


def verify_ssh_ciphes_and_hmac(ciphers=[], hmacs=[], **kwargs):
    '''

    :param ciphers:
    :param hmacs:
    :param kwargs:
    :return:
    '''

    controllers = infra_utils.get_vm_of_type('controller')

    for each_controller in controllers:
        cmd = "cat /etc/ssh/sshd_config"
        output = each_controller.execute_command(cmd)
        _verify_output(output, "Ciphers", ciphers, each_controller, "controller")
        _verify_output(output, "MACs", hmacs, each_controller, "controller")

    ses = infra_utils.get_vm_of_type('se')
    for each_se in ses:
        cmd = "cat /etc/ssh/sshd_config"
        output = each_se.execute_command(cmd)
        _verify_output(output, "Ciphers", ciphers, each_se, "se")
        _verify_output(output, "MACs", hmacs, each_se, "se")


def remove_ssh_ciphers_and_hmac(ciphers, hmacs, **kwargs):
    '''

    :param ciphers:
    :param hmacs:
    :param kwargs:
    :return:
    '''
    systemconfiguration = get_system_configuration()
    if ciphers:
        # append if exist
        for cipher in ciphers:
            ssh_ciphers = systemconfiguration.get('ssh_ciphers', None)
            if ssh_ciphers:
                systemconfiguration['ssh_ciphers'].remove(cipher)

    if hmacs:
        # append if exist
        for hmac in hmacs:
            ssh_hmacs = systemconfiguration.get('ssh_hmacs', None)
            if ssh_hmacs:
                systemconfiguration['ssh_hmacs'].remove(hmac)

    rest.put('systemconfiguration', data = systemconfiguration)
