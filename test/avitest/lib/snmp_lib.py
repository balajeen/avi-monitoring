from avi_objects.infra_imports import get, patch, put, get_vm_of_type, logger, error
import json
import shlex
from lib.cluster_lib import get_cluster_master_vm

def set_community_string(community_string=None):
    if community_string is not None:
        obj_type= 'systemconfiguration'
        obj_name= 'snmp_configuration'
        resp_code, resp_data = get(obj_type)
        if(resp_code != 200):
            error('Error! REST call failed, obj_type %s' % obj_type)

        if not resp_data:
            error('Error! data NULL for %s' % obj_type)
        if obj_name in resp_data:
            resp_data[obj_name]['community'] = community_string
            patch(obj_type,'', data = json.dumps(resp_data), tenant='admin')
        else:
            resp_data["snmp_configuration"] = {"community": community_string}
            put(obj_type, '', data=json.dumps(resp_data))

def get_community_string():
    community_string = []
    obj_type='systemconfiguration'
    resp_code, resp_data = get(obj_type)
    if(resp_code != 200):
        error('Error! REST call failed, obj_type %s' % obj_type)

    if not resp_data:
        error('Error! data NULL for %s' % obj_type)
    if 'snmp_configuration' in resp_data:
        community_string=resp_data['snmp_configuration']['community']
    return community_string

def execute_snmpwalk(test_string=None):
    if test_string is not None:
        controller_list = get_vm_of_type('controller')
        for controller_vm in controller_list:
            controller_ip = controller_vm.ip
            cmd = 'snmpwalk -v 2c -c ' + test_string + ' ' + controller_ip
            print 'Running SNMP walk for %s' % (cmd)
            client_vm = get_vm_of_type('client')
            out =  client_vm.execute_command(cmd)
            print 'out', out
            return out

def execute_snmpwalk_for_avi(test_string='public', query_string=None, vm=None, version="SNMP_VER2", **kwargs):
    """
    Execute the snmpwalk on client vm
    @param test_string: community string
    @param query_string: snmpwalk search object
    @param vm: vm to query
    @return out: Output from snmpwalk
    """
    if not vm:
        vm = get_cluster_master_vm()
    controller_ip = vm.ip

    if version=="SNMP_VER2":
        snmp_cmd = 'snmpwalk -v 2c -c %s %s %s' % (test_string, controller_ip, query_string)
    else:
        username =  kwargs.get("username", "user1")
        priv_type = kwargs.get("priv_type", "AES")
        priv_passphrase = kwargs.get("priv_passphrase", "avinetworks")
        auth_passphrase = kwargs.get("auth_passphrase", "avinetworks")
        auth_type = kwargs.get("auth_type", "MD5")
        snmp_cmd = "snmpwalk -v 3 -l AuthPriv  -u %s -a %s -A %s -x %s -X %s  %s %s"\
                     % (username, auth_type, auth_passphrase, priv_type, priv_passphrase, controller_ip, query_string) 
    cmd = 'export MIBS=+ALL  && export MIBDIR=/usr/share/snmp/mibs && %s' % snmp_cmd
    info = 'Running SNMP walk for %s' % (cmd)
    logger.trace(info)

    client_vm = get_vm_of_type('client')[0]
    out =  client_vm.execute_command(cmd, usesudo=False)
    logger.trace('out %s' % out)
    return out

def parse_snmpwalk_response(response_data):
    """
    Parse the output of snmpwalk command
    @param response_data: output from snmpwalk command
    @return obj: parsed dict
    """
    related_fields={"virtualservice":["aviVirtualServiceUUID", "aviVirtualServiceName", "aviVirtualServiceAddrType",
 "aviVirtualServiceAddr", "aviVirtualServiceStatus"],
                    "serviceengine":["aviServiceEngineUUID", "aviServiceEngineName", "aviServiceEngineAddrType",
 "aviServiceEngineAddr", "aviServiceEngineStatus"],
                    "controller":["aviControllerUUID", "aviControllerName", "aviControllerAddrType",
 "aviControllerAddr", "aviControllerStatus"]}
    obj = {"virtualservice":{}, "serviceengine":{},"controller":{}}
    key_objects = ['aviVirtualServiceName', 'aviControllerAddr', 'aviServiceEngineAddr']
    for line in response_data:
        try:
            #Parse line eg. AVI-NETWORKS-MIB::aviVirtualServiceStatus.2 = INTEGER: down(2)
            type_id_value = shlex.split(line)
            id_value = type_id_value[0].split("::")
            id_value = id_value[1].split(".")
            if id_value[0] == 'aviVirtualServiceName':
                obj['virtualservice'][type_id_value[3]]={"id":id_value[1]}
            if id_value[0]== 'aviServiceEngineAddr':
                obj['serviceengine'][type_id_value[3]] = {"id": id_value[1]}
            if id_value[0]== 'aviControllerAddr':
                obj['controller'][type_id_value[3]] = {"id": id_value[1]}
        except Exception as e:
            logger.trace("Failed to parse line :: %s" % line)
            continue

    for line in response_data:
        try:
            #Parse line eg. AVI-NETWORKS-MIB::aviVirtualServiceStatus.2 = INTEGER: down(2)
            type_id_value = shlex.split(line)
            id_value = type_id_value[0].split("::")
            id_value = id_value[1].split(".")
            for obj_type, attribute in related_fields.iteritems():
                if id_value[0] in attribute:
                    for object, object_dict in obj[obj_type].iteritems():
                        if object_dict["id"] == id_value[1]:
                            obj[obj_type][object][id_value[0]] = type_id_value[3]
        except Exception as e:
            logger.trace("Failed to parse line :: %s" % line)
            continue
    logger.trace("Objects :: %s" % obj)
    return obj

def install_snmp_and_copy_mib_on_client():
    """
    Copy  AVI-NETWORKS-MIB on client vm
    """
    client_vm = get_vm_of_type('client')
    client_vm[0].execute_command('apt-get install snmp')
    cmd = 'git clone https://github.com/avinetworks/sdk.git /tmp/snmp-mib/'
    try:
        client_vm[0].execute_command(cmd)
    except Exception as e:
        pass
    cmd = 'cp -r /tmp/snmp-mib/mibs /usr/share/snmp/'
    client_vm[0].execute_command(cmd)

def set_snmp_configuration(version="SNMP_VER3", **kwargs):
    obj_type= 'systemconfiguration'
    resp_code, system_configuration = get(obj_type)
    if(resp_code != 200):
        error('Error! REST call failed, obj_type %s' % obj_type)

    community_string = kwargs.get("community_string", None)
    sys_location = kwargs.get("sys_location", None)
    sys_contact = kwargs.get("sys_contact", None)

    if not system_configuration.has_key("snmp_configuration"):
        system_configuration["snmp_configuration"] = {}
    system_configuration["snmp_configuration"]["version"] = version
    if version == "SNMP_VER2":
        system_configuration["snmp_configuration"]["community"] = community_string
        if system_configuration["snmp_configuration"].has_key("snmp_v3_config"):
            del system_configuration["snmp_configuration"]["snmp_v3_config"]
    else:
        username =  kwargs.get("username", "user1")
        engine_id = kwargs.get("engine_id", "0x123456789ABCDE")
        priv_type = kwargs.get("priv_type", "SNMP_V3_PRIV_AES")
        priv_passphrase = kwargs.get("priv_passphrase", "avinetworks")
        auth_passphrase = kwargs.get("auth_passphrase", "avinetworks")
        auth_type = kwargs.get("auth_type", "SNMP_V3_AUTH_MD5")

        system_configuration["snmp_configuration"]["snmp_v3_config"] = {"engine_id": engine_id, "user": {"username": username, 
            "priv_type": priv_type, "priv_passphrase": priv_passphrase, "auth_type": auth_type, "auth_passphrase": auth_passphrase}}

        if system_configuration["snmp_configuration"].has_key("community"):
            del system_configuration["snmp_configuration"]["community"]

    if sys_location:
        system_configuration["snmp_configuration"]["sys_location"] = sys_location
    if sys_contact:
        system_configuration["snmp_configuration"]["sys_contact"] = sys_contact
    system_configuration = json.dumps(system_configuration)
    put("systemconfiguration", data= system_configuration)

def get_snmp_configuration():
    snmp_configuration = {}
    obj_type='systemconfiguration'
    resp_code, resp_data = get(obj_type)
    if(resp_code != 200):
        error('Error! REST call failed, obj_type %s' % obj_type)

    if 'snmp_configuration' in resp_data:
        snmp_configuration=resp_data['snmp_configuration']
    return snmp_configuration
