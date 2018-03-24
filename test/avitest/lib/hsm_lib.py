from avi.sdk.avi_api import ApiSession
import json
import pexpect
import logging
from api.Linux import Linux
from scp import SCPClient
import time
from requests_toolbelt import MultipartEncoder
import os
import re
"""
==============
HSM Configuration
==============

This library can be used to:
    -> uploads hsm package on controller
    -> create/configure the HSM groups
    -> register the client ips to HSM server,
    -> assign and remove HSM group from SE group
    -> create ssl certs
    -> cleanup of HSM group and dependent objects(ssl_certs)

    hsmpkg_configuration()      -> uploads the hsm packages on the controller
    e.g hsmpkg_configuration(session, "/mnt/builds/safenet_pkg/safenet.tar")

    create_hsm_safenet_group()  -> create HSM group, register the client ips to HSM server, and set the HA
    e.g create_hsm_safenet_group(session, "hsmgrp_name", hsm_server_partitions=[("hsm_server_ip", "partition_name"), ...])

    associate_hsm_group_to_se_group()   -> assign hsm group to se group
    e.g associate_hsm_group_to_se_group(session, "Default-Group", "hsmgrp_name")

    verify_hsm_configuration()          -> verifies HSM configured correctly
    e.g verify_hsm_configuration(session, "hsmgrp_name", "se_grp_name")

    hsm_cleanup()   -> removes the ssl certs associated with the HSM group from vs, deletes the ssl certs, removes the hsm group from se group
                       delete clients from HSM server, delete HSM group
    e.g hsm_cleanup(session, "hsmgrp_name", segrp_name="Default-Group")

"""

LOG = logging.getLogger(__name__)

user = "admin"
root_user = "root"
password = "avi123"

hsm_server_details = {
            "10.128.1.51":{"hsm_username":"admin", "hsm_password": "1!Avi123"},
            "10.128.1.52":{"hsm_username": "admin", "hsm_password": "1!Avi123"},
          }
hsm_partition_details = {
            "10.128.1.51":{
                "par1": {'serial_num': '529532014', 'partition_password': "S@fenet123"},
                "par2": {'serial_num': '529532018', 'partition_password': "S@fenet123"}
                },
            "10.128.1.52":{
                "par1": {'serial_num': '529579014', 'partition_password': "S@fenet123"},
                "par2": {'serial_num': '529579541', 'partition_password': "S@fenet123"}
                },
            }

def create_session(c_ip, username, password, tenant='admin', api_version=None, port=443):
    """
    creates controller session
    :return: session object
    """
    api = ApiSession.get_session(c_ip, username, password, tenant=tenant, api_version=api_version, port=port)
    LOG.debug("session created")
    return api


def _scp_file(remote_ip, username, password, src, dest, remote_to_local=True):
    client = Linux(remote_ip, username, password)
    scpClient = SCPClient(client.child.get_transport(), socket_timeout=60.0)
    try:
        if remote_to_local:
            scpClient.get(src, dest)
        else:
            scpClient.put(src, dest)
    except Exception as e:
        raise Exception("Exception: %s" % e)


def _create_ssh_session(host_ip, username, password):
    """
    Creates ssh connection with host
    :return: ssh session handle which can use to execute further commands on remote host
    """
    cmd = "ssh %s@%s" % (username, host_ip)
    ssh_session = pexpect.spawn(cmd)
    try:
        response = ssh_session.expect('Are you sure you want to continue connecting (yes/no)?', 5)
        if response == 0:
            ssh_session.sendline("Yes")
    except:
        pass
    password_response = ssh_session.expect('password:')
    if password_response == 0:
        ssh_session.sendline(password)
        ssh_response = ssh_session.expect('Last login:')
        if ssh_response == 0:
            ssh_session.timeout = 20
            return ssh_session
    return


def _hsm_client_delete(ssh_session, client_ip):
    """
    delete registered clients
    :param ssh_session:
    :param client_ip:
    """
    delete_cmd = "client delete -c %s" % (client_ip)
    try:
        ssh_session.sendline(delete_cmd)
        ssh_session.expect('Are you sure you wish to delete client named')
        LOG.debug("Are you sure you wish to delete client named %s" % client_ip)
        ssh_session.sendline("proceed")
        LOG.debug("proceed")
        ssh_session.expect("'client delete' successful")
        LOG.debug("client %s deleted successfully" % client_ip)
    except Exception as e:
        LOG.error("Error while deleting client %s" % e)


def _hsm_client_revoke_partition(sshsession, client_ip, partition_name):
    cmd = "client revokePartition -c %s -p %s" % (client_ip, partition_name)
    sshsession.sendline(cmd)
    try:
        par_revoke_resp = sshsession.expect("'client revokePartition' successful")
        if par_revoke_resp == 0:
            LOG.debug("Partition revoked successfully for client %s" % client_ip)
            return
    except:
        try:
            sshsession.expect("Specified partition was not assigned to client")
            LOG.debug("Specified partition was not assigned to client %s " % client_ip)
        except Exception as e:
            raise Exception("Exception : %s" % e)

def _verify_client_register(ssh_session):
    register_resp = ssh_session.expect("'client register' successful")
    if register_resp == 0:
        LOG.debug("client registerd successfully")
        return
    else:
        LOG.error("client registration failed")
        raise Exception("client registration failed")

def hsm_client_setup(session, hsmgrp_name, force_delete=False, expect_error=True, hsm_server_conf=[]):
    """
    scp the client certs from controller to HSM(<client_ip>.pem), register client and assign partition
    :param skip_client: skip the registration for clients
    :param force_delete: delete client before registration if client is already registered
    :param expect_error: expect a error if client is already registered
    """
    hsm_resp = session.get_object_by_name("hardwaresecuritymodulegroup", hsmgrp_name)
    registered_hsm_servers = []
    if hsm_server_conf:
        hsm_servers = hsm_server_conf
    else:
        hsm_servers = hsm_resp['hsm']['sluna']['server']
    for hsm_server in hsm_servers:
        hsm_server_ip = hsm_server["remote_ip"]
        hsm_registered_ips = _get_registered_client_ips(hsm_server_ip)
        ssh_session = _create_ssh_session(hsm_server_ip, hsm_server_details[hsm_server_ip]["hsm_username"],
                                                           hsm_server_details[hsm_server_ip]["hsm_password"])
        if hsm_server_conf:
            partition_name = hsm_server["partition_name"]
        else:
            partition_name = [ part_name for (part_name, part_details) in  hsm_partition_details[hsm_server_ip].iteritems() if part_details['serial_num'] == hsm_server['partition_serial_number']][0]
        for node in hsm_resp['hsm']['sluna']['node_info']:
            client_ip = node["client_ip"]
            if hsm_server_ip not in registered_hsm_servers:
                if client_ip in hsm_registered_ips and force_delete:
                    _hsm_client_revoke_partition(ssh_session, client_ip,  partition_name)
                    _hsm_client_delete(ssh_session, client_ip)
                    hsm_registered_ips.remove(client_ip)
                elif client_ip in hsm_registered_ips and expect_error:
                    raise Exception("Client %s already registered" % client_ip)
                if client_ip not in hsm_registered_ips:
                    _scp_client_cert_to_hsm(session, hsmgrp_name, client_ip, hsm_server_ip,
                                           hsm_server_details[hsm_server_ip]["hsm_username"],
                                           hsm_server_details[hsm_server_ip]["hsm_password"])
                    _hsm_client_register(ssh_session, client_ip)

            _hsm_client_assign_partition(ssh_session, client_ip, partition_name)
        registered_hsm_servers.append(hsm_server_ip)

def _hsm_client_register(ssh_session, client_ip):
    """
    register client on hsm server
    """

    hsm_login_resp = ssh_session.expect("lunash:>")
    if hsm_login_resp == 0:
        LOG.debug("Logged in to HSM ")
    register_cmd = "client register -c %s -i %s" % (client_ip, client_ip)
    ssh_session.sendline(register_cmd)
    LOG.debug(register_cmd)
    try:
        _verify_client_register(ssh_session)
        return
    except Exception as e:
        LOG.error("Exception: %s" % e)

def _hsm_client_assign_partition(sshsession, client_ip, partition_name):
    """
    Assigns partition to registered client
    :param sshsession: loggedin session for HSM server
    :param client_ip: client IP address to which the partition is to be aassigned
    :param partition_name: partition name
    :return:
    """
    cmd = "client assignPartition -c %s -p %s" % (client_ip, partition_name)
    sshsession.sendline(cmd)
    try:
        par_assign_resp = sshsession.expect("'client assignPartition' successful")
        if par_assign_resp == 0:
            LOG.debug("successfully assigned partition to the client: %s" % client_ip)
            return
    except:
        try:
            sshsession.expect("client already has access")
            LOG.debug("The client already has access to the specified partition")
        except Exception as e:
            LOG.error("Exception : %s" % e)


def _read_file(filepath):
    """
    read the contents of file
    """
    try:
        with open(filepath, 'r') as infile:
            return infile.read()
    except Exception as e:
        LOG.error("Error: %s" % e)
        raise Exception("Error: %s" % e)


def _write_file(filepath, content):
    """
    write the contents to file
    """
    try:
        file = open(filepath, 'w')
        file.write(content)
    except Exception as e:
        LOG.error("Error: %s" % e)
        raise Exception("Error: %s" % e)


def _get_hsm_server_cert(server_ip, username, password):
    """
    get HSM server cert from HSM server
    """
    server_pem_file = "/tmp/server%s.pem" % server_ip
    _scp_file(server_ip, username, password, "server.pem",server_pem_file)
    server_cert = _read_file(server_pem_file)
    return server_cert


def create_hsm_safenet_group(session, hsmgrp_name, hsm_server_partitions=[], dedicated_flag=False, client_ips=[], is_ha=True, dedicated_ctrl_ip=False, expect_error=True, force_delete=False):
    """
    created the HSM safenet group
    :param hsmgrp_name: HSM group name
    :param hsm_server_partitions: hsm server ip and partition name list eg. [("1.1.1.1", "par1"), ("2.2.2.2", "par2")]
    :param session: api session of controller
    :param tenant: tenant name
    :param client_ips: client IP address for HSM server
    :return: contents of HSM group creation response
    """
    hsm_group_obj = {}
    hsm_group_obj['name'] = hsmgrp_name
    hsm_group_obj['hsm'] = {'type': 'HSM_TYPE_SAFENET_LUNA', 'sluna': {}}
    hsm_group_obj['hsm']['sluna']['server'] = []
    hsm_group_obj['hsm']['sluna']['node_info'] = []

    for hsm_server_partition in hsm_server_partitions:
        (hsm_server_ip, partition_name) = hsm_server_partition
        hsm_server = hsm_server_details[hsm_server_ip]
        server_cert = _get_hsm_server_cert(hsm_server_ip, hsm_server['hsm_username'],
                                          hsm_server['hsm_password'])
        hsm_server_detail = {"remote_ip": hsm_server_ip, "partition_passwd": hsm_partition_details[hsm_server_ip][partition_name]['partition_password'],
                "partition_serial_number":hsm_partition_details[hsm_server_ip][partition_name]['serial_num'], "server_cert": server_cert}
        hsm_group_obj['hsm']['sluna']['server'].append(hsm_server_detail)
    if client_ips:
        for client_ip in client_ips:
            hsm_group_obj['hsm']['sluna']['node_info'].append({"client_ip": client_ip})
    else:
        if dedicated_flag:
            client_ips = _get_hsm_dedicated_ips(session, dedicated_ctrl_ip)
            hsm_group_obj['hsm']['sluna']['node_info'] = client_ips
            hsm_group_obj['hsm']['sluna']['use_dedicated_network'] = True
        else:
            client_ips = _get_hsm_management_ips(session)
            hsm_group_obj['hsm']['sluna']['node_info'] = client_ips
        client_ips = [client["client_ip"] for client in client_ips]

    data = json.dumps(hsm_group_obj)
    out = session.post("hardwaresecuritymodulegroup", data=data)
    if out.status_code >= 300:
        LOG.error("Failed to create HSM group. Error: %s" % out.content)
        raise Exception("Failed to create HSM group. Error: %s" % out.content)
    LOG.debug("HSM group created. Content: %s" % out.content)
    _verify_client_certs_for_hsmgroup(session, hsmgrp_name, client_ips)
    hsm_client_setup(session, hsmgrp_name, expect_error=expect_error, force_delete=force_delete)
    set_hsm_ha(session, hsmgrp_name, is_ha)


def _get_controller_ips(session):
    cluster_resp = session.get("cluster")
    cluster_resp = json.loads(cluster_resp.content)
    controller_ips = [node["ip"]["addr"] for node in cluster_resp["nodes"]]
    return controller_ips

def _get_se_ips(session, segrp_name=None):
    if segrp_name:
        se_ip_resp = session.get("serviceengine?se_group_ref.name=%s" % segrp_name).content
        se_ip_resp = json.loads(se_ip_resp)["results"]
        se_ips = [se_data['mgmt_vnic']['vnic_networks'][0]['ip']['ip_addr']['addr'] for se_data in se_ip_resp]
    else:
        se_ip_resp = session.get("serviceengine?search=(is_mgmt,true)&fields=mgmt_vnic.vnic_networks.ip.ip_addr.addr,mgmt_vnics.is_mgmt").content
        se_ip_resp = json.loads(se_ip_resp)["results"]
        se_ips = [se["mgmt_vnic"]["vnic_networks"][0]["ip"]["ip_addr"]["addr"] for se in se_ip_resp if se.has_key('mgmt_vnic')]
    return se_ips

def _get_hsm_management_ips(session):
    client_ips = []
    controller_ips = _get_controller_ips(session)
    se_ips = _get_se_ips(session)
    for ip in controller_ips:
        client_ips.append({"client_ip": ip})
    for ip in se_ips:
        client_ips.append({"client_ip": ip})
    return client_ips


def _get_hsm_dedicated_ips(session, dedicated_ctrl_ips):
    client_ips = []
    if dedicated_ctrl_ips:
        controller_ips= get_controllers_dedicated_ips(session)
    else:
        controller_ips= _get_controller_ips(session)
    securechannel_resp = session.get(
        "serviceengine?search=(is_hsm%2Ctrue)&fields=data_vnics.vnic_networks.ip.ip_addr.addr%2Cdata_vnics.is_hsm")
    securechannel_resp = json.loads(securechannel_resp.content)["results"]
    for se_data in securechannel_resp:
        for data_vnic in se_data["data_vnics"]:
            if data_vnic["is_hsm"]:
                for vnic_network in data_vnic["vnic_networks"]:
                    client_ip = vnic_network["ip"]["ip_addr"]["addr"]
                    client_ips.append({"client_ip": client_ip})

    for ip in controller_ips:
        client_ips.append({"client_ip": ip})

    return client_ips


def set_hsm_ha(session, hsmgrp_name, is_ha=True):
    """
    updates HA mode for HSM
    """
    hsm_grp_resp = session.get_object_by_name("hardwaresecuritymodulegroup", hsmgrp_name)
    hsm_grp_resp['hsm']['sluna']['is_ha'] = is_ha
    hsm_update_resp = session.put_by_name("hardwaresecuritymodulegroup", hsmgrp_name, data=hsm_grp_resp)
    if hsm_update_resp.status_code >= 300:
        raise Exception("Failed to set HSM HA. Error: %s" % hsm_update_resp.content)


def _get_hsm_grp_uuid(session, hsm_grp_name):
    """
    returns the hsm group uuid for name
    """
    hsm_resp = session.get_object_by_name("hardwaresecuritymodulegroup", hsm_grp_name)
    hsm_grp_uuid = session.get_obj_uuid(hsm_resp)
    return hsm_grp_uuid


def _scp_client_cert_to_hsm(session, hsm_grp_name, client_ip, hsm_ip, hsm_username, hsm_password):
    """
    scp the client certs from controller to HSM
    """
    dest_path = "/tmp/%s.pem" % client_ip
    hsm_resp = session.get_object_by_name("hardwaresecuritymodulegroup", hsm_grp_name)
    for client_info in hsm_resp["hsm"]["sluna"]["node_info"]:
        if client_info["client_ip"] == client_ip:
            client_cert = client_info["client_cert"]
            break
    _write_file(dest_path, client_cert)
    _scp_file(hsm_ip, hsm_username, hsm_password, dest_path, "%s.pem" % client_ip, remote_to_local=False)


def hsm_cleanup(session, hsmgrp_name, segrp_name="Default-Group", local_cleanup=False, skip_client=[]):
    """
    hsm cleanup
    :param session: api session
    :param hsmgrp_name: HSM group name to delete
    :param tenant:
    :return:
    """
    delete_ssl_certs(session, hsmgrp_name)
    remove_hsm_group_from_se_group(session, segrp_name)
    hsm_resp = session.get_object_by_name("hardwaresecuritymodulegroup", hsmgrp_name)
    hsm_server_ips = _get_hsm_server_ips(session, hsmgrp_name)
    hsm_delete_resp = session.delete_by_name("hardwaresecuritymodulegroup", hsmgrp_name)
    if hsm_delete_resp.status_code >=300:
        LOG.debug("Failed to delete HSM group %s. Error: %s" % (hsmgrp_name, hsm_delete_resp.content))
        raise Exception("Failed to delete HSM group %s. Error: %s" % (hsmgrp_name, hsm_delete_resp.content))

    clean_hsm_servers = []
    if not local_cleanup:
        for hsm_server in hsm_resp['hsm']['sluna']['server']:
            hsm_server_ip = hsm_server["remote_ip"]
            partition_name = [ part_name for (part_name, part_details) in  hsm_partition_details[hsm_server_ip].iteritems() if part_details['serial_num'] == hsm_server['partition_serial_number']][0]
            ssh_session = _create_ssh_session(hsm_server_ip, hsm_server_details[hsm_server_ip]["hsm_username"],
                                             hsm_server_details[hsm_server_ip]['hsm_password'])
            for node in hsm_resp['hsm']['sluna']['node_info']:
                if node['client_ip'] not in skip_client:
                    _hsm_client_revoke_partition(ssh_session, node['client_ip'], partition_name)
                    if hsm_server_ip not in clean_hsm_servers:
                        _hsm_client_delete(ssh_session, node['client_ip'])
            clean_hsm_servers.append(hsm_server_ip)

def create_hsm_ssl_cert(session, hsmgrp_name, common_name, ssl_cert_name, algorithm="SSL_KEY_ALGORITHM_RSA", key_size="SSL_KEY_2048_BITS", curve="SSL_KEY_EC_CURVE_SECP256R1"):
    hsmgrp_uuid = _get_hsm_grp_uuid(session, hsmgrp_name)
    sslkeyandcertificate_obj = {
                                    "key_params": {
                                        "ec_params": {"curve": curve},
                                        "rsa_params": {"key_size": key_size, "exponent": 65537},
                                    "algorithm": algorithm
                                    },
                                  "certificate": {
                                    "self_signed": True,
                                    "subject": {"common_name": common_name}
                                  },
                                  "name": ssl_cert_name,
                                  "hardwaresecuritymodulegroup_uuid": hsmgrp_uuid
                                }
    data = json.dumps(sslkeyandcertificate_obj)
    ssl_resp = session.post("sslkeyandcertificate?include_name", data=data)
    if ssl_resp.status_code >= 300:
        raise Exception("Failed to create ssl cert. error: %s" % ssl_resp.content)

def _get_hsm_client_ips(session, hsmgrp_name):
    hsm_resp = session.get_object_by_name("hardwaresecuritymodulegroup", hsmgrp_name)
    client_ips = [node["client_ip"] for node in hsm_resp['hsm']['sluna']['node_info']]
    return client_ips

def _get_hsm_server_ips(session, hsmgrp_name):
    hsm_resp = session.get_object_by_name("hardwaresecuritymodulegroup", hsmgrp_name)
    server_ips = [hsm_server['remote_ip'] for hsm_server in hsm_resp['hsm']['sluna']['server']]
    return server_ips

def _associate_hsm_group_to_se_group(session, segrp_name, hsmgrp_name):
    hsmgrp_uuid = _get_hsm_grp_uuid(session, hsmgrp_name)
    segrp_resp = session.get_object_by_name("serviceenginegroup", segrp_name)
    segrp_resp["hardwaresecuritymodulegroup_uuid"] = hsmgrp_uuid
    segrp_data = json.dumps(segrp_resp)
    segrp_update_resp = session.put_by_name("serviceenginegroup", segrp_name, data=segrp_data)
    if segrp_update_resp.status_code >= 300:
        raise Exception("Failed to set HSM group to se group. Error: %s" % segrp_update_resp.content)


def remove_hsm_group_from_se_group(session, segrp_name):
    segrp_resp = session.get_object_by_name("serviceenginegroup", segrp_name)
    if segrp_resp.has_key("hardwaresecuritymodulegroup_ref"):
        del segrp_resp["hardwaresecuritymodulegroup_ref"]
        segrp_update_resp = session.put_by_name("serviceenginegroup", segrp_name, data=segrp_resp)
        if segrp_update_resp.status_code >= 300:
            raise Exception("Failed to remove HSM group from se group. Error: %s" % segrp_update_resp.content)
        _wait_for_se_oper_status(session, segrp_name, oper_status="OPER_DOWN")
        _wait_for_se_oper_status(session, segrp_name, oper_status="OPER_UP") 


def get_se_grp_uuid(session, se_grp_name):
    se_grp_resp = session.get_object_by_name("serviceenginegroup", se_grp_name)
    se_grp_uuid = session.get_obj_uuid(se_grp_resp)
    return se_grp_uuid


def _wait_for_se_oper_status(session, se_grp_name=None, oper_status="OPER_UP", timeout=300, interval=5):
    """
    wait untill all se's from specified SE group in required SE oper state or if se_grp_name not provided then wait untill
    all se's in required SE oper state
    """
    verified_se = []
    while timeout > 0:
        if se_grp_name:
            se_resp = session.get("serviceengine?se_group_ref.name=%s" % se_grp_name).content
        else:
            se_resp = session.get("serviceengine").content
        se_resp = json.loads(se_resp)
        for se in se_resp["results"]:
            if se["name"] not in verified_se:
                if se["oper_status"]["state"] == oper_status:
                    verified_se.append(se["name"])
                else:
                    break
        else:
            return
        time.sleep(interval)
        timeout -= interval
    else:
        raise Exception("All service engines are not in %s state after timeout" % oper_status)

def _get_sslcert_uuids_for_hsm_group(session, hsmgrp_name):
    hsmgrp_uuid = _get_hsm_grp_uuid(session, hsmgrp_name)
    sslkeycert_resp = session.get("sslkeyandcertificate")
    sslkeycert_data = json.loads(sslkeycert_resp.content)
    sslkeycert_list = []
    for sslkeycert in sslkeycert_data["results"]:
        if sslkeycert.has_key("hardwaresecuritymodulegroup_ref"):
            sslkeycert_hsm_uuid = sslkeycert["hardwaresecuritymodulegroup_ref"].split("/")[-1]
            if sslkeycert_hsm_uuid == hsmgrp_uuid:
                sslkeycert_list.append(sslkeycert["uuid"])
    return sslkeycert_list


def _delete_vs_sslkeycert(session, sslkeycert_uuid_list):
    vs_resp = session.get("virtualservice")
    vs_data = json.loads(vs_resp.content)
    for vs in vs_data["results"]:
        if vs.has_key("ssl_key_and_certificate_refs"):
            for ssl_keycert_ref in vs["ssl_key_and_certificate_refs"]:
                sslkeycert_uuid = ssl_keycert_ref.split("/")[-1]
                if sslkeycert_uuid in sslkeycert_uuid_list:
                    vs["ssl_key_and_certificate_refs"].remove(ssl_keycert_ref)
            resp = session.put_by_name("virtualservice", vs["name"], data=vs)
            if resp.status_code > 300:
                raise Exception("Failed to remove the ssl certs from VS %s" % vs["name"])


def delete_ssl_certs(session, hsmgrp_name):
    sslkeycert_uuid_list = _get_sslcert_uuids_for_hsm_group(session, hsmgrp_name)
    _delete_vs_sslkeycert(session, sslkeycert_uuid_list)
    for sslkeycert_uuid in sslkeycert_uuid_list:
        sslkeycert_delete_resp = session.delete("sslkeyandcertificate/%s" % sslkeycert_uuid, timeout=180)
        if sslkeycert_delete_resp.status_code > 300:
            raise Exception("Failed to delete sslkeyandcertificate object. Error: %s" % sslkeycert_delete_resp.content)
        time.sleep(30)

def associate_hsm_group_to_se_group(session, segrp_name, hamgrp_name):
    _associate_hsm_group_to_se_group(session, segrp_name, hamgrp_name)
    _wait_for_se_oper_status(session, segrp_name, oper_status="OPER_DOWN")
    _wait_for_se_oper_status(session, segrp_name, oper_status="OPER_UP")


def _verify_hsm_configuration_on_vm(session, vm_ip, hsmgrp_name, is_se=False, ha=False,
                                    user='root', password='avi123', tenant='admin'):
    vm = Linux(vm_ip, user, password)
    if is_se:
        verify_cmd = '/usr/safenet/lunaclient/bin/vtl verify'
    else:
        verify_cmd = 'sudo /opt/avi/scripts/safenet.py -p %s -i %s -c "/usr/safenet/lunaclient/bin/vtl verify" -t %s'\
                     % (hsmgrp_name, vm_ip, tenant)
    verify_resp = vm.execute_command(verify_cmd)
    for line in verify_resp:
        if "Error: Unable to find any Luna SA slots/partitions among registered server" in line:
            LOG.error("Error: Unable to find any Luna SA slots/partitions among registered server")
            raise Exception("Error: Unable to find any Luna SA slots/partitions among registered server")
    LOG.debug("HSM group verified successfully")

    if is_se:
        listslots_cmd = '/usr/safenet/lunaclient/bin/vtl listslots'
    else:
        listslots_cmd = 'sudo /opt/avi/scripts/safenet.py -p %s -i %s -c ' \
                            '"/usr/safenet/lunaclient/bin/vtl listslots" -t %s' % (hsmgrp_name, vm_ip, tenant)
    listslots_resp = vm.execute_command(listslots_cmd)

    if not ha:
        hsm_server_ips = _get_hsm_server_ips(session, hsmgrp_name)
        for hsm_server in range(0, len(hsm_server_ips)):
            for line in listslots_resp:
                if "LunaNet Slot" in line:
                    listslots_resp.remove(line)
                    break
            else:
                raise Exception("HSM group listslots verification failed. Expected %d servers, got %d" % (len(hsm_server_ips), hsm_server))
    else:
        for line in listslots_resp:
            if "HA Virtual Card Slot" in line:
                break
        else:
            raise Exception("HSM group listslots verification failed.")


    if is_se:
        #haadmin_show_cmd = '/usr/safenet/lunaclient/bin/vtl haadmin show'
        haadmin_show_cmd = '/usr/safenet/lunaclient/bin/lunacm -q hagroup listgroups'
    else:
        haadmin_show_cmd = 'sudo /opt/avi/scripts/safenet.py -p %s -i %s -c ' \
                                '"/usr/safenet/lunaclient/bin/lunacm -q hagroup listgroups" -t %s' % (hsmgrp_name, vm_ip, tenant)
    haadmin_show_resp =  vm.execute_command(haadmin_show_cmd)
    print haadmin_show_resp

    for line in haadmin_show_resp:
        #if line.find("HA Group and Member Information") >= 0:
        if line.find("Group Members") >= 0:
            if not ha:
                raise Exception("HA Group and Member Information found on controller before configuring HA")
            else:
                break
    else:
        if ha:
            raise Exception("HSM group haadmin show verification failed")
    LOG.debug("HSM group listslots verified successfully on vm %s" % vm_ip)


def _verify_hsm_files_on_se(se_ip, user='admin', password='avi123'):
    se = Linux(se_ip, user, password)
    verify_keycert_cmd = "ls /etc/luna/cert/client/"
    keycert_files = [file.strip() for file in se.execute_command(verify_keycert_cmd)]
    if [ x for x in keycert_files if not re.search(r'\d+\.?(Key)?\.pem', x)]:
        # Expect pem files only
        raise Exception("Expected key certs /etc/luna/cert/client/ not found on se")
    verify_chrystoki_cmd = "ls /etc/Chrystoki.conf"
    verify_chrystoki_resp = se.execute_command(verify_chrystoki_cmd)
    if not "/etc/Chrystoki.conf" == verify_chrystoki_resp[0].strip():
        raise Exception("Expected /etc/Chrystoki.conf not found on controller")
    verify_safenet_cmd = "ls /usr/safenet/lunaclient/"
    verify_safenet_resp = se.execute_command(verify_safenet_cmd)
    if verify_safenet_resp[0].find("No such file or directory") >= 0:
        raise Exception("Directory /usr/safenet/lunaclient/ not found on controller")
    LOG.debug("HSM files verified successfully on se %s" % se_ip)

def verify_hsm_configuration(session, hsmgrp_name, segrp_name=None):
    client_ips = _get_hsm_client_ips(session, hsmgrp_name)
    controller_ips = _get_controller_ips(session)

    ha = _get_ha_status(session, hsmgrp_name)
    controller_ips = list(set(controller_ips).intersection(client_ips))

    for controller_ip in controller_ips:
        _verify_hsm_configuration_on_vm(session, controller_ip, hsmgrp_name, ha=ha,
                                        user=session.username,
                                        password=session.password, tenant=session.tenant)

    if segrp_name:
        se_ips = _get_se_ips(session, segrp_name)
        for se_ip in se_ips:
            _verify_hsm_files_on_se(se_ip, user=session.username,
                                   password=session.password)
            _verify_hsm_configuration_on_vm(session, se_ip, hsmgrp_name, is_se=True, ha=ha,
                                            user=session.username,
                                            password=session.password, tenant=session.tenant)

def hsmpkg_configuration(session, hsmpkg_path):
    _hsmpkg_upload(session, file_path=hsmpkg_path)
    _reboot_all_se(session)
    _verify_hsmpkg_uploaded(session)

def _file_upload(session, file_path, file_uri, uri, **kwargs):
    """ base function to post multipart files """
    filename = os.path.basename(file_path)
    fd = open(file_path, 'rb')
    file_dict = {
        "file" : (filename, fd, 'application/octet-stream'),
        "uri"  : file_uri
    }
    data = MultipartEncoder(file_dict)
    headers = {}
    headers['Content-Type'] = data.content_type
    upload_resp = session.post(uri, headers=headers, data=data)
    if upload_resp.status_code > 300:
        LOG.error("Failed to upload file %s on api %s" % file_path, uri)
        raise Exception("Failed to upload file %s on api %s" % (file_path, file_uri))
    LOG.debug("File %s Uploaded successfully on api %s" % (file_path, uri))


def _hsmpkg_upload(session, file_path):
    """ hsm pkg upload interface """
    _file_upload(session, file_path, "controller://hsmpackages",
                 "fileservice/hsmpackages?hsmtype=safenet")
    return

def _reboot_all_se(session):
    se_ips = _get_se_ips(session)
    for se_ip in se_ips:
        se = Linux(se_ip, session.username, session.password)
        se.execute_command("sudo reboot")
        se.wait_node_up(se_ip)
        se.close()
    _wait_for_se_oper_status(session, oper_status="OPER_DOWN", interval=2)
    _wait_for_se_oper_status(session, oper_status="OPER_UP", interval=2)

def _verify_hsmpkg_uploaded(session):
    controller_ips = _get_controller_ips(session)
    se_ips = _get_se_ips(session)

    for controller_ip in controller_ips:
        _verify_hsmpkg_uploaded_on_vm(controller_ip, user=session.username,
                                      password=session.password)

    for se_ip in se_ips:
        _verify_hsmpkg_uploaded_on_vm(se_ip, user=session.username,
                                      password=session.password)

def _verify_hsmpkg_uploaded_on_vm(vm_ip, timeout=60, interval=5, user='admin',
                                  password='avi123'):
    vm = Linux(vm_ip, user, password)

    while timeout > 0:
        hsmpkg_verify_resp = vm.execute_command("ls /var/lib/avi/hsmpackages/")
        if hsmpkg_verify_resp:
            for line in hsmpkg_verify_resp:
                if "safenet.tar" == line.strip():
                    LOG.debug("/var/lib/avi/hsmpackages/safenet.tar verified successfully on VM %s" % vm_ip)
                    return
        time.sleep(interval)
        timeout -= interval
    else:
        LOG.error("/var/lib/avi/hsmpackages/safenet.tar not found on VM %s" % vm_ip)
        raise Exception("/var/lib/avi/hsmpackages/safenet.tar not found on VM %s" % vm_ip)
    vm.close()

def _get_registered_client_ips(hsm_server_ip):
    register_client_ips = []
    hsm_server = Linux(hsm_server_ip, hsm_server_details[hsm_server_ip]['hsm_username'], hsm_server_details[hsm_server_ip]['hsm_password'])
    client_list_resp = hsm_server.execute_command("client list")
    for line in client_list_resp:
        try:
            register_client_ips.append(re.findall( r'[0-9]+(?:\.[0-9]+){3}', line)[0])
        except:
            pass
    return register_client_ips


def _get_ha_status(session, hsmgrp_name):
    hsm_grp_resp = session.get_object_by_name("hardwaresecuritymodulegroup", hsmgrp_name)
    return hsm_grp_resp['hsm']['sluna']['is_ha']

def cleanup_hsm_package(session, username="admin", password="avi123"):
    controller_ips = _get_controller_ips(session)
    controller = Linux(controller_ips[0], username, password)
    hsm_uninstall_cmd = "sudo /opt/avi/scripts/hsmpackage_install.sh --all --uninstall"
    controller.execute_command(hsm_uninstall_cmd)

def _verify_client_certs_for_hsmgroup(session, hsmgrp_name, expected_client_ips):
    hsm_resp = session.get_object_by_name("hardwaresecuritymodulegroup", hsmgrp_name)
    client_ips = _get_hsm_client_ips(session, hsmgrp_name)
    if client_ips != expected_client_ips:
        LOG.debug("Expected client ips %s not found in hsmgroup" % (set(expected_client_ips) - set(client_ips)))
        raise Exception("Expected client ips %s not found in hsmgroup" % (set(expected_client_ips) - set(client_ips)))

    for client_info in hsm_resp["hsm"]["sluna"]["node_info"]:
        if not client_info.has_key("client_cert"):
            raise Exception("No client cert found for client ip %s" % client_info["client_ip"])

def _get_controller_all_ips(controller_ip, user, password):
    controller = Linux(controller_ip, user, password)
    cmd = "ip addr | grep 'state UP' -A2"
    out = controller.execute_command(cmd)
    controller_ips = []
    for index  in range(2, len(out), 4):
        ip = out[index].split()[1].split('/')[0]
        controller_ips.append(ip)
    return controller_ips

def get_controllers_dedicated_ips(session):
    cntr_mgmt_ips = _get_controller_ips(session)
    cntr_dedicated_ips = []
    for cntr_mgmt_ip in cntr_mgmt_ips:
        dedicated_ips = _get_controller_all_ips(cntr_mgmt_ip, session.username, session.password)
        dedicated_ips.remove(cntr_mgmt_ip)
        if dedicated_ips:
            cntr_dedicated_ips.append(dedicated_ips[0])
        else:
            raise Exception("No dedicated IP configured for controller %s " % cntr_mgmt_ip)
    return cntr_dedicated_ips

def create_hsm_with_dummy_servers(session, hsmgrp_name, hsm_server_partitions=[], dedicated_flag=False, client_ips=[], dedicated_ctrl_ip=False):
    """
    created the HSM safenet group
    :param hsmgrp_name: HSM group name
    :param hsm_server_partitions: hsm server ip, partition name and HSM server dummy cert list eg. [("1.1.1.1", "par1", "dummy_hsm_server_cert"), ("2.2.2.2", "par2", "dummy_hsm_server_cert")]
    :param session: api session of controller
    :param tenant: tenant name
    """
    hsm_group_obj = {}
    hsm_group_obj['name'] = hsmgrp_name
    hsm_group_obj['hsm'] = {'type': 'HSM_TYPE_SAFENET_LUNA', 'sluna': {}}
    hsm_group_obj['hsm']['sluna']['server'] = []
    hsm_group_obj['hsm']['sluna']['node_info'] = []

    for index, hsm_server_partition in enumerate(hsm_server_partitions):
        (hsm_server_ip, partition_name, dummy_cert) = hsm_server_partition
        hsm_server_detail = {"remote_ip": hsm_server_ip, "partition_passwd": "abc123",
               "partition_serial_number": "1234", "server_cert": dummy_cert}
        hsm_group_obj['hsm']['sluna']['server'].append(hsm_server_detail)
    if client_ips:
        for client_ip in client_ips:
            hsm_group_obj['hsm']['sluna']['node_info'].append({"client_ip": client_ip})
    else:
        if dedicated_flag:
            client_ips = _get_hsm_dedicated_ips(session, dedicated_ctrl_ip)
            hsm_group_obj['hsm']['sluna']['node_info'] = client_ips
            hsm_group_obj['hsm']['sluna']['use_dedicated_network'] = True
        else:
            client_ips = _get_hsm_management_ips(session)
            hsm_group_obj['hsm']['sluna']['node_info'] = client_ips
        client_ips = [client["client_ip"] for client in client_ips]

    data = json.dumps(hsm_group_obj)
    out = session.post("hardwaresecuritymodulegroup", data=data)
    if out.status_code >= 300:
        LOG.error("Failed to create HSM group. Error: %s" % out.content)
        raise Exception("Failed to create HSM group. Error: %s" % out.content)
    LOG.debug("HSM group created. Content: %s" % out.content)
    _verify_client_certs_for_hsmgroup(session, hsmgrp_name, client_ips)

def update_hsmgrp_servers(session, hsmgrp_name, hsm_server_partitions=[]):
    hsm_grp_resp = session.get_object_by_name("hardwaresecuritymodulegroup", hsmgrp_name)
    for index, hsm_server_partition in enumerate(hsm_server_partitions):
        (hsm_server_ip, partition_name) = hsm_server_partition
        hsm_server = hsm_server_details[hsm_server_ip]
        server_cert = _get_hsm_server_cert(hsm_server_ip, hsm_server['hsm_username'],
                                          hsm_server['hsm_password'])
        hsm_server_detail = {"remote_ip": hsm_server_ip, "partition_passwd": hsm_partition_details[hsm_server_ip][partition_name]['partition_password'], "partition_serial_number":hsm_partition_details[hsm_server_ip][partition_name]['serial_num'], "server_cert": server_cert}
        hsm_grp_resp['hsm']['sluna']['server'][index] = hsm_server_detail
    hsm_update_resp = session.put_by_name("hardwaresecuritymodulegroup", hsmgrp_name, data=hsm_grp_resp)
    if hsm_update_resp.status_code >= 300:
        raise Exception("Failed to set HSM HA. Error: %s" % hsm_update_resp.content)
