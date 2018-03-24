"""
Usage: webapp_lib.py

This script contails all APIs related to webapp
"""

import json
from avi_objects.rest import ApiNode, get_session
import avi_objects.rest as rest
from avi_objects.logger_utils import error, fail
from avi_objects.logger import logger
import re
import os
from avi_objects.infra_imports import post
import tempfile
from requests_toolbelt import MultipartEncoder


def change_role_privileges_and_expect_failure(role_name, resource_name, access, **kwargs):
    """ API to Change the User Role Privileges and Expect to Failure.

    Args:
        :param role_name: User access role name
        :type role_name: str
        :param resource_name: Privilege/Resource name
        :type resource_name: str
        :param access: User Access Mode
        :type access: str
    Returns:
        Success - Return Failure message
        Failure - Raise Error with relative message
    """
    status_code, resp = change_role_privileges(role_name, resource_name, access, check_status_code=False, **kwargs)
    if status_code == 400 and 'Cannot modify Role' in str(resp):
        logger.info("Expected Failure with status code 400 and Cannot modify Role in error message")
    else:
        error('Status code Expected=400 Received=%s and error msg Exepcted=Cannot modify Role \
               Received=%s' %(status_code, str(resp)))


def change_role_privileges(role_name, resource_name, access, **kwargs):
    """ API to Change/Update the User Role Privileges.

    Args:
        :param role_name: User access role name
        :type role_name: str
        :param resource_name: Privilege/Resource name
        :type resource_name: str
        :param access: User Access Mode
        :type access: str
    """
    check_status_code = kwargs.pop('check_status_code', True)
    role_node = ApiNode('role', name=role_name)
    status_code, role = role_node.get()
    logger.info("status_code %s , resp %s" % (status_code, role))

    change = False
    for privilege in role['privileges']:
        if privilege['resource'] == resource_name.upper():
            privilege['type'] = access.upper()
            change = True

    if not change:
        data = {'resource': resource_name.upper(), 'type': access.upper()}
        role['privileges'].append(data)

    status_code, resp = role_node.put(data=json.dumps(role), check_status_code=check_status_code)
    logger.info("Change Role Privileges, status_code: %s " % status_code)
    return (status_code, resp)


def get_uuid_from_ref(url_ref=None):
    if not url_ref:
        error("URL ref is None")
    out = str(url_ref).split('/')[-1]
    if '#' in out:
        out = out.split('#')
        out = out[0]
    return out


def get_name_from_ref(ref):
    if not ref:
        return ''
    found = re.match("http.*api(.*)", ref)
    if not found:
        fail("ERROR! Cannot get api from ref")
    obj_type = found.group(1)
    logger.trace('get_name_from_ref: ref %s found %s obj_type %s' % (
        ref, str(found), obj_type))
    status_code, json_data = rest.get(obj_type)
    return json_data.get('name')


def get_slug_from_uri(uri):
    return os.path.basename(uri)


def get_name_by_uuid(obj_type, obj_uuid, **kwargs):
    """
    Given object type and UUID, return name of the object
    :param obj_type:
    :param obj_uuid:
    :param kwargs:
    :return:
    """

    resp_code, data = rest.get(obj_type, uuid=obj_uuid)
    name = data.get('name', None)
    logger.trace('URI: %s/%s Name: %s' % (obj_type, obj_uuid, name))
    return name


def check_return_code(request_type, rsp, should_pass, ignore_bad_code=False):
    if ignore_bad_code and rsp.status_code >=300:
        print ('Return bad response: %s - %s , Ignore set to %r' %(rsp.status_code, rsp.content, ignore_bad_code))
        return
    logger.debug("%d:: %s :: %r" % (rsp.status_code, rsp.content, should_pass))
    if rsp.status_code >= 300 and should_pass and not ignore_bad_code:
        fail('%s return bad response: code %s, content %s' %
                         (request_type, rsp.status_code, rsp.content))

    elif rsp.status_code < 300 and not should_pass and not ignore_bad_code:
        fail('%s should have failed: code %s, content %s' %
                         (request_type, rsp.status_code, rsp.content))


def do_get_request(path, should_pass=True, return_response=True, ignore_bad_code=False):
    status_code, rsp = rest.get(str(path))
    check_return_code('GET', rsp, should_pass, ignore_bad_code)
    logger.info('status code: %s, resp: %s' % (rsp.status_code, rsp.content))
    if return_response and rsp.status_code < 300:
        rsp = json.loads(rsp.content)
        return rsp
    elif return_response and rsp.status_code > 300 and not should_pass:
        rsp = json.loads(rsp.content)
        return rsp
    else:
        return


def validate_after_delete(obj_type, obj_name, **kwargs):
    """

    :param obj_type:
    :param obj_name:
    :param kwargs:
    :return:
    """
    try:
        status_code, resp = rest.get(obj_type, name=obj_name)
    except:
        return
    logger.trace('Status: %s, Resp: %s' % (status_code, resp))
    fail('%s deletion failed for object - %s' % (obj_type, obj_name))


def export_configuration(export_type=None, passphrase=None, **kwargs):
    """
    Export configuration on controller
    @param tenant: name of tenant
    @param export_type: export type
    @param kwargs: key pair params
    @return: None
    """

    json_data = {}
    if passphrase:
        json_data = {'passphrase': passphrase}
    path = "/configuration/export"

    if export_type in ['full', 'passphrase-full']:
        path += '?full_system=true'

    for index, value in kwargs.iteritems():
        path += ("&%s=%s" if "?" in path else "?%s=%s") % (index, value)

    logger.info(path)
    status_code, resp = post(path, data = json_data, timeout=300)
    logger.info("Export configuration status code: %s" % status_code)
    return resp

def export_configuration_file(export_type=None, passphrase=None, **kwargs):
    data = export_configuration(export_type, passphrase, **kwargs)
    new_file = tempfile.NamedTemporaryFile(delete=False)
    json.dump(data, new_file)
    new_file.close()
    return new_file.name

def import_configuration(data, vm, tenant='admin', force_mode=False, should_pass=True, passphrase=None):
    """
    @param data: configuration data
    @param vm: controller vm
    @param tenant: name of tenant
    @param force_mode: mode of import configuration
    @param should_pass: flag for should pass
    @param passphrase: value of passphrase
    @param keep_uuid: keep uuid
    @return: None
    """
    # Clear config UUId cache
    #config.name_to_uuid_map = {}
    f = tempfile.NamedTemporaryFile(delete=False)
    file_name = os.path.basename(f.name)
    json.dump(data, f)
    f.close()
    upload_file(f.name, 'controller://uploads')
    os.unlink(f.name)
    json_data = {'uri': 'controller://uploads/' + file_name}
    if passphrase:
        json_data['passphrase'] = passphrase
    path = '/configuration/import'
    params = {}
    if force_mode:
        params['force_mode'] = True
    status_code, resp = post(path, json_data, timeout=300, params=json.dumps(params))

def _upload_multipart_file_form(file_path, file_uri):
    if not os.path.exists(file_path):
        error('File not found: ' + file_path)

    #port = get_controller_port()i
    session = get_session()
    #port = session.port
    port = 443
    path = 'https://%s:%s/api/fileservice/uploads' % (session.controller_ip, port)
    file_name = os.path.basename(file_path)

    with open(file_path, "rb") as f:
        f_data = {"file": (file_name, f, "application/octet-stream"),
                  "uri": file_uri}
        m = MultipartEncoder(f_data)
        r = session.post(path, data=m)

        if r.status_code > 300:
            error('Fail to upload: ' + r.content)

def upload_file(file_path, directory, should_pass=True, expected_error=None):
    try:
        _upload_multipart_file_form(file_path, directory)
    except Exception as e:
        if not should_pass:
            if expected_error and expected_error not in str(e):
                raise e
        else:
            error("File upload should have passed but got: " + str(e))

