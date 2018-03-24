import json
import re
from urlparse import urlparse
from avi.sdk import avi_api
from logger import logger

import avi_objects.logger_utils as logger_utils
import requests.packages.urllib3

requests.packages.urllib3.disable_warnings()


class ApiNode(object):
    def __init__(self, endpoint, uuid=None, name=None):
        ''' Class providing object access to the underlying session.
        :param endpoint: The object being referenced; e.g. virtualservice, serviceengine, cluster
        :param uuid: Optional uuid of object. Note some objects may not have uuids either because the
                endpoint is not a singular object, or because the object has not been created yet
        :param name: Name of object if applicable. The name will be used to look up to obtain the uuid.
        '''
        if '/' in endpoint:
            logger.warning('ApiNode endpoint %s contains a forward slash. This is not supported usage' % endpoint)
        self.endpoint = endpoint
        self.uuid = uuid
        self.name = name

    def _api(self, api_name, path='', check_status_code=True, **kwargs):
        ''' Invoke the session function corresponding to the api_name requested (get/put/delete/etc)
        :param api_name: api function to execute on the sesssion object
        :param path: optional extra path on the endpoint, e.g. 'runtime' on /virtualservice/vs_uuid/
        :param check_status_code: if True, fail if the response status code >= 300.
                Set to False if the caller should get and handle the status code directly or
                does not care about any errors (e.g. deleting objects already deleted)
        '''
        # legacy warning
        if 'ignore_error' in kwargs:
            logger.warning('\'ignore_error\' has been removed. Please use \'check_status_code\' instead.\n'
                           'check_status_code=False == ignore_error=True')

        if self.name and not self.uuid:
            try:
                self.uuid = get_uuid_by_name(self.endpoint, self.name)
            except avi_api.ObjectNotFound as e:
                logger.debug("Did not find uuid for object %s with name %s" % (self.endpoint, self.name))
                pass

        if not self.uuid:
            if self.name and (api_name in ['put', 'get', 'delete']):
                if check_status_code:
                    logger_utils.fail('Object %s with name %s not found for \'%s\' operation'
                                      % (self.endpoint, self.name, api_name))
                else:
                    return [404, {'error': 'Object %s with name %s not found for \'%s\' operation'
                                           % (self.endpoint, self.name, api_name)}]
            else:
                # endpoint with no name, or post of named object
                if path:
                    full_path = '%s/%s' % (self.endpoint, path)
                else:
                    full_path = self.endpoint
        elif api_name == 'delete' or not path:
            full_path = '%s/%s' % (self.endpoint, self.uuid)
        else:
            full_path = '%s/%s/%s' % (self.endpoint, self.uuid, path)

        if kwargs.get('force', None):
            full_path += '?skip_optional_checks'
            kwargs.pop('force')

        session = get_session()
        if not session:
            logger.debug('No session found, Controller is not present .. !')
            return [None, None]
        api_version = get_api_version()
        cloud_context = get_cloud_context()
        if cloud_context:
            cloud_header = {"X-Avi-Cloud": "%s" % cloud_context}
            headers = kwargs.get('headers', {})
            headers.update(cloud_header)
            kwargs['headers'] = headers
        session_func = getattr(session, api_name)
        logger.debug('ApiNode calling api \'%s\' with path %s' % (api_name, full_path))
        if api_name in ['post', 'put', 'patch']:
            data = kwargs.get('data', None)
            logger.trace("Sending %s with data %s" % (api_name, data))
        resp = session_func(full_path, api_version=api_version, **kwargs)
        resp.encoding = 'UTF-8'
        logger.trace("Received: %s %s" % (resp.status_code, resp.text))
        if check_status_code and resp.status_code >= 300:
            logger_utils.fail("Received non 2xx response: %s %s" % (resp.status_code, resp.text))
        try:
            ret_json = resp.json()
        except Exception as e:
            ret_json = str(e)  # REVIEW should we propagate the exception? return status_code 5xx?

        return [resp.status_code, ret_json]

    def get(self, path='', **kwargs):
        return self._api('get', path=path, **kwargs)

    def delete(self, **kwargs):
        return self._api('delete', **kwargs)

    def post(self, path='', **kwargs):
        return self._api('post', path=path, **kwargs)

    def put(self, path='', **kwargs):
        return self._api('put', path=path, **kwargs)

    def put_no_status_check(self, path='', **kwargs):
        return self._api('put', path=path, check_status_code=False, **kwargs)

    def patch(self, path='', **kwargs):
        return self._api('patch', path=path, **kwargs)

    def update(self, check_status_code=True, **kwargs):
        _, data = self.get(check_status_code=check_status_code)
        data.update(kwargs)
        return self.put(data=json.dumps(data), check_status_code=check_status_code)


# REVIEW the following are provided as support for functional calls but people should use objects directly
# Should we deprecated these?
def get(endpoint, uuid=None, name=None, path='', **kwargs):
    api_obj = ApiNode(endpoint, uuid=uuid, name=name)
    return api_obj.get(path, **kwargs)


def delete(endpoint, uuid=None, name=None, **kwargs):
    api_obj = ApiNode(endpoint, uuid=uuid, name=name)
    return api_obj.delete(**kwargs)


def post(endpoint, uuid=None, name=None, path='', **kwargs):
    api_obj = ApiNode(endpoint, uuid=uuid, name=name)
    return api_obj.post(path, **kwargs)


def put(endpoint, uuid=None, name=None, path='', **kwargs):
    api_obj = ApiNode(endpoint, uuid=uuid, name=name)
    return api_obj.put(path, **kwargs)


def patch(endpoint, uuid=None, name=None, path='', **kwargs):
    api_obj = ApiNode(endpoint, uuid=uuid, name=name)
    return api_obj.patch(path, **kwargs)


def update(endpoint, uuid=None, name=None, **kwargs):
    api_obj = ApiNode(endpoint, uuid=uuid, name=name)
    return api_obj.update(**kwargs)


def get_session():
    # REVIEW: per discussion with Vivek et al, this should probably also refresh the session
    # to preemptively avoid session timeouts
    from avi_objects.infra_utils import get_config
    config = get_config()
    mode = config.get_mode()
    context_key = config.get_context_key()
    session = mode['session']
    if session:
        return session
    try:
        session = config.sessions[context_key]
    except KeyError:
        config.sessions[context_key] = create_session()
        session = config.sessions[context_key]
    return session


def get_api_version():
    from avi_objects.infra_utils import get_config
    config = get_config()
    mode = config.get_mode()
    return mode['version']


def get_cloud_context():
    from avi_objects.infra_utils import get_config
    config = get_config()
    mode = config.get_mode()
    return mode['cloud']


def create_session(controller=None, ip=None, lazy_authentication=True):
    from avi_objects.infra_utils import get_config
    config = get_config()
    mode = config.get_mode()
    logger.trace('Creating Session with mode %s' % mode)
    tenant = mode['tenant']
    user = mode['user']
    password = mode['password']
    if not controller:
        controller_list = config.get_vm_of_type('controller')
        controller = controller_list[0] if controller_list else None
    if not controller or controller.ip == '':
        logger.debug('No controllers found in testbed')
        return None
    controller_ip = controller.ip
    if ip:
        controller_ip = ip
    port = controller.api_port  # REVIEW do we use this?
    api_version = get_api_version()
    session = avi_api.ApiSession(controller_ip, username=user, tenant=tenant, \
                                 password=password, port=port, api_version=api_version, \
                                 lazy_authentication=lazy_authentication)
    # session.authenticate_session() #due to AV-33802, AV-33873
    return session


def get_uuid_by_name(endpoint, name):
    session = get_session()
    api_version = get_api_version()
    cloud_context = get_cloud_context()
    cloud_header = {}
    if cloud_context:
        cloud_header = {"X-Avi-Cloud": "%s" % cloud_context}
    resp = session.get_object_by_name(endpoint, name, api_version=api_version, headers=cloud_header)
    return session.get_obj_uuid(resp)


def import_config(path=None, configuration=None, **kwargs):
    if path:
        uri = "controller://" + path
        data = {"uri": uri}
    elif configuration:
        data = {"configuration": configuration}

    return post('configuration', path='import?ignore_uuid=true', data=data, **kwargs)

def switch_session(down_vm=None, controller=None):
    from avi_objects.infra_utils import get_config
    config = get_config()
    context_key = config.get_context_key()
    if not isinstance(down_vm, list):
        down_vm = [down_vm]
    if not controller:
        for _controller in config.get_vm_of_type("controller"):
            if _controller not in down_vm:
                controller = _controller
                break
    if not controller:
        fail("No controllers running to switch to.")
    config.sessions[context_key] = create_session(controller=controller)

def reset_admin_user(username, password, old_password='admin', **kwargs):
    data = json.dumps(
        {
            'username': username,
            'password': password,
            'old_password': old_password,
            'full_name': 'System Administrator',
        })
    from avi_objects.infra_utils import get_config
    config = get_config()
    config.switch_mode(password=old_password)
    status_code, data = put('useraccount', data=data, check_status_code=False)

def update_admin_user(username, password, old_password='admin', **kwargs):
    data = json.dumps(
        {
            'username': username,
            'password': password,
            'old_password': old_password,
            'full_name': 'System Administrator',
        })
    from avi_objects.infra_utils import get_config
    config = get_config()
    config.switch_mode(password=old_password)
    try:
        put('useraccount', data=data)
    except Exception as e:
        config.switch_mode(password=password)
        logger.debug('%s/%s failed:%s' % (username, old_password, e))
        logger.debug('Assuming credentials are already %s/%s' % (username, password))

    config.switch_mode(password=password)
    context_key = config.get_context_key()
    config.sessions[context_key] = create_session()


def get_uuid_from_ref(url_ref=None):
    """ Helps to get the UUID from given URL Reference """
    if not url_ref:
        logger_utils.fail("URL ref is None")
    out = str(url_ref).split('/')[-1]
    if '#' in out:
        out = out.split('#')
        out = out[0]
    return out


def get_name_from_ref(url_ref, **kwargs):
    """ Helps to get the Name from given URL Reference """
    if not url_ref:
        logger_utils.fail("URL ref is None")
    uuid = str(url_ref).split('/')[-1]
    obj_type = str(url_ref).split('/')[-2]
    status_code, resp = get(obj_type, uuid=uuid, **kwargs)
    return resp['name']


def get_cloud_type(get_configuration=False):
    from avi_objects.infra_utils import get_config
    config = get_config()
    mode = config.get_mode()
    cloud_name = mode.get('cloud')
    if not cloud_name:
        ret_val = (None, None) if get_configuration else None
        return ret_val
    _, data = get('cloud', name=cloud_name)
    vtype = data['vtype']
    logger.info('get_cloud_type vtype=%s' % vtype)
    cloud_type = None
    configuration = None
    if vtype == 'CLOUD_NONE':
        cloud_type = None
    elif vtype == 'CLOUD_VCENTER':
        configuration = data['vcenter_configuration']
        cloud_type = 'vcenter'
    elif vtype == 'CLOUD_OPENSTACK':
        configuration = data['openstack_configuration']
        cloud_type = 'openstack'
    elif vtype == 'CLOUD_AWS':
        configuration = data['aws_configuration']
        cloud_type = 'aws'
    elif vtype == 'CLOUD_MESOS':
        cloud_type = 'mesos'
    elif vtype == 'CLOUD_OSHIFT_K8S':
        cloud_type = 'openshift'
    elif vtype == 'CLOUD_AZURE':
        cloud_type = 'azure'
        cc_ref = data['azure_configuration']['cloud_credentials_ref']
        _, cc_info = get('cloudconnectoruser', uuid=get_uuid_from_ref(cc_ref))
        configuration = data['azure_configuration']
        configuration['cc_info'] = cc_info
    elif vtype == 'CLOUD_LINUXSERVER':
        configuration = data['linuxserver_configuration']
        cloud_details = data
        if 'ipam_provider_ref' in cloud_details:
            ipam_ref = cloud_details['ipam_provider_ref']
            url_parsed = urlparse(ipam_ref)
            ipam_uuid = url_parsed.path.split('/')[-1]
            _, ipam_details = get('ipamdnsproviderprofile', uuid=ipam_uuid)
            if ipam_details['type'] == 'IPAMDNS_TYPE_AZURE':
                configuration['cc_info'] = ipam_details['azure_profile']
                cloud_type = 'azure'
            elif ipam_details['type'] == 'IPAMDNS_TYPE_GCP':
                cloud_type = 'gcp'
        else:
            cloud_type = 'baremetal'
    if get_configuration:
        return cloud_type, configuration
    else:
        return cloud_type


def get_query_params(kv_dict):
    """

    :param kv_dict: dictionary containing the key value arguments.
    :return: query param strings formed based on the key, value tuples passed
    """

    query = ''
    if kv_dict:
        for k, v in kv_dict.items():
            query += '%s=%s&' % (k, v)
        # strip the last &
        query = query[:-1]
    return query


def get_obj_ref(obj_type, obj_name, **kwargs): # TODO: Remove tenant='admin'
    resp_code, data = get(obj_type, name=obj_name)
    ref = data['url']
    logger.info('obj %s name %s ref %s' % (obj_type, obj_name, ref))
    return ref

def get_name_by_uuid(obj_type, obj_uuid):
    resp_code, resp_data = get(obj_type, uuid=obj_uuid)
    return resp_data['name']

