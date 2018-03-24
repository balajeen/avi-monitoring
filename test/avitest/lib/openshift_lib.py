import json
import datetime

from copy import deepcopy
from avi_objects.logger import logger

import lib.vs_lib as vs_lib
import lib.webapp_lib as webapp_lib
import avi_objects.rest as rest
import avi_objects.logger_utils as logger_utils
import avi_objects.infra_utils as infra_utils

# REVIEW need to move to using requests + json so we don't have this ugly workaround
try:
    from k8sclient import configuration, api_client, apis
except ImportError: # assume this isn't an openshift testbed that has the client
    pass
import os
from subprocess import Popen, PIPE
import tempfile
import time

#from pip._vendor.requests.packages.urllib3 import exceptions
import requests
import urllib3
if hasattr(urllib3, 'disable_warnings'):
            urllib3.disable_warnings()
if hasattr(requests.packages.urllib3, 'disable_warnings'):
    requests.packages.urllib3.disable_warnings()

server_ca = \
'-----BEGIN CERTIFICATE-----\n\
MIIDIzCCAgugAwIBAgIJAIngrVlp32KrMA0GCSqGSIb3DQEBBQUAMBUxEzARBgNV\n\
BAMTCmF2aXRlc3QtY2EwHhcNMTcwMzIzMjI1ODAxWhcNNDQwODA4MjI1ODAxWjAV\n\
MRMwEQYDVQQDEwphdml0ZXN0LWNhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n\
CgKCAQEAnuFdZvYHK+8X+VB7bh9d3581B9o53Hw2ySfb8OJA55lhv7dmaWFSEMpZ\n\
XMULNEDu3FzCbfyzTsr2vErn9ayq+gYrHF952PH6AjrnPgmczr+C92NXNjXhH9YL\n\
ErxLjaXxg4nlpTCuum7JmX7YFnQ2zc+q+mC25DUmyBC1AwNyv3NnxU5eekKTQuYg\n\
SJh0HfhZrh5m3mcET4VoCJKuX+lLq1CZj2J58uPAVzbAcp70fEB6qFFSinMLO/AK\n\
l/zwej3snP/3VNJSdHILhBlEuLzguItdrwGs/yUGhjMn8wN84pi122fEFudxcezL\n\
V+BY93sacyIoeEenEvN8eat9wGTlNQIDAQABo3YwdDAdBgNVHQ4EFgQUFh86wPw7\n\
w8EoQmnqFV7D6PwoLZYwRQYDVR0jBD4wPIAUFh86wPw7w8EoQmnqFV7D6PwoLZah\n\
GaQXMBUxEzARBgNVBAMTCmF2aXRlc3QtY2GCCQCJ4K1Zad9iqzAMBgNVHRMEBTAD\n\
AQH/MA0GCSqGSIb3DQEBBQUAA4IBAQA9c+jo4WA4VorZLFGeVWBb9usn2Pb364v+\n\
jKH9rMdnxK/7u4adpaGSUMybwPbTN6h71nkhCg738zoAvNusaLpUe2mDAVJem6v/\n\
w1A5oZTYCiCUWjlfXeUA/KvC0WC+ift35z5fcbx/GsZMA0zXoeqn8IQb31ixij38\n\
+D/BcDprQw/fUL+gEALdbXjOYVlPPqdRWH+boqQoIbbu3dAwW13DhVfI8JaMYROJ\n\
EvXtcA/P85d92zSWmJkIU1Tpyg3iQ8YkCa+cHcVF6TGIDJjfs/LNcJ8fSN6JUy+q\n\
Jw8qWVA5fzihALeTNgztzd3X/t6zFIgYq1L8DQehDV/a3EeLIbTB\n\
-----END CERTIFICATE-----\n\
'

DEPLOYMENT_CONFIG = {
    "kind": "DeploymentConfig",
    "apiVersion": "v1",
    "metadata": {
        "name": "${APP_NAME}-dc"
    },
    "spec": {
        "template": {
            "metadata": {
                "labels": {
                    "name": "${APP_NAME}-dc"
                }
            },
            "spec": {
                "nodeSelector": {
                    "zone": "east"
                },
                "containers": [{
                    "name": "${APP_NAME}-dc",
                    "image": "avinetworks/server-os",
                    "resources": {
                        "requests": {
                            "cpu": "100m",
                            "memory": "64Mi"
                        }
                    },
                    "env": [
                        {
                            "name": "SERVER_NAME",
                            "value": "${APP_NAME}"
                        }
                    ],
                    "ports": [{
                        "containerPort": 8080,
                        "protocol": "TCP"
                    }]
                }]
            }
        },
        "replicas": 1,
        "selector": {
            "name": "${APP_NAME}-dc"
        }
    }
}

ANALYTICS_POLICY = {
    'metrics_realtime_update': {
        'enabled': True,
        'duration': 0
    },
    'client_insights': 'NO_INSIGHTS',
    'full_client_logs': {
        'enabled': True,
        'duration': 0
    }
}

NS_VS_CFG = {
    'analytics_policy': ANALYTICS_POLICY,
#REVIEW: do we want to support hardcoded vip?
#    'vip': [{
#        'ip_address': {
#            'addr': '${VIP}',
#            'type': 'V4'
#        }
#    }],
    'vip': [{
        'auto_allocate_ip': True
    }],
    'east_west_placement': False,
    'application_profile_ref': '/api/applicationprofile?name=System-HTTP'
}

EW_VS_CFG = {
    'analytics_policy': ANALYTICS_POLICY,
    'vip': [{
        'auto_allocate_ip': True
    }],
    'east_west_placement': True,
    'application_profile_ref': '/api/applicationprofile?name=System-HTTP'
}

NS_SERVICE = {
    "kind": "Service",
    "apiVersion": "v1",
    "metadata": {
        "name": "${APP_NAME}",
        "labels": {
            "svc": "${APP_NAME}",
            "owner": "func-openshift"
        },
        "annotations": {
            "avi_proxy": {
                "virtualservice": NS_VS_CFG,
                "pool": {
                    "lb_algorithm": "LB_ALGORITHM_ROUND_ROBIN"
                }
            }
        }
    },
    "spec": {
        "ports": [{
            "port": 80,
            "targetPort": 8080
        }],
        "selector": {
            "name": "${APP_NAME}-dc"
        },
        "type": "LoadBalancer"
    }
}

EW_SERVICE = {
    "kind": "Service",
    "apiVersion": "v1",
    "metadata": {
        "name": "${APP_NAME}",
        "labels": {
            "svc": "${APP_NAME}",
            "owner": "func-openshift"
        },
        "annotations": {
            "avi_proxy": {
                "virtualservice": EW_VS_CFG,
                "pool": {
                    "lb_algorithm": "LB_ALGORITHM_ROUND_ROBIN"
                }
            }
        }
    },
    "spec": {
        "ports": [{
            "port": 80,
            "targetPort": 8080
        }],
        "selector": {
            "name": "${APP_NAME}-dc"
        },
        "type": "LoadBalancer"
    }
}

NS_TEMPLATE = {
    "kind": "Template",
    "apiVersion": "v1",
    "metadata": {
        "name": "ns",
        "annotations": {
            "description": "Template to deploy North-South app",
            "tags": "ns"
        }
    },
    "labels": {
        "template": "ns"
    },
    "objects": [DEPLOYMENT_CONFIG, NS_SERVICE],
    "parameters": [
        {
            "name": "VIP",
            "description": "VIP for the virtual service",
        },
        {
            "name": "APP_NAME",
            "description": "Name for the application"
        }
    ]
}

EW_TEMPLATE = {
    "kind": "Template",
    "apiVersion": "v1",
    "metadata": {
        "name": "ew",
        "annotations": {
            "description": "Template to deploy East-West app",
            "tags": "ew"
        }
    },
    "labels": {
        "template": "ew"
    },
    "objects": [DEPLOYMENT_CONFIG, EW_SERVICE],
    "parameters": [
        {
            "name": "VIP",
            "description": "VIP for the virtual service",
            "value": "169.254.0.200"
        },
        {
            "name": "APP_NAME",
            "description": "Name for the application"
        }
    ]
}

ENDPOINTS = {
    "kind": "Endpoints",
    "apiVersion": "v1",
    "metadata": {
        "name": "${APP_NAME}"
    },
    "subsets": [
        {
            "addresses": [
                { "ip": "${POOL_IP}" }
            ],
            "ports": [
                { "port": 80 }
            ]
        }
    ]
}

class OpenshiftTestUtils(object):

    def __init__(self):
        self.master_node = None
        self.rest_client = None

    def _lazy_init(self):
        ''' delay this until the test framework has initialized the config object '''
        if self.master_node and self.rest_client:
            return

        # get out of any saved sessions
        # may still be susceptible to race conditions if multiple instances
        from lib import mesos_lib
        config = infra_utils.get_config()
        self._oc_logout()
        openshift_config = config.testbed[config.site_name].cloud[0]['oshiftk8s_configuration']
        if not ',' in openshift_config['client_tls_key_and_certificate_uuid']:
            raise Exception('Did not find client tls key and certificate string in proper format in cloud config')
        client_key_file, client_cert_file = openshift_config['client_tls_key_and_certificate_uuid'].split(',')
        ca_cert_file = openshift_config['ca_tls_key_and_certificate_uuid']
        self.master_node = openshift_config['master_nodes'][0]
        configuration.host = openshift_config['master_nodes'][0]
        configuration.ssl_ca_cert = mesos_lib.get_full_cert_path(ca_cert_file)
        configuration.cert_file = mesos_lib.get_full_cert_path(client_cert_file)
        configuration.key_file = mesos_lib.get_full_cert_path(client_key_file)
        client = api_client.ApiClient(openshift_config['master_nodes'][0])
        self.rest_client = apis.ApivApi(client)
        self._oc_login()
        logger.info('Initialized a new OpenshiftTestUtils for master %s' % self.master_node)

    def _oc_logout(self):
        cmd = 'oc logout'
        p = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
        stdout, stderr = p.communicate()
        if stderr:
            logger.warning('WARNING: oc logout failed with %s' %stderr)

    def _oc_login(self, username='aviuser', password='aviuser'):
        ''' login with user -- must exist and with permission
        e.g.: oadm policy add-cluster-role-to-user cluster-admin aviuser
        '''
        cmd = 'oc login %s -u %s -p %s --insecure-skip-tls-verify' %(self.master_node, username, password)
        p = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
        stdout, stderr = p.communicate()
        if stderr:
            logger.warning('WARNING: oc login failed with %s' %stderr)

    def _change_project(self, project_name):
        logger.info('Switching to project: %s' %project_name)
        change_project_cmd = 'oc project %s' %project_name
        p = Popen(change_project_cmd, stdout=PIPE, stderr=PIPE, shell=True)
        stdout, stderr = p.communicate()
        if stderr:
            logger.warning('WARNING: Changing oc project failed with %s' %stderr)
        logger.debug('stdout: %s' %stdout)

    def _create_project(self, project_name):
        new_project_cmd = 'oc new-project %s' %project_name
        p = Popen(new_project_cmd, stdout=PIPE, stderr=PIPE, shell=True)
        stdout, stderr = p.communicate()
        if stderr:
            if 'already exists' in stderr:
                logger.debug('Project %s already exists' %project_name)
            else:
                logger.warning('WARNING: oc new-project failed with %s' %stderr)

    def _project(self, project_name):
        if project_name != 'default': # REVIEW shall we be more clever and list all projects and only create if it doesn't exist?
            self._create_project(project_name)
        self._change_project(project_name)

    def delete_project(self, project_name):
        delete_project_cmd = 'oc delete project %s' %project_name
        p = Popen(delete_project_cmd, stdout=PIPE, stderr=PIPE, shell=True)
        stdout, stderr = p.communicate()
        if stderr:
            if 'not found' in stderr:
                logger.debug('Project %s already deleted' %project_name)
            else:
                logger.warning('WARNING: oc delete project failed with %s' %stderr)

    def run_oc_cmd(self, cmd, retry=True, ignore_err=False, project='default'):
        self._lazy_init()
        self._project(project) # REVIEW these may fail if we need to login
        p = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
        stdout, stderr = p.communicate()
        if 'system:anonymous' in stderr or 'You must be logged in' in stderr: #REVIEW any better signal?
            if ignore_err:
                return stdout, stderr
            elif retry:
                logger.info('Attempting to re-login to oc CLI')
                self._oc_login()
                p = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
                stdout, stderr = p.communicate()
            else:
                raise Exception('Failed to login to oc CLI, please check credentials and paths')
        return stdout, stderr

    def create_openshift_app_from_template(self, northsouth, app_id, instances, vip, **kwargs):
        ''' Uses CLI
        Populates the template with args and creates the app
        '''
        # update template with any args
        if northsouth:
            json_data = deepcopy(NS_TEMPLATE)
        else:
            json_data = deepcopy(EW_TEMPLATE)
        print 'Creating template from %s' %json_data
        tenant = kwargs.get('tenant', 'default')
        version = kwargs.get('version')
        pool = kwargs.get('pool', {})
        virtualservice = kwargs.get('virtualservice', {})
        image = kwargs.get('image', None)
        protocol = kwargs.get('protocol', 'http')
        external_pool = kwargs.get('external_pool', None)
        constraints = kwargs.get('constraints', [])
        headless = kwargs.get('headless', False)
        svc_ports = kwargs.get('svc_ports', [])
        sessionAffinity = kwargs.get('sessionAffinity', None)
        dc_target_ports_protocol = kwargs.get('dc_target_ports_protocol', {})
        rm_applicationprofile = kwargs.get('rm_applicationprofile', False)
        svc_avi_proxy = kwargs.get('svc_avi_proxy', [])
        svc_spec = kwargs.get('svc_spec', None)
        svc_annotations = kwargs.get('svc_annotations', None)
        # REVIEW do we need to support floating ip?
        secure_egress_pod = kwargs.get('secure_egress_pod', False)
        # No need to create DeploymentConfig while egress service creation
        if secure_egress_pod:
            del json_data['objects'][0]

        for object in json_data['objects']:
            if object['kind'] == 'DeploymentConfig':
                object['spec']['replicas'] = instances
                logger.info('Setting replicas for app %s to %d' %(app_id, instances))
                if protocol == 'https':
                    object['spec']['template']['spec']['containers'][0]['ports'][0]['containerPort'] = 8443
                if image:
                    object['spec']['template']['spec']['containers'][0]['image'] = image
                    logger.info('Setting image for app %s to %s' %(app_id, image))
                for constraint in constraints:
                    key = constraint[0]
                    value = constraint[2]
                    object['spec']['template']['spec']['nodeSelector'][key] = value
                    logger.info('Adding nodeSelector %s = %s' %(key, value))
                if dc_target_ports_protocol:
                    #delete existing container port from template and add new as specified in dc_target_ports
                    del object['spec']['template']['spec']['containers'][0]['ports'][:]
                    for port, protocol in dc_target_ports_protocol.iteritems():
                        container_port = {"containerPort": int(port), "protocol": protocol}
                        object['spec']['template']['spec']['containers'][0]['ports'].append(container_port)

            elif object['kind'] == 'Service':
                #replace the complete avi_proxy from template with svc_avi_proxy
                if svc_annotations:
                    object['metadata']['annotations'] = svc_annotations
                if svc_avi_proxy:
                    object['metadata']['annotations']['avi_proxy'] = svc_avi_proxy
                # Refer to https://kubernetes.io/docs/user-guide/services/#headless-services
                if headless:
                    logger.info('setting to headless mode')
                    object['spec']['clusterIP'] = None
                avi_proxy = object['metadata']['annotations']['avi_proxy']
                if secure_egress_pod:
                    egress_pod = object['metadata']['annotations']['egress_pod']
                if protocol == 'https':
                    object['spec']['ports'][0]['port'] = 443
                    object['spec']['ports'][0]['targetPort'] = 8443
                    pki_profile = kwargs.get('pki_profile', None)
                    if pki_profile:
                        avi_proxy['virtualservice']['services'] = [{'port': 443, 'enable_ssl': True}]
                        avi_proxy['virtualservice']['application_profile_ref'] = '/api/applicationprofile?name=System-Secure-HTTP'
                        avi_proxy['virtualservice']['ssl_key_and_certificate_refs'] = ['System-Default-Cert']
                        avi_proxy['virtualservice']['ssl_profile_ref'] = '/api/sslprofile/?name=System-Standard'
                        avi_proxy['pool']['ssl_profile_ref'] = '/api/sslprofile/?name=System-Standard'
                        avi_proxy['pool']['pki_profile_ref'] = '/api/pkiprofile/?name=%s'%pki_profile
                    else:
                        avi_proxy['virtualservice'].pop('application_profile_ref')
                if tenant:
                    avi_proxy['tenant'] = tenant
                if version:
                    avi_proxy['version'] = version
                if virtualservice:
                    if 'virtualservice' not in avi_proxy:
                        avi_proxy['virtualservice'] = virtualservice
                    else:
                        for k, v in virtualservice.iteritems():
                            avi_proxy['virtualservice'][k] = v
                if pool:
                    if 'pool' not in avi_proxy:
                        avi_proxy['pool'] = pool
                    else:
                        for k, v in pool.iteritems():
                            avi_proxy['pool'][k] = v
                if svc_spec:
                    object['spec'] = svc_spec
                if sessionAffinity:
                    object['spec']['sessionAffinity'] = sessionAffinity
                    del avi_proxy['pool']['lb_algorithm']
                if rm_applicationprofile:
                    del avi_proxy['virtualservice']['application_profile_ref']
                if svc_ports:
                    del object['spec']['ports'][:]
                    for svc_port in svc_ports:
                        port = svc_port = {"name": "port-%s" % str(svc_port['port']), "port": svc_port['port'], "targetPort":
                                svc_port['target_port']}
                        object['spec']['ports'].append(port)

                object['metadata']['annotations']['avi_proxy'] = json.dumps(avi_proxy)
                if secure_egress_pod:
                    object['metadata']['annotations']['egress_pod'] = json.dumps(egress_pod)
                logger.info('Updated avi_proxy %s' %(object['metadata']['annotations']['avi_proxy']))

        # Refer to http://kubernetes.io/docs/user-guide/services/#services-without-selectors
        if external_pool:
            logger.info('Creating app with external pool %s' %external_pool)
            assert json_data['objects'][1]['kind'] == 'Service'
            json_data['objects'][1]['spec'].pop('selector')
            assert json_data['objects'][0]['kind'] == 'DeploymentConfig'
            json_data['objects'].pop(0)
            endpoint_data = deepcopy(ENDPOINTS)
            endpoint_data['subsets'][0]['addresses'][0]['ip'] = external_pool
            json_data['objects'].append(endpoint_data)

        self.create_openshift_app(json_data, app_id, vip, project=tenant)

    def create_openshift_app(self, json_data, app_id, vip, project='default'):
        ''' Uses CLI
        Creates app with given json.
        '''
        try:
            _, template_file = tempfile.mkstemp()
            with open(template_file, 'w') as outfile:
                json.dump(json_data, outfile)

            cmd = 'oc process -f %s -p APP_NAME=%s -p VIP=%s | oc create --save-config -f -' %(template_file, app_id, vip)
            stdout, stderr = self.run_oc_cmd(cmd, project=project)
            if stderr:
                if 'already exists' in stderr:
                    raise Exception('App %s already exists' %app_id)
                else:
                    raise Exception('Unknown error: %s' %stderr)
            if 'created' in stdout:
                logger.info('Openshift Client: Created app %s' %app_id)
            else:
                raise Exception('Unexpected output: %s' %stdout)
        except Exception as e:
            raise Exception('Got exception %s trying to create app %s' %(str(e), app_id))
        finally:
            #print 'app %s template file %s' %(app_id, template_file)
            os.remove(template_file)

    def delete_openshift_app(self, app_id, project='default'):
        ''' Uses CLI
        Deletes app with given id
        '''
        # for expediency, assume it doesn't matter which of NS or EW template we use to delete
        try:
            json_data = deepcopy(EW_TEMPLATE)
            for object in json_data['objects']:
                if object['kind'] == 'Service':
                    avi_proxy = object['metadata']['annotations']['avi_proxy']
                    object['metadata']['annotations']['avi_proxy'] = json.dumps(avi_proxy)
            _, template_file = tempfile.mkstemp()
            with open(template_file, 'w') as outfile:
                json.dump(json_data, outfile)

            cmd = 'oc process -f %s -p APP_NAME=%s | oc delete -f -' %(template_file, app_id)
            stdout, stderr = self.run_oc_cmd(cmd, project=project)
            if stderr:
                if 'not found' in stderr:
                    logger.info('Openshift Client: app %s not found for deletion' %app_id)
                else:
                    raise Exception('Unknown error: %s' %stderr)
            if 'deleted' in stdout:
                logger.info('Openshift Client: Deleted app %s' %app_id)
        except Exception as e:
            raise Exception('Got exception %s trying to delete app %s' %(str(e), app_id))
        finally:
            os.remove(template_file)
        return app_id

    def delete_all_openshift_apps(self):
        app_ids = []
        if not self.rest_client:
            self._lazy_init()
        res = self.rest_client.list_namespaced_service_0(label_selector='owner=func-openshift') # note label convention
        ret = res.to_dict()
        items = ret['items']
        num_apps = len(items)
        for inst in items:
            metadata = inst['metadata']
            app_id = metadata['name']
            project = metadata['namespace']
            self.delete_openshift_app(app_id, project=project)
            app_ids.append(app_id)
        logger.info('Openshift Client: Deleted %d apps' %num_apps)
        return app_ids

    def scale_openshift_app(self, app_id, num_inst, project='default'):
        ''' Uses CLI
        Scales app with given id to num_inst
        '''
        cmd = 'oc scale deploymentconfig %s-dc --replicas=%d' %(app_id, num_inst)
        stdout, stderr = self.run_oc_cmd(cmd, project=project)
        if stderr:
            if 'not found' in stderr:
                logger.info('Openshift: app %s not found for scaling' %app_id)
            else:
                raise Exception('Unknown error: %s' %stderr)
        if 'scaled' in stdout:
            retries = 10
            while retries > 0:
                time.sleep(5)
                if num_inst == self.get_openshift_app_runtime(app_id).instances:
                    break
            else:
                logger.info('App scaled to %d but found instances = %d, sleeping and checking again...'
                            %(num_inst, self.get_openshift_app_runtime(app_id).instances))
                retries -= 1
        if retries == 0:
            raise Exception('App scaled to %d but after retries, found instances = %d' %(num_inst, self.get_openshift_app_runtime(app_id).instances))
        logger.info('Openshift: Scaled app %s to %d instances' %(app_id, num_inst))

    def update_openshift_app(self, app_name, instances, annotations, project='default', **kwargs):
        # get northsouth and vip from existing app
        metadata = self.get_openshift_app_metadata(app_name)
        avi_proxy = json.loads(metadata['annotations']['avi_proxy'])
        eastwest = avi_proxy['virtualservice'].get('east_west_placement', True) # also east-west if not specified
        northsouth = not eastwest
        vip = ''
        if northsouth:
            vip = self._get_vip_from_proxy(avi_proxy)

        svc_spec = kwargs.get('svc_spec', None)
        if instances is None:
            instances = self.get_openshift_app_runtime(app_name).instances
        if not annotations:
            annotations = metadata['annotations']

        if northsouth:
            json_data = deepcopy(NS_TEMPLATE)
        else:
            json_data = deepcopy(EW_TEMPLATE)
        for object in json_data['objects']:
            if object['kind'] == 'DeploymentConfig':
                object['spec']['replicas'] = instances
                logger.info('Setting replicas for %s to %d' %(app_name, instances))
            elif object['kind'] == 'Service':
                object['metadata']['annotations'] = annotations
                if svc_spec:
                    object['spec'] = svc_spec
            else:
                raise Exception('Unknown object: %s' %object['kind'])

        try:
            _, template_file = tempfile.mkstemp()
            with open(template_file, 'w') as outfile:
                json.dump(json_data, outfile)

            cmd = 'oc process -f %s -p APP_NAME=%s -p VIP=%s | oc apply -f -' %(template_file, app_name, vip)
            stdout, stderr = self.run_oc_cmd(cmd, project=project)
            if stderr:
                raise Exception('Unknown error: %s' %stderr)
            if 'configured' in stdout:
                logger.info('Openshift Client: Updated app %s' %app_name)
            else:
                raise Exception('Unexpected output: %s' %stdout)
        except Exception as e:
            raise Exception('Got exception %s trying to update app %s' %(str(e), app_name))
        finally:
            os.remove(template_file)

    # REVIEW: this is apparently not supported by openshift; trying to update an existing service with a selector
    # by removing the selector does not work; the service will still have the deployment config attached
    def update_external_pool(self, app_name, pool_ip, project='default'):
        """ Implement service without selector and create endpoint for the pool """
        # get northsouth and vip from existing app
        metadata = self.get_openshift_app_metadata(app_name)
        annotations = metadata['annotations']
        avi_proxy = json.loads(metadata['annotations']['avi_proxy'])
        eastwest = avi_proxy['virtualservice'].get('east_west_placement', True) # east-west if not specified
        northsouth = not eastwest
        vip = ''
        if northsouth:
            vip = self._get_vip_from_proxy(avi_proxy)
        # probably not necessary
        #instances = self.get_openshift_app_runtime(app_name).instances
        #if instances < 1:
        #    instances = 1

        if northsouth:
            json_data = deepcopy(NS_TEMPLATE)
        else:
            json_data = deepcopy(EW_TEMPLATE)
        """ Refer to http://kubernetes.io/docs/user-guide/services/#services-without-selectors """
        assert json_data['objects'][1]['kind'] == 'Service'
        json_data['objects'][1]['spec'].pop('selector')
        json_data['objects'][1]['metadata']['annotations'] = annotations
        assert json_data['objects'][0]['kind'] == 'DeploymentConfig'
        json_data['objects'].pop(0)

        # remove will mutate the list so the iteration breaks
        #for object in json_data['objects']:
        #    if object['kind'] == 'DeploymentConfig':
        #        json_data['objects'].remove(object)
        #    elif object['kind'] == 'Service':
        #        object['spec'].pop('selector')
        #        object['metadata']['annotations'] = annotations
        #    else:
        #        raise Exception('Unknown object: %s' %object['kind'])

        #REVIEW maybe the port should be a param too
        endpoint_data = deepcopy(ENDPOINTS)
        endpoint_data['metadata']['name'] = app_name
        endpoint_data['subsets'][0]['addresses'][0]['ip'] = pool_ip
        #json_data['objects'].append(endpoint_data)

        try:
            _, template_file = tempfile.mkstemp()
            with open(template_file, 'w') as outfile:
                json.dump(json_data, outfile)

            cmd = 'oc process -f %s -p APP_NAME=%s -p VIP=%s | oc apply -f -' %(template_file, app_name, vip)
            stdout, stderr = self.run_oc_cmd(cmd, project=project)
            if stderr:
                raise Exception('Unknown error: %s' %stderr)
            if 'configured' in stdout:
                logger.info('Openshift Client: Updated app %s to remove selector and deploymentconfig' %app_name)
            else:
                raise Exception('Unexpected output: %s' %stdout)
        except Exception as e:
            raise Exception('Got exception %s trying to update app %s to remove selector and dc' %(str(e), app_name))
        finally:
            #print 'update external pool json at %s' %template_file
            os.remove(template_file)

        try:
            _, endpoint_file = tempfile.mkstemp()
            with open(endpoint_file, 'w') as outfile:
                json.dump(endpoint_data, outfile)

            cmd = 'oc apply -f %s' %(endpoint_file)
            stdout, stderr = self.run_oc_cmd(cmd, project=project)
            if stderr:
                raise Exception('Unknown error: %s' %stderr)
            if 'configured' in stdout:
                logger.info('Openshift Client: Updated app %s to create endpoint' %app_name)
            else:
                raise Exception('Unexpected output: %s' %stdout)
        except Exception as e:
            raise Exception('Got exception %s trying to update app %s to create endpoint' %(str(e), app_name))
        finally:
            #print 'endpoint json at %s' %endpoint_file
            os.remove(endpoint_file)

    def get_endpoints(self, endpoint, project='default', status=True):
        #get the endpoint response in the json format
        cmd = 'oc get endpoints %s -o=json' %endpoint
        stdout, stderr = self.run_oc_cmd(cmd, project=project)
        logger.info('stdout: %s' %stdout)
        logger.info('stderr: %s' %stderr)
        if stderr:
            return set()

        eps = set()
        oc_endpoint_data = json.loads(stdout)
        for address in oc_endpoint_data['subsets'][0]['addresses']:
            for port in oc_endpoint_data['subsets'][0]['ports']:
                eps.add((address['ip'], port['port']))
        return eps

    def check_route(self, route, project='default', status=True):
        cmd = 'oc get route %s -o json' % route
        stdout, stderr = self.run_oc_cmd(cmd, project=project)
        logger.info('stdout: %s' % stdout)
        logger.info('stderr: %s' % stderr)
        stdout = json.loads(stdout)
        if stderr:
            return (False, stderr)
        if status:
            try:
                ''' This should be a valid timestamp format YYYY-MM-DDTHH:M:SZ '''
                date = stdout['status']['ingress'][0]['conditions'][0]['lastTransitionTime']
                datetime.datetime.strptime(date, '%Y-%m-%dT%H:%M:%SZ')
            except ValueError:
                raise ValueError("Incorrect date format, should be YYYY-MM-DDTHH:M:SZ")

            keys = stdout['status']['ingress'][0]
            if keys['routerName'] == 'AviVantage' and keys['host'] == stdout['spec']['host'] and \
                                keys['conditions'][0]['status'] == 'True' and keys['conditions'][0]['type'] == 'Admitted':
                return (True, stdout)

        return (False, stderr)

    def create_route(self, app_name, type='http', termination='edge', vip=None, shared_vs=None,
                     domain='avi-container-dns.internal', project='default', **kwargs):
        """ Construct and append route to existing service """
        cert_name = kwargs.get('cert_name', None)
        route_name = kwargs.get('route_name', '%s-route' %app_name)
        annotations = kwargs.get("annotations", None)
        if not vip:
            avi_proxy = {"virtualservice": {"auto_allocate_ip": True}}
        else:
            avi_proxy = {
                "virtualservice": {
                    "vip": [{
                        "ip_address": {
                            "addr": "%s" %vip,
                            "type": "V4"
                        }
                    }]
                }
            }
        if cert_name:
            avi_proxy['virtualservice']['ssl_key_and_certificate_refs'] = ['%s'%cert_name]

        route_json = {
            "kind": "Route",
            "apiVersion": "v1",
            "metadata": {
                "name": "%s" %route_name,
                "annotations": {
                    "avi_proxy": "%s" %json.dumps(avi_proxy)
                }
            },
            "spec": {
                "host": "%s.%s" %(app_name, domain),
                "to": {
                    "kind": "Service",
                    "name": "%s" %app_name
                }
            }
        }
        if annotations:
            annotations['avi_proxy'] = json.dumps(annotations['avi_proxy'])
            route_json['metadata']['annotations'] = annotations
        if shared_vs:
            route_json['metadata']['annotations'].pop('avi_proxy')
            route_json['metadata']['annotations']['route_virtualservice'] = shared_vs

        if 'path' in kwargs:
            route_json['spec']['path'] = kwargs['path']

        # REVIEW should this move up into the class itself?
        def read_file(filename):
            with open(filename, 'r') as infile:
                return infile.read()

        tls = {
            "termination": "%s"%termination
        }
        self._lazy_init()
        if not cert_name:
            key_string = read_file(configuration.key_file)
            crt_string = read_file(configuration.cert_file)
            tls['key'] = "|-\n%s" %key_string
            tls['certificate'] = "|-\n%s" %crt_string
            tls['caCertificate'] = "|-\n%s" %server_ca

        if termination == 'reencrypt':
            if kwargs.get('reencrypt_cert'):
                reencrypt_cert = kwargs.get('reencrypt_cert')
                crt_string = read_file(reencrypt_cert)
            else:
                crt_string = server_ca
            tls['destinationCACertificate'] = "|-\n%s" %crt_string

        if type == 'http':
            pass
        elif type == 'https':
            route_json['spec']['tls'] = tls
        elif type == 'http+https':
            route_json['spec']['tls'] = tls
            if termination == 'edge':
                route_json['spec']['tls']['insecureEdgeTerminationPolicy'] = 'Allow'
        elif type == 'http->https':
            route_json['spec']['tls'] = tls
            if termination == 'edge':
                route_json['spec']['tls']['insecureEdgeTerminationPolicy'] = 'Redirect'
        else:
            raise Exception('Unknown route type: %s' %type)

        try:
            _, json_file = tempfile.mkstemp()
            with open(json_file, 'w') as outfile:
                json.dump(route_json, outfile)
            
            cmd = 'oc create --save-config -f %s' %json_file
            stdout, stderr = self.run_oc_cmd(cmd, project=project)
            logger.info('stdout: %s' %stdout)
            logger.info('stderr: %s' %stderr)
            if stderr:
                if 'already exists' in stderr:
                    logger.warning('WARNING route %s already exists' %route_name)
                else:
                    raise Exception('Unexpected output %s while creating route: %s' %(stderr, route_name))
            elif 'created' in stdout:
                logger.info('Openshift Client: Created route %s for app %s' %(route_name, app_name))
            else:
                raise Exception('Unexpected output: %s creating route %s for app %s' %(stdout, route_name, app_name))
        except Exception as e:
            raise Exception('Got exception %s trying to create route %s for app %s' %(str(e), route_name, app_name))
        finally:
            os.remove(json_file)

    def delete_service(self, service_name, project='default'):
        cmd = 'oc delete service %s' %service_name
        stdout, stderr = self.run_oc_cmd(cmd, project=project)
        if stderr:
            if 'not found' in stderr:
                pass
            else:
                raise Exception('Unexpected output: %s while deleting service %s' %(stderr, service_name))
        elif 'deleted' in stdout:
            logger.info('Openshift Client: Deleted service %s' %service_name)
        else:
            raise Exception('Unexpected output: %s deleting service %s' %(stdout, service_name))

    def delete_route(self, app_name, route_name=None, project='default'):
        if not route_name:
            route_name = app_name + '-route'
        cmd = 'oc delete route %s' %route_name
        stdout, stderr = self.run_oc_cmd(cmd, project=project)
        if stderr:
            if 'not found' in stderr:
                pass
            else:
                raise Exception('Unexpected output: %s while deleting route %s' %(stderr, route_name))
        elif 'deleted' in stdout:
            logger.info('Openshift Client: Deleted route %s' %route_name)
        else:
            raise Exception('Unexpected output: %s deleting route %s' %(stdout, route_name))

    def delete_all_routes(self, project='default'):
        """ Deletes all routes """
        cmd = 'oc delete route --all'
        stdout, stderr = self.run_oc_cmd(cmd, project=project)
        if stderr:
            if 'No resources found' in stderr:
                pass
            else:
                raise Exception('Unexpected output: %s while deleting all routes' %stderr)
        elif 'No resources found' in stdout:
            pass # it seems to be in stdout instead of stderr?
        elif 'deleted' in stdout:
            logger.info('Openshift Client: Deleted all routes')
        else:
            raise Exception('Unexpected output: %s deleting all routes' %stdout)

    def get_openshift_app_runtime(self, app_id, project='default'):
        if not self.rest_client:
            self._lazy_init()
        res = self.rest_client.list_namespaced_pod_0(label_selector='name=%s-dc'%app_id) # note label convention
        ret = res.to_dict()
        instances = ret['items']

        tasks_running = 0
        tasks_healthy = 0
        tasks = []
        for inst in instances:
            try:
                if inst['metadata']['namespace'] != project:
                    continue
                if inst['status']['container_statuses'][0]['ready']: # REVIEW any better proxy for healthy/running tasks?
                    tasks_running += 1
                    tasks_healthy += 1
                task = {}
                task['host'] = inst['status']['host_ip']
                task['pod'] = inst['status']['pod_ip']
                # REVIEW any other info for this?
                tasks.append(task)
            except (KeyError, TypeError):
                logger.info('Got error accessing instances for app %s...may not be up yet' %app_id)
        return OpenshiftAppRuntime(len(tasks), tasks_running, tasks_healthy, tasks)

    def get_openshift_app_metadata(self, app_id, project='default'):
        if not self.rest_client:
            self._lazy_init()
        res = self.rest_client.list_namespaced_service_0(label_selector='svc=%s'%app_id) # note label convention
        ret = res.to_dict()
        items = ret['items']
        for inst in items:
            metadata = inst['metadata']
            if metadata['name'] == app_id and metadata['namespace'] == project:
                return metadata
        logger.warning('did not find any app named %s in project %s' %(app_id, project))

    def get_openshift_slaves(self):
        if not self.rest_client:
            self._lazy_init()
        res = self.rest_client.list_node()
        ret = res.to_dict()
        return ret['items']

    def _get_vip_from_proxy(self, avi_proxy):
        vip = ''
        try:
            if avi_proxy['virtualservice']['auto_allocate_ip']:
                pass
            else:
                vip = str(avi_proxy['virtualservice']['ip_address']['addr'])
        except KeyError:
            # 17.1 multivip
            if avi_proxy['virtualservice']['vip'][0]['auto_allocate_ip']:
                pass
            else:
                vip = str(avi_proxy['virtualservice']['vip'][0]['ip_address']['addr'])
        return vip

    def get_pod_config(self, pod, project='default'):
        """
        Get openshift pod configuration
        """
        cmd = "oc get pods %s -o=json" %pod
        pod_config, stderr = self.run_oc_cmd(cmd, project=project)
        pod_config = json.loads(pod_config)
        if stderr:
            logger.info("Unable to get pod with name %s. Error %s" % (pod, stderr))
        return pod_config

    def get_pool_config_for_app(self, app_id, project='default'):
        """
        Get openshift pool configuration
        """
        cmd = "oc get svc %s -o=json" % app_id
        svc_config, stderr = self.run_oc_cmd(cmd, project=project)
        svc_config = json.loads(svc_config)
        if stderr:
            logger.info("Unable to get service with name %s. Error %s" % (app_id, stderr))
        pool_config = []
        for port in svc_config["spec"]["ports"]:
            pool = {"port": port['targetPort'], "service_port": port['port'], "protocol": port['protocol'].lower()}
            if port.has_key("name"):
                pool["name"] = port["name"]
            pool_config.append(pool)
        return pool_config

    def get_route_path_from_vs_httppolicies(self, vs_name, route_name, tenant='default', project='default'):
        cmd = 'oc get route %s -o json' % route_name
        stdout, stderr = self.run_oc_cmd(cmd, project=project)
        logger.info('stdout: %s' % stdout)
        logger.info('stderr: %s' % stderr)
        stdout = json.loads(stdout)
        if stderr:
            return (False, stderr)
        route_path = stdout["spec"]["path"]
        vs_resp = vs_lib.get_vs(vs_name)
        vs_http_policy_uuid = webapp_lib.get_slug_from_uri(vs_resp["http_policies"][0]["http_policy_set_ref"])
        resp_code, httppolicyset_resp = rest.get("httppolicyset", uuid=vs_http_policy_uuid, tenant=tenant)

        path_list = []
        for rule in httppolicyset_resp["http_request_policy"]["rules"]:
            for path in rule["match"]["path"]["match_str"]:
                path_list.append(path)
        if route_path not in path_list:
            logger_utils.fail("Httppolicies path not matching to route path")

    def get_openshift_svc_config(self, app_id, project='default'):
        """
        Get openshift service configuration
        """
        cmd = "oc get svc %s -o=json" % app_id
        svc_config, stderr = self.run_oc_cmd(cmd, project=project)
        svc_config = json.loads(svc_config)
        if stderr:
            logger.info("Unable to get service with name %s. Error %s" % (app_id, stderr))

        return svc_config

    def get_replicationcontroller_for_egress_service(self, replicationcontroller_name, tenant='default'):
        cmd = 'oc get rc %s -o json' % replicationcontroller_name
        stdout, stderr = self.run_oc_cmd(cmd, project=tenant)
        logger.info('stdout: %s \n stderr: %s' % (stdout, stderr))
        if stderr:
            logger_utils.fail(stderr)

        return json.loads(stdout)

    def get_pod_from_replicationcontroller(self, replicationcontroller_name,
                                           tenant='default'):
        '''
        Pod name generated by appending some random string to replication controller
        example:
        RC name : vs-1-avi-egress-pod
        Pod name : vs-1-avi-egress-pod-tn95k
        so here need to get pod name by doing grep to RC
        '''
        cmd = 'oc get pod | grep %s' % replicationcontroller_name
        stdout, stderr = self.run_oc_cmd(cmd, project=tenant)
        logger.info('stdout: %s \n stderr: %s' % (stdout, stderr))
        if stderr:
            logger_utils.fail(stderr)

        if not stdout:
            logger_utils.fail("Replication controller not found")

        cmd = 'oc get pod %s -o json' % stdout.split()[0]
        stdout, stderr = self.run_oc_cmd(cmd, project=tenant)
        logger.info('stdout: %s \n stderr: %s' % (stdout, stderr))
        if stderr:
            logger_utils.fail(stderr)

        return json.loads(stdout)

    def get_serviceaccounts_for_egress_service(self, serviceaccounts_name, tenant='default'):
        cmd = 'oc get serviceaccounts %s -o json' % serviceaccounts_name
        stdout, stderr = self.run_oc_cmd(cmd, project=tenant)
        logger.info('stdout: %s \n stderr: %s' % (stdout, stderr))
        if stderr:
            logger_utils.fail(stderr)

        return json.loads(stdout)

    def get_scc_for_egress_service(self, scc_name, tenant='default'):
        cmd = 'oc get securitycontextconstraints %s -o json' % scc_name
        stdout, stderr = self.run_oc_cmd(cmd, project=tenant)
        logger.info('stdout: %s \n stderr: %s' % (stdout, stderr))
        if stderr:
            logger_utils.fail(stderr)

        return json.loads(stdout)

    def get_projects(self, tenant='default'):
        cmd = 'oc get project -o json'
        stdout, stderr = self.run_oc_cmd(cmd, project=tenant)
        if stderr:
            logger_utils.fail('Error:%s' % stderr)
        return json.loads(stdout)

    def get_object_status(self, object_type, object_name, action='create', tenant='default', **kwargs):
        retries = kwargs.get('retries', 5)
        cmd = 'oc get %s | grep %s' %(object_type, object_name)
        for i in range(retries):
            stdout, stderr = self.run_oc_cmd(cmd, project=tenant)
            if action == 'create':
                if not stdout:
                    time.sleep(20)
                    continue
                return True
            elif action == 'delete':
                if stdout:
                    time.sleep(20)
                    continue
                return True
        else:
            logger_utils.fail("%s action failed" % action)

    def create_serviceaccount(self, serviceaccount_name, tenant='default'):
        serviceaccount_config = {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {
                "name": "%s" %serviceaccount_name
            }
        }
        try:
            _, template_file = tempfile.mkstemp()
            with open(template_file, 'w') as outfile:
                json.dump(serviceaccount_config, outfile)

            cmd = 'oc create --save-config -f %s ' % (template_file)
            stdout, stderr = self.run_oc_cmd(cmd, project=tenant)
            logger.info('stdout: %s \n stderr: %s' % (stdout, stderr))
            if stderr:
                logger_utils.fail('Error: %s' % stderr)
        except Exception as e:
            logger_utils.fail('Got exception while creating serviceaccount %s' %e)
        finally:
            os.remove(template_file)

    def create_clusterrole(self, clusterrole_config, tenant='default'):
        try:
            _, template_file = tempfile.mkstemp()
            with open(template_file, 'w') as outfile:
                json.dump(clusterrole_config, outfile)

            cmd = 'oc create --save-config -f %s ' % (template_file)
            stdout, stderr = self.run_oc_cmd(cmd, project=tenant)
            logger.info('stdout: %s \n stderr: %s' % (stdout, stderr))
            if stderr:
                logger_utils.fail('Error: %s' % stderr)
        except Exception as e:
            logger_utils.fail('Got exception while creating clusterrole %s' % e)
        finally:
            os.remove(template_file)

    def get_serviceaccount_token(self, serviceaccount_name, tenant='default'):
        cmd = 'oc get serviceaccount %s -o json' % serviceaccount_name
        stdout, stderr = self.run_oc_cmd(cmd, project=tenant)
        logger.info('stdout: %s \n stderr: %s' % (stdout, stderr))
        if stderr:
            logger_utils.fail('Error: %s' % stderr)

        stdout = json.loads(stdout)
        for secret in stdout['secrets']:
            if 'docker' in secret['name']:
                cmd = 'oc get secret %s -o json' % secret['name']
                break
        stdout, stderr = self.run_oc_cmd(cmd, project=tenant)
        logger.info('stdout: %s \n stderr: %s' % (stdout, stderr))
        if stderr:
            logger_utils.fail('Error: %s' % stderr)
        stdout = json.loads(stdout)
        service_account_token = stdout['metadata']['annotations'][
            'openshift.io/token-secret.value']

        return service_account_token

    def delete_clusterrole(self, clusterrole_name, tenant='default'):
        cmd = 'oc delete clusterrole %s' %clusterrole_name
        stdout, stderr = self.run_oc_cmd(cmd, project=tenant)
        logger.info('stdout: %s \n stderr: %s' % (stdout, stderr))
        if stderr:
            logger_utils.fail('Error: %s' % stderr)

    def delete_serviceaccount(self, serviceaccount_name, tenant='default'):
        cmd = 'oc delete serviceaccount %s' %serviceaccount_name
        stdout, stderr = self.run_oc_cmd(cmd, project=tenant)
        logger.info('stdout: %s \n stderr: %s' % (stdout, stderr))
        if stderr:
            logger_utils.fail('Error: %s' % stderr)
    
    def add_update_alternatebackends(self, route, backend_vs_name_list, weight_list, project='default', **kwargs):
        cmd = 'oc get route %s -o json' % route
        stdout, stderr = self.run_oc_cmd(cmd, project=project)
        logger.info('stdout: %s' % stdout)
        logger.info('stderr: %s' % stderr)
        stdout = json.loads(stdout)
        if stderr:
            return (False, stderr)
        is_add = kwargs.get('is_add', False)
        is_update = kwargs.get('is_update', False)

        if is_add:
            for backend_vs_name, weight in zip(backend_vs_name_list,
                                               weight_list):
                alternateBackends_json = [
                    {
                        "kind": "Service",
                        "name": "%s" % backend_vs_name,
                        "weight": int(weight)
                    }
                ]
                if stdout['spec'].has_key('alternateBackends'):
                    stdout['spec']['alternateBackends'].append(alternateBackends_json[0])
                else:
                    stdout['spec']['alternateBackends']=alternateBackends_json

        if is_update:
            for key in stdout['spec']['alternateBackends']:
                for backend_vs_name, weight in zip(backend_vs_name_list,
                                                   weight_list):
                    if key['name'] == backend_vs_name:
                        key['weight'] = int(weight)

        try:
            _, template_file = tempfile.mkstemp()
            with open(template_file, 'w') as outfile:
                json.dump(stdout, outfile)

            cmd = 'oc apply -f %s ' %(template_file)
            stdout, stderr = self.run_oc_cmd(cmd, project=project)
            if stderr:
                raise Exception('Unknown error: %s' %stderr)
        except Exception as e:
            raise Exception('Got exception while updating alternatebackends %s'%e.message)
        finally:
            os.remove(template_file) 
    
    def set_label_to_host_in_openshift(self, node_ip, key, value, tenant='default'):
        cmd = 'oc label node %s %s=%s --overwrite=true' % (node_ip, key, value)
        stdout, stderr = self.run_oc_cmd(cmd, project=tenant)
        logger.info('stdout: %s \n stderr: %s' % (stdout, stderr))
        if stderr:
            raise Exception('Error: %s' % stderr)

        return stdout

    def get_openshift_daemon_set(self, expected_pod_count, tenant='default', **kwargs):
        retries = kwargs.get('retries', 5)
        for i in range(retries):
            cmd = "oc get pod | grep Running | grep avise"
            pod_config, stderr = self.run_oc_cmd(cmd, project=tenant)
            if stderr:
                logger.info("Unable to get expected pod list")

            pod_content_list = pod_config.split(' ')
            indices = [i for i, s in enumerate(pod_content_list) if 'avise' in s]
            pod_list = []
            for index in indices:
                pod_list.append(pod_content_list[index])
            if len(pod_list) != expected_pod_count:
                logger_utils.asleep(delay=30)
            else:
                return pod_list
        else:
            logger_utils.fail("Failed to get expected length pod list")

    def delete_openshift_pod(self, pod_name, tenant='default'):
        cmd = "oc delete pod %s" % pod_name
        stdout, stderr = self.run_oc_cmd(cmd, project=tenant)
        if stderr:
            logger.info("Unable to delete expected pod")

        return stdout


class OpenshiftAppRuntime(object):
    ''' Snapshot of a running openshift app '''
    def __init__(self, instances, tasks_running, tasks_healthy, tasks):
        self.instances = instances
        self.tasks_running = tasks_running
        self.tasks_healthy = tasks_healthy
        self.tasks = tasks
