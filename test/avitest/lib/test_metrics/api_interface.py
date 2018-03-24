
############################################################################
 # 
 # AVI CONFIDENTIAL
 # __________________
 # 
 # [2013] - [2017] Avi Networks Incorporated
 # All Rights Reserved.
 # 
 # NOTICE: All information contained herein is, and remains the property
 # of Avi Networks Incorporated and its suppliers, if any. The intellectual
 # and technical concepts contained herein are proprietary to Avi Networks
 # Incorporated, and its suppliers and are covered by U.S. and Foreign
 # Patents, patents in process, and are protected by trade secret or
 # copyright law, and other laws. Dissemination of this information or
 # reproduction of this material is strictly forbidden unless prior written
 # permission is obtained from Avi Networks Incorporated.
 ###

'''
Created on Jun 10, 2015
@author: Gaurav Rastogi
'''

from collections import namedtuple

import avi
from avi.sdk.avi_api import ApiSession
from avi.sdk.utils.api_utils import ApiUtils
import json

class APINotImplemented(Exception):
    pass

class ObjectNotFound(Exception):
    pass

class ApiError(Exception):
    pass

AviApiResp = namedtuple('AviApiResp', ['status', 'results_dict'])


class AviAPIInterface(object):
    '''
    Interface class that will be used by the HealthScore to make API calls.
    '''
    def get(self, uri, params=None, headers=None):
        raise APINotImplemented()

    def post(self, uri, params=None, headers=None, data=None):
        raise APINotImplemented()

    def put(self, uri, params=None, headers=None, data=None):
        raise APINotImplemented()

    def delete(self, uri, params=None, headers=None):
        raise APINotImplemented()


class AviSDKApi(AviAPIInterface):
    sess = None
    server_crt = None
    server_key = None
    ca_key = None
    ca_cert = None
    tenant = 'admin'

    def __init__(self, controller_ip, user='admin', passwd='avi123',
                 tenant='admin'):
        sdk_path = avi.sdk.__path__[0]
        with open(sdk_path + '/samples/certs/server.crt') as f:
            self.server_crt = f.read()
        with open(sdk_path + '/samples/certs/server.key') as f:
            self.server_key = f.read()
        with open(sdk_path + '/samples/certs/cakey.pem') as f:
            self.ca_key = f.read()
        with open(sdk_path + '/samples/certs/cacert.pem') as f:
            self.ca_cert = f.read()
        self.sess = ApiSession.get_session(controller_ip, user, passwd, tenant=tenant)
        try:
            ApiUtils(self.sess).import_ssl_certificate(
                'MyCert', self.server_key, self.server_crt)
        except:
            pass

        self.tenant = tenant

    def get(self, uri, params=None, headers=None):
        params = {} if not params else params
        headers = {} if not headers else headers
        if not headers and self.tenant != 'admin':
            headers = {'AVI-X-TENANT': self.tenant}
        rsp = self.sess.get(uri, params=params, headers=headers)
        if rsp.status_code == 404:
            raise ObjectNotFound
        elif rsp.status_code > 299:
            raise ApiError
        rsp = AviApiResp(status=rsp.status_code, 
                         results_dict=json.loads(rsp.text))
        return rsp

    def post(self, uri, params=None, headers=None, data=None):
        params = {} if not params else params
        headers = {} if not headers else headers
        data = {} if not data else data
        rsp = self.sess.post(uri, params=params, headers=headers,
                                  data=data)
        if rsp.status_code == 404:
            raise ObjectNotFound
        elif rsp.status_code > 299:
            raise ApiError
        rsp = AviApiResp(status=rsp.status_code,
                         results_dict=json.loads(rsp.text))
        return rsp

    def put(self, uri, params=None, headers=None, data=None):
        params = {} if not params else params
        headers = {} if not headers else headers
        data = {} if not data else data
        rsp = self.sess.put(uri, params=params, headers=headers,
                                  data=data)
        if rsp.status_code == 404:
            raise ObjectNotFound
        elif rsp.status_code > 299:
            raise ApiError
        rsp = AviApiResp(status=rsp.status_code,
                         results_dict=json.loads(rsp.text))
        return rsp

    def delete(self, uri, params=None, headers=None):
        params = {} if not params else params
        headers = {} if not headers else headers
        rsp = self.sess.delete(uri, params=params, headers=headers)
        if rsp.status_code == 404:
            raise ObjectNotFound
        elif rsp.status_code > 299:
            raise ApiError
        rsp = AviApiResp(status=rsp.status_code,
                         results_dict=json.loads(rsp.text))
        return rsp
