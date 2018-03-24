import json
import lib.common as common
import avi_objects.rest as rest
from avi_objects.logger import logger
import avi_objects.logger_utils as logger_utils

def update_app_profile(ap_name, **kwargs):
    '''

    :param ap_name:
    :param kwargs:
    :return:
    '''
    status_code, json_applicationprofile_data = rest.get('applicationprofile',
                                                name=ap_name)
    type = kwargs.get('type', None)

    try:
        if type:
            logger.info('update application profile: %s with type: %s' % (
                ap_name, type))
            if type == 'APPLICATION_PROFILE_TYPE_L4':
                del json_applicationprofile_data['http_profile']
            if type == 'APPLICATION_PROFILE_TYPE_HTTP':
                json_applicationprofile_data['http_profile'][
                        'connection_multiplexing_enabled'] = True
            json_applicationprofile_data['type'] = type

        if kwargs.get('http_profile__connection_multiplexing_enabled'):
            json_applicationprofile_data['http_profile'][
                'connection_multiplexing_enabled'] = kwargs.get(
                'http_profile__connection_multiplexing_enabled')

        if kwargs.get('http_profile__enable_xff'):
            json_applicationprofile_data['http_profile'][
                'enable_xff'] = kwargs.get('http_profile__enable_xff')

        if kwargs.get('http_profile__xff_header_name'):
            json_applicationprofile_data['http_profile'][
                'xff_header_name'] = kwargs.get('http_profile__xff_header_name')

    except KeyError as e:
        logger.info('Raised KeyError:  %s' % str(e))
    else:
        rest.put('applicationprofile', name=ap_name, data=json_applicationprofile_data)
