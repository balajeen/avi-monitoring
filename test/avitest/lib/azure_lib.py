from avi_objects import infra_utils
from avi_objects.cloud_manager import Azure
import avi_objects.rest as rest
import json
from avi_objects.logger_utils import asleep, fail

def azure_server_scale(min_size, max_size, kwargs):
    """
    :param min_size: Min number of servers in serverautoscale policy
    :param max_size: Max number of servers in serverautoscale policy
    Args:
        policy_name: Name of the serverautoscale policy
        max_scalein_adjustment_setup: Max number of instances that can be scalein together
        max_scaleout_adjustment_step: Max number of instances that can be scaleout together
        scalein_cooldown: Cooldown time between two scalein operations
        scaleout_cooldown: Cooldown time between two scaleout operations
    """
    if kwargs['policy_name']:
        kwargs['min_size'] = min_size
        kwargs['max_size'] = max_size
        kwargs['name'] = kwargs['policy_name']
        kwargs['min_size'] = min_size
        kwargs['max_size'] = max_size
        status, result = rest.put('serverautoscalepolicy', name=kwargs['policy_name'], data=json.dumps(kwargs))
    else:
        fail('server autoscale policy name is not defined')

def wait_for_scale_set_success(ss_name):
    """
    :param ss_name: Azure scale set name
    """
    asleep('Dummy waiting since scale set autoscaling does not take effect instantly', delay=10)
    cloud_type, configuration = rest.get_cloud_type(get_configuration = True)
    azure = Azure(configuration, 'Default-Cloud')
    azure.check_scale_set_status(ss_name)
