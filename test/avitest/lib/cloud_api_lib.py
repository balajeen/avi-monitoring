import avi_objects.infra_utils as infra_utils
import avi_objects.rest as rest
from lib.cluster_lib import get_cluster_master_vm


def set_cloud_vip_static_routes(cloud_name='Default-Cloud'):
    """

    :param cloud_name:
    :return:
    """
    leader_vm = get_cluster_master_vm()
    session = rest.create_session(controller=leader_vm)
    infra_utils.switch_mode(session=session)
    rest.update('cloud', name=cloud_name, enable_vip_static_routes=True)


def set_cloud_prefer_static_routes(cloud_name='Default-Cloud'):
    """

    :param cloud_name:
    :return:
    """
    leader_vm = get_cluster_master_vm()
    session = rest.create_session(controller=leader_vm)
    infra_utils.switch_mode(session=session)
    rest.update('cloud', name=cloud_name, prefer_static_routes=True)
