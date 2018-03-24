from avi_objects.infra_utils import get_server_by_handle


def iptables_drop_from_source(server_handle, source_ip):
    """

    :param server_handle:
    :param source_ip:
    :return:
    """
    server = get_server_by_handle(server_handle)
    server_vm = server.vm()
    server_vm.execute_command('iptables -A INPUT -s %s -j DROP' % source_ip)


def iptables_allow_from_source(server_handle, source_ip):
    """

    :param server_handle:
    :param source_ip:
    :return:
    """
    server = get_server_by_handle(server_handle)
    server_vm = server.vm()
    server_vm.execute_command('iptables -D INPUT -s %s -j DROP' % source_ip)


