import os
from avi_objects import logger_utils
class SIP():
    def __init__(self, local_host, local_port, remote_host, remote_port, username, auth_password, **kwargs):
        self.scen = None
        self.local_host = local_host
        self.local_port = local_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.username = username
        self.auth_password = auth_password
        self.transport = kwargs.get("transport", "u1")

    def execute_scenario(self, scen_dir, client):
        client_scen_dir = scp_xml_on_client(scen_dir, client)
        cmd = 'python /root/client/tools/sip/sip_traffic.py'
        cmd = '%s --local_host %s' % (cmd, self.local_host)
        cmd = '%s --local_port %s' % (cmd, self.local_port)
        cmd = '%s --remote_host %s' % (cmd, self.remote_host)
        cmd = '%s --remote_port %s' % (cmd, self.remote_port)
        cmd = '%s --username %s' % (cmd, self.username)
        cmd = '%s --auth_password %s' % (cmd, self.auth_password)
        cmd = '%s --transport %s' % (cmd, self.transport)
        cmd = "%s --scen_dir %s" % (cmd, client_scen_dir)
        try:
            client.execute_command(cmd, sudoless = True)
            return True
        except Exception:
            return False

def scp_xml_on_client(scen_dir, client_vm):
    dir_path = scen_dir.rstrip(os.sep)
    dir_name = os.path.basename(dir_path)
    client_path = "/root/client/tools/sip/xml/%s" % dir_name
    try:
        client_vm.execute_command("mkdir %s" % client_path)
    except:
        client_vm.execute_command("rm -r %s" % client_path)
        client_vm.execute_command("mkdir %s" % client_path)
        pass

    for item in os.listdir(scen_dir):
        client_vm.scp_file(os.path.join(scen_dir, item),\
                '%s/%s' % (client_path, item))

    return client_path

