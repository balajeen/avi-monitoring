import os
from lib.cluster_lib import wait_until_cluster_ready
from lib.webapp_lib import upload_file
from avi_objects.logger import logger

def restore_config(path=None, master_vm=None, passphrase=None, follower_nodes=None, sudo_timeout=60, flushdb=False):
    """
    restore_config.py script execution on the controller itself
    @param passphrase: export type passphrase or not
    @param master_vm: Cluster master vm
    @param path: Config path/string
    @return:Boolean flag
    """
    if path is None:
        raise RuntimeError("File path not provided.")
    if master_vm is None:
        raise RuntimeError("Master vm object not provided.")
    try:
        file_name = os.path.basename(path)
        upload_file(master_vm, path, 'controller://uploads')
        if passphrase is None:
            cmd = "python /opt/avi/scripts/restore_config.py --config /var/lib/avi/uploads/%s" % file_name
        else:
            cmd = "python /opt/avi/scripts/restore_config.py --config /var/lib/avi/uploads/%s --passphrase %s" % (file_name, passphrase)
        if flushdb:
            cmd = "%s --flushdb" % cmd       
            sudo_timeout=120
        if follower_nodes:
            cmd = "%s --followers %s" % (cmd,follower_nodes)
        out = master_vm.execute_command(cmd, sudo_timeout=sudo_timeout)
        logger.info(out)
    except Exception as e:
        return False

