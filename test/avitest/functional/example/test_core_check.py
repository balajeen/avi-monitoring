import pytest
from avi_objects.infra_utils import get_vm_of_type

def test_core_check():
    cntrl_list = get_vm_of_type("controller")
    se_list = get_vm_of_type('se')
    for vm in cntrl_list+se_list:
        vm.execute_command('sudo touch /var/lib/vi/archive/test_core.tar.gz')

