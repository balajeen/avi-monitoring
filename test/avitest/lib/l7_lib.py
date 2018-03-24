import pytest
import time

from avi_objects.infra_imports import *
from . import system_lib
from . import vs_lib
from . import waf_lib

from ftw.http import HttpUA as HttpClient
from ftw.ruleset import Input as HttpInput

def setup_for_l7_tests():
    print('setup_for_l7_tests')
    for vm in get_vm_of_type('server'):
        vm.execute_command('stop wpr', log_error=False)
        # If we start its automatically running on 6666 Port,
        # so better to not to start again
        # vm.execute_command('start wpr')
        vm.cleanup_uploads()
        # Not doing anything commented
        # vm.setup_webreplay()
        # vm.setup_php_apps()
        # vm.setup_node_apps()

    '''
    for vm in get_vm_of_type('client'):
        vm.cleanup_downloads()
    '''


def get_vserver_stats(vs_name, api):
    resp_code, resp_data = get('virtualservice', name=vs_name, path=api)
    if not resp_data:
        raise RuntimeError("ERROR! %s data NULL " % api)
    return resp_data[0]


def l7virtualservicestats(vs_name):
    return get_vserver_stats(vs_name, 'httpstats')


def verify_applog(rule_id, response_code=None, server_response_code=None,
                  significance_code=None, vs='virtualservice-1',
                  waf_match_in_significance=True, check_significant_log=False,
                  exp_significant_reason=None, not_exp_significant_reason=None,
                  check_log_status=False, waf_mode_enforcement=False, 
                  request_id=None, is_disruptive_rule=True):
        """ Verifications for Applog and the WAF Log within it
        """
        # FIXME: we should not sleep here but poll for the correct log
        # line. But this needs a way to check via request id what the
        # correct log line is.
        vs = VirtualService(vs)
        if request_id is not None:
            data = vs.get_application_log(request_id=request_id, timeout=90)
        else:
            # legacy test code
            data = vs.get_application_log(request_id=request_id, timeout=10)
        logger.debug('VS App Log Data')
        logger.debug(data)

        if check_significant_log:
            if exp_significant_reason:
                assert exp_significant_reason in data['significant_log']
            if not_exp_significant_reason:
                assert not_exp_significant_reason not in data['significant_log']

        if significance_code is not None:
            assert ("Request ended abnormally: response code %s" %significance_code) in data['significance']
            if waf_match_in_significance:
                assert "WAF matched the transaction" in data['significance']

        if check_log_status:
            if waf_mode_enforcement:
                if rule_id:
                    if is_disruptive_rule:
                        assert data['waf_log']['status'] == 'REJECTED'
                    else:
                        assert data['waf_log']['status'] == 'PASSED'
                else:   
                    assert data['waf_log']['status'] == 'PASSED'
            else:
                if rule_id:
                    assert data['waf_log']['status'] == 'FLAGGED'
                else:
                    assert data['waf_log']['status'] == 'PASSED'


        if rule_id:
            try:
                assert data['waf_log']['rule_logs'][0]['rule_id'] == rule_id
            except KeyError as e:
                error('KeyError with waf_log as %s not found' %e)
        if response_code:
            assert data['response_code'] == response_code
        if server_response_code:
            assert data['server_response_code'] == server_response_code


def verify_applog_simple(vs, request_id, status, ruleid=None, gname=None, rname=None):
    vs = VirtualService(vs)
    data = vs.get_application_log(request_id=request_id, timeout=90, nf='True')
    assert data['waf_log']['status'] == status
    if ruleid:
        assert data['waf_log']['rule_logs'][0]['rule_id'] == ruleid
    if gname:
        assert data['waf_log']['rule_logs'][0]['rule_group'] == gname
    if rname:
        assert data['waf_log']['rule_logs'][0]['rule_name'] == rname

class DictWrapper(dict):
    """A wrapper around a dict which allow access via attributes.

      e.g. foo.bar insteaf of foo.get("bar")
    """
    def __init__(self, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)

    def __getattr__(self, name):
        return self.get(name)


class Stats(object):
    """Abstraction about the L7 stats for a VS which keeps state and
    return the data in an easy digestible format"""

    def __init__(self, vs_name):
        self.vs_name = vs_name
        self.reset()

    def reset(self):
        """reset the stats, changes are counted from here"""
        self._stats = self.stats()

    @aretry(retry=5, period=1, exceptions=(KeyError, RuntimeError))
    def stats(self):
        """raw stats for the VS"""
        return get_vserver_stats(self.vs_name, 'httpstats')

    def changes(self):
        """return an object which includes the changes for all the stats"""
        res = DictWrapper()
        stats = self.stats()
        for k, v in stats.items():
            res[k] = v - self._stats.get(k, 0)
        return res


class VirtualService(object):
    """Abstraction around a VS object"""

    def __init__(self, name):
        self.vs_name = name
        self.stats = Stats(name)
        resp_code, resp_data = get("virtualservice", name=name)
        if resp_code != 200:
            raise RuntimeError('ERROR! get /virtualservice/?name=%s failed' % name)
        if not resp_data:
            raise RuntimeError("ERROR! /virtualservice/?name=%s data NULL " % name)
        # FIXME: Assumes regular VS (non-SNI)
        # Make this more generic to support multiple VIPs, ports, SSL etc
        self.addr = resp_data['vip'][0]['ip_address']['addr']
        self.port = resp_data['services'][0]['port']

    def disable(self):
        logger.info('Disable VS {0}'.format(self.vs_name))
        vs_lib.disable_vs(self.vs_name)

    def enable(self):
        """enable a VS and wait until it is up"""
        logger.info('Enable VS {0}'.format(self.vs_name))
        vs_lib.enable_vs(self.vs_name)
        vs_lib.vs_should_be_in_status(self.vs_name, "OPER_UP", retry_timeout=30)
        # enable/disable a vs may reset the stats
        self.stats.reset()

    def force_config_push(self):
        self.disable()
        self.enable()

    def set_waf_policy(self, waf_policy_name):
        logger.info("Add WAF policy '{0}' to virtual service '{1}'".format(waf_policy_name, self.vs_name))
        waf_lib.add_waf_policy_to_vs(self.vs_name, waf_policy_name)

    def get_application_log(self, request_id=None, timeout=5, udf='False', nf='False'):
        """get the last log entry for the vs

        If request_id is provide, poll until the log entry contains the
        request id in the header or timeout is reached.

        If reqeust_id is not provided, sleep for timeout and then return the last log line.
        'False' and 'True' are defined as strings instead of boolean for the system_lib
        api to work
        """

        if request_id is not None:
            poll_until = time.time() + timeout
            while time.time() < poll_until:
                data = system_lib.get_application_log(self.vs_name, udf, nf)
                if data and len(data["results"]) > 0:
                    for data in data["results"]:
                        # check if this request contains the request_id, either in the 
                        # query args or all_request_header
                        if request_id in data.get("uri_query", ""):
                            return data
                        if request_id in data.get("all_request_headers", ""):
                            return data
                asleep("Wait a second before the next poll.", delay=1)
            return None # timeout reached
        # Old use case, this should be removed when all the client code is fixed
        time.sleep(timeout)
        data = system_lib.get_application_log(self.vs_name, udf, nf, page_size=1)
        return data['results'][0]


@pytest.fixture
def system_policy():
    """returns a writeable copy of the CRS ruleset.

    To avoid creating too much of them, we are naming it crs and reusing it.
    """
    crs = waf_lib.WafPolicy(name="crs")
    system_policy = waf_lib.WafPolicy.default()
    policy_data = system_policy.get()
    # remove unneeded entries
    for name in "uuid", "name", "_last_modified":
        policy_data.pop(name, None)
    crs.update(**policy_data)
    return crs

@pytest.fixture
def crs_test_profile():
    """return a writeable copy of the default CRS profile
    but change the actions in the profile to allow better test cases.

    Set the default actions for phase N -> 420 + (N-1)
    To avoid creating too much of them, we are naming it crs and reusing it.
    """
    crs_profile = waf_lib.WafProfile(name="crs")
    system_profile = waf_lib.WafProfile.default()
    profile_data = system_profile.get()
    # remove unneeded entries
    for name in "uuid", "name", "_last_modified":
        profile_data.pop(name, None)
    profile_data["config"].update(
        request_hdr_default_action= "phase:1,deny,status:420,log,auditlog", 
        request_body_default_action= "phase:2,deny,status:421,log,auditlog", 
        response_hdr_default_action= "phase:3,deny,status:422,log,auditlog", 
        response_body_default_action= "phase:4,deny,status:423,log,auditlog", 
        static_extensions=[".txt"],
        )
    crs_profile.update(**profile_data)
    return crs_profile

@pytest.fixture
def crs():
    """returns a writeable copy of the CRS ruleset but change the
    profile to the test_profile above
    """
    crs = system_policy()
    crs.update(
            mode="WAF_MODE_ENFORCEMENT",
            paranoia_level="WAF_PARANOIA_LEVEL_LOW",
            waf_profile_ref=crs_test_profile().ref,
    )
    return crs


@pytest.fixture
def vs():
    """return an abstraction of the virtualservice-1"""
    return VirtualService("virtualservice-1")



