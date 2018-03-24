from avi_objects.infra_imports import *

import json
import copy
from uuid import uuid4
import string
import avi_objects.infra_utils as infra_utils

def clear_backend_uploads():
    servers = infra_utils.get_vm_of_type('server')
    for server in servers:
        server.execute_command('rm -rf /usr/share/nginx/www/uploads/*')
   
def get_waf_policy(name):
    status_code, policy = get('wafpolicy', name=name)
    assert status_code == 200 
    return policy

def put_waf_policy(policy_name, policy, check_status_code=True):
    logger.debug('new-policy %s' %policy)
    return put('wafpolicy', name=policy_name, data=policy, check_status_code=check_status_code)

def add_waf_policy_to_vs(vs_name, waf_policy_name):
    waf_uuid = get_uuid_by_name('wafpolicy', waf_policy_name)
    if not waf_uuid:
        waf_policy_ref = '/api/wafpolicy/?name=' + waf_policy_name
    else:
        waf_policy_ref = '/api/wafpolicy/' + waf_uuid
    update('virtualservice', name=vs_name, waf_policy_ref=waf_policy_ref)


def add_waf_group(waf_policy, gidx, gname, gset='post_crs_groups', check_status_code=True):
    policy_node = ApiNode('wafpolicy', name=waf_policy)
    status_code, waf = policy_node.get()
    if gset not in waf:
        waf[gset] = []
        
    grp = {}
    grp['index'] = gidx
    grp['name'] = gname
    grp['enable'] = True
    grp['rules'] = []
    logger.debug('waf-grp %s' %grp)
    waf[gset].extend([grp])
    logger.debug('new-waf %s' %waf)
    return policy_node.put(data=json.dumps(waf), check_status_code=check_status_code)

def delete_waf_group(waf_policy, gidx, gset='post_crs_groups'):
    policy_node = ApiNode('wafpolicy', name=waf_policy)
    status_code, waf = policy_node.get()
    i = 0
    for g in waf[gset]:
        if g['index'] == gidx:
            break
        i = i + 1
    grp = waf[gset][i]
    logger.debug('waf-grp %s' %grp)
    del waf[gset][i]
    logger.debug('new-waf %s' %waf)
    return policy_node.put(data=json.dumps(waf))


def add_waf_rule(waf_policy, rule, gidx, ridx, gset='post_crs_groups', check_status_code=True):
    """
    add rule to the group index gidx in waf_policy
    """
    policy_node = ApiNode('wafpolicy', name=waf_policy)
    status_code, waf = policy_node.get()
    i = 0
    for g in waf[gset]:
        if g['index'] == gidx:
            break
        i = i + 1

    grp = waf[gset][i]
    logger.debug('waf-grp %s' %grp)
    r1 =  {}
    r1['index'] = ridx
    r1['enable'] = True
    r1['rule'] = rule.decode('utf-8')
    if 'rules' not in grp:
        grp['rules'] = []
    grp['rules'].extend([r1])

    logger.debug('new-waf %s' %waf)
    return policy_node.put(data=json.dumps(waf), check_status_code=check_status_code)

def update_waf_rules(waf_policy, rule, gset='post_crs_groups', check_status_code=True):
    policy_node = ApiNode('wafpolicy', name=waf_policy)
    status_code, waf = policy_node.get()
    grp = waf[gset][0]
    logger.debug('waf-grp %s' %grp)
    r1 =  grp['rules'][0]
    r1['rule'] = rule.decode('utf-8')
    grp['rules'] = []
    grp['rules'].extend([r1])

    logger.debug('new-waf %s' %waf)
    return policy_node.put(data=json.dumps(waf), check_status_code=check_status_code)

def delete_waf_rule(waf_policy, gidx, ridx, gset='post_crs_groups'):
    policy_node = ApiNode('wafpolicy', name=waf_policy)
    status_code, waf = policy_node.get()
    i = 0
    for g in waf[gset]:
        if g['index'] == gidx:
            break
        i = i + 1
    grp = waf[gset][i]
    logger.debug('waf-grp %s' %grp)
    i = 0
    for r in grp['rules']:
        if r['index'] == ridx:
            break
        i = i + 1
        
    if i == len(grp['rules']):
        return

    del grp['rules'][i]
    logger.debug('new-waf %s' %waf)
    return policy_node.put(data=json.dumps(waf))


def update_waf_profile(waf_profile, **kwargs):
    body_sz = kwargs.get('body_sz')
    request_hdr_default = kwargs.get('request_hdr_default')
    profile_node = ApiNode('wafprofile', name=waf_profile)
    status_code, profile = profile_node.get()
    if body_sz:
        profile['config']['client_nonfile_upload_max_body_size'] = int(body_sz)
    if request_hdr_default:
        profile['config']['request_hdr_default_action'] = request_hdr_default

    logger.debug('new-profile %s' %profile)
    return profile_node.put(data=json.dumps(profile))

def update_waf_profile_no_status_check(waf_profile, **kwargs):
    request_hdr_default = kwargs.get('request_hdr_default')
    profile_node = ApiNode('wafprofile', name=waf_profile)
    status_code, profile = profile_node.get()
    if request_hdr_default:
        profile['config']['request_hdr_default_action'] = request_hdr_default

    logger.debug('new-profile %s' %profile)
    return profile_node.put_no_status_check(data=json.dumps(profile))

def update_waf_policy(waf_policy, gset='post_crs_groups', **kwargs):
    policy_node = ApiNode('wafpolicy', name=waf_policy)
    status_code, policy = policy_node.get()
    enforcement = kwargs.get('enforcement')
    if enforcement:
        if enforcement is 'yes':
            policy['mode'] = "WAF_MODE_ENFORCEMENT"
        else:
            policy['mode'] = "WAF_MODE_DETECTION_ONLY"

    #group name
    gname = kwargs.get('group_name')
    if gname:
        gidx = kwargs.get('group_idx')
        grp = policy[gset][int(gidx)]
        print 'group is'
        print grp
        grp['name'] = gname

    #rule name
    rname = kwargs.get('rule_name')
    if rname:
        gidx = kwargs.get('group_idx')
        ridx = kwargs.get('rule_idx')
        grp = policy[gset][int(gidx)]
        r = grp['rules'][int(ridx)]
        r['name'] = rname

    #group disable
    genable = kwargs.get('group_enable')
    if genable and genable is 'no':
        gidx = kwargs.get('group_idx')
        grp = policy[gset][int(gidx)]
        print 'group is'
        print grp
        grp['enable'] = False
   
    #group enable
    genable = kwargs.get('group_enable')
    if genable and genable is 'yes':
        gidx = kwargs.get('group_idx')
        grp = policy[gset][int(gidx)]
        grp['enable'] = True
        
    #rule_disable
    renable = kwargs.get('rule_enable')
    if renable and renable is 'no':
        gidx = kwargs.get('group_idx')
        ridx = kwargs.get('rule_idx')
        grp = policy[gset][int(gidx)]
        r = grp['rules'][int(ridx)]
        r['enable'] = False

    #rule_enable
    genable = kwargs.get('rule_enable')
    if renable and renable is 'yes':
        gidx = kwargs.get('group_idx')
        ridx = kwargs.get('rule_idx')
        grp = policy[gset][int(gidx)]
        r = grp['rules'][int(ridx)]
        r['enable'] = True

    logger.debug('new-policy %s' %policy)
    return policy_node.put(data=json.dumps(policy))

                
def add_waf_exclude(waf_policy, gidx=0, ridx=None, gset='post_crs_groups', **kwargs):
    """ add waf exclude for rule or group """
    _, waf = get('wafpolicy', name=waf_policy)
    grp = waf[gset][gidx]
    exclude = {}
    u =  kwargs.get('uri')
    if u:
        exclude['uri_path'] = u
    e = kwargs.get('match_element')
    if e:
        exclude['match_element'] = e
    if ridx != None:
        r = grp['rules'][ridx]
        if 'exclude_list' not in r:
            r['exclude_list'] = []
        r['exclude_list'].extend([exclude])
    else:
        if 'exclude_list' not in grp:
            grp['exclude_list'] = []
        grp['exclude_list'].extend([exclude])

    logger.debug('new-waf %s' %waf)
    return put('wafpolicy', name=waf_policy, data=json.dumps(waf))


def del_waf_exclude(waf_policy, gidx=0, ridx=None, eidx=0, gset='post_crs_groups', **kwargs):
    """ del waf exclude for rule or group """
    _, waf = get('wafpolicy', name=waf_policy)
    grp = waf[gset][gidx]
    if ridx != None:
        r = grp['rules'][ridx]
        del r['exclude_list'][eidx]
    else:
        del grp['exclude_list'][eidx]

    logger.debug('new-waf %s' %waf)
    return put('wafpolicy', name=waf_policy, data=json.dumps(waf))


class WafObjectBase(object):
    """An abstract API object class.

    Should not initialized directly
    """
    # if this class provides a default object, state it's name here.
    DEFAULT_NAME = None

    @classmethod
    def default(cls):
        assert cls.DEFAULT_NAME is not None
        res = cls(name=cls.DEFAULT_NAME)
        res.__read_only = True
        return res

    @classmethod
    def make_uuid(cls):
        return "{0}-{1}".format(cls.NAMESPACE, uuid4())

    def __init__(self, uuid=None, name=None, ref=None):
        """create an object from uuid, name or ref

        At least on of the 3 must be set. If you set more than one,
        the behaviour is undefined.
        """
        assert uuid or name or ref
        self.__read_only = False
        if ref is not None:
            uuid = ref.split("/")[-1]
        self.name = name
        if self.name:
            uuid = get_uuid_by_name(self.NAMESPACE, self.name)
            assert uuid is not None
        self.uuid = uuid
        if self.uuid:
            # make sure the object really exist and get the name from it
            obj_name = self.get_element("name")
            assert obj_name is not None
            assert name is None or name == obj_name, "name conflict, specified was {0} but the object have {1}".format(name, obj_name)
            self.name == obj_name

    @property
    def ref(self):
        """return a ref for this object which can be used in other objects"""
        return "/api/{0}/{1}".format(self.NAMESPACE, self.uuid)

    @property
    def url(self):
        return "{0}/{1}".format(self.NAMESPACE, self.uuid)

    def clone(self, name=None):
        """make acopy of this object with a new name.

        if no name is give, choose one by random. If the name is give, it should not exist.
        """
        # make copy of ourself
        data = self.get()
        if name is None:
            name = self.make_uuid()
        data.update(name=name)
        status, data = post("{0}/".format(self.NAMESPACE), data=json.dumps(data))
        assert status == 201
        uuid = data["uuid"]
        return self.__class__(uuid=uuid, name=name)

    # REST methods

    def get(self):
        path = "{0}/{1}".format(self.NAMESPACE, self.uuid)
        print "get(" + path + ")"
        status, data = get(path)
        assert status == 200
        return data

    def update(self, **kwargs):
        status_code, data = get(self.url)
        data.update(kwargs)
        put(self.url, data=json.dumps(data))

    def delete(self):
        """delete this instance from the API"""
        status, data = delete(self.url)
        assert status == 200

    def get_element(self, name, default=None):
        data = self.get()
        return data.get(name, default)

    def __getattr__(self, name):
        """try to be smart about attributes"""
        res = self.get_element(name)
        assert res is not None
        return res


class WafProfile(WafObjectBase):
    DEFAULT_NAME = "System-WAF-Profile"
    NAMESPACE = "wafprofile"


class WafPolicy(WafObjectBase):
    DEFAULT_NAME = "System-WAF-Policy"
    NAMESPACE = "wafpolicy"

    @property
    def profile(self):
        """get the profile object for a policy"""
        return WafProfile(ref=self.waf_profile_ref)

    def enable_crs_group(self, name, enable=True):
        crs_groups = self.get()["crs_groups"]
        found = False
        for group in crs_groups:
            if group["name"] == name:
                group["enable"] = enable
                found = True
        assert found == True, "This group does not exist"
        self.update(crs_groups=crs_groups)


