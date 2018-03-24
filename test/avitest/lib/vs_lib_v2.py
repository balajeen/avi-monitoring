import re
import json
import time
import traceback
from datetime import datetime, timedelta
import avi_objects.rest as rest
from avi_objects.infra_utils import *
from avi_objects.logger import logger
from avi_objects.logger_utils import error, fail
from avi_objects.rest import get_uuid_by_name
from lib.se_lib import get_se_name_from_uuid, reboot_se, get_all_se_uuid, \
    get_se_info, se_stop_by_uuid, se_start_by_uuid, map_se_uuid_to_name, se_disconnect_vm, \
    wait_for_se_to_disconnect, get_se_runtime_summary, se_reconnect_vm, wait_for_se_to_connect
from logs_lib import get_event_id_based_log_v2, get_event_id_based_log_should_increase_v2
from lib.vs_lib import keys_should_rotate, keys_should_not_rotate
from avi_objects.infra_utils import get_se_vm
# global variable to keep objects of all vs


class VsWellnessCheck(object):

    def __init__(self, vs_name, timeout):
        self.vs_name = vs_name
        #TODO:AV-31536:right now hardcoded the time_left but should be set to 600 if cloud_access type is write
        self.timeleft = int(timeout)+360
        self.expected_state = {}
        self.vs_uuid = None
        self.vs = get_vs_api(self.vs_name)
        self.vs_uuid = self.vs['uuid']
        self.se_list = None
        self.vs_placement = None
        self.vs_internal = None
        self.vs_detail = None
        self.disconnected_se_list = list()
        self.down_se_list = list()
        self.skip_ew_vs_check = False
        self.east_west = True if 'east_west_placement' in self.vs.keys() and self.vs['east_west_placement'] else False
        self.vs_summary = get_vs_api(self.vs_name, '/runtime')
        self.transient_oper_status_list = ['OPER_CREATING',
                                           'OPER_PROCESSING',
                                           'OPER_RESOURCES',
                                           'OPER_SE_PROCESSING',
                                           'OPER_PARTITIONED']
        self.MAX_SUMMARY_DETAIL_MISMATCH_ATTEMPTS = 5

    def __parse_expected_state(self, expected_state):
        for index, data in enumerate(expected_state):
            split_str = data.split('-')
            vip_id = split_str[0]
            e_req = int(split_str[1])
            e_assign = int(split_str[2])
            e_operstate = str(split_str[3])

            if 'east_west_placement' in self.vs.keys() and self.vs['east_west_placement']:
                api = "serviceengine?cloud_ref__uuid=%s" % rest.get_uuid_from_ref(self.vs['cloud_ref'])
                status_code, json_data = rest.get(api)
                e_req = e_assign = json_data['count']
                if not self.vs['enabled']:
                    e_assign = 0
                else:
                    se_down = len([se_data['name'] for se_data in json_data['results'] if
                                   se_data['oper_status']['state'] == 'OPER_DOWN'])
                    e_req = e_assign = e_req - se_down
                logger.info("east_west vs, auto-fixing e_req=e_assign=%d" % e_req)

            self.expected_state[vip_id] = {'e_req': e_req, 'e_assign': e_assign, 'e_operstate': e_operstate}

    def __get_vs_runtime_internal(self):
        runtime_internal = get_vs_api(self.vs_name, '/runtime/internal')
        return next(data for data in runtime_internal if
                    "virtualservice_runtime" in data.keys())

    def __set_disconnected_down_se_list(self):
        _, json_data = rest.get('serviceengine')
        for data in json_data['results']:
            resp_code, se_data = rest.get('serviceengine', name=data['name'],
                                          path='/runtime')
            if se_data['oper_status']['state'] == 'OPER_DOWN':
                self.down_se_list.append(data['uuid'])
            elif not se_data.has_key('se_connected'):
                self.disconnected_se_list.append(data['uuid'])
        if (self.down_se_list or self.disconnected_se_list) and self.east_west:
            self.skip_ew_vs_check = True

    def get_vs_event_history(self, vip_id):
        event_history = list()
        if not self.vs_internal:
            self.vs_internal = self.__get_vs_runtime_internal()
        for vip_runtime in self.vs_internal['virtualservice_runtime']['vip_runtime']:
            if vip_runtime['vip_id'] == vip_id:
                event_history = vip_runtime['ev']
        #return self.vs_internal['virtualservice_runtime']['vip_runtime'][vip_id]['ev']
        return event_history

    def __wait_until_vs_is_in_expected_state(self):
        #FIXME: e_agg_state  = same as vip state for one vip, otherwise oper_down or oper_up
        e_agg_state, rstr = 'OPER_DOWN', None
        state_check_end_time = datetime.now() + timedelta(seconds=self.timeleft)

        if 'vip_summary' not in self.vs_summary:
            fail("vs[%s] vip_summary missing in vs_summary" % self.vs_name)
        for vip_id, e_vip_state in self.expected_state.iteritems():
            attempt = 0
            while True:
                summary_vips_state = self.get_vips_state()
                if summary_vips_state[vip_id]['oper_state'] != e_vip_state['e_operstate']:
                    rstr = "vs[%s:%s] summary_oper_state(%s) != expected_oper_state(%s)" % \
                           (self.vs_name, vip_id, summary_vips_state[vip_id]['oper_state'], e_vip_state['e_operstate'])
                    logger.debug(rstr)
                    #if c_oper_state not in self.transient_oper_status_list:
                    #    logger.trace("summary_oper_state not transient, not expected")
                    #    if c_oper_state != self.vs_detail[0]['vip_detail'][vip_id]['oper_status']['state']:
                    #        rstr = "[%s:%d] summary_oper_state(%s) != detail_oper_state(%s)" % \
                    #               (self.vs_name, vip_id, c_oper_state,
                    #                self.vs_detail[0]['vip_detail'][vip_id]['oper_status']['state'])
                    #        logger.trace("%s" % rstr)
                    #        attempt += 1
                    #        logger.trace("%s: attempt %d" % (rstr, attempt))
                    #        if attempt == self.MAX_SUMMARY_DETAIL_MISMATCH_ATTEMPTS:
                    #            raise RuntimeError(rstr)
                    #else:
                    #if not isinstance(self.vs_detail, list):
                    #    logger.trace("vs_detail is not well formed, ignore, try again %s" % self.vs_detail)
                    #    continue
                    #if summary_vips_state[vip_id]['oper_state'] != detail_vips_state[vip_id]['oper_state']:
                    #    rstr = "[%s:%d] summary_oper_state(%s) != detail_oper_state(%s)" % \
                    #           (self.vs_name, vip_id, summary_vips_state[vip_id]['oper_state'],
                    #            detail_vips_state[vip_id]['oper_state'])
                    #    logger.trace(rstr)
                    #    attempt += 1
                else:
                    logger.info("vs[%s:%s] summary_oper_state(%s) matches expected_oper_state(%s)"
                                % (self.vs_name, vip_id, summary_vips_state[vip_id]['oper_state'],
                                   e_vip_state['e_operstate']))
                    if summary_vips_state[vip_id]['oper_state'] not in ['OPER_CREATING', 'OPER_PROCESSING',
                                                                        'OPER_SE_PROCESSING']:
                        self.vs_detail = get_vs_api(self.vs_name, '/runtime/detail')
                        detail_vips_state = self.get_detail_vips_state()
                        # check if summary oper state macthes detail oper state
                        if summary_vips_state[vip_id]['oper_state'] == detail_vips_state[vip_id]['oper_state']:
                            rstr = "vs[%s:%s] summary_oper_state matches detail_oper_state" % (self.vs_name, vip_id)
                            logger.info(rstr)
                            if self.skip_ew_vs_check:
                                logger.info('Skip num_se_requested and num_se_assigned check for ew VS. All SE not connected.')
                                break
                            # break loop if num req and assigned SE's matches for all vips
                            all_good, rstr = self.__check_num_se_requested_and_assigned()
                            if all_good:
                                break
                        else:
                            rstr = "vs[%s:%s] cache issue! summary_oper_state(%s) != detail_oper_state(%s)" % \
                                   (self.vs_name, vip_id, summary_vips_state[vip_id]['oper_state'],
                                    detail_vips_state[vip_id]['oper_state'])
                            logger.warning(rstr)
                            attempt += 1

                if summary_vips_state[vip_id]['oper_state'] == 'OPER_CREATING':
                    time.sleep(10)
                else:
                    time.sleep(1)
                logger.info("vs[%s:%s] %s: attempt %d" % (self.vs_name, vip_id, rstr, attempt))
                if attempt == self.MAX_SUMMARY_DETAIL_MISMATCH_ATTEMPTS:
                    fail(rstr)
                elif state_check_end_time <= datetime.now():    # check if retry time is over
                    logger.debug("vs[%s:%s] timeout: %s" % (self.vs_name, vip_id, rstr))
                    fail('vs[%s:%s] timeout: %s' % (self.vs_name, vip_id, rstr))

                self.timeleft = (state_check_end_time - datetime.now()).total_seconds()
                logger.debug("vs[%s:%s] %s is transient, retry timeleft=%d" %
                            (self.vs_name, vip_id, summary_vips_state[vip_id]['oper_state'], self.timeleft))
                self.vs_summary = get_vs_api(self.vs_name, '/runtime')

            logger.info("vs[%s:%s] oper_status looks good" % (self.vs_name, vip_id))
            if not self.vs['enabled']:
                e_agg_state = 'OPER_DISABLED'

            # e_agg_state is same as vip state for one vip or e_agg_state is UP if any vip is UP
            if len(self.vs_summary['vip_summary']) == 1 or summary_vips_state[vip_id]['oper_state'] == 'OPER_UP':
                e_agg_state = summary_vips_state[vip_id]['oper_state']

        if self.vs_summary['oper_status']['state'] != e_agg_state:
            rstr = "vs[%s] vs_agg_oper_state(%s) != e_agg_oper_state(%s)" % \
                   (self.vs_name, self.vs_summary['oper_status']['state'], e_agg_state)
            logger.info(rstr)
            fail(rstr)
        logger.debug("vs[%s] oper_status good" % self.vs_name)
        return True

    def get_vip_summary(self, vip_id='0', vs_summary=None):
        vip_data = None
        if not vs_summary:
            vs_summary = self.vs_summary
        for vip_summary in vs_summary['vip_summary']:
            if str(vip_id) == vip_summary["vip_id"]:
                vip_data = vip_summary
                break
        if not vip_data:
            fail("vs[%s:%s] vip summary not found for specified vip_id" % (
                self.vs_name, vip_id))
        return vip_data

    def get_vips_state(self):
        vip_dict = dict()
        for vip_summary in self.vs_summary['vip_summary']:
            vip_dict[vip_summary['vip_id']] = {'num_se_requested': vip_summary['num_se_requested'],
                                                    'num_se_assigned': vip_summary['num_se_assigned'],
                                                    'oper_state': vip_summary['oper_status']['state']}
            if "service_engine" in vip_summary:
                vip_dict[vip_summary['vip_id']]['service_engine'] = vip_summary['service_engine']
        return vip_dict

    def get_detail_vips_state(self):
        detail_vip_dict = dict()
        for vip_detail in self.vs_detail[0]['vip_detail']:
            detail_vip_dict[vip_detail['vip_id']] = {'num_se_requested': vip_detail['num_se_requested'],
                                                          'num_se_assigned': vip_detail['num_se_assigned'],
                                                          'oper_state': vip_detail['oper_status']['state']}
            if "service_engine" in vip_detail:
                detail_vip_dict[vip_detail['vip_id']]['service_engine'] = vip_detail['service_engine']
        return detail_vip_dict

    def __check_num_se_requested_and_assigned(self):
        for vip_id, e_vip_state in self.expected_state.iteritems():
            vip_summary = self.get_vip_summary(vip_id)
            c_req = vip_summary['num_se_requested']
            c_assign = vip_summary['num_se_assigned']
            detail_vip_dict = self.get_detail_vips_state()

            # log warning when runtime and detail are not in sync
            if c_req != detail_vip_dict[vip_id]['num_se_requested']:
                logger.warning('vs[%s:%s] /virtualservice/runtime num_se_requested[%d] '
                               '!= /virtualservice/runtime/detail num_se_requested[%d]'
                               % (self.vs_name, vip_id, c_req, detail_vip_dict[vip_id]['num_se_requested']))

            if c_assign != detail_vip_dict[vip_id]['num_se_assigned']:
                logger.warning('vs[%s:%s] /api/runtime num_se_assigned[%d] != /api/runtime/detail num_se_assigned[%d]'
                               % (self.vs_name, vip_id, c_req, detail_vip_dict[vip_id]['num_se_assigned']))

            if c_req != e_vip_state['e_req']:
                rstr = "vs[%s:%s] current requested %d != expected requested %d" % \
                       (self.vs_name, vip_id, c_req, e_vip_state['e_req'])
                logger.debug(rstr)
                return False, rstr

            if c_assign != e_vip_state['e_assign']:
                rstr = "vs[%s:%s] current_assigned %d != expected_assigned %d" % \
                       (self.vs_name, vip_id, c_assign, e_vip_state['e_assign'])
                logger.debug(rstr)
                return False, rstr
        logger.info("vs[%s] num_se_requested and num_se_assigned good" % self.vs_name)
        return True, None

    def __verify_snat_ip(self):
        snat_ip_list = list()
        assigned_snat = dict()
        for snat_ip in self.vs['snat_ip']:
            snat_ip_list.append(snat_ip['addr'])

        for vip_id in self.expected_state.keys():    # iterating all vips to verify all attached SE's
            vip_summary = self.get_vip_summary(vip_id)
            if vip_summary.get('service_engine', None):
                # getting list of all SE's for current vip
                se_list = vip_summary['service_engine']
                for se_info in se_list:
                    if se_info['standby'] or (se_info.get('scalein_in_progress', None) and se_info['scalein_in_progress']):
                        # skipping snat ip check if standby SE or scalein_in_progress
                        continue

                    if se_info.get('snat_ip', None):
                        # verifying if SNAT ip for SE is from snat_ip_list
                        if se_info['snat_ip']['addr'] not in snat_ip_list:
                            fail("vs[%s:%s] SNAT ip for SE[%s] not found in snat_ip_list[%s]" %
                                 (self.vs_name, vip_id, se_info['uuid'], snat_ip_list))
                        # checking if current SNAT ip is already assigned to any se attached
                        elif assigned_snat.get(se_info['snat_ip']['addr'], None):
                            fail("vs[%s:%s] duplicate SNAT ip found for SE[%s]. It is already assigned to SE[%s]" %
                                 (self.vs_name, vip_id, se_info['uuid'], assigned_snat[se_info['snat_ip']['addr']]))
                        # adding current snat ip to assigned_snat dict for verifying duplicates
                        assigned_snat[se_info['snat_ip']['addr']] = se_info['uuid']
                    else:
                        # raising error when SE does not have SNAT ip configured
                        raise RuntimeError("vs[%s:%s] SE[%s] does not have SNAT ip" % (self.vs_name, vip_id, se_info['uuid']))
        logger.info("vs[%s] SNAT ip successfully verified" % self.vs_name)
        return True

    def is_vs_well(self, vipid_requested_assigned_operstate):
        # storing given values into expected_state dict.
        self.__parse_expected_state(vipid_requested_assigned_operstate)

        # check number of vips
        if len(self.vs_summary['vip_summary']) != len(self.expected_state):
            fail("vs[%s] num vips in test input(%d) != num vips in summary(%d)" %
                 (self.vs_name, len(self.expected_state), len(self.vs_summary['vip_summary'])))

        # check oper_state
        self.__wait_until_vs_is_in_expected_state()
        logger.info("vs[%s] oper_status in expected state, timeleft:%d" % (self.vs_name, self.timeleft))

        # setting the disconnected_se_list, down_se_list and skip_ew_vs_check flag
        self.__set_disconnected_down_se_list()

        # initialising vs runtime internal data
        asleep("waiting for updating vs runtime internal objects", delay=10)
        self.vs_internal = self.__get_vs_runtime_internal()

        # storing all se's as per vip_id
        self.se_list = {vip_runtime['vip_id']: vip_runtime.get('se_list') for vip_runtime in
                        self.vs_internal['virtualservice_runtime']['vip_runtime']}

        # Verification of pool
        logger.info("timeleft:%d" % self.timeleft)
        # FIXME: check pool state for 'OPER_UP' when VS is UP
        #if 'pool_ref' in self.vs and self.vs_summary['oper_status']['state'] == 'OPER_UP':
            # checking pool state for 'OPER_UP'
            #logger.info('## start pool wellness check: pool=%s t_state=OPER_UP' % self.pool_name)
            #api = 'pool/' + self.pool_name + '/runtime'
            #resp_code, resp_data = get(api)
            #summary_oper_state = resp_data['oper_status']['state']

            #if summary_oper_state != 'OPER_UP':
            #    logger.trace("summary state %s != expected pool state 'OPER_UP'" % summary_oper_state)
            #    raise RuntimeError("summary state %s != expected pool state 'OPER_UP'" % summary_oper_state)
            #logger.info("Pool %s oper_state is OPER_UP" % self.pool_name)

            #FIXME: check for pool oper state only
            #pool_and_servers_should_be_up(self.__get_pool_name(), retry_timeout=self.timeleft)

        logger.info("pool and servers are up")
        logger.info("timeleft:%d" % self.timeleft)

        logger.info("vs[%s] VS type is %s." % (self.vs_name, self.vs['type']))
        if self.vs['type'] in ['VS_TYPE_VH_CHILD', 'VS_TYPE_VH_PARENT']:
            self.__vs_validate_parent_child()
            logger.info("vs[%s] VS parent and child are successfully validated" % self.vs_name)

        # verifying SE's for given vips
        self.__vs_se_flags_check()
        # getting vs placement info
        self.vs_placement = get_vs_api(self.vs_name, 'placement')
        if not self.east_west:
            self.__verify_virtualservice_assignment()
        elif not self.skip_ew_vs_check:  # if vs is east_west and skip flag is false then procceed verification
            # skipping for now, will enable once fixed
            # self.__verify_east_west_vs_assignment()
            pass

        # verification of SNAT ip of vs and se
        if self.vs.get('snat_ip', None):
            self.__verify_snat_ip()
        return True

    #def __get_pool_name(self):
    #    pool_name = None
    #    if 'pool_ref' in self.vs:
    #        pool_ref = self.vs['pool_ref']
    #        pool_uuid = pool_ref.rpartition('/')[2]
    #        api = 'pool/' + pool_uuid
    #        resp_code, resp_data = get(api, fix_url=False)
    #        pool_name = resp_data['name']
    #    return pool_name

    def __vs_validate_parent_child(self):
        if 'type' in self.vs.keys() and self.vs['type'] == 'VS_TYPE_VH_CHILD':
            se_dict = self.virtualservice_get_se_lists()
            if not self.vs['enabled'] and [se_uuid for se_uuid in se_dict.values() if se_uuid]:
                fail('vs[%s] APP SE (Disabled) List (%s) not empty' % (self.vs_name, str(se_dict)))
            else:    # skip if child VS is Disabled or Down
                if self.vs_summary['oper_status']['state'] in ['OPER_DISABLED', 'OPER_DOWN']:
                    logger.debug('Skipping SE check. %s VS is in %s state' %
                                 (self.vs_name, self.vs_summary['oper_status']['state']))
                    return True
                parent_name = rest.get_name_from_ref(self.vs['vh_parent_vs_ref'])
                if not parent_name:
                    fail('vs[%s] Parent VS not found' % self.vs_name)
                parent_vs_obj = VsWellnessCheck(parent_name, 5)
                parent_se_dict = parent_vs_obj.virtualservice_get_se_lists()
                for se_type, se_list in se_dict.items():
                    if sorted(se_list) != sorted(parent_se_dict[se_type]):
                        logger.trace('vs[%s] APP SE List (%s) != Parent SE LIST (%s)' %
                                     (self.vs_name, se_list, parent_se_dict[se_type]))
                        fail('vs[%s] APP SE List (%s) != Parent SE LIST (%s)' %
                                           (self.vs_name, se_list, parent_se_dict[se_type]))
                    logger.info('vs[%s] APP SE List(%s) matches Parent SE LIST (%s)' %
                                 (self.vs_name, se_dict, parent_se_dict))

        elif 'type' in self.vs.keys() and self.vs['type'] == 'VS_TYPE_VH_PARENT':
            se_dict = self.virtualservice_get_se_lists()
            if not self.vs['enabled'] and [se_uuid for se_uuid in se_dict.values() if se_uuid]:
                fail('vs[%s] APP SE (Disabled) List (%s) not empty' % (self.vs_name, str(se_dict)))
            else:
                child_list = self.vs_summary['vh_child_vs_ref']
                if not child_list:
                    logger.debug('vs[%s] Child VS does not exists' % self.vs_name)
                    return
                for child_vs in child_list:
                    child_name = rest.get_name_from_ref(child_vs)
                    child_vs_obj = VsWellnessCheck(child_name, 5)
                    if child_vs_obj.vs_summary['oper_status']['state'] in ['OPER_DISABLED', 'OPER_DOWN']:
                        continue
                    child_se_dict = child_vs_obj.virtualservice_get_se_lists()
                    for se_type, se_list in se_dict.items():
                        if sorted(se_list) != sorted(child_se_dict[se_type]):
                            logger.trace('vs[%s] APP SE List (%s) != Chlid SE LIST (%s)' %
                                         (self.vs_name, se_list, child_se_dict[se_type]))
                            fail('vs[%s] APP SE List (%s) != Child SE LIST (%s)' %
                                 (self.vs_name, se_list, child_se_dict[se_type]))
                        logger.info('vs[%s] APP SE List(%s) matches Child SE LIST (%s)' %
                                    (self.vs_name, se_list, child_se_dict[se_type]))
        return True

    def __vs_se_flags_check(self):
        for vip_id, vip_data in self.expected_state.items():
            if not self.se_list[vip_id]:
                logger.debug('vs[%s:%s] No SE found' % (self.vs_name, vip_id))
                return False
            logger.info('vs[%s:%s] num_in_selist=%d' % (self.vs_name, vip_id, len(self.se_list[vip_id])))

            try:
                num_primary = num_secondary = num_standby = num_disconnected_se = 0
                # counting num of primary, secondary and standby SE's, also verifying
                # at_curr_ver, delete_in_progress and admin_down_requested fields
                for se in self.se_list[vip_id]:
                    if se['se_ref'].split('/')[-1] in self.down_se_list:
                        fail('vs[%s:%s] SE[%s] should not be present in vip se_list when part of se_down_list' %
                        (self.vs_name, vip_id, se['se_ref'].split('/')[-1]))

                    if (se['se_ref'].split('/')[-1] in self.disconnected_se_list) and se['is_connected']:
                        fail('vs[%s:%s] SE[%s] should be disconnected when part of se_disconnected_list' %
                        (self.vs_name, vip_id, se['se_ref'].split('/')[-1]))

                    if not se['is_connected']:
                        num_disconnected_se += 1

                    if not se['at_curr_ver']:
                        fail('vs[%s:%s] at_curr_ver is False' % (self.vs_name, vip_id))

                    elif se['delete_in_progress']:
                        fail('vs[%s:%s] delete_in_progress is True' % (self.vs_name, vip_id))

                    elif se.get('admin_down_requested') and se['admin_down_requested']:
                        fail('vs[%s:%s] admin_down_requested is True' % (self.vs_name, vip_id))

                    if se['is_primary']:
                        num_primary += 1
                        if se['is_standby']:
                            fail('vs[%s:%s] Primary SE is also standby' % (self.vs_name, vip_id))
                    elif se['is_standby']:
                        num_standby += 1
                    else:
                        num_secondary += 1

                logger.info('vs[%s:%s] num_in_selist=%d, num_primary=%d, '
                            'num_secondary=%d, num_standby=%d, num_disconnected_se=%d' %
                            (self.vs_name, vip_id, len(self.se_list[vip_id]), num_primary, num_secondary,
                             num_standby, num_disconnected_se))

                if vip_data['e_operstate'] == 'OPER_PARTITIONED':
                    if len(self.se_list[vip_id]) != num_disconnected_se:  # make sure all SE should not be disconnected
                        fail('vs[%s:%s] Total SE[%d] != num_disconnected_se[%d] when vip is OPER_PARTITIONED' %
                             (self.vs_name, vip_id, len(self.se_list[vip_id]), num_disconnected_se))
                elif len(self.se_list[vip_id]) == num_disconnected_se:
                    # if vip is UP then atleast one SE should be connected
                    fail('vs[%s:%s] Total SE[%d] equals num_disconnected_se[%d] when vip state is UP' % (
                        self.vs_name, vip_id, len(self.se_list[vip_id]), num_disconnected_se))

                if num_primary != 1:
                    fail('vs[%s:%s] num_primary[%d] != 1' % (self.vs_name, vip_id, num_primary))

                if num_standby > 0:
                    if (num_primary + num_standby) != len(self.se_list[vip_id]):
                        error('vs[%s:%s] (num_primary[%d] + num_standby[%d]) != total_in_selist[%d]' %
                                     (self.vs_name, vip_id, num_primary, num_standby, len(self.se_list[vip_id])))
                        fail('vs[%s:%s] (num_primary[%d] + num_standby[%d]) != total_in_selist[%d]' %
                                           (self.vs_name, vip_id, num_primary, num_standby, len(self.se_list[vip_id])))
                    if num_secondary > 0:
                        error('vs[%s:%s] both standby and secondary are set' % (self.vs_name, vip_id))
                        fail('vs[%s:%s] both standby and secondary are set' % (self.vs_name, vip_id))
                    #TODO: check that one_plus_one is set in runtime
                else:
                    if (num_primary + num_secondary) != len(self.se_list[vip_id]):
                        error('vs[%s:%s] (num_primary[%d] + num_secondary[%d]) != total_in_selist[%d]' %
                              (self.vs_name, vip_id, num_primary, num_secondary, len(self.se_list[vip_id])))
                        fail('vs[%s:%s] (num_primary[%d] + num_secondary[%d]) != total_in_selist[%d]' %
                             (self.vs_name, vip_id, num_primary,
                              num_secondary, len(self.se_list[vip_id])))
            except Exception as e:
                logger.debug(traceback.format_exc())
                error("vs[%s:%s] se_validate function failed = %s" % (self.vs_name, vip_id, str(e)))
        return True

    def __verify_east_west_vs_assignment(self):
        try:
            # verification of primary se
            primary_se_uuid_of_placement_vs = self.__placement_get_vs_primary_se_uuids()
            vs_internal = get_vs_api(self.vs_name, '/runtime/internal')
            primary_se_uuid_vs_internal = list()
            for internal_data in vs_internal:
                if internal_data.get('sestatuslist', None):
                    primary_se_uuid_vs_internal.extend([se_status['se_uuid']
                                                        for se_status in internal_data['sestatuslist']
                                                        if se_status['is_primary']])

            if sorted(primary_se_uuid_vs_internal) != sorted(primary_se_uuid_of_placement_vs):
                error('vs[%s] Primary SE %s[/runtime/internal] != RM SE %s[virtualservice/%s/placement]' %
                             (self.vs_name, primary_se_uuid_vs_internal,
                              primary_se_uuid_of_placement_vs, self.vs_uuid))
                fail('vs[%s] Primary SE %s[/runtime/internal] != RM SE %s[virtualservice/%s/placement]' %
                                   (self.vs_name, primary_se_uuid_vs_internal,
                                    primary_se_uuid_of_placement_vs, self.vs_uuid))

            # verification of vs resources
            num_se_of_placement_vs = self.__placement_get_vs_num_se()
            num_se_of_runtime_vs = self.__vs_get_num_se()
            for vip_id, vip_data in num_se_of_runtime_vs.items():
                if vip_data['oper_state'] == 'OPER_DISABLED':
                    if num_se_of_placement_vs[vip_id] != 0:
                        fail(
                            'vs[%s] RM num_se[%d][virtualservice/%s/placement] should be zero if vip state is OPER_DISABLED' %
                            (self.vs_name, num_se_of_placement_vs[vip_id], self.vs_uuid))
                elif vip_data['num_se'] != num_se_of_placement_vs[vip_id]:
                        fail('vs[%s] VS num_se %d[virtualservice/] and '
                                           'RM num_se %d[virtualservice/%s/placement] mismatched' %
                                           (self.vs_name, vip_data['num_se'],
                                            num_se_of_placement_vs[vip_id], self.vs_uuid))
            # verification of num se used
            se_used_of_placement_vs = sum(self.__placement_get_vs_se_used())
            se_used_of_internal_vs = sum([len(internal_data['sestatuslist'])
                                          for internal_data in vs_internal if internal_data.get('sestatuslist', None)])
            if se_used_of_placement_vs != se_used_of_internal_vs:
                fail('vs[%s] VS SE Used %s[/runtime/internal] and '
                                   'RM SE Used %s[virtualservice/%s/placement] mismatched' %
                                   (self.vs_name, se_used_of_internal_vs, se_used_of_placement_vs, self.vs_uuid))

            logger.info("vs[%s] east west placement are verified" % self.vs_name)
            return True
        except Exception as e:
            logger.debug(traceback.format_exc())
            error('vs[%s] Exception: %s' % (self.vs_name, str(e)))

    def __verify_virtualservice_assignment(self):
        try:
            # verification of primary se
            vips_state_dict = self.get_vips_state()
            primary_se_uuid_of_placement_vs = self.__placement_get_vs_primary_se_uuids()
            for vip_id, vip_summary in vips_state_dict.items():
                if vip_summary['oper_state'] != 'OPER_UP':    # skipping check if vip state is not UP
                    continue
                primary_se = self.vs_get_primary_se_uuid(vip_id)
                if primary_se not in primary_se_uuid_of_placement_vs:
                    fail('vs[%s:%s] Primary SE %s[/runtime] not in RM SE %s[virtualservice/%s/placement]' %
                                       (self.vs_name, vip_id, primary_se,
                                        primary_se_uuid_of_placement_vs, self.vs_uuid))

            # verification of vs resources
            num_se_of_placement_vs = self.__placement_get_vs_num_se()
            num_se_of_runtime_vs = self.__vs_get_num_se()
            child_flag = True if self.vs['type'] == 'VS_TYPE_VH_CHILD' else False
            if child_flag:
                parent_name = rest.get_name_from_ref(self.vs['vh_parent_vs_ref'])
                parent_vs_summary = get_vs_api(parent_name, '/runtime')

            for vip_id, vip_data in num_se_of_runtime_vs.items():
                if vip_data['oper_state'] in ['OPER_DISABLED', 'OPER_INACTIVE']:
                    if child_flag:
                        parent_vip_summary = self.get_vip_summary(vip_id=vip_id, vs_summary=parent_vs_summary)
                        if parent_vip_summary['oper_status']['state'] == 'OPER_UP':
                            if vip_data['num_se'] != 1:
                                fail('vs[%s:%s] VS num_se %s[virtualservice/] '
                                     'should be 1 when vip state is Disabled and Parent vip is UP' %
                                     (self.vs_name, vip_id, vip_data['num_se']))
                            continue

                    if num_se_of_placement_vs[vip_id] != 0:
                        error('vs[%s:%s] RM num_se[%d][virtualservice/%s/placement] should be zero '
                                     'if vip state is OPER_DISABLED' % (self.vs_name, vip_id,
                                                                        num_se_of_placement_vs[vip_id], self.vs_uuid))
                        fail('vs[%s:%s] RM num_se[%d][virtualservice/%s/placement] should be zero '
                             'if vip state is OPER_DISABLED' % (self.vs_name, vip_id,
                                                                num_se_of_placement_vs[vip_id], self.vs_uuid))
                else:
                    if child_flag:
                        parent_vip_summary = self.get_vip_summary(vip_id=vip_id, vs_summary=parent_vs_summary)
                        if parent_vip_summary['oper_status']['state'] == 'OPER_DISABLED':
                            # If child VS and same vip of Parent VS is disabled then RM SE should be zero
                            if num_se_of_placement_vs[vip_id] != 0:
                                fail('vs[%s:%s] RM num_se[%d][virtualservice/%s/placement] should be zero'
                                                   ' if Parent vip state is OPER_DISABLED' %
                                     (self.vs_name, vip_id, num_se_of_placement_vs[vip_id], self.vs_uuid))
                            continue    # skipping following check as vip of Parent VS is not UP
                    if vip_data['num_se'] != num_se_of_placement_vs[vip_id]:
                        if vip_data.get('scaleout_in_progress', None) and \
                                (vip_data['num_se'] + 1 != num_se_of_placement_vs[vip_id]):
                            error('vs[%s:%s] scaleout_in_progress, VS num_se %d[virtualservice/runtime] + 1 != '
                                         'RM num_se %d[virtualservice/%s/placement]' %
                                         (self.vs_name, vip_id, vip_data['num_se'],
                                          num_se_of_placement_vs[vip_id], self.vs_uuid))
                            fail('vs[%s:%s] scaleout_in_progress, VS num_se %d[virtualservice/runtime] + 1 != '
                                 'RM num_se %d[virtualservice/%s/placement]' %
                                 (self.vs_name, vip_id, vip_data['num_se'],
                                  num_se_of_placement_vs[vip_id], self.vs_uuid))
                        else:
                            error('vs[%s:%s] VS num_se %d[virtualservice/runtime] != '
                                         'RM num_se %d[virtualservice/%s/placement] mismatched' %
                                         (self.vs_name, vip_id, vip_data['num_se'],
                                          num_se_of_placement_vs[vip_id], self.vs_uuid))
                            fail('vs[%s:%s] VS num_se %d[virtualservice/runtime] != '
                                 'RM num_se %d[virtualservice/%s/placement] mismatched' %
                                 (self.vs_name, vip_id, vip_data['num_se'],
                                  num_se_of_placement_vs[vip_id], self.vs_uuid))

            # verification of num se used
            se_used_of_placement_vs = sum(self.__placement_get_vs_se_used())
            se_used_of_runtime_vs = sum(self.__virtualservice_get_num_se_used())
            if se_used_of_placement_vs != se_used_of_runtime_vs:
                error('vs[%s] VS SE Used %s[/runtime] and '
                      'RM SE Used %s[virtualservice/%s/placement] mismatched' %
                      (self.vs_name, se_used_of_runtime_vs, se_used_of_placement_vs, self.vs_uuid))
                fail('vs[%s] VS SE Used %s[/runtime] and '
                     'RM SE Used %s[virtualservice/%s/placement] mismatched' %
                     (self.vs_name, se_used_of_runtime_vs, se_used_of_placement_vs, self.vs_uuid))

            # verification of total primary, secondary and standby SE's
            se_list_of_placement_vs = self.__placement_get_vs_se_lists()
            se_list_of_runtime_vs = self.virtualservice_get_se_lists()
            for se_type, se_uuids in se_list_of_runtime_vs.items():
                if sorted(se_uuids) != sorted(se_list_of_placement_vs[se_type]):
                    error('vs[%s] %s SE List %s[/runtime] and '
                          'RM SE List %s[virtualservice/%s/placement] mismatched' %
                          (self.vs_name, se_type, se_uuids, se_list_of_placement_vs[se_type], self.vs_uuid))
                    fail('vs[%s] %s SE list %s[/runtime] and '
                         'RM SE list %s[virtualservice/%s/placement] mismatched' %
                         (self.vs_name, se_type, se_uuids, se_list_of_placement_vs[se_type], self.vs_uuid))

            logger.info("vs[%s] VS placement are verified" % self.vs_name)
            return True
        except Exception as e:
            logger.debug(traceback.format_exc())
            error('vs[%s] Exception: %s' % (self.vs_name, str(e)))

    def __placement_get_vs_primary_se_uuids(self):
        se_uuid = []
        for id in range(len(self.vs_placement)):
            if 'resources_consumed' in self.vs_placement[id]:
                for res in self.vs_placement[id]['resources_consumed']:
                    if res['is_primary']:
                        se_uuid.append(res['res_ref'].rpartition('/')[-1])
        return se_uuid

    def __placement_get_vs_num_se(self):
        num_se = dict()
        self.vs_placement = get_vs_api(self.vs_name, '/placement')
        for consumer in self.vs_placement:
            vip_id = consumer['uuid'].split('#')[-1]
            num_se[vip_id] = consumer['num_se']
        return num_se

    def __placement_get_vs_se_used(self):
        res_consume = []
        for id in range(len(self.vs_placement)):
            resource_consume = 0
            if 'resources_consumed' in self.vs_placement[id]:
                resource_consume = len(self.vs_placement[id]['resources_consumed'])
            res_consume.append(resource_consume)
        return res_consume

    def virtualservice_get_se_lists(self):
        vip_summary = self.vs_summary['vip_summary']
        se_dict = {'primary': [], 'secondary': [], 'standby': []}
        for vip_data in vip_summary:
            if "service_engine" in vip_data.keys():
                for se in vip_data['service_engine']:
                    if se.get('primary'):
                        se_dict['primary'].append(se['uuid'])
                    elif se.get('standby'):
                        se_dict['standby'].append(se['uuid'])
                    else:
                        se_dict['secondary'].append(se['uuid'])
        return se_dict

    def __placement_get_vs_se_lists(self):
        se_dict = {'primary': [], 'secondary': [], 'standby': []}
        for id in range(len(self.vs_placement)):
            if 'resources_consumed' in self.vs_placement[id]:
                for res in self.vs_placement[id]['resources_consumed']:
                    se_uuid = res['res_ref'].rpartition('/')[-1]
                    if res.get('is_primary'):
                        se_dict['primary'].append(se_uuid)
                    elif res.get('is_stby'):
                        se_dict['standby'].append(se_uuid)
                    else:
                        se_dict['secondary'].append(se_uuid)

        return se_dict

    def __vs_get_num_se(self):
        num_se = dict()
        #self.vs = get_vs_api(self.vs_name)
        #for vip_runtime in self.vs['vip_runtime']:
        for vip_runtime in self.vs_internal['virtualservice_runtime']['vip_runtime']:
            #vip_summary = self.get_vip_summary(vip_id=vip_runtime['vip_id'], vs_summary=get_vs_api(self.vs_name, '/runtime'))
            vip_summary = self.get_vip_summary(vip_id=vip_runtime['vip_id'])
            vip_state = vip_summary['oper_status']['state']
            num_se[vip_runtime['vip_id']] = {
                'num_se': vip_runtime['requested_resource']['num_se'],
                'oper_state':  vip_state
            }
        return num_se

    def __virtualservice_get_num_se_used(self):
        se_used = []
        for vip_id in self.expected_state.iterkeys():
            for vip_data in self.vs_summary['vip_summary']:
                if vip_data['vip_id'] == vip_id and 'service_engine' in vip_data:
                        se_used.append(len(vip_data['service_engine']))
        return se_used

    def vs_get_primary_se_uuid(self, vip_id='0'):
        vip_summary = self.get_vip_summary(vip_id)
        if 'service_engine' not in vip_summary:
            fail('vs[%s:%s] not assigned to SE' % (self.vs_name, vip_id))
        se_uuid = None
        for se in vip_summary['service_engine']:
            if se['primary']:
                se_uuid = se['uuid']
                break
        return se_uuid

    def vs_get_secondary_se_uuid(self, secondary_index=0, vip_id='0'):
        vip_summary = self.get_vip_summary(vip_id)
        if 'service_engine' not in vip_summary:
            fail('vs[%s:%s] not assigned to SE' % (self.vs_name, vip_id))
        se_uuids = list()
        for se in vip_summary['service_engine']:
            if not se['primary']:
                se_uuids.append(se['uuid'])

        if not se_uuids:
            fail("vs[%s:%s] no secondary se for this vs" % (self.vs_name, vip_id))
        return se_uuids[secondary_index]

    def vs_get_standby_se_uuid(self, vip_id='0'):
        vip_summary = self.get_vip_summary(vip_id)
        if 'service_engine' not in vip_summary:
            fail('vs[%s:%s] not assigned to SE' % (self.vs_name, vip_id))
        se_uuid = None
        for se in vip_summary['service_engine']:
            if se['standby']:
                se_uuid = se['uuid']
                break
        return se_uuid

    def get_tls_ticket_keys(self):
        final_key_list = list()
        self.vs_internal = self.__get_vs_runtime_internal()
        tls_ticket_key_list = self.vs_internal['virtualservice_runtime']['tls_ticket_key']
        # make sure all keys are unique
        for key in tls_ticket_key_list:
            if key in final_key_list:
                fail('vs[%s] duplicate tls_ticket_key[%s] found in %s' % (self.vs_name, key, tls_ticket_key_list))
            final_key_list.append(key)
        return final_key_list

    def tls_keys_should_rotate(self, old_keys, count=1):
        for index in range(3):   # retrying for max 3 times, if keys_should_rotate fails
            new_keys = self.get_tls_ticket_keys()
            ret, msg = keys_should_rotate(old_keys, new_keys, int(count))
            if not ret or (index == 2 and msg):
                raise RuntimeError(msg)

    def tls_keys_should_not_rotate(self, old_keys):
        new_keys = self.get_tls_ticket_keys()
        keys_should_not_rotate(old_keys, new_keys)

    def analytics_policy_should_disabled(self, full_client_logs=False, metrics_realtime_update=False,
                                         client_log_filters=None):
        """
        :param full_client_logs: Boolean flag to check policy state of full_client_logs type
        :param metrics_realtime_update: Boolean flag to check policy state of metrics_realtime_update type
        :param client_log_filters: name of client_log_filter policy to check state
        :return: True if all given policies are disabled else raises exception
        """
        policy_dict = {'full_client_logs': full_client_logs, 'client_log_filters': client_log_filters,
                        'metrics_realtime_update': metrics_realtime_update}
        for policy_name, policy_set in policy_dict.items():
            if policy_set:
                for i in range(3):  # retrying 3 times if policy doesn't disabled
                    self.vs = get_vs_api(self.vs_name)
                    if policy_name == 'client_log_filters':
                        disabled = False
                        for policy_data in self.vs['analytics_policy'][policy_name]:
                            # iterating over list of client_log_filters policy names to get exact policy
                            if policy_data['name'] == client_log_filters and not policy_data['enabled']:
                                disabled = True
                                break   # break iterating over policy when policy is disabled
                        if disabled:    # if policy is disabled then break loop
                            break

                    elif not self.vs['analytics_policy'][policy_name]['enabled']:
                        break    # for policy other than client_log_filters

                    if i==2:
                        fail('Error: analytics_policy[%s] are not disabled' % policy_name)
        return True

    def verify_vs_log_throttling(self, udf_log_throttle=False, full_client_logs=False,
                                 significant_log_throttle=False, count=10):
        """
        :param full_client_logs: Boolean flag to check throttle of full_client_logs type
        :param udf_log_throttle: Boolean flag to check throttle of udf_log_throttle
        :param significant_log_throttle: Boolean flag to check throttle of significant_log_throttle
        :return: True if all given policies are disabled else raises exception
        """
        throttle_dict = {'full_client_logs': full_client_logs, 'udf_log_throttle': udf_log_throttle,
                        'significant_log_throttle': significant_log_throttle}
        self.vs = get_vs_api(self.vs_name)
        for throttle_name, throttle_set in throttle_dict.items():
            if throttle_set:
                if throttle_name == 'full_client_logs':
                    if self.vs['analytics_policy'][throttle_name]['throttle'] != int(count):
                        fail('Error: Expected %s count[%d] != %d' %
                             (throttle_name, int(count), self.vs['analytics_policy'][throttle_name]['throttle']))
                elif self.vs['analytics_policy'][throttle_name] != int(count):
                    fail('Error: Expected %s count[%d] != %d' % (throttle_name, int(count),
                                                                 self.vs['analytics_policy'][throttle_name]))
        return True

    def reboot_se(self, vip_id='0', primary=0, se_uuid=None):
        reboot_se_uuid = self.vs_get_primary_se_uuid(vip_id) if primary else se_uuid
        se_vm = get_se_vm(se_uuid=reboot_se_uuid)[0]
        reboot_se(se_vm)

    def wait_until_vs_scaleout_complete(self, vip_id):
        """
        waits for scaleout operation to get finished
        :param vip_id: index to fetch vip_summary data
        :return: True on successful otherwise raising an exception
        """
        timeout = timeleft = 200
        #TODO: right now hardcoded the time_left but should be set to 600 if cloud_access type is write
        #if config.cloud_access_pb.type == 'write':
        #    timeleft = 600
        while True:
            logger.debug("vs[%s:%s] check for scaleout complete" % (self.vs_name, vip_id))
            vip_summary = self.get_vip_summary(vip_id, vs_summary=get_vs_api(self.vs_name, '/runtime'))
            if u'scaleout_in_progress' not in vip_summary.keys() or \
                    not vip_summary['scaleout_in_progress']:
                logger.info("vs[%s:%s] scaleout complete" % (self.vs_name, vip_id))
                return True
            else:
                if timeleft == 0:
                    fail("vs[%s:%s] error: scaleout not complete in %s sec" % (self.vs_name, vip_id, timeout))
                time.sleep(1)
                timeleft -= 1

    def wait_until_vs_scalein_complete(self, vip_id):
        """
        waits for scalein operation to get finished
        :param vip_id: index to fetch vip_summary data
        :return: True on successful otherwise raising an exception
        """
        timeout = timeleft = 60
        #added extra timeout for Azure scalein
        #if config.cloud.type == 'azure':
        #    timeout = timeleft = 300
        #if config.cloud_access_pb.type == 'write':
        #    timeleft = 600
        while True:
            logger.debug("vs[%s:%s] check for scalein complete" % (self.vs_name, vip_id))
            vip_summary = self.get_vip_summary(vip_id, vs_summary=get_vs_api(self.vs_name, '/runtime'))
            if u'scalein_in_progress' not in vip_summary.keys() or \
                    not vip_summary['scalein_in_progress']:
                logger.info("vs[%s:%s] scalein complete" % (self.vs_name, vip_id))
                return True
            else:
                if timeleft == 0:
                    error("vs[%s:%s] error: scalein not complete in %s sec" % (self.vs_name, vip_id, timeout))
                    fail("vs[%s:%s] error: scalein not complete in %s sec" % (self.vs_name, vip_id, timeout))
                time.sleep(1)
                timeleft -= 1

    def wait_until_vs_migration_complete(self, vip_id):
        """
        waits for migration operation to get finished
        :param vip_id: index to fetch vip_summary data
        :return: True on successful otherwise raising an exception
        """
        timeout = timeleft = 60
        #if config.cloud_access_pb.type == 'write':
        #    timeleft = 600
        while True:
            logger.debug("vs[%s:%s] check for migration completion" % (self.vs_name, vip_id))
            self.vs_summary = get_vs_api(self.vs_name, '/runtime')
            vip_summary = self.get_vip_summary(vip_id)
            if u'migrate_in_progress' not in vip_summary.keys() or \
                    not vip_summary['migrate_in_progress']:
                logger.info("vs[%s:%s] migration completed" % (self.vs_name, vip_id))
                return True
            else:
                if timeleft == 0:
                    logger.trace("vs[%s:%s] error: migration not completed in %s sec" % (self.vs_name, vip_id, timeout))
                    fail("vs[%s:%s] error: migration not completed in %s sec" % (self.vs_name, vip_id, timeout))
                time.sleep(1)
                timeleft -= 1

    def verify_scaleout_not_in_progress(self, vip_id):
        """
        verify if scaleout operation is not triggered
        :param vip_id: index to fetch vip_summary data
        """
        vip_summary = self.get_vip_summary(vip_id, vs_summary=get_vs_api(self.vs_name, '/runtime'))
        if u'scaleout_in_progress' in vip_summary.keys() and \
                vip_summary['scaleout_in_progress']:
            logger.trace("vs[%s:%s] scaleout operation should not be started" % (self.vs_name, vip_id))
            fail("vs[%s:%s] scaleout operation should not be started" % (self.vs_name, vip_id))

    def wait_until_vs_scalein_started(self, vip_id):
        """
        waits for scalein operation to get started
        :param vip_id: index to fetch vip_summary data
        :return: True on successful otherwise raising an exception
        """
        timeout = timeleft = 5
        logger.info("vs[%s:%s] check for scalein is started" % (self.vs_name, vip_id))
        while True:
            vip_summary = self.get_vip_summary(vip_id, vs_summary=get_vs_api(self.vs_name, '/runtime'))
            if u'scalein_in_progress' in vip_summary.keys() and vip_summary['scalein_in_progress']:
                logger.debug("vs[%s:%s] scalein started successfully" % (self.vs_name, vip_id))
                return True
            else:
                if timeleft == 0:
                    logger.debug("vs[%s:%s] scalein not started in %s sec or may be already completed" %
                                 (self.vs_name, vip_id, timeout))
                    return False
                time.sleep(1)
                timeleft -= 1

    def verify_last_scale_state(self, vip_id, ex_state, curr_state):
        if ex_state != curr_state:
            fail('vs[%s:%s] Exepcted state[%s] != current state[%s]' %
                               (self.vs_name, vip_id, ex_state, curr_state))
        logger.info("vs[%s:%s] Last scale SE state is %s" % (self.vs_name, vip_id, curr_state))

    def verify_last_scale_action(self, vip_id, ex_action, curr_action):
        if ex_action != curr_action:
            fail('vs[%s:%s] Exepcted action[%s] != current action[%s]' %
                               (self.vs_name, vip_id, ex_action, curr_action))
        logger.info('vs[%s:%s] scalein action is %s' % (self.vs_name, vip_id, curr_action))

    def verify_last_scale_start_end_time(self, vip_id, start_time, end_time):
        if datetime.strptime(start_time, '%Y-%m%d %H:%M:%S.%f') > \
                datetime.strptime(end_time, '%Y-%m%d %H:%M:%S.%f'):
            fail('vs[%s:%s] scale start time cannot be greater than end time' % (self.vs_name, vip_id))

        logger.info('vs[%s:%s] scale start time and end time verified successfully' % (self.vs_name, vip_id))

    def verify_num_req_se(self, vip_id, ex_se_req, curr_se_req):
        if ex_se_req != curr_se_req:
            fail('vs[%s:%s] Exepcted num_se_requested[%d] != num_se_requested[%d]' %
                               (self.vs_name, vip_id, ex_se_req, curr_se_req))
        logger.info('vs[%s:%s] Exepcted num_se_requested[%d] matches num_se_requested[%d]' %
                    (self.vs_name, vip_id, ex_se_req, curr_se_req))

    def verify_num_assigned_se(self, vip_id, ex_se_assigned, curr_se_assigned):
        if ex_se_assigned != curr_se_assigned:
            fail('vs[%s:%s] Exepcted num_se_assigned[%d] != num_se_assigned[%d]' %
                               (self.vs_name, vip_id, ex_se_assigned, curr_se_assigned))
        logger.info('vs[%s:%s] Exepcted num_se_assigned[%d] matches num_se_assigned[%d]' %
                    (self.vs_name, vip_id, ex_se_assigned, curr_se_assigned))

    def verify_vs_se_after_migrate(self, vs_pre_migrate, vip_id, primary, from_se, to_se, migrate_rollback):
        curr_pse = self.vs_get_primary_se_uuid(vip_id)
        pre_pse = vs_pre_migrate.vs_get_primary_se_uuid(vip_id)
        if migrate_rollback:
            if primary:
                if pre_pse != curr_pse:
                    fail('vs[%s:%s] Primary SE[%s] should not changed after Migrate Rollback' %
                                       (self.vs_name, vip_id, from_se))
            else:
                pre_sse_list = vs_pre_migrate.vs_get_secondary_se_uuid(vip_id=vip_id)
                curr_sse_list = self.vs_get_secondary_se_uuid(vip_id=vip_id)
                if pre_sse_list != curr_sse_list:
                    fail('vs[%s:%s] Secondary SE[%s] should not changed after Migrate Rollback' %
                                       (self.vs_name, vip_id, from_se))
        elif from_se:
            if primary:
                if from_se == curr_pse:
                    fail('vs[%s:%s] Primary SE[%s] not changed even after migration' %
                                       (self.vs_name, vip_id, from_se))
            else:
                curr_sse_list = self.vs_get_secondary_se_uuid(vip_id=vip_id)
                if from_se in curr_sse_list:
                    fail('vs[%s:%s] Secondary SE[%s] not changed even after migration' %
                                       (self.vs_name, vip_id, from_se))
        pre_vips_state_dict = vs_pre_migrate.get_vips_state()
        if len(pre_vips_state_dict.keys()) > 1:    # in case of multivip vs, other vip state should not be changed
            pre_vips_state_dict = self.get_vips_state()
            for vip, vip_data in pre_vips_state_dict.iteritems():
                if vip == vip_id:
                    continue
                if vip_data['num_se_requested'] != pre_vips_state_dict[vip]['num_se_requested']:
                    fail('vs[%s:%s] num_se_requested should not changed for this vip id' %
                                       (self.vs_name, vip))
                elif vip_data['num_se_assigned'] != pre_vips_state_dict[vip]['num_se_assigned']:
                    fail('vs[%s:%s] num_se_assigned should not changed for this vip id' %
                                       (self.vs_name, vip))
                elif vip_data['oper_state'] != pre_vips_state_dict[vip]['oper_state']:
                    fail('vs[%s:%s] oper_state should not changed for this vip id' %
                                       (self.vs_name, vip))
        logger.info('vs[%s:%s] Verification of SE after migration successfully done' % (self.vs_name, vip_id))

    def verify_scaleout_event_history_logs(self, event_history, vip_id, to_se_uuid,
                                           scaleout_rollback, admin_up):
        # getting se name from uuid in case 'to_se_uuid' is given
        scale_se_name = get_se_name_from_uuid(to_se_uuid) if to_se_uuid else None
        # dictionary of events to be generated
        event_dict = {'SCALEOUT': ['SCALE_OUT auto', 'SE_ADDED', 'SCALEOUT_READY'],
                      'SCALEOUT_TO_SE': ['SCALE_OUT %s' % scale_se_name, 'SE_ADDED %s' % scale_se_name,
                                         'SCALEOUT_READY'],
                      'ADMIN_UP': ['SCALEOUT_ADMINUP %s' % scale_se_name, 'SCALEOUT_READY'],
                      'SCALEOUT_ROLLBACK': ['SCALE_OUT auto', 'SCALEOUT_ROLLEDBACK']
                      }
        event_history_new = self.get_vs_event_history(vip_id)    # events history after scaleout operation

        # getting newly generated events for scaleout operation
        latest_generated_events = event_history_new[(event_history_new.index(event_history[-1]) + 1):]
        if not latest_generated_events:
            fail('vs[%s:%s] No ev_history' % (self.vs_name, vip_id))

        # taking the expected list of events based on flags
        expected_event_list = event_dict['SCALEOUT']
        if admin_up:
            expected_event_list = event_dict['ADMIN_UP']
        elif to_se_uuid:
            expected_event_list = event_dict['SCALEOUT_TO_SE']
        elif scaleout_rollback:
            expected_event_list = event_dict['SCALEOUT_ROLLBACK']
        if len(expected_event_list) != len(latest_generated_events):
            if len(expected_event_list) > len(latest_generated_events):
                fail('vs[%s:%s] Number in internal ev_history expected:[%d] != Got [%d]' %
                     (self.vs_name, vip_id, len(expected_event_list), len(latest_generated_events)))
            else:
                logger.warning('vs[%s:%s] extra events generated %s'
                               % (self.vs_name, vip_id, set(latest_generated_events).difference(set(expected_event_list))))

        for expected_event in expected_event_list:
            try:
                if next(True for latest_event in latest_generated_events
                        if expected_event in re.sub(' +', ' ', latest_event)):
                    logger.debug('ev_history after scaleout looks good')

            except StopIteration:
                fail('vs[%s:%s] Expected %s not in ev_history' %
                     (self.vs_name, vip_id, expected_event))

        logger.debug('vs[%s:%s] ev_history after scaleout looks good' % (
            self.vs_name, vip_id))
        return True

    def verify_scalein_event_history_logs(self, event_history, vip_id, se_uuid, admin_down, primary):
        # getting se name from uuid in case 'se_uuid' is given
        scale_se_name = get_se_name_from_uuid(se_uuid) if se_uuid else None
        # dictionary of events to be generated
        event_dict = {'SCALEIN': ['SCALE_IN auto', 'SE_SCALING_IN', 'SCALEIN_READY'],
                      'SCALEIN_FROM_SE': ['SCALE_IN %s' % scale_se_name, 'SE_SCALING_IN %s' % scale_se_name,
                                          'SCALEIN_READY'],
                      'SCALEIN_PRIMARY_FROM_SE': ['SCALE_IN %s' % scale_se_name,
                                                  ['NEW_PRIMARY', 'SE_SCALING_IN %s' % scale_se_name],
                                                  'SCALEIN_READY %s' % scale_se_name],
                      'ADMIN_DOWN': ['SCALEIN_ADMINDOWN %s' % scale_se_name, 'SE_SCALING_IN %s' % scale_se_name,
                                     'SCALEIN_READY %s' % scale_se_name],
                      'NEW_PRIMARY': ['SCALE_IN auto', 'NEW_PRIMARY', 'SCALEIN_READY']
                      }

        event_history_new = self.get_vs_event_history(vip_id)    # events history after scalein operation
        # getting newly generated events for scalein operation
        latest_generated_events = event_history_new[(event_history_new.index(event_history[-1]) + 1):]
        if not latest_generated_events:
            fail('vs[%s:%s] No ev_history' % (self.vs_name, vip_id))

        # taking the expected list of events based on flags
        expected_event_list = event_dict['SCALEIN']
        if se_uuid:
            expected_event_list = event_dict['SCALEIN_FROM_SE']
            if primary:  # when given se_uuid is primary
                expected_event_list = event_dict['SCALEIN_PRIMARY_FROM_SE']
            if admin_down:
                expected_event_list = event_dict['ADMIN_DOWN']
        elif primary:
            expected_event_list = event_dict['NEW_PRIMARY']

        if len(expected_event_list) != len(latest_generated_events):
            if len(expected_event_list) > len(latest_generated_events):
                fail('vs[%s:%s] Number in internal ev_history expected [%d] != Got [%d]' %
                     (self.vs_name, vip_id, len(expected_event_list), len(latest_generated_events)))
            else:
                logger.warning('vs[%s:%s] extra events generated %s'
                               % (self.vs_name, vip_id, set(latest_generated_events).difference(set(expected_event_list))))

        for expected_event in expected_event_list:
            if isinstance(expected_event, list):
                try:
                    if next(True for latest_event in latest_generated_events
                            for ex_event in expected_event if ex_event in re.sub(' +', ' ', latest_event)):
                        logger.debug('ev_history after scalein looks good')
                except StopIteration:
                    fail('vs[%s:%s] Expected %s not in ev_history' %
                         (self.vs_name, vip_id, expected_event))
            else:
                try:
                    if next(True for latest_event in latest_generated_events
                            if expected_event in re.sub(' +', ' ', latest_event)):
                        logger.debug(' v_history after scalein looks good')

                except StopIteration:
                    fail('vs[%s:%s] Expected %s not in ev_history' %
                         (self.vs_name, vip_id, expected_event))

        logger.debug('vs[%s:%s] ev_history after scalein looks good' % (self.vs_name, vip_id))
        return True

    def verify_migrate_event_history_logs(self, event_history, vip_id, primary, from_se, to_se, migrate_rollback):
        # getting se name from uuid in case 'se_uuid' is given
        from_se = get_se_name_from_uuid(from_se) if from_se else None
        to_se = get_se_name_from_uuid(to_se) if to_se else None
        if len(self.se_list[vip_id]) == 1:    # If vip has single SE then setting primary
            primary = True

        # dictionary of events to be generated
        event_dict = {'MIGRATE': ['MIGRATE_SCALEOUT auto',
                                  'SE_ADDED',
                                  'MIGRATE_SCALEIN',
                                  ['NEW_PRIMARY', 'SE_SCALING_IN %s' % from_se],
                                  'SCALEIN_READY'],
                      'MIGRATE_FROM_PRIMARY': ['MIGRATE_SCALEOUT %s' % to_se,
                                               'SE_ADDED %s' % to_se,
                                               'MIGRATE_SCALEIN %s' % from_se,
                                               ['NEW_PRIMARY', 'SE_SCALING_IN %s' % from_se],    # either of events
                                               'SCALEIN_READY %s' % from_se],
                      'MIGRATE_FROM_SECONDARY': ['MIGRATE_SCALEOUT %s' % to_se,
                                                 'SE_ADDED %s' % to_se,
                                                 'MIGRATE_SCALEIN %s' % from_se,
                                                 'SE_SCALING_IN %s' % from_se,
                                                 'SCALEIN_READY %s' % from_se],
                      'MIGRATE_SECONDARY_WITHOUT_TO_SE': ['MIGRATE_SCALEOUT auto',
                                                          'SE_ADDED',
                                                          'MIGRATE_SCALEIN %s' % from_se,
                                                          'SE_SCALING_IN %s' % from_se,
                                                          'SCALEIN_READY %s' % from_se],
                      'MIGRATE_ROLLBACK': ['MIGRATE_SCALEOUT %s' % to_se, 'SE_SCALEOUT_FAILED %s' % to_se],
                      'MIGRATE_ROLLBACK_WITHOUT_TO_SE': ['MIGRATE_SCALEOUT auto', 'SCALEOUT_ROLLEDBACK']
                      }

        event_history_new = self.get_vs_event_history(vip_id)    # events history after migrate operation
        # getting newly generated events for migrate
        latest_generated_events = event_history_new[(event_history_new.index(event_history[-1]) + 1):]
        if not latest_generated_events:
            fail('vs[%s:%s] No event logs are generated' % (self.vs_name, vip_id))

        # taking the expected list of events based on flags
        expected_event_list = event_dict['MIGRATE']    # for default auto migration
        if not primary:    # when migrating secondary SE
            expected_event_list = event_dict['MIGRATE_FROM_SECONDARY'] \
                if to_se else event_dict['MIGRATE_SECONDARY_WITHOUT_TO_SE']
        if from_se and to_se:
            expected_event_list = event_dict['MIGRATE_FROM_PRIMARY'] \
                if primary else event_dict['MIGRATE_FROM_SECONDARY']
        if migrate_rollback:    # when rollback is expected
            expected_event_list = event_dict['MIGRATE_ROLLBACK'] \
                if to_se else event_dict['MIGRATE_ROLLBACK_WITHOUT_TO_SE']

        if len(expected_event_list) != len(latest_generated_events):
            fail('vs[%s:%s] Expected number of events[%d] != actual genarated events[%d]' %
                 (self.vs_name, vip_id, len(expected_event_list), len(latest_generated_events)))

        for index, event in enumerate(latest_generated_events):
            expected_event = expected_event_list[index]
            if isinstance(expected_event, list):
                found = [True for ex_event in expected_event if ex_event in re.sub(' +', ' ', event)]
                if not found:
                    fail('vs[%s:%s] Expected events either of %s not generated' %
                         (self.vs_name, vip_id, expected_event))

            elif expected_event not in re.sub(' +', ' ', event):
                fail('vs[%s:%s] Expected events %s not generated' %
                     (self.vs_name, vip_id, expected_event))

        logger.debug('vs[%s:%s] Expected events for migration are successfully generated' % (self.vs_name, vip_id))
        return True

    def verify_se_stop_event_history_logs(self, event_history, se_uuid, vip_id):
        # getting se name from uuid in case 'se_uuid' is given
        se_name = get_se_name_from_uuid(se_uuid) if se_uuid else None

        expected_event = 'SE_REMOVED %s' % se_name
        event_history_new = self.get_vs_event_history(vip_id)    # events history after scaleout operation

        # getting newly generated events for se stop operation
        latest_generated_events = event_history_new[(event_history_new.index(event_history[-1]) + 1):]
        if not latest_generated_events:
            fail('vs[%s:%s] No event logs are generated' % (self.vs_name, vip_id))

        found_event = False
        for event in latest_generated_events:
            if 'SE_FORCE_RELEASE' in re.sub(' +', ' ', event):  # raise error when SE_FORCE_RELEASE event found
                fail('se[%s] Unexpected event [%s] found' % (se_uuid, re.sub(' +', ' ', event)))
            if expected_event in re.sub(' +', ' ', event):
                found_event = True  # setting flag True when event gets found

        if not found_event:
            fail('se[%s] Expected event %s not found in latest generated events[%s]' %
                 (se_uuid, expected_event, latest_generated_events))

        logger.debug('se[%s] Expected events for se stop are successfully generated' % se_uuid)
        return True

    def verify_se_disconnect_event_history_logs(self, event_history, se_uuid, vip_id):
        # getting se name from uuid in case 'se_uuid' is given
        se_name = get_se_name_from_uuid(se_uuid) if se_uuid else None

        expected_event = 'SE_DISCONNECT %s' % se_name
        event_history_new = self.get_vs_event_history(vip_id)    # events history after scaleout operation

        # getting newly generated events for se stop operation
        latest_generated_events = event_history_new[(event_history_new.index(event_history[-1]) + 1):]
        if not latest_generated_events:
            fail('vs[%s:%s] No event logs are generated' % (self.vs_name, vip_id))

        found_event = False
        for event in latest_generated_events:
            if expected_event in re.sub(' +', ' ', event):
                found_event = True  # setting flag True when event gets found

        if not found_event:
            fail('se[%s] Expected event %s not found in latest generated events[%s]' %
            (se_uuid, expected_event, latest_generated_events))

        logger.debug('se[%s] Expected events for se disconnect are successfully generated' % se_uuid)
        return True


def vs_wellness_check(vs_name, vipid_requested_assigned_operstate, timeout=240):
    vs_well_obj = VsWellnessCheck(vs_name, timeout)
    try:
        vs_well_obj.is_vs_well(vipid_requested_assigned_operstate)
    except Exception as e:
        logger.info(traceback.format_exc())
        error(str(e))
    return vs_well_obj


def vs_scaleout_v2(vs_name, vip_id='0', to_se_uuid=None, expected_error=None,
                   scaleout_rollback=False, to_new_se=False, admin_up=False, host_name=None, wait=True):

    vs_obj = scaleout_v2(vs_name, vip_id, to_se_uuid, expected_error,
                         scaleout_rollback, to_new_se, admin_up, host_name, wait)
    return vs_obj


def vs_scalein_v2(vs_name, vip_id='0', primary=0, se_uuid=None, expected_error=None,
                  admin_down=False, wait=True):
    vs_obj = scalein_v2(vs_name, vip_id, primary, se_uuid, expected_error,
                        admin_down, wait)
    return vs_obj


def vs_migrate_v2(vs_name, vip_id='0', from_se=None, to_se=None, expected_error=None, migrate_rollback=False, wait=True):
    vs_obj = migrate_v2(vs_name, vip_id, from_se, to_se, expected_error, migrate_rollback, wait)
    return vs_obj


def se_stop_v2(vs_name=None, se_uuid=None, vip_id='0', primary=0):
    if not (vs_name or se_uuid):
        fail("Invalid arguments. Either vs_name or se_uuid is needed")
    verify_history_events = False
    if vs_name:
        verify_history_events = True
        vs_obj_pre = VsWellnessCheck(vs_name, 5)
        event_history = vs_obj_pre.get_vs_event_history(vip_id)  # storing event history logs before stopping se
        if not se_uuid:
            if primary:
                se_uuid = vs_obj_pre.vs_get_primary_se_uuid(vip_id=vip_id)
            else:
                se_uuid = vs_obj_pre.vs_get_secondary_se_uuid(vip_id=vip_id)

    event_dict = get_event_logs(["VS_REMOVED_SE", 'SE_DOWN'])
    # getting num vs attached to se
    se_data = get_se_info(se_uuid=se_uuid)
    #num_vs = 0 if 'consumers' not in se_data else len(se_data['consumers'])
    se_stop_by_uuid(se_uuid)
    # verify that VS_REMOVED_SE event should be equal to vs attached
    #get_event_id_based_log_should_increase_v2('VS_REMOVED_SE', event_dict['VS_REMOVED_SE'],
    #                                          increase_count_by=num_vs)

    # verify SE_DOWN event should be generated
    get_event_id_based_log_should_increase_v2('SE_DOWN', event_dict['SE_DOWN'])

    if verify_history_events:
        vs_obj_post = VsWellnessCheck(vs_name, 5)
        se_dict = vs_obj_post.virtualservice_get_se_lists()    # getting se list for given vs
        for se_type, se_uuid_list in se_dict.items():    # SE should be disconnected from vs
            if se_uuid in se_uuid_list:
                fail("se[%s] is not disconnected from vs[%s]" % (se_uuid, vs_name))
        # verify event history logs
        vs_obj_post.verify_se_stop_event_history_logs(event_history, se_uuid, vip_id)


def se_start_v2(se_uuid):
    # getting SE_UP event before se start
    event_dict = get_event_logs(["SE_UP"])
    se_start_by_uuid(se_uuid)
    # verify that SE_UP event should be generated
    get_event_id_based_log_should_increase_v2('SE_UP', event_dict['SE_UP'],
                                              retry_count= 20)


def get_vs_api(vs_name, level="", **kwargs):
    resp_code, resp_data = rest.get('virtualservice', name=vs_name, path=level, tenant='*')
    if resp_code > 299:
        fail('Error! get api virtualservice/%s/%s\n resp_code: %s\n resp_data:%s' %
             (vs_name, level, resp_code, resp_data))
    return resp_data


def get_vs_wellness_args(vip_dict):
    arg_list = list()
    for vip_id, vip_data in vip_dict.iteritems():
        arg_list.append(str(vip_id) + '-' + str(vip_data['num_se_requested']) +
                        '-' + str(vip_data['num_se_assigned']) + '-' + vip_data['oper_state'])
    return arg_list


def get_event_logs(event_id_list):
    """
    receives event logs and returns dictionary of events
    :param event_id_list: list of event id's
    :return: dictionary of events
    """
    event_dict = dict()
    for event_id in event_id_list:
        event_dict[event_id] = get_event_id_based_log_v2(event_id)
    return event_dict


def get_scaleout_api(vip_id, to_se_uuid, to_new_se, admin_up, host_name):
    data = {'vip_id': vip_id}
    if to_se_uuid:
        # adding to_se_ref parameter when se uuid given
        params = '/api/serviceengine/%s' % to_se_uuid
        data['to_se_ref'] = params
    elif to_new_se:    # used to spin up new SE
        data['to_new_se'] = 'true'
    if host_name:
        data['to_host_ref'] = host_name
    if admin_up:
        data['admin_up'] = 'true'
    return data


def scaleout_v2(vs_name, vip_id='0', to_se_uuid=None, expected_error=None,
                scaleout_rollback=False, to_new_se=False, admin_up=False, host_name=None, wait=True):
    """
    function does scaleout operation, wait until finish and also verifies last scale status fields and
    checks event logs.
    :param vs_name: name of VS on which scaleout operation will be triggered
    :param vip_id: index to fetch vip_summary data and also used to trigger scaleout operation
    :param to_se_uuid: SE uuid on which scaleout should be done
    :param expected_error: expected error message
    :param scaleout_rollback: flag for SCALEOUT_ROLLBACK state
    :param to_new_se: spin up new se(useful with write access)
    :param wait: flag to wait untill scaleout operation get finished
    :return:
    """
    # storing vs state before scaleout operation
    vs_pre_scale = VsWellnessCheck(vs_name, timeout=5)
    if not expected_error:
        # getting all se uuid list only when to_new_se flag is set
        se_uuid_list = get_all_se_uuid() if to_new_se else None
        event_dict = get_event_logs(["VS_SCALEOUT_COMPLETE", "VS_SCALEOUT_FAILED"])

        # get the vips state before scaleout operation
        vips_state_dict = vs_pre_scale.get_vips_state()

        event_history = vs_pre_scale.get_vs_event_history(vip_id)    # storing event history logs

    data = get_scaleout_api(vip_id, to_se_uuid, to_new_se, admin_up, host_name)
    try:
        resp_code, resp_data = rest.post('virtualservice', name=vs_name, path='scaleout', data=json.dumps(data))
    except Exception as e:
        # checking for expected error string
        if expected_error:
            logger.debug("Error: %s" % str(e))
            if expected_error in str(e):
                logger.info("Expected error message successfully found")
                vs_pre_scale.verify_scaleout_not_in_progress(vip_id)
                return True
            fail('vs[%s:%s] scaleout: Expected error: [%s] not found' % (vs_name, vip_id, expected_error))
        else:
            fail('vs[%s:%s] scaleout Error: [%s]' % (vs_name, vip_id, str(e)))

    # if expected_error is True and no error is found then raising exception
    if expected_error:
        fail('vs[%s:%s] Expected error: [%s] not found' % (vs_name, vip_id, expected_error))

    #vs_pre_scale.verify_scaleout_in_progress(vip_id)    # verify scaleout is triggered
    # return after triggering scaleout if wait is False
    if not wait:
        return vs_pre_scale

    vs_pre_scale.wait_until_vs_scaleout_complete(vip_id)

    # storing vs state after scaleout operation
    vs_post_scale = VsWellnessCheck(vs_name, timeout=5)

    # num requested and assigned SE increases by 1 when SCALEOUT_SUCCESS
    if not (scaleout_rollback or admin_up):
        vips_state_dict[vip_id]['num_se_requested'] += 1
        vips_state_dict[vip_id]['num_se_assigned'] += 1

    try:
        verify_last_scaleout_status(vips_state_dict, vs_post_scale, vip_id, to_se_uuid,
                                scaleout_rollback, to_new_se, admin_up, se_uuid_list)

        # creating list of arguments for vs_is_well function
        arg_list = get_vs_wellness_args(vips_state_dict)
        vs_wellness_check(vs_name, arg_list, timeout=5)

        # checking the event logs increament
        if scaleout_rollback:
            get_event_id_based_log_should_increase_v2('VS_SCALEOUT_FAILED', event_dict['VS_SCALEOUT_FAILED'],
                                                  start_time=event_dict['VS_SCALEOUT_FAILED']['start'])
        else:
            get_event_id_based_log_should_increase_v2('VS_SCALEOUT_COMPLETE', event_dict['VS_SCALEOUT_COMPLETE'],
                                                  start_time=event_dict['VS_SCALEOUT_COMPLETE']['start'])
        # verify events generated for scaleout operation
        vs_post_scale.verify_scaleout_event_history_logs(event_history, vip_id, to_se_uuid,
                                                     scaleout_rollback, admin_up)
    except Exception as e:
        logger.debug(traceback.format_exc())
        error('vs[%s:%s] Error: %s' % (vs_name, vip_id, str(e)))
    return vs_post_scale


def verify_last_scaleout_status(vips_state_dict, vs_post_scale, vip_id, to_se_uuid,
                                scaleout_rollback, to_new_se, admin_up, se_uuid_list):
    """
    verifies last scaleout operation status
    :param vips_state_dict: vip summary info before scaleout
    :param vs_post_scale: VsWellnessCheck object after scaleout
    :param vip_id: index to fetch vip_summary data
    :param to_se_uuid: SE uuid on which scaleout should be done
    :param scaleout_rollback: flag for SCALEOUT_ROLLBACK state
    :param to_new_se: useful for write access to spin up new se
    :param se_uuid_list: useful when to_new_se flag is set
    :return: True on successful otherwise raising an exception
    """
    # taking last scale status data from vs_post_scale vs object
    last_scale_status = vs_post_scale.get_vip_summary(vip_id)['last_scale_status']

    # checking SCALEOUT_ROLLBACK state when scaleout_rollback flag is set
    if scaleout_rollback:
        vs_post_scale.verify_last_scale_state(vip_id, 'SCALEOUT_ROLLBACK', last_scale_status['state'])
    else:    # checking SCALEOUT_SUCCESS state
        vs_post_scale.verify_last_scale_state(vip_id, 'SCALEOUT_SUCCESS', last_scale_status['state'])

    # checking for SCALEOUT_ADMINUP action when admin_up flag is set
    if admin_up:
        vs_post_scale.verify_last_scale_action(vip_id, 'SCALEOUT_ADMINUP', last_scale_status['action'])

    # verifying number of requested and assigned SE's
    vs_post_scale.verify_num_req_se(vip_id, vips_state_dict[vip_id]['num_se_requested'],
                                    last_scale_status['num_se_requested'])
    vs_post_scale.verify_num_assigned_se(vip_id, vips_state_dict[vip_id]['num_se_assigned'],
                                         last_scale_status['num_se_assigned'])

    # check for scale_se for auto in case of SCALEOUT_ROLLBACK
    if scaleout_rollback:
        if to_se_uuid:
            se_uuid = get_uuid_by_name('serviceengine',
                                       last_scale_status['scale_se'])
            if se_uuid != to_se_uuid:
                fail('vs[%s:%s] scale se should be [%s]' % (
                vs_post_scale.vs_name, vip_id, to_se_uuid))
        elif last_scale_status['scale_se'] != 'auto':
            fail('vs[%s:%s] scale se should be [auto] in case of SCALEOUT_ROLLBACK' %
                               (vs_post_scale.vs_name, vip_id))
    else:
        # getting se_uuid from se_name taken from last_scale_status data
        se_uuid = get_uuid_by_name('serviceengine', last_scale_status['scale_se'])
        # checking if last scale se matches expected se
        if to_se_uuid and se_uuid != to_se_uuid:
            fail('vs[%s:%s] not scaled out to expected se[%s]' %
                               (vs_post_scale.vs_name, vip_id, to_se_uuid))
        elif to_new_se and se_uuid in se_uuid_list:    # new SE should be spin up in write access
            fail('vs[%s:%s] not scaled out to new se' %
                               (vs_post_scale.vs_name, vip_id))
        else:
            se_list = list()
            # getting se list before scaleout operation triggered
            if vips_state_dict[vip_id]['oper_state'] == 'OPER_UP':
                se_list = [service_engine['uuid'] for service_engine in vips_state_dict[vip_id]['service_engine']]

            # checking if VS is placed on new SE
            if se_uuid in se_list:
                fail('vs[%s:%s] not scaled out to new se' % (vs_post_scale.vs_name, vip_id))
            logger.info('vs[%s:%s] scaled out to new se %s' % (vs_post_scale.vs_name, vip_id, se_uuid))

    # checking scaleout start and end time of scaleout operation
    vs_post_scale.verify_last_scale_start_end_time(vip_id, last_scale_status['start_time_str'],
                                                   last_scale_status['end_time_str'])
    return True


def get_scalein_api(vip_id, se_uuid, primary, admin_down):
    data = {'vip_id': vip_id}
    if se_uuid:
        # adding from_se_ref parameter when se uuid given
        data['from_se_ref'] = se_uuid
    else:
        data['scalein_primary'] = True if primary else False

    if admin_down:
        data['admin_down'] = 'true'
    return data


def scalein_v2(vs_name, vip_id='0', primary=0, se_uuid=None, expected_error=None,
               admin_down=False, wait=True):
    """
    function does scalein operation.
    :param vs_name: name of VS on which scaleout operation will be triggered
    :param vip_id: index to fetch vip_summary data and also used to trigger scalein operation
    :param primary: specify if scalein SE should be primary or not
    :param se_uuid: SE uuid from which scalein should be performed
    :param expected_error: expected error message
    :param wait: flag to wait untill scaleout operation get finished
    :return:
    """
    # storing vs state before scalein operation
    vs_pre_scale = VsWellnessCheck(vs_name, timeout=5)
    if not expected_error:
        event_dict = get_event_logs(["VS_SCALEIN_COMPLETE"])

        # get vips state before scalein operation
        vips_state_dict = vs_pre_scale.get_vips_state()

        event_history = vs_pre_scale.get_vs_event_history(vip_id)    # storing event history logs

    data = get_scalein_api(vip_id, se_uuid, primary, admin_down)
    try:
        resp_code, resp_data = rest.post('virtualservice', name=vs_name, path='scalein', data=json.dumps(data))
    except Exception as e:
        # checking for expected error string
        if expected_error: 
            logger.debug("Error: %s" % str(e))
            if expected_error in str(e):
                logger.info("Expected error message successfully found")
                vs_pre_scale.verify_scaleout_not_in_progress(vip_id)
                return True
            fail('vs[%s:%s] scalein: Expected error: [%s] not found' % (vs_name, vip_id, expected_error))
        else:
            fail('vs[%s:%s] scalein Error: [%s]' % (vs_name, vip_id, str(e)))

    # if expected_error is True and no error is found then raising exception
    if expected_error:
        fail('vs[%s:%s] Expected error: [%s] not found' % (vs_name, vip_id, expected_error))

    # setting primary flag when given SE is primary
    if se_uuid and vs_pre_scale.vs_get_primary_se_uuid(
            vip_id=vip_id) == se_uuid:
        primary = True

    # return after triggering scalein if wait is False
    if not wait:
        return vs_pre_scale

    vs_pre_scale.wait_until_vs_scalein_complete(vip_id)

    # storing vs state after scalein operation
    vs_post_scale = VsWellnessCheck(vs_name, timeout=5)

    # num requested and assigned SE decreases by 1 when SCALEIN_SUCCESS
    if not admin_down:
        # keeping num_se_assigned unchanged when dummy scalein operation
        if vips_state_dict[vip_id]['num_se_requested'] > vips_state_dict[vip_id]['num_se_assigned']:
            vips_state_dict[vip_id]['num_se_requested'] -= 1
        else:
            vips_state_dict[vip_id]['num_se_requested'] -= 1
            vips_state_dict[vip_id]['num_se_assigned'] -= 1

    try:
        verify_last_scalein_status(vs_pre_scale, vs_post_scale, vip_id, se_uuid,
                                   primary, admin_down, vips_state_dict)

        # creating list of arguments for vs_is_well function
        arg_list = get_vs_wellness_args(vips_state_dict)
        vs_wellness_check(vs_name, arg_list, timeout=5)

        # checking the event log increament
        get_event_id_based_log_should_increase_v2('VS_SCALEIN_COMPLETE', event_dict['VS_SCALEIN_COMPLETE'],
                                              start_time=event_dict['VS_SCALEIN_COMPLETE']['start'])
        # verify events genrated for scalein operation
        vs_post_scale.verify_scalein_event_history_logs(event_history, vip_id, se_uuid, admin_down, primary)
    except Exception as e:
        logger.debug(traceback.format_exc())
        error('vs[%s:%s] Error: %s' % (vs_name, vip_id, str(e)))
    return vs_post_scale


def verify_last_scalein_status(vs_pre_scale, vs_post_scale, vip_id, se_uuid,
                               primary, admin_down, vips_state_dict):
    """
    verifies last scalein operation status
    :param vs_pre_scale: VsWellnessCheck object before scalein
    :param vs_post_scale: VsWellnessCheck object after scalein
    :param vip_id: index to fetch vip_summary data
    :param se_uuid: SE uuid from which scalein should be done
    :param primary: flag to check if primary SE is scalein
    :param vips_state_dict: vip summary info before scalein
    :return: True on successful otherwise raising an exception
    """
    # taking last scale status data from vs_post_scale vs object
    last_scale_status = vs_post_scale.get_vip_summary(vip_id)['last_scale_status']
    vs_post_scale.verify_last_scale_state(vip_id, 'SCALEIN_SUCCESS', last_scale_status['state'])

    # verifying number of requested and assigned SE's
    vs_post_scale.verify_num_req_se(vip_id, vips_state_dict[vip_id]['num_se_requested'],
                                    last_scale_status['num_se_requested'])
    vs_post_scale.verify_num_assigned_se(vip_id, vips_state_dict[vip_id]['num_se_assigned'],
                                         last_scale_status['num_se_assigned'])

    # checking for SCALEOUT_ADMINDOWN action when admin_down flag is set, otherwise checking for SCALE_IN action
    if admin_down:
        vs_post_scale.verify_last_scale_action(vip_id, 'SCALEIN_ADMINDOWN', last_scale_status['action'])
    else:
        vs_post_scale.verify_last_scale_action(vip_id, 'SCALE_IN', last_scale_status['action'])

    # getting se_uuid from se_name taken from last_scale_status data
    scale_se_uuid = get_uuid_by_name('serviceengine', last_scale_status['scale_se'])
    if se_uuid and se_uuid != scale_se_uuid:    # checking if last scale se matches expected se
        fail('vs[%s:%s] scalein expected SE[%s] Failed' %
                           (vs_post_scale.vs_name, vip_id, se_uuid))
    else:
        primary_se = vs_pre_scale.vs_get_primary_se_uuid()
        if primary and primary_se != scale_se_uuid:    # verify if primary SE is scalein
            fail('vs[%s:%s] scalein primary SE[%s] Failed' %
                               (vs_post_scale.vs_name, vip_id, primary_se))
        elif not primary and primary_se == scale_se_uuid:    # verify primary should not be scalein
            fail('vs[%s:%s] primary SE[%s] should not be scalein' %
                               (vs_post_scale.vs_name, vip_id, primary_se))
    logger.info('vs[%s:%s] scale in SE[%s] successfully' % (vs_post_scale.vs_name, vip_id, scale_se_uuid))

    # verifying scalein start and end time
    vs_post_scale.verify_last_scale_start_end_time(vip_id, last_scale_status['start_time_str'],
                                                   last_scale_status['end_time_str'])
    return True


def get_migrate_api(vip_id='0', from_se=None, to_se=None):
    data = {'vip_id': vip_id}
    if from_se:
        data['from_se_ref'] = '/api/serviceengine/%s' % from_se
    if to_se:
        data['to_se_ref'] = '/api/serviceengine/%s' % to_se
    return data


def migrate_v2(vs_name, vip_id='0', from_se=None, to_se=None,
               expected_error=None, migrate_rollback=False, wait=True):
    """
    :param vs_name: name of VS on which migration operation will be triggered
    :param vip_id: vip id on which migration will happen
    :param from_se: VS will be migrated from this SE
    :param to_se: VS will be migrated to this SE
    :param expected_error: expected error message
    :param migrate_rollback: set True when rollback is expected
    :param wait: flag to wait for migration completion
    :return:
    """
    if not expected_error:
        primary = False
        event_dict = get_event_logs(["VS_MIGRATE_COMPLETE", "VS_SWITCHOVER",
                                     "VS_ADD_SE", "VS_REMOVED_SE", 'VS_MIGRATE_FAILED'])
        # storing vs state before migration
        vs_pre_migrate = VsWellnessCheck(vs_name, timeout=5)

        if not from_se:
            from_se = vs_pre_migrate.vs_get_primary_se_uuid(vip_id)

        if from_se == vs_pre_migrate.vs_get_primary_se_uuid(vip_id):
            primary = True    # setting primary flag when migrating primary

        # get vips state before migration
        vips_state_dict = vs_pre_migrate.get_vips_state()

        event_history = vs_pre_migrate.get_vs_event_history(vip_id)    # storing event history logs

    data = get_migrate_api(vip_id, from_se, to_se)
    logger.debug('migrate_vs params: %s' % json.dumps(data))
    try:
        resp_code, resp_data = rest.post('virtualservice', name=vs_name,
                                         path='migrate', data=json.dumps(data))
    except Exception as e:
        # checking for expected error string
        if expected_error:
            logger.debug("Error: %s" % str(e))
            if expected_error in str(e):
                logger.info("Expected error message successfully found")
                return True
            fail('vs[%s:%s] migrate: Expected error: [%s] not found' % (vs_name, vip_id, expected_error))
        else:
            fail('vs[%s:%s] scalein Error: [%s]' % (vs_name, vip_id, str(e)))

    # if expected_error is True and no error is found then raising exception
    if expected_error:
        fail('vs[%s:%s] Expected error: [%s] not found' % (vs_name, vip_id, expected_error))

    # return after triggering migration if wait is False
    if not wait:
        return vs_pre_migrate

    vs_pre_migrate.wait_until_vs_migration_complete(vip_id)

    # storing vs state after migration
    vs_post_migrate = VsWellnessCheck(vs_name, timeout=5)

    try:
        verify_last_migration_status(vs_post_migrate, vip_id, from_se,
                                 to_se, migrate_rollback, vips_state_dict)

        # creating list of arguments for vs_is_well function
        arg_list = get_vs_wellness_args(vips_state_dict)
        vs_post_migrate = vs_wellness_check(vs_name, arg_list, timeout=5)

        # checking the event logs increament
        if migrate_rollback:
            get_event_id_based_log_should_increase_v2('VS_MIGRATE_FAILED', event_dict['VS_MIGRATE_FAILED'],
                                                  start_time=event_dict['VS_MIGRATE_FAILED']['start'])
        else:
            get_event_id_based_log_should_increase_v2('VS_MIGRATE_COMPLETE', event_dict['VS_MIGRATE_COMPLETE'],
                                                  start_time=event_dict['VS_MIGRATE_COMPLETE']['start'])

        # verify events generated for migration
        vs_post_migrate.verify_migrate_event_history_logs(event_history, vip_id,
                                                          primary, from_se, to_se, migrate_rollback)

        # verify SE list of VS after migration
        vs_post_migrate.verify_vs_se_after_migrate(vs_pre_migrate, vip_id, primary, from_se, to_se, migrate_rollback)
    except Exception as e:
        logger.debug(traceback.format_exc())
        error('vs[%s:%s] Error: %s' % (vs_name, vip_id, str(e)))
    return vs_post_migrate


def verify_last_migration_status(vs_post_migrate, vip_id, from_se, to_se, migrate_rollback, vips_state_dict):
    """
    verifies last migrate operation status
    :param vs_post_migrate: VsWellnessCheck object after migration
    :param vip_id: index to fetch vip_summary data
    :param from_se: SE uuid from which migration should be done
    :param to_se: SE uuid to which migration should be done
    :param migrate_rollback: set True when rollback is expected
    :param vips_state_dict: vip summary info before migration
    :return: True on successful otherwise raising an exception
    """
    # taking last scale status data from vs_post_migarte vs object
    last_scale_status = vs_post_migrate.get_vip_summary(vip_id)['last_scale_status']

    if migrate_rollback:
        vs_post_migrate.verify_last_scale_action(vip_id, 'MIGRATE_SCALEOUT',
                                                 last_scale_status.get('action'))
        vs_post_migrate.verify_last_scale_state(vip_id, 'MIGRATE_SCALEOUT_ROLLBACK', last_scale_status['state'])
        if (from_se and to_se) and last_scale_status['scale_se'] != to_se:
            fail('vs[%s:%s] Expected rollback SE[%s] mismatched' % (vs_post_migrate.vs_name, vip_id, to_se))
    else:
        vs_post_migrate.verify_last_scale_state(vip_id, 'SCALEIN_SUCCESS', last_scale_status['state'])
        # getting se_uuid from se_name taken from last_scale_status data
        scale_se_uuid = get_uuid_by_name('serviceengine', last_scale_status['scale_se'])
        if (from_se and to_se) and from_se != scale_se_uuid:    # checking if last scale se matches expected se
            fail('vs[%s:%s] scalein expected SE[%s] Failed' %
                               (vs_post_migrate.vs_name, vip_id, from_se))
        logger.info('vs[%s:%s] scale in SE[%s] successfully' % (vs_post_migrate.vs_name, vip_id, scale_se_uuid))

    # verifying number of requested and assigned SE's
    vs_post_migrate.verify_num_req_se(vip_id, vips_state_dict[vip_id]['num_se_requested'],
                                    last_scale_status['num_se_requested'])
    vs_post_migrate.verify_num_assigned_se(vip_id, vips_state_dict[vip_id]['num_se_assigned'],
                                         last_scale_status['num_se_assigned'])

    # verifying scalein start and end time
    vs_post_migrate.verify_last_scale_start_end_time(vip_id, last_scale_status['start_time_str'],
                                                   last_scale_status['end_time_str'])
    return True


def vs_expect_scale_status(vs_name, vip_id, reason_string=None):
    """
    function does verification for scale_status for vs_summary
    :param vs_name: name of the vs for which need to verify the scale_status
    :param vip_id: index to fetch vip_summary data
    :param reason_string: to match the exact error_string in scale_status
    """
    vs_obj = VsWellnessCheck(vs_name, timeout=5)
    scale_status_data = vs_obj.get_vip_summary(vip_id)
    scale_status = scale_status_data.get('scale_status', None)

    if not scale_status:
        fail('vs[%s:%s] scale_status not set.' % (vs_name, vip_id))

    if scale_status['reason_code_string'] == reason_string:
        return True
    else:
        fail('vs[%s:%s] scale_status error string[%s] do not match with expected error string[%s]' %
             (vs_name, vip_id, scale_status['reason_code_string'], reason_string))


def se_disconnect_v2(vs_name=None, se_uuid=None, vip_id='0', primary=0, wait=True):
    if not (vs_name or se_uuid):
        raise RuntimeError("Invalid arguments. Either vs_name or se_uuid is needed")
    verify_history_events = False
    if vs_name and wait:
        verify_history_events = True
        vs_obj_pre = VsWellnessCheck(vs_name, 5)
        event_history = vs_obj_pre.get_vs_event_history(vip_id)  # storing event history logs before disconnecting se
        if not se_uuid:
            if primary:
                se_uuid = vs_obj_pre.vs_get_primary_se_uuid(vip_id=vip_id)
            else:
                se_uuid = vs_obj_pre.vs_get_secondary_se_uuid(vip_id=vip_id)
    se_vm = get_se_vm(se_uuid=se_uuid)
    se_name = map_se_uuid_to_name(se_uuid)
    event_dict = get_event_logs(['SE_HEARTBEAT_FAILURE'])

    se_disconnect_vm(se_vm[0])                   #disconnect se from controller
    if not wait:
        return
    wait_for_se_to_disconnect(se_name)
    se_summary = get_se_runtime_summary(se_uuid)

    try:
        summary_oper_state = se_summary['oper_status']['state']
    except KeyError, Argument:
        fail("## Oper status not available: %s" % Argument)

    if summary_oper_state != 'OPER_PARTITIONED':
        fail("summary_oper_state(%s) does not matches expected_oper_state(OPER_PARTITIONED)"
             % se_summary['oper_status']['state'])

    # verify SE_HEARTBEAT_FAILURE event should be generated
    get_event_id_based_log_should_increase_v2('SE_HEARTBEAT_FAILURE', event_dict['SE_HEARTBEAT_FAILURE'])

    if verify_history_events:
        vs_obj_post = VsWellnessCheck(vs_name, 5)
        # verify event history logs
        vs_obj_post.verify_se_disconnect_event_history_logs(event_history, se_uuid, vip_id)


def se_reconnect_v2(se_uuid, wait=True):
    # getting SE_UP event before se start
    event_dict = get_event_logs(["SE_UP"])
    pre_se_summary = get_se_runtime_summary(se_uuid)
    se_vm = get_se_vm(se_uuid=se_uuid)
    se_name = map_se_uuid_to_name(se_uuid)

    se_reconnect_vm(se_vm[0])      #reconnect se to controller

    if not wait:
        return
    wait_for_se_to_connect(se_name)

    se_summary = get_se_runtime_summary(se_uuid)

    try:
        summary_oper_state = se_summary['oper_status']['state']
    except KeyError, Argument:
        fail("## Oper status not available: %s" % Argument)

    if summary_oper_state != 'OPER_UP':
        fail("summary_oper_state(%s) does not matches expected_oper_state(OPER_UP)"
             % se_summary['oper_status']['state'])

    # verify that SE_UP event should be generated when se is connected after partitioned
    if pre_se_summary['oper_status']['state'] == 'OPER_PARTITIONED':
        get_event_id_based_log_should_increase_v2('SE_UP', event_dict['SE_UP'])
