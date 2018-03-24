import pytest
from avi_objects.logger import logger
import avi_objects.rest as rest
from avi_objects.infra_utils import clear_session, get_config, switch_mode, switch_mode_default, setup_cloud
from avi_objects.cluster import wait_until_n_cluster_nodes_ready
import json
import time
import urllib

@pytest.fixture(scope="function")
def create_new_user():
    switch_mode(user='admin', password='avi123')
    clear_session()
    user_data = json.dumps({
        'full_name': 'test-user-1',
        'is_active': True,
        'password': 'avi123',
        'username': 'test-user-1',
        'access': [{
            'role_ref': "/api/role/?name=System-Admin",
            'tenant_ref': "/api/tenant/?name=admin"
        }],
        'default_tenant_ref': "/api/tenant/?name=admin"
    })
    rest.post('user', data=user_data)
    clear_session()

    yield

    clear_session(all_sessions=True)
    switch_mode(user='admin', password='avi123')
    rest.delete('user', name='test-user-1')

class TestSession():

    def test_switch_mode_user(self, create_new_user):
        '''
            Switch mode user and test if the session is updated correctly based on mode user
        '''
        switch_mode(user='admin', password='avi123')
        se_1 = rest.get('serviceengine')
        session = rest.get_session()
        assert session.username == 'admin' and session.password == 'avi123'
        
        switch_mode(user='test-user-1')
        se_2 = rest.get('serviceengine')
        session = rest.get_session()
        assert se_1 == se_2
        assert session.username == 'test-user-1' and session.password == 'avi123'
        clear_session(all_sessions=True)


    def test_switch_mode_password(self):
        '''
            switch mode password and test if the session is updated correctly based on mode password
        '''
        switch_mode(user='admin', password='avi123')
        rest.get('serviceengine')
        session = rest.get_session()
        assert session.username == 'admin' and session.password == 'avi123'

        # REVIEW: switch_mode on password does nothing as of now
        switch_mode(password='Test123')
        try:
            rest.get('serviceengine')
        except Exception as e:
            logger.info("authentication error expected: " + str(e))
        else:
            assert 0, "Session is not getting updated based on password"
        clear_session()


    def test_switch_mode_session(self):
        '''
            switch mode session and test if the requests on the session go through correctly
        '''
        switch_mode(user='admin', password='avi123')
        session = rest.get_session()
        clear_session()
        switch_mode(password='Temp123')
        try:
            rest.get('serviceengine')
        except Exception as e:
            logger.info("authentication error expected: " + str(e))
        else:
            assert 0, "Session is not getting updated based on password"
        switch_mode(session=session)
        rest.get('serviceengine')

        # REVIEW: Once session in mode is set, no further switch_mode works
        switch_mode(user='test-user-1', password='Temp123')
        try:
            rest.get('serviceengine')
        except Exception as e:
            logger.info("authentication error expected: " + str(e))
        else:
            assert 0, "Once switched on session, no other switch mode works"
        clear_session(all_sessions=True)


    def test_update_admin_user(self, create_new_user):
        '''
            Test update_admin_user
                - Test if it updates the user password correctly
                - Test if it updates the user password correctly when mode user is not the same as the passed username
        '''
        switch_mode(user='test-user-1', password='avi123')
        se_1 = rest.get('serviceengine')
        rest.update_admin_user('test-user-1', 'Test123', 'avi123')
        clear_session()

        # REVIEW:
        #   when the passed username to update_admin_user is not the same as mode user
        #       - update_admin_user fails
        #       - Also, sets wrong password on the mode
        # Should this be fixed?
        switch_mode(user='admin', password='avi123')
        rest.update_admin_user('test-user-1', 'avi123', 'Test123')

        switch_mode(user='test-user-1', password='avi123')
        se_2 = rest.get('serviceengine')
        assert se_1 == se_2


    def test_update_admin_user_performance(self):
        '''
            Test update admin user performance
                Reports time taken for update_admin_user when
                    - the admin user password is already set to avi123 correctly
                    - the admin user password needs to be changed to avi123
        '''
        switch_mode(user='admin', password='avi123')
        ts = time.time()
        rest.update_admin_user('admin', 'avi123', 'admin')
        logger.info("Password is already avi123 - update_admin_user took %2.2f seconds" % (
                    time.time() - ts
        ))

        rest.update_admin_user('admin', 'admin', 'avi123')
        switch_mode(user='admin', password='avi123')
        ts = time.time()
        rest.update_admin_user('admin', 'avi123', 'admin')
        logger.info("updating password to avi123 - update_admin_user took %2.2f seconds" % (
                    time.time() - ts
        ))
        rest.update_admin_user('admin', 'avi123', 'admin')


    def test_get_session(self, create_new_user):
        '''
            Test get_session
                - Test if it returns the already created session if it exists
                - If there is no already created session, it should create a new session and return
        '''
        switch_mode(user='test-user-1', password='avi123')
        se_1 = rest.get('serviceengine')
        session_test_user = rest.get_session()

        switch_mode(user='admin', password='avi123')
        rest.get('serviceengine')
        session = rest.get_session()
        assert session.username == 'admin' and session.password == 'avi123'

        switch_mode(user='test-user-1')
        se_2 = rest.get('serviceengine')
        session = rest.get_session()
        assert session is session_test_user and se_1 == se_2
        clear_session(all_sessions=True)


    def test_create_session(self, create_new_user):
        '''
            Test create_session
                - Test if create_sesion returns the correct session in various modes
        '''
        switch_mode(user='test-user-1', password='avi123')
        session = rest.create_session()
        assert session.username == 'test-user-1' and session.password == 'avi123'
        session.get('serviceengine')

        switch_mode(user='admin', password='avi123')
        session = rest.create_session()
        assert session.username == 'admin' and session.password == 'avi123'
        session.get('serviceengine')


    def test_clear_session_basic(self):
        '''
            Basic usage of clear_session
        '''
        switch_mode(user='admin', password='avi123')
        rest.get('serviceengine')
        config = get_config()
        session = rest.get_session()
        switch_mode(session=session)
        assert config.sessions and config.session

        clear_session()
        config = get_config()
        context_key = config.get_context_key()
        assert config.session is None and context_key not in config.sessions


    def test_clear_session_two_users(self, create_new_user):
        '''
            Test clear_session
                - By default, clear_session() clears the current mode's session
                - When all_sessions=True is passed, it should clear all existing sessions
        '''
        switch_mode(user='admin', password='avi123')
        rest.get('serviceengine')
        config = get_config()
        context_key_admin = config.get_context_key()

        switch_mode(user='test-user-1', password='avi123')
        se_1 = rest.get('serviceengine')
        context_key_test_user = config.get_context_key()

        assert context_key_test_user in config.sessions and context_key_admin in config.sessions
        clear_session()
        assert context_key_test_user not in config.sessions and context_key_admin in config.sessions
        se_2 = rest.get('serviceengine')
        assert se_1 == se_2
        assert context_key_test_user in config.sessions and context_key_admin in config.sessions
        clear_session(all_sessions=True)
        assert context_key_test_user not in config.sessions and context_key_admin not in config.sessions
        clear_session(all_sessions=True)


    def test_clear_session_making_get_request(self):
        '''
            Test if get() requests work as expected after clearing sessions
        '''
        switch_mode(user='admin', password='avi123')
        se_1 = rest.get('serviceengine')
        session = rest.get_session()
        
        switch_mode(password='Temp123')
        # This should pass because it uses already created session
        se_2 = rest.get('serviceengine')
        assert se_1 == se_2
        clear_session()
        try:
            # This should fail during authentication(uses password Temp123)
            rest.get('serviceengine')
        except Exception as e:
            logger.info('Authentication failure expected: ' + str(e))
        else:
            assert 0, 'Sessions are not cleared, Still using password avi123'

        switch_mode(password='avi123')
        clear_session()


    def test_controller_goes_down(self):
        '''
            Test the request on sessions if the controller goes down
            Does the request on the sessions work when the controller comes back up
        '''
        switch_mode(user='admin', password='avi123')
        logger.info('Configuring cloud, This may take sometime..')
        setup_cloud(wait_for_cloud_ready=True)
        config = get_config()
        mode = config.get_mode()
        controller = config.get_vm_of_type('controller')[0]
        session = rest.get_session()
        data_1 = rest.get('serviceengine')

        cloud_obj = config.testbed[mode['site_name']].cloud_obj[mode['cloud']]
        controller_name = controller.name
        cloud_obj.powerOffVM(controller_name)
        try:
            rest.get('serviceengine')
        except Exception as e:
            logger.info('Expected ReadTimeout: ' + str(e))
        cloud_obj.powerOnVM(controller_name)
        wait_until_n_cluster_nodes_ready()
        data_2 = rest.get('serviceengine')
        assert data_1 == data_2


    def test_session_expiry(self):
        '''
            Tests requests on expired sessions
        '''
        switch_mode(user='admin', password='avi123')
        data = json.dumps({
            'api_idle_timeout' : 1
        });
        rest.put('controllerproperties', data=data)
        clear_session()
        data_1 = rest.get('serviceengine')
        time.sleep(2*60)
        data_2 = rest.get('serviceengine')
        assert data_1 == data_2
        time.sleep(21*60)
        data_1 = rest.get('serviceengine')
        assert data_1 == data_2


    def test_get_cloud_context(self):
        '''
            Test get_cloud_context
        '''
        switch_mode(user='admin', password='avi123')
        cloud_old = rest.get_cloud_context()
        switch_mode(cloud='Vmware-Cloud')
        cloud = rest.get_cloud_context()
        assert cloud == 'Vmware-Cloud'
        switch_mode(cloud=cloud_old)


    def test_get_api_version(self):
        '''
            Test get_api_version
        '''
        switch_mode(user='admin', password='avi123')
        version_old = rest.get_api_version() 
        switch_mode(version='17.2.5')
        version = rest.get_api_version()
        assert version == '17.2.5'
        switch_mode_default()
        version = rest.get_api_version()
        assert version == version_old
        switch_mode(version=version_old)


    @pytest.mark.parametrize("obj_type,obj_name", [
        ('role', 'System-Admin'),
        ('tenant', 'admin'),
        ('user', 'admin')
    ])
    def test_get_obj_api(self, obj_type, obj_name):
        '''
            Test get_obj_ref, get_uuid_from_ref, get_name_from_ref, get_uuid_by_name, get_name_by_uuid
        '''
        obj_url = rest.get_obj_ref(obj_type, obj_name)
        uuid_from_url = rest.get_uuid_from_ref(obj_url)
        name_from_url = rest.get_name_from_ref(obj_url)
        name_from_url_uuid = rest.get_name_by_uuid(obj_type, uuid_from_url)
        assert name_from_url == name_from_url_uuid == obj_name

        uuid_from_name_1 = rest.get_uuid_by_name(obj_type, name_from_url)
        uuid_from_name_2 = rest.get_uuid_by_name(obj_type, name_from_url_uuid)
        assert uuid_from_name_1 == uuid_from_url == uuid_from_name_2


    @pytest.mark.parametrize("querydict", [
        ({'id': 1, 'name': 'name', 'value': 'value'}),
        ({'id': 2, 'specialchars': '-&#*^%@!()~`'}),
    ])
    def test_get_query_params(self, querydict):
        '''
            Test get_query_params
        '''
        # Testcase failing for specialchars inside names, will this cause issues?
        # REVIEW: should we remove get_query_params and use urllib.urlencode
        query_from_urllib = urllib.urlencode(querydict)
        query_from_api = rest.get_query_params(querydict)
        assert query_from_urllib == query_from_api
