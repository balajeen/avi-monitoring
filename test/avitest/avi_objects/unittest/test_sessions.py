import pytest
from avi_objects.logger import logger
import avi_objects.rest as rest
from avi_objects.infra_utils import clear_session, get_config, switch_mode
import json

@pytest.fixture(scope="function")
def create_new_user():
    switch_mode(user='admin', password='avi123')
    clear_session()
    user_data = json.dumps({
        'full_name': 'testuser1',
        'is_active': True,
        'password': 'avi123',
        'username': 'testuser1',
        'access': [{
            'role_ref': "/api/role/?name=System-Admin",
            'tenant_ref': "/api/tenant/?name=admin",
        }],
    })
    rest.post('user', data=user_data)

    yield

    switch_mode(user='admin', password='avi123')
    clear_session()
    rest.delete('user', name='testuser1')

class TestSession():

    def test_clear_session_basic(self):
        '''
            test_clear_session_basic
                - Test the basic usage of clear_session api
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
            test_clear_session_two_users
                - Test clear_session with two user sessions
                - When all_sessions=True is passed, all the existing sessions should be removed
        '''
        switch_mode(user='admin', password='avi123')
        rest.get('serviceengine')
        config = get_config()
        context_key_admin = config.get_context_key()

        switch_mode(user='testuser1', password='avi123')
        rest.get('serviceengine')
        context_key_test_user = config.get_context_key()

        assert context_key_test_user in config.sessions and context_key_admin in config.sessions
        clear_session()
        assert context_key_test_user not in config.sessions and context_key_admin in config.sessions
        rest.get('serviceengine')
        assert context_key_test_user in config.sessions and context_key_admin in config.sessions
        clear_session(all_sessions=True)
        assert context_key_test_user not in config.sessions and context_key_admin not in config.sessions
        clear_session(all_sessions=True)

    def test_clear_session_making_get_request(self):
        '''
            test_clear_session_making_get_requests
                - Make a get request after clear_session and verify that the request uses mode user and password
        '''
        switch_mode(user='admin', password='avi123')
        rest.get('serviceengine')
        session = rest.get_session()
        
        switch_mode(password='Temp123')
        # This should pass because it uses already created session
        rest.get('serviceengine')
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
