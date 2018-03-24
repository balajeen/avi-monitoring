import pytest
from logger_utils import asleep
from logger import logger
from cleanup import cleanup_client_and_servers
from avi_objects.traffic_manager import (traffic_start,
                                     traffic_get_stats,
                                     traffic_stop)
from suite_vars import suite_vars

@pytest.fixture(scope="function")
def traffic_test_case(request):
    """ Traffic fixture - Start Traffic on all VS which are present """
    logger.info("STARTING TRAFFIC")
    traffic_obj = traffic_start()
    asleep(msg="Starting the traffic and waiting to settle", delay = 5)
    def traffic_teardown():
        traffic_get_stats(traffic_obj)
        logger.info("STOPPING TRAFFIC")
        traffic_stop()
    request.addfinalizer(traffic_teardown)
    return traffic_obj

@pytest.fixture(scope="function", autouse=False)
def cleanup_client_server(request):
    if not suite_vars.skip_create_config:
        logger.info("Cleaning Client and Server")
        cleanup_client_and_servers()
    else:
        logger.info("Skipping Cleaning Client and Server for skip_create_config is set to True")
