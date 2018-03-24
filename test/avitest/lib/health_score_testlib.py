import pytz
import avi_objects.logger_utils as logger_utils
from avi_objects.logger import logger
from datetime import datetime


def hs_next_computation(now=None, step=300, step_times=1):
    """

    :param now:
    :param step:
    :param step_times:
    :return:
    """

    if not now:
        now = datetime.utcnow().replace(tzinfo=pytz.UTC)
    epoch = (datetime.utcfromtimestamp(0)).replace(tzinfo=pytz.UTC)
    from_epoch = (now - epoch).total_seconds()
    ts_offset = step - (from_epoch % step) + 30
    # Adjust for step times
    ts_offset += (step_times - 1) * step
    return ts_offset


def wait_for_next_hs_computation(now=None, step=300, step_times=1):
    """

    :param now:
    :param step:
    :param step_times:
    :return:
    """

    time_to_wait = hs_next_computation(now, step, int(step_times))
    logger.info('Sleeping for hs computation for %s secs' % time_to_wait)
    logger_utils.asleep(delay=time_to_wait)
    return
