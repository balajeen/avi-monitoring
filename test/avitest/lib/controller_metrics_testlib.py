import lib.metrics_lib as metrics_lib
import avi_objects.logger_utils as logger_utils
import avi_objects.rest as rest
from string import Template


lic_usage_uri = Template('licenseusage?${options}')


def license_api_sanity(**kwargs):
    """
    Check the license usage API for sanity
    :param kwargs: type dict
    :return: None
    """

    query_options = metrics_lib.generate_query_string(kwargs)
    path = lic_usage_uri.substitute(options=query_options)
    _, results = rest.get(path)
    # Check if the license usage numbers match the expectations
    for k, v in kwargs.iteritems():
        metric_name = '_'.join(k.split('_')[1:])
        enterprise_18_lic_usage = results['pertier']['ENTERPRISE_18']
        if k == 'expected_num_tenants':
            metric_value = len(enterprise_18_lic_usage['pertenant'])
        else:
            metric_value = results.get(metric_name)

        if (metric_value is None) or (str(metric_value) != v):
            logger_utils.fail('k %s v %s m metric_name %s value %s' % (
                k, v, metric_name, metric_value))
    return
