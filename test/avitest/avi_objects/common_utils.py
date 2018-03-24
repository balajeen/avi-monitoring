import re
from avi_objects.logger_utils import fail, abort, error, asleep, aretry

def get_value_verify_unit(value, unit):
    match = re.search('([0-9]+)(\D+)', value)
    if match is None:
        fail(
            'No match was found in get_value_verify_unit,' +
            ' value: %s, unit: %s' % (value, unit))
    value_val = int(match.group(1))
    value_unit = match.group(2)
    if isinstance(unit, basestring):
        if not value_unit == unit:
            fail(
                'Value <%s> should end with <%s>. Ex: "100ms"' % (value, unit))
    else:
        if value_unit not in unit:
            fail(
                'Value <%s> should end with one of %s. Ex: "100ms" or "10 percent"' %
                (value, unit))
    return value_val

def median(data):
    '''
    Returns the middle pont of the sorted data if it is odd length
      or the average of the two middle points if it is even length
    '''
    l = len(data)
    if l is 0:
        fail('data must contain at least 1 point')
    data_sorted = sorted(data)
    index = l / 2
    if l % 2 is 0:
        first = data_sorted[index - 1]
        second = data_sorted[index]
        return float(first + second) / 2
    else:
        return data_sorted[index]

    return data_sorted

def q1_median_q3(data):
    '''
      Returns the q1, median and q3 of the sorted data
      (used for finding outliers)
      Best used with 10+ data points
      http://www.wikihow.com/Calculate-Outliers
      ex: data = [1, 2, 3, 4, 5]
      q1 = 1.5
      median = 3
      q3 = 3.5
    '''
    l = len(data)
    if l < 2:
        fail('data must contain at least 2 points')
    data_sorted = sorted(data)
    med = median(data_sorted)
    mid = l / 2
    q1 = median(data_sorted[:mid])
    q3 = median(data_sorted[-mid:])
    return (q1, med, q3)
