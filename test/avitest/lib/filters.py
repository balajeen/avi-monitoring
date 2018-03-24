

def get_field_value(data, field_passed, return_single=False, ignore_nested=False):
    if type(data) == list:
        data = data[0]
    for field in data:
        if field == field_passed:
            if return_single is True and type(data[field]) == list:
                return data[field][0]
            else:
                return data[field]
        elif ignore_nested:
            continue
        elif type(data[field]) == dict:
            response = get_field_value(data[field], field_passed)
            if response:
                return response
    return False