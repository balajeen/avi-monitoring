import avi_objects.rest as rest

def get_inventory_config(obj_type, obj_name, include_name=False):
    params = {'include_name': include_name}
    status_code, response = \
        rest.get(obj_type + "-inventory", name=obj_name, params=params)
    return response

