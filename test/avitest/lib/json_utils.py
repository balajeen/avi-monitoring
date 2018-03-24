from avi_objects.infra_imports import *
import jsonpointer
import json
import avi_objects.logger_utils as logger_utils


def json_diff(doc1, doc2, name, *args, **kwargs):
    val1 = json_value(doc1, name, *args, **kwargs)
    val2 = json_value(doc2, name, *args, **kwargs)
    return int(val1) - int(val2)

def json_value(doc, name, *args, **kwargs):
    if (not isinstance(doc, dict) and
            not isinstance(doc, list)):
        doc = json.loads(doc)
    if isinstance(doc, list):
        for obj in doc:
            try:
                val = json_value(obj, name, *args, **kwargs)
                return val
            except:
                pass
        fail('Unable to find the field')
    else:
        pointer = get_json_pointer(doc, name, *args, **kwargs)
        val = jsonpointer.resolve_pointer(doc, pointer)
        return val

def get_json_pointer(doc, name, *args, **kwargs):
    if (not isinstance(doc, dict) and
            not isinstance(doc, list)):
        doc = json.loads(doc)
    field = kwargs.get('field', None)
    if field is not None:
        del kwargs['field']
    pointer = ''
    try:
        # Find the field in the doc
        jsonpointer.resolve_pointer(doc, field)
        pointer = field
    except:
        # Walk the dictionary and find the field. Ignore any list that is
        # found
        path = []
        if get_json_path(doc, name, path, field, 0, 0, *args, **kwargs) is False:
            raise RuntimeError('Unable to find the field')
        pointer = ''
        for p in path:
            pointer = pointer + '/' + p
    return pointer

def get_json_path(doc1, name, path, field, match_index, match_field,
                  *args, **kwargs):
    index = kwargs
    # print name, path, field
    for key, val in doc1.iteritems():
        # print key, val
        if isinstance(val, dict):
            path.append(key)
            # print path
            # print '*****Key = %s val = %s name = %s'%(key, val, name)
            if key == name and field is None and len(index) == 0:
                # Matched the structure that is being looked at
                return True
            if get_json_path(val, name, path, field,
                             1 if key == name and len(index) > 0 else 0,
                             1 if field is not None else 0, *args, **kwargs) is True:
                return True
            path.pop()
            # print path
        elif isinstance(val, list):
            path.append(key)
            if key == name and field is None and len(index) == 0:
                return True
            arr_index = 0
            while arr_index < len(val):
                path.append(str(arr_index))
                if isinstance(val[arr_index], dict) and \
                        get_json_path(val[arr_index], name, path, field,
                                      1 if key == name and len(
                                          index) > 0 else 0,
                                      1 if field is not None else 0, *args, **kwargs) is True:
                    return True
                arr_index = arr_index + 1
                path.pop()
            path.pop()
        else:
            # print "match_index %d match_field %d" % (match_index,
            # match_field)
            if match_index == 1:
                # Is this field part of the index
                index_field = index.get(key, None)
                # print "***** Index is %s and index_field is %s"% (index, index_field)
                # print "***** index_field %s val is %s" % (index_field,
                # str(val))
                if index_field is not None and index_field == str(val):
                    del index[key]

                if len(index) != 0:
                    # not a full match of index. continue searching
                    continue
                else:
                    # print '*****Index fully matched'
                    if field is None:
                        return True
                    # print doc1
                    return get_json_path(doc1, name, path, field,
                                         0, 1, *args)
            if match_field == 1 and len(index) == 0:
                # match for the field
                # print field
                if field is None:
                    return True
                tokens = field.split('/')
                if len(path) < len(tokens):
                    continue
                path.append(key)
                found = True
                for pos in xrange(1, len(tokens) + 1):
                    # print "**tokens compare %s : %s" %(path[-pos],
                    # tokens[-pos])
                    if path[-pos] != tokens[-pos]:
                        found = False
                        break
                if found is True:
                    # print "Field found"
                    # print path
                    return True
                else:
                    path.pop()
            elif key == name:
                path.append(key)
                # print 'Field found'
                return True
    return False


def compare_json(upgrade_history, status):
    for (key, value), (key2, value2) in zip(upgrade_history.items(), status.items()):
        if isinstance(value, dict):
            return compare_json(value, value2)
        if isinstance(value, list):
            for ele1, ele2 in zip(value, value2):
                if isinstance(ele1, dict):
                    compare_json(ele1, ele2)
                elif isinstance(ele1, list) and ele1 != ele2:
                    logger_utils.fail('upgrade_history != upgrade_status, failed {} : {}'.format(ele1, ele2))

        elif str(value).lower() != str(value2).lower():
            logger_utils.fail('upgrade_history != upgrade_status, failed {} : {'
                           '}'.format(key, value), '{} : {}'.format(key2, value2))

