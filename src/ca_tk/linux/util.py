import copy
import ctypes
from .consts import *


def bytes_to_struct(data, struct_klass):
    tmp = ctypes.cast(data, ctypes.POINTER(struct_klass)).contents
    # there is an odd bug, but the data gets corrupted if we
    # return directly after the cast, so we create a deep copy
    # and return that value
    # Note if there are any pointers in the struct it will fail
    # https://stackoverflow.com/questions/1470343/python-ctypes-copying-structures-contents
    dst = copy.deepcopy(tmp)
    return dst

def json_serialize_struct(strct):
    r = {}
    for f, ct in strct._fields_:
        v = getattr(strct, f)
        if isinstance(v, (ctypes.Structure, ctypes.Union)):
            r[f] = json_serialize_struct(v)
        else:
            r[f] = v
    return r


