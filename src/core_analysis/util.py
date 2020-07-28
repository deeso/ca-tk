import ctypes

from .core_structures_x86 import USER_REGSX32_STRUCT, USER_REGS32_STRUCT

def bytes_to_struct(data, struct_klass):
    return ctypes.cast(data, ctypes.POINTER(struct_klass)).contents


def handle_pyelftools_not_prstatusx_wierdness(note):
    struct_klass = ELF_PRSTATUS32X
    ssz = ctypes.sizeof(struct_klass)
    if note.get('n_type', '') == 'NT_PRSTATUS':
        reg_data = bytes([ord(i) for i in note['n_desc']])
        if len(reg_data) >= ssz:
            return bytes_to_struct(reg_data[-ssz:], struct_klass)
    return None

def extract_prstatusx_info(note):
    struct_klass = ELF_PRSTATUS32X
    ssz = ctypes.sizeof(struct_klass)
    if note.get('n_type', '') == 'NT_PRSTATUS':
        reg_data = bytes([ord(i) for i in note['n_desc']])
        if len(reg_data) >= ssz:
            return bytes_to_struct(reg_data[-ssz:], struct_klass)
    return None

def json_serialize_struct(strct):
    r = {}
    for f, ct in strct._fields_:
        v = getattr(strct, f)
        if isinstance(v, (ctypes.Structure, ctypes.Union)):
            r[f] = json_serialize_struct(v)
        else:
            r[f] = v
    return r

def serialize_prstatusx_note(note, idx=0):
    s = extract_prstatusx_info(note)
    r = json_serialize_struct(s) if s is not None else {}
    for k in note:
        if k == 'n_desc':
            continue
        r[k] = note[k]
    r['index'] = idx
    return r

def serialize_x86_state_note(note, idx=0):
    s = extract_x86_state_info(note)
    r = json_serialize_struct(s) if s is not None else {}
    for k in note:
        if k == 'n_desc':
            continue
        r[k] = note[k]
    r['index'] = idx
    return r


def serialize_prstatusx_notes(notes):
    prstatusx_notes = []
    idx = 0
    for note in notes:
        if note.get('n_type', '') == 'NT_PRSTATUS':
            prstatusx_notes.append(serialize_prstatusx_note(note, idx))
            idx += 1
    return prstatusx_notes