import copy
import ctypes

from .core_structures_x86 import USER_REGSX32_STRUCT, USER_REGS32_STRUCT, 
                                 ELF_PRSTATUS32X, ELF_PRSTATUS32X_WITH_UNUSED,
                                 ELF_PRSTATUS32, ELF_PRSTATUS32_WITH_UNUSED,
                                 AMD64_XSAVE, SIGINFO

MASK_64_BITS = 0xffffffffffffffff
MASK_16_BITS = 0xffff

def bytes_to_struct(data, struct_klass):
    tmp = ctypes.cast(data, ctypes.POINTER(struct_klass)).contents
    # there is an odd bug, but the data gets corrupted if we
    # return directly after the cast, so we create a deep copy
    # and return that value
    # Note if there are any pointers in the struct it will fail
    # https://stackoverflow.com/questions/1470343/python-ctypes-copying-structures-contents
    dst = copy.deepcopy(tmp)
    return dst

def handle_pyelftools_not_prstatusx_wierdness(note):
    struct_klass = ELF_PRSTATUS32X
    ssz = ctypes.sizeof(struct_klass)
    if note.get('n_type', '') == 'NT_PRSTATUS':
        reg_data = bytes([ord(i) for i in note['n_desc']])
        if len(reg_data) >= ssz:
            return bytes_to_struct(reg_data[-ssz:], struct_klass)
    return None

def extract_prstatus_info(note):
    struct_klass = ELF_PRSTATUS32X
    ssz = ctypes.sizeof(struct_klass)
    if note.get('n_type', '') == 'NT_PRSTATUS':
        reg_data = bytes([ord(i) for i in note['n_desc']])
        if len(reg_data) == ctypes.sizeof(ELF_PRSTATUS32X):
            return bytes_to_struct(reg_data, ELF_PRSTATUS32X)
        elif len(reg_data) == ctypes.sizeof(ELF_PRSTATUS32X_WITH_UNUSED):
            return bytes_to_struct(reg_data, ELF_PRSTATUS32X_WITH_UNUSED)
        elif len(reg_data) == ctypes.sizeof(ELF_PRSTATUS32_WITH_UNUSED):
            return bytes_to_struct(reg_data, ELF_PRSTATUS32_WITH_UNUSED)
        elif len(reg_data) == ctypes.sizeof(ELF_PRSTATUS32):
            return bytes_to_struct(reg_data, ELF_PRSTATUS32)
    return None

def extract_x86_state_info(note):
    struct_klass = AMD64_XSAVE
    ssz = ctypes.sizeof(struct_klass)
    if note.get('n_type', '') == 514 or note.get('n_type', '') == 'NT_X86_XSTATE' :
        reg_data = bytes([ord(i) for i in note['n_desc']])
        if len(reg_data) >= ssz:
            return bytes_to_struct(reg_data, struct_klass)
    return None

def extract_siginfo_info(note):
    struct_klass = SIGINFO
    ssz = ctypes.sizeof(struct_klass)
    if note.get('n_type', '') == 0x53494749 or note.get('n_type', '') == 'NT_SIGINFO' :
        reg_data = bytes([ord(i) for i in note['n_desc']])
        if len(reg_data) >= ssz:
            return bytes_to_struct(reg_data, struct_klass)
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


def serialize_x86_state_note(note, idx=0):
    s = extract_x86_state_info(note)
    r = json_serialize_struct(s) if s is not None else {}

    # serialize st* and xmm*
    keys = ["st{}".format(i) for i in range(0, 8)] + \
           ["xmm{}".format(i) for i in range(0, 16)]
    
    for k in keys:
        a = getattr(s, k)
        if k.find('st') == 0:
            v = int("0x{:016x}{:016x}".format(a[1] & MASK_16_BITS, a[0] ), 16)
            raw_v = int("0x{:016x}{:016x}".format(a[1], a[0] ), 16)
            # fix me value needs to remove 
            r[k] = v
            r[k+'_raw'] = raw_v
        else:
            v = int("0x{:016x}{:016x}".format(a[1], a[0]), 16)
            r[k] = v

    for k in note:
        if k == 'n_desc':
            continue
        r[k] = note[k]
    r['idx'] = idx
    r['n_type'] = 'NT_X86_XSTATE,'
    return r

def serialize_prstatus_notes(notes):
    prstatusx_notes = []
    idx = 0
    for note in notes:
        if note.get('n_type', '') == 'NT_PRSTATUS':
            prstatusx_notes.append(serialize_prstatus_note(note, idx))
            idx += 1
    return prstatusx_notes

def serialize_prstatus_note(note, idx=0):
    s = extract_prstatus_info(note)
    r = json_serialize_struct(s) if s is not None else {}
    for k in note:
        if k == 'n_desc':
            continue
        r[k] = note[k]
    r['idx'] = idx
    return r


def serialize_siginfo_note(note, idx=0):
    s = extract_siginfo_info(note)
    r = json_serialize_struct(s) if s is not None else {}
    for k in note:
        if k == 'n_desc':
            continue
        r[k] = note[k]
    snum = r['si_signo']
    if snum in SIGNAL_LABELS:
        r['signal'] = SIGNAL_LABELS[snum]
        if snum in SIGNAL_ATTR:
            attr = SIGNAL_ATTR[snum]
            l = json_serialize_struct(getattr(s['_sigfields'], attr))
            if l:
                r.update(l)
    r['idx'] = idx
    return r
