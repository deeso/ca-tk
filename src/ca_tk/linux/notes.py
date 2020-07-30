import copy
import ctypes

from .core_structures_x86 import USER_REGSX32_STRUCT, USER_REGS32_STRUCT, 
                                 ELF_PRSTATUS32X, ELF_PRSTATUS32X_WITH_UNUSED,
                                 ELF_PRSTATUS32, ELF_PRSTATUS32_WITH_UNUSED,
                                 AMD64_XSAVE, SIGINFO, siginfo_signal_info64, 
                                 siginfo_signal_info, auxv_t, auxv_t_64,
                                 I387_FXSAVE

from .consts import *


class ExtractNoteDesc(object):

    @classmethod
    def extract_prstatus_info(cls, note):
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

    @classmethod
    def extract_x86_state_info(cls, note, is_amd64=True):
        #FIXME intentionally throw an error here, not sure we can handle i386 in the same way
        struct_klass = AMD64_XSAVE if is_amd64 else I387_FXSAVE
        ssz = ctypes.sizeof(struct_klass)
        if note.get('n_type', '') == 514 or note.get('n_type', '') == 'NT_X86_XSTATE' :
            reg_data = bytes([ord(i) for i in note['n_desc']])
            if len(reg_data) >= ssz:
                return bytes_to_struct(reg_data, struct_klass)
        return None

    @classmethod
    def extract_fpreg_state_info(cls, note, is_amd64=True):
        #FIXME intentionally throw an error here, not sure we can handle i386 in the same way
        struct_klass = AMD64_XSAVE if is_amd64 else I387_FXSAVE
        ssz = ctypes.sizeof(struct_klass)
        if note.get('n_type', '') == 514 or note.get('n_type', '') == 'NT_FPREGSET' :
            reg_data = bytes([ord(i) for i in note['n_desc']])
            if len(reg_data) >= ssz:
                return bytes_to_struct(reg_data, struct_klass)
        return None

    @classmethod
    def extract_siginfo_info(cls, note, is_amd64=True):
        struct_klass = SIGINFO if not is_amd64 else SIGINFO64
        ssz = ctypes.sizeof(struct_klass)
        if note.get('n_type', '') == 0x53494749 or note.get('n_type', '') == 'NT_SIGINFO' :
            reg_data = bytes([ord(i) for i in note['n_desc']])
            if len(reg_data) >= ssz:
                return bytes_to_struct(reg_data, struct_klass)
        return None

    @classmethod
    def extract_auxv_info(cls, note, is_amd64=True):
        auxv = []
        struct_klass = auxv_t if not is_amd64 else auxv_t_64
        if note.get('n_type', '') == 'NT_AUXV':
            sz = 0
            aux_data = bytes([ord(i) for i in note['n_desc']])
            while sz < len(aux_data):
                s = bytes_to_struct(aux_data[sz:sz+ctypes.sizeof(struct_klass)], struct_klass)
                sz += ctypes.sizeof(struct_klass)
                auxv.append(s)
        return auxv


class SerializeNotes(object):
    @classmethod
    def serialize_fpregset_note(cls, note, idx=0):
        s = ExtractNoteDesc.extract_fpreg_state_info(note)
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
        r['type'] = 'NT_X86_XSTATE'
        r['idx'] = idx
        r['name'] = note['n_name']
        r['offset'] = note['n_offset']
        r['descsz'] = note['n_descsz']
        r['size'] = note['n_size']

        return r

    @classmethod
    def serialize_x86_state_note(cls, note, idx=0):
        s = ExtractNoteDesc.extract_x86_state_info(note)
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
        r['type'] = 'NT_X86_XSTATE'
        r['idx'] = idx
        r['name'] = note['n_name']
        r['offset'] = note['n_offset']
        r['descsz'] = note['n_descsz']
        r['size'] = note['n_size']

        return r

    @classmethod
    def serialize_prstatus_notes(cls, notes):
        prstatusx_notes = []
        idx = 0
        for note in notes:
            if note.get('n_type', '') == 'NT_PRSTATUS':
                prstatusx_notes.append(cls.serialize_prstatus_note(note, idx))
                idx += 1
        return prstatusx_notes

    @classmethod
    def serialize_prstatus_note(cls, note, idx=0):
        s = ExtractNoteDesc.extract_prstatus_info(note)
        r = json_serialize_struct(s) if s is not None else {}
        for k in note:
            if k == 'n_desc':
                continue
            r[k] = note[k]
        r['idx'] = idx
        r['type'] = note['n_type']
        r['name'] = note['n_name']
        r['offset'] = note['n_offset']
        r['descsz'] = note['n_descsz']
        r['size'] = note['n_size']
        return r

    @classmethod
    def serialize_siginfo_note(cls, note, idx=0, is_amd64=True):
        s = ExtractNoteDesc.extract_siginfo_info(note, is_amd64)
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
            del r['_sigfields']['_pad']
        
        r['idx'] = idx
        r['type'] = note['n_type']
        r['name'] = note['n_name']
        r['offset'] = note['n_offset']
        r['descsz'] = note['n_descsz']
        r['size'] = note['n_size']
        return r

    @classmethod
    def serialize_auxv_note(cls, note, is_amd64=True):
        auxv = ExtractNoteDesc.extract_auxv_info(note, is_amd64)
        s_auxv = []
        r = {}
        idx = 0
        for _av in auxv:
            av = json_serialize_struct(_av)
            av['type'] = AUX_TYPES.get(_av.a_type, "INVALID")
            av['idx'] = idx
            s_auxv.append(av)
            idx += 1
        
        r['auxv'] = s_auxv
        r['type'] = note['n_type']
        r['name'] = note['n_name']
        r['offset'] = note['n_offset']
        r['descsz'] = note['n_descsz']
        r['size'] = note['n_size']
        return r

    @classmethod
    def serialize_siginfo_note(cls, note, idx=0, is_amd64=True):
        s = ExtractNoteDesc.extract_siginfo_info(note, is_amd64)
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
            del r['_sigfields']['_pad']
        r['idx'] = idx
        r['type'] = note['n_type']
        r['name'] = note['n_name']
        r['offset'] = note['n_offset']
        r['descsz'] = note['n_descsz']
        r['size'] = note['n_size']
        return r

    @classmethod
    def serialize_file_note(cls, note, idx=0, is_amd64=True):
        r = {}
        note_desc_data = note['n_desc'] 
        filenames = note_desc_data['filename']
        elf_entries = note_desc_data['Elf_Nt_File_Entry']
        
        r['num_map_entries'] = note_desc_data['num_map_entries']
        r['page_size'] = note_desc_data['page_size']
        r['type'] = note['n_type']
        r['name'] = note['n_name']
        r['offset'] = note['n_offset']
        r['descsz'] = note['n_descsz']
        r['size'] = note['n_size']

        memory_map = []
        for fname, _info in zip(filenames, elf_entries):
            info = {k:v for k, v in _info.items()}
            info['filename'] = fname
            memory_map.append(info)

        r['memory_map'] = memory_map
        return r