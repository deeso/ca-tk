from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection


flag_bits = {1:'x', 2:'w', 4:'r', 0:'-'}
and_bit = lambda x, v: flag_bits[x & v] 
get_flag_str = lambda flags: ''.join([and_bit(flags, m) for m in [4, 2, 1]])
0x55a0f42b2000     0x55a0f42c0000     0xe000        0x0 /usr/lib/firefox/firefox
FMT = "0x{:08x}    0x{:08x}   0x{:04x}  0x{:x}"  
get_section_string = lambda hdr: FMT.format(hdr.sh_addr, hdr.sh_addr+hdr.sh_size, hdr.sh_size, hdr.sh_offset) 

core_files = ['firefox_dso_synced.4804',
 'firefox_dso_synced.4679',
 'firefox_dso_synced.3503',
 'firefox_dso_synced.3678',
 'firefox_dso_synced.5130',
 'firefox_dso_synced.3849',
 'firefox_dso_synced.4523',
 'firefox_dso_synced.3571',
 'firefox_dso_synced.5357',
 'firefox_dso_synced.3601']


core_file = core_files[0]

ef = ELFFile(open(core_file, 'rb'))

sections = [i for i in ef.iter_sections()]                             
segments = [i for i in ef.iter_segments()]

pt_loads = [i for i in segments if i.header.p_type == 'PT_LOAD']

pt_notes = [i for i in segments if i.header.p_type == 'PT_NOTE']
pt_note = pt_notes[0]
notes = [n for n in pt_note.iter_notes()]

aux_notes = [n for n in pt_note.iter_notes() if n['n_desc'] == 'NT_AUXV']
# NT_PRPSINFO 
#notes[0].keys() => dict_keys(['n_namesz', 'n_descsz', 'n_type', 'n_offset', 'n_name', 'n_desc', 'n_size'])
#notes[0]['n_desc'].keys() => dict_keys(['pr_state', 'pr_sname', 'pr_zomb', 'pr_nice', 'pr_flag', 'pr_uid', 'pr_gid', 'pr_pid', 'pr_ppid', 'pr_pgrp', 'pr_sid', 'pr_fname', 'pr_psargs'])  

# NT_PRSTATUS
#notes[1].keys() => dict_keys(['n_namesz', 'n_descsz', 'n_type', 'n_offset', 'n_name', 'n_desc', 'n_size'])

# NT_FPREGSET pyelftools does not parse the register state
#notes[2].keys() => dict_keys(['n_namesz', 'n_descsz', 'n_type', 'n_offset', 'n_name', 'n_desc', 'n_size'])

# NT_X86_XSTATE pyelftools does not parse the register state, does not correctly identify the type string
#notes[3].keys() => dict_keys(['n_namesz', 'n_descsz', 'n_type', 'n_offset', 'n_name', 'n_desc', 'n_size'])

# NT_SIGINFO n_desc is not parsed
#notes[3].keys() => dict_keys(['n_namesz', 'n_descsz', 'n_type', 'n_offset', 'n_name', 'n_desc', 'n_size'])

# NT_FILE 
# notes[-1].keys() => dict_keys(['n_namesz', 'n_descsz', 'n_type', 'n_offset', 'n_name', 'n_desc', 'n_size'])
# notes[-1]['n_desc'].keys() => dict_keys(['num_map_entries', 'page_size', 'Elf_Nt_File_Entry', 'filename'])

infos = []
for fname, _info in zip(notes[-1]['n_desc']['filename'], notes[-1]['n_desc']['Elf_Nt_File_Entry']):
    info = {k:v for k, v in _info.items()}
    info['filename'] = fname
    infos.append(info)



# what do i want to accomplish with the core information?
# 1. Create a custom Python class that maps the core file VMAs and Physical addresses
# 2. Load read-only files from disk or bytes as needed
# 3. Provide basic seek, read, and emulation capabilities?



Unit tests: python -m unittest discover -s testing/ -p '*_test.py'

from ca_tk.load import Elf
filename = 'sample/ipython-core-all.31971.zip'
fd, ef = Elf.from_zip(self.ZIP_SAMPLE, inmemory=True)
fd, ef = Elf.from_zip(filename, inmemory=True)

sections = [i for i in ef.iter_sections()]                             
segments = [i for i in ef.iter_segments()]

pt_loads = [i for i in segments if i.header.p_type == 'PT_LOAD']
pt_notes = [i for i in segments if i.header.p_type == 'PT_NOTE']
pt_note = pt_notes[0]
notes = [n for n in pt_note.iter_notes()]

aux_notes = [n for n in pt_note.iter_notes() if n['n_type'] == 'NT_AUXV']

import logging
from ca_tk.linux.core import ElfCore, Thread
from ca_tk.linux.notes import NTDescToJson
ZIPFILE_NAME = '/home/adpridge/research/core-dump-parser/sample/ipython-core-all.31971.zip'
FILENAME = 'ipython-core-all.31971'
ec = ElfCore(core_zip_filename=ZIPFILE_NAME, core_filename=FILENAME, 
             inmemory=True,loglevel=logging.DEBUG)
