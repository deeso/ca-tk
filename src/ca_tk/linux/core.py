from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection
from ma_tk.manager import Manager
from st_log.st_log import Logger
from .. load import Elf
from .core_structures_x86 import *
from .util import NTDescToJson
from .thread import Thread

# Steps to mapping in files
# 1. Parse the core format
# 2. Extract relevant data points
# 3. Map relevant parts into memory
# 4. Load relevant supporting parts into memory
# 5. Perform analysis

import logging
import logging.handlers



class ElfCore(object):

    def load_elf(self, core_filename: str=None, 
                       core_data: bytes=None,
                       inmemory=False,
                       core_zip_filename: str =None):
        
        self.source = "Failed"
        print("core_filename", core_filename, 
            "core_data", core_data, 
            "inmemory", inmemory, 
            "core_zip_filename", core_zip_filename, Elf.is_zip(core_zip_filename))
        self.logger.debug("Attempting to load ELF Core")
        if core_data is not None:
            self.core_io, self.elf = Elf.from_bytes(core_data)
            self.source = "bytes"
        elif core_zip_filename is not None and Elf.is_zip(core_zip_filename):
            self.core_io, self.elf = Elf.from_zip(core_zip_filename, 
                                                  core_filename, 
                                                  inmemory)
            self.source = "zip://{}".format(core_zip_filename)
            core_filename = self.core_io.name
        elif core_filename is not None:
            self.core_io, self.elf = Elf.from_file(core_filename, 
                                      inmemory)
            self.source = "file://{}".format(core_filename)

        self.logger.debug("Loaded ELF Core from: {}".format(self.source))
        if self.core_io is None or self.elf is None:
            raise Exception("Unable to load the core file for analysis")


    def __init__(self, core_filename: str=None, 
                       core_data: bytes=None,
                       files_location: list=None,
                       files_bytes: dict=None,
                       inmemory=False,
                       core_zip_filename: str=None,
                       loglevel=logging.INFO):
        
        self.logger = Logger("ElfCore", level=loglevel)
        self.physical_ranges = []
        self.virtual_ranges = []

        # parse out each relevant program hdr and segment

        # map pages to a specific range
        self.virtual_cache = dict()
        self.mgr = Manager()
        # TODO FIXME set the page_mask correctly through parameterization
        self.page_size = 4096
        self.page_mask = ec.mgr.page_mask

        self.core_io = None
        self.elf = None
        self.source = None
        self.load_elf(core_filename=core_filename, 
                      core_data=core_data, inmemory=inmemory, 
                      core_zip_filename=core_zip_filename)
        self.get_meta()
        


    def get_meta(self):
        self.get_segments()
        self.get_sections()
        self.get_pt_notes()
        self.get_pt_loads()
        self.get_notes()
        self.get_prstatus_notes()
        self.get_fpregset_notes()
        self.get_prpsinfo_notes()
        self.get_taskstruct_notes()
        self.get_siginfo_notes()
        self.get_auxv_notes()
        self.get_xstate_notes()
        self.get_file_notes()

        self.proc_properties = {PRPSINFO[k]: v for k, v in NTDescToJson.nt_prpsinfo(self.notes[0])}

        threads_meta = zip(self.get_prstatus_notes(), 
                           self.get_fpregset_notes(),
                           self.get_siginfo_notes(),
                           self.get_xstate_notes())

        self.threads_metas = {c: Thread(tm)  for c, tm  in enumerate(threads_meta)}
        self.threads = {c: Thread(tm) for c, tm in enumerate(self.threads_metas)}

        self.auxv = NTDescToJson.nt_auxv(self.nt_auxv[0])

    def stitch_files(self):
        self.files = NTDescToJson.nt_file(self.nt_file[0])
        map_meta = {p.header.p_vaddr: p for p in self.pt_notes }
        map_files = {f['vm_start'],f for f in self.files }
        map_files_pc = {f['vm_start']:set()}
        ec = self
        info = [i for i in self.files['memory_map']]
        map_files_pc = {f['vm_start']: 
                                      set([i&self.page_mask 
                                           for i in range(f['vm_start'], 
                                                           f['vm_end'], 
                                                           self.page_size)]) for f in info}


    def read_mapping(self):

        mappings = {}
        for f_info in self.files:
            va_start = f_info['vm_start']
            va_end = f_info['vm_end']
            page_offset = f_info['page_offset']
            file_name = f_info['filename']
            size = va_end - va_start
            self.add_mapping(va_start, va_end, page_offset, )


    def get_thread_meta(self, idx):
        return self.threads_metas[idx] if idx in self.threads_metas else None
    
    def get_thread_info(self, idx):
        return self.threads[idx] if idx in self.threads else None

    def get_thread_count(self):
        return len(self.threads_metas)

    def get_segments(self):
        if not hasattr(self, 'segments'):
            self.segments = [i for i in self.elf.iter_segments()]
        return self.segments
        
    def get_sections(self):
        if not hasattr(self, 'sections'):
            self.sections = [i for i in self.elf.iter_sections()]
        return self.sections

    def get_notes(self):
        if not hasattr(self, 'notes'):
            pt_note = self.get_pt_notes()[0]
            self.notes = [n for n in pt_note.iter_notes()]
        return self.notes

    def get_pt_loads(self):
        if not hasattr(self, 'pt_loads'):
            self.pt_loads = [i for i in self.segments if i.header.p_type == 'PT_LOAD']
        return self.pt_loads

    def get_pt_notes(self):
        if not hasattr(self, 'pt_notes'):
            self.pt_notes = [i for i in self.segments if i.header.p_type == 'PT_NOTE']
        return self.pt_notes

    def get_prstatus_notes(self):
        notes = self.notes
        if not hasattr(self, 'nt_prstatus'):
            self.nt_prstatus = [i for i in notes if i['n_type'] == 'NT_PRSTATUS' or i['n_type'] == 1]
        return self.nt_prstatus

    def get_fpregset_notes(self):
        notes = self.notes
        if not hasattr(self, 'nt_fpregset'):
            self.nt_fpregset = [i for i in notes if i['n_type'] == 'NT_FPREGSET' or i['n_type'] == 2]
        return self.nt_fpregset

    def get_prpsinfo_notes(self):
        notes = self.notes
        if not hasattr(self, 'nt_prpsinfo'):
            self.nt_prpsinfo = [i for i in notes if i['n_type'] == 'NT_PRPSINFO' or i['n_type'] == 3]
        return self.nt_prpsinfo

    def get_taskstruct_notes(self):
        notes = self.notes
        if not hasattr(self, 'nt_taskstruct'):
            self.nt_taskstruct = [i for i in notes if i['n_type'] == 'NT_TASKSTRUCT' or i['n_type'] == 4]
        return self.nt_taskstruct

    def get_auxv_notes(self):
        notes = self.notes
        if not hasattr(self, 'nt_auxv'):
            self.nt_auxv = [i for i in notes if i['n_type'] == 'NT_AUXV' or i['n_type'] == 4]
        return self.nt_auxv

    def get_siginfo_notes(self):
        notes = self.notes
        if not hasattr(self, 'nt_siginfo'):
            self.nt_siginfo = [i for i in notes if i['n_type'] == 'NT_SIGINFO' or i['n_type'] == 0x53494749]
        return self.nt_siginfo

    def get_file_notes(self):
        notes = self.notes
        if not hasattr(self, 'nt_file'):
            self.nt_file = [i for i in notes if i['n_type'] == 'NT_FILE' or i['n_type'] == 0x46494c45]
        return self.nt_file

    def get_xstate_notes(self):
        notes = self.notes
        return [i for i in notes if i['n_type'] == 'NT_X86_XSTATE' or i['n_type'] == 0x202]        


    def contains_physical(self, offset) -> bytes:
        for mr in self.physical_ranges:
            if offset in mr:
                return True
        return False

    def physical_to_virtual_address(self, offset: int) -> int:
        # convert the offset into a virtual address
        # 1) is offset in core file?
        # 2) is offset in another file that might be mapped in
        pass

    def virtual_to_physical(self, vma: int) -> int:
        # convert the offset into a virtual address
        # 1) is offset in core file?
        # 2) is offset in another file that might be mapped in
        pass


    def read_physical(self, offset, size, mapping=None) -> bytes:
        # 1) check if offset into the core file is present
        # 2) if not, is the map the offset from this core into 
        #    the target file
        # 3) if none of the files are present return None
        pass

    def read_virtual(self, address, size) -> bytes:
        # 1) check if address maps into the core file is present
        # 2) if not, is the map the offset from this core into 
        #    the target file
        # 3) if none of the files are present return None
        pass

    def get_memory_range(self, address=None, offset=None, io_back=None):
        # if address is not none, look up address and return back the range
        # if offset is not none, look up offset and return back the range
        # if the io_back is not none, look up the io_back and return the range
        pass

    def map_threads(self):
        pass

    def get_process(self, pid=None):
        # 1) return threads/processes
        pass

    def get_thread(self, thread=None):
        # 1) return threads/processes
        pass

    def get_processes(self, pid=None):
        # 1) return threads/processes
        pass

    def get_threads(self, thread=None):
        # 1) return threads/processes
        pass