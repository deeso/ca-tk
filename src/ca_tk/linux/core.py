import os
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection
from ma_tk.manager import Manager
from st_log.st_log import Logger
from .. load import Elf
from .core_structures_x86 import *
from .notes import NTDescToJson
from .thread import Thread

from .consts import *
from .memory import *
# Steps to mapping in files
# 1. Parse the core format
# 2. Extract relevant data points
# 3. Map relevant parts into memory
# 4. Load relevant supporting parts into memory
# 5. Perform analysis

import logging
import logging.handlers



class ElfCore(object):

    def __init__(self, core_filename: str=None, 
                       core_data: bytes=None,
                       required_files_location_list: list=None,
                       required_files_location: dict=None,
                       required_files_bytes: dict=None,
                       required_files_dir: str=None,
                       required_files_zip: str=None,
                       inmemory=False,
                       core_zip_filename: str=None,
                       load_external_files=True,
                       loglevel=logging.INFO):
        
        self.logger = Logger("ElfCore", level=loglevel)
        self.physical_ranges = []
        self.virtual_ranges = []
        self.load_external_files = load_external_files
        self.inmemory = inmemory
        self.required_files_to_elf = {}
        self.required_files_to_location = {}

        # cheap shot here.
        self.rfiles_location = {} if required_files_location is None \
                                  else required_files_location.copy()

        if required_files_location_list is not None:
            for f in required_files_location_list:
                if f not in self.rfiles_location:
                    self.rfiles_location[f] = f

        self.rfiles_bytes = {} if required_files_bytes is None \
                               else required_files_bytes
        # tell the memory loader that we have the file
        # but its already in memory
        self.rfiles_location.update({k: None for k in self.rfiles_bytes})
        self.rfiles_zip = None
        if required_files_zip is not None and Elf.is_zip(required_files_zip):
            self.rfiles_zip = required_files_zip
            self.rfiles_zip_names = Elf.zip_names()

        if required_files_dir is not None:
            # FIXME non-path recursion here :(
            files = [os.path.join(required_files_dir, i) for i in os.listdir('.')]
            self.rfiles_location.update({k:k for k in files})
        # parse out each relevant program hdr and segment

        # map pages to a specific range
        self.virtual_cache = dict()
        self.mgr = Manager()
        # TODO FIXME set the page_mask correctly through parameterization
        self.page_size = 4096
        self.page_mask = self.mgr.page_mask

        self.core_io = None
        self.elf = None
        self.source = None
        self.load_elf(core_filename=core_filename, 
                      core_data=core_data, inmemory=self.inmemory, 
                      core_zip_filename=core_zip_filename)
        self.core_data = core_data
        self.core_filename = core_filename
        self.core_zip_filename = core_zip_filename
        self.init_meta()
        
    def build_memory_backed(self, pt_note):
        filename = pt_note.get

    def init_meta(self):
        self.logger.debug("Extracting the sections, notes, and segments")
        self.get_segments()
        self.get_sections()
        self.get_pt_notes()
        self.get_pt_loads()
        self.get_notes()
        
        _ = self.get_taskstruct_notes()
        self.logger.debug("Getting the process information")
        ps_props = self.get_prpsinfo_notes()
        ps_json = NTDescToJson.nt_prpsinfo(ps_props)
        self.proc_properties = {PRPSINFO[k]: v for k, v in ps_json.items() if k in PRPSINFO}

        self.logger.debug("Stitching together the thread state")
        thread_regs = self.get_prstatus_notes()
        thread_fpregs = self.get_fpregset_notes()
        thread_siginfos = self.get_siginfo_notes()
        thread_xstates = self.get_xstate_notes()
        threads_meta = zip(thread_regs, 
                           thread_fpregs,
                           thread_siginfos,
                           thread_xstates)

        self.threads_metas = {c: tm  for c, tm  in enumerate(threads_meta)}
        self.threads = {c: Thread(*tm) for c, tm in self.threads_metas.items()}

        self.logger.debug("Parsing the AUX vector")
        auxv = self.get_auxv_notes()
        self.auxv = NTDescToJson.nt_auxv(auxv)
        
        self.stitch_files()
        self.load_memory()

    def get_required_files_list(self):
        if not hasattr(self, 'required_files'):
            required_files = set()
            for info in self.get_stitching():
                if info.get('requires_file', False):
                    required_files.add(info['filename'])
            self.required_files = sorted(required_files)
        return self.required_files

    def get_stitching(self):
        if not hasattr(self, 'stitching'):
            self.stitching = self.stitch_files()
        return self.stitching

    def init_required_file(self, filename):
        '''
        1) resolve the required file,
        2) load the file if found,
        3) map the sections by p_offset from the segment header
        None if any of this stuff fails.
        '''
        location = self.where_is_required_file(filename)
        if location is None:
            return None
        fd, ef = self.load_elf_location(location)
        if ef is None:
            self.required_files_to_elf[filename] = None
            return None

        if ef is not None:
            x = {i.header.p_offset: i for i in ef.iter_segments()}
            segments_by_offset = x

        return {
            'filename': filename
            'elf':ef,
            'fd': fd,
            'location': location,
            'segments_by_offset': segments_by_offset}

    def get_required_file(self, filename):
        '''
        list of required files by the core file,
        based on the NT_FILES note
        '''
        if filename in self.required_files_to_elf:
            return self.required_files_to_elf[filename]
        result = self.init_required_file(filename)
        self.required_files_to_elf[filename] = result
        return self.required_files_to_elf[filename]

    def load_elf_location(self, location):
        '''
        load the file using the Elf loader class
        returns an IO file descriptor and pyelf file
        '''
        fd = None
        ef = None
        if location == b'bytes::':
            data = self.rfiles_bytes[location]
            fd, ef = Elf.from_bytes(data, fname)
            fd.name = fname
        elif location == b'zip::':
            name = location.strip('zip::')
            fd, ef = Elf.from_zip(self.rfiles_zip, name, inmemory)
            fd.name = fname
        elif location is not None:
            fd, ef = Elf.from_file(self.rfiles_zip, location, inmemory)
            fd.name = fname
        return fd, ef

    def where_is_required_file(self, filename):
        '''
        The ELF file we want to load can be in several places:
            1a) provided directory (a directory)
            1b) list of files passed in during initialization
            2) in memory as a byte array ('bytes::')
            3) in a zip file ('zip::')
            4) on the local system

            at initialization, this dictionary maps known
            elfs for resolution in all cases except local system
        '''
        location = None
        if filename in self.required_files_to_location:
            return self.required_files_to_location[filename]

        # tell where the file is.
        # checks in memory bytes, mapping of filename to a location.
        if filename in self.rfiles_location:
            location = self.rfiles_location.get(filename)
            location = b'bytes::' if location is None else location

        # try just the filename if its in a path
        if location is None and os.path.split(filename) > 0:
            just_fn = os.path.split(filename)
            location = self.where_is_required_file(filename)

        # check the zip names list
        if location is None and self.rfiles_zip_names is not None:
            for n in self.rfiles_zip_names:
                if n.find(filename) > -1:
                    location = b'zip::' + n
                    break

        # check local file system
        if location is None:
            if os.path.exists(filename):
                location = filename
        self.required_files_to_location[filename] = location
        return location

    def read_data_elf_info(self, page_offset, elf_info, expected_size=None):
        '''
        read the data from a specific page offset in the elf header.
        this page offset comes from the core PT_LOAD page offset, 
        and we use the file name to determine where to read this data
        from in the target ELF.

        Also of note, we read only the the file segments size, and then
        pad that data to the expected virtual address size.

        elf_info contains:
        {
            'filename': filename
            'elf':ef,
            'fd': fd,
            'location': location,
            'segments_by_offset': segments_by_offset
        }

        '''
        fd = elf_info.get('fd', None)
        filename = elf_info['filename']
        segment = elf_info.get('segments_by_offset', {}).get(page_offset, None)

        if segment is None:
            self.info("Unable to retrieve Segment @ {:016x} for {}".format(page_offset, filename))
            return None

        ef = elf_info.get('elf', None)
        if fd is None:
            self.info("Invalid file descriptor for {}".format(filename))
            return None

        size = segment.get('p_filesz', None)
        if size is None or size < 1:
            self.info("Invalid size for segment at 0x{:016x}".format(page_offset))
            return None
        # FIXME not thread safe
        fd.seek(page_offset, os.SEEK_SET)
        data = fd.read(size)
        if expected_size > size:
            self.debug("Expected size larger than actual size, padding".format())
            data = data + b'\x00' * (expected_size - size)
        return data

    def load_core_segment_inmemory(self, stitched_info):
        '''
        load an bytes- memory segment using 
        information gathered during the stitching process
        '''
        ibm = None
        info = stitched_info
        filename = info.get('filename', None)
        elf_info = self.get_required_file()
        page_offset = info['page_offset']
        data_size = info['vm_size']
        va_start = info['vm_start']
        flags = info['p_flags']
        data = None
        if segment_in_core(info):
            core_io.seek(page_offset, os.SEEK_SET)
            data = core_io.read(data_size)
        elif elf_info is not None:
            data = self.read_data_elf_info(page_offset, elf_info, expected_size=data_size)

        if data is not None:
            self.debug("Creating a memory object for the buffer from: {}@{:08x} starting @{:016x}".format(filename, page_offset, vaddr))
            ibm = self.mgr.add_buffermap(data, va_start, vm_size, 0,
                                   page_size=4096, filename=filename, 
                                   flags=flags)
            setattr(ibm, 'elf_info', elf_info)
            setattr(ibm, 'info', info)
        return ibm

    def load_core_segment_file(self, stitched_info):
        '''
        load an ioobject memory segment using 
        information gathered during the stitching process
        '''
        ibm = None
        info = stitched_info
        filename = info.get('filename', None)
        elf_info = self.get_required_file()
        page_offset = info['page_offset']
        data_size = info['vm_size']
        va_start = info['vm_start']
        flags = info['p_flags']
        core_io = None
        if segment_in_core(info):
            core_io = self.clone_core_io()
            core_io.seek(page_offset, os.SEEK_SET)

        else:
            elf_info = self.init_required_file(filename)
            if elf_info is not None and elf_info.get('fd', None) is not None:
                core_io = elf_info['fd']

        if core_io is not None:
            self.debug("Creating a memory object for the file memory object from: {}@{:08x} starting @{:016x}".format(filename, page_offset, vaddr))
            ibm = self.mgr.add_ioobj(core_io, va_start, size, phy_start=page_offset, 
                              flags=flags, filename=filename, page_size=4096)
            setattr(ibm, 'elf_info', elf_info)
            setattr(ibm, 'info', info)
        return ibm

    def load_core_segments(self):
        '''
        load up segments from the core file or from other files, depending if
        present for loading.  in memory creates byte objects and io_obj use
        python IO (much slower)
        '''
        inmemory = self.inmemory
        rfiles = self.get_required_files_list()

        segment_in_core = lambda info: info.get('page_offset', 0) > 0
        segment_in_elf = lambda info: info.get('filename', 'a'*20) in rfiles         
        mem_list = []
        for info in self.get_stitching():
            ibm = None
            if self.inmemory:
                ibm = self.load_core_segment_inmemory(info)
            else:
                ibm = self.load_core_segment_file(info)
            mem_list.append(ibm)
        return mem_list        
        
    def stitch_files(self):
        '''
        stitch together information from the NT_FILES and PT_LOAD segments

        this information is used to load the respective memory segments for
        analysis 
        '''
        self.logger.debug("Stitching together file information")
        file_info = self.get_files_info()
        file_addrs = file_info.get('memory_map', [])
        all_vaddrs = [p.header.p_vaddr for p in self.get_pt_notes()] + \
                     [f['vm_start'] for f in file_addrs]
        
        self.stitching = {vaddr: DEFAULT_MEMORY_META.copy() for vaddr in all_vaddrs}
        for p in self.get_pt_notes():
            hdr = p.header
            vaddr = hdr['p_vaddr']
            self.stitching[vaddr].update(hdr)

        for info in file_addrs:
            vaddr = info['vm_start']
            vm_size = info['vm_end'] - info['vm_start']
            filename = info['filename']
            self.stitching[vaddr].update(info)
            self.stitching[vaddr]['vm_size'] = vm_size
            self.stitching[vaddr]['loaded'] = False
            self.stitching[vaddr]['requires_file'] = info['page_offset'] == 0
            if info['page_offset'] == 0:
                self.stitching[vaddr]['loadable'] = filename.find(b'(deleted)') > -1
        return self.stitching

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

    def get_pt_notes(self):
        if not hasattr(self, 'pt_notes'):
            self.pt_notes = [i for i in self.segments if i.header.p_type == 'PT_NOTE']
        return self.pt_notes

    def get_prstatus_notes(self):
        notes = self.get_notes()
        if not hasattr(self, 'nt_prstatus'):
            self.nt_prstatus = [i for i in notes if i['n_type'] == 'NT_PRSTATUS' or i['n_type'] == 1]
        return self.nt_prstatus

    def get_fpregset_notes(self):
        notes = self.get_notes()
        if not hasattr(self, 'nt_fpregset'):
            self.nt_fpregset = [i for i in notes if i['n_type'] == 'NT_FPREGSET' or i['n_type'] == 2]
        return self.nt_fpregset

    def get_prpsinfo_notes(self):
        notes = self.get_notes()
        # Note the pyelf tools a good enough job pulling out the relevant details
        if not hasattr(self, 'nt_prpsinfo'):
            x = [i for i in notes if i['n_type'] == 'NT_PRPSINFO' or i['n_type'] == 3]
            self.nt_prpsinfo = x[0]
        return self.nt_prpsinfo

    def get_taskstruct_notes(self):
        notes = self.get_notes()
        if not hasattr(self, 'nt_taskstruct'):
            self.nt_taskstruct = [i for i in notes if i['n_type'] == 'NT_TASKSTRUCT' or i['n_type'] == 4]
        return self.nt_taskstruct

    def get_auxv_notes(self):
        notes = self.get_notes()
        if not hasattr(self, 'nt_auxv'):
            x = [i for i in notes if i['n_type'] == 'NT_AUXV' or i['n_type'] == 4]
            self.nt_auxv = x[0]
        return self.nt_auxv

    def get_siginfo_notes(self):
        notes = self.get_notes()
        if not hasattr(self, 'nt_siginfo'):
            self.nt_siginfo = [i for i in notes if i['n_type'] == 'NT_SIGINFO' or i['n_type'] == 0x53494749]
        return self.nt_siginfo

    def get_file_notes(self):
        notes = self.get_notes()
        if not hasattr(self, 'nt_file'):
            x = [i for i in notes if i['n_type'] == 'NT_FILE' or i['n_type'] == 0x46494c45]
            self.nt_file = x
        return self.nt_file

    def get_xstate_notes(self):
        notes = self.get_notes()
        return [i for i in notes if i['n_type'] == 'NT_X86_XSTATE' or i['n_type'] == 0x202]        

    def get_files_info(self):
        if not hasattr(self, 'files_info'):
            self.file_info = NTDescToJson.nt_file(self.get_file_notes()[0])
        return self.file_info

    def get_pt_loads(self):
        if not hasattr(self, 'pt_loads'):
            self.pt_loads = [i for i in self.segments if i.header.p_type == 'PT_LOAD']
        return self.pt_loads

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


    def load_elf(self, core_filename: str=None, 
                       core_data: bytes=None,
                       inmemory=False,
                       core_zip_filename: str =None):
        
        self.source = "Failed"
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

    def clone_core_io(self):
        
        if self.source == "Failed":
            raise Exception("Attempting to clone a failed core_io")

        if self.source == "bytes":
            return Elf.from_bytes(self.core_data)

        else if self.source.find('zip://') > -1:
            return Elf.from_zip(self.core_zip_filename, 
                                self.core_filename, 
                                self.inmemory)
        else:
            return Elf.from_file(self.core_filename, self.inmemory)













