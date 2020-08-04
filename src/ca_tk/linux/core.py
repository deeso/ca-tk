import uuid
import os
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection

from .core_structures_x86 import *
from .notes import NTDescToJson
from .thread import Thread
from .consts import *
from .memory import *

from st_log.st_log import Logger
from ma_tk.manager import Manager
from ma_tk.load.elf import OpenELF, ElfFileLoader
from ma_tk.load.file import FileLoader

# Steps to mapping in files
# 1. Parse the core format
# 2. Extract relevant data points
# 3. Map relevant parts into memory
# 4. Load relevant supporting parts into memory
# 5. Perform analysis

import logging
import logging.handlers

class StitchObject(object):
    def __init__(self):
        for k, v in DEFAULT_MEMORY_META.items():
            setattr(self, k, v)

    def get_filename(self):
        getattr(self, 'filename', None)

    def update(self, info_dict: dict):
        for k, v in info_dict.items():
            setattr(self, k, v)

    def set_loaded(self, loaded=True):
        setattr(self, 'loaded', loaded)

    def get_file_size(self):
        return self.p_filesz

    def get_mem_size(self):
        return self.p_memsz

    def get_vm_size(self):
        return self.vm_end - self.vm_start

    def get_page_offset(self):
        return self.page_offset

    def get_size(self):
        if self.get_page_offset() < 0 and \
           self.vm_start < 0:
            return self.get_mem_size()
        return self.get_vm_size()

    def __str__(self):
        vm_start = getattr(self, 'vm_start')
        vm_end = getattr(self, 'vm_end')
        page_offset = getattr(self, 'page_offset')
        filename = getattr(self, 'filename')
        size = self.get_size()
        args = [vm_start, vm_end, page_offset, size, filename]
        return "{:016x}-{:016x} {:08x} {:08x} {}".format(*args)
    
    def __repr__(self):
        return str(self)

class ELFCore(object):

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
                       loglevel=logging.INFO,
                       namespace='ca_tk',
                       other_namespaces=None,
                       auto_load_files=False):
        
        self.logger = Logger("ca_tk.linux.core.OpenELFCore", level=loglevel)
        self.physical_ranges = []
        self.virtual_ranges = []
        self.load_external_files = load_external_files
        self.inmemory = inmemory
        self.namespace = namespace
        self.other_namespaces = [] if other_namespaces is None else other_namespaces
        self.auto_load_files = False

        self.file_loader = FileLoader.create_fileloader( namespace=namespace,
            required_files_location_list=required_files_location_list,
            required_files_location=required_files_location,
            required_files_bytes=required_files_bytes,
            required_files_dir=required_files_dir,
            required_files_zip=required_files_zip)

        self.elf_loader = ElfFileLoader.create_fileloader( namespace=namespace+'_elf',
            required_files_location_list=required_files_location_list,
            required_files_location=required_files_location,
            required_files_bytes=required_files_bytes,
            required_files_dir=required_files_dir,
            required_files_zip=required_files_zip)
        self.elf_loader.set_file_opener(OpenELF)

        # parse out each relevant program hdr and segment

        # map pages to a specific range
        self.virtual_cache = dict()
        self.mgr = Manager(loglevel=loglevel)
        # TODO FIXME set the page_mask correctly through parameterization
        self.page_size = 4096
        self.page_mask = self.mgr.page_mask

        self.core_file_obj = None
        self.elf = None
        self.source = "Failed"
        self.load_core_elf(core_filename=core_filename, 
                      core_data=core_data, inmemory=self.inmemory, 
                      core_zip_filename=core_zip_filename)
        self.core_data = core_data
        self.core_filename = core_filename
        self.core_zip_filename = core_zip_filename
        self.clone_interps = False
        self.init_meta()
        
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
        self.organize_stitchings()
        if self.auto_load_files:
            self.load_core_segments()

    def get_required_files_list(self):
        if not hasattr(self, 'required_files'):
            required_files = set()
            stitching = self.get_stitching()
            for info in stitching.values():
                if info.requires_file:
                    required_files.add(info.filename)
            self.required_files = sorted(required_files)
        return self.required_files

    def add_stitch_page(self, vaddr, stitching):
        self.page_caches[vaddr&self.page_mask] = stitching

    def has_stitch_page(self, vaddr):
        return vaddr&self.page_mask in self.page_caches

    def get_stitch_page(self, vaddr):
        return self.page_caches.get(vaddr & self.page_mask, None)

    def init_stitch_pages(self, va_start, va_end, stitching=None):
        for vaddr in range(va_start, va_end, self.page_size):
            self.add_stitch_page(vaddr, stitching)

    def init_stitching_pages(self, stitching):
        return self.init_stitch_pages(stitching.vm_start, stitching.vm_end, stitching)

    def organize_stitchings(self):
        self.internal_segments = []
        self.internal_segments_by_file = {}
        self.internal_segments_by_vaddr = {}
        self.external_segments = []
        self.external_segments_by_file = {}
        self.external_segments_by_vaddr = {}
        self.page_caches = {}

        for stitching in self.get_stitching().values():
            filename = stitching.filename
            vaddr = stitching.vm_start
            self.init_stitching_pages(stitching)

            if stitching.loadable:
                self.internal_segments.append(stitching)
                if filename not in self.internal_segments_by_file:
                    self.internal_segments_by_file[filename] = []
                self.internal_segments_by_file[filename].append(stitching)
                self.internal_segments_by_vaddr[vaddr] = stitching
            else:
                self.external_segments.append(stitching)
                if filename not in self.external_segments_by_file:
                    self.external_segments_by_file[filename] = []
                self.external_segments_by_file[filename].append(stitching)
                self.external_segments_by_vaddr[vaddr] = stitching

    def get_external_segments(self):
        if not hasattr(self, 'external_segments'):
            # self.required_files = sorted(required_files)
            self.organize_stitchings()
        return self.external_segments

    def get_external_segments_by_file(self):
        if not hasattr(self, 'external_segments_by_file'):
            # self.required_files = sorted(required_files)
            self.organize_stitchings()
        return self.external_segments_by_file

    def get_stitching_by_file(self):
        if not hasattr(self, 'internal_segments_by_file'):
            # self.required_files = sorted(required_files)
            self.organize_stitchings()
        return self.internal_segments_by_file

    def get_stitching(self):
        if not hasattr(self, 'stitching'):
            self.stitching = self.stitch_files()
        return self.stitching

    def read_data_elf_info(self, page_offset, elf_info, expected_size=None):
        '''
        read the data from a specific page offset in the elf header.
        this page offset comes from the core PT_LOAD page offset, 
        and we use the file name to determine where to read this data
        from in the target ELF.

        Also of note, we read only the the file segments size, and then
        pad that data to the expected virtual address size.
        see ma_tk.load.file.FileLoader for info
        

        '''
        fd = elf_info.get_fd()
        filename = elf_info.get_filename()
        segment = elf_info.get_attr('segments_by_offset', {}).get(page_offset, None)

        if segment is None:
            self.info("Unable to retrieve Segment @ {:016x} for {}".format(page_offset, filename))
            return None

        # ef = elf_info.get_file_interpreter()
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

    def load_stitch_inmemory(self, stitched_info):
        '''
        load an bytes- memory segment using 
        information gathered during the stitching process
        '''
        ibm = None
        filename = stitched_info.filename
        elf_info = None
        # FIXME need a better way of handling the file loading (e.g. data, exe disguised as not ELFs)        # assuming this is an elf, means if its not we will fail anyway later
        # assuming this is an elf, means if its not we will fail anyway later
        try:    
            elf_info = self.elf_loader.load_file(filename, namespace=self.namespace, namespaces=self.other_namespaces)
        except:
            elf_info = self.file_loader.load_file(filename, namespace=self.namespace, namespaces=self.other_namespaces)

        page_offset = stitched_info.page_offset
        data_size = stitched_info.p_filesz
        vm_size = stitched_info.vm_size
        va_start = stitched_info.vm_start
        flags = stitched_info.p_flags
        data = None

        ibm = self.mgr.get_map(va_start)
        # TODO would reload the map here
        if ibm is not None:
            return ibm

        segment_in_core = lambda info: info.page_offset > 0
        segment_in_elf = lambda info: info.filename in rfiles
        if segment_in_core(stitched_info):
            self.core_file_obj.seek(page_offset, os.SEEK_SET)
            data = self.core_file_obj.read(0, data_size)
        elif elf_info is not None:
            data = self.read_data_elf_info(page_offset, elf_info, expected_size=data_size)


        if data is not None:
            # map the memory object into the manager for accessiblity
            # update the info indicated it was loaded
            if len(data) != data_size:
                data = data + b'\x00' * (vm_size - len(data))
            self.logger.debug("Creating a memory object for the buffer from: {}@{:08x} starting @{:016x}".format(filename, page_offset, va_start))
            ibm = self.mgr.add_buffermap(data, va_start, size=data_size, offset=0,
                                   page_size=4096, filename=filename, 
                                   flags=flags)
            setattr(ibm, 'elf_info', elf_info)
            setattr(ibm, 'info', stitched_info)
            stitched_info.set_loaded(True)
        return ibm

    def load_stitch_infile(self, stitched_info):
        '''
        load an ioobject memory segment using 
        information gathered during the stitching process
        '''
        ibm = None
        filename = stitched_info.filename
        # FIXME need a better way of handling the file loading (e.g. data, exe disguised as not ELFs)
        # assuming this is an elf, means if its not we will fail anyway later
        elf_info = None
        try:    
            elf_info = self.elf_loader.load_file(filename, namespace=self.namespace, namespaces=self.other_namespaces)
        except:
            elf_info = self.file_loader.load_file(filename, namespace=self.namespace, namespaces=self.other_namespaces)
        page_offset = stitched_info.page_offset
        data_size = stitched_info.vm_size
        va_start = stitched_info.vm_start
        flags = stitched_info.p_flags
        core_io = None

        segment_in_core = lambda info: info.page_offset > 0
        segment_in_elf = lambda info: info.filename in rfiles
        if segment_in_core(stitched_info):
            core_io = self.clone_core_io()
            core_io.seek(page_offset, os.SEEK_SET)

        else:
            elf_info = self.file_loader.load_file(filename, namespace=self.namespace, namespaces=self.other_namespaces)
            if elf_info is not None and elf_info.get_fd() is not None:
                core_io = elf_info.clone(create_new_file_interp=self.clone_interps)

        if core_io is not None:
            # map the memory object into the manager for accessiblity
            # update the info indicated it was loaded
            self.debug("Creating a memory object for the file memory object from: {}@{:08x} starting @{:016x}".format(filename, page_offset, vaddr))
            ibm = self.mgr.add_ioobj(core_io, va_start, size, phy_start=page_offset, 
                              flags=flags, filename=filename, page_size=4096)
            setattr(ibm, 'elf_info', elf_info)
            setattr(ibm, 'info', info)
            info['loaded'] = True
        return ibm

    def load_stitch(self, stitched_info):
        ibm = None
        if stitched_info is None or \
           not stitched_info.loadable or \
           stitched_info.vm_start == -1:
            if stitch is not None and not stitch.loadable:
                self.logger.debug("ELFCore.load_stitch unloadable segment: {}".format(stitch))
            elif stitch is not None and stitched_info.vm_start == -1:
                self.logger.debug("ELFCore.load_stitch unloadable segment, bad VA: {}".format(stitch))
            else:
                self.logger.debug("ELFCore.load_stitch unloadable segment, bad stitch value: {}".format(stitch))
            
            return ibm
        elif self.inmemory:
            ibm = self.load_stitch_inmemory(stitched_info)
            print(ibm)
        else:
            ibm = self.load_stitch_infile(stitched_info)

        if ibm is not None:
            stitched_info.set_loaded(True)
        return ibm

    def load_stitches_by_file(self, filename):
        stchs = self.get_external_segments_by_file().get(filename, []) + \
                self.get_external_segments_by_file().get(filename, [])

        return self._load_stitches(stchs)

    def load_stitch_by_vaddr(self, vaddr, stitch=None):
        if stitch is None:
            stitch = self.get_stitch_page(vaddr)
        ibm = self.load_stitch(stitch)
        return ibm

    def _load_stitches(self, stitch_infos):
        mem_list = []
        for info in stitch_infos:
            ibm = self.load_stitch_by_vaddr(info.vm_start, stitch)
            if ibm is not None:
                mem_list.append(ibm)
            else:
                self.logger.debug("Failed to load: [{}]".format(info))            
        return mem_list        
        
    def stitch_files(self):
        '''
        stitch together information from the NT_FILES and PT_LOAD segments

        this information is used to load the respective memory segments for
        analysis

        #TODO clean up the data here, since the stitching will create
        incorrect perspectives into the core file. this was a hack to
        get around deeper understanding.
        '''
        self.logger.debug("Stitching together file information")
        files_info = self.get_files_info()
        file_addrs = self.get_files_by_vaddr()
        ptloads_by_vaddr = self.get_pt_loads_by_vaddr()
        all_vaddrs = [vaddr for vaddr in ptloads_by_vaddr if vaddr > 0] + \
                     [vaddr for vaddr in file_addrs if vaddr > 0]
        
        # add the progam header meta data into the vaddr entry
        # the logic is that where the PT_LOAD and NT_FILE 
        # segments align, we'll get a clear picture.  Not always happening

        self.stitching = {vaddr: StitchObject() for vaddr in all_vaddrs}
        for vaddr in self.stitching:
            stitch = self.stitching[vaddr]
            if vaddr == 0:
                continue
            pt_load = ptloads_by_vaddr.get(vaddr, None)
            file_association = file_addrs.get(vaddr, None)
            bd = {}
            vm_size = 0
            
            if pt_load is not None:
                bd.update({k:v for k, v in pt_load.header.items()})
            if file_association is not None:
                bd.update({k:v for k,v in file_association.items()})
                bd['vm_size'] = file_association['vm_end'] - file_association['vm_start']
                bd['requires_file'] = file_association['page_offset'] <= 0
                bd['page_offset'] = file_association['page_offset']
                bd['loadable'] = bd['page_offset'] >= 0 and \
                                 file_association['filename'].find(b'(deleted)') == -1

            stitch.update(bd)
            stitch.set_loaded(False)

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
            self.files_by_vaddr = {i['vm_start']:i for i in self.file_info['memory_map']}
        return self.file_info

    def get_files_by_vaddr(self):
        if not hasattr(self, 'files_by_vaddr'):
            self.get_files_info()
        return self.files_by_vaddr

    def get_pt_loads_by_vaddr(self):
        if not hasattr(self, 'pt_loads_by_vaddr'):
            self.get_pt_loads_by_vaddr()
        return self.pt_loads_by_vaddr

    def get_pt_loads(self):
        if not hasattr(self, 'pt_loads'):
            self.pt_loads = [i for i in self.segments if i.header.p_type == 'PT_LOAD']
            self.pt_loads_by_vaddr = {i.header.p_vaddr: i for i in self.pt_loads}
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

    def load_elf_zip(self, zip_filename, filename=None, inmemory=True):
        return self.elf_loader.load_file_from_zip(zip_filename, filename, inmemory=inmemory)


    def load_elf_bytes(self, data, filename=None, update_bytes=True):
        if data is not None and filename is None:
            filename = str(uuid.uuid4())

        # FIXME
        if data is not None and\
           filename in self.elf_loader.required_files_bytes and not update_bytes:
           # TODO there may be a case where multiple byte blogs or what ever get 
           # set in known byte arrays KB e.g. elf_loader.required_files_bytes
           # what do we do when this happens?
           # right now, we ignore it and use the data already there
           self.logger.critical("There might be a data collision for {}".format(filename))
        elif data is not None and\
           filename in self.elf_loader.required_files_bytes and update_bytes:
           # TODO there may be a case where multiple byte blogs or what ever get 
           # set in known byte arrays KB e.g. elf_loader.required_files_bytes
           # what do we do when this happens?
           # right now, we ignore it and use the data already there
           self.logger.critical("There might be a data collision for {}".format(filename))
           self.elf_loader.required_files_bytes[filename] = data
        elif data is not None:
           self.elf_loader.required_files_bytes[filename] = data

        return self.elf_loader.load_file(data, self.namespace, 
                                         namespaces=self.other_namespaces)

    def load_elf(self, filename: str=None, 
                       data: bytes=None,
                       inmemory=False,
                       zip_filename: str =None, update_bytes=True):
        source = "Failed"
        self.logger.debug("Attempting to load ELF Core")
        if data is not None:
            file_obj = self.load_elf_byte(data, filename=filename, update_bytes=update_bytes) 
        elif zip_filename is not None and self.elf_loader.is_zip(zip_filename):
            file_obj = self.load_elf_zip(zip_filename, filename=filename, inmemory=self.inmemory)           
        elif filename is not None:
            file_obj = self.elf_loader.load_file(filename, inmemory=inmemory)

        if file_obj is not None:
            source = file_obj.get_source()

        self.logger.debug("Loaded ELF Core from: {}".format(source))
        if file_obj is None:
            raise Exception("Unable to load the core file for analysis")
        return file_obj

    def load_core_elf(self, core_filename: str=None, 
                       core_data: bytes=None,
                       inmemory=False,
                       core_zip_filename: str =None):
        
        self.core_file_obj = self.load_elf(filename=core_filename,
                                           data=core_data,
                                           inmemory=inmemory,
                                           zip_filename=core_zip_filename)        
        if self.core_file_obj is None:
            self.source = "Failed"
        else:
            self.source = self.core_file_obj.source
            self.elf = self.core_file_obj.get_file_interpreter()
        if self.core_file_obj is None:
            raise Exception("Unable to load the core file for analysis")

    def clone_core_io(self):
        if self.source == "Failed":
            raise Exception("Attempting to clone a failed core_io")
        return self.core_file_obj.clone(create_new_file_interp=self.clone_interps)

    def check_load(self, vaddr):
        if self.mgr.check_vaddr(vaddr):
            return True

        elif not self.has_stitch_page(vaddr):
            self.logger.debug("ELFCore.check_load {:08x} is unknown".format(vaddr))
            return False

        stitch = self.get_stitch_page(vaddr)            
        ibm = self.load_stitch(stitch)
        if ibm is not None:
            return True
        return False

    def read_word(self, vaddr, little_endian=True):
        return self.mgr.read_word(vaddr, little_endian)

    def read_dword(self, vaddr, little_endian=True):
        return self.mgr.read_dword(vaddr, little_endian)

    def read_qword(self, vaddr, little_endian=True):
        return self.mgr.read_qword(vaddr, little_endian)

    def read_at_vaddr(self, vaddr, size=1):
        return self.mgr.read_at_vaddr(vaddr, size)

    def read(self, size=1):
        return self.mgr.read(size)

    def read_cstruct(self, vaddr, cstruct):
        return self.mgr.read_cstruct(cstruct, addr=vaddr)

    def seek(self, vaddr):
        return self.mgr.seek(addr=vaddr)
