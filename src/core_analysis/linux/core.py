from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection
from .core_structures_x86 import *
import io



class AddrRange(object):
    pass

class CoreAddrRange(AddrRange):

    def __init__(self, vstart: int, pstart: int, size:int=0, io_back=None):
        # io_back could be a file or io.bytes object
        if end is None:
            end = start + size

        self.vstart = vstart
        self.pstart = pstart
        self.io_back = io_back

        self.vend = end
        self.size = size

    def __in__(self, value: int)
        if value < end and start <= value:
            return True
        return False

class FileAddrRange(AddrRange):

    def __init__(self, vstart: int, pstart: int, end:int =None, size:int=0):
        if end is None:
            end = start + size

        self.vstart = start
        self.vend = end
        self.size = size

    def __in__(self, value: int)
        if value < end and start <= value:
            return True
        return False


class ElfCore(object):

    def __init__(self, core_filename: str=None, 
                       core_data: bytes=None,
                       core_io: io.BytesIO=None,
                       files_location: list=None,
                       files_bytes: dict=None):
        
        self.physical_ranges = []
        self.virtual_ranges = []

        if core_filename is None and core_data is None and io_back is None:
            raise Exception("ELF File data or file not provided")


        self.core_io = core_io
        if self.core_io is None:
            self.core_io = open(core_filename, 'rb') if filename is not None \
                                                else io.BytesIO(core_data) 



        self.elf = ELFFile(self.core_io)

        # parse out each relevant program hdr and segment
        self.elf_sections = [i for i in self.elf.iter_sections()]
        self.elf_segments = [i for i in self.elf.iter_segments()]
        self.pt_loads = self.get_pt_loads()
        self.notes = self.get_notes()

        self.page_size = 4096
        # map pages to a specific range
        self.virtual_cache = dict()

    def get_notes(self):
        if hasattr(self, 'notes'):
            return self.notes
        
        pt_note = self.get_pt_notes()[0]
        self.notes = [n for n in pt_note.iter_notes()]   

    def get_pt_loads(self):
        return [i for i in self.elf_segments if i.header.p_type == 'PT_LOAD']

    def get_pt_notes(self):
        return [i for i in self.elf_segments if i.header.p_type == 'PT_NOTE']

    def get_prstatus_notes(self, notes):
        return [i for i in notes if i['n_type'] == 'NT_PRSTATUS' or i['n_type'] == 1]

    def get_fpregset_notes(self, notes):
        return [i for i in notes if i['n_type'] == 'NT_FPREGSET' or i['n_type'] == 2]

    def get_prpsinfo_notes(self, notes):
        return [i for i in notes if i['n_type'] == 'NT_PRPSINFO' or i['n_type'] == 3]

    def get_taskstruct_notes(self, notes):
        return [i for i in notes if i['n_type'] == 'NT_TASKSTRUCT' or i['n_type'] == 4]

    def get_auxv_notes(self, notes):
        return [i for i in notes if i['n_type'] == 'NT_AUXV' or i['n_type'] == 4]

    def get_siginfo_notes(self, notes):
        return [i for i in notes if i['n_type'] == 'NT_SIGINFO' or i['n_type'] == 0x53494749]

    def get_file_notes(self, notes):
        return [i for i in notes if i['n_type'] == 'NT_FILE' or i['n_type'] == 0x46494c45]

    def get_xstate_notes(self, notes):
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