from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection
from .core_structures_x86 import *



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

    def __init__(self, filename: str=None, 
                       iobytes: bytes=None,
                       files_location: list=None,
                       files_bytes: dict=None):
        
        self.physical_ranges = []
        self.virtual_ranges = []

        self.page_size = 4096
        # map pages to a specific range
        self.virtual_cache = dict()


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