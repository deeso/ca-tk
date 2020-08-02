from ma_tk.store.bfr import BufferBacked
from ma_tk.store.io import IOBacked

class CoreBufferBacked(BufferBacked):

    def __init__(self, bytes_data, va_start: int, size: int, 
                 phy_start: int = 0,  page_size: int = 4096, 
                 filename: str = None, flags: str = 0):
        super().__init__(bytes_data, va_start, phy_start, size, 
                         page_size=page_size, filename=filename, flags=flags)

class CoreFileBacked(IOBacked):

    def __init__(self, bytes_data, va_start: int, size: int, 
                 phy_start: int = 0,  page_size: int = 4096, 
                 filename: str = None, flags: str = 0):
        super().__init__(bytes_data, va_start, phy_start, size, 
                         page_size=page_size, filename=filename, flags=flags)