import io
import zipfile
import os
from elftools.elf.elffile import ELFFile

class Elf(object):

    @classmethod
    def is_zip(cls, filename):
        if not os.exists(filename):
            return None

        try:
            zipfile.ZipFile(zipname).namelist()
            return True
        except:
            return False


    @classmethod
    def from_zip(cls, zipname, filename=None, inmemory=False):
        if zipname is None or not os.exists(zipname):
            return None, None

        zf = zipfile.ZipFile(zipname)
        names = zf.namelist()
        if len(names) == 0:
            return None, None
        if filename is None:
            filename = names[0]
        if filename not in names:
            return None, None
        fd = zf.read(filname)
        if inmemory:
        if inmemory:
            result = cls.from_bytes(fd.read())
            fd.close()
            zf.close()
            return result
        return fd, ELFFile(fd)

    @classmethod
    def from_file(cls, filename=None, inmemory=False):
        if filename is None or not os.exists(filename):
            return None, None
        fd = open(filename, 'rb')
        if inmemory:
            result = cls.from_bytes(fd.read())
            fd.close()
            return result
        return fd, ELFFile(fd)

    @classmethod
    def from_bytes(cls, data):
        if filename is None or not os.exists(filename):
            return None, None
        fd = io.BytesIO(data)
        return fd, ELFFile(fd)


