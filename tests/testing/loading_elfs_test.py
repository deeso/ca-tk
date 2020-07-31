import zipfile
import tempfile
import io
import os
import unittest
from ca_tk.load import Elf



BUFFER_VA = 0x14000
FILE_VA = 0x24000

class TestManager(unittest.TestCase):
    THIS_MODULE = os.path.realpath(__file__)
    THIS_DIR = os.path.split(THIS_MODULE)[0]
    SAMPLE_DIR = THIS_DIR + '/../../sample/'
    ZIP_SAMPLE = SAMPLE_DIR + 'ipython-core-all.31971.zip'
    TMP_FILE = None
    TMP_NAME = None
    DATA = None
    def setUp(self):
        # setup our tmp file
        self.TMP_FILE = tempfile.NamedTemporaryFile()
        zf = zipfile.ZipFile(self.ZIP_SAMPLE)
        self.DATA = zf.read(zf.namelist()[0])
        self.TMP_FILE.write(self.DATA)
        self.TMP_FILE.flush()
        self.TMP_FILE.seek(0)
        self.TMP_NAME = self.TMP_FILE.name


    def tearDown(self):
        # setup our tmp file
        pass

    def test_load_elf(self):
        # read sample
        # write to a temporary location
        # load the file using the filename
        fd, ef = Elf.from_file(self.TMP_NAME)
        self.assertTrue(fd is not None)
        fd.seek(0)
        x = fd.read(8)
        self.assertTrue(x == b'\x7fELF\x02\x01\x01\x00')

    def test_load_elf_zip(self):
        # try to load the sampe zip
        fd, ef = Elf.from_zip(self.ZIP_SAMPLE)
        self.assertTrue(fd is not None)
        fd.seek(0)
        x = fd.read(8)
        self.assertTrue(x == b'\x7fELF\x02\x01\x01\x00')

    def test_load_elf_zip_inmemory(self):
        # try to load the sampe zip
        fd, ef = Elf.from_zip(self.ZIP_SAMPLE, inmemory=True)
        self.assertTrue(fd is not None)
        self.assertTrue(isinstance(fd, io.BytesIO))
        fd.seek(0)
        x = fd.read(8)
        self.assertTrue(x == b'\x7fELF\x02\x01\x01\x00')

    def test_load_elf_file_inmemory(self):
        # try to load the sampe zip
        fd, ef = Elf.from_file(self.TMP_NAME, inmemory=True)
        self.assertTrue(fd is not None)
        self.assertTrue(isinstance(fd, io.BytesIO))
        fd.seek(0)
        x = fd.read(8)
        self.assertTrue(x == b'\x7fELF\x02\x01\x01\x00')

    def test_load_elf_bytes(self):
        # try to load the sampe zip
        fd, ef = Elf.from_bytes(self.DATA)
        self.assertTrue(fd is not None)
        fd.seek(0)
        x = fd.read(8)
        self.assertTrue(x == b'\x7fELF\x02\x01\x01\x00')


if __name__ == '__main__':
    unittest.main()