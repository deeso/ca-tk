import zipfile
import tempfile
import io
import os
import unittest
from ma_tk.load.elf import OpenELF


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
        file_info = OpenELF.from_file(self.TMP_NAME)
        self.assertTrue(file_info is not None)
        fd = file_info.get_fd()
        self.assertTrue(fd is not None)
        fd.seek(0)
        x = fd.read(8)
        self.assertTrue(x == b'\x7fELF\x02\x01\x01\x00')

    def test_load_elf_zip(self):
        # try to load the sampe zip
        file_info = OpenELF.from_zip(self.ZIP_SAMPLE)
        self.assertTrue(file_info is not None)
        fd = file_info.get_fd()

        self.assertTrue(fd is not None)
        fd.seek(0)
        x = fd.read(8)
        self.assertTrue(x == b'\x7fELF\x02\x01\x01\x00')

    def test_load_elf_zip_inmemory(self):
        # try to load the sampe zip
        file_info = OpenELF.from_zip(self.ZIP_SAMPLE, inmemory=True)
        self.assertTrue(file_info is not None)
        fd = file_info.get_fd()

        self.assertTrue(fd is not None)
        self.assertTrue(isinstance(fd, io.BytesIO))
        fd.seek(0)
        x = fd.read(8)
        self.assertTrue(x == b'\x7fELF\x02\x01\x01\x00')

    def test_load_elf_file_inmemory(self):
        # try to load the sampe zip
        file_info = OpenELF.from_file(self.TMP_NAME, inmemory=True)
        self.assertTrue(file_info is not None)
        fd = file_info.get_fd()

        self.assertTrue(fd is not None)
        self.assertTrue(isinstance(fd, io.BytesIO))
        fd.seek(0)
        x = fd.read(8)
        self.assertTrue(x == b'\x7fELF\x02\x01\x01\x00')

    def test_load_elf_bytes(self):
        # try to load the sampe zip
        file_info = OpenELF.from_bytes(self.DATA)
        self.assertTrue(file_info is not None)
        fd = file_info.get_fd()

        self.assertTrue(fd is not None)
        fd.seek(0)
        x = fd.read(8)
        self.assertTrue(x == b'\x7fELF\x02\x01\x01\x00')

    def test_elf_parsing(self):
        # from file is really slow, analysis needs to be
        # in memory, or prepare to sit for a lot longer
        assertTrue = self.assertTrue
        file_info = OpenELF.from_zip(self.ZIP_SAMPLE, inmemory=True)
        self.assertTrue(file_info is not None)
        fd = file_info.get_fd()
        ef = file_info.get_file_interpreter()

        sections = [i for i in ef.iter_sections()]
        assertTrue(len(sections) == 132)
        assertTrue(sorted({i.header.sh_type for i in sections}) == ['SHT_NOTE', 'SHT_NULL', 'SHT_PROGBITS', 'SHT_STRTAB'])

        segments = [i for i in ef.iter_segments()]
        assertTrue(len(segments) == 130)
        assertTrue(sorted({i.header.p_type for i in segments}) == ['PT_LOAD', 'PT_NOTE'])

        pt_loads = [i for i in segments if i.header.p_type == 'PT_LOAD']
        assertTrue(len(pt_loads) == 129)
        pt_notes = [i for i in segments if i.header.p_type == 'PT_NOTE']
        pt_note = pt_notes[0]
        notes = [n for n in pt_notes[0].iter_notes()]
        assertTrue(len(notes) == 15)

        aux_notes = [n for n in pt_note.iter_notes() if n['n_type'] == 'NT_AUXV']
        assertTrue(len(aux_notes) == 1)
        file_notes = [n for n in pt_note.iter_notes() if n['n_type'] == 'NT_FILE']
        assertTrue(len(file_notes) == 1)


if __name__ == '__main__':
    unittest.main()