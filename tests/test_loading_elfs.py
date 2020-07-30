import os
import unittest
from core_analysis.load import Elf



BUFFER_VA = 0x14000
FILE_VA = 0x24000

class TestManager(unittest.TestCase):
    TEST_FILE = './samples/'
    def setUp(self):
        # setup our tmp file
        print (os.path.realpath())

    def tearDown(self):
        # setup our tmp file
        pass

    def test_load_elf(self):
        # read sample
        # write to a temporary location
        # load the file using the filename
        pass

    def test_load_elf_zip(self):
        # try to load the sampe zip
        pass

    def test_load_elf_bytes(self):
        # try to load the sampe zip
        pass        


if __name__ == '__main__':
    unittest.main()