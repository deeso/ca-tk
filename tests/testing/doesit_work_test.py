import os
import unittest
import logging
from ca_tk.linux.core import ELFCore
from ca_tk.linux.thread import Thread
from ca_tk.linux.notes import NTDescToJson

class TestDoesItStart(unittest.TestCase):
    # FIXME needs to be run from the root of the project
    def test_does_it_start(self):
        ZIPFILE_NAME = './sample/ipython-core-all.31971.zip'
        FILENAME = 'ipython-core-all.31971'
        ec = ELFCore(core_zip_filename=ZIPFILE_NAME, 
                     core_filename=FILENAME, 
                     inmemory=True,loglevel=logging.DEBUG)
        self.assertTrue(ec is not None)

    def test_does_it_load_afile(self):
        ZIPFILE_NAME = './sample/ipython-core-all.31971.zip'
        FILENAME = 'ipython-core-all.31971'
        ec = ELFCore(core_zip_filename=ZIPFILE_NAME, 
                     core_filename=FILENAME, 
                     inmemory=True,loglevel=logging.DEBUG)
        self.assertTrue(ec is not None)
        libz = required_files[-1]
        required_files = ec.get_required_files_list()
        self.assertTrue(len(required_files) == 28)
        self.assertTrue(libz.find(b'libz') > 0)

        segments = [i for i in ec.get_stitching().values() if i.filename.find(libz) > -1]
        segments_needing_load = [i for i in segments if i.page_offset == 0]
        self.assertTrue(len(segments) == 3)
        self.assertTrue(len(segments_needing_load) == 1)
        

if __name__ == '__main__':
    unittest.main()