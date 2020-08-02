from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection
from ma_tk.manager import Manager
from st_log.st_log import Logger
from .. load import Elf
from .core_structures_x86 import *
from .notes import NTDescToJson
from .consts import THREAD_MAPPING, FP_REGS


# Steps to mapping in files
# 1. Parse the core format
# 2. Extract relevant data points
# 3. Map relevant parts into memory
# 4. Load relevant supporting parts into memory
# 5. Perform analysis

import logging
import logging.handlers


class Thread(object):


    def __init__(self, nt_prstatus, nt_fpregset, nt_siginfo, nt_x86_state=None):
        self.nt_prstatus = nt_prstatus
        self.nt_fpregset = nt_fpregset
        self.nt_x86_state = nt_x86_state
        self.nt_siginfo = nt_siginfo
        self.regs = {}
        self.fpregs = {}
        self.init_fpregs()
        self.init_prstatus()
        self.init_siginfo()
        if self.nt_x86_state is not None:
            self.init_x86_state()

    def set_mapped_info(self, json_dict):
        if not isinstance(json_dict, dict):
            return
        for k, v in json_dict.items():
            if k in THREAD_MAPPING:
                setattr(self, THREAD_MAPPING[k], v)

    def init_prstatus(self):
        self.reg_info = NTDescToJson.nt_prstatus(self.nt_prstatus)
        self.set_mapped_info(self.reg_info)

    def init_fpregs(self):
        self.fpreg_info = NTDescToJson.nt_fpregset(self.nt_fpregset)
        self.set_mapped_info(self.fpreg_info)
        for k, v in self.fpreg_info.items():
            if k in FP_REGS:
                self.fpregs[FP_REGS[k]] = v 

    def init_siginfo(self):
        self.siginfo_info = NTDescToJson.nt_siginfo(self.nt_siginfo)
        self.set_mapped_info(self.siginfo_info)
        items = [ (k,v) for k,v in self.sigfields.items()]
        for k, v in items:
            del self.sigfields[k]
            self.sigfields[k.strip('_')] = v

    def init_x86_state(self):
        self.x86_state_info = NTDescToJson.nt_x86_state(self.nt_x86_state)
        # FIXME dont really handle this atm, fpregset does most of this for me
        self.set_mapped_info(self.x86_state_info)

    def get_regs(self):
        return getattr(self, self.THREAD_MAPPING['pr_reg'], {})

    def get_reg(self, reg_name):
        regs = self.get_regs()
        return regs.get(reg_name, None)
    
    def get_fpregs(self):
        return getattr(self, 'fpregs', {})

    def get_fpreg(self, reg_name):
        regs = self.get_regs()
        return regs.get(reg_name, None)