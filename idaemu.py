from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
from struct import pack
from idaapi import get_func
from idc import Qword, GetManyBytes


PAGE_ALIGN = 0x1000 # 4k

COMPILE_GCC = 1
COMPILE_MSVC = 2

class Emu(object):    
    def __init__(self, arch, mode, compiler=COMPILE_GCC, stack=0xf000000, \
                ssize=3, RA=0xdeadbeaf):
        assert(arch in [UC_ARCH_X86])
        self.arch = arch
        self.mode = mode
        self.compiler = compiler
        self.stack = self._alignAddr(stack)
        self.ssize = ssize
        self.RA = RA # return address, for stop emulate
        self.data = []
    
    # callback for tracing invalid memory access (READ or WRITE, FETCH)
    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        addr = self._alignAddr(address)
        uc.mem_map(addr, PAGE_ALIGN)
        data = self._getOriginData(addr, PAGE_ALIGN)
        uc.mem_write(addr, data)
        return True

    def _alignAddr(self, addr):
        return addr // PAGE_ALIGN * PAGE_ALIGN

    def _getOriginData(self, address, size):
        res = []
        for offset in xrange(0, size, 64):
            tmp = GetManyBytes(address + offset, 64)
            if tmp == None:
                res.extend([pack("<Q", Qword(address + offset + i)) for i in range(0, 64, 8)])
            else:
                res.append(tmp)
        res = "".join(res)
        return res[:size]

    def _initStackAndArgs(self, uc, RA, *args):
        uc.mem_map(self.stack, (self.ssize+1) * PAGE_ALIGN)
        sp = self.stack + self.ssize * PAGE_ALIGN
        regs = []
        if self.mode == UC_MODE_16:
            step = 2
            uc.reg_write(UC_X86_REG_SP, sp)
            uc.mem_write(sp, pack('<H', RA))
            self.RES_REG = UC_X86_REG_AX
        elif self.mode == UC_MODE_32:
            step = 4
            uc.reg_write(UC_X86_REG_ESP, sp)
            uc.mem_write(sp, pack('<I', RA))
            self.RES_REG = UC_X86_REG_EAX
        elif self.mode == UC_MODE_64:
            step = 8
            uc.reg_write(UC_X86_REG_RSP, sp)
            uc.mem_write(sp, pack('<Q', RA))
            self.RES_REG = UC_X86_REG_RAX
            if self.compiler == COMPILE_GCC:
                regs = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX, 
                        UC_X86_REG_R8, UC_X86_REG_R9]
            elif self.compiler == COMPILE_MSVC:
                regs = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
        
        ## init the arguments
        i = 0
        while i < len(regs) and i < len(args):
            uc.reg_write(regs[i], args[i])
            i += 1
        while i < len(args):
            sp += step
            uc.mem_write(sp, args[i])
            i += 1

    def _initData(self, uc):
        for address, data, init in self.data:
            addr = self._alignAddr(address)
            size = PAGE_ALIGN
            while addr + size < len(data): size += PAGE_ALIGN
            uc.mem_map(addr, size)
            if init: uc.mem_write(addr, self._getOriginData(addr, size))
            uc.mem_write(address, data)

    # set the data before emulation
    def setData(self, address, data, init=False):
        self.data.append((address, data, init))

    def eFunc(self, address, *args):
        func = get_func(address)
        funcSize = func.endEA - func.startEA
        try:
            uc = Uc(self.arch, self.mode)

            self._initStackAndArgs(uc, self.RA, *args)

            self._initData(uc)

            # add the invalid memory access hook
            uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | \
                        UC_HOOK_MEM_FETCH_UNMAPPED, self._hook_mem_invalid)
            # start emulate
            uc.emu_start(func.startEA, self.RA)
            
            print("Euclation done. Below is the Result:")
            res = uc.reg_read(self.RES_REG)
            print(">>> function result = %d" % res)
        except UcError as e:
            print("#ERROR: %s" % e)
        
