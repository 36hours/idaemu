from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
from struct import pack
from idaapi import get_func
from idc import Qword
import idc
import idaapi
import idautils

PAGE_ALIGN = 1024 * 1024 # 1m

COMPILE_GCC = 1
COMPILE_MSVC = 2

class Emu(object):    
    def __init__(self, arch, mode, compiler=COMPILE_GCC, stack=0xf000000, ssize=3):
        assert(arch in [UC_ARCH_X86])
        self.arch = arch
        self.mode = mode
        self.compiler = compiler
        self.stack = self._alignAddr(stack)
        self.ssize = ssize
    
    # callback for tracing invalid memory access (READ or WRITE)
    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        addr = self._alignAddr(address)
        uc.mem_map(addr, PAGE_ALIGN)
        data = self._getOriginData(addr, PAGE_ALIGN)
        uc.mem_write(addr, data)
        return True

    def _alignAddr(self, addr):
        return addr // PAGE_ALIGN * PAGE_ALIGN

    def _getOriginData(self, address, size):
        res = [pack("<Q", Qword(address + offset)) for offset in xrange(0, size+8, 8)]
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

    def _showStatus(self, uc):
        try:
            if self.mode == UC_MODE_16:
                ax = uc.reg_read(UC_X86_REG_AX)
                bx = uc.reg_read(UC_X86_REG_BX)
                cx = uc.reg_read(UC_X86_REG_CX)
                dx = uc.reg_read(UC_X86_REG_DX)
                di = uc.reg_read(UC_X86_REG_SI)
                si = uc.reg_read(UC_X86_REG_DI)
                bp = uc.reg_read(UC_X86_REG_BP)
                sp = uc.reg_read(UC_X86_REG_SP)
                ip = uc.reg_read(UC_X86_REG_IP)
                eflags = uc.reg_read(UC_X86_REG_EFLAGS)
                
                print(">>> AX = 0x%x BX = 0x%x CX = 0x%x DX = 0x%x" % (ax, bx, cx, dx))
                print(">>> DI = 0x%x SI = 0x%x BP = 0x%x SP = 0x%x" % (di, si, bp, sp))
                print(">>> IP = 0x%x" % eip)
                print(">>> EFLAGS = 0x%x" % eflags)
            elif self.mode == UC_MODE_32:
                eax = uc.reg_read(UC_X86_REG_EAX)
                ebx = uc.reg_read(UC_X86_REG_EBX)
                ecx = uc.reg_read(UC_X86_REG_ECX)
                edx = uc.reg_read(UC_X86_REG_EDX)
                edi = uc.reg_read(UC_X86_REG_ESI)
                esi = uc.reg_read(UC_X86_REG_EDI)
                ebp = uc.reg_read(UC_X86_REG_EBP)
                esp = uc.reg_read(UC_X86_REG_ESP)
                eip = uc.reg_read(UC_X86_REG_EIP)
                eflags = uc.reg_read(UC_X86_REG_EFLAGS)
                
                print(">>> EAX = 0x%x EBX = 0x%x ECX = 0x%x EDX = 0x%x" % (eax, ebx, ecx, edx))
                print(">>> EDI = 0x%x ESI = 0x%x EBP = 0x%x ESP = 0x%x" % (edi, esi, ebp, esp))
                print(">>> EIP = 0x%x" % eip)
                print(">>> EFLAGS = 0x%x" % eflags)
            elif self.mode == UC_MODE_64:
                rax = uc.reg_read(UC_X86_REG_RAX)
                rbx = uc.reg_read(UC_X86_REG_RBX)
                rcx = uc.reg_read(UC_X86_REG_RCX)
                rdx = uc.reg_read(UC_X86_REG_RDX)
                rdi = uc.reg_read(UC_X86_REG_RSI)
                rsi = uc.reg_read(UC_X86_REG_RDI)
                rbp = uc.reg_read(UC_X86_REG_RBP)
                rsp = uc.reg_read(UC_X86_REG_RSP)
                rip = uc.reg_read(UC_X86_REG_RIP)
                eflags = uc.reg_read(UC_X86_REG_EFLAGS)
                
                print(">>> RAX = 0x%x RBX = 0x%x RCX = 0x%x RDX = 0x%x" % (rax, rbx, rcx, rdx))
                print(">>> RDI = 0x%x RSI = 0x%x RBP = 0x%x RSP = 0x%x" % (rdi, rsi, rbp, rsp))
                print(">>> RIP = 0x%x" % rip)
                print(">>> EFLAGS = 0x%x" % eflags)   
        except UcError as e:
            print("#ERROR: %s" % e)
			
    def setString(self, address, data, init=False):
        addr = self._alignAddr(address)
        size = PAGE_ALIGN
        while addr + size < len(data): size += PAGE_ALIGN
        uc.mem_map(addr, size)
        if init: uc.mem_write(addr, self._getOriginData(addr, size))
        uc.mem_write(address, data)
        return address

    def eFunc(self, address, *args):
        func = get_func(address)
        funcSize = func.endEA - func.startEA
        try:
            uc = Uc(self.arch, self.mode)
            # init code
            addr = self._alignAddr(func.startEA)
            size = PAGE_ALIGN
            while addr + size <= func.endEA: size += PAGE_ALIGN
            uc.mem_map(addr, size)
            code = self._getOriginData(func.startEA, funcSize)
            uc.mem_write(func.startEA, code)

            RA = addr + size - 1 # return addr, for stop emulate
            self._initStackAndArgs(uc, RA, *args)

            # add the invalid memory access hook
            uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, \
                        self._hook_mem_invalid)
            # start emulate
            uc.emu_start(func.startEA, RA)
            
            print("Euclation done. Below is the Result:")
            res = uc.reg_read(self.RES_REG)
            print(">>> function result = %d" % res)
            
            self._showStatus(uc)
        except UcError as e:
            print("#ERROR: %s" % e)
			
    def eSelCode(self):
        codeStart = self._alignAddr(idc.SelStart())
        codeEnd = self._alignAddr(idc.SelEnd())
        print("%x" % codeStart)
        print("%x" % codeEnd)
