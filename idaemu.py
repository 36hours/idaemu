from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
from struct import pack
from idaapi import get_func
from idc import Qword, GetManyBytes, SelStart, SelEnd

PAGE_ALIGN = 0x1000 # 4k

COMPILE_GCC = 1
COMPILE_MSVC = 2

TRACE_OFF = 0
TRACE_DATA_READ = 1
TRACE_DATA_WRITE = 2
TRACE_CODE = 4

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
        self.regs = []
        self.curUC = None
        self.traceOption = TRACE_OFF
        self.logBuffer = []
    
    def _addTrace(self, logInfo):
        self.logBuffer.append(logInfo)

    # callback for tracing invalid memory access (READ or WRITE, FETCH)
    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        addr = self._alignAddr(address)
        uc.mem_map(addr, PAGE_ALIGN)
        data = self._getOriginData(addr, PAGE_ALIGN)
        uc.mem_write(addr, data)
        return True

    def _hook_mem_access(self, uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE and self.traceOption & TRACE_DATA_WRITE:
            self._addTrace("### Memory WRITE at 0x%x, data size = %u, data value = 0x%x" \
                    %(address, size, value))
        elif access == UC_MEM_READ and self.traceOption & TRACE_DATA_READ:
            self._addTrace("### Memory READ at 0x%x, data size = %u" \
                    %(address, size))  

    def _hook_code(self, uc, address, size, user_data):
        self._addTrace("### Trace Instruction at 0x%x, size = %u" %(address, size))

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

    def _getBit(self, value, offset):
        mask = 1 << offset
        return 1 if (value & mask) > 0 else 0

    def _showRegs(self, uc):
        print(">>> regs:")
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
                
                print("    AX = 0x%x BX = 0x%x CX = 0x%x DX = 0x%x" % (ax, bx, cx, dx))
                print("    DI = 0x%x SI = 0x%x BP = 0x%x SP = 0x%x" % (di, si, bp, sp))
                print("    IP = 0x%x" % eip)     
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
                
                print("    EAX = 0x%x EBX = 0x%x ECX = 0x%x EDX = 0x%x" % (eax, ebx, ecx, edx))
                print("    EDI = 0x%x ESI = 0x%x EBP = 0x%x ESP = 0x%x" % (edi, esi, ebp, esp))
                print("    EIP = 0x%x" % eip)
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
                r8 = uc.reg_read(UC_X86_REG_R8)
                r9 = uc.reg_read(UC_X86_REG_R9)
                r10 = uc.reg_read(UC_X86_REG_R10)
                r11 = uc.reg_read(UC_X86_REG_R11)
                r12 = uc.reg_read(UC_X86_REG_R12)
                r13 = uc.reg_read(UC_X86_REG_R13)
                r14 = uc.reg_read(UC_X86_REG_R14)
                r15 = uc.reg_read(UC_X86_REG_R15)
                eflags = uc.reg_read(UC_X86_REG_EFLAGS)
                
                print("    RAX = 0x%x RBX = 0x%x RCX = 0x%x RDX = 0x%x" % (rax, rbx, rcx, rdx))
                print("    RDI = 0x%x RSI = 0x%x RBP = 0x%x RSP = 0x%x" % (rdi, rsi, rbp, rsp))
                print("    R8 = 0x%x R9 = 0x%x R10 = 0x%x R11 = 0x%x R12 = 0x%x " \
                        "R13 = 0x%x R14 = 0x%x R15 = 0x%x" % (r8, r9, r10, r11, r12, r13, r14, r15))
                print("    RIP = 0x%x" % rip)
            print("    EFLAGS:")
            print("    CF=%d PF=%d AF=%d ZF=%d SF=%d TF=%d IF=%d DF=%d OF=%d IOPL=%d " \
                    "NT=%d RF=%d VM=%d AC=%d VIF=%d VIP=%d ID=%d"
                    % (self._getBit(eflags, 0),
                       self._getBit(eflags, 2),
                       self._getBit(eflags, 4),
                       self._getBit(eflags, 6),
                       self._getBit(eflags, 7),
                       self._getBit(eflags, 8),
                       self._getBit(eflags, 9),
                       self._getBit(eflags, 10),
                       self._getBit(eflags, 11),
                       self._getBit(eflags, 12) + self._getBit(eflags, 13) * 2,
                       self._getBit(eflags, 14),
                       self._getBit(eflags, 16),
                       self._getBit(eflags, 17),
                       self._getBit(eflags, 18),
                       self._getBit(eflags, 19),
                       self._getBit(eflags, 20),
                       self._getBit(eflags, 21)))
        except UcError as e:
            print("#ERROR: %s" % e)

    def _initData(self, uc):
        for address, data, init in self.data:
            addr = self._alignAddr(address)
            size = PAGE_ALIGN
            while addr + size < len(data): size += PAGE_ALIGN
            uc.mem_map(addr, size)
            if init: uc.mem_write(addr, self._getOriginData(addr, size))
            uc.mem_write(address, data)

    def _initRegs(self, uc):
        for reg, value in self.regs:
            uc.reg_write(reg, value)

    def _emulate(self, startAddr, stopAddr, *args):
        try:
            self.logBuffer = []
            uc = Uc(self.arch, self.mode)
            self.curUC = uc
            
            self._initStackAndArgs(uc, stopAddr, *args)
            self._initData(uc)
            self._initRegs(uc)
            
            # add the invalid memory access hook
            uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | \
                        UC_HOOK_MEM_FETCH_UNMAPPED, self._hook_mem_invalid)    
            
            # add the trace hook
            if self.traceOption & (TRACE_DATA_READ | TRACE_DATA_WRITE) :
                uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self._hook_mem_access)
            if self.traceOption & TRACE_CODE :
                uc.hook_add(UC_HOOK_CODE, self._hook_code)

            # start emulate
            uc.emu_start(startAddr, stopAddr)
        except UcError as e:
            print("#ERROR: %s" % e)

    # set the data before emulation
    def setData(self, address, data, init=False):
        self.data.append((address, data, init))

    def setReg(self, reg, value):
        self.regs.append((reg, value))

    def showRegs(self, *regs):
        if self.curUC == None:
            print("current uc is none.")
            return
        for reg in regs:
            print("0x%x" % self.curUC.reg_read(reg))
            
    def showData(self, fmt, addr, count = 1):
        if self.curUC == None:
            print("current uc is none.")
            return
        if count > 1: print('[', end="")
        for i in range(count):
            dataSize = struct.calcsize(fmt)
            data = self.curUC.mem_read(addr + i * dataSize, dataSize)
            print(struct.unpack_from(fmt, data)[0], end="")
            if count > 1 and i < count - 1: print(',', end="")
        print(']') if count > 1 else print('')
        
    def setTrace(self, opt):
        if opt != TRACE_OFF:
            self.traceOption |= opt
        else:
            self.traceOption = TRACE_OFF

    def showTrace(self):
        logs = "\n".join(self.logBuffer)
        print(logs)

    def eFunc(self, address, *args):
        func = get_func(address)
        self._emulate(func.startEA, self.RA, *args)
        print("Euclation done. Below is the Result:")
        res = self.curUC.reg_read(self.RES_REG)
        print(">>> function result = %d" % res)
        
    def eBlock(self):
        codeStart = SelStart()
        codeEnd = SelEnd()
        self._emulate(codeStart, codeEnd)
        self._showRegs(self.curUC)
        