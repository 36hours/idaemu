from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *

class Loger(object):
    logs = []
    enable = False

    @staticmethod
    def setEnable(bEnable):
        Loger.enable = bEnable
    
    @staticmethod
    def append(log):
        if not Loger.enable:
            return
        Loger.logs.append(log)
    
    @staticmethod
    def clear():
        Loger.logs.clear()
    
    @staticmethod
    def show():
        if not Loger.enable:
            return
        for log in Loger.logs: print(log)
        
class Hooker(object):

    # callback for tracing basic blocks
    @staticmethod
    def hook_block(uc, address, size, user_data):
        Loger.append(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))

    # callback for tracing instructions
    @staticmethod
    def hook_code(uc, address, size, user_data):
        Loger.append(">>> Tracing instruction at 0x%x, instruction size = %u" %(address, size))
        eip = uc.reg_read(UC_X86_REG_EIP)
        Loger.append(">>> EIP = 0x%x" %(eip))

    # callback for tracing memory access (READ or WRITE)
    @staticmethod
    def hook_mem_access(uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE:
            Loger.append(">>> Memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" \
                    %(address, size, value))
        else:   # READ
            Loger.append(">>> Memory is being READ at 0x%x, data size = %u" \
                    %(address, size))

    @staticmethod
    def debugHook(uc, startAddr, endAddr):
        # tracing all basic blocks with customized callback
        uc.hook_add(UC_HOOK_BLOCK, Hooker.hook_block)

        # tracing all instructions in range [startAddr, endAddr]
        uc.hook_add(UC_HOOK_CODE, Hooker.hook_code, None, startAddr, endAddr)

        # tracing all memory READ & WRITE access
        uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, Hooker.hook_mem_access)