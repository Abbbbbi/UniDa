from unicorn import UC_HOOK_INTR
from unicorn.arm_const import *

from Emulator.hooks.ARMConst import *
from Emulator.utils.Memory_Helpers import isThumb


class ARM32SyscallHandler:
    def __init__(self, emulator):
        self.emulator = emulator
        self.syscallHandlerMaps = {}
        self.emulator.mu.hook_add(UC_HOOK_INTR, self.hook)

    def hook(self, mu, intno, userdata):
        # 断点
        pc = mu.reg_read(UC_ARM_REG_PC)
        if isThumb(mu):
            swi = int.from_bytes(mu.mem_read(pc - 2, 2), byteorder='little') & 0xff
        else:
            swi = int.from_bytes(mu.mem_read(pc - 4, 4), byteorder='little') & 0xffffff
        if intno == EXCP_BKPT:
            return
        if intno != EXCP_SWI:
            mu.emu_stop()
            raise Exception("Unhandled interrupt %d" % intno)
        NR = mu.reg_read(UC_ARM_REG_R7)
        if swi != 0:
            if swi in self.emulator.hooker.hookMaps:
                mu.reg_write(UC_ARM_REG_R0, self.emulator.hooker.hookMaps[swi](mu))
                return
            mu.emu_stop()
            raise Exception("Unhandled svcHook %d" % swi)
        if NR in self.syscallHandlerMaps:
            mu.reg_write(UC_ARM_REG_R0, self.syscallHandlerMaps[NR](mu))
            return
        mu.emu_stop()
        raise Exception("Unhandled svc %d" % NR)
