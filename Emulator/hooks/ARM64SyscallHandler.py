from unicorn import UC_HOOK_INTR
from unicorn.arm64_const import *

from Emulator.hooks.ARMConst import *


class ARM64SyscallHandler:
    def __init__(self, emulator):
        self.emulator = emulator
        self.syscallHandlerMaps = {}
        self.emulator.mu.hook_add(UC_HOOK_INTR, self.hook)

    def hook(self, mu, intno, swi, userdata):
        # 断点
        if intno == EXCP_BKPT:
            return
        if intno != EXCP_SWI:
            raise Exception("Unhandled interrupt %d" % intno)
        NR = mu.reg_read(UC_ARM64_REG_X8)
        if swi != 0:
            if swi in self.emulator.hooker.hookMaps:
                mu.reg_write(UC_ARM64_REG_X0, self.emulator.hooker.hookMaps[swi](mu))
                return
            mu.emu_stop()
            raise Exception("Unhandled svcHook %d" % swi)
        if NR in self.syscallHandlerMaps:
            mu.reg_write(UC_ARM64_REG_X0, self.syscallHandlerMaps[NR](mu))
            return
        mu.emu_stop()
        raise Exception("Unhandled sv %d" % NR)
