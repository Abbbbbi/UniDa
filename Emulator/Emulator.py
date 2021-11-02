import logging
from random import randint

from unicorn import *
from keystone import *
from unicorn.arm64_const import *
from unicorn.arm_const import *

from Emulator.dvm.DalvikVM import DalvikVM
from Emulator.hooks.Hooker import Hooker
from Emulator.linker.Linker import Linker
from Emulator.utils.Memory_Helpers import ptrStr
from Emulator.vm.Memory import Memory
from Emulator.vm.ARM32SyscallHandler import ARM32SyscallHandler
from Emulator.vm.ARM64SyscallHandler import ARM64SyscallHandler
from Emulator.vm.PCB import PCB

logger = logging.getLogger(__name__)


def hook_code(uc, address, size, userdata):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x %s" % (address, size, ptrStr(userdata, address)))
    print(
        "UC_ARM_REG_R0 0x%X UC_ARM_REG_R1 0x%X UC_ARM_REG_R2 0x%X UC_ARM_REG_R3 0x%X UC_ARM_REG_R4 0x%X"
        "UC_ARM_REG_R5 0x%X UC_ARM_REG_R6 0x%X UC_ARM_REG_R7 0x%X UC_ARM_REG_R8 0x%X" % (
            uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1), uc.reg_read(UC_ARM_REG_R2),
            uc.reg_read(UC_ARM_REG_R3), uc.reg_read(UC_ARM_REG_R4), uc.reg_read(UC_ARM_REG_R5),
            uc.reg_read(UC_ARM_REG_R6), uc.reg_read(UC_ARM_REG_R7),
            uc.reg_read(UC_ARM_REG_R8)))
    print(
        "PC 0x%X SP 0x%X" % (uc.reg_read(UC_ARM_REG_PC), uc.reg_read(UC_ARM_REG_SP)))


def hook_memory(uc, access, address, size, value, userdata):
    print(userdata)
    pc = uc.reg_read(UC_ARM_REG_PC)
    print("memory error: pc:%s address:%X size:%x" % (ptrStr(userdata, pc), address, size))


class Emulator:
    def __init__(self, fridaBridge, is64Bit=True, apkPath="", processName="UniDa"):
        self.processName = processName
        self.apkPath = apkPath
        self.fridaBridge = fridaBridge
        self.is64Bit = is64Bit
        self.mu = Uc(UC_ARCH_ARM64 if is64Bit else UC_ARCH_ARM, UC_MODE_ARM)
        self.keystone = Ks(KS_ARCH_ARM64 if is64Bit else KS_ARCH_ARM, KS_MODE_LITTLE_ENDIAN if is64Bit else KS_MODE_ARM)
        self.enableVFP()
        self.PCB = PCB()
        self.memory = Memory(self)
        self.vm = DalvikVM()
        self.hooker = Hooker(self)
        self.syscallHandler = ARM64SyscallHandler(self) if is64Bit else ARM32SyscallHandler(self)
        self.linker = Linker(self)
        self.mu.hook_add(UC_HOOK_CODE, hook_code, self.linker)
        # self.mu.hook_add(UC_HOOK_MEM_FETCH_PROT, hook_memory, self.linker)

    def loadLibrary(self, fileName, callInit=False):
        return self.linker.do_dlopen(fileName, callInit)

    def call_native(self, addr, *argv):
        if addr is None:
            raise Exception("Call addr is None")
        LR_REG = UC_ARM_REG_LR
        R0_REG = UC_ARM_REG_R0
        LR = self.hooker.hooker_area_base
        if self.is64Bit:
            LR_REG = UC_ARM64_REG_LR
            R0_REG = UC_ARM64_REG_X0
        self.mu.reg_write(LR_REG, LR)
        try:
            self.mu.emu_start(addr, LR)
        except UcError:
            raise Exception(UcError)
        res = self.mu.reg_read(R0_REG)
        return res

    def enableVFP(self):
        if self.is64Bit:
            value = self.mu.reg_read(UC_ARM64_REG_CPACR_EL1)
            value |= 0x300000
            self.mu.reg_write(UC_ARM64_REG_CPACR_EL1, value)
        else:
            value = self.mu.reg_read(UC_ARM_REG_C1_C0_2)
            value |= (0xf << 20)
            self.mu.reg_write(UC_ARM_REG_C1_C0_2, value)
            self.mu.reg_write(UC_ARM_REG_FPEXC, 0x40000000)

    def getPointSize(self):
        return 8 if self.is64Bit else 4
