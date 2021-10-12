from unicorn import *
from keystone import *

from Emulator.dvm.DalvikVM import DalvikVM
from Emulator.hooks.Hooker import Hooker
from Emulator.linker.Linker import Linker
from Emulator.vm.Memory import Memory
from Emulator.hooks.ARM32SyscallHandler import ARM32SyscallHandler
from Emulator.hooks.ARM64SyscallHandler import ARM64SyscallHandler
from Emulator.vm.PCB import PCB


class Emulator:
    def __init__(self, fridaBridge, is64Bit=True, apkPath=""):
        self.apkPath = apkPath
        self.fridaBridge = fridaBridge
        self.is64Bit = is64Bit
        self.mu = Uc(UC_ARCH_ARM64 if is64Bit else UC_MODE_ARM, UC_MODE_ARM)
        self.keystone = Ks(KS_ARCH_ARM64 if is64Bit else KS_ARCH_ARM, KS_MODE_LITTLE_ENDIAN if is64Bit else KS_MODE_ARM)
        self.PCB = PCB()
        self.memory = Memory(self)
        self.vm = DalvikVM()
        self.hooker = Hooker(self)
        self.syscallHandler = ARM64SyscallHandler(self) if is64Bit else ARM32SyscallHandler(self)
        self.linker = Linker(self)

    def loadLibrary(self, fileName, callInit=False):
        return self.linker.do_dlopen(fileName, callInit)

    def call_native(self, addr, *argv):
        pass

    def getPointSize(self):
        return 8 if self.is64Bit else 4
