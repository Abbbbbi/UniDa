from unicorn import *

from Emulator.linker.Linker import Linker
from Emulator.vm.Memory import Memory
from Emulator.vm.SyscallHandler import SyscallHandler


class Emulator:
    def __init__(self, fridaBridge, is64Bit=True, apkPath=""):
        self.apkPath = apkPath
        self.fridaBridge = fridaBridge
        self.is64Bit = is64Bit
        self.mu = Uc(UC_ARCH_ARM64 if is64Bit else UC_MODE_ARM, UC_MODE_ARM)
        self.memory = Memory(self, self.mu)
        self.linker = Linker(self)
        self.syscallHandler = SyscallHandler()

    def loadLibrary(self, fileName, callInit=False):
        return self.linker.do_dlopen(fileName, callInit)

    def call_native(self, addr, *argv):
        pass
