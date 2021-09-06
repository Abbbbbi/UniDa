from Emulator.linker.ElfReader import ElfReader
from Emulator.linker.Module import Module
from Emulator.utils.Open_Helpers import openSOByName


class Linker:
    def __init__(self, emulator):
        self.emulator = emulator
        self.modules = list()

    def load_library(self, soName):
        fd = openSOByName(self.emulator, soName)
        if fd is None:
            raise Exception("Lib %s open failed" % soName)

        reader = ElfReader(self.emulator, soName, fd)

        if not reader.load():
            raise Exception("ElfReader load Failed")

        self.soinfo_link_image(reader)

        module = Module(reader.load_start, reader.load_size, reader.soName, reader.load_bias)
        self.modules.append(module)
        return module

    def find_loaded_library_by_name(self, soName):
        for module in self.modules:
            if soName in module.soName:
                return module
        return None

    def do_dlopen(self, soName, callInit=True):
        module = self.find_loaded_library_by_name(soName)
        if module is not None:
            return module
        module = self.load_library(soName)
        if module is None:
            raise Exception('Module %s not found' % soName)
        if callInit:
            module.callInit()

    def soinfo_link_image(self, elfReader):
        for so_name in elfReader.so_needed:
            self.do_dlopen(so_name, True)
            pass
        pass
