from Emulator.linker import ElfConst
from Emulator.linker.ElfReader import ElfReader
from Emulator.linker.Module import Module
from Emulator.utils.Open_Helpers import openSOByName
from unicorn import *


class Linker:
    def __init__(self, emulator):
        self.emulator = emulator
        self.symbol_hooks = dict()
        self.modules = dict()
        soinfo_area_sz = 0x40000
        self.soinfo_area_base = emulator.memory.mmap(0, soinfo_area_sz, UC_PROT_WRITE | UC_PROT_READ)

    def load_library(self, soName):
        fd = openSOByName(self.emulator, soName)
        if fd is None:
            raise Exception("Lib %s open failed" % soName)

        reader = ElfReader(self.emulator, soName, fd)

        if not reader.load():
            raise Exception("ElfReader load Failed")

        for so_name in reader.so_needed:
            self.do_dlopen(so_name, True)

        symbols_resolved = dict()

        for symbol in reader.dynsymols:
            symbol_address = self.elf_get_symAddr(reader.load_start, symbol)
            if symbol_address is not None:
                name = symbol["name"]
                symbols_resolved[name] = symbol_address

        init_array_offset, init_array_size = reader.get_init_array()
        init_array = []

        for relName in reader.rels:
            for rel in reader.rels[relName]:
                r_type = rel["r_info_type"]
                r_sym = rel["r_info_sym"]
                r_addend = rel["r_addend"]
                reloc = reader.load_start + rel["r_offset"]

                if r_type == 0:
                    print("Unhandled relocation type " + str(r_type))
                    continue

                if r_sym != 0:
                    symbol = reader.dynsymols[r_sym]
                    sym_name = symbol["name"]
                    if r_type == ElfConst.R_ARM_ABS32:
                        if sym_name in symbols_resolved:
                            sym_addr = symbols_resolved[sym_name]
                            reloc_bytes = self.emulator.mu.mem_read(reloc, 4)
                            reloc_value = int.from_bytes(reloc_bytes, byteorder='little')
                            value = sym_addr + reloc_value
                            self.emulator.mu.mem_write(reloc, value.to_bytes(4, byteorder='little'))
                    if r_type == ElfConst.R_AARCH64_ABS64:
                        if sym_name in symbols_resolved:
                            sym_addr = symbols_resolved[sym_name]
                            value = sym_addr + r_addend
                            self.emulator.mu.mem_write(reloc, value.to_bytes(8, byteorder='little'))
                    elif r_type in (ElfConst.R_ARM_GLOB_DAT, ElfConst.R_ARM_JUMP_SLOT):
                        if sym_name in symbols_resolved:
                            value = symbols_resolved[sym_name]
                            self.emulator.mu.mem_write(reloc, value.to_bytes(4, byteorder='little'))
                    elif r_type in (ElfConst.R_AARCH64_GLOB_DAT, ElfConst.R_AARCH64_JUMP_SLOT):
                        if sym_name in symbols_resolved:
                            value = symbols_resolved[sym_name] + r_addend
                            self.emulator.mu.mem_write(reloc, value.to_bytes(8, byteorder='little'))
                    elif r_type in ElfConst.R_ARM_RELATIVE:
                        if symbol["st_value"] == 0:
                            reloc_bytes = self.emulator.mu.mem_read(reloc, 4)
                            reloc_value = int.from_bytes(reloc_bytes, byteorder='little')
                            value = reader.load_start + reloc_value
                            self.emulator.mu.mem_write(reloc, value.to_bytes(4, byteorder='little'))
                        else:
                            raise NotImplementedError()
                    elif r_type in ElfConst.R_AARCH64_RELATIVE:
                        if symbol["st_value"] == 0:
                            value = reader.load_start + r_addend
                            self.emulator.mu.mem_write(reloc, value.to_bytes(8, byteorder='little'))
                        else:
                            raise NotImplementedError()
                    else:
                        print("Unhandled relocation type %i." % r_type)

        if reader.init_off != 0:
            init_array.append(reader.load_start + reader.init_off)

        PointerSize = self.emulator.getPointSize()

        for _ in range(int(init_array_size / PointerSize)):
            b = self.emulator.mu.mem_read(reader.load_start + init_array_offset, PointerSize)
            fun_ptr = int.from_bytes(b, byteorder='little', signed=False)
            if fun_ptr != 0:
                init_array.append(fun_ptr)
            init_array_offset += PointerSize

        module = Module(reader.load_start, reader.load_size, reader.soName, symbols_resolved, init_array,
                        self.soinfo_area_base)
        self.modules[reader.soName] = module
        return module

    def find_loaded_library_by_name(self, soName):
        return self.modules[soName] if soName in self.modules.keys() else None

    def do_dlopen(self, soName, callInit=True):
        module = self.find_loaded_library_by_name(soName)
        if module is not None:
            return module
        module = self.load_library(soName)
        if module is None:
            raise Exception('Module %s not found' % soName)
        if callInit:
            module.callInit(self.emulator)

    def add_symbol_hook(self, symbol_name, addr):
        self.symbol_hooks[symbol_name] = addr

    def elf_get_symAddr(self, elf_base, symbol):
        name = symbol["name"]
        if name in self.symbol_hooks:
            return self.symbol_hooks[name]

        if symbol['st_shndx'] == ElfConst.SHN_UNDEF:
            target = self.elf_lookup_symbol(name)
            if target is None:
                if symbol['st_info_bind'] == ElfConst.STB_WEAK:
                    return 0
                else:
                    print('=> Undefined external symbol: %s' % name)
                    return None
            else:
                return target
        elif symbol['st_shndx'] == ElfConst.SHN_ABS:
            return elf_base + symbol['st_value']
        else:
            return elf_base + symbol['st_value']

    def elf_lookup_symbol(self, name):
        for _, module in self.modules.items():
            if name in module.symbols:
                addr = module.symbols[name]
                if addr != 0:
                    return addr
        return None
