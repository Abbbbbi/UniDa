import struct

from Emulator.linker import ElfConst
from Emulator.utils.Memory_Helpers import PAGE_START, PAGE_END, PFLAGS_TO_PROT


class ElfReader:
    def __init__(self, emulator, fileName, fd):
        self.fd = fd
        self.fileName = fileName
        self.soName = ""
        self.emulator = emulator
        self.fdKey = emulator.syscallHandler.findMinFd()
        emulator.syscallHandler.FDMaps[self.fdKey] = {"fd": fd, "addr": 0}

        self.elfData = None
        self.elfClass = None
        self.arch = 0
        self.phOffset = 0
        self.phNum = 0
        self.phEntrySize = 0
        self.programHeaderTable = []
        self.load_bias = 0
        self.load_start = 0
        self.load_size = 0

        self.dyn_off = 0
        self.rel_off = 0
        self.rel_size = 0
        self.relplt_off = 0
        self.relplt_size = 0
        self.rel_entry_size = 0
        self.init_off = 0
        self.init_array_off = 0
        self.init_array_size = 0
        self.dt_need = []
        self.plt_got_off = 0
        self.dyn_str_off = 0
        self.dyn_str_size = 0
        self.dyn_str_buf = b''
        self.dyn_sym_off = 0
        self.sym_entry_size = 0
        self.hash_off = 0
        self.gnu_hash_off = 0
        self.nbucket = 0
        self.nchain = 0
        self.bucket = 0
        self.chain = 0
        self.soname_off = 0
        self.dynsymols = []
        self.rels = {}
        self.so_needed = []
        self.is_gnu_hash = False

    def load(self):
        return self.readAndVerifyElfHeader() \
               and self.readProgramHeaders() \
               and self.reserveAddressSpace() \
               and self.loadSegments() \
               and self.loadDynamicSection() \
               and self.loadDone()

    def readAndVerifyElfHeader(self):
        self.fd.seek(0, 0)
        e_ident_size = 0x10
        e_ident_bytes = self.fd.read(e_ident_size)
        ElfMagic, self.elfClass, self.elfData, ElfVersion, _ = struct.unpack("<4ssss9s", e_ident_bytes)
        if ElfMagic != ElfConst.ElfMagic:
            raise Exception('ElfMagic is Invalid : %s' % str(ElfMagic))
        if (self.elfClass == ElfConst.ElfClass32 or self.elfClass == ElfConst.ElfClass64) is not True:
            raise Exception('ElfClass is Invalid : %s' % str(self.elfClass))
        if self.elfData != ElfConst.ElfData2LSB:
            raise Exception('ElfData is Invalid Must be LSB : %s' % str(self.elfData))
        if ElfVersion != ElfConst.ElfVersion:
            raise Exception('ElfVersion is Invalid : %s' % str(ElfVersion))

        Ehdr_size = ElfConst.Ehdr32_size if self.elfClass == b'\x01' else ElfConst.Ehdr64_size
        Ehdr_fmt = "<HHIIIIIHHHHHH" if self.elfClass == b'\x01' else "<HHIQQQIHHHHHH"
        Ehdr_bytes = self.fd.read(Ehdr_size - e_ident_size)
        _, self.arch, _, _, self.phOffset, _, _, _, self.phEntrySize, self.phNum, _, _, _ = struct.unpack(Ehdr_fmt,
                                                                                                          Ehdr_bytes)
        return True

    def readProgramHeaders(self):
        self.fd.seek(self.phOffset, 0)
        for i in range(0, self.phNum):
            Phdr_bytes = self.fd.read(self.phEntrySize)
            if self.elfClass == b'\x01':
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack("<IIIIIIII",
                                                                                                        Phdr_bytes)
            else:
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack("<IIQQQQQQ",
                                                                                                        Phdr_bytes)
            self.programHeaderTable.append(
                {"p_type": p_type, "p_flags": p_flags, "p_offset": p_offset, "p_vaddr": p_vaddr,
                 "p_paddr": p_paddr,
                 "p_filesz": p_filesz, "p_memsz": p_memsz, "p_align": p_align})
        return True

    def reserveAddressSpace(self):
        min_vaddr = ElfConst.UINT64_MAX
        max_vaddr = 0
        found_pt_load = False
        for Phdr in self.programHeaderTable:
            if Phdr["p_type"] != ElfConst.PT_LOAD:
                continue
            found_pt_load = True

            if Phdr["p_vaddr"] < min_vaddr:
                min_vaddr = Phdr["p_vaddr"]

            high = Phdr["p_vaddr"] + Phdr["p_memsz"]
            if high > max_vaddr:
                max_vaddr = high

        if found_pt_load:
            min_vaddr = 0
        max_vaddr = PAGE_END(max_vaddr)
        min_vaddr = PAGE_START(min_vaddr)
        self.load_size = max_vaddr - min_vaddr
        if self.load_size == 0:
            raise Exception('%s has no loadable segments' % self.fileName)
        self.load_start = self.emulator.memory.mmap(min_vaddr, self.load_size, mem_reserve=True)
        self.load_bias = self.load_start - min_vaddr
        self.emulator.syscallHandler.FDMaps[self.fdKey]["addr"] = self.load_start
        return True

    def loadSegments(self):
        for Phdr in self.programHeaderTable:
            if Phdr["p_type"] == ElfConst.PT_DYNAMIC:
                self.dyn_off = Phdr["p_offset"]
                if self.dyn_off == 0:
                    raise Exception('no dynamic in this elf.')
            if Phdr["p_type"] != ElfConst.PT_LOAD:
                continue
            # segment在内存中地址
            seg_start = Phdr["p_vaddr"] + self.load_bias
            seg_end = seg_start + Phdr["p_memsz"]

            seg_page_start = PAGE_START(seg_start)
            seg_page_end = PAGE_END(seg_end)

            seg_file_end = seg_start + Phdr["p_filesz"]

            file_start = Phdr["p_offset"]
            file_end = file_start + Phdr["p_filesz"]

            file_page_start = PAGE_START(file_start)
            file_length = file_end - file_page_start

            if file_length >= 0:
                self.emulator.memory.mmap(seg_page_start, file_length, PFLAGS_TO_PROT(Phdr["p_flags"]),
                                          self.fdKey, file_page_start)

            seg_file_end = PAGE_END(seg_file_end)
            if seg_page_end > seg_file_end:
                self.emulator.memory.mmap(seg_file_end, seg_page_end - seg_file_end,
                                          PFLAGS_TO_PROT(Phdr["p_flags"]))

        return True

    def loadDynamicSection(self):
        Dyn_size = ElfConst.Dyn32_size if self.elfClass == b'\x01' else ElfConst.Dyn64_size
        Dyn_fmt = "<II" if self.elfClass == b'\x01' else "<QQ"
        self.fd.seek(self.dyn_off, 0)
        while True:
            dyn_item_bytes = self.fd.read(Dyn_size)
            d_tag, d_val_ptr = struct.unpack(Dyn_fmt, dyn_item_bytes)
            if d_tag == ElfConst.DT_HASH:
                self.hash_off = d_val_ptr
            if d_tag == ElfConst.DT_GNU_HASH:
                self.gnu_hash_off = d_val_ptr
            if d_tag == ElfConst.DT_PLTGOT:
                self.plt_got_off = d_val_ptr
            if d_tag == ElfConst.DT_REL or d_tag == ElfConst.DT_RELA:
                self.rel_off = d_val_ptr
            if d_tag == ElfConst.DT_RELSZ or d_tag == ElfConst.DT_RELASZ:
                self.rel_size = d_val_ptr
            if d_tag == ElfConst.DT_RELENT or d_tag == ElfConst.DT_RELAENT:
                self.rel_entry_size = d_val_ptr
            if d_tag == ElfConst.DT_JMPREL:
                self.relplt_off = d_val_ptr
            if d_tag == ElfConst.DT_PLTRELSZ:
                self.relplt_size = d_val_ptr
            if d_tag == ElfConst.DT_SYMTAB:
                self.dyn_sym_off = d_val_ptr
            if d_tag == ElfConst.DT_SYMENT:
                self.sym_entry_size = d_val_ptr
            if d_tag == ElfConst.DT_STRTAB:
                self.dyn_str_off = d_val_ptr
            if d_tag == ElfConst.DT_STRSZ:
                self.dyn_str_size = d_val_ptr
            if d_tag == ElfConst.DT_INIT:
                self.init_off = d_val_ptr
            if d_tag == ElfConst.DT_INIT_ARRAY:
                self.init_array_off = d_val_ptr
            if d_tag == ElfConst.DT_INIT_ARRAYSZ:
                self.init_array_size = d_val_ptr
            if d_tag == ElfConst.DT_NEEDED:
                self.dt_need.append(d_val_ptr)
            if d_tag == ElfConst.DT_SONAME:
                self.soname_off = d_val_ptr
            if d_tag == ElfConst.DT_NULL:
                break

        if self.hash_off > 0:
            self.fd.seek(self.virtualMemoryAddrToFileOffset(self.hash_off), 0)
            self.nbucket, self.nchain = struct.unpack("<II", self.fd.read(8))
            self.bucket = self.hash_off + 8
            self.chain = self.hash_off + 8 + self.nbucket * 4
        elif self.gnu_hash_off > 0:
            self.is_gnu_hash = True
            self.fd.seek(self.virtualMemoryAddrToFileOffset(self.gnu_hash_off), 0)
            gnu_nbucket, symndx, gnu_maskwords, gnu_shift2 = struct.unpack("<IIII", self.fd.read(16))
            self.nchain = symndx
            gnu_bloom_filter = self.gnu_hash_off + 16
            gnu_bucket = gnu_bloom_filter + gnu_maskwords
            gnu_chain = gnu_bucket + gnu_nbucket - symndx

        if self.dyn_str_off > 0:
            self.fd.seek(self.virtualMemoryAddrToFileOffset(self.dyn_str_off), 0)
            self.dyn_str_buf = self.fd.read(self.dyn_str_size)

        if self.soname_off > 0:
            self.soName = self.st_name_to_name(self.soname_off)

        if self.dyn_sym_off > 0:
            self.fd.seek(self.dyn_sym_off, 0)
            for i in range(0, self.nchain):
                sym_bytes = self.fd.read(self.sym_entry_size)
                if self.elfClass == b'\x01':
                    st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack("<IIIccH", sym_bytes)
                else:
                    st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack("<IccHQQ", sym_bytes)
                int_st_info = int.from_bytes(st_info, byteorder='little', signed=False)
                st_info_bind = int_st_info >> 4
                st_info_type = int_st_info & 0x0f
                name = self.st_name_to_name(st_name)
                self.dynsymols.append(
                    {"name": name, "st_name": st_name, "st_value": st_value, "st_size": st_size, "st_info": st_info,
                     "st_other": st_other,
                     "st_shndx": st_shndx, "st_info_bind": st_info_bind, "st_info_type": st_info_type})

        if self.rel_off > 0:
            self.fd.seek(self.rel_off, 0)
            rel_table = []
            rel_count = int(self.rel_size / self.rel_entry_size)
            for i in range(0, rel_count):
                rel_item_bytes = self.fd.read(self.rel_entry_size)
                r_offset, r_info, r_addend = 0, 0, 0
                if self.rel_entry_size == 8 or self.rel_entry_size == 16:
                    rel_fmt = "<II" if self.elfClass == b'\x01' else "<QQ"
                    r_offset, r_info = struct.unpack(rel_fmt, rel_item_bytes)
                elif self.rel_entry_size == 12 or self.rel_entry_size == 24:
                    rel_fmt = "<III" if self.elfClass == b'\x01' else "<QQQ"
                    r_offset, r_info, r_addend = struct.unpack(rel_fmt, rel_item_bytes)
                r_info_sym = r_info >> 8 if self.elfClass == b'\x01' else r_info >> 32
                r_info_type = r_info & 0x0ff if self.elfClass == b'\x01' else r_info & 0xffffffff
                rel_table.append(
                    {"r_offset": r_offset, "r_info": r_info, "r_addend": r_addend, "r_info_type": r_info_type,
                     "r_info_sym": r_info_sym})
            self.rels["dynrel"] = rel_table

        if self.relplt_off > 0:
            self.fd.seek(self.relplt_off, 0)
            relplt_table = []
            relplt_count = int(self.relplt_size / self.rel_entry_size)
            for i in range(0, relplt_count):
                relplt_item_bytes = self.fd.read(self.rel_entry_size)
                r_offset, r_info, r_addend = 0, 0, 0
                if self.rel_entry_size == 8 or self.rel_entry_size == 16:
                    relplt_fmt = "<II" if self.elfClass == b'\x01' else "<QQ"
                    r_offset, r_info = struct.unpack(relplt_fmt, relplt_item_bytes)
                elif self.rel_entry_size == 12 or self.rel_entry_size == 24:
                    relplt_fmt = "<III" if self.elfClass == b'\x01' else "<QQQ"
                    r_offset, r_info, r_addend = struct.unpack(relplt_fmt, relplt_item_bytes)
                r_info_sym = r_info >> 8 if self.elfClass == b'\x01' else r_info >> 32
                r_info_type = r_info & 0x0ff if self.elfClass == b'\x01' else r_info & 0xffffffff
                relplt_table.append(
                    {"r_offset": r_offset, "r_info": r_info, "r_addend": r_addend, "r_info_type": r_info_type,
                     "r_info_sym": r_info_sym})
            self.rels["relplt"] = relplt_table

        for str_off in self.dt_need:
            self.so_needed.append(self.st_name_to_name(str_off))
        return True

    def loadDone(self):
        self.fd.close()
        del self.emulator.syscallHandler.FDMaps[self.fdKey]
        return True

    def st_name_to_name(self, st_name):
        if not st_name < self.dyn_str_size:
            raise Exception('st_name_to_name st_name %d out of range %d' % (st_name, self.dyn_str_size))

        endId = self.dyn_str_buf.find(b"\x00", st_name)
        r = self.dyn_str_buf[st_name:endId]
        name = r.decode("utf-8")
        return name

    def get_dyn_string_by_rel_sym(self, rel_sym):
        nsym = len(self.dynsymols)
        assert rel_sym < nsym
        sym = self.dynsymols[rel_sym]
        st_name = sym["st_name"]
        r = self.st_name_to_name(st_name)
        return r

    def virtualMemoryAddrToFileOffset(self, address):
        for Phdr in self.programHeaderTable:
            if Phdr["p_vaddr"] <= address < (Phdr["p_vaddr"] + Phdr["p_memsz"]):
                relativeOffset = address - Phdr["p_vaddr"]
                if relativeOffset >= Phdr["p_filesz"]:
                    raise Exception(
                        "Can not convert virtual memory address %08x to file offset - found segment %s but address "
                        "maps "
                        "to memory outside file range" % (address, str(Phdr)))
                return Phdr["p_offset"] + relativeOffset
        raise Exception("Cannot find segment for address %08x" % address)
