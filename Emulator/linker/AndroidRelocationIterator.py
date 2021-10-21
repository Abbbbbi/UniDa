import copy

from Emulator.linker.SLEB128Decoder import SLEB128Decoder

RELOCATION_GROUPED_BY_INFO_FLAG = 1
RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG = 2
RELOCATION_GROUPED_BY_ADDEND_FLAG = 4
RELOCATION_GROUP_HAS_ADDEND_FLAG = 8


class AndroidRelocationIterator:
    def __init__(self, buffer, elfClass, rela=False):
        self.rela = rela
        self.buffer = buffer
        self.elfClass = elfClass
        self.decoder = SLEB128Decoder(buffer, 32 if self.elfClass == b'\x01' else 64)
        self.reloc = {"r_offset": 0, "r_info": 0, "r_addend": 0, "r_info_type": 0, "r_info_sym": 0}

        self.relocation_count_ = self.decoder.pop_front()
        self.reloc["r_offset"] = self.decoder.pop_front()

        self.relocation_index_ = 0
        self.relocation_group_index_ = 0
        self.group_size_ = 0
        self.group_flags_ = 0
        self.group_r_offset_delta_ = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self.relocation_index_ >= self.relocation_count_:
            raise StopIteration

        if self.relocation_group_index_ == self.group_size_:
            if self.read_group_fields() is not True:
                self.relocation_index_ = 0
                self.relocation_count_ = 0
                return None

        if self.is_relocation_grouped_by_offset_delta():
            self.reloc["r_offset"] += self.group_r_offset_delta_
        else:
            self.reloc["r_offset"] += self.decoder.pop_front()

        if self.is_relocation_grouped_by_info() is not True:
            self.reloc["r_info"] = self.decoder.pop_front()

        if self.is_relocation_group_has_addend() and self.is_relocation_grouped_by_addend() is not True:
            if self.rela is not True:
                raise Exception("unexpected r_addend in android.rel section")
            self.reloc["r_addend"] += self.decoder.pop_front()

        self.relocation_index_ += 1
        self.relocation_group_index_ += 1

        self.reloc["r_info_sym"] = self.reloc["r_info"] >> 8 if self.elfClass == b'\x01' else self.reloc["r_info"] >> 32
        self.reloc["r_info_type"] = self.reloc["r_info"] & 0x0ff if self.elfClass == b'\x01' else self.reloc["r_info"] & 0xffffffff

        return copy.deepcopy(self.reloc)

    def read_group_fields(self):
        self.group_size_ = self.decoder.pop_front()
        self.group_flags_ = self.decoder.pop_front()

        if self.is_relocation_grouped_by_offset_delta():
            self.group_r_offset_delta_ = self.decoder.pop_front()

        if self.is_relocation_grouped_by_info():
            self.reloc["r_info"] = self.decoder.pop_front()

        if self.is_relocation_group_has_addend() and self.is_relocation_grouped_by_addend():
            if self.rela is not True:
                raise Exception("unexpected r_addend in android.rel section")
            self.reloc["r_addend"] += self.decoder.pop_front()
        elif self.is_relocation_group_has_addend() is not True:
            if self.rela:
                self.reloc["r_addend"] = 0

        self.relocation_group_index_ = 0
        return True

    def is_relocation_grouped_by_info(self):
        return (self.group_flags_ & RELOCATION_GROUPED_BY_INFO_FLAG) != 0

    def is_relocation_grouped_by_offset_delta(self):
        return (self.group_flags_ & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) != 0

    def is_relocation_grouped_by_addend(self):
        return (self.group_flags_ & RELOCATION_GROUPED_BY_ADDEND_FLAG) != 0

    def is_relocation_group_has_addend(self):
        return (self.group_flags_ & RELOCATION_GROUP_HAS_ADDEND_FLAG) != 0
