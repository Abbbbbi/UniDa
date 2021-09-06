import os
import traceback

from unicorn import *

from Emulator.utils.Memory_Helpers import *


class Memory:
    def __init__(self, emulator, mu):
        self.emulator = emulator
        self.mu = mu

    def mmap(self, address, size, prot=UC_PROT_READ | UC_PROT_WRITE, fdKey=-1, offset=0, mem_reserve=False):
        if not self._is_multiple(address):
            raise Exception('map address was not multiple of page size (%d, %d).' % (address, PAGE_SIZE))
        print("map address:0x%08X, end:0x%08X, sz:0x%08X off=0x%08X" % (address, address + size, size, offset))

        al_address = address
        al_size = PAGE_END(al_address + size) - al_address
        res_addr = self._map(al_address, al_size, prot, mem_reserve)
        if res_addr != -1 and fdKey != -1:
            fd = self.emulator.syscallHandler.FDMaps[fdKey]["fd"]
            fd.seek(offset, 0)
            data = self._read_fully(fd, size)
            self.mu.mem_write(res_addr, data)
        return res_addr

    def _map(self, address, size, prot=UC_PROT_READ | UC_PROT_WRITE, mem_reserve=False):
        if size <= 0:
            raise Exception('Heap map size was <= 0.')
        try:
            if address == 0:
                regions = []
                for r in self.mu.mem_regions():
                    regions.append(r)
                regions.sort()
                map_base = -1
                l_regions = len(regions)
                if l_regions < 1:
                    map_base = MAP_ALLOC_BASE
                else:
                    prefer_start = MAP_ALLOC_BASE
                    next_loop = True
                    while next_loop:
                        next_loop = False
                        for r in regions:
                            if self._is_overlap(prefer_start, prefer_start + size, r[0], r[1] + 1):
                                prefer_start = r[1] + 1
                                next_loop = True
                                break
                    map_base = prefer_start

                if map_base < MAP_ALLOC_BASE or map_base > MAP_ALLOC_BASE + MAP_ALLOC_SIZE:
                    raise RuntimeError("mmap error map_base 0x%08X out of range (0x%08X-0x%08X)!!!" % (
                        map_base, MAP_ALLOC_BASE, MAP_ALLOC_BASE + MAP_ALLOC_SIZE))

                print("before mem_map address:0x%08X, sz:0x%08X" % (map_base, size))

                if not mem_reserve:
                    self.mu.mem_map(map_base, size, perms=prot)
                return map_base
            else:
                # MAP_FIXED
                try:
                    self.mu.mem_map(address, size, perms=prot)
                except unicorn.UcError as e:
                    if e.errno == UC_ERR_MAP:
                        blocks = set()
                        extra_protect = set()
                        for b in range(address, address + size, 0x1000):
                            blocks.add(b)

                        for r in self.mu.mem_regions():
                            # 修改属性
                            raddr = r[0]
                            rend = r[1] + 1
                            for b in range(raddr, rend, 0x1000):
                                if b in blocks:
                                    blocks.remove(b)
                                    extra_protect.add(b)

                        for b_map in blocks:
                            self.mu.mem_map(b_map, 0x1000, prot)

                        for b_protect in extra_protect:
                            self.mu.mem_protect(b_protect, 0x1000, prot)

                return address

        except unicorn.UcError as e:
            for r in self.mu.mem_regions():
                print("region begin :0x%08X end:0x%08X, prot:%d" % (r[0], r[1], r[2]))
            raise

    def protect(self, address, len, prot):
        if not self._is_multiple(address):
            raise Exception('address was not multiple of page size (%d, %d).' % (address, PAGE_SIZE))

        len_in = PAGE_END(address + len) - address
        try:
            self.mu.mem_protect(address, len_in, prot)
        except unicorn.UcError as e:
            print("Warning mprotect with address: 0x%08X len: 0x%08X prot:0x%08X failed!!!" % (address, len, prot))
            return -1
        return 0

    def munmap(self, address, size):
        if not self._is_multiple(address):
            raise Exception('address was not multiple of page size (%d, %d).' % (address, PAGE_SIZE))

        size = PAGE_END(address + size) - address
        try:
            print("unmap 0x%08X sz=0x0x%08X end=0x0x%08X" % (address, size, address + size))
            for fdKey, fdMap in self.emulator.syscallHandler.FDMaps:
                if fdMap["addr"] == address:
                    del self.emulator.syscallHandler.FDMaps[fdKey]
            self.mu.mem_unmap(address, size)
        except unicorn.UcError as e:
            for r in self.mu.mem_regions():
                print("region begin :0x%08X end:0x%08X, prot:%d" % (r[0], r[1], r[2]))
            raise
        return 0

    @staticmethod
    def _read_fully(fd, size):
        b_read = fd.read(size)
        sz_read = len(b_read)
        if sz_read <= 0:
            return b_read

        sz_left = size - sz_read
        while sz_left > 0:
            this_read = os.read(fd, sz_left)
            len_this_read = len(this_read)
            print(len_this_read)
            if len_this_read <= 0:
                break
            b_read = b_read + this_read
            sz_left = sz_left - len_this_read

        return b_read

    @staticmethod
    def _is_overlap(addr1, end1, addr2, end2):
        r = (addr1 <= addr2 and end1 >= end2) or (addr2 <= addr1 and end2 >= end1) or (
                end1 > addr2 and addr1 < end2) or (end2 > addr1 and addr2 < end1)
        return r

    @staticmethod
    def _is_multiple(address):
        return address % PAGE_SIZE == 0
