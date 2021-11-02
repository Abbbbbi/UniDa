import logging
import os
from unicorn import *
from Emulator.utils.Memory_Helpers import *

logger = logging.getLogger(__name__)


class Memory:
    def __init__(self, emulator):
        self.emulator = emulator
        self.sp = 0
        self.brkAddr = 0
        self.errnoPtr = 0
        self.SP_REG = UC_ARM64_REG_SP if self.emulator.is64Bit else UC_ARM_REG_SP
        self.initStack()
        self.initializeTLS(["ANDROID_DATA=/data",
                            "ANDROID_ROOT=/system"])

    def brk(self,addr):
        if addr == 0:
            self.brkAddr = 0x8048000
            return self.brkAddr

        if addr % PAGE_SIZE != 0:
            raise NotImplementedError("Unsupported brk operation")

        if addr > self.brkAddr:
            self.emulator.mu.mem_map(self.brkAddr, addr-self.brkAddr,UC_PROT_READ|UC_PROT_WRITE)
            self.brkAddr = addr
        elif addr < self.brkAddr:
            self.emulator.mu.mem_unmap(addr,self.brkAddr - addr)
            self.brkAddr = addr

        return self.brkAddr

    def initStack(self):
        self.mmap(STACK_ALLOC_BASE - STACK_ALLOC_SIZE, STACK_ALLOC_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self.emulator.mu.reg_write(self.SP_REG, STACK_ALLOC_BASE)
        self.sp = self.emulator.mu.reg_read(self.SP_REG)
        logger.debug("initStack Success addr=0x%X" % self.sp)

    def initializeTLS(self, envs):
        pointSize = self.emulator.getPointSize()

        thread = self.allocateStack(0x400)

        __stack_chk_guard = self.allocateStack(pointSize)

        processName = self.emulator.processName
        programName = write_utf8(self.emulator.mu, self.allocateStack(len(processName)), processName)
        programNamePtr = self.allocateStack(pointSize)
        self.emulator.mu.mem_write(programNamePtr, programName.to_bytes(pointSize, byteorder='little'))

        auxv = self.allocateStack(0x100)
        num = 25
        self.emulator.mu.mem_write(auxv, num.to_bytes(pointSize, byteorder='little'))
        self.emulator.mu.mem_write(auxv + pointSize, __stack_chk_guard.to_bytes(pointSize, byteorder='little'))

        environ = self.allocateStack(pointSize * (len(envs) + 1))
        ptr = environ
        for env in envs:
            envPtr = write_utf8(self.emulator.mu, self.allocateStack(len(env)), env)
            self.emulator.mu.mem_write(ptr, envPtr.to_bytes(pointSize, byteorder='little'))
            ptr += pointSize
        self.emulator.mu.mem_write(ptr, b'\x00' * 4)
        argv = self.allocateStack(0x100)
        self.emulator.mu.mem_write(argv + pointSize, programNamePtr.to_bytes(pointSize, byteorder='little'))
        self.emulator.mu.mem_write(argv + 2 * pointSize, environ.to_bytes(pointSize, byteorder='little'))
        self.emulator.mu.mem_write(argv + 3 * pointSize, auxv.to_bytes(pointSize, byteorder='little'))
        tls = self.allocateStack(0x80 * 4)
        self.emulator.mu.mem_write(tls + pointSize, thread.to_bytes(pointSize, byteorder='little'))
        self.errnoPtr = tls + 2 * pointSize
        self.emulator.mu.mem_write(tls + 3 * pointSize, argv.to_bytes(pointSize, byteorder='little'))
        if self.emulator.is64Bit:
            self.emulator.mu.reg_write(UC_ARM64_REG_TPIDR_EL0, tls)
        else:
            self.emulator.mu.reg_write(UC_ARM_REG_C13_C0_3, tls)
        logger.debug(
            "initializeTLS Success tls=0x%X thread=0x%X errnoPtr=0x%X argv=0x%X auxv=0x%X environ=0x%X "
            "programNamePtr=0x%X __stack_chk_guard=0x%X" % (
                tls, thread, self.errnoPtr, argv, auxv, environ, programNamePtr, __stack_chk_guard))

    def allocateStack(self, size):
        self.sp = self.sp - size
        self.emulator.mu.reg_write(self.SP_REG, self.sp)
        return self.sp

    def mmap(self, address, size, prot=UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC, fdKey=-1, offset=0,
             mem_reserve=False):
        if not self._is_multiple(address):
            raise Exception('map address was not multiple of page size (%d, %d).' % (address, PAGE_SIZE))
        logger.debug("map address:0x%X, end:0x%X, sz:0x%X offset=0x%X" % (address, address + size, size, offset))

        al_address = address
        # al_size = PAGE_END(al_address + size) - al_address
        al_size = alignSize(size)
        res_addr = self._map(al_address, al_size, prot, mem_reserve)
        if res_addr != -1 and fdKey != -1:
            fo = self.emulator.PCB.FDMaps[fdKey]["fo"]
            fo.seek(offset, 0)
            data = self._read_fully(fo, size)
            self.emulator.mu.mem_write(res_addr, data)
        return res_addr

    def _map(self, address, size, prot=UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC, mem_reserve=False):
        if size <= 0:
            raise Exception('Heap map size was <= 0.')
        try:
            if address == 0:
                regions = []
                for r in self.emulator.mu.mem_regions():
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
                    raise RuntimeError("mmap error map_base 0x%X out of range (0x%X-0x%X)!!!" % (
                        map_base, MAP_ALLOC_BASE, MAP_ALLOC_BASE + MAP_ALLOC_SIZE))

                logger.debug("before mem_map address:0x%X, sz:0x%X" % (map_base, size))

                if not mem_reserve:
                    self.emulator.mu.mem_map(map_base, size, perms=prot)
                return map_base
            else:
                # MAP_FIXED
                try:
                    self.emulator.mu.mem_map(address, size, perms=prot)
                except unicorn.UcError as e:
                    if e.errno == UC_ERR_MAP:
                        blocks = set()
                        extra_protect = set()
                        for b in range(address, address + size, 0x1000):
                            blocks.add(b)

                        for r in self.emulator.mu.mem_regions():
                            # 修改属性
                            raddr = r[0]
                            rend = r[1] + 1
                            for b in range(raddr, rend, 0x1000):
                                if b in blocks:
                                    blocks.remove(b)
                                    extra_protect.add(b)

                        for b_map in blocks:
                            self.emulator.mu.mem_map(b_map, 0x1000, prot)

                        for b_protect in extra_protect:
                            self.emulator.mu.mem_protect(b_protect, 0x1000, prot)

                return address

        except unicorn.UcError as e:
            for r in self.emulator.mu.mem_regions():
                logger.debug("region begin :0x%X end:0x%X, prot:%d" % (r[0], r[1], r[2]))
            raise

    def protect(self, address, len, prot):
        if not self._is_multiple(address):
            raise Exception('address was not multiple of page size (%d, %d).' % (address, PAGE_SIZE))

        try:
            self.emulator.mu.mem_protect(address, len, prot)
        except unicorn.UcError as e:
            logger.warning("Warning mprotect with address: 0x%X len: 0x%X prot:0x%X failed!!!" % (address, len, prot))
            return -1
        return 0

    def munmap(self, address, size):
        if not self._is_multiple(address):
            raise Exception('address was not multiple of page size (%d, %d).' % (address, PAGE_SIZE))
        # size = PAGE_END(address + size) - address
        size = alignSize(size)
        try:
            logger.debug("unmap 0x%X sz=0x%X end=0x%X" % (address, size, address + size))
            for fdKey, fdMap in self.emulator.PCB.FDMaps.items():
                if fdMap["addr"] == address:
                    del self.emulator.PCB.FDMaps[fdKey]
            self.emulator.mu.mem_unmap(address, size)
        except unicorn.UcError as e:
            for r in self.emulator.mu.mem_regions():
                logger.debug("region begin :0x%X end:0x%X, prot:%d" % (r[0], r[1], r[2]))
            raise
        return 0

    @staticmethod
    def _read_fully(fo, size):
        b_read = fo.read(size)
        sz_read = len(b_read)
        if sz_read <= 0:
            return b_read

        sz_left = size - sz_read
        while sz_left > 0:
            this_read = fo.read(sz_left)
            len_this_read = len(this_read)
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
