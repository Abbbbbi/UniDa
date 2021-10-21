from unicorn import UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.arm64_const import *

from unicorn.arm_const import *

PAGE_SIZE = 0x1000

PF_X = 0x1  # Executable
PF_W = 0x2  # Writable
PF_R = 0x4  # Readable

MAP_ANONYMOUS = 0x20
MAP_FIXED = 0x10

MAP_ALLOC_BASE = 0x40000000
MAP_ALLOC_SIZE = 0xA0000000 - MAP_ALLOC_BASE

STACK_ALLOC_BASE = 0xc0000000
STACK_ALLOC_SIZE = 256 * PAGE_SIZE


def PAGE_START(addr):
    return addr & (~(PAGE_SIZE - 1))


def PAGE_END(addr):
    return PAGE_START(addr) + PAGE_SIZE


def PFLAGS_TO_PROT(prot_in):
    prot = 0

    if prot_in & PF_R != 0:
        prot |= 1

    if prot_in & PF_W != 0:
        prot |= 2

    if prot_in & PF_X != 0:
        prot |= 4

    return prot


def getPointerArg(mu, index):
    regArgCount = 4
    R0_REG = UC_ARM_REG_R0
    SP_REG = UC_ARM_REG_SP
    pointerSize = 4
    if mu._arch == 2:
        regArgCount = 8
        R0_REG = UC_ARM64_REG_X0
        SP_REG = UC_ARM64_REG_SP
        pointerSize = 8
    if index < regArgCount:
        return int.from_bytes(mu.reg_read(R0_REG + index), byteorder='little')
    sp = mu.reg_read(SP_REG)
    return int.from_bytes(mu.mem_read(sp + (index - regArgCount) * pointerSize), byteorder='little')


def getLRPointer(mu):
    LR_REG = UC_ARM_REG_LR
    if mu._arch == 2:
        LR_REG = UC_ARM64_REG_LR
    return mu.reg_read(LR_REG)


def ptrStr(linker, addr):
    m = linker.findModuleByAddress(addr)
    protName = ""
    for r in linker.emulator.mu.mem_regions():
        if r[0] <= addr < r[1]:
            prot = r[2]
            if prot & UC_PROT_READ != 0:
                protName += "R"
            if prot & UC_PROT_WRITE != 0:
                protName += "W"
            if prot & UC_PROT_EXEC != 0:
                protName += "X"

    return "%s@0x%X[%s:0x%X]0x%X" % (protName, addr, m.so_name, m.base, addr - m.base)


def toIntPeer(addr):
    return addr & 0xffffffff


def read_utf8(mu, address):
    buffer_address = address
    buffer_read_size = 32
    buffer = b""
    null_pos = None

    # Keep reading until we read something that contains a null terminator.
    while null_pos is None:
        buf_read = mu.mem_read(buffer_address, buffer_read_size)
        if b'\x00' in buf_read:
            null_pos = len(buffer) + buf_read.index(b'\x00')
        buffer += buf_read
        buffer_address += buffer_read_size

    return buffer[:null_pos].decode("utf-8")


def write_utf8(mu, address, value):
    mu.mem_write(address, value.encode(encoding="utf-8") + b"\x00")
    return address


def isThumb(mu):
    pass
