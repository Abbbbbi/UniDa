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


def getPointerArg(mu, index, is64=True):
    regArgCount = 4
    ArgReg0 = UC_ARM_REG_R0
    SPReg = UC_ARM_REG_SP
    if is64:
        regArgCount = 8
        ArgReg0 = UC_ARM64_REG_X0
        SPReg = UC_ARM64_REG_SP
    if index < regArgCount:
        return mu.mem_read(ArgReg0 + index)

    return mu.mem_read(SPReg)


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
