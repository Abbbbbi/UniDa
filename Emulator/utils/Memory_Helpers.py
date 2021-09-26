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

