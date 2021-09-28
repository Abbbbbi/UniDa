from unicorn import UC_PROT_WRITE, UC_PROT_READ, UC_PROT_EXEC, UC_HOOK_INTR


class Hooker:
    def __init__(self, emulator):
        self.emulator = emulator
        self.hookMaps = dict()
        hooker_area_size = 0x10000
        self.hooker_area_base = emulator.memory.mmap(0, hooker_area_size, UC_PROT_WRITE | UC_PROT_READ | UC_PROT_EXEC)

    def write_function(self, func):
        hookId = self.findMinHookId()
        asm = "SVC #%s\nRET" % hex(hookId) if self.emulator.is64Bit else "SVC #%s\nbx lr" % hex(hookId)
        asm_bytes_list, asm_count = self.emulator.keystone.asm(bytes(asm, encoding='ascii'))
        if asm_count != 2:
            raise ValueError("Expected asm_count to be 2 instead of %u." % asm_count)
        func_addr = self.hooker_area_base
        self.emulator.mu.mem_write(self.hooker_area_base, bytes(asm_bytes_list))
        self.hooker_area_base += len(asm_bytes_list)
        self.hookMaps[hookId] = func
        return func_addr

    def write_function_table(self, struct_table):
        PointSize = self.emulator.getPointSize()
        tab_len = max(struct_table.keys()) + 1
        struct_table_bytes = b""
        struct_table_addr = self.hooker_area_base
        for index in range(0, tab_len):
            addr = self.write_function(struct_table[index]) if index in struct_table else 0
            struct_table_bytes += int(addr).to_bytes(PointSize, byteorder='little')
        self.emulator.mu.mem_write(struct_table_addr, struct_table_bytes)
        self.hooker_area_base += len(struct_table_bytes)
        ptr_struct_table_addr = self.hooker_area_base
        self.emulator.mu.mem_write(ptr_struct_table_addr, struct_table_addr.to_bytes(PointSize, byteorder='little'))
        self.hooker_area_base += PointSize
        return ptr_struct_table_addr, struct_table_addr

    def findMinHookId(self):
        hookId = 0xFF00
        for key in self.hookMaps.keys():
            if hookId < key:
                hookId = key
        return hookId + 1

    def add_symbol_hook(self, symbol_name, addr):
        self.emulator.linker.symbol_hooks[symbol_name] = addr
