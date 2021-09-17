class Module:
    def __init__(self, base, size, so_name, symbols_resolved, init_array, soinfo_addr):
        self.base = base
        self.size = size
        self.so_name = so_name
        self.symbol_lookup = dict()
        self.symbols = symbols_resolved
        self.init_array = init_array
        self.soinfo_addr = soinfo_addr
        
        for symbol_name in self.symbols:
            addr = self.symbols[symbol_name]
            if addr != 0:
                self.symbol_lookup[addr] = symbol_name

    def callInit(self, emulator):
        for fun_ptr in self.init_array:
            fun_addr = fun_ptr
            print("Calling Init_array %s function: 0x%08X " % (self.so_name, fun_addr))
            emulator.call_native(fun_addr)

    def callJniOnload(self):
        pass
