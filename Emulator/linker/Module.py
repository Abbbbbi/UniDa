class Module:
    def __init__(self, base, size, soName, init_array):
        self.base = base
        self.size = size
        self.soName = soName
        self.init_array = init_array
        # self.soinfo_addr = soinfo_addr

    def callInit(self):
        pass

    def callJniOnload(self):
        pass
