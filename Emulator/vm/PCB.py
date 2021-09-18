class PCB:
    def __init__(self):
        self.FDMaps = {}
        pass

    def findMinFd(self):
        fd = -1
        for key, _ in self.FDMaps.items():
            if fd < key:
                fd = key
        return fd + 1