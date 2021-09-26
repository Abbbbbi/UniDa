import sys


class PCB:
    def __init__(self):
        self.FDMaps = dict()
        self.FDMaps[self.findMinFd()] = {"fd": sys.stdin, "addr": 0}
        self.FDMaps[self.findMinFd()] = {"fd": sys.stdout, "addr": 0}
        self.FDMaps[self.findMinFd()] = {"fd": sys.stderr, "addr": 0}
        pass

    def findMinFd(self):
        fd = -1
        for key in self.FDMaps.keys():
            if fd < key:
                fd = key
        return fd + 1
