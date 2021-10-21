from numpy import int32

from Emulator.dvm.DvmClass import DvmClass
from Emulator.dvm.JniConst import *
from Emulator.utils.Dvm_Helpers import hashCode


class DalvikVM:
    def __init__(self):
        self.classMaps = dict()
        self.localObjectMaps = dict()
        self.globalObjectMaps = dict()

    def resolveClass(self, className, interfaceClasses=None):
        superClass = None
        if interfaceClasses is None:
            interfaceClasses = []
        elif len(interfaceClasses) > 0:
            superClass = interfaceClasses[0]
            interfaceClasses = interfaceClasses[1:len(interfaceClasses)]
        classHash = hashCode(className)
        if classHash not in self.classMaps:
            dvmClass = DvmClass(self, className, superClass, interfaceClasses)
            self.classMaps[classHash] = dvmClass
            self.addObject(dvmClass)
        dvmClass = self.classMaps[classHash]
        return dvmClass

    def addObject(self, obj, isGlobal=True, weak=False):
        if obj is None:
            return JNI_NULL
        h = obj.hashCode()
        if isGlobal:
            self.globalObjectMaps[h] = {"obj": obj, "weak": weak}
        else:
            self.localObjectMaps[h] = {"obj": obj, "weak": weak}
        return h

    def getObject(self, h):
        if h in self.globalObjectMaps:
            return self.globalObjectMaps[h].obj
        elif h in self.localObjectMaps:
            return self.localObjectMaps[h].obj
        return None
