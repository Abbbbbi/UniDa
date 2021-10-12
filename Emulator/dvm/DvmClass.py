from Emulator.dvm.DvmMethod import DvmMethod
from Emulator.dvm.DvmObject import DvmObject
from Emulator.utils.Dvm_Helpers import hashCode


class DvmClass:
    def __init__(self, vm, className, superClass, interfaceClasses):
        self.vm = vm
        self.className = className
        self.superClass = superClass
        self.staticMethodMaps = dict()
        self.methodMaps = dict()
        self.interfaceClasses = interfaceClasses

    def newObject(self, value):
        return DvmObject(self, value)

    def hashCode(self):
        return hashCode(self.className)

    def getMethodID(self, methodName, args, isStatic=False):
        signature = self.className + "->" + methodName + args
        h = hashCode(signature)
        mapsName = "staticMethodMaps" if isStatic else "methodMaps"
        if h not in getattr(self, mapsName)[h]:
            setattr(self, mapsName, DvmMethod(self, methodName, args, isStatic))

    def getMethod(self, h, isStatic=False):
        mapsName = "staticMethodMaps" if isStatic else "methodMaps"
        if h in getattr(self, mapsName):
            return getattr(self, mapsName)[h]
        elif self.superClass is not None and h in getattr(self.superClass, mapsName):
            return getattr(self.superClass, mapsName)[h]
        else:
            for interfaceClass in self.interfaceClasses:
                if h in getattr(interfaceClass, mapsName):
                    return getattr(interfaceClass, mapsName)[h]
        return None
