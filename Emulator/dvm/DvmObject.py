class DvmObject:
    def __init__(self, dvmClass, value):
        self.vm = dvmClass.vm
        self.value = value
        self.dvmClass = dvmClass

    def hashCode(self):
        return self.__hash__()
