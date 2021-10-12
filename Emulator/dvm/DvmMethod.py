class DvmMethod:
    def __init__(self, dvmClass, methodName, args, isStatic=False):
        self.args = args
        self.dvmClass = dvmClass
        self.isStatic = isStatic
        self.methodName = methodName
