rpc.exports = {
    callNativeFunc(soName, exportName, argsTypeArr, retType, args) {
        var funcAddr = Module.findExportByName(soName, exportName)
        var nativeFunc = new NativeFunction(funcAddr, retType, argsTypeArr);
        return nativeFunc.apply(null, args)
    },
    callJniEnvFunc(funcName, args) {
        return Java.vm.tryGetEnv()[funcName].apply(null, args)
    },
    testfunc(soName, exportName) {
        var funcAddr = Module.findExportByName(soName, exportName)
        return funcAddr
    }
}