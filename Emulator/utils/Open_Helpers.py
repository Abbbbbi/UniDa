import os
import zipfile


def openSOByName(emu, soName):
    if emu.apkPath != "":
        apkFD = openApkLib(emu, soName)
        if apkFD is not None:
            return apkFD
    baseLibPath = "SystemLib/SDK23/%s" % "lib64" if emu.is64Bit else "lib"
    for fileName in os.listdir(baseLibPath):
        if soName.replace("+", "p") in fileName:
            return open(baseLibPath + "/" + fileName, 'rb')
    return None


def openApkLib(emu, soName):
    if not zipfile.is_zipfile(emu.apkPath):
        raise Exception("%s is not a zipfile" % emu.apkPath)
    z = zipfile.ZipFile(emu.apkPath)
    for filePath in z.namelist():
        if soName in filePath and ("arm64-v8a" if emu.is64Bit else "armeabi-v7a") in filePath:
            return z.open(filePath)
    z.close()
    return None
