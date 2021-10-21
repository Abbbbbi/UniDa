import logging
import sys

from Emulator.Emulator import Emulator
from BridgeScript.AttachBridge import AttachBridge

logging.basicConfig(level=logging.DEBUG,
                    format='[%(asctime)s %(process)d] %(levelname)s [%(name)s] (%(filename)s:%(lineno)d) - %(message)s',
                    datefmt="%H:%M:%S", stream=sys.stderr)

if __name__ == "__main__":
    # fridaBridge = AttachBridge("com.tencent.mm")
    emulator = Emulator("fridaBridge", is64Bit=True, apkPath="bin/apks/weixin809android1940_arm64.apk")
    emulator.loadLibrary("libwechatnormsg.so", True)
    print(emulator.linker.modules.keys())
