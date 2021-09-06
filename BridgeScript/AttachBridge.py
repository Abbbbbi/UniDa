import os
import pprint
import signal
from pathlib import Path

import frida


class AttachBridge:
    def __init__(self, process):
        device = frida.get_usb_device()
        print("attach")
        session = device.attach(process)
        with open(Path(__file__).resolve().parent.joinpath("./BridgeScript.js"), encoding="utf-8") as f:
            ScriptFile = f.read()
        script = session.create_script(ScriptFile)
        script.on("message", self.onMessage)
        script.load()
        self.exports = script.exports
        self.process = process

    @staticmethod
    def onMessage(message, data):
        if message["type"] == "error":
            pprint.pprint(message)
            os.kill(os.getpid(), signal.SIGTERM)
            return
