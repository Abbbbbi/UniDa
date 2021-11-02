import logging
import os
import sys
import time

from Emulator.utils.Memory_Helpers import PAGE_SIZE

logger = logging.getLogger(__name__)

S_IFREG = 0x8000
S_IFDIR = 0x4000
S_IFCHR = 0x2000
S_IFLNK = 0xa000
S_IFSOCK = 0xc000

_IOC_NRBITS = 8
_IOC_TYPEBITS = 8
_IOC_SIZEBITS = 14

_IOC_WRITE = 1
_IOC_READ = 2

ANDROID_ALARM_GET_TIME = 4

AndroidAlarmType = [
    "ANDROID_ALARM_RTC_WAKEUP",
    "ANDROID_ALARM_RTC",
    "ANDROID_ALARM_ELAPSED_REALTIME_WAKEUP",
    "ANDROID_ALARM_ELAPSED_REALTIME",
    "ANDROID_ALARM_SYSTEMTIME",
    "ANDROID_ALARM_TYPE_COUNT"
]


class PCB:
    def __init__(self):
        self.FDMaps = dict()
        self.FDMaps[self.findMinFd()] = {"pathname": "stdin", "fo": sys.stdin, "fd": sys.stdin.fileno(), "addr": -1}
        self.FDMaps[self.findMinFd()] = {"pathname": "stdout", "fo": sys.stdout, "fd": sys.stdout.fileno(), "addr": -1}
        self.FDMaps[self.findMinFd()] = {"pathname": "stderr", "fo": sys.stderr, "fd": sys.stderr.fileno(), "addr": -1}

    def findMinFd(self):
        fd = -1
        for key in self.FDMaps.keys():
            if fd < key:
                fd = key
        return fd + 1

    def open(self, emulator, pathname, oflags):
        minFd = self.findMinFd()
        filename = pathname
        if pathname.startswith("/dev") or pathname.startswith("/proc") or pathname.startswith("/system"):
            filename = "Android/SDK23%s" % pathname
        if pathname == "/dev/alarm":
            self.FDMaps[minFd] = {"pathname": pathname, "fo": -1, "fd": -1, "addr": -1}
        else:
            fd = os.open(filename, os.O_RDONLY | os.O_BINARY)
            fo = open(fd, 'rb')
            self.FDMaps[minFd] = {"pathname": pathname, "fo": fo, "fd": fd, "addr": -1}
        return minFd

    def fstat(self, mu, fd, stat_ptr):
        f = self.FDMaps[fd]
        stat = os.stat(f["fd"])

        st_rdev = 0
        st_mode = S_IFREG
        st_blksize = PAGE_SIZE
        st_blocks = (stat.st_size + PAGE_SIZE - 1) / PAGE_SIZE
        stdev = stat.st_dev

        uid = 10086
        if f["pathname"] == "/dev/__properties__":
            uid = 0
        if hasattr(stat, "st_rdev"):
            st_rdev = stat.st_rdev
        if hasattr(stat, "st_blksize"):
            st_blksize = stat.st_blksize
        if hasattr(stat, "st_blocks"):
            st_blocks = stat.st_blocks
        if stdev < 0:
            stdev = stdev * -1

        mu.mem_write(stat_ptr, int(stdev).to_bytes(8, byteorder='little'))
        mu.mem_write(stat_ptr + 8, int(0).to_bytes(4, byteorder='little'))  # PAD 4
        mu.mem_write(stat_ptr + 12, int(stat.st_ino).to_bytes(8, byteorder='little', signed=False))
        mu.mem_write(stat_ptr + 16, int(st_mode).to_bytes(4, byteorder='little'))
        mu.mem_write(stat_ptr + 20, int(stat.st_nlink).to_bytes(4, byteorder='little'))
        mu.mem_write(stat_ptr + 24, int(uid).to_bytes(4, byteorder='little'))
        mu.mem_write(stat_ptr + 28, int(uid).to_bytes(4, byteorder='little'))
        mu.mem_write(stat_ptr + 32, int(st_rdev).to_bytes(8, byteorder='little'))
        mu.mem_write(stat_ptr + 40, int(0).to_bytes(4, byteorder='little'))  # PAD 4
        mu.mem_write(stat_ptr + 48, int(stat.st_size).to_bytes(8, byteorder='little'))
        mu.mem_write(stat_ptr + 56, int(st_blksize).to_bytes(4, byteorder='little'))
        mu.mem_write(stat_ptr + 64, int(st_blocks).to_bytes(8, byteorder='little'))

        mu.mem_write(stat_ptr + 72, int(stat.st_atime).to_bytes(8, byteorder='little'))
        mu.mem_write(stat_ptr + 80, int(stat.st_mtime).to_bytes(8, byteorder='little'))
        mu.mem_write(stat_ptr + 88, int(stat.st_ctime).to_bytes(8, byteorder='little'))

        mu.mem_write(stat_ptr + 96, int(stat.st_ino).to_bytes(8, byteorder='little'))

        return 0

    def close(self, fd):
        os.close(self.FDMaps[fd]["fd"])
        del self.FDMaps[fd]
        return 0

    def read(self, mu, fd, buffer_ptr, count):
        fo = self.FDMaps[fd]["fo"]
        buf = fo.read(count)
        mu.mem_write(buffer_ptr, buf)
        return len(buf)

    def ioctl(self, mu, fd, request, argp):
        fdMap = self.FDMaps[fd]
        if fdMap["pathname"] == "/dev/alarm":
            ioc = request
            nr = ioc & 0xff
            ioc >>= _IOC_NRBITS
            type = ioc & 0xff
            ioc >>= _IOC_TYPEBITS
            size = ioc & 0x3ff
            ioc >>= _IOC_SIZEBITS
            dir = ioc
            if chr(type) == 'a':
                c = nr & 0xf
                type = nr >> 4
                return self.androidAlarm(mu, dir, c, type, size, argp)
            logger.info("alarm ioctl request=0x%X, argp=0x%X, nr= %d, type= %d, size= %d, dir= %d" % (
                request, argp, nr, type, size, dir))

        return -1

    def androidAlarm(self, mu, dir, c, type, size, argp):
        if dir == _IOC_WRITE and c == ANDROID_ALARM_GET_TIME and AndroidAlarmType[type] == "ANDROID_ALARM_ELAPSED_REALTIME":
            t = int(round(time.time() * 1000))
            tv_sec = int(t / 1000000000)
            tv_nsec = int(t % 1000000000)
            print(tv_sec)
            if size == 8:
                mu.mem_write(argp, tv_sec.to_bytes(4, byteorder='little'))
                mu.mem_write(argp + 4, tv_nsec.to_bytes(4, byteorder='little'))
                return 0
            elif self == 16:
                mu.mem_write(argp, tv_sec.to_bytes(8, byteorder='little'))
                mu.mem_write(argp + 8, tv_nsec.to_bytes(8, byteorder='little'))
                return 0
            else:
                raise Exception("androidAlarm invalid size= %d" % size)

        logger.info("androidAlarm argp=0x%X, c= %d, type= %s, size= %d, dir= %d" % (argp, c, type, size, dir))
        return -1
