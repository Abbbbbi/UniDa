import logging

from unicorn import UC_HOOK_INTR
from unicorn.arm_const import *

from Emulator.hooks.ARMConst import *
from Emulator.utils.Memory_Helpers import isThumb, read_utf8, ptrStr, getLRPointer, write_utf8, PAGE_SIZE, alignSize

logger = logging.getLogger(__name__)

MMAP2_SHIFT = 12

FUTEX_WAIT = 0
FUTEX_WAKE = 1

PR_GET_DUMPABLE = 3
PR_SET_DUMPABLE = 4
PR_SET_NAME = 15
PR_GET_NAME = 16
BIONIC_PR_SET_VMA = 0x53564d41
PR_SET_PTRACER = 0x59616d61


class ARM32SyscallHandler:
    def __init__(self, emulator):
        self.emulator = emulator
        self.syscallHandlerMaps = {
            0: self.restart_syscall,
            1: self.exit,
            2: self.fork,
            3: self.read,
            4: self.write,
            5: self.open,
            6: self.close,
            8: self.creat,
            9: self.link,
            10: self.unlink,
            11: self.execve,
            12: self.chdir,
            14: self.mknod,
            15: self.chmod,
            16: self.lchown,
            19: self.lseek,
            20: self.getpid,
            21: self.mount,
            23: self.setuid,
            24: self.getuid,
            26: self.ptrace,
            29: self.pause,
            33: self.access,
            34: self.nice,
            36: self.sync,
            37: self.kill,
            38: self.rename,
            39: self.mkdir,
            40: self.rmdir,
            41: self.dup,
            42: self.pipe,
            43: self.times,
            45: self.brk,
            46: self.setgid,
            47: self.getgid,
            49: self.geteuid,
            50: self.getegid,
            51: self.acct,
            52: self.umount2,
            54: self.ioctl,
            55: self.fcntl,
            57: self.setpgid,
            60: self.umask,
            61: self.chroot,
            62: self.ustat,
            63: self.dup2,
            64: self.getppid,
            65: self.getpgrp,
            66: self.setsid,
            67: self.sigaction,
            70: self.setreuid,
            71: self.setregid,
            72: self.sigsuspend,
            73: self.sigpending,
            74: self.sethostname,
            75: self.setrlimit,
            77: self.getrusage,
            78: self.gettimeofday,
            79: self.settimeofday,
            80: self.getgroups,
            81: self.setgroups,
            83: self.symlink,
            85: self.readlink,
            86: self.uselib,
            87: self.swapon,
            88: self.reboot,
            91: self.munmap,
            92: self.truncate,
            93: self.ftruncate,
            94: self.fchmod,
            95: self.fchown,
            96: self.getpriority,
            97: self.setpriority,
            99: self.statfs,
            100: self.fstatfs,
            103: self.syslog,
            104: self.setitimer,
            105: self.getitimer,
            106: self.stat,
            107: self.lstat,
            108: self.fstat,
            111: self.vhangup,
            114: self.wait4,
            115: self.swapoff,
            116: self.sysinfo,
            118: self.fsync,
            119: self.sigreturn,
            120: self.clone,
            121: self.setdomainname,
            122: self.uname,
            124: self.adjtimex,
            125: self.mprotect,
            126: self.sigprocmask,
            128: self.init_module,
            129: self.delete_module,
            131: self.quotactl,
            132: self.getpgid,
            133: self.fchdir,
            134: self.bdflush,
            135: self.sysfs,
            136: self.personality,
            138: self.setfsuid,
            139: self.setfsgid,
            140: self._llseek,
            141: self.getdents,
            142: self._newselect,
            143: self.flock,
            144: self.msync,
            145: self.readv,
            146: self.writev,
            147: self.getsid,
            148: self.fdatasync,
            149: self._sysctl,
            150: self.mlock,
            151: self.munlock,
            152: self.mlockall,
            153: self.munlockall,
            154: self.sched_setparam,
            155: self.sched_getparam,
            156: self.sched_setscheduler,
            157: self.sched_getscheduler,
            158: self.sched_yield,
            159: self.sched_get_priority_max,
            160: self.sched_get_priority_min,
            161: self.sched_rr_get_interval,
            162: self.nanosleep,
            163: self.mremap,
            164: self.setresuid,
            165: self.getresuid,
            168: self.poll,
            169: self.nfsservctl,
            170: self.setresgid,
            171: self.getresgid,
            172: self.prctl,
            173: self.rt_sigreturn,
            174: self.rt_sigaction,
            175: self.rt_sigprocmask,
            176: self.rt_sigpending,
            177: self.rt_sigtimedwait,
            178: self.rt_sigqueueinfo,
            179: self.rt_sigsuspend,
            180: self.pread64,
            181: self.pwrite64,
            182: self.chown,
            183: self.getcwd,
            184: self.capget,
            185: self.capset,
            186: self.sigaltstack,
            187: self.sendfile,
            190: self.vfork,
            191: self.ugetrlimit,
            192: self.mmap2,
            193: self.truncate64,
            194: self.ftruncate64,
            195: self.stat64,
            196: self.lstat64,
            197: self.fstat64,
            198: self.lchown32,
            199: self.getuid32,
            200: self.getgid32,
            201: self.geteuid32,
            202: self.getegid32,
            203: self.setreuid32,
            204: self.setregid32,
            205: self.getgroups32,
            206: self.setgroups32,
            207: self.fchown32,
            208: self.setresuid32,
            209: self.getresuid32,
            210: self.setresgid32,
            211: self.getresgid32,
            212: self.chown32,
            213: self.setuid32,
            214: self.setgid32,
            215: self.setfsuid32,
            216: self.setfsgid32,
            217: self.getdents64,
            218: self.pivot_root,
            219: self.mincore,
            220: self.madvise,
            221: self.fcntl64,
            224: self.gettid,
            225: self.readahead,
            226: self.setxattr,
            227: self.lsetxattr,
            228: self.fsetxattr,
            229: self.getxattr,
            230: self.lgetxattr,
            231: self.fgetxattr,
            232: self.listxattr,
            233: self.llistxattr,
            234: self.flistxattr,
            235: self.removexattr,
            236: self.lremovexattr,
            237: self.fremovexattr,
            238: self.tkill,
            239: self.sendfile64,
            240: self.futex,
            241: self.sched_setaffinity,
            242: self.sched_getaffinity,
            243: self.io_setup,
            244: self.io_destroy,
            245: self.io_getevents,
            246: self.io_submit,
            247: self.io_cancel,
            248: self.exit_group,
            249: self.lookup_dcookie,
            250: self.epoll_create,
            251: self.epoll_ctl,
            252: self.epoll_wait,
            253: self.remap_file_pages,
            256: self.set_tid_address,
            257: self.timer_create,
            258: self.timer_settime,
            259: self.timer_gettime,
            260: self.timer_getoverrun,
            261: self.timer_delete,
            262: self.clock_settime,
            263: self.clock_gettime,
            264: self.clock_getres,
            265: self.clock_nanosleep,
            266: self.statfs64,
            267: self.fstatfs64,
            268: self.tgkill,
            269: self.utimes,
            270: self.arm_fadvise64_64,
            271: self.pciconfig_iobase,
            272: self.pciconfig_read,
            273: self.pciconfig_write,
            274: self.mq_open,
            275: self.mq_unlink,
            276: self.mq_timedsend,
            277: self.mq_timedreceive,
            278: self.mq_notify,
            279: self.mq_getsetattr,
            280: self.waitid,
            281: self.socket,
            282: self.bind,
            283: self.connect,
            284: self.listen,
            285: self.accept,
            286: self.getsockname,
            287: self.getpeername,
            288: self.socketpair,
            289: self.send,
            290: self.sendto,
            291: self.recv,
            292: self.recvfrom,
            293: self.shutdown,
            294: self.setsockopt,
            295: self.getsockopt,
            296: self.sendmsg,
            297: self.recvmsg,
            298: self.semop,
            299: self.semget,
            300: self.semctl,
            301: self.msgsnd,
            302: self.msgrcv,
            303: self.msgget,
            304: self.msgctl,
            305: self.shmat,
            306: self.shmdt,
            307: self.shmget,
            308: self.shmctl,
            309: self.add_key,
            310: self.request_key,
            311: self.keyctl,
            312: self.semtimedop,
            314: self.ioprio_set,
            315: self.ioprio_get,
            316: self.inotify_init,
            317: self.inotify_add_watch,
            318: self.inotify_rm_watch,
            319: self.mbind,
            320: self.get_mempolicy,
            321: self.set_mempolicy,
            322: self.openat,
            323: self.mkdirat,
            324: self.mknodat,
            325: self.fchownat,
            326: self.futimesat,
            327: self.fstatat64,
            328: self.unlinkat,
            329: self.renameat,
            330: self.linkat,
            331: self.symlinkat,
            332: self.readlinkat,
            333: self.fchmodat,
            334: self.faccessat,
            335: self.pselect6,
            336: self.ppoll,
            337: self.unshare,
            338: self.set_robust_list,
            339: self.get_robust_list,
            340: self.splice,
            341: self.sync_file_range2,
            342: self.tee,
            343: self.vmsplice,
            344: self.move_pages,
            345: self.getcpu,
            346: self.epoll_pwait,
            347: self.kexec_load,
            348: self.utimensat,
            349: self.signalfd,
            350: self.timerfd_create,
            351: self.eventfd,
            352: self.fallocate,
            353: self.timerfd_settime,
            354: self.timerfd_gettime,
            355: self.signalfd4,
            356: self.eventfd2,
            357: self.epoll_create1,
            358: self.dup3,
            359: self.pipe2,
            360: self.inotify_init1,
            361: self.preadv,
            362: self.pwritev,
            363: self.rt_tgsigqueueinfo,
            364: self.perf_event_open,
            365: self.recvmmsg,
            366: self.accept4,
            367: self.fanotify_init,
            368: self.fanotify_mark,
            369: self.prlimit64,
            370: self.name_to_handle_at,
            371: self.open_by_handle_at,
            372: self.clock_adjtime,
            373: self.syncfs,
            374: self.sendmmsg,
            375: self.setns,
            376: self.process_vm_readv,
            377: self.process_vm_writev,
            378: self.kcmp,
            379: self.finit_module,
            380: self.sched_setattr,
            381: self.sched_getattr,
            382: self.renameat2,
            383: self.seccomp,
            384: self.getrandom,
            385: self.memfd_create,
            386: self.bpf,
            387: self.execveat,
            388: self.userfaultfd,
            389: self.membarrier,
            390: self.mlock2,
            391: self.copy_file_range,
            392: self.preadv2,
            393: self.pwritev2,
            394: self.pkey_mprotect,
            395: self.pkey_alloc,
            396: self.pkey_free,
            397: self.statx,
            398: self.rseq,
            399: self.io_pgetevents,
            400: self.migrate_pages,
            401: self.kexec_file_load,
            403: self.clock_gettime64,
            404: self.clock_settime64,
            405: self.clock_adjtime64,
            406: self.clock_getres_time64,
            407: self.clock_nanosleep_time64,
            408: self.timer_gettime64,
            409: self.timer_settime64,
            410: self.timerfd_gettime64,
            411: self.timerfd_settime64,
            412: self.utimensat_time64,
            413: self.pselect6_time64,
            414: self.ppoll_time64,
            416: self.io_pgetevents_time64,
            417: self.recvmmsg_time64,
            418: self.mq_timedsend_time64,
            419: self.mq_timedreceive_time64,
            420: self.semtimedop_time64,
            421: self.rt_sigtimedwait_time64,
            422: self.futex_time64,
            423: self.sched_rr_get_interval_time64,
            424: self.pidfd_send_signal,
            425: self.io_uring_setup,
            426: self.io_uring_enter,
            427: self.io_uring_register,
            428: self.open_tree,
            429: self.move_mount,
            430: self.fsopen,
            431: self.fsconfig,
            432: self.fsmount,
            433: self.fspick,
            434: self.pidfd_open,
            435: self.clone3,
            436: self.close_range,
            437: self.openat2,
            438: self.pidfd_getfd,
            439: self.faccessat2,
            440: self.process_madvise,
            441: self.epoll_pwait2,
            442: self.mount_setattr,
            443: self.quotactl_fd,
            444: self.landlock_create_ruleset,
            445: self.landlock_add_rule,
            446: self.landlock_restrict_self,
            448: self.process_mrelease
        }
        self.emulator.mu.hook_add(UC_HOOK_INTR, self.hook)

    def hook(self, mu, intno, userdata):
        # 断点
        pc = mu.reg_read(UC_ARM_REG_PC)
        if isThumb(mu):
            swi = int.from_bytes(mu.mem_read(pc - 2, 2), byteorder='little') & 0xff
        else:
            swi = int.from_bytes(mu.mem_read(pc - 4, 4), byteorder='little') & 0xffffff
        if intno == EXCP_BKPT:
            return
        if intno != EXCP_SWI:
            mu.emu_stop()
            raise Exception("Unhandled interrupt %d" % intno)
        NR = mu.reg_read(UC_ARM_REG_R7)
        if swi != 0:
            if swi in self.emulator.hooker.hookMaps:
                mu.reg_write(UC_ARM_REG_R0, self.emulator.hooker.hookMaps[swi](mu))
                return
            mu.emu_stop()
            raise Exception("Unhandled svcHook %d" % swi)
        if NR in self.syscallHandlerMaps:
            mu.reg_write(UC_ARM_REG_R0, self.syscallHandlerMaps[NR](mu))
            return
        mu.emu_stop()
        raise Exception("Unhandled svc %d" % NR)

    def restart_syscall(self, mu):
        raise NotImplementedError()

    def exit(self, mu):
        status = mu.reg_read(UC_ARM_REG_R0)
        logger.info("exit status= %d" % status)
        mu.emu_stop()
        return

    def fork(self, mu):
        raise NotImplementedError()

    def read(self, mu):
        fd = mu.reg_read(UC_ARM_REG_R0)
        buffer_ptr = mu.reg_read(UC_ARM_REG_R1)
        count = mu.reg_read(UC_ARM_REG_R3)
        logger.debug("Read fd= %d, buffer_ptr= 0x%X,count= %d" % (fd, buffer_ptr, count))
        return self.emulator.PCB.read(mu, fd, buffer_ptr, count)

    def write(self, mu):
        raise NotImplementedError()

    def open(self, mu):
        raise NotImplementedError()

    def close(self, mu):
        fd = mu.reg_read(UC_ARM_REG_R0)
        logger.debug("close fd= %d" % fd)
        return self.emulator.PCB.close(fd)

    def creat(self, mu):
        raise NotImplementedError()

    def link(self, mu):
        raise NotImplementedError()

    def unlink(self, mu):
        raise NotImplementedError()

    def execve(self, mu):
        raise NotImplementedError()

    def chdir(self, mu):
        raise NotImplementedError()

    def mknod(self, mu):
        raise NotImplementedError()

    def chmod(self, mu):
        raise NotImplementedError()

    def lchown(self, mu):
        raise NotImplementedError()

    def lseek(self, mu):
        raise NotImplementedError()

    def getpid(self, mu):
        raise NotImplementedError()

    def mount(self, mu):
        raise NotImplementedError()

    def setuid(self, mu):
        raise NotImplementedError()

    def getuid(self, mu):
        raise NotImplementedError()

    def ptrace(self, mu):
        raise NotImplementedError()

    def pause(self, mu):
        raise NotImplementedError()

    def access(self, mu):
        raise NotImplementedError()

    def nice(self, mu):
        raise NotImplementedError()

    def sync(self, mu):
        raise NotImplementedError()

    def kill(self, mu):
        raise NotImplementedError()

    def rename(self, mu):
        raise NotImplementedError()

    def mkdir(self, mu):
        raise NotImplementedError()

    def rmdir(self, mu):
        raise NotImplementedError()

    def dup(self, mu):
        raise NotImplementedError()

    def pipe(self, mu):
        raise NotImplementedError()

    def times(self, mu):
        raise NotImplementedError()

    def brk(self, mu):
        address = mu.reg_read(UC_ARM_REG_R0) & 0xffffffff
        logger.debug("brk address= 0x%X " % address)
        return self.emulator.memory.brk(address)

    def setgid(self, mu):
        raise NotImplementedError()

    def getgid(self, mu):
        raise NotImplementedError()

    def geteuid(self, mu):
        raise NotImplementedError()

    def getegid(self, mu):
        raise NotImplementedError()

    def acct(self, mu):
        raise NotImplementedError()

    def umount2(self, mu):
        raise NotImplementedError()

    def ioctl(self, mu):
        fd = mu.reg_read(UC_ARM_REG_R0)
        request = mu.reg_read(UC_ARM_REG_R1)
        argp = mu.reg_read(UC_ARM_REG_R2)
        return self.emulator.PCB.ioctl(mu,fd, request, argp)

    def fcntl(self, mu):
        raise NotImplementedError()

    def setpgid(self, mu):
        raise NotImplementedError()

    def umask(self, mu):
        raise NotImplementedError()

    def chroot(self, mu):
        raise NotImplementedError()

    def ustat(self, mu):
        raise NotImplementedError()

    def dup2(self, mu):
        raise NotImplementedError()

    def getppid(self, mu):
        raise NotImplementedError()

    def getpgrp(self, mu):
        raise NotImplementedError()

    def setsid(self, mu):
        raise NotImplementedError()

    def sigaction(self, mu):
        raise NotImplementedError()

    def setreuid(self, mu):
        raise NotImplementedError()

    def setregid(self, mu):
        raise NotImplementedError()

    def sigsuspend(self, mu):
        raise NotImplementedError()

    def sigpending(self, mu):
        raise NotImplementedError()

    def sethostname(self, mu):
        raise NotImplementedError()

    def setrlimit(self, mu):
        raise NotImplementedError()

    def getrusage(self, mu):
        raise NotImplementedError()

    def gettimeofday(self, mu):
        raise NotImplementedError()

    def settimeofday(self, mu):
        raise NotImplementedError()

    def getgroups(self, mu):
        raise NotImplementedError()

    def setgroups(self, mu):
        raise NotImplementedError()

    def symlink(self, mu):
        raise NotImplementedError()

    def readlink(self, mu):
        raise NotImplementedError()

    def uselib(self, mu):
        raise NotImplementedError()

    def swapon(self, mu):
        raise NotImplementedError()

    def reboot(self, mu):
        raise NotImplementedError()

    def munmap(self, mu):
        start = mu.reg_read(UC_ARM_REG_R0) & 0xffffffff
        len = mu.reg_read(UC_ARM_REG_R1)
        self.emulator.memory.munmap(start, len)
        logger.debug(
            "munmap start= 0x%X ,len= %d ,from= %s" % (start, len, ptrStr(self.emulator.linker, getLRPointer(mu))))
        return 0

    def truncate(self, mu):
        raise NotImplementedError()

    def ftruncate(self, mu):
        raise NotImplementedError()

    def fchmod(self, mu):
        raise NotImplementedError()

    def fchown(self, mu):
        raise NotImplementedError()

    def getpriority(self, mu):
        raise NotImplementedError()

    def setpriority(self, mu):
        raise NotImplementedError()

    def statfs(self, mu):
        raise NotImplementedError()

    def fstatfs(self, mu):
        raise NotImplementedError()

    def syslog(self, mu):
        raise NotImplementedError()

    def setitimer(self, mu):
        raise NotImplementedError()

    def getitimer(self, mu):
        raise NotImplementedError()

    def stat(self, mu):
        raise NotImplementedError()

    def lstat(self, mu):
        raise NotImplementedError()

    def fstat(self, mu):
        raise NotImplementedError()

    def vhangup(self, mu):
        raise NotImplementedError()

    def wait4(self, mu):
        raise NotImplementedError()

    def swapoff(self, mu):
        raise NotImplementedError()

    def sysinfo(self, mu):
        raise NotImplementedError()

    def fsync(self, mu):
        raise NotImplementedError()

    def sigreturn(self, mu):
        raise NotImplementedError()

    def clone(self, mu):
        raise NotImplementedError()

    def setdomainname(self, mu):
        raise NotImplementedError()

    def uname(self, mu):
        raise NotImplementedError()

    def adjtimex(self, mu):
        raise NotImplementedError()

    def mprotect(self, mu):
        addr = mu.reg_read(UC_ARM_REG_R0) & 0xffffffff
        len = mu.reg_read(UC_ARM_REG_R1)
        prot = mu.reg_read(UC_ARM_REG_R2)
        alignedAddress = int(addr / PAGE_SIZE * PAGE_SIZE)
        off = addr - alignedAddress
        alignedLen = alignSize(len + off)
        logger.debug(
            "mprotect address= 0x%X, alignedAddress= 0x%X, offset= %d, length= %d, alignedLength= %d, prot= 0x%X" % (
                addr, alignedAddress, off, len, alignedLen, prot))

        self.emulator.memory.protect(alignedAddress, alignedLen, prot)
        return 0

    def sigprocmask(self, mu):
        raise NotImplementedError()

    def init_module(self, mu):
        raise NotImplementedError()

    def delete_module(self, mu):
        raise NotImplementedError()

    def quotactl(self, mu):
        raise NotImplementedError()

    def getpgid(self, mu):
        raise NotImplementedError()

    def fchdir(self, mu):
        raise NotImplementedError()

    def bdflush(self, mu):
        raise NotImplementedError()

    def sysfs(self, mu):
        raise NotImplementedError()

    def personality(self, mu):
        raise NotImplementedError()

    def setfsuid(self, mu):
        raise NotImplementedError()

    def setfsgid(self, mu):
        raise NotImplementedError()

    def _llseek(self, mu):
        raise NotImplementedError()

    def getdents(self, mu):
        raise NotImplementedError()

    def _newselect(self, mu):
        raise NotImplementedError()

    def flock(self, mu):
        raise NotImplementedError()

    def msync(self, mu):
        raise NotImplementedError()

    def readv(self, mu):
        raise NotImplementedError()

    def writev(self, mu):
        raise NotImplementedError()

    def getsid(self, mu):
        raise NotImplementedError()

    def fdatasync(self, mu):
        raise NotImplementedError()

    def _sysctl(self, mu):
        raise NotImplementedError()

    def mlock(self, mu):
        raise NotImplementedError()

    def munlock(self, mu):
        raise NotImplementedError()

    def mlockall(self, mu):
        raise NotImplementedError()

    def munlockall(self, mu):
        raise NotImplementedError()

    def sched_setparam(self, mu):
        raise NotImplementedError()

    def sched_getparam(self, mu):
        raise NotImplementedError()

    def sched_setscheduler(self, mu):
        raise NotImplementedError()

    def sched_getscheduler(self, mu):
        raise NotImplementedError()

    def sched_yield(self, mu):
        raise NotImplementedError()

    def sched_get_priority_max(self, mu):
        raise NotImplementedError()

    def sched_get_priority_min(self, mu):
        raise NotImplementedError()

    def sched_rr_get_interval(self, mu):
        raise NotImplementedError()

    def nanosleep(self, mu):
        raise NotImplementedError()

    def mremap(self, mu):
        raise NotImplementedError()

    def setresuid(self, mu):
        raise NotImplementedError()

    def getresuid(self, mu):
        raise NotImplementedError()

    def poll(self, mu):
        raise NotImplementedError()

    def nfsservctl(self, mu):
        raise NotImplementedError()

    def setresgid(self, mu):
        raise NotImplementedError()

    def getresgid(self, mu):
        raise NotImplementedError()

    def prctl(self, mu):
        option = mu.reg_read(UC_ARM_REG_R0)
        arg2 = mu.reg_read(UC_ARM_REG_R1) & 0xffffffff
        logger.debug("prctl option= 0x%X ,arg2= 0x%X" % (option, arg2))
        if option in (PR_SET_DUMPABLE, PR_SET_DUMPABLE):
            return 0
        if option == PR_SET_NAME:
            threadNamePtr = mu.reg_read(UC_ARM_REG_R1)
            write_utf8(mu, threadNamePtr, self.emulator.processName)
            logger.debug("prctl set thread name: %s" % self.emulator.processName)
            return 0
        if option == PR_GET_NAME:
            threadNamePtr = mu.reg_read(UC_ARM_REG_R1)
            name = read_utf8(mu, threadNamePtr)
            self.emulator.processName = name
            logger.debug("prctl get thread name: %s" % self.emulator.processName)
            return 0
        if option == BIONIC_PR_SET_VMA:
            addr = mu.reg_read(UC_ARM_REG_R2)
            len = mu.reg_read(UC_ARM_REG_R3)
            ptr = mu.reg_read(UC_ARM_REG_R4)
            logger.debug(
                "prctl set vma addr= 0x%X, len= %d, pointer= 0x%X, name= %s" % (addr, len, ptr, read_utf8(mu, ptr)))
            return 0
        if option == PR_SET_PTRACER:
            pid = arg2
            logger.debug("prctl set ptracer: %d" % pid)
            return 0
        raise NotImplementedError("Unsupported prctl option= %d" % option)

    def rt_sigreturn(self, mu):
        raise NotImplementedError()

    def rt_sigaction(self, mu):
        raise NotImplementedError()

    def rt_sigprocmask(self, mu):
        raise NotImplementedError()

    def rt_sigpending(self, mu):
        raise NotImplementedError()

    def rt_sigtimedwait(self, mu):
        raise NotImplementedError()

    def rt_sigqueueinfo(self, mu):
        raise NotImplementedError()

    def rt_sigsuspend(self, mu):
        raise NotImplementedError()

    def pread64(self, mu):
        raise NotImplementedError()

    def pwrite64(self, mu):
        raise NotImplementedError()

    def chown(self, mu):
        raise NotImplementedError()

    def getcwd(self, mu):
        raise NotImplementedError()

    def capget(self, mu):
        raise NotImplementedError()

    def capset(self, mu):
        raise NotImplementedError()

    def sigaltstack(self, mu):
        raise NotImplementedError()

    def sendfile(self, mu):
        raise NotImplementedError()

    def vfork(self, mu):
        raise NotImplementedError()

    def ugetrlimit(self, mu):
        raise NotImplementedError()

    def mmap2(self, mu):
        start = mu.reg_read(UC_ARM_REG_R0) & 0xffffffff
        len = mu.reg_read(UC_ARM_REG_R1)
        prot = mu.reg_read(UC_ARM_REG_R2)
        flags = mu.reg_read(UC_ARM_REG_R3)
        fd = mu.reg_read(UC_ARM_REG_R4)
        offset = mu.reg_read(UC_ARM_REG_R5) << MMAP2_SHIFT
        msg = "mmap2 start= 0x%X, length= %d, prot= 0x%X, flags= 0x%X, fd= 0x%x, offset= %d, from= %s" % (
            start, len, prot, flags, fd, offset, ptrStr(self.emulator.linker, getLRPointer(mu)))
        logger.debug(msg)
        if fd != 0xffffffff:
            if fd < 2:
                raise NotImplementedError("Unsupported read operation for file descriptor %d." % fd)
            if fd not in self.emulator.PCB.FDMaps:
                raise NotImplementedError()
            return self.emulator.memory.mmap(start, len, prot, fd, offset)
        else:
            return self.emulator.memory.mmap(start, len, prot)

    def truncate64(self, mu):
        raise NotImplementedError()

    def ftruncate64(self, mu):
        raise NotImplementedError()

    def stat64(self, mu):
        raise NotImplementedError()

    def lstat64(self, mu):
        raise NotImplementedError()

    def fstat64(self, mu):
        fd = mu.reg_read(UC_ARM_REG_R0)
        stat_ptr = mu.reg_read(UC_ARM_REG_R1)
        logger.debug("fstat64 fd= %d, stat= 0x%X" % (fd, stat_ptr))
        return self.emulator.PCB.fstat(mu, fd, stat_ptr)

    def lchown32(self, mu):
        raise NotImplementedError()

    def getuid32(self, mu):
        raise NotImplementedError()

    def getgid32(self, mu):
        raise NotImplementedError()

    def geteuid32(self, mu):
        raise NotImplementedError()

    def getegid32(self, mu):
        raise NotImplementedError()

    def setreuid32(self, mu):
        raise NotImplementedError()

    def setregid32(self, mu):
        raise NotImplementedError()

    def getgroups32(self, mu):
        raise NotImplementedError()

    def setgroups32(self, mu):
        raise NotImplementedError()

    def fchown32(self, mu):
        raise NotImplementedError()

    def setresuid32(self, mu):
        raise NotImplementedError()

    def getresuid32(self, mu):
        raise NotImplementedError()

    def setresgid32(self, mu):
        raise NotImplementedError()

    def getresgid32(self, mu):
        raise NotImplementedError()

    def chown32(self, mu):
        raise NotImplementedError()

    def setuid32(self, mu):
        raise NotImplementedError()

    def setgid32(self, mu):
        raise NotImplementedError()

    def setfsuid32(self, mu):
        raise NotImplementedError()

    def setfsgid32(self, mu):
        raise NotImplementedError()

    def getdents64(self, mu):
        raise NotImplementedError()

    def pivot_root(self, mu):
        raise NotImplementedError()

    def mincore(self, mu):
        raise NotImplementedError()

    def madvise(self, mu):
        return 0

    def fcntl64(self, mu):
        raise NotImplementedError()

    def gettid(self, mu):
        raise NotImplementedError()

    def readahead(self, mu):
        raise NotImplementedError()

    def setxattr(self, mu):
        raise NotImplementedError()

    def lsetxattr(self, mu):
        raise NotImplementedError()

    def fsetxattr(self, mu):
        raise NotImplementedError()

    def getxattr(self, mu):
        raise NotImplementedError()

    def lgetxattr(self, mu):
        raise NotImplementedError()

    def fgetxattr(self, mu):
        raise NotImplementedError()

    def listxattr(self, mu):
        raise NotImplementedError()

    def llistxattr(self, mu):
        raise NotImplementedError()

    def flistxattr(self, mu):
        raise NotImplementedError()

    def removexattr(self, mu):
        raise NotImplementedError()

    def lremovexattr(self, mu):
        raise NotImplementedError()

    def fremovexattr(self, mu):
        raise NotImplementedError()

    def tkill(self, mu):
        raise NotImplementedError()

    def sendfile64(self, mu):
        raise NotImplementedError()

    def futex(self, mu):
        uaddr = mu.reg_read(UC_ARM_REG_R0)
        futex_op = mu.reg_read(UC_ARM_REG_R1)
        val = mu.reg_read(UC_ARM_REG_R2)
        old = int.from_bytes((mu.mem_read(uaddr, 4)), byteorder='little')
        op = futex_op & 0x7f
        msg = "futex uaddr= %s , _futexop= %d, op= %d, val= %d, old= %d" % (
            ptrStr(self.emulator.linker, uaddr), futex_op, op, val, old)
        logger.debug(msg)
        if op == FUTEX_WAIT:
            if old != val:
                raise Exception("old %d val %d" % (old, val))
            # TODO:未完善
            timeout = mu.reg_read(UC_ARM_REG_R3)
            mytype = val & 0xc000
            shared = val & 0x2000
            logger.debug("futex FUTEX_WAIT mytype= %d , shared= %d, timeout= %d , test= %d " % (
                mytype, shared, timeout, (mytype | shared)))
            mu.mem_write(uaddr, int(mytype | shared).to_bytes(4, byteorder='little'))
            return 0
        if op == FUTEX_WAKE:
            return 0
        raise NotImplementedError()

    def sched_setaffinity(self, mu):
        raise NotImplementedError()

    def sched_getaffinity(self, mu):
        raise NotImplementedError()

    def io_setup(self, mu):
        raise NotImplementedError()

    def io_destroy(self, mu):
        raise NotImplementedError()

    def io_getevents(self, mu):
        raise NotImplementedError()

    def io_submit(self, mu):
        raise NotImplementedError()

    def io_cancel(self, mu):
        raise NotImplementedError()

    def exit_group(self, mu):
        raise NotImplementedError()

    def lookup_dcookie(self, mu):
        raise NotImplementedError()

    def epoll_create(self, mu):
        raise NotImplementedError()

    def epoll_ctl(self, mu):
        raise NotImplementedError()

    def epoll_wait(self, mu):
        raise NotImplementedError()

    def remap_file_pages(self, mu):
        raise NotImplementedError()

    def set_tid_address(self, mu):
        raise NotImplementedError()

    def timer_create(self, mu):
        raise NotImplementedError()

    def timer_settime(self, mu):
        raise NotImplementedError()

    def timer_gettime(self, mu):
        raise NotImplementedError()

    def timer_getoverrun(self, mu):
        raise NotImplementedError()

    def timer_delete(self, mu):
        raise NotImplementedError()

    def clock_settime(self, mu):
        raise NotImplementedError()

    def clock_gettime(self, mu):
        raise NotImplementedError()

    def clock_getres(self, mu):
        raise NotImplementedError()

    def clock_nanosleep(self, mu):
        raise NotImplementedError()

    def statfs64(self, mu):
        raise NotImplementedError()

    def fstatfs64(self, mu):
        raise NotImplementedError()

    def tgkill(self, mu):
        raise NotImplementedError()

    def utimes(self, mu):
        raise NotImplementedError()

    def arm_fadvise64_64(self, mu):
        raise NotImplementedError()

    def pciconfig_iobase(self, mu):
        raise NotImplementedError()

    def pciconfig_read(self, mu):
        raise NotImplementedError()

    def pciconfig_write(self, mu):
        raise NotImplementedError()

    def mq_open(self, mu):
        raise NotImplementedError()

    def mq_unlink(self, mu):
        raise NotImplementedError()

    def mq_timedsend(self, mu):
        raise NotImplementedError()

    def mq_timedreceive(self, mu):
        raise NotImplementedError()

    def mq_notify(self, mu):
        raise NotImplementedError()

    def mq_getsetattr(self, mu):
        raise NotImplementedError()

    def waitid(self, mu):
        raise NotImplementedError()

    def socket(self, mu):
        raise NotImplementedError()

    def bind(self, mu):
        raise NotImplementedError()

    def connect(self, mu):
        raise NotImplementedError()

    def listen(self, mu):
        raise NotImplementedError()

    def accept(self, mu):
        raise NotImplementedError()

    def getsockname(self, mu):
        raise NotImplementedError()

    def getpeername(self, mu):
        raise NotImplementedError()

    def socketpair(self, mu):
        raise NotImplementedError()

    def send(self, mu):
        raise NotImplementedError()

    def sendto(self, mu):
        raise NotImplementedError()

    def recv(self, mu):
        raise NotImplementedError()

    def recvfrom(self, mu):
        raise NotImplementedError()

    def shutdown(self, mu):
        raise NotImplementedError()

    def setsockopt(self, mu):
        raise NotImplementedError()

    def getsockopt(self, mu):
        raise NotImplementedError()

    def sendmsg(self, mu):
        raise NotImplementedError()

    def recvmsg(self, mu):
        raise NotImplementedError()

    def semop(self, mu):
        raise NotImplementedError()

    def semget(self, mu):
        raise NotImplementedError()

    def semctl(self, mu):
        raise NotImplementedError()

    def msgsnd(self, mu):
        raise NotImplementedError()

    def msgrcv(self, mu):
        raise NotImplementedError()

    def msgget(self, mu):
        raise NotImplementedError()

    def msgctl(self, mu):
        raise NotImplementedError()

    def shmat(self, mu):
        raise NotImplementedError()

    def shmdt(self, mu):
        raise NotImplementedError()

    def shmget(self, mu):
        raise NotImplementedError()

    def shmctl(self, mu):
        raise NotImplementedError()

    def add_key(self, mu):
        raise NotImplementedError()

    def request_key(self, mu):
        raise NotImplementedError()

    def keyctl(self, mu):
        raise NotImplementedError()

    def semtimedop(self, mu):
        raise NotImplementedError()

    def ioprio_set(self, mu):
        raise NotImplementedError()

    def ioprio_get(self, mu):
        raise NotImplementedError()

    def inotify_init(self, mu):
        raise NotImplementedError()

    def inotify_add_watch(self, mu):
        raise NotImplementedError()

    def inotify_rm_watch(self, mu):
        raise NotImplementedError()

    def mbind(self, mu):
        raise NotImplementedError()

    def get_mempolicy(self, mu):
        raise NotImplementedError()

    def set_mempolicy(self, mu):
        raise NotImplementedError()

    def openat(self, mu):
        dirfd = mu.reg_read(UC_ARM_REG_R0)
        pathname = read_utf8(mu, mu.reg_read(UC_ARM_REG_R1))
        oflags = mu.reg_read(UC_ARM_REG_R2)
        mode = mu.reg_read(UC_ARM_REG_R3)
        msg = "openat dirfd= 0x%X, pathname= %s, oflags= 0x%X, mode= 0x%X" % (dirfd, pathname, oflags, mode)
        logger.debug(msg)
        if pathname.startswith("/"):
            fd = self.emulator.PCB.open(self.emulator, pathname, oflags)
            if fd == -1:
                logger.warning(msg)
            return fd
        else:
            if dirfd != -100:
                raise Exception(msg)
            fd = self.emulator.PCB.open(self.emulator, pathname, oflags)
            if fd == -1:
                logger.warning(msg)
            return fd

    def mkdirat(self, mu):
        raise NotImplementedError()

    def mknodat(self, mu):
        raise NotImplementedError()

    def fchownat(self, mu):
        raise NotImplementedError()

    def futimesat(self, mu):
        raise NotImplementedError()

    def fstatat64(self, mu):
        raise NotImplementedError()

    def unlinkat(self, mu):
        raise NotImplementedError()

    def renameat(self, mu):
        raise NotImplementedError()

    def linkat(self, mu):
        raise NotImplementedError()

    def symlinkat(self, mu):
        raise NotImplementedError()

    def readlinkat(self, mu):
        raise NotImplementedError()

    def fchmodat(self, mu):
        raise NotImplementedError()

    def faccessat(self, mu):
        raise NotImplementedError()

    def pselect6(self, mu):
        raise NotImplementedError()

    def ppoll(self, mu):
        raise NotImplementedError()

    def unshare(self, mu):
        raise NotImplementedError()

    def set_robust_list(self, mu):
        raise NotImplementedError()

    def get_robust_list(self, mu):
        raise NotImplementedError()

    def splice(self, mu):
        raise NotImplementedError()

    def sync_file_range2(self, mu):
        raise NotImplementedError()

    def tee(self, mu):
        raise NotImplementedError()

    def vmsplice(self, mu):
        raise NotImplementedError()

    def move_pages(self, mu):
        raise NotImplementedError()

    def getcpu(self, mu):
        raise NotImplementedError()

    def epoll_pwait(self, mu):
        raise NotImplementedError()

    def kexec_load(self, mu):
        raise NotImplementedError()

    def utimensat(self, mu):
        raise NotImplementedError()

    def signalfd(self, mu):
        raise NotImplementedError()

    def timerfd_create(self, mu):
        raise NotImplementedError()

    def eventfd(self, mu):
        raise NotImplementedError()

    def fallocate(self, mu):
        raise NotImplementedError()

    def timerfd_settime(self, mu):
        raise NotImplementedError()

    def timerfd_gettime(self, mu):
        raise NotImplementedError()

    def signalfd4(self, mu):
        raise NotImplementedError()

    def eventfd2(self, mu):
        raise NotImplementedError()

    def epoll_create1(self, mu):
        raise NotImplementedError()

    def dup3(self, mu):
        raise NotImplementedError()

    def pipe2(self, mu):
        raise NotImplementedError()

    def inotify_init1(self, mu):
        raise NotImplementedError()

    def preadv(self, mu):
        raise NotImplementedError()

    def pwritev(self, mu):
        raise NotImplementedError()

    def rt_tgsigqueueinfo(self, mu):
        raise NotImplementedError()

    def perf_event_open(self, mu):
        raise NotImplementedError()

    def recvmmsg(self, mu):
        raise NotImplementedError()

    def accept4(self, mu):
        raise NotImplementedError()

    def fanotify_init(self, mu):
        raise NotImplementedError()

    def fanotify_mark(self, mu):
        raise NotImplementedError()

    def prlimit64(self, mu):
        raise NotImplementedError()

    def name_to_handle_at(self, mu):
        raise NotImplementedError()

    def open_by_handle_at(self, mu):
        raise NotImplementedError()

    def clock_adjtime(self, mu):
        raise NotImplementedError()

    def syncfs(self, mu):
        raise NotImplementedError()

    def sendmmsg(self, mu):
        raise NotImplementedError()

    def setns(self, mu):
        raise NotImplementedError()

    def process_vm_readv(self, mu):
        raise NotImplementedError()

    def process_vm_writev(self, mu):
        raise NotImplementedError()

    def kcmp(self, mu):
        raise NotImplementedError()

    def finit_module(self, mu):
        raise NotImplementedError()

    def sched_setattr(self, mu):
        raise NotImplementedError()

    def sched_getattr(self, mu):
        raise NotImplementedError()

    def renameat2(self, mu):
        raise NotImplementedError()

    def seccomp(self, mu):
        raise NotImplementedError()

    def getrandom(self, mu):
        raise NotImplementedError()

    def memfd_create(self, mu):
        raise NotImplementedError()

    def bpf(self, mu):
        raise NotImplementedError()

    def execveat(self, mu):
        raise NotImplementedError()

    def userfaultfd(self, mu):
        raise NotImplementedError()

    def membarrier(self, mu):
        raise NotImplementedError()

    def mlock2(self, mu):
        raise NotImplementedError()

    def copy_file_range(self, mu):
        raise NotImplementedError()

    def preadv2(self, mu):
        raise NotImplementedError()

    def pwritev2(self, mu):
        raise NotImplementedError()

    def pkey_mprotect(self, mu):
        raise NotImplementedError()

    def pkey_alloc(self, mu):
        raise NotImplementedError()

    def pkey_free(self, mu):
        raise NotImplementedError()

    def statx(self, mu):
        raise NotImplementedError()

    def rseq(self, mu):
        raise NotImplementedError()

    def io_pgetevents(self, mu):
        raise NotImplementedError()

    def migrate_pages(self, mu):
        raise NotImplementedError()

    def kexec_file_load(self, mu):
        raise NotImplementedError()

    def clock_gettime64(self, mu):
        raise NotImplementedError()

    def clock_settime64(self, mu):
        raise NotImplementedError()

    def clock_adjtime64(self, mu):
        raise NotImplementedError()

    def clock_getres_time64(self, mu):
        raise NotImplementedError()

    def clock_nanosleep_time64(self, mu):
        raise NotImplementedError()

    def timer_gettime64(self, mu):
        raise NotImplementedError()

    def timer_settime64(self, mu):
        raise NotImplementedError()

    def timerfd_gettime64(self, mu):
        raise NotImplementedError()

    def timerfd_settime64(self, mu):
        raise NotImplementedError()

    def utimensat_time64(self, mu):
        raise NotImplementedError()

    def pselect6_time64(self, mu):
        raise NotImplementedError()

    def ppoll_time64(self, mu):
        raise NotImplementedError()

    def io_pgetevents_time64(self, mu):
        raise NotImplementedError()

    def recvmmsg_time64(self, mu):
        raise NotImplementedError()

    def mq_timedsend_time64(self, mu):
        raise NotImplementedError()

    def mq_timedreceive_time64(self, mu):
        raise NotImplementedError()

    def semtimedop_time64(self, mu):
        raise NotImplementedError()

    def rt_sigtimedwait_time64(self, mu):
        raise NotImplementedError()

    def futex_time64(self, mu):
        raise NotImplementedError()

    def sched_rr_get_interval_time64(self, mu):
        raise NotImplementedError()

    def pidfd_send_signal(self, mu):
        raise NotImplementedError()

    def io_uring_setup(self, mu):
        raise NotImplementedError()

    def io_uring_enter(self, mu):
        raise NotImplementedError()

    def io_uring_register(self, mu):
        raise NotImplementedError()

    def open_tree(self, mu):
        raise NotImplementedError()

    def move_mount(self, mu):
        raise NotImplementedError()

    def fsopen(self, mu):
        raise NotImplementedError()

    def fsconfig(self, mu):
        raise NotImplementedError()

    def fsmount(self, mu):
        raise NotImplementedError()

    def fspick(self, mu):
        raise NotImplementedError()

    def pidfd_open(self, mu):
        raise NotImplementedError()

    def clone3(self, mu):
        raise NotImplementedError()

    def close_range(self, mu):
        raise NotImplementedError()

    def openat2(self, mu):
        raise NotImplementedError()

    def pidfd_getfd(self, mu):
        raise NotImplementedError()

    def faccessat2(self, mu):
        raise NotImplementedError()

    def process_madvise(self, mu):
        raise NotImplementedError()

    def epoll_pwait2(self, mu):
        raise NotImplementedError()

    def mount_setattr(self, mu):
        raise NotImplementedError()

    def quotactl_fd(self, mu):
        raise NotImplementedError()

    def landlock_create_ruleset(self, mu):
        raise NotImplementedError()

    def landlock_add_rule(self, mu):
        raise NotImplementedError()

    def landlock_restrict_self(self, mu):
        raise NotImplementedError()

    def process_mrelease(self, mu):
        raise NotImplementedError()
