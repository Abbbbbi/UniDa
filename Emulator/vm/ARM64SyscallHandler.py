from unicorn import UC_HOOK_INTR
from unicorn.arm64_const import *

from Emulator.hooks.ARMConst import *


class ARM64SyscallHandler:
    def __init__(self, emulator):
        self.emulator = emulator
        self.syscallHandlerMaps = {
            0: self.io_setup,
            1: self.io_destroy,
            2: self.io_submit,
            3: self.io_cancel,
            4: self.io_getevents,
            5: self.setxattr,
            6: self.lsetxattr,
            7: self.fsetxattr,
            8: self.getxattr,
            9: self.lgetxattr,
            10: self.fgetxattr,
            11: self.listxattr,
            12: self.llistxattr,
            13: self.flistxattr,
            14: self.removexattr,
            15: self.lremovexattr,
            16: self.fremovexattr,
            17: self.getcwd,
            18: self.lookup_dcookie,
            19: self.eventfd2,
            20: self.epoll_create1,
            21: self.epoll_ctl,
            22: self.epoll_pwait,
            23: self.dup,
            24: self.dup3,
            25: self.fcntl,
            26: self.inotify_init1,
            27: self.inotify_add_watch,
            28: self.inotify_rm_watch,
            29: self.ioctl,
            30: self.ioprio_set,
            31: self.ioprio_get,
            32: self.flock,
            33: self.mknodat,
            34: self.mkdirat,
            35: self.unlinkat,
            36: self.symlinkat,
            37: self.linkat,
            38: self.renameat,
            39: self.umount2,
            40: self.mount,
            41: self.pivot_root,
            42: self.nfsservctl,
            43: self.statfs,
            44: self.fstatfs,
            45: self.truncate,
            46: self.ftruncate,
            47: self.fallocate,
            48: self.faccessat,
            49: self.chdir,
            50: self.fchdir,
            51: self.chroot,
            52: self.fchmod,
            53: self.fchmodat,
            54: self.fchownat,
            55: self.fchown,
            56: self.openat,
            57: self.close,
            58: self.vhangup,
            59: self.pipe2,
            60: self.quotactl,
            61: self.getdents64,
            62: self.lseek,
            63: self.read,
            64: self.write,
            65: self.readv,
            66: self.writev,
            67: self.pread64,
            68: self.pwrite64,
            69: self.preadv,
            70: self.pwritev,
            71: self.sendfile,
            72: self.pselect6,
            73: self.ppoll,
            74: self.signalfd4,
            75: self.vmsplice,
            76: self.splice,
            77: self.tee,
            78: self.readlinkat,
            79: self.newfstatat,
            80: self.fstat,
            81: self.sync,
            82: self.fsync,
            83: self.fdatasync,
            84: self.sync_file_range,
            85: self.timerfd_create,
            86: self.timerfd_settime,
            87: self.timerfd_gettime,
            88: self.utimensat,
            89: self.acct,
            90: self.capget,
            91: self.capset,
            92: self.personality,
            93: self.exit,
            94: self.exit_group,
            95: self.waitid,
            96: self.set_tid_address,
            97: self.unshare,
            98: self.futex,
            99: self.set_robust_list,
            100: self.get_robust_list,
            101: self.nanosleep,
            102: self.getitimer,
            103: self.setitimer,
            104: self.kexec_load,
            105: self.init_module,
            106: self.delete_module,
            107: self.timer_create,
            108: self.timer_gettime,
            109: self.timer_getoverrun,
            110: self.timer_settime,
            111: self.timer_delete,
            112: self.clock_settime,
            113: self.clock_gettime,
            114: self.clock_getres,
            115: self.clock_nanosleep,
            116: self.syslog,
            117: self.ptrace,
            118: self.sched_setparam,
            119: self.sched_setscheduler,
            120: self.sched_getscheduler,
            121: self.sched_getparam,
            122: self.sched_setaffinity,
            123: self.sched_getaffinity,
            124: self.sched_yield,
            125: self.sched_get_priority_max,
            126: self.sched_get_priority_min,
            127: self.sched_rr_get_interval,
            128: self.restart_syscall,
            129: self.kill,
            130: self.tkill,
            131: self.tgkill,
            132: self.sigaltstack,
            133: self.rt_sigsuspend,
            134: self.rt_sigaction,
            135: self.rt_sigprocmask,
            136: self.rt_sigpending,
            137: self.rt_sigtimedwait,
            138: self.rt_sigqueueinfo,
            139: self.rt_sigreturn,
            140: self.setpriority,
            141: self.getpriority,
            142: self.reboot,
            143: self.setregid,
            144: self.setgid,
            145: self.setreuid,
            146: self.setuid,
            147: self.setresuid,
            148: self.getresuid,
            149: self.setresgid,
            150: self.getresgid,
            151: self.setfsuid,
            152: self.setfsgid,
            153: self.times,
            154: self.setpgid,
            155: self.getpgid,
            156: self.getsid,
            157: self.setsid,
            158: self.getgroups,
            159: self.setgroups,
            160: self.uname,
            161: self.sethostname,
            162: self.setdomainname,
            163: self.getrlimit,
            164: self.setrlimit,
            165: self.getrusage,
            166: self.umask,
            167: self.prctl,
            168: self.getcpu,
            169: self.gettimeofday,
            170: self.settimeofday,
            171: self.adjtimex,
            172: self.getpid,
            173: self.getppid,
            174: self.getuid,
            175: self.geteuid,
            176: self.getgid,
            177: self.getegid,
            178: self.gettid,
            179: self.sysinfo,
            180: self.mq_open,
            181: self.mq_unlink,
            182: self.mq_timedsend,
            183: self.mq_timedreceive,
            184: self.mq_notify,
            185: self.mq_getsetattr,
            186: self.msgget,
            187: self.msgctl,
            188: self.msgrcv,
            189: self.msgsnd,
            190: self.semget,
            191: self.semctl,
            192: self.semtimedop,
            193: self.semop,
            194: self.shmget,
            195: self.shmctl,
            196: self.shmat,
            197: self.shmdt,
            198: self.socket,
            199: self.socketpair,
            200: self.bind,
            201: self.listen,
            202: self.accept,
            203: self.connect,
            204: self.getsockname,
            205: self.getpeername,
            206: self.sendto,
            207: self.recvfrom,
            208: self.setsockopt,
            209: self.getsockopt,
            210: self.shutdown,
            211: self.sendmsg,
            212: self.recvmsg,
            213: self.readahead,
            214: self.brk,
            215: self.munmap,
            216: self.mremap,
            217: self.add_key,
            218: self.request_key,
            219: self.keyctl,
            220: self.clone,
            221: self.execve,
            222: self.mmap,
            223: self.fadvise64,
            224: self.swapon,
            225: self.swapoff,
            226: self.mprotect,
            227: self.msync,
            228: self.mlock,
            229: self.munlock,
            230: self.mlockall,
            231: self.munlockall,
            232: self.mincore,
            233: self.madvise,
            234: self.remap_file_pages,
            235: self.mbind,
            236: self.get_mempolicy,
            237: self.set_mempolicy,
            238: self.migrate_pages,
            239: self.move_pages,
            240: self.rt_tgsigqueueinfo,
            241: self.perf_event_open,
            242: self.accept4,
            243: self.recvmmsg,
            260: self.wait4,
            261: self.prlimit64,
            262: self.fanotify_init,
            263: self.fanotify_mark,
            264: self.name_to_handle_at,
            265: self.open_by_handle_at,
            266: self.clock_adjtime,
            267: self.syncfs,
            268: self.setns,
            269: self.sendmmsg,
            270: self.process_vm_readv,
            271: self.process_vm_writev,
            272: self.kcmp,
            273: self.finit_module,
            274: self.sched_setattr,
            275: self.sched_getattr,
            276: self.renameat2,
            277: self.seccomp,
            278: self.getrandom,
            279: self.memfd_create,
            280: self.bpf,
            281: self.execveat,
            282: self.userfaultfd,
            283: self.membarrier,
            284: self.mlock2,
            285: self.copy_file_range,
            286: self.preadv2,
            287: self.pwritev2,
            288: self.pkey_mprotect,
            289: self.pkey_alloc,
            290: self.pkey_free,
            291: self.statx,
            292: self.io_pgetevents,
            293: self.rseq,
            294: self.kexec_file_load,
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
            447: self.memfd_secret,
            448: self.process_mrelease
        }
        self.emulator.mu.hook_add(UC_HOOK_INTR, self.hook)

    def hook(self, mu, intno, userdata):
        # 断点
        pc = mu.reg_read(UC_ARM64_REG_PC)
        swi = (int.from_bytes(mu.mem_read(pc - 4, 4), byteorder='little') >> 5) & 0xff
        if intno == EXCP_BKPT:
            return
        if intno != EXCP_SWI:
            mu.emu_stop()
            raise Exception("Unhandled interrupt %d" % intno)
        NR = mu.reg_read(UC_ARM64_REG_X8)
        if swi != 0:
            if swi in self.emulator.hooker.hookMaps:
                mu.reg_write(UC_ARM64_REG_X0, self.emulator.hooker.hookMaps[swi](mu))
                return
            mu.emu_stop()
            raise Exception("Unhandled svcHook %d" % swi)
        if NR in self.syscallHandlerMaps:
            mu.reg_write(UC_ARM64_REG_X0, self.syscallHandlerMaps[NR](mu))
            return
        mu.emu_stop()
        raise Exception("Unhandled svc %d" % NR)

    def io_setup(self, mu):
        raise NotImplementedError()

    def io_destroy(self, mu):
        raise NotImplementedError()

    def io_submit(self, mu):
        raise NotImplementedError()

    def io_cancel(self, mu):
        raise NotImplementedError()

    def io_getevents(self, mu):
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

    def getcwd(self, mu):
        raise NotImplementedError()

    def lookup_dcookie(self, mu):
        raise NotImplementedError()

    def eventfd2(self, mu):
        raise NotImplementedError()

    def epoll_create1(self, mu):
        raise NotImplementedError()

    def epoll_ctl(self, mu):
        raise NotImplementedError()

    def epoll_pwait(self, mu):
        raise NotImplementedError()

    def dup(self, mu):
        raise NotImplementedError()

    def dup3(self, mu):
        raise NotImplementedError()

    def fcntl(self, mu):
        raise NotImplementedError()

    def inotify_init1(self, mu):
        raise NotImplementedError()

    def inotify_add_watch(self, mu):
        raise NotImplementedError()

    def inotify_rm_watch(self, mu):
        raise NotImplementedError()

    def ioctl(self, mu):
        raise NotImplementedError()

    def ioprio_set(self, mu):
        raise NotImplementedError()

    def ioprio_get(self, mu):
        raise NotImplementedError()

    def flock(self, mu):
        raise NotImplementedError()

    def mknodat(self, mu):
        raise NotImplementedError()

    def mkdirat(self, mu):
        raise NotImplementedError()

    def unlinkat(self, mu):
        raise NotImplementedError()

    def symlinkat(self, mu):
        raise NotImplementedError()

    def linkat(self, mu):
        raise NotImplementedError()

    def renameat(self, mu):
        raise NotImplementedError()

    def umount2(self, mu):
        raise NotImplementedError()

    def mount(self, mu):
        raise NotImplementedError()

    def pivot_root(self, mu):
        raise NotImplementedError()

    def nfsservctl(self, mu):
        raise NotImplementedError()

    def statfs(self, mu):
        raise NotImplementedError()

    def fstatfs(self, mu):
        raise NotImplementedError()

    def truncate(self, mu):
        raise NotImplementedError()

    def ftruncate(self, mu):
        raise NotImplementedError()

    def fallocate(self, mu):
        raise NotImplementedError()

    def faccessat(self, mu):
        raise NotImplementedError()

    def chdir(self, mu):
        raise NotImplementedError()

    def fchdir(self, mu):
        raise NotImplementedError()

    def chroot(self, mu):
        raise NotImplementedError()

    def fchmod(self, mu):
        raise NotImplementedError()

    def fchmodat(self, mu):
        raise NotImplementedError()

    def fchownat(self, mu):
        raise NotImplementedError()

    def fchown(self, mu):
        raise NotImplementedError()

    def openat(self, mu):
        raise NotImplementedError()

    def close(self, mu):
        raise NotImplementedError()

    def vhangup(self, mu):
        raise NotImplementedError()

    def pipe2(self, mu):
        raise NotImplementedError()

    def quotactl(self, mu):
        raise NotImplementedError()

    def getdents64(self, mu):
        raise NotImplementedError()

    def lseek(self, mu):
        raise NotImplementedError()

    def read(self, mu):
        raise NotImplementedError()

    def write(self, mu):
        raise NotImplementedError()

    def readv(self, mu):
        raise NotImplementedError()

    def writev(self, mu):
        raise NotImplementedError()

    def pread64(self, mu):
        raise NotImplementedError()

    def pwrite64(self, mu):
        raise NotImplementedError()

    def preadv(self, mu):
        raise NotImplementedError()

    def pwritev(self, mu):
        raise NotImplementedError()

    def sendfile(self, mu):
        raise NotImplementedError()

    def pselect6(self, mu):
        raise NotImplementedError()

    def ppoll(self, mu):
        raise NotImplementedError()

    def signalfd4(self, mu):
        raise NotImplementedError()

    def vmsplice(self, mu):
        raise NotImplementedError()

    def splice(self, mu):
        raise NotImplementedError()

    def tee(self, mu):
        raise NotImplementedError()

    def readlinkat(self, mu):
        raise NotImplementedError()

    def newfstatat(self, mu):
        raise NotImplementedError()

    def fstat(self, mu):
        raise NotImplementedError()

    def sync(self, mu):
        raise NotImplementedError()

    def fsync(self, mu):
        raise NotImplementedError()

    def fdatasync(self, mu):
        raise NotImplementedError()

    def sync_file_range(self, mu):
        raise NotImplementedError()

    def timerfd_create(self, mu):
        raise NotImplementedError()

    def timerfd_settime(self, mu):
        raise NotImplementedError()

    def timerfd_gettime(self, mu):
        raise NotImplementedError()

    def utimensat(self, mu):
        raise NotImplementedError()

    def acct(self, mu):
        raise NotImplementedError()

    def capget(self, mu):
        raise NotImplementedError()

    def capset(self, mu):
        raise NotImplementedError()

    def personality(self, mu):
        raise NotImplementedError()

    def exit(self, mu):
        raise NotImplementedError()

    def exit_group(self, mu):
        raise NotImplementedError()

    def waitid(self, mu):
        raise NotImplementedError()

    def set_tid_address(self, mu):
        raise NotImplementedError()

    def unshare(self, mu):
        raise NotImplementedError()

    def futex(self, mu):
        raise NotImplementedError()

    def set_robust_list(self, mu):
        raise NotImplementedError()

    def get_robust_list(self, mu):
        raise NotImplementedError()

    def nanosleep(self, mu):
        raise NotImplementedError()

    def getitimer(self, mu):
        raise NotImplementedError()

    def setitimer(self, mu):
        raise NotImplementedError()

    def kexec_load(self, mu):
        raise NotImplementedError()

    def init_module(self, mu):
        raise NotImplementedError()

    def delete_module(self, mu):
        raise NotImplementedError()

    def timer_create(self, mu):
        raise NotImplementedError()

    def timer_gettime(self, mu):
        raise NotImplementedError()

    def timer_getoverrun(self, mu):
        raise NotImplementedError()

    def timer_settime(self, mu):
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

    def syslog(self, mu):
        raise NotImplementedError()

    def ptrace(self, mu):
        raise NotImplementedError()

    def sched_setparam(self, mu):
        raise NotImplementedError()

    def sched_setscheduler(self, mu):
        raise NotImplementedError()

    def sched_getscheduler(self, mu):
        raise NotImplementedError()

    def sched_getparam(self, mu):
        raise NotImplementedError()

    def sched_setaffinity(self, mu):
        raise NotImplementedError()

    def sched_getaffinity(self, mu):
        raise NotImplementedError()

    def sched_yield(self, mu):
        raise NotImplementedError()

    def sched_get_priority_max(self, mu):
        raise NotImplementedError()

    def sched_get_priority_min(self, mu):
        raise NotImplementedError()

    def sched_rr_get_interval(self, mu):
        raise NotImplementedError()

    def restart_syscall(self, mu):
        raise NotImplementedError()

    def kill(self, mu):
        raise NotImplementedError()

    def tkill(self, mu):
        raise NotImplementedError()

    def tgkill(self, mu):
        raise NotImplementedError()

    def sigaltstack(self, mu):
        raise NotImplementedError()

    def rt_sigsuspend(self, mu):
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

    def rt_sigreturn(self, mu):
        raise NotImplementedError()

    def setpriority(self, mu):
        raise NotImplementedError()

    def getpriority(self, mu):
        raise NotImplementedError()

    def reboot(self, mu):
        raise NotImplementedError()

    def setregid(self, mu):
        raise NotImplementedError()

    def setgid(self, mu):
        raise NotImplementedError()

    def setreuid(self, mu):
        raise NotImplementedError()

    def setuid(self, mu):
        raise NotImplementedError()

    def setresuid(self, mu):
        raise NotImplementedError()

    def getresuid(self, mu):
        raise NotImplementedError()

    def setresgid(self, mu):
        raise NotImplementedError()

    def getresgid(self, mu):
        raise NotImplementedError()

    def setfsuid(self, mu):
        raise NotImplementedError()

    def setfsgid(self, mu):
        raise NotImplementedError()

    def times(self, mu):
        raise NotImplementedError()

    def setpgid(self, mu):
        raise NotImplementedError()

    def getpgid(self, mu):
        raise NotImplementedError()

    def getsid(self, mu):
        raise NotImplementedError()

    def setsid(self, mu):
        raise NotImplementedError()

    def getgroups(self, mu):
        raise NotImplementedError()

    def setgroups(self, mu):
        raise NotImplementedError()

    def uname(self, mu):
        raise NotImplementedError()

    def sethostname(self, mu):
        raise NotImplementedError()

    def setdomainname(self, mu):
        raise NotImplementedError()

    def getrlimit(self, mu):
        raise NotImplementedError()

    def setrlimit(self, mu):
        raise NotImplementedError()

    def getrusage(self, mu):
        raise NotImplementedError()

    def umask(self, mu):
        raise NotImplementedError()

    def prctl(self, mu):
        raise NotImplementedError()

    def getcpu(self, mu):
        raise NotImplementedError()

    def gettimeofday(self, mu):
        raise NotImplementedError()

    def settimeofday(self, mu):
        raise NotImplementedError()

    def adjtimex(self, mu):
        raise NotImplementedError()

    def getpid(self, mu):
        raise NotImplementedError()

    def getppid(self, mu):
        raise NotImplementedError()

    def getuid(self, mu):
        raise NotImplementedError()

    def geteuid(self, mu):
        raise NotImplementedError()

    def getgid(self, mu):
        raise NotImplementedError()

    def getegid(self, mu):
        raise NotImplementedError()

    def gettid(self, mu):
        raise NotImplementedError()

    def sysinfo(self, mu):
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

    def msgget(self, mu):
        raise NotImplementedError()

    def msgctl(self, mu):
        raise NotImplementedError()

    def msgrcv(self, mu):
        raise NotImplementedError()

    def msgsnd(self, mu):
        raise NotImplementedError()

    def semget(self, mu):
        raise NotImplementedError()

    def semctl(self, mu):
        raise NotImplementedError()

    def semtimedop(self, mu):
        raise NotImplementedError()

    def semop(self, mu):
        raise NotImplementedError()

    def shmget(self, mu):
        raise NotImplementedError()

    def shmctl(self, mu):
        raise NotImplementedError()

    def shmat(self, mu):
        raise NotImplementedError()

    def shmdt(self, mu):
        raise NotImplementedError()

    def socket(self, mu):
        raise NotImplementedError()

    def socketpair(self, mu):
        raise NotImplementedError()

    def bind(self, mu):
        raise NotImplementedError()

    def listen(self, mu):
        raise NotImplementedError()

    def accept(self, mu):
        raise NotImplementedError()

    def connect(self, mu):
        raise NotImplementedError()

    def getsockname(self, mu):
        raise NotImplementedError()

    def getpeername(self, mu):
        raise NotImplementedError()

    def sendto(self, mu):
        raise NotImplementedError()

    def recvfrom(self, mu):
        raise NotImplementedError()

    def setsockopt(self, mu):
        raise NotImplementedError()

    def getsockopt(self, mu):
        raise NotImplementedError()

    def shutdown(self, mu):
        raise NotImplementedError()

    def sendmsg(self, mu):
        raise NotImplementedError()

    def recvmsg(self, mu):
        raise NotImplementedError()

    def readahead(self, mu):
        raise NotImplementedError()

    def brk(self, mu):
        raise NotImplementedError()

    def munmap(self, mu):
        raise NotImplementedError()

    def mremap(self, mu):
        raise NotImplementedError()

    def add_key(self, mu):
        raise NotImplementedError()

    def request_key(self, mu):
        raise NotImplementedError()

    def keyctl(self, mu):
        raise NotImplementedError()

    def clone(self, mu):
        raise NotImplementedError()

    def execve(self, mu):
        raise NotImplementedError()

    def mmap(self, mu):
        raise NotImplementedError()

    def fadvise64(self, mu):
        raise NotImplementedError()

    def swapon(self, mu):
        raise NotImplementedError()

    def swapoff(self, mu):
        raise NotImplementedError()

    def mprotect(self, mu):
        raise NotImplementedError()

    def msync(self, mu):
        raise NotImplementedError()

    def mlock(self, mu):
        raise NotImplementedError()

    def munlock(self, mu):
        raise NotImplementedError()

    def mlockall(self, mu):
        raise NotImplementedError()

    def munlockall(self, mu):
        raise NotImplementedError()

    def mincore(self, mu):
        raise NotImplementedError()

    def madvise(self, mu):
        raise NotImplementedError()

    def remap_file_pages(self, mu):
        raise NotImplementedError()

    def mbind(self, mu):
        raise NotImplementedError()

    def get_mempolicy(self, mu):
        raise NotImplementedError()

    def set_mempolicy(self, mu):
        raise NotImplementedError()

    def migrate_pages(self, mu):
        raise NotImplementedError()

    def move_pages(self, mu):
        raise NotImplementedError()

    def rt_tgsigqueueinfo(self, mu):
        raise NotImplementedError()

    def perf_event_open(self, mu):
        raise NotImplementedError()

    def accept4(self, mu):
        raise NotImplementedError()

    def recvmmsg(self, mu):
        raise NotImplementedError()

    def wait4(self, mu):
        raise NotImplementedError()

    def prlimit64(self, mu):
        raise NotImplementedError()

    def fanotify_init(self, mu):
        raise NotImplementedError()

    def fanotify_mark(self, mu):
        raise NotImplementedError()

    def name_to_handle_at(self, mu):
        raise NotImplementedError()

    def open_by_handle_at(self, mu):
        raise NotImplementedError()

    def clock_adjtime(self, mu):
        raise NotImplementedError()

    def syncfs(self, mu):
        raise NotImplementedError()

    def setns(self, mu):
        raise NotImplementedError()

    def sendmmsg(self, mu):
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

    def io_pgetevents(self, mu):
        raise NotImplementedError()

    def rseq(self, mu):
        raise NotImplementedError()

    def kexec_file_load(self, mu):
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

    def memfd_secret(self, mu):
        raise NotImplementedError()

    def process_mrelease(self, mu):
        raise NotImplementedError()
