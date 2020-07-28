import ctypes

# struct elf_siginfo
# {
#     int si_signo;           /* signal number */
#     int si_code;            /* extra code */
#     int si_errno;           /* errno */
# };

class ELF_SIGINFO(ctypes.Structure):
    _fields_ = [
        ('si_signo', ctypes.c_int),   
        ('si_code', ctypes.c_int),
        ('si_errno', ctypes.c_int),   
    ]

# struct prstatus32_timeval
#   {
#     int tv_sec;
#     int tv_usec;
#   };

class PRSTATUS32_TIMEVAL(ctypes.Structure):
    _fields_ = [
        ("tv_sec", ctypes.c_ulong),
        ("tv_usec", ctypes.c_ulong),
    ]

# struct user_regs32_struct
# {
#   int32_t ebx;
#   int32_t ecx;
#   int32_t edx;
#   int32_t esi;
#   int32_t edi;
#   int32_t ebp;
#   int32_t eax;
#   int32_t xds;
#   int32_t xes;
#   int32_t xfs;
#   int32_t xgs;
#   int32_t orig_eax;
#   int32_t eip;
#   int32_t xcs;
#   int32_t eflags;
#   int32_t esp;
#   int32_t xss;
# };

class USER_REGS32_STRUCT(ctypes.Structure):
    _fields_ = [
        ('ebx', ctypes.c_ulong),
        ('ecx', ctypes.c_ulong),
        ('edx', ctypes.c_ulong),
        ('esi', ctypes.c_ulong),
        ('edi', ctypes.c_ulong),
        ('ebp', ctypes.c_ulong),
        ('eax', ctypes.c_ulong),
        ('xds', ctypes.c_ulong),
        ('xes', ctypes.c_ulong),
        ('xfs', ctypes.c_ulong),
        ('xgs', ctypes.c_ulong),
        ('orig_eax', ctypes.c_ulong),
        ('eip', ctypes.c_ulong),
        ('xcs', ctypes.c_ulong),
        ('eflags', ctypes.c_ulong),
        ('esp', ctypes.c_ulong),
        ('xss', ctypes.c_ulong),
    ]


# typedef uint32_t elf_greg32_t;
# typedef uint64_t elf_gregx32_t;

# struct elf_prstatus32
#   {
#     struct elf_siginfo pr_info;         /* Info associated with signal.  */
#     short int pr_cursig;                /* Current signal.  */
#     unsigned int pr_sigpend;            /* Set of pending signals.  */
#     unsigned int pr_sighold;            /* Set of held signals.  */
#     pid_t pr_pid;
#     pid_t pr_ppid;
#     pid_t pr_pgrp;
#     pid_t pr_sid;
#     struct prstatus32_timeval pr_utime;         /* User time.  */
#     struct prstatus32_timeval pr_stime;         /* System time.  */
#     struct prstatus32_timeval pr_cutime;        /* Cumulative user time.  */
#     struct prstatus32_timeval pr_cstime;        /* Cumulative system time.  */
#     elf_gregset32_t pr_reg;             /* GP registers.  */
#     int pr_fpvalid;                     /* True if math copro being used.  */
#   };


class ELF_PRSTATUS32(ctypes.Structure):
    _fields_ = [
        ('pr_info', ELF_SIGINFO),
        ('pr_cursig', ctypes.c_short),
        ('pr_sigpend', ctypes.c_uint),
        ('pr_sighold', ctypes.c_uint),
        ('pr_pid', ctypes.c_int),
        ('pr_ppid', ctypes.c_int),
        ('pr_pgrp', ctypes.c_int),
        ('pr_sid', ctypes.c_int),
        ('pr_utime', PRSTATUS32_TIMEVAL),
        ('pr_stime', PRSTATUS32_TIMEVAL),
        ('pr_cutime', PRSTATUS32_TIMEVAL),
        ('pr_cstime', PRSTATUS32_TIMEVAL),
        ('pr_reg', USER_REGS32_STRUCT),
        ('pr_fpvalid', ctypes.c_int),
    ]


# struct user_regsx32_struct
# {
#   uint64_t r15;
#   uint64_t r14;
#   uint64_t r13;
#   uint64_t r12;
#   uint64_t rbp;
#   uint64_t rbx;
#   uint64_t r11;
#   uint64_t r10;
#   uint64_t r9;
#   uint64_t r8;
#   uint64_t rax;
#   uint64_t rcx;
#   uint64_t rdx;
#   uint64_t rsi;
#   uint64_t rdi;
#   uint64_t orig_rax;
#   uint64_t rip;
#   uint64_t cs;
#   uint64_t eflags;
#   uint64_t rsp;
#   uint64_t ss;
#   uint64_t fs_base;
#   uint64_t gs_base;
#   uint64_t ds;
#   uint64_t es;
#   uint64_t fs;
#   uint64_t gs;
# };

class USER_REGSX32_STRUCT(ctypes.Structure):
    _fields_ = [
        ('r15', ctypes.c_ulonglong),
        ('r14', ctypes.c_ulonglong),
        ('r13', ctypes.c_ulonglong),
        ('r12', ctypes.c_ulonglong),
        ('rbp', ctypes.c_ulonglong),
        ('rbx', ctypes.c_ulonglong),
        ('r11', ctypes.c_ulonglong),
        ('r10', ctypes.c_ulonglong),
        ('r9', ctypes.c_ulonglong),
        ('r8', ctypes.c_ulonglong),
        ('rax', ctypes.c_ulonglong),
        ('rcx', ctypes.c_ulonglong),
        ('rdx', ctypes.c_ulonglong),
        ('rsi', ctypes.c_ulonglong),
        ('rdi', ctypes.c_ulonglong),
        ('orig_rax', ctypes.c_ulonglong),
        ('rip', ctypes.c_ulonglong),
        ('cs', ctypes.c_ulonglong),
        ('eflags', ctypes.c_ulonglong),
        ('rsp', ctypes.c_ulonglong),
        ('ss', ctypes.c_ulonglong),
        ('fs_base', ctypes.c_ulonglong),
        ('gs_base', ctypes.c_ulonglong),
        ('ds', ctypes.c_ulonglong),
        ('es', ctypes.c_ulonglong),
        ('fs', ctypes.c_ulonglong),
        ('gs', ctypes.c_ulonglong),
    ]

class ELF_PRSTATUS32X(ctypes.Structure):
    _fields_ = [
        ('pr_info', ELF_SIGINFO),
        ('pr_cursig', ctypes.c_short),
        ('pr_sigpend', ctypes.c_uint),
        ('pr_sighold', ctypes.c_uint),
        ('pr_pid', ctypes.c_int),
        ('pr_ppid', ctypes.c_int),
        ('pr_pgrp', ctypes.c_int),
        ('pr_sid', ctypes.c_int),
        ('pr_utime', PRSTATUS32_TIMEVAL),
        ('pr_stime', PRSTATUS32_TIMEVAL),
        ('pr_cutime', PRSTATUS32_TIMEVAL),
        ('pr_cstime', PRSTATUS32_TIMEVAL),
        ('pr_reg', USER_REGSX32_STRUCT),
        ('pr_fpvalid', ctypes.c_int),
    ]

# If the "orig_rax" register contains a value >= 0,
# it is interpreted as the system call number
# that the kernel is supposed to restart.

# Enum that defines the syscall identifiers for amd64 linux.
# Used for process record/replay, these will be translated into
# a gdb-canonical set of syscall ids in linux-record.c.

AMD64_SYSCALL = {
  0:"AMD64_SYS_READ",
  1:"AMD64_SYS_WRITE",
  2:"AMD64_SYS_OPEN",
  3:"AMD64_SYS_CLOSE",
  4:"AMD64_SYS_NEWSTAT",
  5:"AMD64_SYS_NEWFSTAT",
  6:"AMD64_SYS_NEWLSTAT",
  7:"AMD64_SYS_POLL",
  8:"AMD64_SYS_LSEEK",
  9:"AMD64_SYS_MMAP",
  10:"AMD64_SYS_MPROTECT",
  11:"AMD64_SYS_MUNMAP",
  12:"AMD64_SYS_BRK",
  13:"AMD64_SYS_RT_SIGACTION",
  14:"AMD64_SYS_RT_SIGPROCMASK",
  15:"AMD64_SYS_RT_SIGRETURN",
  16:"AMD64_SYS_IOCTL",
  17:"AMD64_SYS_PREAD64",
  18:"AMD64_SYS_PWRITE64",
  19:"AMD64_SYS_READV",
  20:"AMD64_SYS_WRITEV",
  21:"AMD64_SYS_ACCESS",
  22:"AMD64_SYS_PIPE",
  23:"AMD64_SYS_SELECT",
  24:"AMD64_SYS_SCHED_YIELD",
  25:"AMD64_SYS_MREMAP",
  26:"AMD64_SYS_MSYNC",
  27:"AMD64_SYS_MINCORE",
  28:"AMD64_SYS_MADVISE",
  29:"AMD64_SYS_SHMGET",
  30:"AMD64_SYS_SHMAT",
  31:"AMD64_SYS_SHMCTL",
  32:"AMD64_SYS_DUP",
  33:"AMD64_SYS_DUP2",
  34:"AMD64_SYS_PAUSE",
  35:"AMD64_SYS_NANOSLEEP",
  36:"AMD64_SYS_GETITIMER",
  37:"AMD64_SYS_ALARM",
  38:"AMD64_SYS_SETITIMER",
  39:"AMD64_SYS_GETPID",
  40:"AMD64_SYS_SENDFILE64",
  41:"AMD64_SYS_SOCKET",
  42:"AMD64_SYS_CONNECT",
  43:"AMD64_SYS_ACCEPT",
  44:"AMD64_SYS_SENDTO",
  45:"AMD64_SYS_RECVFROM",
  46:"AMD64_SYS_SENDMSG",
  47:"AMD64_SYS_RECVMSG",
  48:"AMD64_SYS_SHUTDOWN",
  49:"AMD64_SYS_BIND",
  50:"AMD64_SYS_LISTEN",
  51:"AMD64_SYS_GETSOCKNAME",
  52:"AMD64_SYS_GETPEERNAME",
  53:"AMD64_SYS_SOCKETPAIR",
  54:"AMD64_SYS_SETSOCKOPT",
  55:"AMD64_SYS_GETSOCKOPT",
  56:"AMD64_SYS_CLONE",
  57:"AMD64_SYS_FORK",
  58:"AMD64_SYS_VFORK",
  59:"AMD64_SYS_EXECVE",
  60:"AMD64_SYS_EXIT",
  61:"AMD64_SYS_WAIT4",
  62:"AMD64_SYS_KILL",
  63:"AMD64_SYS_UNAME",
  64:"AMD64_SYS_SEMGET",
  65:"AMD64_SYS_SEMOP",
  66:"AMD64_SYS_SEMCTL",
  67:"AMD64_SYS_SHMDT",
  68:"AMD64_SYS_MSGGET",
  69:"AMD64_SYS_MSGSND",
  70:"AMD64_SYS_MSGRCV",
  71:"AMD64_SYS_MSGCTL",
  72:"AMD64_SYS_FCNTL",
  73:"AMD64_SYS_FLOCK",
  74:"AMD64_SYS_FSYNC",
  75:"AMD64_SYS_FDATASYNC",
  76:"AMD64_SYS_TRUNCATE",
  77:"AMD64_SYS_FTRUNCATE",
  78:"AMD64_SYS_GETDENTS",
  79:"AMD64_SYS_GETCWD",
  80:"AMD64_SYS_CHDIR",
  81:"AMD64_SYS_FCHDIR",
  82:"AMD64_SYS_RENAME",
  83:"AMD64_SYS_MKDIR",
  84:"AMD64_SYS_RMDIR",
  85:"AMD64_SYS_CREAT",
  86:"AMD64_SYS_LINK",
  87:"AMD64_SYS_UNLINK",
  88:"AMD64_SYS_SYMLINK",
  89:"AMD64_SYS_READLINK",
  90:"AMD64_SYS_CHMOD",
  91:"AMD64_SYS_FCHMOD",
  92:"AMD64_SYS_CHOWN",
  93:"AMD64_SYS_FCHOWN",
  94:"AMD64_SYS_LCHOWN",
  95:"AMD64_SYS_UMASK",
  96:"AMD64_SYS_GETTIMEOFDAY",
  97:"AMD64_SYS_GETRLIMIT",
  98:"AMD64_SYS_GETRUSAGE",
  99:"AMD64_SYS_SYSINFO",
  100:"AMD64_SYS_TIMES",
  101:"AMD64_SYS_PTRACE",
  102:"AMD64_SYS_GETUID",
  103:"AMD64_SYS_SYSLOG",
  104:"AMD64_SYS_GETGID",
  105:"AMD64_SYS_SETUID",
  106:"AMD64_SYS_SETGID",
  107:"AMD64_SYS_GETEUID",
  108:"AMD64_SYS_GETEGID",
  109:"AMD64_SYS_SETPGID",
  110:"AMD64_SYS_GETPPID",
  111:"AMD64_SYS_GETPGRP",
  112:"AMD64_SYS_SETSID",
  113:"AMD64_SYS_SETREUID",
  114:"AMD64_SYS_SETREGID",
  115:"AMD64_SYS_GETGROUPS",
  116:"AMD64_SYS_SETGROUPS",
  117:"AMD64_SYS_SETRESUID",
  118:"AMD64_SYS_GETRESUID",
  119:"AMD64_SYS_SETRESGID",
  120:"AMD64_SYS_GETRESGID",
  121:"AMD64_SYS_GETPGID",
  122:"AMD64_SYS_SETFSUID",
  123:"AMD64_SYS_SETFSGID",
  124:"AMD64_SYS_GETSID",
  125:"AMD64_SYS_CAPGET",
  126:"AMD64_SYS_CAPSET",
  127:"AMD64_SYS_RT_SIGPENDING",
  128:"AMD64_SYS_RT_SIGTIMEDWAIT",
  129:"AMD64_SYS_RT_SIGQUEUEINFO",
  130:"AMD64_SYS_RT_SIGSUSPEND",
  131:"AMD64_SYS_SIGALTSTACK",
  132:"AMD64_SYS_UTIME",
  133:"AMD64_SYS_MKNOD",
  135:"AMD64_SYS_PERSONALITY",
  136:"AMD64_SYS_USTAT",
  137:"AMD64_SYS_STATFS",
  138:"AMD64_SYS_FSTATFS",
  139:"AMD64_SYS_SYSFS",
  140:"AMD64_SYS_GETPRIORITY",
  141:"AMD64_SYS_SETPRIORITY",
  142:"AMD64_SYS_SCHED_SETPARAM",
  143:"AMD64_SYS_SCHED_GETPARAM",
  144:"AMD64_SYS_SCHED_SETSCHEDULER",
  145:"AMD64_SYS_SCHED_GETSCHEDULER",
  146:"AMD64_SYS_SCHED_GET_PRIORITY_MAX",
  147:"AMD64_SYS_SCHED_GET_PRIORITY_MIN",
  148:"AMD64_SYS_SCHED_RR_GET_INTERVAL",
  149:"AMD64_SYS_MLOCK",
  150:"AMD64_SYS_MUNLOCK",
  151:"AMD64_SYS_MLOCKALL",
  152:"AMD64_SYS_MUNLOCKALL",
  153:"AMD64_SYS_VHANGUP",
  154:"AMD64_SYS_MODIFY_LDT",
  155:"AMD64_SYS_PIVOT_ROOT",
  156:"AMD64_SYS_SYSCTL",
  157:"AMD64_SYS_PRCTL",
  158:"AMD64_SYS_ARCH_PRCTL",
  159:"AMD64_SYS_ADJTIMEX",
  160:"AMD64_SYS_SETRLIMIT",
  161:"AMD64_SYS_CHROOT",
  162:"AMD64_SYS_SYNC",
  163:"AMD64_SYS_ACCT",
  164:"AMD64_SYS_SETTIMEOFDAY",
  165:"AMD64_SYS_MOUNT",
  166:"AMD64_SYS_UMOUNT",
  167:"AMD64_SYS_SWAPON",
  168:"AMD64_SYS_SWAPOFF",
  169:"AMD64_SYS_REBOOT",
  170:"AMD64_SYS_SETHOSTNAME",
  171:"AMD64_SYS_SETDOMAINNAME",
  172:"AMD64_SYS_IOPL",
  173:"AMD64_SYS_IOPERM",
  175:"AMD64_SYS_INIT_MODULE",
  176:"AMD64_SYS_DELETE_MODULE",
  179:"AMD64_SYS_QUOTACTL",
  180:"AMD64_SYS_NFSSERVCTL",
  186:"AMD64_SYS_GETTID",
  187:"AMD64_SYS_READAHEAD",
  188:"AMD64_SYS_SETXATTR",
  189:"AMD64_SYS_LSETXATTR",
  190:"AMD64_SYS_FSETXATTR",
  191:"AMD64_SYS_GETXATTR",
  192:"AMD64_SYS_LGETXATTR",
  193:"AMD64_SYS_FGETXATTR",
  194:"AMD64_SYS_LISTXATTR",
  195:"AMD64_SYS_LLISTXATTR",
  196:"AMD64_SYS_FLISTXATTR",
  197:"AMD64_SYS_REMOVEXATTR",
  198:"AMD64_SYS_LREMOVEXATTR",
  199:"AMD64_SYS_FREMOVEXATTR",
  200:"AMD64_SYS_TKILL",
  201:"AMD64_SYS_TIME",
  202:"AMD64_SYS_FUTEX",
  203:"AMD64_SYS_SCHED_SETAFFINITY",
  204:"AMD64_SYS_SCHED_GETAFFINITY",
  206:"AMD64_SYS_IO_SETUP",
  207:"AMD64_SYS_IO_DESTROY",
  208:"AMD64_SYS_IO_GETEVENTS",
  209:"AMD64_SYS_IO_SUBMIT",
  210:"AMD64_SYS_IO_CANCEL",
  212:"AMD64_SYS_LOOKUP_DCOOKIE",
  213:"AMD64_SYS_EPOLL_CREATE",
  216:"AMD64_SYS_REMAP_FILE_PAGES",
  217:"AMD64_SYS_GETDENTS64",
  218:"AMD64_SYS_SET_TID_ADDRESS",
  219:"AMD64_SYS_RESTART_SYSCALL",
  220:"AMD64_SYS_SEMTIMEDOP",
  221:"AMD64_SYS_FADVISE64",
  222:"AMD64_SYS_TIMER_CREATE",
  223:"AMD64_SYS_TIMER_SETTIME",
  224:"AMD64_SYS_TIMER_GETTIME",
  225:"AMD64_SYS_TIMER_GETOVERRUN",
  226:"AMD64_SYS_TIMER_DELETE",
  227:"AMD64_SYS_CLOCK_SETTIME",
  228:"AMD64_SYS_CLOCK_GETTIME",
  229:"AMD64_SYS_CLOCK_GETRES",
  230:"AMD64_SYS_CLOCK_NANOSLEEP",
  231:"AMD64_SYS_EXIT_GROUP",
  232:"AMD64_SYS_EPOLL_WAIT",
  233:"AMD64_SYS_EPOLL_CTL",
  234:"AMD64_SYS_TGKILL",
  235:"AMD64_SYS_UTIMES",
  237:"AMD64_SYS_MBIND",
  238:"AMD64_SYS_SET_MEMPOLICY",
  239:"AMD64_SYS_GET_MEMPOLICY",
  240:"AMD64_SYS_MQ_OPEN",
  241:"AMD64_SYS_MQ_UNLINK",
  242:"AMD64_SYS_MQ_TIMEDSEND",
  243:"AMD64_SYS_MQ_TIMEDRECEIVE",
  244:"AMD64_SYS_MQ_NOTIFY",
  245:"AMD64_SYS_MQ_GETSETATTR",
  246:"AMD64_SYS_KEXEC_LOAD",
  247:"AMD64_SYS_WAITID",
  248:"AMD64_SYS_ADD_KEY",
  249:"AMD64_SYS_REQUEST_KEY",
  250:"AMD64_SYS_KEYCTL",
  251:"AMD64_SYS_IOPRIO_SET",
  252:"AMD64_SYS_IOPRIO_GET",
  253:"AMD64_SYS_INOTIFY_INIT",
  254:"AMD64_SYS_INOTIFY_ADD_WATCH",
  255:"AMD64_SYS_INOTIFY_RM_WATCH",
  256:"AMD64_SYS_MIGRATE_PAGES",
  257:"AMD64_SYS_OPENAT",
  258:"AMD64_SYS_MKDIRAT",
  259:"AMD64_SYS_MKNODAT",
  260:"AMD64_SYS_FCHOWNAT",
  261:"AMD64_SYS_FUTIMESAT",
  262:"AMD64_SYS_NEWFSTATAT",
  263:"AMD64_SYS_UNLINKAT",
  264:"AMD64_SYS_RENAMEAT",
  265:"AMD64_SYS_LINKAT",
  266:"AMD64_SYS_SYMLINKAT",
  267:"AMD64_SYS_READLINKAT",
  268:"AMD64_SYS_FCHMODAT",
  269:"AMD64_SYS_FACCESSAT",
  270:"AMD64_SYS_PSELECT6",
  271:"AMD64_SYS_PPOLL",
  272:"AMD64_SYS_UNSHARE",
  273:"AMD64_SYS_SET_ROBUST_LIST",
  274:"AMD64_SYS_GET_ROBUST_LIST",
  275:"AMD64_SYS_SPLICE",
  276:"AMD64_SYS_TEE",
  277:"AMD64_SYS_SYNC_FILE_RANGE",
  278:"AMD64_SYS_VMSPLICE",
  279:"AMD64_SYS_MOVE_PAGES",
}