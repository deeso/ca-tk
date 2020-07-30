import ctypes

# struct elf_siginfo
# {
#     int si_signo;           /* signal number */
#     int si_code;            /* extra code */
#     int si_errno;           /* errno */
# };

class NOTE_SIGINFO(ctypes.Structure):
    _fields_ = [
        ('si_signo', ctypes.c_int),   
        ('si_code', ctypes.c_int),
        ('si_errno', ctypes.c_int),   
    ]


# from /usr/include/x86_64-linux-gnu/bits/types/siginfo_t.h
# class SIGINFO(ctypes.Structure):
#     _fields_ = [
#         ('si_signo', ctypes.c_int),   
#         ('si_code', ctypes.c_int),
#         ('si_value', ctypes.c_int),
#         ('si_errno', ctypes.c_int),
#         ('si_pid', ctypes.c_int),
#         ('si_uid', ctypes.c_int),
#         ('si_addr', ctypes.c_ulong),
#         ('si_status', ctypes.c_int),
#         ('si_band', ctypes.c_int)
#     ]

class siginfo_kill(ctypes.Structure):
    _fields_ = [
        ('si_pid', ctypes.c_int),   
        ('si_uid', ctypes.c_int),
    ]

class siginfo_timer(ctypes.Structure):
    _fields_ = [
        ('si_tid', ctypes.c_int),   
        ('si_overrun', ctypes.c_int),
    ]

class siginfo_rt(ctypes.Structure):
    _fields_ = [
        ('si_pid', ctypes.c_int),   
        ('si_uid', ctypes.c_int),
        ('si_sigval', ctypes.c_int),
    ]

class siginfo_sigchld(ctypes.Structure):
    _fields_ = [
        ('si_pid', ctypes.c_int),   
        ('si_uid', ctypes.c_int),
        ('si_status', ctypes.c_int),
        ('si_utime', ctypes.c_ulong),
        ('si_stime', ctypes.c_ulong),
    ]


class siginfo_sigsys64(ctypes.Structure):
    _fields_ = [
        ('si_call_addr', ctypes.c_ulonglong),   
        ('syscall', ctypes.c_uint),
        ('arch', ctypes.c_uint),
    ]

class siginfo_sigsys(ctypes.Structure):
    _fields_ = [
        ('si_call_addr', ctypes.c_ulong),   
        ('syscall', ctypes.c_uint),
        ('arch', ctypes.c_uint),
    ]

class siginfo_sigpoll(ctypes.Structure):
    _fields_ = [
        ('si_band', ctypes.c_ulonglong),   
        ('fd', ctypes.c_int),
    ]

class siginfo_addr_bnd(ctypes.Structure):
    _fields_ = [
        ('_lower', ctypes.c_ulong),   
        ('_upper', ctypes.c_ulong),
    ]

class siginfo_addr_bnd64(ctypes.Structure):
    _fields_ = [
        ('_lower', ctypes.c_ulonglong),   
        ('_upper', ctypes.c_ulonglong),
    ]

class siginfo_addr_bnd(ctypes.Structure):
    _fields_ = [
        ('_lower', ctypes.c_ulong),   
        ('_upper', ctypes.c_ulong),
    ]

class siginfo_addr_bnd64(ctypes.Structure):
    _fields_ = [
        ('_lower', ctypes.c_ulonglong),   
        ('_upper', ctypes.c_ulonglong),
    ]

class siginfo_bounds(ctypes.Union):
    _fields_ = [
        ("_addr_bnd", siginfo_addr_bnd),   
        ('_pkey', ctypes.c_ulong),
    ]

class siginfo_addr_bnd64(ctypes.Structure):
    _fields_ = [
        ("_addr_bnd", siginfo_addr_bnd64),   
        ('_pkey', ctypes.c_ulong),
    ]

class siginfo_sigfault(ctypes.Structure):
    _fields_ = [
        ('si_addr', ctypes.c_ulong),   
        ('si_addr_lsb', ctypes.c_ushort),
        ('_bounds', siginfo_addr_bnd),
    ]

class siginfo_sigfault64(ctypes.Structure):
    _fields_ = [
        ('si_addr', ctypes.c_ulong),   
        ('si_addr_lsb', ctypes.c_ushort),
        ('_bounds', siginfo_addr_bnd64),
    ]

class siginfo_signal_info(ctypes.Union):
    _fields_ = [
        ('_pad', ctypes.c_uint*29),
        ('_kill', siginfo_kill),
        ('_timer', siginfo_timer),
        ('_rt', siginfo_sigpoll),
        ('_sigchld', siginfo_sigchld),
        ('_sigfault', siginfo_sigfault),
        ('_sigpoll', siginfo_sigpoll),
        ('_sigsys', siginfo_sigsys),
    ]

class siginfo_signal_info64(ctypes.Union):
    _fields_ = [
        ('_pad', ctypes.c_uint*28),
        ('_kill', siginfo_kill),
        ('_timer', siginfo_timer),
        ('_rt', siginfo_sigpoll),
        ('_sigchld', siginfo_sigchld),
        ('_sigfault', siginfo_sigfault64),
        ('_sigpoll', siginfo_sigpoll),
        ('_sigsys', siginfo_sigsys64),
    ]


class SIGINFO(ctypes.Structure):
    _fields_ = [
        ('si_signo', ctypes.c_int),   
        ('si_errno', ctypes.c_int),
        ('si_code', ctypes.c_int),
        ('_sigfields', siginfo_signal_info)
    ]

class SIGINFO64(ctypes.Structure):
    _fields_ = [
        ('si_signo', ctypes.c_int),   
        ('si_errno', ctypes.c_int),
        ('si_code', ctypes.c_int),
        ('_sigfields', siginfo_signal_info64)
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

# Heh, this is interesting, looks like the prstatus_t struct might have
# additional info in it. 
# https://code.woboq.org/linux/linux/include/uapi/linux/elfcore.h.html
# struct elf_prstatus
# {
# #if 0
#     long    pr_flags;   /* XXX Process flags */
#     short   pr_why;     /* XXX Reason for process halt */
#     short   pr_what;    /* XXX More detailed reason */
# #endif
class ELF_PRSTATUS32_WITH_UNUSED(ctypes.Structure):
    _fields_ = [
        ('pr_flags', ctypes.c_uint),
        ('pr_why', ctypes.c_ushort),
        ('pr_what', ctypes.c_ushort),

        ('pr_info', NOTE_SIGINFO),
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

class ELF_PRSTATUS32(ctypes.Structure):
    _fields_ = [
        ('pr_info', NOTE_SIGINFO),
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

# Heh, this is interesting, looks like the prstatus_t struct might have
# additional info in it. 
# https://code.woboq.org/linux/linux/include/uapi/linux/elfcore.h.html
# struct elf_prstatus
# {
# #if 0
#     long    pr_flags;   /* XXX Process flags */
#     short   pr_why;     /* XXX Reason for process halt */
#     short   pr_what;    /* XXX More detailed reason */
# #endif
class ELF_PRSTATUS32X_WITH_UNUSED(ctypes.Structure):
    _fields_ = [
        ('pr_flags', ctypes.c_uint),
        ('pr_why', ctypes.c_ushort),
        ('pr_what', ctypes.c_ushort),
        # ('pr_unknown', ctypes.c_ulonglong),
        ('pr_info', NOTE_SIGINFO),
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

class ELF_PRSTATUS32X(ctypes.Structure):
    _fields_ = [
        ('pr_info', NOTE_SIGINFO),
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

class AMD64_XSAVE(ctypes.Structure):
    _fields_ = [('fp_ctrl', ctypes.c_ushort),
                ('fp_stat', ctypes.c_ushort),
                ('fp_tag', ctypes.c_uint8),
                ('rsvrd', ctypes.c_uint8),
                ('fp_opcode', ctypes.c_ushort),
                ('fp_inst_off', ctypes.c_uint),
                ('fp_inst_seg', ctypes.c_ushort),

                ('fp_data_off', ctypes.c_uint),
                ('fp_data_seg', ctypes.c_ushort),
                ('mxcsr', ctypes.c_uint),
                ('mxcsr_mask', ctypes.c_uint),
                
                # https://stackoverflow.com/questions/19631698/handling-128-bit-integers-with-ctypes?noredirect=1
                ('st0', ctypes.c_ulonglong*2),
                ('st1', ctypes.c_ulonglong*2),
                ('st2', ctypes.c_ulonglong*2),
                ('st3', ctypes.c_ulonglong*2),
                ('st4', ctypes.c_ulonglong*2),
                ('st5', ctypes.c_ulonglong*2),
                ('st6', ctypes.c_ulonglong*2),
                ('st7', ctypes.c_ulonglong*2),
                ('xmm0', ctypes.c_ulonglong*2),
                ('xmm1', ctypes.c_ulonglong*2),
                ('xmm2', ctypes.c_ulonglong*2),
                ('xmm3', ctypes.c_ulonglong*2),
                ('xmm4', ctypes.c_ulonglong*2),
                ('xmm5', ctypes.c_ulonglong*2),
                ('xmm6', ctypes.c_ulonglong*2),
                ('xmm7', ctypes.c_ulonglong*2),
                ('xmm8', ctypes.c_ulonglong*2),
                ('xmm9', ctypes.c_ulonglong*2),
                ('xmm10', ctypes.c_ulonglong*2),
                ('xmm11', ctypes.c_ulonglong*2),
                ('xmm12', ctypes.c_ulonglong*2),
                ('xmm13', ctypes.c_ulonglong*2),
                ('xmm14', ctypes.c_ulonglong*2),
                ('xmm15', ctypes.c_ulonglong*2),
               ]
# struct i387_fxsave_struct {
#     u16         cwd; /* Control Word            */
#     u16         swd; /* Status Word         */
#     u16         twd; /* Tag Word            */
#     u16         fop; /* Last Instruction Opcode     */
#     union {
#         struct {
#             u64 rip; /* Instruction Pointer     */
#             u64 rdp; /* Data Pointer            */
#         };
#         struct {
#             u32 fip; /* FPU IP Offset           */
#             u32 fcs; /* FPU IP Selector         */
#             u32 foo; /* FPU Operand Offset      */
#             u32 fos; /* FPU Operand Selector        */
#         };
#     };
#     u32         mxcsr;      /* MXCSR Register State */
#     u32         mxcsr_mask; /* MXCSR Mask       */

#     /* 8*16 bytes for each FP-reg = 128 bytes:          */
#     u32         st_space[32];

#     /* 16*16 bytes for each XMM-reg = 256 bytes:            */
#     u32         xmm_space[64];

#     u32         padding[12];

#     union {
#         u32     padding1[12];
#         u32     sw_reserved[12];
#     };

class I387_FXSAVE_ip(ctypes.Structure):
    _fields_ = [
        ('rip', ctypes.c_ulonglong),
        ('rdp', ctypes.c_ulonglong),
    ]

class I387_FXSAVE_fop(ctypes.Structure):
    _fields_ = [
        ('fip', ctypes.c_ulong),
        ('fcs', ctypes.c_ulong),
        ('foo', ctypes.c_ulong),
        ('fos', ctypes.c_ulong),
    ]

class I387_FXSAVE_op(ctypes.Union):
    _fields_ = [
        ('ip', I387_FXSAVE_ip),
        ('fop', I387_FXSAVE_fop),
    ]

# Based on linux kernel code https://elixir.bootlin.com/linux/v3.0.101/source/arch/x86/include/asm/processor.h
class I387_FXSAVE(ctypes.Structure):
    _fields_ = [
        ('cwd', ctypes.c_ushort),
        ('swd', ctypes.c_ushort),
        ('twd', ctypes.c_ushort),
        ('fop', ctypes.c_ushort),
        ('op', I387_FXSAVE_op),
        ('mxcsr', ctypes.c_ulong),
        ('mxcsr_mask', ctypes.c_ulong),
        ('st0', ctypes.c_ulonglong*2),
        ('st1', ctypes.c_ulonglong*2),
        ('st2', ctypes.c_ulonglong*2),
        ('st3', ctypes.c_ulonglong*2),
        ('st4', ctypes.c_ulonglong*2),
        ('st5', ctypes.c_ulonglong*2),
        ('st6', ctypes.c_ulonglong*2),
        ('st7', ctypes.c_ulonglong*2),
        ('xmm0', ctypes.c_ulonglong*2),
        ('xmm1', ctypes.c_ulonglong*2),
        ('xmm2', ctypes.c_ulonglong*2),
        ('xmm3', ctypes.c_ulonglong*2),
        ('xmm4', ctypes.c_ulonglong*2),
        ('xmm5', ctypes.c_ulonglong*2),
        ('xmm6', ctypes.c_ulonglong*2),
        ('xmm7', ctypes.c_ulonglong*2),
        ('xmm8', ctypes.c_ulonglong*2),
        ('xmm9', ctypes.c_ulonglong*2),
        ('xmm10', ctypes.c_ulonglong*2),
        ('xmm11', ctypes.c_ulonglong*2),
        ('xmm12', ctypes.c_ulonglong*2),
        ('xmm13', ctypes.c_ulonglong*2),
        ('xmm14', ctypes.c_ulonglong*2),
        ('xmm15', ctypes.c_ulonglong*2),
        ('padding1', ctypes.c_ulong*12),
        ('sw_reserved', ctypes.c_ulong*12),
    ]





# http://articles.manugarg.com/aboutelfauxiliaryvectors
# https://github.com/torvalds/linux/blob/v5.4/include/uapi/linux/auxvec.h
class auxv_t(ctypes.Structure):
    _fields_ = [
        ('a_type', ctypes.c_ulong),
        ('a_val', ctypes.c_ulong),
    ]

class auxv_t_64(ctypes.Structure):
    _fields_ = [
        ('a_type', ctypes.c_ulonglong),
        ('a_val', ctypes.c_ulonglong),
    ]
