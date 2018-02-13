#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#define SYSCALL_MAX 314 //Max is 314

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <asm/uaccess.h>
#include <asm/cacheflush.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/utsname.h>
#include <linux/spinlock.h>
#include <linux/time.h>
#include <linux/inet.h>
#include <linux/inet_diag.h>
#include <linux/inet_lro.h>
#include <linux/inetdevice.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/math64.h>
#include <net/inet_common.h>
#include <net/inet_connection_sock.h>
#include <net/inet_ecn.h>
#include <net/inet_frag.h>
#include <net/inet_hashtables.h>
#include <net/inet_sock.h>
#include <net/inetpeer.h>
#include <net/ip.h>

MODULE_DESCRIPTION("system call trace module");
MODULE_LICENSE("Dual BSD/GPL");
/* following string SYSCALL_TABLE_ADDRESS will be replaced by set_syscall_table_address.sh */
static void **syscall_table = (void *) 0xffffffff81801400;
static int syscall_count[SYSCALL_MAX];
static int mirai_syscall_count[SYSCALL_MAX];
static int mirai_pid;
struct timespec ts_global;
/* sysfs define */
/* Time define */
/********************************************************************
*********************************************************************
****************** original system call function ********************
*********************************************************************
********************************************************************/
asmlinkage long (*orig_sys_read)(unsigned int fd, char __user *buf, size_t count);
asmlinkage long (*orig_sys_write)(unsigned int fd, const char __user *buf,
                          size_t count);
asmlinkage long (*orig_sys_open)(const char __user *filename, int flags, umode_t mode);
asmlinkage long (*orig_sys_close)(unsigned int fd);
asmlinkage long (*orig_sys_stat)(const char __user *filename,
                        struct __old_kernel_stat __user *statbuf);
asmlinkage long (*orig_sys_fstat)(unsigned int fd,
                        struct __old_kernel_stat __user *statbuf);
asmlinkage long (*orig_sys_lstat)(const char __user *filename,
                        struct __old_kernel_stat __user *statbuf);
asmlinkage long (*orig_sys_poll)(struct pollfd __user *ufds, unsigned int nfds,
                                int timeout);
asmlinkage long (*orig_sys_lseek)(unsigned int fd, off_t offset,
                          unsigned int whence);
asmlinkage long (*orig_sys_mmap)(struct mmap_arg_struct __user *arg);
asmlinkage long (*orig_sys_mprotect)(unsigned long start, size_t len,
                                unsigned long prot);
asmlinkage long (*orig_sys_munmap)(unsigned long addr, size_t len);
asmlinkage long (*orig_sys_brk)(unsigned long brk);
asmlinkage long (*orig_sys_rt_sigaction)(int,
                                 const struct sigaction __user *,
                                 struct sigaction __user *,
                                 size_t);
asmlinkage long (*orig_sys_rt_sigprocmask)(int how, sigset_t __user *set,
                                sigset_t __user *oset, size_t sigsetsize);
asmlinkage long (*orig_sys_ioctl)(unsigned int fd, unsigned int cmd,
                                unsigned long arg);
asmlinkage long (*orig_sys_pread64)(unsigned int fd, char __user *buf,
                            size_t count, loff_t pos);
asmlinkage long (*orig_sys_pwrite64)(unsigned int fd, const char __user *buf,
                             size_t count, loff_t pos);
asmlinkage long (*orig_sys_readv)(unsigned long fd,
                          const struct iovec __user *vec,
                          unsigned long vlen);
asmlinkage long (*orig_sys_writev)(unsigned long fd,
                           const struct iovec __user *vec,
                           unsigned long vlen);
asmlinkage long (*orig_sys_access)(const char __user *filename, int mode);
asmlinkage long (*orig_sys_pipe)(int __user *fildes);
asmlinkage long (*orig_sys_select)(int n, fd_set __user *inp, fd_set __user *outp,
                        fd_set __user *exp, struct timeval __user *tvp);
asmlinkage long (*orig_sys_sched_yield)(void);
asmlinkage long (*orig_sys_mremap)(unsigned long addr,
                           unsigned long old_len, unsigned long new_len,
                           unsigned long flags, unsigned long new_addr);
asmlinkage long (*orig_sys_msync)(unsigned long start, size_t len, int flags);
asmlinkage long (*orig_sys_mincore)(unsigned long start, size_t len,
                                unsigned char __user * vec);
asmlinkage long (*orig_sys_madvise)(unsigned long start, size_t len, int behavior);
asmlinkage long (*orig_sys_shmget)(key_t key, size_t size, int flag);
asmlinkage long (*orig_sys_shmat)(int shmid, char __user *shmaddr, int shmflg);
asmlinkage long (*orig_sys_shmctl)(int shmid, int cmd, struct shmid_ds __user *buf);
asmlinkage long (*orig_sys_dup)(unsigned int fildes);
asmlinkage long (*orig_sys_dup2)(unsigned int oldfd, unsigned int newfd);
asmlinkage long (*orig_sys_pause)(void);
asmlinkage long (*orig_sys_nanosleep)(struct timespec __user *rqtp, struct timespec __user *rmtp);
asmlinkage long (*orig_sys_getitimer)(int which, struct itimerval __user *value);
asmlinkage long (*orig_sys_alarm)(unsigned int seconds);
asmlinkage long (*orig_sys_setitimer)(int which,
                                struct itimerval __user *value,
                                struct itimerval __user *ovalue);
asmlinkage long (*orig_sys_getpid)(void);
asmlinkage long (*orig_sys_sendfile)(int out_fd, int in_fd,
                             off_t __user *offset, size_t count);
asmlinkage long (*orig_sys_socket)(int, int, int);
asmlinkage long (*orig_sys_connect)(int, struct sockaddr __user *, int);
asmlinkage long (*orig_sys_accept)(int, struct sockaddr __user *, int __user *);
asmlinkage long (*orig_sys_sendto)(int, void __user *, size_t, unsigned,
                                struct sockaddr __user *, int);
asmlinkage long (*orig_sys_recvfrom)(int, void __user *, size_t, unsigned,
                                struct sockaddr __user *, int __user *);
asmlinkage long (*orig_sys_sendmsg)(int fd, struct msghdr __user *msg, unsigned flags);
asmlinkage long (*orig_sys_recvmsg)(int fd, struct msghdr __user *msg, unsigned flags);
asmlinkage long (*orig_sys_shutdown)(int, int);
asmlinkage long (*orig_sys_bind)(int, struct sockaddr __user *, int);
asmlinkage long (*orig_sys_listen)(int, int);
asmlinkage long (*orig_sys_getsockname)(int, struct sockaddr __user *, int __user *);
asmlinkage long (*orig_sys_getpeername)(int, struct sockaddr __user *, int __user *);
asmlinkage long (*orig_sys_socketpair)(int, int, int, int __user *);
asmlinkage long (*orig_sys_setsockopt)(int fd, int level, int optname,
                                char __user *optval, int optlen);
asmlinkage long (*orig_sys_getsockopt)(int fd, int level, int optname,
                                char __user *optval, int __user *optlen);
asmlinkage long (*orig_sys_clone)(unsigned long, unsigned long, int, int __user *,
			  int __user *, int);
asmlinkage long (*orig_sys_fork)(void);
asmlinkage long (*orig_sys_vfork)(void);
asmlinkage long (*orig_sys_execve)(const char __user *filename,
                const char __user *const __user *argv,
                const char __user *const __user *envp);
asmlinkage long (*orig_sys_exit)(int error_code);
asmlinkage long (*orig_sys_wait4)(pid_t pid, int __user *stat_addr,
                                int options, struct rusage __user *ru);
asmlinkage long (*orig_sys_kill)(int pid, int sig);
asmlinkage long (*orig_sys_uname)(struct old_utsname *buf);
asmlinkage long (*orig_sys_semget)(key_t key, int nsems, int semflg);
asmlinkage long (*orig_sys_semop)(int semid, struct sembuf __user *sops,
                                unsigned nsops);
asmlinkage long (*orig_sys_semctl)(int semid, int semnum, int cmd, unsigned long arg);
asmlinkage long (*orig_sys_shmdt)(char __user *shmaddr);
asmlinkage long (*orig_sys_msgget)(key_t key, int msgflg);
asmlinkage long (*orig_sys_msgsnd)(int msqid, struct msgbuf __user *msgp,
                                size_t msgsz, int msgflg);
asmlinkage long (*orig_sys_msgrcv)(int msqid, struct msgbuf __user *msgp,
                                size_t msgsz, long msgtyp, int msgflg);
asmlinkage long (*orig_sys_msgctl)(int msqid, int cmd, struct msqid_ds __user *buf);
asmlinkage long (*orig_sys_fcntl)(unsigned int fd, unsigned int cmd, unsigned long arg);
asmlinkage long (*orig_sys_flock)(unsigned int fd, unsigned int cmd);
asmlinkage long (*orig_sys_fsync)(unsigned int fd);
asmlinkage long (*orig_sys_fdatasync)(unsigned int fd);
asmlinkage long (*orig_sys_truncate)(const char __user *path, long length);
asmlinkage long (*orig_sys_ftruncate)(unsigned int fd, unsigned long length);
asmlinkage long (*orig_sys_getdents)(unsigned int fd,
                                struct linux_dirent __user *dirent,
                                unsigned int count);
asmlinkage long (*orig_sys_getcwd)(char __user *buf, unsigned long size);
asmlinkage long (*orig_sys_chdir)(const char __user *filename);
asmlinkage long (*orig_sys_fchdir)(unsigned int fd);
asmlinkage long (*orig_sys_rename)(const char __user *oldname,
                                const char __user *newname);
asmlinkage long (*orig_sys_mkdir)(const char __user *pathname, umode_t mode);
asmlinkage long (*orig_sys_rmdir)(const char __user *pathname);
asmlinkage long (*orig_sys_creat)(const char __user *pathname, umode_t mode);
asmlinkage long (*orig_sys_link)(const char __user *oldname,
                                const char __user *newname);
asmlinkage long (*orig_sys_unlink)(const char __user *pathname);
asmlinkage long (*orig_sys_symlink)(const char __user *old, const char __user *new);
asmlinkage long (*orig_sys_readlink)(const char __user *path,
                                char __user *buf, int bufsiz);
asmlinkage long (*orig_sys_chmod)(const char __user *filename, umode_t mode);
asmlinkage long (*orig_sys_fchmod)(unsigned int fd, umode_t mode);
asmlinkage long (*orig_sys_chown)(const char __user *filename,
                                uid_t user, gid_t group);
asmlinkage long (*orig_sys_fchown)(unsigned int fd, uid_t user, gid_t group);
asmlinkage long (*orig_sys_lchown)(const char __user *filename,
                                uid_t user, gid_t group);
asmlinkage long (*orig_sys_umask)(int mask);
asmlinkage long (*orig_sys_gettimeofday)(struct timeval __user *tv,
                                struct timezone __user *tz);
asmlinkage long (*orig_sys_getrlimit)(unsigned int resource,
                                struct rlimit __user *rlim);
asmlinkage long (*orig_sys_getrusage)(int who, struct rusage __user *ru);
asmlinkage long (*orig_sys_sysinfo)(struct sysinfo __user *info);
asmlinkage long (*orig_sys_times)(struct tms __user *tbuf);
asmlinkage long (*orig_sys_ptrace)(long request, long pid, unsigned long addr,
                           unsigned long data);
asmlinkage long (*orig_sys_getuid)(void);
asmlinkage long (*orig_sys_syslog)(int type, char __user *buf, int len);
asmlinkage long (*orig_sys_getgid)(void);
asmlinkage long (*orig_sys_setuid)(uid_t uid);
asmlinkage long (*orig_sys_setgid)(gid_t gid);
asmlinkage long (*orig_sys_geteuid)(void);
asmlinkage long (*orig_sys_getegid)(void);
asmlinkage long (*orig_sys_setpgid)(pid_t pid, pid_t pgid);
asmlinkage long (*orig_sys_getppid)(void);
asmlinkage long (*orig_sys_getpgrp)(void);
asmlinkage long (*orig_sys_setsid)(void);
asmlinkage long (*orig_sys_setreuid)(uid_t ruid, uid_t euid);
asmlinkage long (*orig_sys_setregid)(gid_t rgid, gid_t egid);
asmlinkage long (*orig_sys_getgroups)(int gidsetsize, gid_t __user *grouplist);
asmlinkage long (*orig_sys_setregid)(gid_t rgid, gid_t egid);
asmlinkage long (*orig_sys_setgroups)(int gidsetsize, gid_t __user *grouplist);
asmlinkage long (*orig_sys_setresuid)(uid_t ruid, uid_t euid, uid_t suid);
asmlinkage long (*orig_sys_getresuid)(uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid);
asmlinkage long (*orig_sys_setresgid)(gid_t rgid, gid_t egid, gid_t sgid);
asmlinkage long (*orig_sys_getresgid)(gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid);
asmlinkage long (*orig_sys_getpgid)(pid_t pid);
asmlinkage long (*orig_sys_setfsuid)(uid_t uid);
asmlinkage long (*orig_sys_setfsgid)(gid_t gid);
asmlinkage long (*orig_sys_getsid)(pid_t pid);
asmlinkage long (*orig_sys_capget)(cap_user_header_t header,
                                cap_user_data_t dataptr);
asmlinkage long (*orig_sys_capset)(cap_user_header_t header,
                                const cap_user_data_t data);
asmlinkage long (*orig_sys_rt_sigpending)(sigset_t __user *set, size_t sigsetsize);
asmlinkage long (*orig_sys_rt_sigtimedwait)(const sigset_t __user *uthese,
                                siginfo_t __user *uinfo,
                                const struct timespec __user *uts,
                                size_t sigsetsize);
asmlinkage long (*orig_sys_rt_sigqueueinfo)(int pid, int sig, siginfo_t __user *uinfo);
asmlinkage long (*orig_sys_rt_sigsuspend)(sigset_t __user *unewset, size_t sigsetsize);
asmlinkage long (*orig_sys_sigaltstack)(const struct sigaltstack __user *uss,
                                struct sigaltstack __user *uoss);
asmlinkage long (*orig_sys_utime)(char __user *filename,
                                struct utimbuf __user *times);
asmlinkage long (*orig_sys_mknod)(const char __user *filename, umode_t mode,
                                unsigned dev);
asmlinkage long (*orig_sys_uselib)(const char __user *library);
asmlinkage long (*orig_sys_personality)(unsigned int personality);
asmlinkage long (*orig_sys_ustat)(unsigned dev, struct ustat __user *ubuf);
asmlinkage long (*orig_sys_statfs)(const char __user * path,
                                struct statfs __user *buf);
asmlinkage long (*orig_sys_fstatfs)(unsigned int fd, struct statfs __user *buf);
asmlinkage long (*orig_sys_sysfs)(int option,
                                unsigned long arg1, unsigned long arg2);
asmlinkage long (*orig_sys_getpriority)(int which, int who);
asmlinkage long (*orig_sys_setpriority)(int which, int who, int niceval);
asmlinkage long (*orig_sys_sched_setparam)(pid_t pid,
                                        struct sched_param __user *param);
asmlinkage long (*orig_sys_sched_getparam)(pid_t pid,
                                        struct sched_param __user *param);
asmlinkage long (*orig_sys_sched_setscheduler)(pid_t pid, int policy,
                                        struct sched_param __user *param);
asmlinkage long (*orig_sys_sched_getscheduler)(pid_t pid);
asmlinkage long (*orig_sys_sched_get_priority_max)(int policy);
asmlinkage long (*orig_sys_sched_get_priority_min)(int policy);
asmlinkage long (*orig_sys_sched_rr_get_interval)(pid_t pid,
                                        struct timespec __user *interval);
asmlinkage long (*orig_sys_mlock)(unsigned long start, size_t len);
asmlinkage long (*orig_sys_munlock)(unsigned long start, size_t len);
asmlinkage long (*orig_sys_mlockall)(int flags);
asmlinkage long (*orig_sys_munlockall)(void);
asmlinkage long (*orig_sys_vhangup)(void);

asmlinkage long (*orig_sys_pivot_root)(const char __user *new_root,
                                const char __user *put_old);
asmlinkage long (*orig_sys_sysctl)(struct __sysctl_args __user *args);
asmlinkage long (*orig_sys_prctl)(int option, unsigned long arg2, unsigned long arg3,
                        unsigned long arg4, unsigned long arg5);

asmlinkage long (*orig_sys_adjtimex)(struct timex __user *txc_p);
asmlinkage long (*orig_sys_setrlimit)(unsigned int resource,
                                struct rlimit __user *rlim);
asmlinkage long (*orig_sys_chroot)(const char __user *filename);
asmlinkage long (*orig_sys_sync)(void);
asmlinkage long (*orig_sys_acct)(const char __user *name);
asmlinkage long (*orig_sys_settimeofday)(struct timeval __user *tv,
                                struct timezone __user *tz);
asmlinkage long (*orig_sys_mount)(char __user *dev_name, char __user *dir_name,
                                char __user *type, unsigned long flags,
                                void __user *data);
asmlinkage long (*orig_sys_umount)(char __user *name, int flags);
asmlinkage long (*orig_sys_swapon)(const char __user *specialfile, int swap_flags);
asmlinkage long (*orig_sys_swapoff)(const char __user *specialfile);
asmlinkage long (*orig_sys_reboot)(int magic1, int magic2, unsigned int cmd,
                                void __user *arg);
asmlinkage long (*orig_sys_sethostname)(char __user *name, int len);
asmlinkage long (*orig_sys_setdomainname)(char __user *name, int len);

asmlinkage long (*orig_sys_ioperm)(unsigned long from, unsigned long num, int on);

asmlinkage long (*orig_sys_init_module)(void __user *umod, unsigned long len,
                                const char __user *uargs);
asmlinkage long (*orig_sys_delete_module)(const char __user *name_user,
                                unsigned int flags);


asmlinkage long (*orig_sys_quotactl)(unsigned int cmd, const char __user *special,
                                qid_t id, void __user *addr);






asmlinkage long (*orig_sys_gettid)(void);
asmlinkage long (*orig_sys_readahead)(int fd, loff_t offset, size_t count);
asmlinkage long (*orig_sys_setxattr)(const char __user *path, const char __user *name,
                             const void __user *value, size_t size, int flags);
asmlinkage long (*orig_sys_lsetxattr)(const char __user *path, const char __user *name,
                              const void __user *value, size_t size, int flags);
asmlinkage long (*orig_sys_fsetxattr)(int fd, const char __user *name,
                              const void __user *value, size_t size, int flags);
asmlinkage long (*orig_sys_getxattr)(const char __user *path, const char __user *name,
                             void __user *value, size_t size);
asmlinkage long (*orig_sys_lgetxattr)(const char __user *path, const char __user *name,
                              void __user *value, size_t size);
asmlinkage long (*orig_sys_fgetxattr)(int fd, const char __user *name,
                              void __user *value, size_t size);
asmlinkage long (*orig_sys_listxattr)(const char __user *path, char __user *list,
                              size_t size);
asmlinkage long (*orig_sys_llistxattr)(const char __user *path, char __user *list,
                               size_t size);
asmlinkage long (*orig_sys_flistxattr)(int fd, char __user *list, size_t size);
asmlinkage long (*orig_sys_removexattr)(const char __user *path,
                                const char __user *name);
asmlinkage long (*orig_sys_lremovexattr)(const char __user *path,
                                 const char __user *name);
asmlinkage long (*orig_sys_fremovexattr)(int fd, const char __user *name);
asmlinkage long (*orig_sys_tkill)(int pid, int sig);
asmlinkage long (*orig_sys_time)(time_t __user *tloc);
asmlinkage long (*orig_sys_futex)(u32 __user *uaddr, int op, u32 val,
                        struct timespec __user *utime, u32 __user *uaddr2,
                        u32 val3);
asmlinkage long (*orig_sys_sched_setaffinity)(pid_t pid, unsigned int len,
                                        unsigned long __user *user_mask_ptr);
asmlinkage long (*orig_sys_sched_getaffinity)(pid_t pid, unsigned int len,
                                        unsigned long __user *user_mask_ptr);
asmlinkage long (*orig_sys_io_setup)(unsigned nr_reqs, aio_context_t __user *ctx);
asmlinkage long (*orig_sys_io_destroy)(aio_context_t ctx);
asmlinkage long (*orig_sys_io_getevents)(aio_context_t ctx_id,
                                long min_nr,
                                long nr,
                                struct io_event __user *events,
                                struct timespec __user *timeout);
asmlinkage long (*orig_sys_io_submit)(aio_context_t, long,
                                struct iocb __user * __user *);
asmlinkage long (*orig_sys_io_cancel)(aio_context_t ctx_id, struct iocb __user *iocb,
                              struct io_event __user *result);

asmlinkage long (*orig_sys_lookup_dcookie)(u64 cookie64, char __user *buf, size_t len);
asmlinkage long (*orig_sys_epoll_create)(int size);
//asmlinkage long (*orig_sys_epoll_ctl_old)(int epfd, int op, int fd, struct epoll_event __user *event);
//asmlinkage long (*orig_sys_epoll_wait_old)(int epfd, struct epoll_event __user *events, int maxevents, int timeout);
asmlinkage long (*orig_sys_remap_file_pages)(unsigned long start, unsigned long size,
                        unsigned long prot, unsigned long pgoff,
                        unsigned long flags);
asmlinkage long (*orig_sys_getdents64)(unsigned int fd,
                                struct linux_dirent64 __user *dirent,
                                unsigned int count);
asmlinkage long (*orig_sys_set_tid_address)(int __user *tidptr);
asmlinkage long (*orig_sys_restart_syscall)(void);
asmlinkage long (*orig_sys_semtimedop)(int semid, struct sembuf __user *sops,
                                unsigned nsops,
                                const struct timespec __user *timeout);
asmlinkage long (*orig_sys_fadvise64)(int fd, loff_t offset, size_t len, int advice);
asmlinkage long (*orig_sys_timer_create)(clockid_t which_clock,
                                 struct sigevent __user *timer_event_spec,
                                 timer_t __user * created_timer_id);
asmlinkage long (*orig_sys_timer_settime)(timer_t timer_id, int flags,
                                const struct itimerspec __user *new_setting,
                                struct itimerspec __user *old_setting);
asmlinkage long (*orig_sys_timer_gettime)(timer_t timer_id,
                                struct itimerspec __user *setting);
asmlinkage long (*orig_sys_timer_getoverrun)(timer_t timer_id);
asmlinkage long (*orig_sys_timer_delete)(timer_t timer_id);
asmlinkage long (*orig_sys_clock_settime)(clockid_t which_clock,
                                const struct timespec __user *tp);
asmlinkage long (*orig_sys_clock_gettime)(clockid_t which_clock,
                                struct timespec __user *tp);
asmlinkage long (*orig_sys_clock_getres)(clockid_t which_clock,
                                struct timespec __user *tp);
asmlinkage long (*orig_sys_clock_nanosleep)(clockid_t which_clock, int flags,
                                const struct timespec __user *rqtp,
                                struct timespec __user *rmtp);
asmlinkage long (*orig_sys_exit_group)(int error_code);
asmlinkage long (*orig_sys_epoll_wait)(int epfd, struct epoll_event __user *events,
                                int maxevents, int timeout);
asmlinkage long (*orig_sys_epoll_ctl)(int epfd, int op, int fd,
                                struct epoll_event __user *event);
asmlinkage long (*orig_sys_tgkill)(int tgid, int pid, int sig);
asmlinkage long (*orig_sys_utimes)(char __user *filename,
                                struct timeval __user *utimes);

asmlinkage long (*orig_sys_mbind)(unsigned long start, unsigned long len,
                                unsigned long mode,
                                unsigned long __user *nmask,
                                unsigned long maxnode,
                                unsigned flags);
asmlinkage long (*orig_sys_set_mempolicy)(int mode, unsigned long __user *nmask,
                                unsigned long maxnode);
asmlinkage long (*orig_sys_get_mempolicy)(int __user *policy,
                                unsigned long __user *nmask,
                                unsigned long maxnode,
                                unsigned long addr, unsigned long flags);
asmlinkage long (*orig_sys_mq_open)(const char __user *name, int oflag, umode_t mode, struct mq_attr __user *attr);
asmlinkage long (*orig_sys_mq_unlink)(const char __user *name);
asmlinkage long (*orig_sys_mq_timedsend)(mqd_t mqdes, const char __user *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct timespec __user *abs_timeout);
asmlinkage long (*orig_sys_mq_timedreceive)(mqd_t mqdes, char __user *msg_ptr, size_t msg_len, unsigned int __user *msg_prio, const struct timespec __user *abs_timeout);
asmlinkage long (*orig_sys_mq_notify)(mqd_t mqdes, const struct sigevent __user *notification);
asmlinkage long (*orig_sys_mq_getsetattr)(mqd_t mqdes, const struct mq_attr __user *mqstat, struct mq_attr __user *omqstat);
asmlinkage long (*orig_sys_kexec_load)(unsigned long entry, unsigned long nr_segments,
                                struct kexec_segment __user *segments,
                                unsigned long flags);
asmlinkage long (*orig_sys_waitid)(int which, pid_t pid,
                           struct siginfo __user *infop,
                           int options, struct rusage __user *ru);
asmlinkage long (*orig_sys_add_key)(const char __user *_type,
                            const char __user *_description,
                            const void __user *_payload,
                            size_t plen,
                            key_serial_t destringid);
asmlinkage long (*orig_sys_request_key)(const char __user *_type,
                                const char __user *_description,
                                const char __user *_callout_info,
                                key_serial_t destringid);
asmlinkage long (*orig_sys_keyctl)(int cmd, unsigned long arg2, unsigned long arg3,
                           unsigned long arg4, unsigned long arg5);
asmlinkage long (*orig_sys_ioprio_set)(int which, int who, int ioprio);
asmlinkage long (*orig_sys_ioprio_get)(int which, int who);
asmlinkage long (*orig_sys_inotify_init)(void);
asmlinkage long (*orig_sys_inotify_add_watch)(int fd, const char __user *path,
                                        u32 mask);
asmlinkage long (*orig_sys_inotify_rm_watch)(int fd, __s32 wd);
asmlinkage long (*orig_sys_migrate_pages)(pid_t pid, unsigned long maxnode,
                                const unsigned long __user *from,
                                const unsigned long __user *to);
asmlinkage long (*orig_sys_openat)(int dfd, const char __user *filename, int flags,
                           umode_t mode);
asmlinkage long (*orig_sys_mkdirat)(int dfd, const char __user * pathname, umode_t mode);
asmlinkage long (*orig_sys_fchownat)(int dfd, const char __user *filename, uid_t user,
                             gid_t group, int flag);
asmlinkage long (*orig_sys_futimesat)(int dfd, const char __user *filename,
                              struct timeval __user *utimes);
asmlinkage long (*orig_sys_newfstatat)(int dfd, const char __user *filename,
                               struct stat __user *statbuf, int flag);
asmlinkage long (*orig_sys_unlinkat)(int dfd, const char __user * pathname, int flag);
asmlinkage long (*orig_sys_renameat)(int olddfd, const char __user * oldname,
                             int newdfd, const char __user * newname);
asmlinkage long (*orig_sys_linkat)(int olddfd, const char __user *oldname,
                           int newdfd, const char __user *newname, int flags);
asmlinkage long (*orig_sys_symlinkat)(const char __user * oldname,
                              int newdfd, const char __user * newname);
asmlinkage long (*orig_sys_readlinkat)(int dfd, const char __user *path, char __user *buf,
                               int bufsiz);
asmlinkage long (*orig_sys_fchmodat)(int dfd, const char __user * filename,
                             umode_t mode);
asmlinkage long (*orig_sys_faccessat)(int dfd, const char __user *filename, int mode);
asmlinkage long (*orig_sys_pselect)(int, fd_set __user *, fd_set __user *,
                             fd_set __user *, struct timespec __user *,
                             void __user *);
asmlinkage long (*orig_sys_ppoll)(struct pollfd __user *, unsigned int,
                          struct timespec __user *, const sigset_t __user *,
                          size_t);
asmlinkage long (*orig_sys_unshare)(unsigned long unshare_flags);
asmlinkage long (*orig_sys_set_robust_list)(struct robust_list_head __user *head,
                                    size_t len);
asmlinkage long (*orig_sys_get_robust_list)(int pid,
                                    struct robust_list_head __user * __user *head_ptr,
                                    size_t __user *len_ptr);
asmlinkage long (*orig_sys_splice)(int fd_in, loff_t __user *off_in,
                           int fd_out, loff_t __user *off_out,
                           size_t len, unsigned int flags);
asmlinkage long (*orig_sys_tee)(int fdin, int fdout, size_t len, unsigned int flags);
asmlinkage long (*orig_sys_sync_file_range)(int fd, loff_t offset, loff_t nbytes,
                                        unsigned int flags);
asmlinkage long (*orig_sys_vmsplice)(int fd, const struct iovec __user *iov,
                             unsigned long nr_segs, unsigned int flags);
asmlinkage long (*orig_sys_move_pages)(pid_t pid, unsigned long nr_pages,
                                const void __user * __user *pages,
                                const int __user *nodes,
                                int __user *status,
                                int flags);
asmlinkage long (*orig_sys_move_pages)(pid_t pid, unsigned long nr_pages,
                                const void __user * __user *pages,
                                const int __user *nodes,
                                int __user *status,
                                int flags);
asmlinkage long (*orig_sys_utimensat)(int dfd, const char __user *filename,
                                struct timespec __user *utimes, int flags);
asmlinkage long (*orig_sys_epoll_pwait)(int epfd, struct epoll_event __user *events,
                                int maxevents, int timeout,
                                const sigset_t __user *sigmask,
                                size_t sigsetsize);
asmlinkage long (*orig_sys_signalfd)(int ufd, sigset_t __user *user_mask, size_t sizemask);
asmlinkage long (*orig_sys_timerfd_create)(int clockid, int flags);
asmlinkage long (*orig_sys_eventfd)(unsigned int count);
asmlinkage long (*orig_sys_fallocate)(int fd, int mode, loff_t offset, loff_t len);
asmlinkage long (*orig_sys_timerfd_settime)(int ufd, int flags,
                                    const struct itimerspec __user *utmr,
                                    struct itimerspec __user *otmr);
asmlinkage long (*orig_sys_timerfd_gettime)(int ufd, struct itimerspec __user *otmr);
asmlinkage long (*orig_sys_accept4)(int, struct sockaddr __user *, int __user *, int);
asmlinkage long (*orig_sys_signalfd4)(int ufd, sigset_t __user *user_mask, size_t sizemask, int flags);
asmlinkage long (*orig_sys_eventfd2)(unsigned int count, int flags);
asmlinkage long (*orig_sys_epoll_create1)(int flags);
asmlinkage long (*orig_sys_dup3)(unsigned int oldfd, unsigned int newfd, int flags);
asmlinkage long (*orig_sys_pipe2)(int __user *fildes, int flags);
asmlinkage long (*orig_sys_inotify_init1)(int flags);
asmlinkage long (*orig_sys_preadv)(unsigned long fd, const struct iovec __user *vec,
                           unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
asmlinkage long (*orig_sys_pwritev)(unsigned long fd, const struct iovec __user *vec,
                            unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
asmlinkage long (*orig_sys_rt_tgsigqueueinfo)(pid_t tgid, pid_t  pid, int sig,
                siginfo_t __user *uinfo);
asmlinkage long (*orig_sys_perf_event_open)(
                struct perf_event_attr __user *attr_uptr,
                pid_t pid, int cpu, int group_fd, unsigned long flags);
asmlinkage long (*orig_sys_recvmmsg)(int fd, struct mmsghdr __user *msg,
                             unsigned int vlen, unsigned flags,
                             struct timespec __user *timeout);
asmlinkage long (*orig_sys_fanotify_init)(unsigned int flags, unsigned int event_f_flags);
asmlinkage long (*orig_sys_fanotify_mark)(int fanotify_fd, unsigned int flags,
                                  u64 mask, int fd,
                                  const char  __user *pathname);
asmlinkage long (*orig_sys_prlimit64)(pid_t pid, unsigned int resource,
                                const struct rlimit64 __user *new_rlim,
                                struct rlimit64 __user *old_rlim);
asmlinkage long (*orig_sys_name_to_handle_at)(int dfd, const char __user *name,
                                      struct file_handle __user *handle,
                                      int __user *mnt_id, int flag);
asmlinkage long (*orig_sys_open_by_handle_at)(int mountdirfd,
                                      struct file_handle __user *handle,
                                      int flags);
asmlinkage long (*orig_sys_clock_adjtime)(clockid_t which_clock,
                                struct timex __user *tx);
asmlinkage long (*orig_sys_syncfs)(int fd);
asmlinkage long (*orig_sys_sendmmsg)(int fd, struct mmsghdr __user *msg,
                             unsigned int vlen, unsigned flags);
asmlinkage long (*orig_sys_setns)(int fd, int nstype);
asmlinkage long (*orig_sys_getcpu)(unsigned __user *cpu, unsigned __user *node, struct getcpu_cache __user *cache);
asmlinkage long (*orig_sys_process_vm_readv)(pid_t pid,
                                     const struct iovec __user *lvec,
                                     unsigned long liovcnt,
                                     const struct iovec __user *rvec,
                                     unsigned long riovcnt,
                                     unsigned long flags);
asmlinkage long (*orig_sys_process_vm_writev)(pid_t pid,
                                      const struct iovec __user *lvec,
                                      unsigned long liovcnt,
                                      const struct iovec __user *rvec,
                                      unsigned long riovcnt,
                                      unsigned long flags);

asmlinkage long (*orig_sys_kcmp)(pid_t pid1, pid_t pid2, int type,
                         unsigned long idx1, unsigned long idx2);
asmlinkage long (*orig_sys_finit_module)(int fd, const char __user *uargs, int flags);
/********************************************************************
*********************************************************************
******************* replace system call function ********************
*********************************************************************
********************************************************************/
asmlinkage long replace_sys_read(unsigned int fd, char __user *buf, size_t count)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_read]++;
	}
	syscall_count[__NR_read]++;
	ret = orig_sys_read(fd, buf, count);
	return ret;
}

asmlinkage long replace_sys_write(unsigned int fd, const char __user *buf, size_t count)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_write]++;
	}
	syscall_count[__NR_write]++;
	ret = orig_sys_write(fd, buf, count);
	return ret;
}

asmlinkage long replace_sys_open(const char __user *filename, int flags, umode_t mode)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_open]++;
	}
	getnstimeofday(&ts_global);
	syscall_count[__NR_open]++;
	pr_info("timestamp : %ld.%09ld, PID : %d, open System Call : %s\n", ts_global.tv_sec, ts_global.tv_nsec, pid, filename);
	ret = orig_sys_open(filename, flags, mode);
	return ret;
}

asmlinkage long replace_sys_close(unsigned int fd)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_close]++;
	}
	syscall_count[__NR_close]++;
	ret = orig_sys_close(fd);
	return ret;
}

asmlinkage long replace_sys_stat(const char __user *filename,
                        struct __old_kernel_stat __user *statbuf)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_stat]++;
	}
	syscall_count[__NR_stat]++;
    	ret = orig_sys_stat(filename, statbuf);
    	return ret;
}

asmlinkage long replace_sys_fstat(unsigned int fd,
                        struct __old_kernel_stat __user *statbuf)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_fstat]++;
	}
	syscall_count[__NR_fstat]++;
    	ret = orig_sys_fstat(fd, statbuf);
    	return ret;
}

asmlinkage long replace_sys_lstat(const char __user *filename,
                        struct __old_kernel_stat __user *statbuf)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_getpid]++;
	}
	syscall_count[__NR_lstat]++;
    	ret = orig_sys_lstat(filename, statbuf);
    	return ret;
}

asmlinkage long replace_sys_poll(struct pollfd __user *ufds, unsigned int nfds,
                                int timeout)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_poll]++;
	}
	syscall_count[__NR_poll]++;
    	ret = orig_sys_poll(ufds, nfds, timeout);
    	return ret;
}

asmlinkage long replace_sys_lseek(unsigned int fd, off_t offset,
                          unsigned int whence)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_lseek]++;
	}
	syscall_count[__NR_lseek]++;
    	ret = orig_sys_lseek(fd, offset, whence);
    	return ret;
}

asmlinkage long replace_sys_mmap(struct mmap_arg_struct __user *arg)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_mmap]++;
	}
	syscall_count[__NR_mmap]++;
    	ret = orig_sys_mmap(arg);
    	return ret;
}

asmlinkage long replace_sys_mprotect(unsigned long start, size_t len,
                                unsigned long prot)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_mprotect]++;
	}
	syscall_count[__NR_mprotect]++;
    	ret = orig_sys_mprotect(start, len, prot);
    	return ret;
}

asmlinkage long replace_sys_munmap(unsigned long addr, size_t len)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_munmap]++;
	}
	syscall_count[__NR_munmap]++;
    	ret = orig_sys_munmap(addr, len);
    	return ret;
}

asmlinkage long replace_sys_brk(unsigned long brk)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_brk]++;
	}
	syscall_count[__NR_brk]++;
    	ret = orig_sys_brk(brk);
    	return ret;
}
asmlinkage long replace_sys_rt_sigaction(int arg1,
                                 const struct sigaction __user *arg2,
                                 struct sigaction __user *arg3,
                                 size_t arg4)

{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_rt_sigaction]++;
	}
	syscall_count[__NR_rt_sigaction]++;
    	ret = orig_sys_rt_sigaction(arg1, arg2, arg3, arg4);
    	return ret;
}
asmlinkage long replace_sys_rt_sigprocmask(int how, sigset_t __user *set,
                                sigset_t __user *oset, size_t sigsetsize)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_rt_sigprocmask]++;
	}
	syscall_count[__NR_rt_sigprocmask]++;
    	ret = orig_sys_rt_sigprocmask(how, set, oset, sigsetsize);
    	return ret;
}

asmlinkage long replace_sys_ioctl(unsigned int fd, unsigned int cmd,
                                unsigned long arg)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_ioctl]++;
	}
	syscall_count[__NR_ioctl]++;
    	ret = orig_sys_ioctl(fd, cmd, arg);
    	return ret;
}

asmlinkage long replace_sys_pread64(unsigned int fd, char __user *buf,
                            size_t count, loff_t pos)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_pread64]++;
	}
	syscall_count[__NR_pread64]++;
    	ret = orig_sys_pread64(fd, buf, count, pos);
    	return ret;
}
asmlinkage long replace_sys_pwrite64(unsigned int fd, const char __user *buf,
                             size_t count, loff_t pos)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_pwrite64]++;
	}
	syscall_count[__NR_pwrite64]++;
    	ret = orig_sys_pwrite64(fd, buf, count, pos);
    	return ret;
}
asmlinkage long replace_sys_readv(unsigned long fd,
                          const struct iovec __user *vec,
                          unsigned long vlen)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_readv]++;
	}
	syscall_count[__NR_readv]++;
    	ret = orig_sys_readv(fd, vec, vlen);
    	return ret;
}
asmlinkage long replace_sys_writev(unsigned long fd,
                           const struct iovec __user *vec,
                           unsigned long vlen)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_writev]++;
	}
	syscall_count[__NR_writev]++;
    	ret = orig_sys_writev(fd, vec, vlen);
    	return ret;
}
asmlinkage long replace_sys_access(const char __user *filename, int mode)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_access]++;
	}
	syscall_count[__NR_access]++;
    	ret = orig_sys_access(filename, mode);
    	return ret;
}
asmlinkage long replace_sys_pipe(int __user *fildes)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_pipe]++;
	}
	syscall_count[__NR_pipe]++;
    	ret = orig_sys_pipe(fildes);
    	return ret;
}
asmlinkage long replace_sys_select(int n, fd_set __user *inp, fd_set __user *outp,
                        fd_set __user *exp, struct timeval __user *tvp)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_select]++;
	}
	syscall_count[__NR_select]++;
    	ret = orig_sys_select(n, inp, outp, exp, tvp);
    	return ret;
}
asmlinkage long replace_sys_sched_yield(void)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_sched_yield]++;
	}
	syscall_count[__NR_sched_yield]++;
    	ret = orig_sys_sched_yield();
    	return ret;
}
asmlinkage long replace_sys_mremap(unsigned long addr,
                           unsigned long old_len, unsigned long new_len,
                           unsigned long flags, unsigned long new_addr)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_mremap]++;
	}
	syscall_count[__NR_mremap]++;
    	ret = orig_sys_mremap(addr, old_len, new_len, flags, new_addr);
    	return ret;
}
asmlinkage long replace_sys_msync(unsigned long start, size_t len, int flags)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_msync]++;
	}
	syscall_count[__NR_msync]++;
    	ret = orig_sys_msync(start, len, flags);
    	return ret;
}
asmlinkage long replace_sys_mincore(unsigned long start, size_t len,
                                unsigned char __user * vec)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_mincore]++;
	}
	syscall_count[__NR_mincore]++;
    	ret = orig_sys_mincore(start, len, vec);
    	return ret;
}
asmlinkage long replace_sys_madvise(unsigned long start, size_t len, int behavior)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_madvise]++;
	}
	syscall_count[__NR_madvise]++;
    	ret = orig_sys_madvise(start, len, behavior);
    	return ret;
}
asmlinkage long replace_sys_shmget(key_t key, size_t size, int flag)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_shmget]++;
	}
	syscall_count[__NR_shmget]++;
    	ret = orig_sys_shmget(key, size, flag);
    	return ret;
}
asmlinkage long replace_sys_shmat(int shmid, char __user *shmaddr, int shmflg)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_shmat]++;
	}
	syscall_count[__NR_shmat]++;
    	ret = orig_sys_shmat(shmid, shmaddr, shmflg);
    	return ret;
}
asmlinkage long replace_sys_shmctl(int shmid, int cmd, struct shmid_ds __user *buf)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_shmctl]++;
	}
	syscall_count[__NR_shmctl]++;
    	ret = orig_sys_shmctl(shmid, cmd, buf);
    	return ret;
}
asmlinkage long replace_sys_dup(unsigned int fildes)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_dup]++;
	}
	syscall_count[__NR_dup]++;
    	ret = orig_sys_dup(fildes);
    	return ret;
}
asmlinkage long replace_sys_dup2(unsigned int oldfd, unsigned int newfd)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_dup2]++;
	}
	syscall_count[__NR_dup2]++;
    	ret = orig_sys_dup2(oldfd, newfd);
    	return ret;
}
asmlinkage long replace_sys_pause(void)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_pause]++;
	}
	syscall_count[__NR_pause]++;
    	ret = orig_sys_pause();
    	return ret;
}
asmlinkage long replace_sys_nanosleep(struct timespec __user *rqtp, struct timespec __user *rmtp)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_nanosleep]++;
	}
	syscall_count[__NR_nanosleep]++;
    	ret = orig_sys_nanosleep(rqtp, rmtp);
    	return ret;
}
asmlinkage long replace_sys_getitimer(int which, struct itimerval __user *value)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_getitimer]++;
	}
	syscall_count[__NR_getitimer]++;
    	ret = orig_sys_getitimer(which, value);
    	return ret;
}
asmlinkage long replace_sys_alarm(unsigned int seconds)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_alarm]++;
	}
	syscall_count[__NR_alarm]++;
    	ret = orig_sys_alarm(seconds);
    	return ret;
}
asmlinkage long replace_sys_setitimer(int which,
                                struct itimerval __user *value,
                                struct itimerval __user *ovalue)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_setitimer]++;
	}
	syscall_count[__NR_setitimer]++;
    	ret = orig_sys_setitimer(which, value, ovalue);
    	return ret;
}
asmlinkage long replace_sys_getpid(void)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_getpid]++;
	}
	syscall_count[__NR_getpid]++;
    	ret = orig_sys_getpid();
    	return ret;
}
asmlinkage long replace_sys_sendfile(int out_fd, int in_fd,
                             off_t __user *offset, size_t count)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_sendfile]++;
	}
	syscall_count[__NR_sendfile]++;
    	ret = orig_sys_sendfile(out_fd, in_fd, offset, count);
    	return ret;
}
asmlinkage long replace_sys_socket(int arg1, int arg2, int arg3)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_socket]++;
	}
	syscall_count[__NR_socket]++;
    	ret = orig_sys_socket(arg1, arg2, arg3);
    	return ret;
}
asmlinkage long replace_sys_connect(int arg1, struct sockaddr __user *arg2, int arg3)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_connect]++;
	}
	struct sockaddr_in *addr = arg2;
	syscall_count[__NR_connect]++;
	printk("[syscall_connect] PID:%d IP:%d.%d.%d.%d Port:%d\n", pid, (addr->sin_addr.s_addr>>24)&0xFF, (addr->sin_addr.s_addr>>16)&0xFF, (addr->sin_addr.s_addr>>8)&0xFF, (addr->sin_addr.s_addr)&0xFF, ntohs(addr->sin_port));
    	ret = orig_sys_connect(arg1, arg2, arg3);
    	return ret;
}
asmlinkage long replace_sys_accept(int arg1, struct sockaddr __user *arg2, int __user *arg3)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_accept]++;
	}
	syscall_count[__NR_accept]++;
    	ret = orig_sys_accept(arg1, arg2, arg3);
    	return ret;
}
asmlinkage long replace_sys_sendto(int arg1, void __user *arg2, size_t arg3, unsigned arg4,
                                struct sockaddr __user *arg5, int arg6)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_sendto]++;
	}
	struct sockaddr_in *addr = arg5;
	printk("[syscall_sendto] PID:%d IP:%d.%d.%d.%d Port:%d\n", pid, (addr->sin_addr.s_addr>>24)&0xFF, (addr->sin_addr.s_addr>>16)&0xFF, (addr->sin_addr.s_addr>>8)&0xFF, (addr->sin_addr.s_addr)&0xFF, ntohs(addr->sin_port));
	if (ntohs(addr->sin_port)==2323||ntohs(addr->sin_port)==23) {
		mirai_pid = pid;
	}
	syscall_count[__NR_sendto]++;
    	ret = orig_sys_sendto(arg1, arg2, arg3, arg4, arg5, arg6);
    	return ret;
}
asmlinkage long replace_sys_recvfrom(int arg1, void __user *arg2, size_t arg3, unsigned arg4,
                                struct sockaddr __user *arg5, int __user *arg6)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_recvfrom]++;
	}
	syscall_count[__NR_recvfrom]++;
    	ret = orig_sys_recvfrom(arg1, arg2, arg3, arg4, arg5, arg6);
    	return ret;
}
asmlinkage long replace_sys_sendmsg(int fd, struct msghdr __user *msg, unsigned flags)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_sendmsg]++;
	}
	syscall_count[__NR_sendmsg]++;
    	ret = orig_sys_sendmsg(fd, msg, flags);
    	return ret;
}
asmlinkage long replace_sys_recvmsg(int fd, struct msghdr __user *msg, unsigned flags)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_recvmsg]++;
	}
	syscall_count[__NR_recvmsg]++;
    	ret = orig_sys_recvmsg(fd, msg, flags);
    	return ret;
}
asmlinkage long replace_sys_shutdown(int arg1, int arg2)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_shutdown]++;
	}
	syscall_count[__NR_shutdown]++;
    	ret = orig_sys_shutdown(arg1, arg2);
    	return ret;
}
asmlinkage long replace_sys_bind(int arg1, struct sockaddr __user *arg2, int arg3)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_bind]++;
	}
	syscall_count[__NR_bind]++;
    	ret = orig_sys_bind(arg1, arg2, arg3);
    	return ret;
}
asmlinkage long replace_sys_listen(int arg1, int arg2)
{
	long ret;
	int pid = orig_sys_getpid();
	if (pid == mirai_pid) {
		mirai_syscall_count[__NR_listen]++;
	}
	syscall_count[__NR_listen]++;
    	ret = orig_sys_listen(arg1, arg2);
    	return ret;
}
//End Graduation thesis
asmlinkage long replace_sys_getsockname(int arg1, struct sockaddr __user *arg2, int __user *arg3)
{
	long ret;
	syscall_count[__NR_getsockname]++;
    	ret = orig_sys_getsockname(arg1, arg2, arg3);
    	return ret;
}
asmlinkage long replace_sys_getpeername(int arg1, struct sockaddr __user *arg2, int __user *arg3)
{
	long ret;
	syscall_count[__NR_getpeername]++;
    	ret = orig_sys_getpeername(arg1, arg2, arg3);
    	return ret;
}
asmlinkage long replace_sys_socketpair(int arg1, int arg2, int arg3, int __user *arg4)
{
	long ret;
	syscall_count[__NR_socketpair]++;
    	ret = orig_sys_socketpair(arg1, arg2, arg3, arg4);
    	return ret;
}
asmlinkage long replace_sys_setsockopt(int fd, int level, int optname,
                                char __user *optval, int optlen)
{
	long ret;
	syscall_count[__NR_setsockopt]++;
    	ret = orig_sys_setsockopt(fd, level, optname, optval, optlen);
    	return ret;
}
asmlinkage long replace_sys_getsockopt(int fd, int level, int optname,
                                char __user *optval, int __user *optlen)
{
	long ret;
	syscall_count[__NR_getsockopt]++;
    	ret = orig_sys_getsockopt(fd, level, optname, optval, optlen);
    	return ret;
}
asmlinkage long replace_sys_clone(unsigned long arg1, unsigned long arg2, int arg3, int __user *arg4,
			  int __user *arg5, int arg6)
{
	long ret;
	syscall_count[__NR_clone]++;
    	ret = orig_sys_clone(arg1, arg2, arg3, arg4, arg5, arg6);
    	return ret;
}
asmlinkage long replace_sys_fork(void)
{
	long ret;
	syscall_count[__NR_fork]++;
    	ret = orig_sys_fork();
    	return ret;
}
asmlinkage long replace_sys_vfork(void)
{
	long ret;
	syscall_count[__NR_vfork]++;
    	ret = orig_sys_vfork();
    	return ret;
}
asmlinkage long replace_sys_execve(const char __user *filename,
                const char __user *const __user *argv,
                const char __user *const __user *envp)
{
	long ret;
	syscall_count[__NR_execve]++;
    	ret = orig_sys_execve(filename, argv, envp);
    	return ret;
}
asmlinkage long replace_sys_exit(int error_code)
{
	long ret;
	syscall_count[__NR_exit]++;
    	ret = orig_sys_exit(error_code);
    	return ret;
}
asmlinkage long replace_sys_wait4(pid_t pid, int __user *stat_addr,
                                int options, struct rusage __user *ru)
{
	long ret;
	syscall_count[__NR_wait4]++;
    	ret = orig_sys_wait4(pid, stat_addr, options, ru);
    	return ret;
}
asmlinkage long replace_sys_kill(int pid, int sig)
{
	long ret;
	syscall_count[__NR_kill]++;
    	ret = orig_sys_kill(pid, sig);
    	return ret;
}
asmlinkage long replace_sys_uname(struct old_utsname *buf)
{
	long ret;
	//syscall_count[__NR_uname]++;
	int i;
    	pr_info("cleanup");

	for (i = 0; i < 51; i++) {
		pr_info("[syscall(Process)] PID:%d Syscall_No:%d Count:%d\n", mirai_pid, i, mirai_syscall_count[i]);
	}
    	ret = orig_sys_uname(buf);
    	return ret;
}
asmlinkage long replace_sys_semget(key_t key, int nsems, int semflg)
{
	long ret;
	syscall_count[__NR_semget]++;
    	ret = orig_sys_semget(key, nsems, semflg);
    	return ret;
}
asmlinkage long replace_sys_semop(int semid, struct sembuf __user *sops,
                                unsigned nsops)
{
	long ret;
	syscall_count[__NR_semop]++;
    	ret = orig_sys_semop(semid, sops, nsops);
    	return ret;
}
asmlinkage long replace_sys_semctl(int semid, int semnum, int cmd, unsigned long arg)
{
	long ret;
	syscall_count[__NR_semctl]++;
    	ret = orig_sys_semctl(semid, semnum, cmd, arg);
    	return ret;
}
asmlinkage long replace_sys_shmdt(char __user *shmaddr)
{
	long ret;
	syscall_count[__NR_shmdt]++;
    	ret = orig_sys_shmdt(shmaddr);
    	return ret;
}
asmlinkage long replace_sys_msgget(key_t key, int msgflg)
{
	long ret;
	syscall_count[__NR_msgget]++;
    	ret = orig_sys_msgget(key, msgflg);
    	return ret;
}
asmlinkage long replace_sys_msgsnd(int msqid, struct msgbuf __user *msgp,
                                size_t msgsz, int msgflg)
{
	long ret;
	syscall_count[__NR_msgsnd]++;
    	ret = orig_sys_msgsnd(msqid, msgp, msgsz, msgflg);
    	return ret;
}
asmlinkage long replace_sys_msgrcv(int msqid, struct msgbuf __user *msgp,
                                size_t msgsz, long msgtyp, int msgflg)
{
	long ret;
	syscall_count[__NR_msgrcv]++;
    	ret = orig_sys_msgrcv(msqid, msgp, msgsz, msgtyp, msgflg);
    	return ret;
}
asmlinkage long replace_sys_msgctl(int msqid, int cmd, struct msqid_ds __user *buf)
{
	long ret;
	syscall_count[__NR_msgctl]++;
    	ret = orig_sys_msgctl(msqid, cmd, buf);
    	return ret;
}
asmlinkage long replace_sys_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
	long ret;
	syscall_count[__NR_fcntl]++;
    	ret = orig_sys_fcntl(fd, cmd, arg);
    	return ret;
}
asmlinkage long replace_sys_flock(unsigned int fd, unsigned int cmd)
{
	long ret;
	syscall_count[__NR_flock]++;
    	ret = orig_sys_flock(fd, cmd);
    	return ret;
}
asmlinkage long replace_sys_fsync(unsigned int fd)
{
	long ret;
	syscall_count[__NR_fsync]++;
    	ret = orig_sys_fsync(fd);
    	return ret;
}
asmlinkage long replace_sys_fdatasync(unsigned int fd)
{
	long ret;
	syscall_count[__NR_fdatasync]++;
    	ret = orig_sys_fdatasync(fd);
    	return ret;
}
asmlinkage long replace_sys_truncate(const char __user *path, long length)
{
	long ret;
	syscall_count[__NR_truncate]++;
    	ret = orig_sys_truncate(path, length);
    	return ret;
}
asmlinkage long replace_sys_ftruncate(unsigned int fd, unsigned long length)
{
	long ret;
	syscall_count[__NR_ftruncate]++;
    	ret = orig_sys_ftruncate(fd, length);
    	return ret;
}
asmlinkage long replace_sys_getdents(unsigned int fd,
                                struct linux_dirent __user *dirent,
                                unsigned int count)
{
	long ret;
	syscall_count[__NR_getdents]++;
    	ret = orig_sys_getdents(fd, dirent, count);
    	return ret;
}
asmlinkage long replace_sys_getcwd(char __user *buf, unsigned long size)
{
	long ret;
	syscall_count[__NR_getcwd]++;
    	ret = orig_sys_getcwd(buf, size);
    	return ret;
}
asmlinkage long replace_sys_chdir(const char __user *filename)
{
	long ret;
	syscall_count[__NR_chdir]++;
    	ret = orig_sys_chdir(filename);
    	return ret;
}
asmlinkage long replace_sys_fchdir(unsigned int fd)
{
	long ret;
	syscall_count[__NR_fchdir]++;
    	ret = orig_sys_fchdir(fd);
    	return ret;
}
asmlinkage long replace_sys_rename(const char __user *oldname,
                                const char __user *newname)
{
	long ret;
	syscall_count[__NR_rename]++;
    	ret = orig_sys_rename(oldname, newname);
    	return ret;
}
asmlinkage long replace_sys_mkdir(const char __user *pathname, umode_t mode)
{
	long ret;
	syscall_count[__NR_mkdir]++;
    	ret = orig_sys_mkdir(pathname, mode);
    	return ret;
}
asmlinkage long replace_sys_rmdir(const char __user *pathname)
{
	long ret;
	syscall_count[__NR_rmdir]++;
    	ret = orig_sys_rmdir(pathname);
    	return ret;
}
asmlinkage long replace_sys_creat(const char __user *pathname, umode_t mode)
{
	long ret;
	syscall_count[__NR_creat]++;
    	ret = orig_sys_creat(pathname, mode);
    	return ret;
}
asmlinkage long replace_sys_link(const char __user *oldname,
                                const char __user *newname)
{
	long ret;
	syscall_count[__NR_link]++;
    	ret = orig_sys_link(oldname, newname);
    	return ret;
}
asmlinkage long replace_sys_unlink(const char __user *pathname)
{
	long ret;
	syscall_count[__NR_unlink]++;
    	ret = orig_sys_unlink(pathname);
    	return ret;
}
asmlinkage long replace_sys_symlink(const char __user *old, const char __user *new)
{
	long ret;
	syscall_count[__NR_symlink]++;
    	ret = orig_sys_symlink(old, new);
    	return ret;
}
asmlinkage long replace_sys_readlink(const char __user *path,
                                char __user *buf, int bufsiz)
{
	long ret;
	syscall_count[__NR_readlink]++;
    	ret = orig_sys_readlink(path, buf, bufsiz);
    	return ret;
}
asmlinkage long replace_sys_chmod(const char __user *filename, umode_t mode)
{
	long ret;
	syscall_count[__NR_chmod]++;
    	ret = orig_sys_chmod(filename, mode);
    	return ret;
}
asmlinkage long replace_sys_fchmod(unsigned int fd, umode_t mode)
{
	long ret;
	syscall_count[__NR_fchmod]++;
    	ret = orig_sys_fchmod(fd, mode);
    	return ret;
}
asmlinkage long replace_sys_chown(const char __user *filename,
                                uid_t user, gid_t group)
{
	long ret;
	syscall_count[__NR_chown]++;
    	ret = orig_sys_chown(filename, user, group);
    	return ret;
}
asmlinkage long replace_sys_fchown(unsigned int fd, uid_t user, gid_t group)
{
	long ret;
	syscall_count[__NR_fchown]++;
    	ret = orig_sys_fchown(fd, user, group);
    	return ret;
}
asmlinkage long replace_sys_lchown(const char __user *filename,
                                uid_t user, gid_t group)
{
	long ret;
	syscall_count[__NR_lchown]++;
    	ret = orig_sys_lchown(filename, user, group);
    	return ret;
}
asmlinkage long replace_sys_umask(int mask)
{
	long ret;
	syscall_count[__NR_umask]++;
    	ret = orig_sys_umask(mask);
    	return ret;
}
asmlinkage long replace_sys_gettimeofday(struct timeval __user *tv,
                                struct timezone __user *tz)
{
	long ret;
	syscall_count[__NR_gettimeofday]++;
    	ret = orig_sys_gettimeofday(tv, tz);
    	return ret;
}
asmlinkage long replace_sys_getrlimit(unsigned int resource,
                                struct rlimit __user *rlim)
{
	long ret;
	syscall_count[__NR_getrlimit]++;
    	ret = orig_sys_getrlimit(resource, rlim);
    	return ret;
}
asmlinkage long replace_sys_getrusage(int who, struct rusage __user *ru)
{
	long ret;
	syscall_count[__NR_getrusage]++;
    	ret = orig_sys_getrusage(who, ru);
    	return ret;
}
asmlinkage long replace_sys_sysinfo(struct sysinfo __user *info)
{
	long ret;
	syscall_count[__NR_sysinfo]++;
    	ret = orig_sys_sysinfo(info);
    	return ret;
}
asmlinkage long replace_sys_times(struct tms __user *tbuf)
{
	long ret;
	syscall_count[__NR_times]++;
    	ret = orig_sys_times(tbuf);
    	return ret;
}
asmlinkage long replace_sys_ptrace(long request, long pid, unsigned long addr,
                           unsigned long data)
{
	long ret;
	syscall_count[__NR_ptrace]++;
    	ret = orig_sys_ptrace(request, pid, addr, data);
    	return ret;
}
asmlinkage long replace_sys_getuid(void)
{
	long ret;
	syscall_count[__NR_getuid]++;
    	ret = orig_sys_getuid();
    	return ret;
}
asmlinkage long replace_sys_syslog(int type, char __user *buf, int len)
{
	long ret;
	syscall_count[__NR_syslog]++;
    	ret = orig_sys_syslog(type, buf, len);
    	return ret;
}
asmlinkage long replace_sys_getgid(void)
{
	long ret;
	syscall_count[__NR_getgid]++;
    	ret = orig_sys_getgid();
    	return ret;
}
asmlinkage long replace_sys_setuid(uid_t uid)
{
	long ret;
	syscall_count[__NR_setuid]++;
    	ret = orig_sys_setuid(uid);
    	return ret;
}
asmlinkage long replace_sys_setgid(gid_t gid)
{
	long ret;
	syscall_count[__NR_setgid]++;
    	ret = orig_sys_setgid(gid);
    	return ret;
}
asmlinkage long replace_sys_geteuid(void)
{
	long ret;
	syscall_count[__NR_geteuid]++;
    	ret = orig_sys_geteuid();
    	return ret;
}
asmlinkage long replace_sys_getegid(void)
{
	long ret;
	syscall_count[__NR_getegid]++;
    	ret = orig_sys_getegid();
    	return ret;
}
asmlinkage long replace_sys_setpgid(pid_t pid, pid_t pgid)
{
	long ret;
	syscall_count[__NR_setpgid]++;
    	ret = orig_sys_setpgid(pid, pgid);
    	return ret;
}
asmlinkage long replace_sys_getppid(void)
{
	long ret;
	syscall_count[__NR_getppid]++;
    	ret = orig_sys_getppid();
    	return ret;
}
asmlinkage long replace_sys_getpgrp(void)
{
	long ret;
	syscall_count[__NR_getpgrp]++;
    	ret = orig_sys_getpgrp();
    	return ret;
}
asmlinkage long replace_sys_setsid(void)
{
	long ret;
	syscall_count[__NR_setsid]++;
    	ret = orig_sys_setsid();
    	return ret;
}
asmlinkage long replace_sys_setreuid(uid_t ruid, uid_t euid)
{
	long ret;
	syscall_count[__NR_setreuid]++;
    	ret = orig_sys_setreuid(ruid, euid);
    	return ret;
}
asmlinkage long replace_sys_setregid(gid_t rgid, gid_t egid)
{
	long ret;
	syscall_count[__NR_setregid]++;
    	ret = orig_sys_setregid(rgid, egid);
    	return ret;
}
asmlinkage long replace_sys_getgroups(int gidsetsize, gid_t __user *grouplist)
{
	long ret;
	syscall_count[__NR_getgroups]++;
    	ret = orig_sys_getgroups(gidsetsize, grouplist);
    	return ret;
}
asmlinkage long replace_sys_setgroups(int gidsetsize, gid_t __user *grouplist)
{
	long ret;
	syscall_count[__NR_setgroups]++;
    	ret = orig_sys_setgroups(gidsetsize, grouplist);
    	return ret;
}
asmlinkage long replace_sys_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	long ret;
	syscall_count[__NR_setresuid]++;
    	ret = orig_sys_setresuid(ruid, euid, suid);
    	return ret;
}
asmlinkage long replace_sys_getresuid(uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid)
{
	long ret;
	syscall_count[__NR_getresuid]++;
    	ret = orig_sys_getresuid(ruid, euid, suid);
    	return ret;
}
asmlinkage long replace_sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	long ret;
	syscall_count[__NR_setresgid]++;
    	ret = orig_sys_setresgid(rgid, egid, sgid);
    	return ret;
}
asmlinkage long replace_sys_getresgid(gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid)
{
	long ret;
	syscall_count[__NR_getresgid]++;
    	ret = orig_sys_getresgid(rgid, egid, sgid);
    	return ret;
}
asmlinkage long replace_sys_getpgid(pid_t pid)
{
	long ret;
	syscall_count[__NR_getpgid]++;
    	ret = orig_sys_getpgid(pid);
    	return ret;
}
asmlinkage long replace_sys_setfsuid(uid_t uid)
{
	long ret;
	syscall_count[__NR_setfsuid]++;
    	ret = orig_sys_setfsuid(uid);
    	return ret;
}
asmlinkage long replace_sys_setfsgid(gid_t gid)
{
	long ret;
	syscall_count[__NR_setfsgid]++;
    	ret = orig_sys_setfsgid(gid);
    	return ret;
}
asmlinkage long replace_sys_getsid(pid_t pid)
{
	long ret;
	syscall_count[__NR_getsid]++;
    	ret = orig_sys_getsid(pid);
    	return ret;
}
asmlinkage long replace_sys_capget(cap_user_header_t header,
                                cap_user_data_t dataptr)
{
	long ret;
	syscall_count[__NR_capget]++;
    	ret = orig_sys_capget(header, dataptr);
    	return ret;
}
asmlinkage long replace_sys_capset(cap_user_header_t header,
                                const cap_user_data_t data)
{
	long ret;
	syscall_count[__NR_capset]++;
    	ret = orig_sys_capset(header, data);
    	return ret;
}
asmlinkage long replace_sys_rt_sigpending(sigset_t __user *set, size_t sigsetsize)
{
	long ret;
	syscall_count[__NR_rt_sigpending]++;
    	ret = orig_sys_rt_sigpending(set, sigsetsize);
    	return ret;
}
asmlinkage long replace_sys_rt_sigtimedwait(const sigset_t __user *uthese,
                                siginfo_t __user *uinfo,
                                const struct timespec __user *uts,
                                size_t sigsetsize)
{
	long ret;
	syscall_count[__NR_rt_sigtimedwait]++;
    	ret = orig_sys_rt_sigtimedwait(uthese, uinfo, uts, sigsetsize);
    	return ret;
}
asmlinkage long replace_sys_rt_sigqueueinfo(int pid, int sig, siginfo_t __user *uinfo)
{
	long ret;
	syscall_count[__NR_rt_sigqueueinfo]++;
    	ret = orig_sys_rt_sigqueueinfo(pid, sig, uinfo);
    	return ret;
}
asmlinkage long replace_sys_rt_sigsuspend(sigset_t __user *unewset, size_t sigsetsize)
{
	long ret;
	syscall_count[__NR_rt_sigsuspend]++;
    	ret = orig_sys_rt_sigsuspend(unewset, sigsetsize);
    	return ret;
}
asmlinkage long replace_sys_sigaltstack(const struct sigaltstack __user *uss,
                                struct sigaltstack __user *uoss)
{
	long ret;
	syscall_count[__NR_sigaltstack]++;
    	ret = orig_sys_sigaltstack(uss, uoss);
    	return ret;
}
asmlinkage long replace_sys_utime(char __user *filename,
                                struct utimbuf __user *times)
{
	long ret;
	syscall_count[__NR_utime]++;
    	ret = orig_sys_utime(filename, times);
    	return ret;
}
asmlinkage long replace_sys_mknod(const char __user *filename, umode_t mode,
                                unsigned dev)
{
	long ret;
	syscall_count[__NR_mknod]++;
    	ret = orig_sys_mknod(filename, mode, dev);
    	return ret;
}
asmlinkage long replace_sys_uselib(const char __user *library)
{
	long ret;
	syscall_count[__NR_uselib]++;
    	ret = orig_sys_uselib(library);
    	return ret;
}
asmlinkage long replace_sys_personality(unsigned int personality)
{
	long ret;
	syscall_count[__NR_personality]++;
    	ret = orig_sys_personality(personality);
    	return ret;
}
asmlinkage long replace_sys_ustat(unsigned dev, struct ustat __user *ubuf)
{
	long ret;
	syscall_count[__NR_ustat]++;
    	ret = orig_sys_ustat(dev, ubuf);
    	return ret;
}
asmlinkage long replace_sys_statfs(const char __user * path,
                                struct statfs __user *buf)
{
	long ret;
	syscall_count[__NR_statfs]++;
    	ret = orig_sys_statfs(path, buf);
    	return ret;
}
asmlinkage long replace_sys_fstatfs(unsigned int fd, struct statfs __user *buf)
{
	long ret;
	syscall_count[__NR_fstatfs]++;
    	ret = orig_sys_fstatfs(fd, buf);
    	return ret;
}
asmlinkage long replace_sys_sysfs(int option,
                                unsigned long arg1, unsigned long arg2)
{
	long ret;
	syscall_count[__NR_sysfs]++;
    	ret = orig_sys_sysfs(option, arg1, arg2);
    	return ret;
}
asmlinkage long replace_sys_getpriority(int which, int who)
{
	long ret;
	syscall_count[__NR_getpriority]++;
    	ret = orig_sys_getpriority(which, who);
    	return ret;
}
asmlinkage long replace_sys_setpriority(int which, int who, int niceval)
{
	long ret;
	syscall_count[__NR_setpriority]++;
    	ret = orig_sys_setpriority(which, who, niceval);
    	return ret;
}
asmlinkage long replace_sys_sched_setparam(pid_t pid,
                                        struct sched_param __user *param)
{
	long ret;
	syscall_count[__NR_sched_setparam]++;
    	ret = orig_sys_sched_setparam(pid, param);
    	return ret;
}
asmlinkage long replace_sys_sched_getparam(pid_t pid,
                                        struct sched_param __user *param)
{
	long ret;
	syscall_count[__NR_sched_getparam]++;
    	ret = orig_sys_sched_getparam(pid, param);
    	return ret;
}
asmlinkage long replace_sys_sched_setscheduler(pid_t pid, int policy,
                                        struct sched_param __user *param)
{
	long ret;
	syscall_count[__NR_sched_setscheduler]++;
    	ret = orig_sys_sched_setscheduler(pid, policy, param);
    	return ret;
}
asmlinkage long replace_sys_sched_getscheduler(pid_t pid)
{
	long ret;
	syscall_count[__NR_sched_getscheduler]++;
    	ret = orig_sys_sched_getscheduler(pid);
    	return ret;
}
asmlinkage long replace_sys_sched_get_priority_max(int policy)
{
	long ret;
	syscall_count[__NR_sched_get_priority_max]++;
    	ret = orig_sys_sched_get_priority_max(policy);
    	return ret;
}
asmlinkage long replace_sys_sched_get_priority_min(int policy)
{
	long ret;
	syscall_count[__NR_sched_get_priority_min]++;
    	ret = orig_sys_sched_get_priority_min(policy);
    	return ret;
}
asmlinkage long replace_sys_sched_rr_get_interval(pid_t pid,
                                        struct timespec __user *interval)
{
	long ret;
	syscall_count[__NR_sched_rr_get_interval]++;
    	ret = orig_sys_sched_rr_get_interval(pid, interval);
    	return ret;
}
asmlinkage long replace_sys_mlock(unsigned long start, size_t len)
{
	long ret;
	syscall_count[__NR_mlock]++;
    	ret = orig_sys_mlock(start, len);
    	return ret;
}
asmlinkage long replace_sys_munlock(unsigned long start, size_t len)
{
	long ret;
	syscall_count[__NR_munlock]++;
    	ret = orig_sys_munlock(start, len);
    	return ret;
}
asmlinkage long replace_sys_mlockall(int flags)
{
	long ret;
	syscall_count[__NR_mlockall]++;
    	ret = orig_sys_mlockall(flags);
    	return ret;
}
asmlinkage long replace_sys_munlockall(void)
{
	long ret;
	syscall_count[__NR_munlockall]++;
    	ret = orig_sys_munlockall();
    	return ret;
}
asmlinkage long replace_sys_vhangup(void)
{
	long ret;
	syscall_count[__NR_vhangup]++;
    	ret = orig_sys_vhangup();
    	return ret;
}

asmlinkage long replace_sys_pivot_root(const char __user *new_root,
                                const char __user *put_old)
{
	long ret;
	syscall_count[__NR_pivot_root]++;
    	ret = orig_sys_pivot_root(new_root, put_old);
    	return ret;
}
asmlinkage long replace_sys_sysctl(struct __sysctl_args __user *args)
{
	long ret;
	syscall_count[__NR__sysctl]++;
    	ret = orig_sys_sysctl(args);
    	return ret;
}
asmlinkage long replace_sys_prctl(int option, unsigned long arg2, unsigned long arg3,
                        unsigned long arg4, unsigned long arg5)
{
	long ret;
	syscall_count[__NR_prctl]++;
    	ret = orig_sys_prctl(option, arg2, arg3, arg4, arg5);
    	return ret;
}

asmlinkage long replace_sys_adjtimex(struct timex __user *txc_p)
{
	long ret;
	syscall_count[__NR_adjtimex]++;
    	ret = orig_sys_adjtimex(txc_p);
    	return ret;
}
asmlinkage long replace_sys_setrlimit(unsigned int resource,
                                struct rlimit __user *rlim)
{
	long ret;
	syscall_count[__NR_setrlimit]++;
    	ret = orig_sys_setrlimit(resource, rlim);
    	return ret;
}
asmlinkage long replace_sys_chroot(const char __user *filename)
{
	long ret;
	syscall_count[__NR_chroot]++;
    	ret = orig_sys_chroot(filename);
    	return ret;
}
asmlinkage long replace_sys_sync(void)
{
	long ret;
	syscall_count[__NR_sync]++;
    	ret = orig_sys_sync();
    	return ret;
}
asmlinkage long replace_sys_acct(const char __user *name)
{
	long ret;
	syscall_count[__NR_acct]++;
    	ret = orig_sys_acct(name);
    	return ret;
}
asmlinkage long replace_sys_settimeofday(struct timeval __user *tv,
                                struct timezone __user *tz)
{
	long ret;
	syscall_count[__NR_settimeofday]++;
    	ret = orig_sys_settimeofday(tv, tz);
    	return ret;
}
asmlinkage long replace_sys_mount(char __user *dev_name, char __user *dir_name,
                                char __user *type, unsigned long flags,
                                void __user *data)
{
	long ret;
	syscall_count[__NR_mount]++;
    	ret = orig_sys_mount(dev_name, dir_name, type, flags, data);
    	return ret;
}
asmlinkage long replace_sys_umount(char __user *name, int flags)
{
	long ret;
	syscall_count[__NR_umount2]++;
    	ret = orig_sys_umount(name, flags);
    	return ret;
}
asmlinkage long replace_sys_swapon(const char __user *specialfile, int swap_flags)
{
	long ret;
	syscall_count[__NR_swapon]++;
    	ret = orig_sys_swapon(specialfile, swap_flags);
    	return ret;
}
asmlinkage long replace_sys_swapoff(const char __user *specialfile)
{
	long ret;
	syscall_count[__NR_swapoff]++;
    	ret = orig_sys_swapoff(specialfile);
    	return ret;
}
asmlinkage long replace_sys_reboot(int magic1, int magic2, unsigned int cmd,
                                void __user *arg)
{
	long ret;
	syscall_count[__NR_reboot]++;
    	ret = orig_sys_reboot(magic1, magic2, cmd, arg);
    	return ret;
}
asmlinkage long replace_sys_sethostname(char __user *name, int len)
{
	long ret;
	syscall_count[__NR_sethostname]++;
    	ret = orig_sys_sethostname(name, len);
    	return ret;
}
asmlinkage long replace_sys_setdomainname(char __user *name, int len)
{
	long ret;
	syscall_count[__NR_setdomainname]++;
    	ret = orig_sys_setdomainname(name, len);
    	return ret;
}

asmlinkage long replace_sys_ioperm(unsigned long from, unsigned long num, int on)
{
	long ret;
	syscall_count[__NR_ioperm]++;
    	ret = orig_sys_ioperm(from, num, on);
    	return ret;
}

asmlinkage long replace_sys_init_module(void __user *umod, unsigned long len,
                                const char __user *uargs)
{
	long ret;
	syscall_count[__NR_init_module]++;
    	ret = orig_sys_init_module(umod, len, uargs);
    	return ret;
}
asmlinkage long replace_sys_delete_module(const char __user *name_user,
                                unsigned int flags)
{
	long ret;
	syscall_count[__NR_delete_module]++;
    	ret = orig_sys_delete_module(name_user, flags);
    	return ret;
}


asmlinkage long replace_sys_quotactl(unsigned int cmd, const char __user *special,
                                qid_t id, void __user *addr)
{
	long ret;
	syscall_count[__NR_quotactl]++;
    	ret = orig_sys_quotactl(cmd, special, id, addr);
    	return ret;
}






asmlinkage long replace_sys_gettid(void)
{
	long ret;
	syscall_count[__NR_gettid]++;
    	ret = orig_sys_gettid();
    	return ret;
}
asmlinkage long replace_sys_readahead(int fd, loff_t offset, size_t count)
{
	long ret;
	syscall_count[__NR_readahead]++;
    	ret = orig_sys_readahead(fd, offset, count);
    	return ret;
}
asmlinkage long replace_sys_setxattr(const char __user *path, const char __user *name,
                             const void __user *value, size_t size, int flags)
{
	long ret;
	syscall_count[__NR_setxattr]++;
    	ret = orig_sys_setxattr(path, name, value, size, flags);
    	return ret;
}
asmlinkage long replace_sys_lsetxattr(const char __user *path, const char __user *name,
                              const void __user *value, size_t size, int flags)
{
	long ret;
	syscall_count[__NR_lsetxattr]++;
    	ret = orig_sys_lsetxattr(path, name, value, size, flags);
    	return ret;
}
asmlinkage long replace_sys_fsetxattr(int fd, const char __user *name,
                              const void __user *value, size_t size, int flags)
{
	long ret;
	syscall_count[__NR_fsetxattr]++;
    	ret = orig_sys_fsetxattr(fd, name, value, size, flags);
    	return ret;
}
asmlinkage long replace_sys_getxattr(const char __user *path, const char __user *name,
                             void __user *value, size_t size)
{
	long ret;
	syscall_count[__NR_getxattr]++;
    	ret = orig_sys_getxattr(path, name, value, size);
    	return ret;
}
asmlinkage long replace_sys_lgetxattr(const char __user *path, const char __user *name,
                              void __user *value, size_t size)
{
	long ret;
	syscall_count[__NR_lgetxattr]++;
    	ret = orig_sys_lgetxattr(path, name, value, size);
    	return ret;
}
asmlinkage long replace_sys_fgetxattr(int fd, const char __user *name,
                              void __user *value, size_t size)
{
	long ret;
	syscall_count[__NR_fgetxattr]++;
    	ret = orig_sys_fgetxattr(fd, name, value, size);
    	return ret;
}
asmlinkage long replace_sys_listxattr(const char __user *path, char __user *list,
                              size_t size)
{
	long ret;
	syscall_count[__NR_listxattr]++;
    	ret = orig_sys_listxattr(path, list, size);
    	return ret;
}
asmlinkage long replace_sys_llistxattr(const char __user *path, char __user *list,
                               size_t size)
{
	long ret;
	syscall_count[__NR_llistxattr]++;
    	ret = orig_sys_llistxattr(path, list, size);
    	return ret;
}
asmlinkage long replace_sys_flistxattr(int fd, char __user *list, size_t size)
{
	long ret;
	syscall_count[__NR_flistxattr]++;
    	ret = orig_sys_flistxattr(fd, list, size);
    	return ret;
}
asmlinkage long replace_sys_removexattr(const char __user *path,
                                const char __user *name)
{
	long ret;
	syscall_count[__NR_removexattr]++;
    	ret = orig_sys_removexattr(path, name);
    	return ret;
}
asmlinkage long replace_sys_lremovexattr(const char __user *path,
                                 const char __user *name)
{
	long ret;
	syscall_count[__NR_lremovexattr]++;
    	ret = orig_sys_lremovexattr(path, name);
    	return ret;
}
asmlinkage long replace_sys_fremovexattr(int fd, const char __user *name)
{
	long ret;
	syscall_count[__NR_fremovexattr]++;
    	ret = orig_sys_fremovexattr(fd, name);
    	return ret;
}
asmlinkage long replace_sys_tkill(int pid, int sig)
{
	long ret;
	syscall_count[__NR_tkill]++;
    	ret = orig_sys_tkill(pid, sig);
    	return ret;
}
asmlinkage long replace_sys_time(time_t __user *tloc)
{
	long ret;
	syscall_count[__NR_time]++;
    	ret = orig_sys_time(tloc);
    	return ret;
}
asmlinkage long replace_sys_futex(u32 __user *uaddr, int op, u32 val,
                        struct timespec __user *utime, u32 __user *uaddr2,
                        u32 val3)
{
	long ret;
	syscall_count[__NR_futex]++;
    	ret = orig_sys_futex(uaddr, op, val, utime, uaddr2, val3);
    	return ret;
}
asmlinkage long replace_sys_sched_setaffinity(pid_t pid, unsigned int len,
                                        unsigned long __user *user_mask_ptr)
{
	long ret;
	syscall_count[__NR_sched_setaffinity]++;
    	ret = orig_sys_sched_setaffinity(pid, len, user_mask_ptr);
    	return ret;
}
asmlinkage long replace_sys_sched_getaffinity(pid_t pid, unsigned int len,
                                        unsigned long __user *user_mask_ptr)
{
	long ret;
	syscall_count[__NR_sched_getaffinity]++;
    	ret = orig_sys_sched_getaffinity(pid, len, user_mask_ptr);
    	return ret;
}
asmlinkage long replace_sys_io_setup(unsigned nr_reqs, aio_context_t __user *ctx)
{
	long ret;
	syscall_count[__NR_io_setup]++;
    	ret = orig_sys_io_setup(nr_reqs, ctx);
    	return ret;
}
asmlinkage long replace_sys_io_destroy(aio_context_t ctx)
{
	long ret;
	syscall_count[__NR_io_destroy]++;
    	ret = orig_sys_io_destroy(ctx);
    	return ret;
}
asmlinkage long replace_sys_io_getevents(aio_context_t ctx_id,
                                long min_nr,
                                long nr,
                                struct io_event __user *events,
                                struct timespec __user *timeout)
{
	long ret;
	syscall_count[__NR_io_getevents]++;
    	ret = orig_sys_io_getevents(ctx_id, min_nr, nr, events, timeout);
    	return ret;
}
asmlinkage long replace_sys_io_submit(aio_context_t arg1, long arg2,
                                struct iocb __user * __user *arg3)
{
	long ret;
	syscall_count[__NR_io_submit]++;
    	ret = orig_sys_io_submit(arg1, arg2, arg3);
    	return ret;
}
asmlinkage long replace_sys_io_cancel(aio_context_t ctx_id, struct iocb __user *iocb,
                              struct io_event __user *result){
	long ret;
	syscall_count[__NR_io_cancel]++;
    	ret = orig_sys_io_cancel(ctx_id, iocb, result);
    	return ret;
}

asmlinkage long replace_sys_lookup_dcookie(u64 cookie64, char __user *buf, size_t len)
{
	long ret;
	syscall_count[__NR_lookup_dcookie]++;
    	ret = orig_sys_lookup_dcookie(cookie64, buf, len);
    	return ret;
}
asmlinkage long replace_sys_epoll_create(int size)
{
	long ret;
	syscall_count[__NR_epoll_create]++;
    	ret = orig_sys_epoll_create(size);
    	return ret;
}
/*
asmlinkage long replace_sys_epoll_ctl_old(int epfd, int op, int fd,
                                struct epoll_event __user *event)
{
	long ret;
	syscall_count[__NR_epoll_ctl_old]++;
    	ret = orig_sys_epoll_ctl_old(epfd, op, fd, event);
    	return ret;
}
*/
/*
asmlinkage long replace_sys_epoll_wait_old(int epfd, struct epoll_event __user *events,
                                int maxevents, int timeout)
{
	long ret;
	syscall_count[__NR_epoll_wait_old]++;
    	ret = orig_sys_epoll_wait_old(epfd, events, maxevents, timeout);
    	return ret;
}
*/
asmlinkage long replace_sys_remap_file_pages(unsigned long start, unsigned long size,
                        unsigned long prot, unsigned long pgoff,
                        unsigned long flags)
{
	long ret;
	syscall_count[__NR_remap_file_pages]++;
    	ret = orig_sys_remap_file_pages(start, size, prot, pgoff, flags);
    	return ret;
}
asmlinkage long replace_sys_getdents64(unsigned int fd,
                                struct linux_dirent64 __user *dirent,
                                unsigned int count)
{
	long ret;
	syscall_count[__NR_getdents64]++;
    	ret = orig_sys_getdents64(fd, dirent, count);
    	return ret;
}
asmlinkage long replace_sys_set_tid_address(int __user *tidptr)
{
	long ret;
	syscall_count[__NR_set_tid_address]++;
    	ret = orig_sys_set_tid_address(tidptr);
    	return ret;
}
asmlinkage long replace_sys_restart_syscall(void)
{
	long ret;
	syscall_count[__NR_restart_syscall]++;
    	ret = orig_sys_restart_syscall();
    	return ret;
}
asmlinkage long replace_sys_semtimedop(int semid, struct sembuf __user *sops,
                                unsigned nsops,
                                const struct timespec __user *timeout)
{
	long ret;
	syscall_count[__NR_semtimedop]++;
    	ret = orig_sys_semtimedop(semid, sops, nsops, timeout);
    	return ret;
}
asmlinkage long replace_sys_fadvise64(int fd, loff_t offset, size_t len, int advice)
{
	long ret;
	syscall_count[__NR_fadvise64]++;
    	ret = orig_sys_fadvise64(fd, offset, len, advice);
    	return ret;
}
asmlinkage long replace_sys_timer_create(clockid_t which_clock,
                                 struct sigevent __user *timer_event_spec,
                                 timer_t __user * created_timer_id)
{
	long ret;
	syscall_count[__NR_timer_create]++;
    	ret = orig_sys_timer_create(which_clock, timer_event_spec, created_timer_id);
    	return ret;
}
asmlinkage long replace_sys_timer_settime(timer_t timer_id, int flags,
                                const struct itimerspec __user *new_setting,
                                struct itimerspec __user *old_setting)
{
	long ret;
	syscall_count[__NR_timer_settime]++;
    	ret = orig_sys_timer_settime(timer_id, flags, new_setting, old_setting);
    	return ret;
}
asmlinkage long replace_sys_timer_gettime(timer_t timer_id,
                                struct itimerspec __user *setting)
{
	long ret;
	syscall_count[__NR_timer_gettime]++;
    	ret = orig_sys_timer_gettime(timer_id, setting);
    	return ret;
}
asmlinkage long replace_sys_timer_getoverrun(timer_t timer_id)
{
	long ret;
	syscall_count[__NR_timer_getoverrun]++;
    	ret = orig_sys_timer_getoverrun(timer_id);
    	return ret;
}
asmlinkage long replace_sys_timer_delete(timer_t timer_id)
{
	long ret;
	syscall_count[__NR_timer_delete]++;
    	ret = orig_sys_timer_delete(timer_id);
    	return ret;
}
asmlinkage long replace_sys_clock_settime(clockid_t which_clock,
                                const struct timespec __user *tp)
{
	long ret;
	syscall_count[__NR_clock_settime]++;
    	ret = orig_sys_clock_settime(which_clock, tp);
    	return ret;
}
asmlinkage long replace_sys_clock_gettime(clockid_t which_clock,
                                struct timespec __user *tp)
{
	long ret;
	syscall_count[__NR_clock_gettime]++;
    	ret = orig_sys_clock_gettime(which_clock, tp);
    	return ret;
}
asmlinkage long replace_sys_clock_getres(clockid_t which_clock,
                                struct timespec __user *tp)
{
	long ret;
	syscall_count[__NR_clock_getres]++;
    	ret = orig_sys_clock_getres(which_clock, tp);
    	return ret;
}
asmlinkage long replace_sys_clock_nanosleep(clockid_t which_clock, int flags,
                                const struct timespec __user *rqtp,
                                struct timespec __user *rmtp)
{
	long ret;
	syscall_count[__NR_clock_nanosleep]++;
    	ret = orig_sys_clock_nanosleep(which_clock, flags, rqtp, rmtp);
    	return ret;
}
asmlinkage long replace_sys_exit_group(int error_code)
{
	long ret;
	syscall_count[__NR_exit_group]++;
    	ret = orig_sys_exit_group(error_code);
    	return ret;
}
asmlinkage long replace_sys_epoll_wait(int epfd, struct epoll_event __user *events,
                                int maxevents, int timeout)
{
	long ret;
	syscall_count[__NR_epoll_wait]++;
    	ret = orig_sys_epoll_wait(epfd, events, maxevents, timeout);
    	return ret;
}
asmlinkage long replace_sys_epoll_ctl(int epfd, int op, int fd,
                                struct epoll_event __user *event)
{
	long ret;
	syscall_count[__NR_epoll_ctl]++;
    	ret = orig_sys_epoll_ctl(epfd, op, fd, event);
    	return ret;
}
asmlinkage long replace_sys_tgkill(int tgid, int pid, int sig)
{
	long ret;
	syscall_count[__NR_tgkill]++;
    	ret = orig_sys_tgkill(tgid, pid, sig);
    	return ret;
}
asmlinkage long replace_sys_utimes(char __user *filename,
                                struct timeval __user *utimes)
{
	long ret;
	syscall_count[__NR_utimes]++;
    	ret = orig_sys_utimes(filename, utimes);
    	return ret;
}

asmlinkage long replace_sys_mbind(unsigned long start, unsigned long len,
                                unsigned long mode,
                                unsigned long __user *nmask,
                                unsigned long maxnode,
                                unsigned flags)
{
	long ret;
	syscall_count[__NR_mbind]++;
    	ret = orig_sys_mbind(start, len, mode, nmask, maxnode, flags);
    	return ret;
}
asmlinkage long replace_sys_set_mempolicy(int mode, unsigned long __user *nmask,
                                unsigned long maxnode)
{
	long ret;
	syscall_count[__NR_set_mempolicy]++;
    	ret = orig_sys_set_mempolicy(mode, nmask, maxnode);
    	return ret;
}
asmlinkage long replace_sys_get_mempolicy(int __user *policy,
                                unsigned long __user *nmask,
                                unsigned long maxnode,
                                unsigned long addr, unsigned long flags)
{
	long ret;
	syscall_count[__NR_get_mempolicy]++;
    	ret = orig_sys_get_mempolicy(policy, nmask, maxnode, addr, flags);
    	return ret;
}
asmlinkage long replace_sys_mq_open(const char __user *name, int oflag, umode_t mode, struct mq_attr __user *attr)
{
	long ret;
	syscall_count[__NR_mq_open]++;
    	ret = orig_sys_mq_open(name, oflag, mode, attr);
    	return ret;
}
asmlinkage long replace_sys_mq_unlink(const char __user *name)
{
	long ret;
	syscall_count[__NR_mq_unlink]++;
    	ret = orig_sys_mq_unlink(name);
    	return ret;
}
asmlinkage long replace_sys_mq_timedsend(mqd_t mqdes, const char __user *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct timespec __user *abs_timeout)
{
	long ret;
	syscall_count[__NR_mq_timedsend]++;
    	ret = orig_sys_mq_timedsend(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout);
    	return ret;
}
asmlinkage long replace_sys_mq_timedreceive(mqd_t mqdes, char __user *msg_ptr, size_t msg_len, unsigned int __user *msg_prio, const struct timespec __user *abs_timeout)
{
	long ret;
	syscall_count[__NR_mq_timedreceive]++;
    	ret = orig_sys_mq_timedreceive(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout);
    	return ret;
}
asmlinkage long replace_sys_mq_notify(mqd_t mqdes, const struct sigevent __user *notification)
{
	long ret;
	syscall_count[__NR_mq_notify]++;
    	ret = orig_sys_mq_notify(mqdes, notification);
    	return ret;
}
asmlinkage long replace_sys_mq_getsetattr(mqd_t mqdes, const struct mq_attr __user *mqstat, struct mq_attr __user *omqstat)
{
	long ret;
	syscall_count[__NR_mq_getsetattr]++;
    	ret = orig_sys_mq_getsetattr(mqdes, mqstat, omqstat);
    	return ret;
}
asmlinkage long replace_sys_kexec_load(unsigned long entry, unsigned long nr_segments,
                                struct kexec_segment __user *segments,
                                unsigned long flags)
{
	long ret;
	syscall_count[__NR_kexec_load]++;
    	ret = orig_sys_kexec_load(entry, nr_segments, segments, flags);
    	return ret;
}
asmlinkage long replace_sys_waitid(int which, pid_t pid,
                           struct siginfo __user *infop,
                           int options, struct rusage __user *ru)
{
	long ret;
	syscall_count[__NR_waitid]++;
    	ret = orig_sys_waitid(which, pid, infop, options, ru);
    	return ret;
}
asmlinkage long replace_sys_add_key(const char __user *_type,
                            const char __user *_description,
                            const void __user *_payload,
                            size_t plen,
                            key_serial_t destringid)
{
	long ret;
	syscall_count[__NR_add_key]++;
    	ret = orig_sys_add_key(_type, _description, _payload, plen, destringid);
    	return ret;
}
asmlinkage long replace_sys_request_key(const char __user *_type,
                                const char __user *_description,
                                const char __user *_callout_info,
                                key_serial_t destringid)
{
	long ret;
	syscall_count[__NR_request_key]++;
    	ret = orig_sys_request_key(_type, _description, _callout_info, destringid);
    	return ret;
}
asmlinkage long replace_sys_keyctl(int cmd, unsigned long arg2, unsigned long arg3,
                           unsigned long arg4, unsigned long arg5)
{
	long ret;
	syscall_count[__NR_keyctl]++;
    	ret = orig_sys_keyctl(cmd, arg2, arg3, arg4, arg5);
    	return ret;
}
asmlinkage long replace_sys_ioprio_set(int which, int who, int ioprio)
{
	long ret;
	syscall_count[__NR_ioprio_set]++;
    	ret = orig_sys_ioprio_set(which, who, ioprio);
    	return ret;
}
asmlinkage long replace_sys_ioprio_get(int which, int who)
{
	long ret;
	syscall_count[__NR_ioprio_get]++;
    	ret = orig_sys_ioprio_get(which, who);
    	return ret;
}
asmlinkage long replace_sys_inotify_init(void)
{
	long ret;
	syscall_count[__NR_inotify_init]++;
    	ret = orig_sys_inotify_init();
    	return ret;
}
asmlinkage long replace_sys_inotify_add_watch(int fd, const char __user *path,
                                        u32 mask)
{
	long ret;
	syscall_count[__NR_inotify_add_watch]++;
    	ret = orig_sys_inotify_add_watch(fd, path, mask);
    	return ret;
}
asmlinkage long replace_sys_inotify_rm_watch(int fd, __s32 wd)
{
	long ret;
	syscall_count[__NR_inotify_rm_watch]++;
    	ret = orig_sys_inotify_rm_watch(fd, wd);
    	return ret;
}
asmlinkage long replace_sys_migrate_pages(pid_t pid, unsigned long maxnode,
                                const unsigned long __user *from,
                                const unsigned long __user *to)
{
	long ret;
	syscall_count[__NR_migrate_pages]++;
    	ret = orig_sys_migrate_pages(pid, maxnode, from, to);
    	return ret;
}
asmlinkage long replace_sys_openat(int dfd, const char __user *filename, int flags,
                           umode_t mode)
{
	long ret;
	syscall_count[__NR_openat]++;
    	ret = orig_sys_openat(dfd, filename, flags, mode);
    	return ret;
}
asmlinkage long replace_sys_mkdirat(int dfd, const char __user * pathname, umode_t mode)
{
	long ret;
	syscall_count[__NR_mkdirat]++;
    	ret = orig_sys_mkdirat(dfd, pathname, mode);
    	return ret;
}
asmlinkage long replace_sys_fchownat(int dfd, const char __user *filename, uid_t user,
                             gid_t group, int flag)
{
	long ret;
	syscall_count[__NR_fchownat]++;
    	ret = orig_sys_fchownat(dfd, filename, user, group, flag);
    	return ret;
}
asmlinkage long replace_sys_futimesat(int dfd, const char __user *filename,
                              struct timeval __user *utimes)
{
	long ret;
	syscall_count[__NR_futimesat]++;
    	ret = orig_sys_futimesat(dfd, filename, utimes);
    	return ret;
}
asmlinkage long replace_sys_newfstatat(int dfd, const char __user *filename,
                               struct stat __user *statbuf, int flag)
{
	long ret;
	syscall_count[__NR_newfstatat]++;
    	ret = orig_sys_newfstatat(dfd, filename, statbuf, flag);
    	return ret;
}
asmlinkage long replace_sys_unlinkat(int dfd, const char __user * pathname, int flag)
{
	long ret;
	syscall_count[__NR_unlinkat]++;
    	ret = orig_sys_unlinkat(dfd, pathname, flag);
    	return ret;
}
asmlinkage long replace_sys_renameat(int olddfd, const char __user * oldname,
                             int newdfd, const char __user * newname)
{
	long ret;
	syscall_count[__NR_renameat]++;
    	ret = orig_sys_renameat(olddfd, oldname, newdfd, newname);
    	return ret;
}
asmlinkage long replace_sys_linkat(int olddfd, const char __user *oldname,
                           int newdfd, const char __user *newname, int flags)
{
	long ret;
	syscall_count[__NR_linkat]++;
    	ret = orig_sys_linkat(olddfd, oldname, newdfd, newname, flags);
    	return ret;
}
asmlinkage long replace_sys_symlinkat(const char __user * oldname,
                              int newdfd, const char __user * newname)
{
	long ret;
	syscall_count[__NR_symlinkat]++;
    	ret = orig_sys_symlinkat(oldname, newdfd, newname);
    	return ret;
}
asmlinkage long replace_sys_readlinkat(int dfd, const char __user *path, char __user *buf,
                               int bufsiz)
{
	long ret;
	syscall_count[__NR_readlinkat]++;
    	ret = orig_sys_readlinkat(dfd, path, buf, bufsiz);
    	return ret;
}
asmlinkage long replace_sys_fchmodat(int dfd, const char __user * filename,
                             umode_t mode)
{
	long ret;
	syscall_count[__NR_fchmodat]++;
    	ret = orig_sys_fchmodat(dfd, filename, mode);
    	return ret;
}
asmlinkage long replace_sys_faccessat(int dfd, const char __user *filename, int mode)
{
	long ret;
	syscall_count[__NR_faccessat]++;
    	ret = orig_sys_faccessat(dfd, filename, mode);
    	return ret;
}
asmlinkage long replace_sys_pselect(int arg1, fd_set __user *arg2, fd_set __user *arg3,
                             fd_set __user *arg4, struct timespec __user *arg5,
                             void __user *arg6)
{
	long ret;
	syscall_count[__NR_pselect6]++;
    	ret = orig_sys_pselect(arg1, arg2, arg3, arg4, arg5, arg6);
    	return ret;
}
asmlinkage long replace_sys_ppoll(struct pollfd __user *arg1, unsigned int arg2,
                          struct timespec __user *arg3, const sigset_t __user *arg4,
                          size_t arg5)
{
	long ret;
	syscall_count[__NR_ppoll]++;
    	ret = orig_sys_ppoll(arg1, arg2, arg3, arg4, arg5);
    	return ret;
}
asmlinkage long replace_sys_unshare(unsigned long unshare_flags)
{
	long ret;
	syscall_count[__NR_unshare]++;
    	ret = orig_sys_unshare(unshare_flags);
    	return ret;
}
asmlinkage long replace_sys_set_robust_list(struct robust_list_head __user *head,
                                    size_t len)
{
	long ret;
	syscall_count[__NR_set_robust_list]++;
    	ret = orig_sys_set_robust_list(head, len);
    	return ret;
}
asmlinkage long replace_sys_get_robust_list(int pid,
                                    struct robust_list_head __user * __user *head_ptr,
                                    size_t __user *len_ptr)
{
	long ret;
	syscall_count[__NR_get_robust_list]++;
    	ret = orig_sys_get_robust_list(pid, head_ptr, len_ptr);
    	return ret;
}
asmlinkage long replace_sys_splice(int fd_in, loff_t __user *off_in,
                           int fd_out, loff_t __user *off_out,
                           size_t len, unsigned int flags)
{
	long ret;
	syscall_count[__NR_splice]++;
    	ret = orig_sys_splice(fd_in, off_in, fd_out, off_out, len, flags);
    	return ret;
}
asmlinkage long replace_sys_tee(int fdin, int fdout, size_t len, unsigned int flags)
{
	long ret;
	syscall_count[__NR_tee]++;
    	ret = orig_sys_tee(fdin, fdout, len, flags);
    	return ret;
}
asmlinkage long replace_sys_sync_file_range(int fd, loff_t offset, loff_t nbytes,
                                        unsigned int flags)
{
	long ret;
	syscall_count[__NR_sync_file_range]++;
    	ret = orig_sys_sync_file_range(fd, offset, nbytes, flags);
    	return ret;
}
asmlinkage long replace_sys_vmsplice(int fd, const struct iovec __user *iov,
                             unsigned long nr_segs, unsigned int flags)
{
	long ret;
	syscall_count[__NR_vmsplice]++;
    	ret = orig_sys_vmsplice(fd, iov, nr_segs, flags);
    	return ret;
}
asmlinkage long replace_sys_move_pages(pid_t pid, unsigned long nr_pages,
                                const void __user * __user *pages,
                                const int __user *nodes,
                                int __user *status,
                                int flags)
{
	long ret;
	syscall_count[__NR_move_pages]++;
    	ret = orig_sys_move_pages(pid, nr_pages, pages, nodes, status, flags);
    	return ret;
}
asmlinkage long replace_sys_utimensat(int dfd, const char __user *filename,
                                struct timespec __user *utimes, int flags)
{
	long ret;
	syscall_count[__NR_utimensat]++;
    	ret = orig_sys_utimensat(dfd, filename, utimes, flags);
    	return ret;
}
asmlinkage long replace_sys_epoll_pwait(int epfd, struct epoll_event __user *events,
                                int maxevents, int timeout,
                                const sigset_t __user *sigmask,
                                size_t sigsetsize)
{
	long ret;
	syscall_count[__NR_epoll_pwait]++;
    	ret = orig_sys_epoll_pwait(epfd, events, maxevents, timeout, sigmask, sigsetsize);
    	return ret;
}
asmlinkage long replace_sys_signalfd(int ufd, sigset_t __user *user_mask, size_t sizemask)
{
	long ret;
	syscall_count[__NR_signalfd]++;
    	ret = orig_sys_signalfd(ufd, user_mask, sizemask);
    	return ret;
}
asmlinkage long replace_sys_timerfd_create(int clockid, int flags)
{
	long ret;
	syscall_count[__NR_timerfd_create]++;
    	ret = orig_sys_timerfd_create(clockid, flags);
    	return ret;
}
asmlinkage long replace_sys_eventfd(unsigned int count)
{
	long ret;
	syscall_count[__NR_eventfd]++;
    	ret = orig_sys_eventfd(count);
    	return ret;
}
asmlinkage long replace_sys_fallocate(int fd, int mode, loff_t offset, loff_t len)
{
	long ret;
	syscall_count[__NR_fallocate]++;
    	ret = orig_sys_fallocate(fd, mode, offset, len);
    	return ret;
}
asmlinkage long replace_sys_timerfd_settime(int ufd, int flags,
                                    const struct itimerspec __user *utmr,
                                    struct itimerspec __user *otmr)
{
	long ret;
	syscall_count[__NR_timerfd_settime]++;
    	ret = orig_sys_timerfd_settime(ufd, flags, utmr, otmr);
    	return ret;
}
asmlinkage long replace_sys_timerfd_gettime(int ufd, struct itimerspec __user *otmr)
{
	long ret;
	syscall_count[__NR_timerfd_gettime]++;
    	ret = orig_sys_timerfd_gettime(ufd, otmr);
    	return ret;
}
asmlinkage long replace_sys_accept4(int arg1, struct sockaddr __user *arg2, int __user *arg3, int arg4)
{
	long ret;
	syscall_count[__NR_accept4]++;
    	ret = orig_sys_accept4(arg1, arg2, arg3, arg4);
    	return ret;
}
asmlinkage long replace_sys_signalfd4(int ufd, sigset_t __user *user_mask, size_t sizemask, int flags)
{
	long ret;
	syscall_count[__NR_signalfd4]++;
    	ret = orig_sys_signalfd4(ufd, user_mask, sizemask, flags);
    	return ret;
}
asmlinkage long replace_sys_eventfd2(unsigned int count, int flags)
{
	long ret;
	syscall_count[__NR_eventfd2]++;
    	ret = orig_sys_eventfd2(count, flags);
    	return ret;
}
asmlinkage long replace_sys_epoll_create1(int flags)
{
	long ret;
	syscall_count[__NR_epoll_create1]++;
    	ret = orig_sys_epoll_create1(flags);
    	return ret;
}
asmlinkage long replace_sys_dup3(unsigned int oldfd, unsigned int newfd, int flags)
{
	long ret;
	syscall_count[__NR_dup3]++;
    	ret = orig_sys_dup3(oldfd, newfd, flags);
    	return ret;
}
asmlinkage long replace_sys_pipe2(int __user *fildes, int flags)
{
	long ret;
	syscall_count[__NR_pipe2]++;
    	ret = orig_sys_pipe2(fildes, flags);
    	return ret;
}
asmlinkage long replace_sys_inotify_init1(int flags)
{
	long ret;
	syscall_count[__NR_inotify_init1]++;
    	ret = orig_sys_inotify_init1(flags);
    	return ret;
}
asmlinkage long replace_sys_preadv(unsigned long fd, const struct iovec __user *vec,
                           unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
{
	long ret;
	syscall_count[__NR_preadv]++;
    	ret = orig_sys_preadv(fd, vec, vlen, pos_l, pos_h);
    	return ret;
}
asmlinkage long replace_sys_pwritev(unsigned long fd, const struct iovec __user *vec,
                            unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
{
	long ret;
	syscall_count[__NR_pwritev]++;
    	ret = orig_sys_pwritev(fd, vec, vlen, pos_l, pos_h);
    	return ret;
}
asmlinkage long replace_sys_rt_tgsigqueueinfo(pid_t tgid, pid_t pid, int sig,
                siginfo_t __user *uinfo)
{
	long ret;
	syscall_count[__NR_rt_tgsigqueueinfo]++;
    	ret = orig_sys_rt_tgsigqueueinfo(tgid, pid, sig, uinfo);
    	return ret;
}
asmlinkage long replace_sys_perf_event_open(
                struct perf_event_attr __user *attr_uptr,
                pid_t pid, int cpu, int group_fd, unsigned long flags)
{
	long ret;
	syscall_count[__NR_perf_event_open]++;
    	ret = orig_sys_perf_event_open(attr_uptr, pid, cpu, group_fd, flags);
    	return ret;
}
asmlinkage long replace_sys_recvmmsg(int fd, struct mmsghdr __user *msg,
                             unsigned int vlen, unsigned flags,
                             struct timespec __user *timeout)
{
	long ret;
	syscall_count[__NR_recvmmsg]++;
    	ret = orig_sys_recvmmsg(fd, msg, vlen, flags, timeout);
    	return ret;
}
asmlinkage long replace_sys_fanotify_init(unsigned int flags, unsigned int event_f_flags)
{
	long ret;
	syscall_count[__NR_fanotify_init]++;
    	ret = orig_sys_fanotify_init(flags, event_f_flags);
    	return ret;
}
asmlinkage long replace_sys_fanotify_mark(int fanotify_fd, unsigned int flags,
                                  u64 mask, int fd,
                                  const char  __user *pathname)
{
	long ret;
	syscall_count[__NR_fanotify_mark]++;
    	ret = orig_sys_fanotify_mark(fanotify_fd, flags, mask, fd, pathname);
    	return ret;
}
asmlinkage long replace_sys_prlimit64(pid_t pid, unsigned int resource,
                                const struct rlimit64 __user *new_rlim,
                                struct rlimit64 __user *old_rlim)
{
	long ret;
	syscall_count[__NR_prlimit64]++;
    	ret = orig_sys_prlimit64(pid, resource, new_rlim, old_rlim);
    	return ret;
}
asmlinkage long replace_sys_name_to_handle_at(int dfd, const char __user *name,
                                      struct file_handle __user *handle,
                                      int __user *mnt_id, int flag)
{
	long ret;
	syscall_count[__NR_name_to_handle_at]++;
    	ret = orig_sys_name_to_handle_at(dfd, name, handle, mnt_id, flag);
    	return ret;
}
asmlinkage long replace_sys_open_by_handle_at(int mountdirfd,
                                      struct file_handle __user *handle,
                                      int flags)
{
	long ret;
	syscall_count[__NR_open_by_handle_at]++;
    	ret = orig_sys_open_by_handle_at(mountdirfd, handle, flags);
    	return ret;
}
asmlinkage long replace_sys_clock_adjtime(clockid_t which_clock,
                                struct timex __user *tx)
{
	long ret;
	syscall_count[__NR_clock_adjtime]++;
    	ret = orig_sys_clock_adjtime(which_clock, tx);
    	return ret;
}
asmlinkage long replace_sys_syncfs(int fd)
{
	long ret;
	syscall_count[__NR_syncfs]++;
    	ret = orig_sys_syncfs(fd);
    	return ret;
}
asmlinkage long replace_sys_sendmmsg(int fd, struct mmsghdr __user *msg,
                             unsigned int vlen, unsigned flags)
{
	long ret;
	syscall_count[__NR_sendmmsg]++;
    	ret = orig_sys_sendmmsg(fd, msg, vlen, flags);
    	return ret;
}
asmlinkage long replace_sys_setns(int fd, int nstype)
{
	long ret;
	syscall_count[__NR_setns]++;
    	ret = orig_sys_setns(fd, nstype);
    	return ret;
}
asmlinkage long replace_sys_getcpu(unsigned __user *cpu, unsigned __user *node, struct getcpu_cache __user *cache)
{
	long ret;
	syscall_count[__NR_getcpu]++;
    	ret = orig_sys_getcpu(cpu, node, cache);
    	return ret;
}
asmlinkage long replace_sys_process_vm_readv(pid_t pid,
                                     const struct iovec __user *lvec,
                                     unsigned long liovcnt,
                                     const struct iovec __user *rvec,
                                     unsigned long riovcnt,
                                     unsigned long flags)
{
	long ret;
	syscall_count[__NR_process_vm_readv]++;
    	ret = orig_sys_process_vm_readv(pid, lvec, liovcnt, rvec, riovcnt, flags);
    	return ret;
}
asmlinkage long replace_sys_process_vm_writev(pid_t pid,
                                      const struct iovec __user *lvec,
                                      unsigned long liovcnt,
                                      const struct iovec __user *rvec,
                                      unsigned long riovcnt,
                                      unsigned long flags)
{
	long ret;
	syscall_count[__NR_process_vm_writev]++;
    	ret = orig_sys_process_vm_writev(pid, lvec, liovcnt, rvec, riovcnt, flags);
    	return ret;
}

asmlinkage long replace_sys_kcmp(pid_t pid1, pid_t pid2, int type,
                         unsigned long idx1, unsigned long idx2)
{
	long ret;
	syscall_count[__NR_kcmp]++;
    	ret = orig_sys_kcmp(pid1, pid2, type, idx1, idx2);
    	return ret;
}
asmlinkage long replace_sys_finit_module(int fd, const char __user *uargs, int flags)
{
	long ret;
	syscall_count[__NR_finit_module]++;
    	ret = orig_sys_finit_module(fd, uargs, flags);
    	return ret;
}












static void save_original_syscall_address(void)
{
	orig_sys_read = syscall_table[__NR_read];
	orig_sys_write = syscall_table[__NR_write];
	orig_sys_open = syscall_table[__NR_open];
	orig_sys_close = syscall_table[__NR_close];
	orig_sys_stat = syscall_table[__NR_stat];
	orig_sys_fstat = syscall_table[__NR_fstat];
	orig_sys_lstat = syscall_table[__NR_lstat];
	orig_sys_poll = syscall_table[__NR_poll];
	orig_sys_lseek = syscall_table[__NR_lseek];
	orig_sys_mmap = syscall_table[__NR_mmap];
	orig_sys_mprotect = syscall_table[__NR_mprotect];
	orig_sys_munmap = syscall_table[__NR_munmap];
	orig_sys_brk = syscall_table[__NR_brk];
	orig_sys_rt_sigaction = syscall_table[__NR_rt_sigaction];
	orig_sys_rt_sigprocmask = syscall_table[__NR_rt_sigprocmask];
	//orig_sys_rt_sigreturn = syscall_table[__NR_rt_sigreturn];
	orig_sys_ioctl = syscall_table[__NR_ioctl];
	orig_sys_pread64 = syscall_table[__NR_pread64];
	orig_sys_pwrite64 = syscall_table[__NR_pwrite64];
	orig_sys_readv = syscall_table[__NR_readv];
	orig_sys_writev = syscall_table[__NR_writev];
	orig_sys_access = syscall_table[__NR_access];
	orig_sys_pipe = syscall_table[__NR_pipe];
	orig_sys_select = syscall_table[__NR_select];
	orig_sys_sched_yield = syscall_table[__NR_sched_yield];
	orig_sys_mremap = syscall_table[__NR_mremap];
	orig_sys_msync = syscall_table[__NR_msync];
	orig_sys_mincore = syscall_table[__NR_mincore];
	orig_sys_madvise = syscall_table[__NR_madvise];
	orig_sys_shmget = syscall_table[__NR_shmget];
	orig_sys_shmat = syscall_table[__NR_shmat];
	orig_sys_shmctl = syscall_table[__NR_shmctl];
	orig_sys_dup = syscall_table[__NR_dup];
	orig_sys_dup2 = syscall_table[__NR_dup2];
	orig_sys_pause = syscall_table[__NR_pause];
	orig_sys_nanosleep = syscall_table[__NR_nanosleep];
	orig_sys_getitimer = syscall_table[__NR_getitimer];
	orig_sys_alarm = syscall_table[__NR_alarm];
	orig_sys_setitimer = syscall_table[__NR_setitimer];
	orig_sys_getpid = syscall_table[__NR_getpid];
	orig_sys_sendfile = syscall_table[__NR_sendfile];
	orig_sys_socket = syscall_table[__NR_socket];
	orig_sys_connect = syscall_table[__NR_connect];
	orig_sys_accept = syscall_table[__NR_accept];
	orig_sys_sendto = syscall_table[__NR_sendto];
	orig_sys_recvfrom = syscall_table[__NR_recvfrom];
	orig_sys_sendmsg = syscall_table[__NR_sendmsg];
	orig_sys_recvmsg = syscall_table[__NR_recvmsg];
	orig_sys_shutdown = syscall_table[__NR_shutdown];
	orig_sys_bind = syscall_table[__NR_bind];
	orig_sys_listen = syscall_table[__NR_listen];
	orig_sys_getsockname = syscall_table[__NR_getsockname];
	orig_sys_getpeername = syscall_table[__NR_getpeername];
	orig_sys_socketpair = syscall_table[__NR_socketpair];
	orig_sys_setsockopt = syscall_table[__NR_setsockopt];
	orig_sys_getsockopt = syscall_table[__NR_getsockopt];

	//orig_sys_clone = syscall_table[__NR_clone];
	//orig_sys_fork = syscall_table[__NR_fork];
	//orig_sys_vfork = syscall_table[__NR_vfork];
	//orig_sys_execve = syscall_table[__NR_execve];

	orig_sys_exit = syscall_table[__NR_exit];
	orig_sys_wait4 = syscall_table[__NR_wait4];
	orig_sys_kill = syscall_table[__NR_kill];
	orig_sys_uname = syscall_table[__NR_uname];

	orig_sys_semget = syscall_table[__NR_semget];
	orig_sys_semop = syscall_table[__NR_semop];
	orig_sys_semctl = syscall_table[__NR_semctl];
	orig_sys_shmdt = syscall_table[__NR_shmdt];
	orig_sys_msgget = syscall_table[__NR_msgget];
	orig_sys_msgsnd = syscall_table[__NR_msgsnd];
	orig_sys_msgrcv = syscall_table[__NR_msgrcv];
	orig_sys_msgctl = syscall_table[__NR_msgctl];
	orig_sys_fcntl = syscall_table[__NR_fcntl];
	orig_sys_flock = syscall_table[__NR_flock];
	orig_sys_fsync = syscall_table[__NR_fsync];
	orig_sys_fdatasync = syscall_table[__NR_fdatasync];
	orig_sys_truncate = syscall_table[__NR_truncate];
	orig_sys_ftruncate = syscall_table[__NR_ftruncate];
	orig_sys_getdents = syscall_table[__NR_getdents];
	orig_sys_getcwd = syscall_table[__NR_getcwd];
	orig_sys_chdir = syscall_table[__NR_chdir];
	orig_sys_fchdir = syscall_table[__NR_fchdir];
	orig_sys_rename = syscall_table[__NR_rename];
	orig_sys_mkdir = syscall_table[__NR_mkdir];
	orig_sys_rmdir = syscall_table[__NR_rmdir];
	orig_sys_creat = syscall_table[__NR_creat];
	orig_sys_link = syscall_table[__NR_link];
	orig_sys_unlink = syscall_table[__NR_unlink];
	orig_sys_symlink = syscall_table[__NR_symlink];
	orig_sys_readlink = syscall_table[__NR_readlink];
	orig_sys_chmod = syscall_table[__NR_chmod];
	orig_sys_fchmod = syscall_table[__NR_fchmod];
	orig_sys_chown = syscall_table[__NR_chown];
	orig_sys_fchown = syscall_table[__NR_fchown];
	orig_sys_lchown = syscall_table[__NR_lchown];
	orig_sys_umask = syscall_table[__NR_umask];
	orig_sys_gettimeofday = syscall_table[__NR_gettimeofday];
	orig_sys_getrlimit = syscall_table[__NR_getrlimit];
	orig_sys_getrusage = syscall_table[__NR_getrusage];
	orig_sys_sysinfo = syscall_table[__NR_sysinfo];
	orig_sys_times = syscall_table[__NR_times];
	orig_sys_ptrace = syscall_table[__NR_ptrace];
	orig_sys_getuid = syscall_table[__NR_getuid];
	orig_sys_syslog = syscall_table[__NR_syslog];
	orig_sys_getgid = syscall_table[__NR_getgid];
	orig_sys_setuid = syscall_table[__NR_setuid];
	orig_sys_setgid = syscall_table[__NR_setgid];
	orig_sys_geteuid = syscall_table[__NR_geteuid];
	orig_sys_getegid = syscall_table[__NR_getegid];
	orig_sys_setpgid = syscall_table[__NR_setpgid];
	orig_sys_getppid = syscall_table[__NR_getppid];
	orig_sys_getpgrp = syscall_table[__NR_getpgrp];
	orig_sys_setsid = syscall_table[__NR_setsid];
	orig_sys_setreuid = syscall_table[__NR_setreuid];
	orig_sys_setregid = syscall_table[__NR_setregid];
	orig_sys_getgroups = syscall_table[__NR_getgroups];
	orig_sys_setgroups = syscall_table[__NR_setgroups];
	orig_sys_setresuid = syscall_table[__NR_setresuid];
	orig_sys_getresuid = syscall_table[__NR_getresuid];
	orig_sys_setresgid = syscall_table[__NR_setresgid];
	orig_sys_getresgid = syscall_table[__NR_getresgid];
	orig_sys_getpgid = syscall_table[__NR_getpgid];
	orig_sys_setfsuid = syscall_table[__NR_setfsuid];
	orig_sys_setfsgid = syscall_table[__NR_setfsgid];
	orig_sys_getsid = syscall_table[__NR_getsid];
	orig_sys_capget = syscall_table[__NR_capget];
	orig_sys_capset = syscall_table[__NR_capset];
	orig_sys_rt_sigpending = syscall_table[__NR_rt_sigpending];
	orig_sys_rt_sigtimedwait = syscall_table[__NR_rt_sigtimedwait];
	orig_sys_rt_sigqueueinfo = syscall_table[__NR_rt_sigqueueinfo];
	orig_sys_rt_sigsuspend = syscall_table[__NR_rt_sigsuspend];
	orig_sys_sigaltstack = syscall_table[__NR_sigaltstack];
	orig_sys_utime = syscall_table[__NR_utime];
	orig_sys_mknod = syscall_table[__NR_mknod];
	orig_sys_uselib = syscall_table[__NR_uselib];
	orig_sys_personality = syscall_table[__NR_personality];
	orig_sys_ustat = syscall_table[__NR_ustat];
	orig_sys_statfs = syscall_table[__NR_statfs];
	orig_sys_fstatfs = syscall_table[__NR_fstatfs];
	orig_sys_sysfs = syscall_table[__NR_sysfs];
	orig_sys_getpriority = syscall_table[__NR_getpriority];
	orig_sys_setpriority = syscall_table[__NR_setpriority];
	orig_sys_sched_setparam = syscall_table[__NR_sched_setparam];
	orig_sys_sched_getparam = syscall_table[__NR_sched_getparam];
	orig_sys_sched_setscheduler = syscall_table[__NR_sched_setscheduler];
	orig_sys_sched_getscheduler = syscall_table[__NR_sched_getscheduler];
	orig_sys_sched_get_priority_max = syscall_table[__NR_sched_get_priority_max];
	orig_sys_sched_get_priority_min = syscall_table[__NR_sched_get_priority_min];
	orig_sys_sched_rr_get_interval = syscall_table[__NR_sched_rr_get_interval];
	orig_sys_mlock = syscall_table[__NR_mlock];
	orig_sys_munlock = syscall_table[__NR_munlock];
	orig_sys_mlockall = syscall_table[__NR_mlockall];
	orig_sys_munlockall = syscall_table[__NR_munlockall];
	orig_sys_vhangup = syscall_table[__NR_vhangup];
	//orig_sys_modifyldt = syscall_table[__NR_modifyldt];
	orig_sys_pivot_root = syscall_table[__NR_pivot_root];
	orig_sys_sysctl = syscall_table[__NR__sysctl];
	orig_sys_prctl = syscall_table[__NR_prctl];
	//orig_sys_archprctl = syscall_table[__NR_archprctl];
	orig_sys_adjtimex = syscall_table[__NR_adjtimex];
	orig_sys_setrlimit = syscall_table[__NR_setrlimit];

	orig_sys_chroot = syscall_table[__NR_chroot];
	orig_sys_sync = syscall_table[__NR_sync];
	orig_sys_acct = syscall_table[__NR_acct];
	orig_sys_settimeofday = syscall_table[__NR_settimeofday];
	orig_sys_mount = syscall_table[__NR_mount];
	orig_sys_umount = syscall_table[__NR_umount2];
	orig_sys_swapon = syscall_table[__NR_swapon];
	orig_sys_swapoff = syscall_table[__NR_swapoff];
	orig_sys_reboot = syscall_table[__NR_reboot];
	orig_sys_sethostname = syscall_table[__NR_sethostname];
	orig_sys_setdomainname = syscall_table[__NR_setdomainname];
	//orig_sys_iopl = syscall_table[__NR_iopl];
	orig_sys_ioperm = syscall_table[__NR_ioperm];
	//orig_sys_create_module = syscall_table[__NR_create_module];
	orig_sys_init_module = syscall_table[__NR_init_module];
	orig_sys_delete_module = syscall_table[__NR_delete_module];
	//orig_sys_get_kernel_syms = syscall_table[__NR_get_kernel_syms];
	//orig_sys_query_module = syscall_table[__NR_query_module];
	orig_sys_quotactl = syscall_table[__NR_quotactl];
	//orig_sys_nfsservctl = syscall_table[__NR_nfsservctl];
	//orig_sys_getpmsg = syscall_table[__NR_getpmsg];
	//orig_sys_putpmsg = syscall_table[__NR_putpmsg];
	//orig_sys_afs_syscall = syscall_table[__NR_afs_syscall];
	//orig_sys_tuxcall = syscall_table[__NR_tuxcall];
	//orig_sys_security = syscall_table[__NR_security];
	orig_sys_gettid = syscall_table[__NR_gettid];
	orig_sys_readahead = syscall_table[__NR_readahead];
	orig_sys_setxattr = syscall_table[__NR_setxattr];
	orig_sys_lsetxattr = syscall_table[__NR_lsetxattr];
	orig_sys_fsetxattr = syscall_table[__NR_fsetxattr];
	orig_sys_getxattr = syscall_table[__NR_getxattr];
	orig_sys_lgetxattr = syscall_table[__NR_lgetxattr];
	orig_sys_fgetxattr = syscall_table[__NR_fgetxattr];
	orig_sys_listxattr = syscall_table[__NR_listxattr];
	orig_sys_llistxattr = syscall_table[__NR_llistxattr];
	orig_sys_flistxattr = syscall_table[__NR_flistxattr];
	orig_sys_removexattr = syscall_table[__NR_removexattr];
	orig_sys_lremovexattr = syscall_table[__NR_lremovexattr];
	orig_sys_fremovexattr = syscall_table[__NR_fremovexattr];
	orig_sys_tkill = syscall_table[__NR_tkill];
	orig_sys_time = syscall_table[__NR_time];
	orig_sys_futex = syscall_table[__NR_futex];
	orig_sys_sched_setaffinity = syscall_table[__NR_sched_setaffinity];
	orig_sys_sched_getaffinity = syscall_table[__NR_sched_getaffinity];
	//orig_sys_set_thread_area = syscall_table[__NR_set_thread_area];
	orig_sys_io_setup = syscall_table[__NR_io_setup];
	orig_sys_io_destroy = syscall_table[__NR_io_destroy];
	orig_sys_io_getevents = syscall_table[__NR_io_getevents];
	orig_sys_io_submit = syscall_table[__NR_io_submit];
	orig_sys_io_cancel = syscall_table[__NR_io_cancel];
	//orig_sys_get_thread_area = syscall_table[__NR_get_thread_area];
	orig_sys_lookup_dcookie = syscall_table[__NR_lookup_dcookie];
	orig_sys_epoll_create = syscall_table[__NR_epoll_create];
	//orig_sys_epoll_ctl_old = syscall_table[__NR_epoll_ctl_old];
	//orig_sys_epoll_wait_old = syscall_table[__NR_epoll_wait_old];
	orig_sys_remap_file_pages = syscall_table[__NR_remap_file_pages];
	orig_sys_getdents64 = syscall_table[__NR_getdents64];
	orig_sys_set_tid_address = syscall_table[__NR_set_tid_address];
	orig_sys_restart_syscall = syscall_table[__NR_restart_syscall];
	orig_sys_semtimedop = syscall_table[__NR_semtimedop];
	orig_sys_fadvise64 = syscall_table[__NR_fadvise64];
	orig_sys_timer_create = syscall_table[__NR_timer_create];
	orig_sys_timer_settime = syscall_table[__NR_timer_settime];
	orig_sys_timer_gettime = syscall_table[__NR_timer_gettime];
	orig_sys_timer_getoverrun = syscall_table[__NR_timer_getoverrun];
	orig_sys_timer_delete = syscall_table[__NR_timer_delete];
	orig_sys_clock_settime = syscall_table[__NR_clock_settime];
	orig_sys_clock_gettime = syscall_table[__NR_clock_gettime];
	orig_sys_clock_getres = syscall_table[__NR_clock_getres];
	orig_sys_clock_nanosleep = syscall_table[__NR_clock_nanosleep];
	orig_sys_exit_group = syscall_table[__NR_exit_group];
	orig_sys_epoll_wait = syscall_table[__NR_epoll_wait];
	orig_sys_epoll_ctl = syscall_table[__NR_epoll_ctl];
	orig_sys_tgkill = syscall_table[__NR_tgkill];
	orig_sys_utimes = syscall_table[__NR_utimes];
	//orig_sys_vserver = syscall_table[__NR_vserver];
	orig_sys_mbind = syscall_table[__NR_mbind];
	orig_sys_set_mempolicy = syscall_table[__NR_set_mempolicy];
	orig_sys_get_mempolicy = syscall_table[__NR_get_mempolicy];
	orig_sys_mq_open = syscall_table[__NR_mq_open];
	orig_sys_mq_unlink = syscall_table[__NR_mq_unlink];
	orig_sys_mq_timedsend = syscall_table[__NR_mq_timedsend];
	orig_sys_mq_timedreceive = syscall_table[__NR_mq_timedreceive];
	orig_sys_mq_notify = syscall_table[__NR_mq_notify];
	orig_sys_mq_getsetattr = syscall_table[__NR_mq_getsetattr];
	orig_sys_kexec_load = syscall_table[__NR_kexec_load];
	orig_sys_waitid = syscall_table[__NR_waitid];
	orig_sys_add_key = syscall_table[__NR_add_key];
	orig_sys_request_key = syscall_table[__NR_request_key];
	orig_sys_keyctl = syscall_table[__NR_keyctl];
	orig_sys_ioprio_set = syscall_table[__NR_ioprio_set];
	orig_sys_ioprio_get = syscall_table[__NR_ioprio_get];
	orig_sys_inotify_init = syscall_table[__NR_inotify_init];
	orig_sys_inotify_add_watch = syscall_table[__NR_inotify_add_watch];
	orig_sys_inotify_rm_watch = syscall_table[__NR_inotify_rm_watch];
	orig_sys_migrate_pages = syscall_table[__NR_migrate_pages];
	orig_sys_openat = syscall_table[__NR_openat];
	orig_sys_mkdirat = syscall_table[__NR_mkdirat];
	//orig_sys_mknodat = syscall_table[__NR_mknodat];
	orig_sys_fchownat = syscall_table[__NR_fchownat];
	orig_sys_futimesat = syscall_table[__NR_futimesat];
	orig_sys_newfstatat = syscall_table[__NR_newfstatat];
	orig_sys_unlinkat = syscall_table[__NR_unlinkat];
	orig_sys_renameat = syscall_table[__NR_renameat];
	orig_sys_linkat = syscall_table[__NR_linkat];
	orig_sys_symlinkat = syscall_table[__NR_symlinkat];
	orig_sys_readlinkat = syscall_table[__NR_readlinkat];
	orig_sys_fchmodat = syscall_table[__NR_fchmodat];
	orig_sys_faccessat = syscall_table[__NR_faccessat];
	orig_sys_pselect = syscall_table[__NR_pselect6];
	orig_sys_ppoll = syscall_table[__NR_ppoll];
	orig_sys_unshare = syscall_table[__NR_unshare];
	orig_sys_set_robust_list = syscall_table[__NR_set_robust_list];
	orig_sys_get_robust_list = syscall_table[__NR_get_robust_list];
	orig_sys_splice = syscall_table[__NR_splice];
	orig_sys_tee = syscall_table[__NR_tee];
	orig_sys_sync_file_range = syscall_table[__NR_sync_file_range];
	orig_sys_vmsplice = syscall_table[__NR_vmsplice];
	orig_sys_move_pages = syscall_table[__NR_move_pages];
	orig_sys_utimensat = syscall_table[__NR_utimensat];
	orig_sys_epoll_pwait = syscall_table[__NR_epoll_pwait];
	orig_sys_signalfd = syscall_table[__NR_signalfd];
	orig_sys_timerfd_create = syscall_table[__NR_timerfd_create];
	orig_sys_eventfd = syscall_table[__NR_eventfd];
	orig_sys_fallocate = syscall_table[__NR_fallocate];
	orig_sys_timerfd_settime = syscall_table[__NR_timerfd_settime];
	orig_sys_timerfd_gettime = syscall_table[__NR_timerfd_gettime];
	orig_sys_accept4 = syscall_table[__NR_accept4];
	orig_sys_signalfd4 = syscall_table[__NR_signalfd4];
	orig_sys_eventfd2 = syscall_table[__NR_eventfd2];
	orig_sys_epoll_create1 = syscall_table[__NR_epoll_create1];
	orig_sys_dup3 = syscall_table[__NR_dup3];
	orig_sys_pipe2 = syscall_table[__NR_pipe2];
	orig_sys_inotify_init1 = syscall_table[__NR_inotify_init1];
	orig_sys_preadv = syscall_table[__NR_preadv];
	orig_sys_pwritev = syscall_table[__NR_pwritev];
	orig_sys_rt_tgsigqueueinfo = syscall_table[__NR_rt_tgsigqueueinfo];
	orig_sys_perf_event_open = syscall_table[__NR_perf_event_open];
	orig_sys_recvmmsg = syscall_table[__NR_recvmmsg];
	orig_sys_fanotify_init = syscall_table[__NR_fanotify_init];
	orig_sys_fanotify_mark = syscall_table[__NR_fanotify_mark];
	orig_sys_prlimit64 = syscall_table[__NR_prlimit64];
	orig_sys_name_to_handle_at = syscall_table[__NR_name_to_handle_at];
	orig_sys_open_by_handle_at = syscall_table[__NR_open_by_handle_at];
	orig_sys_clock_adjtime = syscall_table[__NR_clock_adjtime];
	orig_sys_syncfs = syscall_table[__NR_syncfs];
	orig_sys_sendmmsg = syscall_table[__NR_sendmmsg];
	orig_sys_setns = syscall_table[__NR_setns];
	orig_sys_getcpu = syscall_table[__NR_getcpu];
	orig_sys_process_vm_readv = syscall_table[__NR_process_vm_readv];
	orig_sys_process_vm_writev = syscall_table[__NR_process_vm_writev];
	orig_sys_kcmp = syscall_table[__NR_kcmp];
	orig_sys_finit_module = syscall_table[__NR_finit_module];
}

static void change_page_attr_to_rw(pte_t *pte)
{
    set_pte_atomic(pte, pte_mkwrite(*pte));
}

static void change_page_attr_to_ro(pte_t *pte)
{
    set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));
}

static void replace_system_call(void *new, unsigned int syscall_number)
{
   	unsigned int level = 0;
    	pte_t *pte;

    	pte = lookup_address((unsigned long) syscall_table, &level);
    	/* Need to set r/w to a page which syscall_table is in. */
    	change_page_attr_to_rw(pte);

    	syscall_table[syscall_number] = new;
	/* set back to read only */
    	change_page_attr_to_ro(pte);
}

static int syscall_replace_init(void)
{
	DEFINE_SPINLOCK(spinlock);
    	pr_info("sys_call_table address is 0x%p\n", syscall_table);
	spin_lock(&spinlock);
	save_original_syscall_address();
	replace_system_call(replace_sys_read, 0);
	replace_system_call(replace_sys_write, 1);
	replace_system_call(replace_sys_open, 2);
	replace_system_call(replace_sys_close, 3);
	replace_system_call(replace_sys_stat, 4);
	replace_system_call(replace_sys_fstat, 5);
	replace_system_call(replace_sys_lstat, 6);
	replace_system_call(replace_sys_poll, 7);
	replace_system_call(replace_sys_lseek, 8);
	replace_system_call(replace_sys_mmap, 9);
	replace_system_call(replace_sys_mprotect, 10);
	replace_system_call(replace_sys_munmap, 11);
	replace_system_call(replace_sys_brk, 12);
	replace_system_call(replace_sys_rt_sigaction, 13);
	replace_system_call(replace_sys_rt_sigprocmask, 14);
	//replace_system_call(replace_sys_rt_sigreturn, 15);
	replace_system_call(replace_sys_ioctl, 16);
	replace_system_call(replace_sys_pread64, 17);
	replace_system_call(replace_sys_pwrite64, 18);
	replace_system_call(replace_sys_readv, 19);
	replace_system_call(replace_sys_writev, 20);
	replace_system_call(replace_sys_access, 21);
	replace_system_call(replace_sys_pipe, 22);
	replace_system_call(replace_sys_select, 23);
	replace_system_call(replace_sys_sched_yield, 24);
	replace_system_call(replace_sys_mremap, 25);
	replace_system_call(replace_sys_msync, 26);
	replace_system_call(replace_sys_mincore, 27);
	replace_system_call(replace_sys_madvise, 28);
	replace_system_call(replace_sys_shmget, 29);
	replace_system_call(replace_sys_shmat, 30);
	replace_system_call(replace_sys_shmctl, 31);
	replace_system_call(replace_sys_dup, 32);
	replace_system_call(replace_sys_dup2, 33);
	replace_system_call(replace_sys_pause, 34);
	replace_system_call(replace_sys_nanosleep, 35);
	replace_system_call(replace_sys_getitimer, 36);
	replace_system_call(replace_sys_alarm, 37);
	replace_system_call(replace_sys_setitimer, 38);
	replace_system_call(replace_sys_getpid, 39);
	replace_system_call(replace_sys_sendfile, 40);
	replace_system_call(replace_sys_socket, 41);
	replace_system_call(replace_sys_connect, 42);
	replace_system_call(replace_sys_accept, 43);
	replace_system_call(replace_sys_sendto, 44);
	replace_system_call(replace_sys_recvfrom, 45);
	replace_system_call(replace_sys_sendmsg, 46);
	replace_system_call(replace_sys_recvmsg, 47);
	replace_system_call(replace_sys_shutdown, 48);
	replace_system_call(replace_sys_bind, 49);
	replace_system_call(replace_sys_listen, 50);
	replace_system_call(replace_sys_getsockname, 51);
	replace_system_call(replace_sys_getpeername, 52);
	replace_system_call(replace_sys_socketpair, 53);
	replace_system_call(replace_sys_setsockopt, 54);
	replace_system_call(replace_sys_getsockopt, 55);

	//replace_system_call(replace_sys_clone, 56);
	//replace_system_call(replace_sys_fork, 57);
	//replace_system_call(replace_sys_vfork, 58);
	//replace_system_call(replace_sys_execve, 59);

	replace_system_call(replace_sys_exit, 60);
	replace_system_call(replace_sys_wait4, 61);
	replace_system_call(replace_sys_kill, 62);
	replace_system_call(replace_sys_uname, 63);

	replace_system_call(replace_sys_semget, 64);
	replace_system_call(replace_sys_semop, 65);
	replace_system_call(replace_sys_semctl, 66);
	replace_system_call(replace_sys_shmdt, 67);
	replace_system_call(replace_sys_msgget, 68);
	replace_system_call(replace_sys_msgsnd, 69);
	replace_system_call(replace_sys_msgrcv, 70);
	replace_system_call(replace_sys_msgctl, 71);
	replace_system_call(replace_sys_fcntl, 72);
	replace_system_call(replace_sys_flock, 73);
	replace_system_call(replace_sys_fsync, 74);
	replace_system_call(replace_sys_fdatasync, 75);
	replace_system_call(replace_sys_truncate, 76);
	replace_system_call(replace_sys_ftruncate, 77);
	replace_system_call(replace_sys_getdents, 78);
	replace_system_call(replace_sys_getcwd, 79);
	replace_system_call(replace_sys_chdir, 80);
	replace_system_call(replace_sys_fchdir, 81);
	replace_system_call(replace_sys_rename, 82);
	replace_system_call(replace_sys_mkdir, 83);
	replace_system_call(replace_sys_rmdir, 84);
	replace_system_call(replace_sys_creat, 85);
	replace_system_call(replace_sys_link, 86);
	replace_system_call(replace_sys_unlink, 87);
	replace_system_call(replace_sys_symlink, 88);
	replace_system_call(replace_sys_readlink, 89);
	replace_system_call(replace_sys_chmod, 90);
	replace_system_call(replace_sys_fchmod, 91);
	replace_system_call(replace_sys_chown, 92);
	replace_system_call(replace_sys_fchown, 93);
	replace_system_call(replace_sys_lchown, 94);
	replace_system_call(replace_sys_umask, 95);
	replace_system_call(replace_sys_gettimeofday, 96);
	replace_system_call(replace_sys_getrlimit, 97);
	replace_system_call(replace_sys_getrusage, 98);
	replace_system_call(replace_sys_sysinfo, 99);
	replace_system_call(replace_sys_times, 100);
	replace_system_call(replace_sys_ptrace, 101);
	replace_system_call(replace_sys_getuid, 102);
	replace_system_call(replace_sys_syslog, 103);
	replace_system_call(replace_sys_getgid, 104);
	replace_system_call(replace_sys_setuid, 105);
	replace_system_call(replace_sys_setgid, 106);
	replace_system_call(replace_sys_geteuid, 107);
	replace_system_call(replace_sys_getegid, 108);
	replace_system_call(replace_sys_setpgid, 109);
	replace_system_call(replace_sys_getppid, 110);
	replace_system_call(replace_sys_getpgrp, 111);
	replace_system_call(replace_sys_setsid, 112);
	replace_system_call(replace_sys_setreuid, 113);
	replace_system_call(replace_sys_setregid, 114);
	replace_system_call(replace_sys_getgroups, 115);
	replace_system_call(replace_sys_setgroups, 116);
	replace_system_call(replace_sys_setresuid, 117);
	replace_system_call(replace_sys_getresuid, 118);
	replace_system_call(replace_sys_setresgid, 119);
	replace_system_call(replace_sys_getresgid, 120);
	replace_system_call(replace_sys_getpgid, 121);
	replace_system_call(replace_sys_setfsuid, 122);
	replace_system_call(replace_sys_setfsgid, 123);
	replace_system_call(replace_sys_getsid, 124);
	replace_system_call(replace_sys_capget, 125);
	replace_system_call(replace_sys_capset, 126);
	replace_system_call(replace_sys_rt_sigpending, 127);
	replace_system_call(replace_sys_rt_sigtimedwait, 128);
	replace_system_call(replace_sys_rt_sigqueueinfo, 129);
	replace_system_call(replace_sys_rt_sigsuspend, 130);
	replace_system_call(replace_sys_sigaltstack, 131);
	replace_system_call(replace_sys_utime, 132);
	replace_system_call(replace_sys_mknod, 133);
	replace_system_call(replace_sys_uselib, 134);
	replace_system_call(replace_sys_personality, 135);
	replace_system_call(replace_sys_ustat, 136);
	replace_system_call(replace_sys_statfs, 137);
	replace_system_call(replace_sys_fstatfs, 138);
	replace_system_call(replace_sys_sysfs, 139);
	replace_system_call(replace_sys_getpriority, 140);
	replace_system_call(replace_sys_setpriority, 141);
	replace_system_call(replace_sys_sched_setparam, 142);
	replace_system_call(replace_sys_sched_getparam, 143);
	replace_system_call(replace_sys_sched_setscheduler, 144);
	replace_system_call(replace_sys_sched_getscheduler, 145);
	replace_system_call(replace_sys_sched_get_priority_max, 146);
	replace_system_call(replace_sys_sched_get_priority_min, 147);
	replace_system_call(replace_sys_sched_rr_get_interval, 148);
	replace_system_call(replace_sys_mlock, 149);
	replace_system_call(replace_sys_munlock, 150);
	replace_system_call(replace_sys_mlockall, 151);
	replace_system_call(replace_sys_munlockall, 152);
	replace_system_call(replace_sys_vhangup, 153);
	//replace_system_call(replace_sys_modifyldt, 154);
	replace_system_call(replace_sys_pivot_root, 155);
	replace_system_call(replace_sys_sysctl, 156);
	replace_system_call(replace_sys_prctl, 157);
	//replace_system_call(replace_sys_archprctl, 158);
	replace_system_call(replace_sys_adjtimex, 159);
	replace_system_call(replace_sys_setrlimit, 160);

	replace_system_call(replace_sys_chroot, 161);
	replace_system_call(replace_sys_sync, 162);
	replace_system_call(replace_sys_acct, 163);
	replace_system_call(replace_sys_settimeofday, 164);
	replace_system_call(replace_sys_mount, 165);
	replace_system_call(replace_sys_umount, 166);
	replace_system_call(replace_sys_swapon, 167);
	replace_system_call(replace_sys_swapoff, 168);
	replace_system_call(replace_sys_reboot, 169);
	replace_system_call(replace_sys_sethostname, 170);
	replace_system_call(replace_sys_setdomainname, 171);
	//replace_system_call(replace_sys_iopl, 172);
	replace_system_call(replace_sys_ioperm, 173);
	//replace_system_call(replace_sys_create_module, 174);
	replace_system_call(replace_sys_init_module, 175);
	replace_system_call(replace_sys_delete_module, 176);
	//replace_system_call(replace_sys_get_kernel_syms, 177);
	//replace_system_call(replace_sys_query_module, 178);
	replace_system_call(replace_sys_quotactl, 179);
	//replace_system_call(replace_sys_nfsservctl, 180);
	//replace_system_call(replace_sys_getpmsg, 181);
	//replace_system_call(replace_sys_putpmsg, 182);
	//replace_system_call(replace_sys_afs_syscall, 183);
	//replace_system_call(replace_sys_tuxcall, 184);
	//replace_system_call(replace_sys_security, 185);
	replace_system_call(replace_sys_gettid, 186);
	replace_system_call(replace_sys_readahead, 187);
	replace_system_call(replace_sys_setxattr, 188);
	replace_system_call(replace_sys_lsetxattr, 189);
	replace_system_call(replace_sys_fsetxattr, 190);
	replace_system_call(replace_sys_getxattr, 191);
	replace_system_call(replace_sys_lgetxattr, 192);
	replace_system_call(replace_sys_fgetxattr, 193);
	replace_system_call(replace_sys_listxattr, 194);
	replace_system_call(replace_sys_llistxattr, 195);
	replace_system_call(replace_sys_flistxattr, 196);
	replace_system_call(replace_sys_removexattr, 197);
	replace_system_call(replace_sys_lremovexattr, 198);
	replace_system_call(replace_sys_fremovexattr, 199);
	replace_system_call(replace_sys_tkill, 200);
	replace_system_call(replace_sys_time, 201);
	replace_system_call(replace_sys_futex, 202);
	replace_system_call(replace_sys_sched_setaffinity, 203);
	replace_system_call(replace_sys_sched_getaffinity, 204);
	//replace_system_call(replace_sys_set_thread_area, 205);
	replace_system_call(replace_sys_io_setup, 206);
	replace_system_call(replace_sys_io_destroy, 207);
	replace_system_call(replace_sys_io_getevents, 208);
	replace_system_call(replace_sys_io_submit, 209);
	replace_system_call(replace_sys_io_cancel, 210);
	//replace_system_call(replace_sys_get_thread_area, 211);
	replace_system_call(replace_sys_lookup_dcookie, 212);
	replace_system_call(replace_sys_epoll_create, 213);
	//replace_system_call(replace_sys_epoll_ctl_old, 214);
	//replace_system_call(replace_sys_epoll_wait_old, 215);
	replace_system_call(replace_sys_remap_file_pages, 216);
	replace_system_call(replace_sys_getdents64, 217);
	replace_system_call(replace_sys_set_tid_address, 218);
	replace_system_call(replace_sys_restart_syscall, 219);
	replace_system_call(replace_sys_semtimedop, 220);
	replace_system_call(replace_sys_fadvise64, 221);
	replace_system_call(replace_sys_timer_create, 222);
	replace_system_call(replace_sys_timer_settime, 223);
	replace_system_call(replace_sys_timer_gettime, 224);
	replace_system_call(replace_sys_timer_getoverrun, 225);
	replace_system_call(replace_sys_timer_delete, 226);
	replace_system_call(replace_sys_clock_settime, 227);
	replace_system_call(replace_sys_clock_gettime, 228);
	replace_system_call(replace_sys_clock_getres, 229);
	replace_system_call(replace_sys_clock_nanosleep, 230);
	replace_system_call(replace_sys_exit_group, 231);
	replace_system_call(replace_sys_epoll_wait, 232);
	replace_system_call(replace_sys_epoll_ctl, 233);
	replace_system_call(replace_sys_tgkill, 234);
	replace_system_call(replace_sys_utimes, 235);
	//replace_system_call(replace_sys_vserver, 236);
	replace_system_call(replace_sys_mbind, 237);
	replace_system_call(replace_sys_set_mempolicy, 238);
	replace_system_call(replace_sys_get_mempolicy, 239);
	replace_system_call(replace_sys_mq_open, 240);
	replace_system_call(replace_sys_mq_unlink, 241);
	replace_system_call(replace_sys_mq_timedsend, 242);
	replace_system_call(replace_sys_mq_timedreceive, 243);
	replace_system_call(replace_sys_mq_notify, 244);
	replace_system_call(replace_sys_mq_getsetattr, 245);
	replace_system_call(replace_sys_kexec_load, 246);
	replace_system_call(replace_sys_waitid, 247);
	replace_system_call(replace_sys_add_key, 248);
	replace_system_call(replace_sys_request_key, 249);
	replace_system_call(replace_sys_keyctl, 250);
	replace_system_call(replace_sys_ioprio_set, 251);
	replace_system_call(replace_sys_ioprio_get, 252);
	replace_system_call(replace_sys_inotify_init, 253);
	replace_system_call(replace_sys_inotify_add_watch, 254);
	replace_system_call(replace_sys_inotify_rm_watch, 255);
	replace_system_call(replace_sys_migrate_pages, 256);
	replace_system_call(replace_sys_openat, 257);
	replace_system_call(replace_sys_mkdirat, 258);
	//replace_system_call(replace_sys_mknodat, 259);
	replace_system_call(replace_sys_fchownat, 260);
	replace_system_call(replace_sys_futimesat, 261);
	replace_system_call(replace_sys_newfstatat, 262);
	replace_system_call(replace_sys_unlinkat, 263);
	replace_system_call(replace_sys_renameat, 264);
	replace_system_call(replace_sys_linkat, 265);
	replace_system_call(replace_sys_symlinkat, 266);
	replace_system_call(replace_sys_readlinkat, 267);
	replace_system_call(replace_sys_fchmodat, 268);
	replace_system_call(replace_sys_faccessat, 269);
	replace_system_call(replace_sys_pselect, 270);
	replace_system_call(replace_sys_ppoll, 271);
	replace_system_call(replace_sys_unshare, 272);
	replace_system_call(replace_sys_set_robust_list, 273);
	replace_system_call(replace_sys_get_robust_list, 274);
	replace_system_call(replace_sys_splice, 275);
	replace_system_call(replace_sys_tee, 276);
	replace_system_call(replace_sys_sync_file_range, 277);
	replace_system_call(replace_sys_vmsplice, 278);
	replace_system_call(replace_sys_move_pages, 279);
	replace_system_call(replace_sys_utimensat, 280);
	replace_system_call(replace_sys_epoll_pwait, 281);
	replace_system_call(replace_sys_signalfd, 282);
	replace_system_call(replace_sys_timerfd_create, 283);
	replace_system_call(replace_sys_eventfd, 284);
	replace_system_call(replace_sys_fallocate, 285);
	replace_system_call(replace_sys_timerfd_settime, 286);
	replace_system_call(replace_sys_timerfd_gettime, 287);
	replace_system_call(replace_sys_accept4, 288);
	replace_system_call(replace_sys_signalfd4, 289);
	replace_system_call(replace_sys_eventfd2, 290);
	replace_system_call(replace_sys_epoll_create1, 291);
	replace_system_call(replace_sys_dup3, 292);
	replace_system_call(replace_sys_pipe2, 293);
	replace_system_call(replace_sys_inotify_init1, 294);
	replace_system_call(replace_sys_preadv, 295);
	replace_system_call(replace_sys_pwritev, 296);
	replace_system_call(replace_sys_rt_tgsigqueueinfo, 297);
	replace_system_call(replace_sys_perf_event_open, 298);
	replace_system_call(replace_sys_recvmmsg, 299);
	replace_system_call(replace_sys_fanotify_init, 300);
	replace_system_call(replace_sys_fanotify_mark, 301);
	replace_system_call(replace_sys_prlimit64, 302);
	replace_system_call(replace_sys_name_to_handle_at, 303);
	replace_system_call(replace_sys_open_by_handle_at, 304);
	replace_system_call(replace_sys_clock_adjtime, 305);
	replace_system_call(replace_sys_syncfs, 306);
	replace_system_call(replace_sys_sendmmsg, 307);
	replace_system_call(replace_sys_setns, 308);
	replace_system_call(replace_sys_getcpu, 309);
	replace_system_call(replace_sys_process_vm_readv, 310);
	replace_system_call(replace_sys_process_vm_writev, 311);
	replace_system_call(replace_sys_kcmp, 312);
	replace_system_call(replace_sys_finit_module, 313);
	spin_unlock(&spinlock);
	pr_info("system call replaced\n");
	return 0;
}

static void syscall_replace_cleanup(void)
{
	int i;
	//spinlock_t spinlock = SPIN_LOCK_UNLOCKED;
	DEFINE_SPINLOCK(spinlock);
    	pr_info("cleanup");
	for (i = 0; i < SYSCALL_MAX; i++) {
		pr_info("System Call No.%d : %d\n", i, syscall_count[i]);
	}
	spin_lock(&spinlock);
	replace_system_call(orig_sys_read, 0);
	replace_system_call(orig_sys_write, 1);
	replace_system_call(orig_sys_open, 2);
	replace_system_call(orig_sys_close, 3);
	replace_system_call(orig_sys_stat, 4);
	replace_system_call(orig_sys_fstat, 5);
	replace_system_call(orig_sys_lstat, 6);
	replace_system_call(orig_sys_poll, 7);
	replace_system_call(orig_sys_lseek, 8);
	replace_system_call(orig_sys_mmap, 9);
	replace_system_call(orig_sys_mprotect, 10);
	replace_system_call(orig_sys_munmap, 11);
	replace_system_call(orig_sys_brk, 12);
	replace_system_call(orig_sys_rt_sigaction, 13);
	replace_system_call(orig_sys_rt_sigprocmask, 14);
	//replace_system_call(orig_sys_rt_sigreturn, 15);
	replace_system_call(orig_sys_ioctl, 16);
	replace_system_call(orig_sys_pread64, 17);
	replace_system_call(orig_sys_pwrite64, 18);
	replace_system_call(orig_sys_readv, 19);
	replace_system_call(orig_sys_writev, 20);
	replace_system_call(orig_sys_access, 21);
	replace_system_call(orig_sys_pipe, 22);
	replace_system_call(orig_sys_select, 23);
	replace_system_call(orig_sys_sched_yield, 24);
	replace_system_call(orig_sys_mremap, 25);
	replace_system_call(orig_sys_msync, 26);
	replace_system_call(orig_sys_mincore, 27);
	replace_system_call(orig_sys_madvise, 28);
	replace_system_call(orig_sys_shmget, 29);
	replace_system_call(orig_sys_shmat, 30);
	replace_system_call(orig_sys_shmctl, 31);
	replace_system_call(orig_sys_dup, 32);
	replace_system_call(orig_sys_dup2, 33);
	replace_system_call(orig_sys_pause, 34);
	replace_system_call(orig_sys_nanosleep, 35);
	replace_system_call(orig_sys_getitimer, 36);
	replace_system_call(orig_sys_alarm, 37);
	replace_system_call(orig_sys_setitimer, 38);
	replace_system_call(orig_sys_getpid, 39);
	replace_system_call(orig_sys_sendfile, 40);
	replace_system_call(orig_sys_socket, 41);
	replace_system_call(orig_sys_connect, 42);
	replace_system_call(orig_sys_accept, 43);
	replace_system_call(orig_sys_sendto, 44);
	replace_system_call(orig_sys_recvfrom, 45);
	replace_system_call(orig_sys_sendmsg, 46);
	replace_system_call(orig_sys_recvmsg, 47);
	replace_system_call(orig_sys_shutdown, 48);
	replace_system_call(orig_sys_bind, 49);
	replace_system_call(orig_sys_listen, 50);
	replace_system_call(orig_sys_getsockname, 51);
	replace_system_call(orig_sys_getpeername, 52);
	replace_system_call(orig_sys_socketpair, 53);
	replace_system_call(orig_sys_setsockopt, 54);
	replace_system_call(orig_sys_getsockopt, 55);

	//replace_system_call(orig_sys_clone, 56);
	//replace_system_call(orig_sys_fork, 57);
	//replace_system_call(orig_sys_vfork, 58);
	//replace_system_call(orig_sys_execve, 59);

	replace_system_call(orig_sys_exit, 60);
	replace_system_call(orig_sys_wait4, 61);
	replace_system_call(orig_sys_kill, 62);
	replace_system_call(orig_sys_uname, 63);

	replace_system_call(orig_sys_semget, 64);
	replace_system_call(orig_sys_semop, 65);
	replace_system_call(orig_sys_semctl, 66);
	replace_system_call(orig_sys_shmdt, 67);
	replace_system_call(orig_sys_msgget, 68);
	replace_system_call(orig_sys_msgsnd, 69);
	replace_system_call(orig_sys_msgrcv, 70);
	replace_system_call(orig_sys_msgctl, 71);
	replace_system_call(orig_sys_fcntl, 72);
	replace_system_call(orig_sys_flock, 73);
	replace_system_call(orig_sys_fsync, 74);
	replace_system_call(orig_sys_fdatasync, 75);
	replace_system_call(orig_sys_truncate, 76);
	replace_system_call(orig_sys_ftruncate, 77);
	replace_system_call(orig_sys_getdents, 78);
	replace_system_call(orig_sys_getcwd, 79);
	replace_system_call(orig_sys_chdir, 80);
	replace_system_call(orig_sys_fchdir, 81);
	replace_system_call(orig_sys_rename, 82);
	replace_system_call(orig_sys_mkdir, 83);
	replace_system_call(orig_sys_rmdir, 84);
	replace_system_call(orig_sys_creat, 85);
	replace_system_call(orig_sys_link, 86);
	replace_system_call(orig_sys_unlink, 87);
	replace_system_call(orig_sys_symlink, 88);
	replace_system_call(orig_sys_readlink, 89);
	replace_system_call(orig_sys_chmod, 90);
	replace_system_call(orig_sys_fchmod, 91);
	replace_system_call(orig_sys_chown, 92);
	replace_system_call(orig_sys_fchown, 93);
	replace_system_call(orig_sys_lchown, 94);
	replace_system_call(orig_sys_umask, 95);
	replace_system_call(orig_sys_gettimeofday, 96);
	replace_system_call(orig_sys_getrlimit, 97);
	replace_system_call(orig_sys_getrusage, 98);
	replace_system_call(orig_sys_sysinfo, 99);
	replace_system_call(orig_sys_times, 100);
	replace_system_call(orig_sys_ptrace, 101);
	replace_system_call(orig_sys_getuid, 102);
	replace_system_call(orig_sys_syslog, 103);
	replace_system_call(orig_sys_getgid, 104);
	replace_system_call(orig_sys_setuid, 105);
	replace_system_call(orig_sys_setgid, 106);
	replace_system_call(orig_sys_geteuid, 107);
	replace_system_call(orig_sys_getegid, 108);
	replace_system_call(orig_sys_setpgid, 109);
	replace_system_call(orig_sys_getppid, 110);
	replace_system_call(orig_sys_getpgrp, 111);
	replace_system_call(orig_sys_setsid, 112);
	replace_system_call(orig_sys_setreuid, 113);
	replace_system_call(orig_sys_setregid, 114);
	replace_system_call(orig_sys_getgroups, 115);
	replace_system_call(orig_sys_setgroups, 116);
	replace_system_call(orig_sys_setresuid, 117);
	replace_system_call(orig_sys_getresuid, 118);
	replace_system_call(orig_sys_setresgid, 119);
	replace_system_call(orig_sys_getresgid, 120);
	replace_system_call(orig_sys_getpgid, 121);
	replace_system_call(orig_sys_setfsuid, 122);
	replace_system_call(orig_sys_setfsgid, 123);
	replace_system_call(orig_sys_getsid, 124);
	replace_system_call(orig_sys_capget, 125);
	replace_system_call(orig_sys_capset, 126);
	replace_system_call(orig_sys_rt_sigpending, 127);
	replace_system_call(orig_sys_rt_sigtimedwait, 128);
	replace_system_call(orig_sys_rt_sigqueueinfo, 129);
	replace_system_call(orig_sys_rt_sigsuspend, 130);
	replace_system_call(orig_sys_sigaltstack, 131);
	replace_system_call(orig_sys_utime, 132);
	replace_system_call(orig_sys_mknod, 133);
	replace_system_call(orig_sys_uselib, 134);
	replace_system_call(orig_sys_personality, 135);
	replace_system_call(orig_sys_ustat, 136);
	replace_system_call(orig_sys_statfs, 137);
	replace_system_call(orig_sys_fstatfs, 138);
	replace_system_call(orig_sys_sysfs, 139);
	replace_system_call(orig_sys_getpriority, 140);
	replace_system_call(orig_sys_setpriority, 141);
	replace_system_call(orig_sys_sched_setparam, 142);
	replace_system_call(orig_sys_sched_getparam, 143);
	replace_system_call(orig_sys_sched_setscheduler, 144);
	replace_system_call(orig_sys_sched_getscheduler, 145);
	replace_system_call(orig_sys_sched_get_priority_max, 146);
	replace_system_call(orig_sys_sched_get_priority_min, 147);
	replace_system_call(orig_sys_sched_rr_get_interval, 148);
	replace_system_call(orig_sys_mlock, 149);
	replace_system_call(orig_sys_munlock, 150);
	replace_system_call(orig_sys_mlockall, 151);
	replace_system_call(orig_sys_munlockall, 152);
	replace_system_call(orig_sys_vhangup, 153);
	//replace_system_call(orig_sys_modifyldt, 154);
	replace_system_call(orig_sys_pivot_root, 155);
	replace_system_call(orig_sys_sysctl, 156);
	replace_system_call(orig_sys_prctl, 157);
	//replace_system_call(orig_sys_archprctl, 158);
	replace_system_call(orig_sys_adjtimex, 159);
	replace_system_call(orig_sys_setrlimit, 160);

	replace_system_call(orig_sys_chroot, 161);
	replace_system_call(orig_sys_sync, 162);
	replace_system_call(orig_sys_acct, 163);
	replace_system_call(orig_sys_settimeofday, 164);
	replace_system_call(orig_sys_mount, 165);
	replace_system_call(orig_sys_umount, 166);
	replace_system_call(orig_sys_swapon, 167);
	replace_system_call(orig_sys_swapoff, 168);
	replace_system_call(orig_sys_reboot, 169);
	replace_system_call(orig_sys_sethostname, 170);
	replace_system_call(orig_sys_setdomainname, 171);
	//replace_system_call(orig_sys_iopl, 172);
	replace_system_call(orig_sys_ioperm, 173);
	//replace_system_call(orig_sys_create_module, 174);
	replace_system_call(orig_sys_init_module, 175);
	replace_system_call(orig_sys_delete_module, 176);
	//replace_system_call(orig_sys_get_kernel_syms, 177);
	//replace_system_call(orig_sys_query_module, 178);
	replace_system_call(orig_sys_quotactl, 179);
	//replace_system_call(orig_sys_nfsservctl, 180);
	//replace_system_call(orig_sys_getpmsg, 181);
	//replace_system_call(orig_sys_putpmsg, 182);
	//replace_system_call(orig_sys_afs_syscall, 183);
	//replace_system_call(orig_sys_tuxcall, 184);
	//replace_system_call(orig_sys_security, 185);
	replace_system_call(orig_sys_gettid, 186);
	replace_system_call(orig_sys_readahead, 187);
	replace_system_call(orig_sys_setxattr, 188);
	replace_system_call(orig_sys_lsetxattr, 189);
	replace_system_call(orig_sys_fsetxattr, 190);
	replace_system_call(orig_sys_getxattr, 191);
	replace_system_call(orig_sys_lgetxattr, 192);
	replace_system_call(orig_sys_fgetxattr, 193);
	replace_system_call(orig_sys_listxattr, 194);
	replace_system_call(orig_sys_llistxattr, 195);
	replace_system_call(orig_sys_flistxattr, 196);
	replace_system_call(orig_sys_removexattr, 197);
	replace_system_call(orig_sys_lremovexattr, 198);
	replace_system_call(orig_sys_fremovexattr, 199);
	replace_system_call(orig_sys_tkill, 200);
	replace_system_call(orig_sys_time, 201);
	replace_system_call(orig_sys_futex, 202);
	replace_system_call(orig_sys_sched_setaffinity, 203);
	replace_system_call(orig_sys_sched_getaffinity, 204);
	//replace_system_call(orig_sys_set_thread_area, 205);
	replace_system_call(orig_sys_io_setup, 206);
	replace_system_call(orig_sys_io_destroy, 207);
	replace_system_call(orig_sys_io_getevents, 208);
	replace_system_call(orig_sys_io_submit, 209);
	replace_system_call(orig_sys_io_cancel, 210);
	//replace_system_call(orig_sys_get_thread_area, 211);
	replace_system_call(orig_sys_lookup_dcookie, 212);
	replace_system_call(orig_sys_epoll_create, 213);
	//replace_system_call(orig_sys_epoll_ctl_old, 214);
	//replace_system_call(orig_sys_epoll_wait_old, 215);
	replace_system_call(orig_sys_remap_file_pages, 216);
	replace_system_call(orig_sys_getdents64, 217);
	replace_system_call(orig_sys_set_tid_address, 218);
	replace_system_call(orig_sys_restart_syscall, 219);
	replace_system_call(orig_sys_semtimedop, 220);
	replace_system_call(orig_sys_fadvise64, 221);
	replace_system_call(orig_sys_timer_create, 222);
	replace_system_call(orig_sys_timer_settime, 223);
	replace_system_call(orig_sys_timer_gettime, 224);
	replace_system_call(orig_sys_timer_getoverrun, 225);
	replace_system_call(orig_sys_timer_delete, 226);
	replace_system_call(orig_sys_clock_settime, 227);
	replace_system_call(orig_sys_clock_gettime, 228);
	replace_system_call(orig_sys_clock_getres, 229);
	replace_system_call(orig_sys_clock_nanosleep, 230);
	replace_system_call(orig_sys_exit_group, 231);
	replace_system_call(orig_sys_epoll_wait, 232);
	replace_system_call(orig_sys_epoll_ctl, 233);
	replace_system_call(orig_sys_tgkill, 234);
	replace_system_call(orig_sys_utimes, 235);
	//replace_system_call(orig_sys_vserver, 236);
	replace_system_call(orig_sys_mbind, 237);
	replace_system_call(orig_sys_set_mempolicy, 238);
	replace_system_call(orig_sys_get_mempolicy, 239);
	replace_system_call(orig_sys_mq_open, 240);
	replace_system_call(orig_sys_mq_unlink, 241);
	replace_system_call(orig_sys_mq_timedsend, 242);
	replace_system_call(orig_sys_mq_timedreceive, 243);
	replace_system_call(orig_sys_mq_notify, 244);
	replace_system_call(orig_sys_mq_getsetattr, 245);
	replace_system_call(orig_sys_kexec_load, 246);
	replace_system_call(orig_sys_waitid, 247);
	replace_system_call(orig_sys_add_key, 248);
	replace_system_call(orig_sys_request_key, 249);
	replace_system_call(orig_sys_keyctl, 250);
	replace_system_call(orig_sys_ioprio_set, 251);
	replace_system_call(orig_sys_ioprio_get, 252);
	replace_system_call(orig_sys_inotify_init, 253);
	replace_system_call(orig_sys_inotify_add_watch, 254);
	replace_system_call(orig_sys_inotify_rm_watch, 255);
	replace_system_call(orig_sys_migrate_pages, 256);
	replace_system_call(orig_sys_openat, 257);
	replace_system_call(orig_sys_mkdirat, 258);
	//replace_system_call(orig_sys_mknodat, 259);
	replace_system_call(orig_sys_fchownat, 260);
	replace_system_call(orig_sys_futimesat, 261);
	replace_system_call(orig_sys_newfstatat, 262);
	replace_system_call(orig_sys_unlinkat, 263);
	replace_system_call(orig_sys_renameat, 264);
	replace_system_call(orig_sys_linkat, 265);
	replace_system_call(orig_sys_symlinkat, 266);
	replace_system_call(orig_sys_readlinkat, 267);
	replace_system_call(orig_sys_fchmodat, 268);
	replace_system_call(orig_sys_faccessat, 269);
	replace_system_call(orig_sys_pselect, 270);
	replace_system_call(orig_sys_ppoll, 271);
	replace_system_call(orig_sys_unshare, 272);
	replace_system_call(orig_sys_set_robust_list, 273);
	replace_system_call(orig_sys_get_robust_list, 274);
	replace_system_call(orig_sys_splice, 275);
	replace_system_call(orig_sys_tee, 276);
	replace_system_call(orig_sys_sync_file_range, 277);
	replace_system_call(orig_sys_vmsplice, 278);
	replace_system_call(orig_sys_move_pages, 279);
	replace_system_call(orig_sys_utimensat, 280);
	replace_system_call(orig_sys_epoll_pwait, 281);
	replace_system_call(orig_sys_signalfd, 282);
	replace_system_call(orig_sys_timerfd_create, 283);
	replace_system_call(orig_sys_eventfd, 284);
	replace_system_call(orig_sys_fallocate, 285);
	replace_system_call(orig_sys_timerfd_settime, 286);
	replace_system_call(orig_sys_timerfd_gettime, 287);
	replace_system_call(orig_sys_accept4, 288);
	replace_system_call(orig_sys_signalfd4, 289);
	replace_system_call(orig_sys_eventfd2, 290);
	replace_system_call(orig_sys_epoll_create1, 291);
	replace_system_call(orig_sys_dup3, 292);
	replace_system_call(orig_sys_pipe2, 293);
	replace_system_call(orig_sys_inotify_init1, 294);
	replace_system_call(orig_sys_preadv, 295);
	replace_system_call(orig_sys_pwritev, 296);
	replace_system_call(orig_sys_rt_tgsigqueueinfo, 297);
	replace_system_call(orig_sys_perf_event_open, 298);
	replace_system_call(orig_sys_recvmmsg, 299);
	replace_system_call(orig_sys_fanotify_init, 300);
	replace_system_call(orig_sys_fanotify_mark, 301);
	replace_system_call(orig_sys_prlimit64, 302);
	replace_system_call(orig_sys_name_to_handle_at, 303);
	replace_system_call(orig_sys_open_by_handle_at, 304);
	replace_system_call(orig_sys_clock_adjtime, 305);
	replace_system_call(orig_sys_syncfs, 306);
	replace_system_call(orig_sys_sendmmsg, 307);
	replace_system_call(orig_sys_setns, 308);
	replace_system_call(orig_sys_getcpu, 309);
	replace_system_call(orig_sys_process_vm_readv, 310);
	replace_system_call(orig_sys_process_vm_writev, 311);
	replace_system_call(orig_sys_kcmp, 312);
	replace_system_call(orig_sys_finit_module, 313);
	spin_unlock(&spinlock);
}

module_init(syscall_replace_init);
module_exit(syscall_replace_cleanup);
