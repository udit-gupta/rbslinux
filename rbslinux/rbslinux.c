/*
 * Role Based Security Module (Modifed from selinux hooks functionalities)
 * This file contains the RBSLinux hook function implementations.
 *
 *  Authors:  Udit Gupta, <udit.gupta@stonybrook.edu>
 *
 *  Copyright (C) 2014 Stony Brook University, Inc.
 * 
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2,
 *	as published by the Free Software Foundation
 *
 * 
 *
 */

#include <linux/init.h>
#include <linux/kd.h>
#include <linux/kernel.h>
#include <linux/tracehook.h>
#include <linux/errno.h>
#include <linux/ext2_fs.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/proc_fs.h>
#include <linux/swap.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/tty.h>
#include <net/icmp.h>
#include <net/ip.h>             /* for local_port_range[] */
#include <net/tcp.h>            /* struct or_callable used in sock_rcv_skb */
#include <net/net_namespace.h>
#include <net/netlabel.h>
#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include <asm/atomic.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>    /* for network interface checks */
#include <linux/netlink.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/dccp.h>
#include <linux/quota.h>
#include <linux/un.h>           /* for Unix socket types */
#include <net/af_unix.h>        /* for Unix socket types */
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <net/ipv6.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>
#include <linux/audit.h>
#include <linux/string.h>
#include <linux/selinux.h>
#include <linux/mutex.h>
#include <linux/posix-timers.h>
#include <linux/syslog.h>
#include <linux/user_namespace.h>
#include <linux/uidgid.h>
 

#define FILENAME "/etc/rbslinux.conf"

extern struct security_operations *security_ops;
 
static int rbslinux_ptrace_access_check(struct task_struct *child,
                                     unsigned int mode)
{
        return 0;
}
 
static int rbslinux_ptrace_traceme(struct task_struct *parent)
{
        return 0;
}
 
static int rbslinux_capget(struct task_struct *target, kernel_cap_t *effective,
                          kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
        return 0;
}
 
static int rbslinux_capset(struct cred *new, const struct cred *old,
                          const kernel_cap_t *effective,
                          const kernel_cap_t *inheritable,
                          const kernel_cap_t *permitted)
{
        return 0;
}
 
static int rbslinux_capable(const struct cred *cred,
                           struct user_namespace *ns, int cap, int audit)
{
        return 0;
}
 
static int rbslinux_quotactl(int cmds, int type, int id, struct super_block *sb)
{
        return 0;
}
 
static int rbslinux_quota_on(struct dentry *dentry)
{
        return 0;
}
 
static int rbslinux_syslog(int type)
{
        return 0;
}
 
 
static int rbslinux_vm_enough_memory(struct mm_struct *mm, long pages)
{
        return 0;
}
 
/* binprm security operations */
 
static int rbslinux_bprm_set_creds(struct linux_binprm *bprm)
{
        return 0;
}
 
static int rbslinux_bprm_secureexec(struct linux_binprm *bprm)
{
        return 0;
}
 
static void rbslinux_bprm_committing_creds(struct linux_binprm *bprm)
{
       
}
 
static void rbslinux_bprm_committed_creds(struct linux_binprm *bprm)
{
       
}
 
static int rbslinux_sb_alloc_security(struct super_block *sb)
{
        return 0;
}
 
static void rbslinux_sb_free_security(struct super_block *sb)
{
 
}
 
static int rbslinux_sb_copy_data(char *orig, char *copy)
{
        return 0;
}
 
static int rbslinux_sb_remount(struct super_block *sb, void *data)
{
        return 0;
}
 
static int rbslinux_sb_kern_mount(struct super_block *sb, int flags, void *data)
{
        return 0;
}
 
static int rbslinux_sb_statfs(struct dentry *dentry)
{
        return 0;
}
 
static int rbslinux_mount(const char *dev_name, struct path *path, const char *type, unsigned long flags, void *data)
{
        return 0;
}
 
static int rbslinux_umount(struct vfsmount *mnt, int flags)
{
        return 0;
}
 
 
/* inode security operations */
 
static int rbslinux_inode_alloc_security(struct inode *inode)
{
        return 0;
}
 
static void rbslinux_inode_free_security(struct inode *inode)
{
 
}
 
static int rbslinux_inode_init_security(struct inode *inode, struct inode *dir,
                                       const struct qstr *qstr, const char **name,
                                       void **value, size_t *len)
{
        return 0;
}

static int read_file(const char *filename) {
    char rbs_uname[100];
    int rbs_uid,rbs_role,read_bytes;

    struct file *f;
    char *buf;
    
    unsigned int off;

    mm_segment_t oldfs;
    
    buf=kmalloc(4096,GFP_KERNEL);
    
    if(!buf)
        printk(KERN_INFO "Allocation Error\n");

    memset(buf,0,4096);

    if( get_current_user()->uid.val >= 1000 )  {
        oldfs = get_fs();
        set_fs(get_ds());

        f = filp_open(filename, O_RDONLY, 0);
    
        if(IS_ERR(f))
            printk(KERN_INFO " Err = %ld \n ", PTR_ERR(f));
        
        f->f_op->read(f, buf, 4096, &f->f_pos);
        set_fs(oldfs);

        filp_close(f,NULL);

        off=0;
        while (off < f->f_pos) {
            sscanf(buf+off, "%s %d %d\n%n", rbs_uname, &rbs_uid, &rbs_role, &read_bytes);
            if( ( (rbs_uid==get_current_user()->uid.val) && rbs_role==0 ) )
                goto free_lbl;
            off += read_bytes;
        }

    // printk("Read :%s len : %llu \n", buf, (unsigned long long)f->f_pos);
    kfree(buf);
    return -EPERM;

    }


free_lbl:
    kfree(buf);
    //printk("rbs_name :%s rbs_uid : %d rbs_role : %d \n", rbs_uname, rbs_uid, rbs_role);
    //printk(KERN_INFO "Current UID for me = %u\n", get_current_user()->uid.val);
    return 0;
    
}

static int rbslinux_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
{
    int val=read_file(FILENAME);
    return val;

}
 
static int rbslinux_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
        return 0;
}
 
static int rbslinux_inode_unlink(struct inode *dir, struct dentry *dentry)
{
    int val=read_file(FILENAME);
    return val;
}
 
static int rbslinux_inode_symlink(struct inode *dir, struct dentry *dentry, const char *name)
{
        return 0;
}
 
static int rbslinux_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
    int val=read_file(FILENAME);
    return val;
}
 
static int rbslinux_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
    int val=read_file(FILENAME);
    return val;
}
 
static int rbslinux_inode_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
        return 0;
}
 
static int rbslinux_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
                                struct inode *new_inode, struct dentry *new_dentry)
{
    int val=read_file(FILENAME);
    return val;
}
 
static int rbslinux_inode_readlink(struct dentry *dentry)
{
        return 0;
}
 
static int rbslinux_inode_follow_link(struct dentry *dentry, struct nameidata *nameidata)
{
        return 0;
}
 
static int rbslinux_inode_permission(struct inode *inode, int mask)
{
        return 0;
}
 
static int rbslinux_sb_clone_mnt_opts(const struct super_block *oldsb,
                                        struct super_block *newsb)
{
        return 0;
}
 
static int rbslinux_file_set_fowner(struct file *file)
{
        return 0;
}
 
static int rbslinux_parse_opts_str(char *options, struct security_mnt_opts *opts)
{
    return 0;
}
 
static int rbslinux_inode_setattr(struct dentry *dentry, struct iattr *iattr)
{
        return 0;
}
 
static int rbslinux_inode_getattr(struct vfsmount *mnt, struct dentry *dentry)
{
        return 0;
}
/* 
static int rbslinux_inode_setotherxattr(struct dentry *dentry, const char *name)
{
        return 0;
}
 */
static int rbslinux_inode_setxattr(struct dentry *dentry, const char *name,
                                  const void *value, size_t size, int flags)
{
        return 0;
}
 
static void rbslinux_inode_post_setxattr(struct dentry *dentry, const char *name,
                                        const void *value, size_t size,
                                        int flags)
{
       
}
 
static int rbslinux_inode_getxattr(struct dentry *dentry, const char *name)
{
        return 0;
}
 
static int rbslinux_inode_listxattr(struct dentry *dentry)
{
        return 0;
}
 
static int rbslinux_inode_removexattr(struct dentry *dentry, const char *name)
{
        return 0;
}
 
static int rbslinux_inode_getsecurity(const struct inode *inode, const char *name, void **buffer, bool alloc)
{
        return 0;
}
 
static int rbslinux_inode_setsecurity(struct inode *inode, const char *name,
                                     const void *value, size_t size, int flags)
{
        return 0;
}
 
static int rbslinux_inode_listsecurity(struct inode *inode, char *buffer, size_t buffer_size)
{
        return 0;
}
 
static void rbslinux_inode_getsecid(const struct inode *inode, u32 *secid)
{
       
}
 
 
/* file security operations */
/* 
static int rbslinux_revalidate_file_permission(struct file *file, int mask)
{
        return 0;
}
 */
static int rbslinux_file_permission(struct file *file, int mask)
{
        return 0;
}
 
static int rbslinux_file_alloc_security(struct file *file)
{
        return 0;
}
 
static void rbslinux_file_free_security(struct file *file)
{
 
}
 
static int rbslinux_file_ioctl(struct file *file, unsigned int cmd,
                              unsigned long arg)
{
        return 0;
}
/* 
static int file_map_prot_check(struct file *file, unsigned long prot, int shared)
{
        return 0;
}
 
static int rbslinux_file_mmap(struct file *file, unsigned long reqprot,
                             unsigned long prot, unsigned long flags,
                             unsigned long addr, unsigned long addr_only)
{
        return 0;
}
 */
static int rbslinux_file_mprotect(struct vm_area_struct *vma,
                                 unsigned long reqprot,
                                 unsigned long prot)
{
        return 0;
}
 
static int rbslinux_file_lock(struct file *file, unsigned int cmd)
{
        return 0;
}
 
static int rbslinux_file_fcntl(struct file *file, unsigned int cmd,
                              unsigned long arg)
{
        return 0;
}
 
static int rbslinux_file_send_sigiotask(struct task_struct *tsk,
                                       struct fown_struct *fown, int signum)
{
        return 0;
}
 
static int rbslinux_file_receive(struct file *file)
{
        return 0;
}
 /*
static int rbslinux_dentry_open(struct file *file, const struct cred *cred)
{
        return 0;
}
 */
 
/* task security operations */
 
static int rbslinux_task_create(unsigned long clone_flags)
{
        return 0;
}
 
static int rbslinux_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
        return 0;
}
 
static void rbslinux_cred_free(struct cred *cred)
{
       
}
 
static int rbslinux_cred_prepare(struct cred *new, const struct cred *old,
                                gfp_t gfp)
{
        return 0;
}
 
static void rbslinux_cred_transfer(struct cred *new, const struct cred *old)
{
 
}
 
static int rbslinux_kernel_act_as(struct cred *new, u32 secid)
{
        return 0;
}
 
static int rbslinux_kernel_create_files_as(struct cred *new, struct inode *inode)
{
        return 0;
}
 
static int rbslinux_kernel_module_request(char *kmod_name)
{
        return 0;
}
 
static int rbslinux_task_setpgid(struct task_struct *p, pid_t pgid)
{
        return 0;
}
 
static int rbslinux_task_getpgid(struct task_struct *p)
{
        return 0;
}
 
static int rbslinux_task_getsid(struct task_struct *p)
{
        return 0;
}
 
static void rbslinux_task_getsecid(struct task_struct *p, u32 *secid)
{
       
}
 
static int rbslinux_task_setnice(struct task_struct *p, int nice)
{
        return 0;
}
 
static int rbslinux_task_setioprio(struct task_struct *p, int ioprio)
{
        return 0;
}
 
static int rbslinux_task_getioprio(struct task_struct *p)
{
        return 0;
}
 
static int rbslinux_task_setrlimit(struct task_struct *p, unsigned int resource,
                struct rlimit *new_rlim)
{
        return 0;
}
 
static int rbslinux_task_setscheduler(struct task_struct *p)
{
        return 0;
}
 
static int rbslinux_task_getscheduler(struct task_struct *p)
{
        return 0;
}
 
static int rbslinux_task_movememory(struct task_struct *p)
{
        return 0;
}
 
static int rbslinux_task_kill(struct task_struct *p, struct siginfo *info,
                                int sig, u32 secid)
{
        return 0;
}
 
static int rbslinux_task_wait(struct task_struct *p)
{
        return 0;
}
 
static void rbslinux_task_to_inode(struct task_struct *p,
                                  struct inode *inode)
{
 
}
 
 
/* socket security operations */
 
static int rbslinux_socket_create(int family, int type,
                                 int protocol, int kern)
{
        return 0;
}
 
static int rbslinux_socket_post_create(struct socket *sock, int family,
                                      int type, int protocol, int kern)
{
        return 0;
}
 
static int rbslinux_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen)
{
        return 0;
}
 
static int rbslinux_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
{
        return 0;
}
 
static int rbslinux_socket_listen(struct socket *sock, int backlog)
{
        return 0;
}
 
static int rbslinux_socket_accept(struct socket *sock, struct socket *newsock)
{
        return 0;
}
 
static int rbslinux_socket_sendmsg(struct socket *sock, struct msghdr *msg,
                                  int size)
{
        return 0;
}
 
static int rbslinux_socket_recvmsg(struct socket *sock, struct msghdr *msg,
                                  int size, int flags)
{
        return 0;
}
 
static int rbslinux_socket_getsockname(struct socket *sock)
{
        return 0;
}
 
static int rbslinux_socket_getpeername(struct socket *sock)
{
        return 0;
}
 
static int rbslinux_socket_setsockopt(struct socket *sock, int level, int optname)
{
        return 0;
}
 
static int rbslinux_socket_getsockopt(struct socket *sock, int level,
                                     int optname)
{
        return 0;
}
 
static int rbslinux_socket_shutdown(struct socket *sock, int how)
{
        return 0;
}
 
static int rbslinux_socket_unix_stream_connect(struct sock *sock,
                                              struct sock *other,
                                              struct sock *newsk)
{
        return 0;
}
 
static int rbslinux_sb_show_options(struct seq_file *m, struct super_block *sb)
{
        return 0;
}
 
static int rbslinux_set_mnt_opts(struct super_block *sb,
                                struct security_mnt_opts *opts, unsigned long kern_flags, unsigned long *set_kern_flags)
{
        return 0;
}
 
static int rbslinux_socket_unix_may_send(struct socket *sock,
                                        struct socket *other)
{
        return 0;
}
/* 
static int rbslinux_sock_rcv_skb_compat(struct sock *sk, struct sk_buff *skb,
                                       u16 family)
{
        return 0;
}
 */
static int rbslinux_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
        return 0;
}
 
static int rbslinux_socket_getpeersec_stream(struct socket *sock, char __user *optval,
                                            int __user *optlen, unsigned len)
{
        return 0;
}
 
static int rbslinux_socket_getpeersec_dgram(struct socket *sock, struct sk_buff *skb, u32 *secid)
{
        return 0;
}
 
static int rbslinux_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
{
        return 0;
}
 
static void rbslinux_sk_free_security(struct sock *sk)
{
       
}
 
static void rbslinux_sk_clone_security(const struct sock *sk, struct sock *newsk)
{
       
}
 
static void rbslinux_sk_getsecid(struct sock *sk, u32 *secid)
{
       
}
 
static void rbslinux_sock_graft(struct sock *sk, struct socket *parent)
{
       
}
 
static int rbslinux_inet_conn_request(struct sock *sk, struct sk_buff *skb,
                                     struct request_sock *req)
{
        return 0;
}
 
static void rbslinux_inet_csk_clone(struct sock *newsk,
                                   const struct request_sock *req)
{
       
}
 
static void rbslinux_inet_conn_established(struct sock *sk, struct sk_buff *skb)
{
       
}
 
static int rbslinux_secmark_relabel_packet(u32 sid)
{
        return 0;
}
 
static void rbslinux_secmark_refcount_inc(void)
{
 
}
 
static void rbslinux_secmark_refcount_dec(void)
{
       
}
 
static void rbslinux_req_classify_flow(const struct request_sock *req,
                                      struct flowi *fl)
{
       
}
 
static int rbslinux_tun_dev_create(void)
{
        return 0;
}
/* 
static void rbslinux_tun_dev_post_create(struct sock *sk)
{
       
}
 */
static int rbslinux_tun_dev_attach(struct sock *sk,void *security)
{
        return 0;
}
/* 
static int rbslinux_nlmsg_perm(struct sock *sk, struct sk_buff *skb)
{
        return 0;
}
 */
 
static int rbslinux_netlink_send(struct sock *sk, struct sk_buff *skb)
{
        return 0;
}
/* 
static int rbslinux_netlink_recv(struct sk_buff *skb, int capability)
{
        return 0;
}
*//*
static int ipc_alloc_security(struct task_struct *task,
                              struct kern_ipc_perm *perm,
                              u16 sclass)
{
        return 0;
}
 
static void ipc_free_security(struct kern_ipc_perm *perm)
{
       
}
 */
/*static int msg_msg_alloc_security(struct msg_msg *msg)
{
        return 0;
}
 
static void msg_msg_free_security(struct msg_msg *msg)
{
       
}
 
static int ipc_has_perm(struct kern_ipc_perm *ipc_perms,
                        u32 perms)
{
        return 0;
}
 */
static int rbslinux_msg_msg_alloc_security(struct msg_msg *msg)
{
        return 0;
}
 
static void rbslinux_msg_msg_free_security(struct msg_msg *msg)
{
       
}
 
static int rbslinux_msg_queue_alloc_security(struct msg_queue *msq)
{
        return 0;
}
 
static void rbslinux_msg_queue_free_security(struct msg_queue *msq)
{
       
}
 
static int rbslinux_msg_queue_associate(struct msg_queue *msq, int msqflg)
{
        return 0;
}
 
static int rbslinux_msg_queue_msgctl(struct msg_queue *msq, int cmd)
{
        return 0;
}
 
static int rbslinux_msg_queue_msgsnd(struct msg_queue *msq, struct msg_msg *msg, int msqflg)
{
        return 0;
}
 
static int rbslinux_msg_queue_msgrcv(struct msg_queue *msq, struct msg_msg *msg,
                                    struct task_struct *target,
                                    long type, int mode)
{
        return 0;
}
 
 
/* Shared Memory security operations */
 
static int rbslinux_shm_alloc_security(struct shmid_kernel *shp)
{
        return 0;
}
 
static void rbslinux_shm_free_security(struct shmid_kernel *shp)
{
       
}
 
static int rbslinux_shm_associate(struct shmid_kernel *shp, int shmflg)
{
        return 0;
}
 
static int rbslinux_shm_shmctl(struct shmid_kernel *shp, int cmd)
{
        return 0;
}
 
static int rbslinux_shm_shmat(struct shmid_kernel *shp,
                             char __user *shmaddr, int shmflg)
{
        return 0;
}
 
 
/* Semaphore security operations */
 
static int rbslinux_sem_alloc_security(struct sem_array *sma)
{
return 0;
}
 
static void rbslinux_sem_free_security(struct sem_array *sma)
{
 
}
 
static int rbslinux_sem_associate(struct sem_array *sma, int semflg)
{
        return 0;
}
 
static int rbslinux_sem_semctl(struct sem_array *sma, int cmd)
{
        return 0;
}
 
static int rbslinux_sem_semop(struct sem_array *sma,
                             struct sembuf *sops, unsigned nsops, int alter)
{
        return 0;
}
 
static int rbslinux_ipc_permission(struct kern_ipc_perm *ipcp, short flag)
{
        return 0;
}
 
static void rbslinux_ipc_getsecid(struct kern_ipc_perm *ipcp, u32 *secid)
{
 
}
 
static void rbslinux_d_instantiate(struct dentry *dentry, struct inode *inode)
{
       
}
 
static int rbslinux_getprocattr(struct task_struct *p,
                               char *name, char **value)
{
        return 0;
}
 
static int rbslinux_setprocattr(struct task_struct *p,
                               char *name, void *value, size_t size)
{
        return 0;
}
 
static int rbslinux_secid_to_secctx(u32 secid, char **secdata, u32 *seclen)
{
        return 0;
}
 
static int rbslinux_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid)
{
        return 0;
}
 
static void rbslinux_release_secctx(char *secdata, u32 seclen)
{
       
}
 
static int rbslinux_inode_notifysecctx(struct inode *inode, void *ctx, u32 ctxlen)
{
        return 0;
}
 
static int rbslinux_inode_setsecctx(struct dentry *dentry, void *ctx, u32 ctxlen)
{
        return 0;
}
 
static int rbslinux_inode_getsecctx(struct inode *inode, void **ctx, u32 *ctxlen)
{
        return 0;
}
 
 
//STRUCTS//////////////////////////////////////////////////////////////////////
static struct security_operations rbslinux_ops = {
        .name =                         "rbslinux",
 
        .ptrace_access_check            =               rbslinux_ptrace_access_check,
        .ptrace_traceme                         =               rbslinux_ptrace_traceme,
        .capget                                         =               rbslinux_capget,
        .capset                                         =               rbslinux_capset,
        .capable                                        =               rbslinux_capable,
        .quotactl                                       =               rbslinux_quotactl,
        .quota_on                                       =               rbslinux_quota_on,
        .syslog                                         =               rbslinux_syslog,
        .vm_enough_memory                       =               rbslinux_vm_enough_memory,
 
        .netlink_send                           =               rbslinux_netlink_send,
 
        .bprm_set_creds                         =               rbslinux_bprm_set_creds,
        .bprm_committing_creds          =               rbslinux_bprm_committing_creds,
        .bprm_committed_creds           =               rbslinux_bprm_committed_creds,
        .bprm_secureexec                        =               rbslinux_bprm_secureexec,
 
        .sb_alloc_security                      =               rbslinux_sb_alloc_security,
        .sb_free_security                       =               rbslinux_sb_free_security,
        .sb_copy_data                           =               rbslinux_sb_copy_data,
        .sb_remount                             =               rbslinux_sb_remount,
        .sb_kern_mount                          =               rbslinux_sb_kern_mount,
        .sb_show_options                        =               rbslinux_sb_show_options,
        .sb_statfs                                      =               rbslinux_sb_statfs,
        .sb_mount                                       =               rbslinux_mount,
        .sb_umount                                      =               rbslinux_umount,
        .sb_set_mnt_opts                        =               rbslinux_set_mnt_opts,
        .sb_clone_mnt_opts                      =               rbslinux_sb_clone_mnt_opts,
        .sb_parse_opts_str                      =               rbslinux_parse_opts_str,
 
        .inode_alloc_security           =               rbslinux_inode_alloc_security,
        .inode_free_security            =               rbslinux_inode_free_security,
        .inode_init_security            =               rbslinux_inode_init_security,
        .inode_create                           =               rbslinux_inode_create,
        .inode_link                             =               rbslinux_inode_link,
        .inode_unlink                           =               rbslinux_inode_unlink,
        .inode_symlink                          =               rbslinux_inode_symlink,
        .inode_mkdir                            =               rbslinux_inode_mkdir,
        .inode_rmdir                            =               rbslinux_inode_rmdir,
        .inode_mknod                            =               rbslinux_inode_mknod,
        .inode_rename                           =               rbslinux_inode_rename,
        .inode_readlink                         =               rbslinux_inode_readlink,
        .inode_follow_link                      =               rbslinux_inode_follow_link,
        .inode_permission                       =               rbslinux_inode_permission,
        .inode_setattr                          =               rbslinux_inode_setattr,
        .inode_getattr                          =               rbslinux_inode_getattr,
        .inode_setxattr                         =               rbslinux_inode_setxattr,
        .inode_post_setxattr            =               rbslinux_inode_post_setxattr,
        .inode_getxattr                         =               rbslinux_inode_getxattr,
        .inode_listxattr                        =               rbslinux_inode_listxattr,
        .inode_removexattr                      =               rbslinux_inode_removexattr,
        .inode_getsecurity                      =               rbslinux_inode_getsecurity,
        .inode_setsecurity                      =               rbslinux_inode_setsecurity,
        .inode_listsecurity             =               rbslinux_inode_listsecurity,
        .inode_getsecid                         =               rbslinux_inode_getsecid,
 
        .file_permission                        =               rbslinux_file_permission,
        .file_alloc_security            =               rbslinux_file_alloc_security,
        .file_free_security             =               rbslinux_file_free_security,
        .file_ioctl                             =               rbslinux_file_ioctl,
      //  .file_mmap                                      =               rbslinux_file_mmap,
        .file_mprotect                          =               rbslinux_file_mprotect,
        .file_lock                                      =               rbslinux_file_lock,
        .file_fcntl                             =               rbslinux_file_fcntl,
        .file_set_fowner                        =               rbslinux_file_set_fowner,
        .file_send_sigiotask            =               rbslinux_file_send_sigiotask,
        .file_receive                           =               rbslinux_file_receive,
       
    //    .dentry_open                            =               rbslinux_dentry_open,
 
        .task_create                            =               rbslinux_task_create,
        .cred_alloc_blank                       =               rbslinux_cred_alloc_blank,
        .cred_free                                      =               rbslinux_cred_free,
        .cred_prepare                           =               rbslinux_cred_prepare,
        .cred_transfer                          =               rbslinux_cred_transfer,
        .kernel_act_as                          =               rbslinux_kernel_act_as,
        .kernel_create_files_as         =               rbslinux_kernel_create_files_as,
        .kernel_module_request          =               rbslinux_kernel_module_request,
        .task_setpgid                           =               rbslinux_task_setpgid,
        .task_getpgid                           =               rbslinux_task_getpgid,
        .task_getsid                            =               rbslinux_task_getsid,
        .task_getsecid                          =               rbslinux_task_getsecid,
        .task_setnice                           =               rbslinux_task_setnice,
        .task_setioprio                         =               rbslinux_task_setioprio,
        .task_getioprio                         =               rbslinux_task_getioprio,
        .task_setrlimit                         =               rbslinux_task_setrlimit,
        .task_setscheduler                      =               rbslinux_task_setscheduler,
        .task_getscheduler                      =               rbslinux_task_getscheduler,
        .task_movememory                        =               rbslinux_task_movememory,
        .task_kill                                      =               rbslinux_task_kill,
        .task_wait                                      =               rbslinux_task_wait,
        .task_to_inode                          =               rbslinux_task_to_inode,
 
        .ipc_permission                         =               rbslinux_ipc_permission,
        .ipc_getsecid                           =               rbslinux_ipc_getsecid,
 
        .msg_msg_alloc_security         =               rbslinux_msg_msg_alloc_security,
        .msg_msg_free_security          =               rbslinux_msg_msg_free_security,
 
        .msg_queue_alloc_security       =               rbslinux_msg_queue_alloc_security,
        .msg_queue_free_security        =               rbslinux_msg_queue_free_security,
        .msg_queue_associate            =               rbslinux_msg_queue_associate,
        .msg_queue_msgctl                       =               rbslinux_msg_queue_msgctl,
        .msg_queue_msgsnd                       =               rbslinux_msg_queue_msgsnd,
        .msg_queue_msgrcv                       =               rbslinux_msg_queue_msgrcv,
 
        .shm_alloc_security             =               rbslinux_shm_alloc_security,
        .shm_free_security                      =               rbslinux_shm_free_security,
        .shm_associate                          =               rbslinux_shm_associate,
        .shm_shmctl                             =               rbslinux_shm_shmctl,
        .shm_shmat                                      =               rbslinux_shm_shmat,
 
        .sem_alloc_security             =               rbslinux_sem_alloc_security,
        .sem_free_security                      =               rbslinux_sem_free_security,
        .sem_associate                          =               rbslinux_sem_associate,
        .sem_semctl                             =               rbslinux_sem_semctl,
        .sem_semop                                      =               rbslinux_sem_semop,
 
        .d_instantiate                          =               rbslinux_d_instantiate,
 
        .getprocattr                            =               rbslinux_getprocattr,
        .setprocattr                            =               rbslinux_setprocattr,
 
        .secid_to_secctx                        =               rbslinux_secid_to_secctx,
        .secctx_to_secid                        =               rbslinux_secctx_to_secid,
        .release_secctx                         =               rbslinux_release_secctx,
        .inode_notifysecctx             =               rbslinux_inode_notifysecctx,
        .inode_setsecctx                        =               rbslinux_inode_setsecctx,
        .inode_getsecctx                        =               rbslinux_inode_getsecctx,
 
        .unix_stream_connect            =               rbslinux_socket_unix_stream_connect,
        .unix_may_send                          =               rbslinux_socket_unix_may_send,
 
        .socket_create                          =               rbslinux_socket_create,
        .socket_post_create             =               rbslinux_socket_post_create,
        .socket_bind                            =               rbslinux_socket_bind,
        .socket_connect                         =               rbslinux_socket_connect,
        .socket_listen                          =               rbslinux_socket_listen,
        .socket_accept                          =               rbslinux_socket_accept,
        .socket_sendmsg                         =               rbslinux_socket_sendmsg,
        .socket_recvmsg                         =               rbslinux_socket_recvmsg,
        .socket_getsockname             =               rbslinux_socket_getsockname,
        .socket_getpeername                     =               rbslinux_socket_getpeername,
        .socket_getsockopt                      =               rbslinux_socket_getsockopt,
        .socket_setsockopt                      =               rbslinux_socket_setsockopt,
        .socket_shutdown                        =               rbslinux_socket_shutdown,
        .socket_sock_rcv_skb            =               rbslinux_socket_sock_rcv_skb,
        .socket_getpeersec_stream       =               rbslinux_socket_getpeersec_stream,
        .socket_getpeersec_dgram        =               rbslinux_socket_getpeersec_dgram,
        .sk_alloc_security                      =               rbslinux_sk_alloc_security,
        .sk_free_security                       =               rbslinux_sk_free_security,
        .sk_clone_security                      =               rbslinux_sk_clone_security,
        .sk_getsecid                            =               rbslinux_sk_getsecid,
        .sock_graft                             =               rbslinux_sock_graft,
        .inet_conn_request                      =               rbslinux_inet_conn_request,
        .inet_csk_clone                         =               rbslinux_inet_csk_clone,
        .inet_conn_established          =               rbslinux_inet_conn_established,
        .secmark_relabel_packet         =               rbslinux_secmark_relabel_packet,
        .secmark_refcount_inc           =               rbslinux_secmark_refcount_inc,
        .secmark_refcount_dec           =               rbslinux_secmark_refcount_dec,
        .req_classify_flow                      =               rbslinux_req_classify_flow,
        .tun_dev_create                         =               rbslinux_tun_dev_create,
     //   .tun_dev_post_create            =               rbslinux_tun_dev_post_create,
        .tun_dev_attach                         =               rbslinux_tun_dev_attach,
};
 
 
static __init int rbslinux_init(void)
{
    
    if (!security_module_enable(&rbslinux_ops)) {
                printk(KERN_INFO "Failed to register rbslinux module\n");
                return 0;
    }
    
    if (register_security(&rbslinux_ops)) 
                printk(KERN_INFO "Failed to register rbslinux module\n");
    else
                printk(KERN_ALERT "rbslinux started");
       
    return 0;
}
 
 
security_initcall(rbslinux_init);




