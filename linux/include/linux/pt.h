#ifndef _LINUX_PT_H
#define _LINUX_PT_H

#include <linux/sched.h>
#include <asm/msr.h>
#include <asm/cpufeature.h>

#define pt_avail() test_cpu_cap(&boot_cpu_data, X86_FEATURE_INTEL_PT)

#define pt_enabled() (native_read_msr(MSR_IA32_RTIT_CTL) & RTIT_CTL_TRACEEN)

void pt_pre_execve(void);

void pt_on_execve(void);

void pt_on_exit(void);

int pt_on_interrupt(struct pt_regs *);

void pt_on_clone(struct task_struct *);

void pt_on_mmap(struct file *, unsigned long, unsigned long,
		unsigned long, unsigned long);

void pt_on_syscall(struct pt_regs *);

#endif
