/* 2017-05-30: File added by Sony Corporation */
#ifndef CREATE_SYSCALL_TABLE

#else	/* CREATE_SYSCALL_TABLE */

#define OVERRIDE_TABLE_32_clone
TRACE_SYSCALL_TABLE(clone, clone, 4120, 0)

#endif /* CREATE_SYSCALL_TABLE */
