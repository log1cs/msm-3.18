/* 2017-03-21: File changed by Sony Corporation */
/*
 * Based on arch/arm/mm/proc-macros.S
 *
 * Copyright (C) 2012 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <asm/asm-offsets.h>
#include <asm/thread_info.h>
#ifdef CONFIG_MSM_KEXEC
#include <asm/page.h>
#include <asm/pgtable-hwdef.h>
#include <asm/sysreg.h>
#endif

/*
 * vma_vm_mm - get mm pointer from vma pointer (vma->vm_mm)
 */
	.macro	vma_vm_mm, rd, rn
	ldr	\rd, [\rn, #VMA_VM_MM]
	.endm

/*
 * mmid - get context id from mm pointer (mm->context.id)
 */
	.macro	mmid, rd, rn
	ldr	\rd, [\rn, #MM_CONTEXT_ID]
	.endm

/*
 * dcache_line_size - get the minimum D-cache line size from the CTR register.
 */
	.macro	dcache_line_size, reg, tmp
	mrs	\tmp, ctr_el0			// read CTR
	ubfm	\tmp, \tmp, #16, #19		// cache line size encoding
	mov	\reg, #4			// bytes per word
	lsl	\reg, \reg, \tmp		// actual cache line size
	.endm

/*
 * icache_line_size - get the minimum I-cache line size from the CTR register.
 */
	.macro	icache_line_size, reg, tmp
	mrs	\tmp, ctr_el0			// read CTR
	and	\tmp, \tmp, #0xf		// cache line size encoding
	mov	\reg, #4			// bytes per word
	lsl	\reg, \reg, \tmp		// actual cache line size
	.endm

#ifdef CONFIG_MSM_KEXEC
/*
 * copy_page - copy src to dest using temp registers t1-t8
 */
        .macro copy_page dest:req src:req t1:req t2:req t3:req t4:req t5:req t6:req t7:req t8:req
9998:   ldp     \t1, \t2, [\src]
        ldp     \t3, \t4, [\src, #16]
        ldp     \t5, \t6, [\src, #32]
        ldp     \t7, \t8, [\src, #48]
        add     \src, \src, #64
        stnp    \t1, \t2, [\dest]
        stnp    \t3, \t4, [\dest, #16]
        stnp    \t5, \t6, [\dest, #32]
        stnp    \t7, \t8, [\dest, #48]
        add     \dest, \dest, #64
        tst     \src, #(PAGE_SIZE - 1)
        b.ne    9998b
        .endm
#endif
