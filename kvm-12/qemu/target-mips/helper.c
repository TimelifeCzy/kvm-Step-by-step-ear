/*
 *  MIPS emulation helpers for qemu.
 * 
 *  Copyright (c) 2004-2005 Jocelyn Mayer
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <signal.h>
#include <assert.h>

#include "cpu.h"
#include "exec-all.h"

enum {
    TLBRET_DIRTY = -4,
    TLBRET_INVALID = -3,
    TLBRET_NOMATCH = -2,
    TLBRET_BADADDR = -1,
    TLBRET_MATCH = 0
};

/* MIPS32 4K MMU emulation */
#ifdef MIPS_USES_R4K_TLB
static int map_address (CPUState *env, target_ulong *physical, int *prot,
                        target_ulong address, int rw, int access_type)
{
    target_ulong tag = address & (TARGET_PAGE_MASK << 1);
    uint8_t ASID = env->CP0_EntryHi & 0xFF;
    tlb_t *tlb;
    int i, n;

    for (i = 0; i < MIPS_TLB_NB; i++) {
        tlb = &env->tlb[i];
        /* Check ASID, virtual page number & size */
        if ((tlb->G == 1 || tlb->ASID == ASID) &&
            tlb->VPN == tag && address < tlb->end2) {
            /* TLB match */
            n = (address >> TARGET_PAGE_BITS) & 1;
            /* Check access rights */
           if (!(n ? tlb->V1 : tlb->V0))
                return TLBRET_INVALID;
           if (rw == 0 || (n ? tlb->D1 : tlb->D0)) {
                *physical = tlb->PFN[n] | (address & ~TARGET_PAGE_MASK);
                *prot = PAGE_READ;
                if (n ? tlb->D1 : tlb->D0)
                    *prot |= PAGE_WRITE;
                return TLBRET_MATCH;
            }
            return TLBRET_DIRTY;
        }
    }
    return TLBRET_NOMATCH;
}
#endif

static int get_physical_address (CPUState *env, target_ulong *physical,
                                int *prot, target_ulong address,
                                int rw, int access_type)
{
    /* User mode can only access useg */
    int user_mode = (env->hflags & MIPS_HFLAG_MODE) == MIPS_HFLAG_UM;
    int ret = TLBRET_MATCH;

#if 0
    if (logfile) {
        fprintf(logfile, "user mode %d h %08x\n",
                user_mode, env->hflags);
    }
#endif
    if (user_mode && address > 0x7FFFFFFFUL)
        return TLBRET_BADADDR;
    if (address < 0x80000000UL) {
        if (!(env->hflags & MIPS_HFLAG_ERL)) {
#ifdef MIPS_USES_R4K_TLB
            ret = map_address(env, physical, prot, address, rw, access_type);
#else
            *physical = address + 0x40000000UL;
            *prot = PAGE_READ | PAGE_WRITE;
#endif
        } else {
            *physical = address;
            *prot = PAGE_READ | PAGE_WRITE;
        }
    } else if (address < 0xA0000000UL) {
        /* kseg0 */
        /* XXX: check supervisor mode */
        *physical = address - 0x80000000UL;
        *prot = PAGE_READ | PAGE_WRITE;
    } else if (address < 0xC0000000UL) {
        /* kseg1 */
        /* XXX: check supervisor mode */
        *physical = address - 0xA0000000UL;
        *prot = PAGE_READ | PAGE_WRITE;
    } else if (address < 0xE0000000UL) {
        /* kseg2 */
#ifdef MIPS_USES_R4K_TLB
        ret = map_address(env, physical, prot, address, rw, access_type);
#else
        *physical = address;
        *prot = PAGE_READ | PAGE_WRITE;
#endif
    } else {
        /* kseg3 */
        /* XXX: check supervisor mode */
        /* XXX: debug segment is not emulated */
#ifdef MIPS_USES_R4K_TLB
        ret = map_address(env, physical, prot, address, rw, access_type);
#else
        *physical = address;
        *prot = PAGE_READ | PAGE_WRITE;
#endif
    }
#if 0
    if (logfile) {
        fprintf(logfile, "%08x %d %d => %08x %d (%d)\n", address, rw,
                access_type, *physical, *prot, ret);
    }
#endif

    return ret;
}

#if defined(CONFIG_USER_ONLY) 
target_ulong cpu_get_phys_page_debug(CPUState *env, target_ulong addr)
{
    return addr;
}
#else
target_ulong cpu_get_phys_page_debug(CPUState *env, target_ulong addr)
{
    target_ulong phys_addr;
    int prot;

    if (get_physical_address(env, &phys_addr, &prot, addr, 0, ACCESS_INT) != 0)
        return -1;
    return phys_addr;
}

void cpu_mips_init_mmu (CPUState *env)
{
}
#endif /* !defined(CONFIG_USER_ONLY) */

int cpu_mips_handle_mmu_fault (CPUState *env, target_ulong address, int rw,
                               int is_user, int is_softmmu)
{
    target_ulong physical;
    int prot;
    int exception = 0, error_code = 0;
    int access_type;
    int ret = 0;

    if (logfile) {
#if 0
        cpu_dump_state(env, logfile, fprintf, 0);
#endif
        fprintf(logfile, "%s pc %08x ad %08x rw %d is_user %d smmu %d\n",
                __func__, env->PC, address, rw, is_user, is_softmmu);
    }

    rw &= 1;

    /* data access */
    /* XXX: put correct access by using cpu_restore_state()
       correctly */
    access_type = ACCESS_INT;
    if (env->user_mode_only) {
        /* user mode only emulation */
        ret = TLBRET_NOMATCH;
        goto do_fault;
    }
    ret = get_physical_address(env, &physical, &prot,
                               address, rw, access_type);
    if (logfile) {
        fprintf(logfile, "%s address=%08x ret %d physical %08x prot %d\n",
                __func__, address, ret, physical, prot);
    }
    if (ret == TLBRET_MATCH) {
       ret = tlb_set_page(env, address & TARGET_PAGE_MASK,
                          physical & TARGET_PAGE_MASK, prot,
                          is_user, is_softmmu);
    } else if (ret < 0) {
    do_fault:
        switch (ret) {
        default:
        case TLBRET_BADADDR:
            /* Reference to kernel address from user mode or supervisor mode */
            /* Reference to supervisor address from user mode */
            if (rw)
                exception = EXCP_AdES;
            else
                exception = EXCP_AdEL;
            break;
        case TLBRET_NOMATCH:
            /* No TLB match for a mapped address */
            if (rw)
                exception = EXCP_TLBS;
            else
                exception = EXCP_TLBL;
            error_code = 1;
            break;
        case TLBRET_INVALID:
            /* TLB match with no valid bit */
            if (rw)
                exception = EXCP_TLBS;
            else
                exception = EXCP_TLBL;
            break;
        case TLBRET_DIRTY:
            /* TLB match but 'D' bit is cleared */
            exception = EXCP_LTLBL;
            break;
                
        }
        /* Raise exception */
        env->CP0_BadVAddr = address;
        env->CP0_Context = (env->CP0_Context & 0xff800000) |
	                   ((address >> 9) &   0x007ffff0);
        env->CP0_EntryHi =
            (env->CP0_EntryHi & 0xFF) | (address & (TARGET_PAGE_MASK << 1));
        env->exception_index = exception;
        env->error_code = error_code;
        ret = 1;
    }

    return ret;
}

void do_interrupt (CPUState *env)
{
    target_ulong pc, offset;
    int cause = -1;

    if (logfile && env->exception_index != EXCP_EXT_INTERRUPT) {
        fprintf(logfile, "%s enter: PC %08x EPC %08x cause %d excp %d\n",
                __func__, env->PC, env->CP0_EPC, cause, env->exception_index);
    }
    if (env->exception_index == EXCP_EXT_INTERRUPT &&
        (env->hflags & MIPS_HFLAG_DM))
        env->exception_index = EXCP_DINT;
    offset = 0x180;
    switch (env->exception_index) {
    case EXCP_DSS:
        env->CP0_Debug |= 1 << CP0DB_DSS;
        /* Debug single step cannot be raised inside a delay slot and
         * resume will always occur on the next instruction
         * (but we assume the pc has always been updated during
         *  code translation).
         */
        env->CP0_DEPC = env->PC;
        goto enter_debug_mode;
    case EXCP_DINT:
        env->CP0_Debug |= 1 << CP0DB_DINT;
        goto set_DEPC;
    case EXCP_DIB:
        env->CP0_Debug |= 1 << CP0DB_DIB;
        goto set_DEPC;
    case EXCP_DBp:
        env->CP0_Debug |= 1 << CP0DB_DBp;
        goto set_DEPC;
    case EXCP_DDBS:
        env->CP0_Debug |= 1 << CP0DB_DDBS;
        goto set_DEPC;
    case EXCP_DDBL:
        env->CP0_Debug |= 1 << CP0DB_DDBL;
        goto set_DEPC;
    set_DEPC:
        if (env->hflags & MIPS_HFLAG_BMASK) {
            /* If the exception was raised from a delay slot,
             * come back to the jump
             */
            env->CP0_DEPC = env->PC - 4;
            env->hflags &= ~MIPS_HFLAG_BMASK;
        } else {
            env->CP0_DEPC = env->PC;
        }
    enter_debug_mode:
        env->hflags |= MIPS_HFLAG_DM;
        /* EJTAG probe trap enable is not implemented... */
        pc = 0xBFC00480;
        break;
    case EXCP_RESET:
#ifdef MIPS_USES_R4K_TLB
        env->CP0_random = MIPS_TLB_NB - 1;
#endif
        env->CP0_Wired = 0;
        env->CP0_Config0 = MIPS_CONFIG0;
#if defined (MIPS_CONFIG1)
        env->CP0_Config1 = MIPS_CONFIG1;
#endif
#if defined (MIPS_CONFIG2)
        env->CP0_Config2 = MIPS_CONFIG2;
#endif
#if defined (MIPS_CONFIG3)
        env->CP0_Config3 = MIPS_CONFIG3;
#endif
        env->CP0_WatchLo = 0;
        env->CP0_Status = (1 << CP0St_CU0) | (1 << CP0St_BEV);
        goto set_error_EPC;
    case EXCP_SRESET:
        env->CP0_Status = (1 << CP0St_CU0) | (1 << CP0St_BEV) |
            (1 << CP0St_SR);
        env->CP0_WatchLo = 0;
        goto set_error_EPC;
    case EXCP_NMI:
        env->CP0_Status = (1 << CP0St_CU0) | (1 << CP0St_BEV) |
            (1 << CP0St_NMI);
    set_error_EPC:
        if (env->hflags & MIPS_HFLAG_BMASK) {
            /* If the exception was raised from a delay slot,
             * come back to the jump
             */
            env->CP0_ErrorEPC = env->PC - 4;
            env->hflags &= ~MIPS_HFLAG_BMASK;
        } else {
            env->CP0_ErrorEPC = env->PC;
        }
        env->hflags |= MIPS_HFLAG_ERL;
	env->CP0_Status |= (1 << CP0St_ERL);
        pc = 0xBFC00000;
        break;
    case EXCP_MCHECK:
        cause = 24;
        goto set_EPC;
    case EXCP_EXT_INTERRUPT:
        cause = 0;
        if (env->CP0_Cause & (1 << CP0Ca_IV))
            offset = 0x200;
        goto set_EPC;
    case EXCP_DWATCH:
        cause = 23;
        /* XXX: TODO: manage defered watch exceptions */
        goto set_EPC;
    case EXCP_AdEL:
    case EXCP_AdES:
        cause = 4;
        goto set_EPC;
    case EXCP_TLBL:
        cause = 2;
        if (env->error_code == 1 && !(env->hflags & MIPS_HFLAG_EXL))
            offset = 0x000;
        goto set_EPC;
    case EXCP_IBE:
        cause = 6;
        goto set_EPC;
    case EXCP_DBE:
        cause = 7;
        goto set_EPC;
    case EXCP_SYSCALL:
        cause = 8;
        goto set_EPC;
    case EXCP_BREAK:
        cause = 9;
        goto set_EPC;
    case EXCP_RI:
        cause = 10;
        goto set_EPC;
    case EXCP_CpU:
        cause = 11;
        env->CP0_Cause = (env->CP0_Cause & ~0x03000000) | (env->error_code << 28);
        goto set_EPC;
    case EXCP_OVERFLOW:
        cause = 12;
        goto set_EPC;
    case EXCP_TRAP:
        cause = 13;
        goto set_EPC;
    case EXCP_LTLBL:
        cause = 1;
        goto set_EPC;
    case EXCP_TLBS:
        cause = 3;
        if (env->error_code == 1 && !(env->hflags & MIPS_HFLAG_EXL))
            offset = 0x000;
        goto set_EPC;
    set_EPC:
        if (env->CP0_Status & (1 << CP0St_BEV)) {
            pc = 0xBFC00200;
        } else {
            pc = 0x80000000;
        }
        env->hflags |= MIPS_HFLAG_EXL;
	env->CP0_Status |= (1 << CP0St_EXL);
        pc += offset;
        env->CP0_Cause = (env->CP0_Cause & ~0x7C) | (cause << 2);
        if (env->hflags & MIPS_HFLAG_BMASK) {
            /* If the exception was raised from a delay slot,
             * come back to the jump
             */
            env->CP0_EPC = env->PC - 4;
            env->CP0_Cause |= 0x80000000;
            env->hflags &= ~MIPS_HFLAG_BMASK;
        } else {
            env->CP0_EPC = env->PC;
            env->CP0_Cause &= ~0x80000000;
        }
        break;
    default:
        if (logfile) {
            fprintf(logfile, "Invalid MIPS exception %d. Exiting\n",
                    env->exception_index);
        }
        printf("Invalid MIPS exception %d. Exiting\n", env->exception_index);
        exit(1);
    }
    env->PC = pc;
    if (logfile && env->exception_index != EXCP_EXT_INTERRUPT) {
        fprintf(logfile, "%s: PC %08x EPC %08x cause %d excp %d\n"
                "    S %08x C %08x A %08x D %08x\n",
                __func__, env->PC, env->CP0_EPC, cause, env->exception_index,
                env->CP0_Status, env->CP0_Cause, env->CP0_BadVAddr,
                env->CP0_DEPC);
    }
    env->exception_index = EXCP_NONE;
}
