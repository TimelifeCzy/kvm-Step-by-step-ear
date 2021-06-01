#pragma once

#ifndef __LINUX_KVM_H
#define __LINUX_KVM_H


#include <asm/types.h>
#include <stdint.h>

#define KVM_MEM_LOG_DIRTY_PAGES  1UL


#define KVM_EXIT_TYPE_FAIL_ENTRY 1
#define KVM_EXIT_TYPE_VM_EXIT    2

enum kvm_exit_reason {
	KVM_EXIT_UNKNOWN = 0,
	KVM_EXIT_EXCEPTION = 1,
	KVM_EXIT_IO = 2,
	KVM_EXIT_CPUID = 3,
	KVM_EXIT_DEBUG = 4,
   	KVM_EXIT_HLT = 5,
	KVM_EXIT_MMIO = 6,
	KVM_EXIT_IRQ_WINDOW_OPEN = 7,
	KVM_EXIT_SHUTDOWN = 8,
};



struct translation_cache {
	unsigned long linear;
	void *physical;
};

struct kvm_callbacks {
	int(*cpuid)(void *opaque,
		uint64_t *rax, uint64_t *rbx, uint64_t *rcx, uint64_t *rdx);
	int(*inb)(void *opaque, uint16_t addr, uint8_t *data);
	int(*inw)(void *opaque, uint16_t addr, uint16_t *data);
	int(*inl)(void *opaque, uint16_t addr, uint32_t *data);
	int(*outb)(void *opaque, uint16_t addr, uint8_t data);
	int(*outw)(void *opaque, uint16_t addr, uint16_t data);
	int(*outl)(void *opaque, uint16_t addr, uint32_t data);
	//int(*readb)(void *opaque, uint64_t addr, uint8_t *data);
	//int(*readw)(void *opaque, uint64_t addr, uint16_t *data);
	//int(*readl)(void *opaque, uint64_t addr, uint32_t *data);
	//int(*readq)(void *opaque, uint64_t addr, uint64_t *data);
	//int(*writeb)(void *opaque, uint64_t addr, uint8_t data);
	//int(*writew)(void *opaque, uint64_t addr, uint16_t data);
	//int(*writel)(void *opaque, uint64_t addr, uint32_t data);
	//int(*writeq)(void *opaque, uint64_t addr, uint64_t data);
	int(*debug)(void *opaque, int vcpu);
	int(*halt)(void *opaque, int vcpu);
	int(*io_window)(void *opaque);
};

struct kvm_context {
	int fd;
	struct kvm_callbacks *callbacks;
	void *opaque;
	void *physical_memory;
};

struct kvm_context;

typedef struct kvm_context *kvm_context_t;

/* for KVM_CREATE_MEMORY_REGION */
struct kvm_memory_region {
	__u32 slot;
	__u32 flags;
	unsigned long long guest_phys_addr;
	unsigned long long memory_size; /* bytes */
};


/* for KVM_RUN */
struct kvm_run {
	/* in */
	__u32 vcpu;
	__u32 emulated;  /* skip current instruction */
	__u32 mmio_completed; /* mmio request completed */

	/* out */
	__u32 exit_type;
	__u32 exit_reason;
	__u32 instruction_length;
	union {
		/* KVM_EXIT_UNKNOWN */
		struct {
			__u32 hardware_exit_reason;
		} hw;
		/* KVM_EXIT_EXCEPTION */
		struct {
			__u32 exception;
			__u32 error_code;
		} ex;
		/* KVM_EXIT_IO */
		struct {
#define KVM_EXIT_IO_IN  0
#define KVM_EXIT_IO_OUT 1
			__u8 direction;
			__u8 size; /* bytes */
			__u8 string;
			__u8 string_down;
			__u8 rep;
			__u8 pad;
			__u16 port;
			unsigned long long count;
			union {
				unsigned long long address;
				__u32 value;
			};
		} io;
		struct {
		} debug;
		/* KVM_EXIT_MMIO */
		struct {
			unsigned long long phys_addr;
			__u8  data[8];
			__u32 len;
			__u8  is_write;
		} mmio;
	};
};

/* for KVM_GET_REGS and KVM_SET_REGS */
struct kvm_regs {
	/* in */
	__u32 vcpu;
	__u32 padding;

	/* out (KVM_GET_REGS) / in (KVM_SET_REGS) */
	unsigned long long rax, rbx, rcx, rdx;
	unsigned long long rsi, rdi, rsp, rbp;
	unsigned long long r8, r9, r10, r11;
	unsigned long long r12, r13, r14, r15;
	unsigned long long rip, rflags;
};

struct kvm_segment {
	unsigned long long base;
	__u32 limit;
	__u16 selector;
	__u8  type;
	__u8  present, dpl, db, s, l, g, avl;
	__u8  unusable;
	__u8  padding;
};

struct kvm_dtable {
	unsigned long long base;
	__u16 limit;
	__u16 padding[3];
};

/* for KVM_GET_SREGS and KVM_SET_SREGS */
struct kvm_sregs {
	/* in */
	__u32 vcpu;
	__u32 padding;

	/* out (KVM_GET_SREGS) / in (KVM_SET_SREGS) */
	struct kvm_segment cs, ds, es, fs, gs, ss;
	struct kvm_segment tr, ldt;
	struct kvm_dtable gdt, idt;
	unsigned long long cr0, cr2, cr3, cr4, cr8;
	unsigned long long efer;
	unsigned long long apic_base;

	/* out (KVM_GET_SREGS) */
	__u32 pending_int;
	__u32 padding2;
};

/* for KVM_TRANSLATE */
struct kvm_translation {
	/* in */
	unsigned long long linear_address;
	__u32 vcpu;
	__u32 padding;

	/* out */
	unsigned long long physical_address;
	__u8  valid;
	__u8  writeable;
	__u8  usermode;
};

/* for KVM_INTERRUPT */
struct kvm_interrupt {
	/* in */
	__u32 vcpu;
	__u32 irq;
};

struct kvm_breakpoint {
	__u32 enabled;
	__u32 padding;
	unsigned long long address;
};

/* for KVM_DEBUG_GUEST */
struct kvm_debug_guest {
	/* int */
	__u32 vcpu;
	__u32 enabled;
	struct kvm_breakpoint breakpoints[4];
	__u32 singlestep;
};


#define KVMIO 0xAE

#define KVM_RUN                   _IOWR(KVMIO, 2, struct kvm_run)
#define KVM_GET_REGS              _IOWR(KVMIO, 3, struct kvm_regs)
#define KVM_SET_REGS              _IOW(KVMIO, 4, struct kvm_regs)
#define KVM_GET_SREGS             _IOWR(KVMIO, 5, struct kvm_sregs)
#define KVM_SET_SREGS             _IOW(KVMIO, 6, struct kvm_sregs)
#define KVM_TRANSLATE             _IOWR(KVMIO, 7, struct kvm_translation)
#define KVM_INTERRUPT             _IOW(KVMIO, 8, struct kvm_interrupt)
#define KVM_DEBUG_GUEST           _IOW(KVMIO, 9, struct kvm_debug_guest)
#define KVM_SET_MEMORY_REGION     _IOW(KVMIO, 10, struct kvm_memory_region)
#define KVM_CREATE_VCPU           _IOW(KVMIO, 11, int /* vcpu_slot */)
#define KVM_GET_DIRTY_LOG         _IOW(KVMIO, 12, struct kvm_dirty_log)

kvm_context_t kvm_init(struct kvm_callbacks *callbacks,
	void *opaque);
int kvm_create(kvm_context_t kvm,
	unsigned long phys_mem_bytes,
	void **phys_mem);
int kvm_run(kvm_context_t kvm, int vcpu);
int kvm_get_regs(kvm_context_t, int vcpu, struct kvm_regs *regs);
int kvm_set_regs(kvm_context_t, int vcpu, struct kvm_regs *regs);
int kvm_get_sregs(kvm_context_t, int vcpu, struct kvm_sregs *regs);
int kvm_set_sregs(kvm_context_t, int vcpu, struct kvm_sregs *regs);
int kvm_inject_irq(kvm_context_t, int vcpu, unsigned irq);
int kvm_guest_debug(kvm_context_t, int vcpu, struct kvm_debug_guest *dbg);
void kvm_show_regs(kvm_context_t, int vcpu);
void *kvm_create_phys_mem(kvm_context_t, unsigned long phys_start,
	unsigned long len, int slot, int log, int writable);
void kvm_destroy_phys_mem(kvm_context_t, unsigned long phys_start,
	unsigned long len);
void kvm_get_dirty_pages(kvm_context_t, int slot, void *buf);
void load_file(void *mem, const char *fname);


#endif


