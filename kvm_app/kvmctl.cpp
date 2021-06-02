/*
 * Kernel-based Virtual Machine control library
 *
 * This library provides an API to control the kvm hardware virtualization
 * module.
 *
 * Copyright (C) 2006 Qumranet
 *
 * Authors:
 *
 *  Avi Kivity <avi@qumranet.com>
 *  Yaniv Kamay <yaniv@qumranet.com>
 *
 * This work is licensed under the GNU LGPL license, version 2.
 */

#include <sys/ioctl.h>
#include <sys/unistd.h>
#include <sys/fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include "kvmctl.h"


#define EXPECTED_KVM_API_VERSION 2

//#if EXPECTED_KVM_API_VERSION != KVM_API_VERSION
////#error libkvm: userspace and kernel version mismatch
//#endif

#define PAGE_SIZE 4096ul

 /**
  * \brief The KVM context
  *
  * The verbose KVM context
  */
struct kvm_context {
	/// Filedescriptor to /dev/kvm
	int fd;
	/// Callbacks that KVM uses to emulate various unvirtualizable functionality
	struct kvm_callbacks *callbacks;
	void *opaque;
	/// A pointer to the memory used as the physical memory for the guest
	void *physical_memory;
};

struct translation_cache {
	unsigned long linear;
	void *physical;
};

static void translation_cache_init(struct translation_cache *tr)
{
	tr->physical = 0;
}

static int translate(kvm_context_t kvm, int vcpu, struct translation_cache *tr,
	unsigned long linear, void **physical)
{
	unsigned long page = linear & ~(PAGE_SIZE - 1);
	unsigned long offset = linear & (PAGE_SIZE - 1);

	if (!(tr->physical && tr->linear == page)) {
		struct kvm_translation kvm_tr;
		int r;

		kvm_tr.linear_address = page;
		kvm_tr.vcpu = vcpu;

		r = ioctl(kvm->fd, KVM_TRANSLATE, &kvm_tr);
		if (r == -1)
			return -errno;

		if (!kvm_tr.valid)
			return -EFAULT;

		tr->linear = page;
		tr->physical = (void*)((__u64)kvm->physical_memory + kvm_tr.physical_address);
	}
	*physical = (void*)((unsigned long)tr->physical + offset);
	return 0;
}

kvm_context_t kvm_init(struct kvm_callbacks *callbacks,
	void *opaque)
{
	int fd;
	kvm_context_t kvm;
	int r;

	fd = open("/dev/kvm", O_RDWR);
	if (fd == -1) {
		perror("open /dev/kvm");
		return NULL;
	}
	r = ioctl(fd, KVM_GET_API_VERSION, 0);
	if (r == -1) {
		fprintf(stderr, "kvm kernel version too old\n");
		goto out_close;
	}
	if (r < EXPECTED_KVM_API_VERSION) {
		fprintf(stderr, "kvm kernel version too old\n");
		goto out_close;
	}
	if (r > EXPECTED_KVM_API_VERSION) {
		fprintf(stderr, "kvm userspace version too old\n");
		goto out_close;
	}
	kvm = (kvm_context_t)malloc(sizeof(*kvm));
	kvm->fd = fd;
	kvm->callbacks = callbacks;
	kvm->opaque = opaque;
	return kvm;
out_close:
	close(fd);
	return NULL;
}

void kvm_finalize(kvm_context_t kvm)
{
	close(kvm->fd);
	free(kvm);
}

int kvm_create(kvm_context_t kvm, unsigned long memory, void **vm_mem)
{
	unsigned long dosmem = 0xa0000;
	unsigned long exmem = 0xc0000;
	int fd = kvm->fd;
	int r;
	struct kvm_memory_region low_memory = { 0, };
	low_memory.slot = 3;
	low_memory.memory_size = memory < dosmem ? memory : dosmem;
	low_memory.guest_phys_addr = 0;

	struct kvm_memory_region extended_memory = { 0, };
	extended_memory.slot = 0;
	extended_memory.memory_size = memory < exmem ? 0 : memory - exmem;
	extended_memory.guest_phys_addr = exmem;

	/* 640K should be enough. */
	r = ioctl(fd, KVM_SET_MEMORY_REGION, &low_memory);
	if (r == -1) {
		fprintf(stderr, "kvm_create_memory_region: %m\n");
		return -1;
	}
	if (extended_memory.memory_size) {
		r = ioctl(fd, KVM_SET_MEMORY_REGION, &extended_memory);
		if (r == -1) {
			fprintf(stderr, "kvm_create_memory_region: %m\n");
			return -1;
		}
	}

	*vm_mem = mmap(0, memory, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (*vm_mem == MAP_FAILED) {
		fprintf(stderr, "mmap: %m\n");
		return -1;
	}
	kvm->physical_memory = *vm_mem;

	r = ioctl(fd, KVM_CREATE_VCPU, 0);
	if (r == -1) {
		fprintf(stderr, "kvm_create_vcpu: %m\n");
		return -1;
	}
	return 0;
}

void *kvm_create_phys_mem(kvm_context_t kvm, unsigned long phys_start,
	unsigned long len, int slot, int log, int writable)
{
	void *ptr;
	int r;
	int fd = kvm->fd;
	int prot = PROT_READ;
	struct kvm_memory_region memory = {
		.slot = slot,
		.memory_size = len,
		.guest_phys_addr = phys_start,
		.flags = log ? KVM_MEM_LOG_DIRTY_PAGES : 0,
	};

	r = ioctl(fd, KVM_SET_MEMORY_REGION, &memory);
	if (r == -1)
		return 0;

	if (writable)
		prot |= PROT_WRITE;

	ptr = mmap(0, len, prot, MAP_SHARED, fd, phys_start);
	if (ptr == MAP_FAILED)
		return 0;
	return ptr;
}

void kvm_destroy_phys_mem(kvm_context_t kvm, unsigned long phys_start,
	unsigned long len)
{
	printf("kvm_destroy_phys_mem: implement me\n");
	exit(1);
}


void kvm_get_dirty_pages(kvm_context_t kvm, int slot, void *buf)
{
	int r;
	struct kvm_dirty_log log = {
		.slot = slot,
	};

	log.dirty_bitmap = buf;

	r = ioctl(kvm->fd, KVM_GET_DIRTY_LOG, &log);
	if (r == -1)
		exit(1);
}

static int more_io(struct kvm_run *run, int first_time)
{
	if (!run->io.rep)
		return first_time;
	else
		return run->io.count != 0;
}

static int handle_io(kvm_context_t kvm, struct kvm_run *run)
{
	uint16_t addr = run->io.port;
	struct kvm_regs regs;
	int first_time = 1;
	int delta;
	struct translation_cache tr;

	translation_cache_init(&tr);

	regs.vcpu = run->vcpu;
	ioctl(kvm->fd, KVM_GET_REGS, &regs);

	delta = run->io.string_down ? -run->io.size : run->io.size;

	while (more_io(run, first_time)) {
		void *value_addr;
		int r;

		if (!run->io.string)
			value_addr = &regs.rax;
		else {
			r = translate(kvm, run->vcpu, &tr, run->io.address,
				&value_addr);
			if (r) {
				fprintf(stderr, "failed translating I/O address %x\n",
					run->io.address);
				exit(1);
			}
		}

		switch (run->io.direction) {
		case KVM_EXIT_IO_IN: {
			switch (run->io.size) {
			case 1: {
				uint8_t value;
				r = kvm->callbacks->inb(kvm->opaque, addr, &value);
				*(uint8_t *)value_addr = value;
				break;
			}
			case 2: {
				uint16_t value;
				r = kvm->callbacks->inw(kvm->opaque, addr, &value);
				*(uint16_t *)value_addr = value;
				break;
			}
			case 4: {
				uint32_t value;
				r = kvm->callbacks->inl(kvm->opaque, addr, &value);
				*(uint32_t *)value_addr = value;
				break;
			}
			default:
				fprintf(stderr, "bad I/O size\n");
				exit(1);
			}
			break;
		}
		case KVM_EXIT_IO_OUT:
			switch (run->io.size) {
			case 1:
				r = kvm->callbacks->outb(kvm->opaque, addr,
					*(uint8_t *)value_addr);
				break;
			case 2:
				r = kvm->callbacks->outw(kvm->opaque, addr,
					*(uint16_t *)value_addr);
				break;
			case 4:
				r = kvm->callbacks->outl(kvm->opaque, addr,
					*(uint32_t *)value_addr);
				break;
			default:
				fprintf(stderr, "bad I/O size\n");
				exit(1);
			}
			break;
		default:
			fprintf(stderr, "bad I/O size\n");
			exit(1);
		}
		if (run->io.string) {
			run->io.address += delta;
			switch (run->io.direction) {
			case KVM_EXIT_IO_IN:  regs.rdi += delta; break;
			case KVM_EXIT_IO_OUT: regs.rsi += delta; break;
			}
			if (run->io.rep) {
				--regs.rcx;
				--run->io.count;
			}
		}
		first_time = 0;
		if (r) {
			ioctl(kvm->fd, KVM_SET_REGS, &regs);
			return r;
		}
	}

	ioctl(kvm->fd, KVM_SET_REGS, &regs);
	run->emulated = 1;
	return 0;
}

int handle_debug(kvm_context_t kvm, struct kvm_run *run)
{
	return kvm->callbacks->debug(kvm->opaque, run->vcpu);
}

int kvm_get_regs(kvm_context_t kvm, int vcpu, struct kvm_regs *regs)
{
	regs->vcpu = vcpu;
	return ioctl(kvm->fd, KVM_GET_REGS, regs);
}

int kvm_set_regs(kvm_context_t kvm, int vcpu, struct kvm_regs *regs)
{
	regs->vcpu = vcpu;
	return ioctl(kvm->fd, KVM_SET_REGS, regs);
}

int kvm_get_sregs(kvm_context_t kvm, int vcpu, struct kvm_sregs *sregs)
{
	sregs->vcpu = vcpu;
	return ioctl(kvm->fd, KVM_GET_SREGS, sregs);
}

int kvm_set_sregs(kvm_context_t kvm, int vcpu, struct kvm_sregs *sregs)
{
	sregs->vcpu = vcpu;
	return ioctl(kvm->fd, KVM_SET_SREGS, sregs);
}

/*
 * Returns available msr list.  User must free.
 */
struct kvm_msr_list *kvm_get_msr_list(kvm_context_t kvm)
{
	struct kvm_msr_list sizer, *msrs;
	int r, e;

	sizer.nmsrs = 0;
	r = ioctl(kvm->fd, KVM_GET_MSR_INDEX_LIST, &sizer);
	if (r == -1 && errno != E2BIG)
		return 0;
	msrs = (kvm_msr_list*)malloc(sizeof *msrs + sizer.nmsrs * sizeof *msrs->indices);
	if (!msrs) {
		errno = ENOMEM;
		return 0;
	}
	msrs->nmsrs = sizer.nmsrs;
	r = ioctl(kvm->fd, KVM_GET_MSR_INDEX_LIST, msrs);
	if (r == -1) {
		e = errno;
		free(msrs);
		errno = e;
		return 0;
	}
	return msrs;
}

int kvm_get_msrs(kvm_context_t kvm, int vcpu, struct kvm_msr_entry *msrs,
	int n)
{
	struct kvm_msrs *kmsrs = (kvm_msrs*)malloc(sizeof *kmsrs + n * sizeof *msrs);
	int r, e;

	if (!kmsrs) {
		errno = ENOMEM;
		return -1;
	}
	kmsrs->vcpu = vcpu;
	kmsrs->nmsrs = n;
	memcpy(kmsrs->entries, msrs, n * sizeof *msrs);
	r = ioctl(kvm->fd, KVM_GET_MSRS, kmsrs);
	e = errno;
	memcpy(msrs, kmsrs->entries, n * sizeof *msrs);
	free(kmsrs);
	errno = e;
	return r;
}

int kvm_set_msrs(kvm_context_t kvm, int vcpu, struct kvm_msr_entry *msrs,
	int n)
{
	struct kvm_msrs *kmsrs = (kvm_msrs*)malloc(sizeof *kmsrs + n * sizeof *msrs);
	int r, e;

	if (!kmsrs) {
		errno = ENOMEM;
		return -1;
	}
	kmsrs->vcpu = vcpu;
	kmsrs->nmsrs = n;
	memcpy(kmsrs->entries, msrs, n * sizeof *msrs);
	r = ioctl(kvm->fd, KVM_SET_MSRS, kmsrs);
	e = errno;
	free(kmsrs);
	errno = e;
	return r;
}

void kvm_show_regs(kvm_context_t kvm, int vcpu)
{
	int fd = kvm->fd;
	struct kvm_regs regs;
	int r;

	regs.vcpu = vcpu;
	r = ioctl(fd, KVM_GET_REGS, &regs);
	if (r == -1) {
		perror("KVM_GET_REGS");
		exit(1);
	}
	fprintf(stderr,
		"rax %016llx rbx %016llx rcx %016llx rdx %016llx\n"
		"rsi %016llx rdi %016llx rsp %016llx rbp %016llx\n"
		"r8  %016llx r9  %016llx r10 %016llx r11 %016llx\n"
		"r12 %016llx r13 %016llx r14 %016llx r15 %016llx\n"
		"rip %016llx rflags %08llx\n",
		regs.rax, regs.rbx, regs.rcx, regs.rdx,
		regs.rsi, regs.rdi, regs.rsp, regs.rbp,
		regs.r8, regs.r9, regs.r10, regs.r11,
		regs.r12, regs.r13, regs.r14, regs.r15,
		regs.rip, regs.rflags);
}

static int handle_cpuid(kvm_context_t kvm, struct kvm_run *run)
{
	struct kvm_regs regs;
	uint32_t orig_eax;
	int r;

	kvm_get_regs(kvm, run->vcpu, &regs);
	orig_eax = regs.rax;
	r = kvm->callbacks->cpuid(kvm->opaque,
		(uint64_t*)&regs.rax, (uint64_t*)&regs.rbx, (uint64_t*)&regs.rcx, (uint64_t*)&regs.rdx);
	if (orig_eax == 1)
		regs.rdx &= ~(1ull << 12); /* disable mtrr support */
	kvm_set_regs(kvm, run->vcpu, &regs);
	run->emulated = 1;
	return r;
}

static int handle_mmio(kvm_context_t kvm, struct kvm_run *kvm_run)
{
	unsigned long addr = kvm_run->mmio.phys_addr;
	void *data = kvm_run->mmio.data;
	int r = -1;

	if (kvm_run->mmio.is_write) {
		switch (kvm_run->mmio.len) {
		case 1:
			r = kvm->callbacks->writeb(kvm->opaque, addr, *(uint8_t *)data);
			break;
		case 2:
			r = kvm->callbacks->writew(kvm->opaque, addr, *(uint16_t *)data);
			break;
		case 4:
			r = kvm->callbacks->writel(kvm->opaque, addr, *(uint32_t *)data);
			break;
		case 8:
			r = kvm->callbacks->writeq(kvm->opaque, addr, *(uint64_t *)data);
			break;
		}
	}
	else {
		switch (kvm_run->mmio.len) {
		case 1:
			r = kvm->callbacks->readb(kvm->opaque, addr, (uint8_t *)data);
			break;
		case 2:
			r = kvm->callbacks->readw(kvm->opaque, addr, (uint16_t *)data);
			break;
		case 4:
			r = kvm->callbacks->readl(kvm->opaque, addr, (uint32_t *)data);
			break;
		case 8:
			r = kvm->callbacks->readq(kvm->opaque, addr, (uint64_t *)data);
			break;
		}
		kvm_run->mmio_completed = 1;
	}
	return r;
}

static int handle_io_window(kvm_context_t kvm, struct kvm_run *kvm_run)
{
	return kvm->callbacks->io_window(kvm->opaque);
}

static int handle_halt(kvm_context_t kvm, struct kvm_run *kvm_run)
{
	return kvm->callbacks->halt(kvm->opaque, kvm_run->vcpu);
}

int try_push_interrupts(kvm_context_t kvm)
{
	return kvm->callbacks->try_push_interrupts(kvm->opaque);
}

static void post_kvm_run(kvm_context_t kvm, struct kvm_run *kvm_run)
{
	kvm->callbacks->post_kvm_run(kvm->opaque, kvm_run);
}

int kvm_run(kvm_context_t kvm, int vcpu)
{
	int r;
	int fd = kvm->fd;
	struct kvm_run kvm_run = {
		.vcpu = vcpu,
		.emulated = 0,
		.mmio_completed = 0,
	};

again:
	kvm_run.request_interrupt_window = try_push_interrupts(kvm);
	r = ioctl(fd, KVM_RUN, &kvm_run);
	post_kvm_run(kvm, &kvm_run);

	kvm_run.emulated = 0;
	kvm_run.mmio_completed = 0;
	if (r == -1 && errno != EINTR) {
		printf("kvm_run: %m\n");
		exit(1);
	}
	if (r == -1) {
		r = handle_io_window(kvm, &kvm_run);
		goto more;
	}
	switch (kvm_run.exit_type) {
	case KVM_EXIT_TYPE_FAIL_ENTRY:
		fprintf(stderr, "kvm_run: failed entry, reason %u\n",
			kvm_run.exit_reason & 0xffff);
		exit(1);
		break;
	case KVM_EXIT_TYPE_VM_EXIT:
		switch (kvm_run.exit_reason) {
		case KVM_EXIT_UNKNOWN:
			fprintf(stderr, "unhandled vm exit:  0x%x\n",
				kvm_run.hw.hardware_exit_reason);
			kvm_show_regs(kvm, vcpu);
			abort();
			break;
		case KVM_EXIT_EXCEPTION:
			fprintf(stderr, "exception %d (%x)\n",
				kvm_run.ex.exception,
				kvm_run.ex.error_code);
			abort();
			break;
		case KVM_EXIT_IO:
			r = handle_io(kvm, &kvm_run);
			break;
		case KVM_EXIT_CPUID:
			r = handle_cpuid(kvm, &kvm_run);
			break;
		case KVM_EXIT_DEBUG:
			r = handle_debug(kvm, &kvm_run);
			break;
		case KVM_EXIT_MMIO:
			r = handle_mmio(kvm, &kvm_run);
			break;
		case KVM_EXIT_HLT:
			r = handle_halt(kvm, &kvm_run);
			break;
		case KVM_EXIT_IRQ_WINDOW_OPEN:
			break;
		default:
			fprintf(stderr, "unhandled vm exit: 0x%x\n", kvm_run.exit_reason);
			kvm_show_regs(kvm, vcpu);
			abort();
			break;
		}
	}
more:
	if (!r)
		goto again;
	return r;
}

int kvm_inject_irq(kvm_context_t kvm, int vcpu, unsigned irq)
{
	struct kvm_interrupt intr;

	intr.vcpu = vcpu;
	intr.irq = irq;
	return ioctl(kvm->fd, KVM_INTERRUPT, &intr);
}

int kvm_guest_debug(kvm_context_t kvm, int vcpu, struct kvm_debug_guest *dbg)
{
	dbg->vcpu = vcpu;

	return ioctl(kvm->fd, KVM_DEBUG_GUEST, dbg);
}
