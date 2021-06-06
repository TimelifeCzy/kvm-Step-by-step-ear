/*
 * Kernel-based Virtual Machine test driver
 *
 * This test driver provides a simple way of testing kvm, without a full
 * device model.
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

#include "kvmctl.h"
#include <sys/fcntl.h>
#include <string>
#include <string.h>

kvm_context_t kvm;

static int test_cpuid(void *opaque, uint64_t *rax, uint64_t *rbx,
	uint64_t *rcx, uint64_t *rdx)
{
	printf("cpuid 0x%lx\n", (uint32_t)*rax);
	return 0;
}

static int test_inb(void *opaque, uint16_t addr, uint8_t *value)
{
	printf("inb 0x%x\n", addr);
	return 0;
}

static int test_inw(void *opaque, uint16_t addr, uint16_t *value)
{
	printf("inw 0x%x\n", addr);
	return 0;
}

static int test_inl(void *opaque, uint16_t addr, uint32_t *value)
{
	printf("inl 0x%x\n", addr);
	return 0;
}

static int test_outb(void *opaque, uint16_t addr, uint8_t value)
{
	static int newline = 1;

	switch (addr) {
	case 0xff: // irq injector
		printf("injecting interrupt 0x%x\n", value);
		kvm_inject_irq(kvm, 0, value);
		break;
	case 0xf1: // serial
		if (newline)
			fputs("GUEST: ", stdout);
		putchar(value);
		newline = value == '\n';
		break;
	default:
		printf("outb $0x%x, 0x%x\n", value, addr);
	}
	return 0;
}

static int test_outw(void *opaque, uint16_t addr, uint16_t value)
{
	printf("outw $0x%x, 0x%x\n", value, addr);
	return 0;
}

static int test_outl(void *opaque, uint16_t addr, uint32_t value)
{
	printf("outl $0x%x, 0x%x\n", value, addr);
	return 0;
}

static int test_debug(void *opaque, int vcpu)
{
	printf("test_debug\n");
	return 0;
}

static int test_halt(void *opaque, int vcpu)
{
	printf("test_halt\n");
	return 0;
}

static int test_io_window(void *opaque)
{
	printf("test_io_window\n");
	return 0;
}

static int test_try_push_interrupts(void *opaque)
{
}

static void test_post_kvm_run(void *opaque, struct kvm_run *kvm_run)
{
}

static struct kvm_callbacks test_callbacks = {
	test_cpuid,
	test_inb,
	test_inw,
	test_inl,
	test_outb,
	test_outw,
	test_outl,
	test_debug,
	test_halt,
	test_io_window,
	test_try_push_interrupts,
	test_post_kvm_run
};


static void load_file(void *mem, const char *fname)
{
	int r;
	int fd;

	fd = open(fname, O_RDONLY);
	if (fd == -1) {
		perror("open");
		exit(1);
	}
	while ((r = read(fd, mem, 4096)) != -1 && r != 0)
		mem = (void*)((int*)mem + r);
	if (r == -1) {
		perror("read");
		exit(1);
	}
}

static void enter_32(kvm_context_t kvm)
{
	struct kvm_regs regs = { 0, };
	regs.rsp = 0x80000;  /* 512KB */
	regs.rip = 0x100000; /* 1MB */
	regs.rflags = 2;

	struct kvm_sregs sregs = { 0, };
	sregs.cs = (kvm_segment){ 0, -1u,  8, 11, 1, 0, 1, 1, 0, 1, 0, 0 };
	sregs.ds = (kvm_segment){ 0, -1u, 16,  3, 1, 0, 1, 1, 0, 1, 0, 0 };
	sregs.es = (kvm_segment){ 0, -1u, 16,  3, 1, 0, 1, 1, 0, 1, 0, 0 };
	sregs.fs = (kvm_segment){ 0, -1u, 16,  3, 1, 0, 1, 1, 0, 1, 0, 0 };
	sregs.gs = (kvm_segment){ 0, -1u, 16,  3, 1, 0, 1, 1, 0, 1, 0, 0 };
	sregs.ss = (kvm_segment){ 0, -1u, 16,  3, 1, 0, 1, 1, 0, 1, 0, 0 };

	sregs.tr = (kvm_segment) { 0, 10000, 24, 11, 1, 0, 0, 0, 0, 0, 0, 0 };
	sregs.ldt = (kvm_segment) { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
	sregs.gdt = (kvm_dtable) { 0, 0 };
	sregs.idt = (kvm_dtable) { 0, 0 };
	sregs.cr0 = 0x37;
	sregs.cr3 = 0;
	sregs.cr4 = 0;
	sregs.efer = 0;
	sregs.apic_base = 0;
	memset(sregs.interrupt_bitmap, 0, sizeof(sregs.interrupt_bitmap));

	kvm_set_regs(kvm, 0, &regs);
	kvm_set_sregs(kvm, 0, &sregs);
}

int main(int ac, char **av)
{
	void *vm_mem;

	kvm = kvm_init(&test_callbacks, 0);
	if (!kvm) {
		fprintf(stderr, "kvm_init failed\n");
		return 1;
	}
	if (kvm_create(kvm, 128 * 1024 * 1024, &vm_mem) < 0) {
		kvm_finalize(kvm);
		fprintf(stderr, "kvm_create failed\n");
		return 1;
	}

	if (ac > 1)
		if (strcmp(av[1], "-32") != 0)
			load_file((void*)((int*)vm_mem + 0xf0000), av[1]);
		else
			enter_32(kvm);
	if (ac > 2)
		load_file((void*)((int*)vm_mem + 0x100000), av[2]);
	kvm_show_regs(kvm, 0);

	kvm_run(kvm, 0);

	return 0;
}