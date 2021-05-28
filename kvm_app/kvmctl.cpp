#include <sys/mman.h>
#include <sys/ioctl.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "kvmctl.h"



const int error_code = -1;

kvm_context_t kvm_init(struct kvm_callbacks *callbacks,
	void *opaque)
{
	int fd;
	kvm_context_t kvm;

	fd = open("/dev/kvm", O_RDWR);
	if (fd == -1) {
		printf("open: %m\n");
		exit(1);
	}
	kvm = (kvm_context_t)malloc(sizeof(*kvm));
	kvm->fd = fd;
	kvm->callbacks = callbacks;
	kvm->opaque = opaque;
	return kvm;
}

int kvm_create(kvm_context_t kvm,
	unsigned long phys_mem_bytes,
	void **vm_mem)
{
	if (!kvm->fd)
		return -1;
	unsigned long memory = 128 * 1024 * 1024; // 134217728
	unsigned long dosmem = 0xa0000;	// 655360 671088640
	unsigned long exmem = 0xc0000;	// 786432 805306368
	struct kvm_memory_region low_memory = { 0, };
	low_memory.slot = 3;
	// 最大不超过0xa0000
	low_memory.memory_size = memory < dosmem ? memory : dosmem;
	low_memory.guest_phys_addr = 0;

	struct kvm_memory_region extended_memory = { 0, };
	extended_memory.slot = 0;
	// 最大不超过0xc0000
	extended_memory.memory_size = memory < exmem ? 0 : memory - exmem;
	extended_memory.guest_phys_addr = exmem;

	int ctrl = 0;

	ctrl = ioctl(kvm->fd, KVM_SET_MEMORY_REGION, &low_memory);
	if (-1 == ctrl) {
		exit(1);
	}
	if (extended_memory.memory_size) {
		ctrl = ioctl(kvm->fd, KVM_SET_MEMORY_REGION, &extended_memory);
		if (ctrl == -1) {
			printf("kvm_create_memory_region: %m\n");
			exit(1);
		}
	}
	// printf("slot: %d,  flags: %d, guest_phys_addr: %d%d, memory_size: %d%d\n", low_memory.memory_size, low_memory.flags, low_memory.guest_phys_addr, low_memory.memory_size);
	*vm_mem = mmap(0, memory, PROT_READ | PROT_WRITE, MAP_SHARED, kvm->fd, 0);
	if (*vm_mem == MAP_FAILED) {
		printf("mmap: %m\n");
		exit(1);
	}
	
	// kvm->physical_memory = *vm_mem;

	ctrl = ioctl(kvm->fd, KVM_CREATE_VCPU, 0);
	if (-1 == ctrl) {
		printf("创建失败\n");
		exit(1);
	}

	printf("创建成功\n");

	return 0;
}


void load_file(void *mem, const char *fname)
{
	int r;
	int fd;

	fd = open(fname, O_RDONLY);
	if (fd == -1) {
		perror("open");
		exit(1);
	}
	while ((r = read(fd, mem, 4096)) != -1 && r != 0)
		mem = (void*)((int*)mem + r);;
	if (r == -1) {
		perror("read");
		exit(1);
	}
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
	printf("rax %016llx rbx %016llx rcx %016llx rdx %016llx\n"
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

static int handle_io_window(kvm_context_t kvm, struct kvm_run *kvm_run)
{
	return kvm->callbacks->io_window(kvm->opaque);
}


int kvm_run(kvm_context_t kvm, int vcpu)
{
	int r;
	int fd = kvm->fd;
	struct kvm_run kvm_run = { 0, };
	kvm_run.vcpu = vcpu;
	kvm_run.emulated = 0;
	kvm_run.mmio_completed = 0;

again:
	// 发送kvm_run
	r = ioctl(fd, KVM_RUN, &kvm_run);
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

	// 退出分发
	switch (kvm_run.exit_type)
	{
	case KVM_EXIT_IO:
		break;
	case KVM_EXIT_HLT:
		printf("halt\n");
		return 0;
	default:
		break;
	}

more:
	if (!r)
		goto again;
	return r;
}