#include <sys/mman.h>
#include <sys/ioctl.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "kvmctl.h"

#define PAGE_SIZE 4096ul

const int error_code = -1;

//struct kvm_context {
//	int fd;
//	struct kvm_callbacks *callbacks;
//	void *opaque;
//	void *physical_memory;
//};

//struct translation_cache {
//	unsigned long linear;
//	void *physical;
//};

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
		tr->physical = (void*)((unsigned long long)kvm->physical_memory + kvm_tr.physical_address);
	}
	*physical = (void *)((unsigned long)tr->physical + offset);
	return 0;
}

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
		printf("Error %d: Failed to open file\n", errno);
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
//

static int more_io(struct kvm_run *run, int first_time)
{
	if (!run->io.rep)
		return first_time;
	else
		return run->io.count != 0;
}

int handle_io(kvm_context_t kvm, struct kvm_run *run)
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
				printf("failed translating I/O address %x\n",
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
				printf("bad I/O size\n");
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
				printf("bad I/O size\n");
				exit(1);
			}
			break;
		default:
			printf("bad I/O size\n");
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

	//if (kvm_run->mmio.is_write) {
	//	switch (kvm_run->mmio.len) {
	//	case 1:
	//		r = kvm->callbacks->writeb(kvm->opaque, addr, *(uint8_t *)data);
	//		break;
	//	case 2:
	//		r = kvm->callbacks->writew(kvm->opaque, addr, *(uint16_t *)data);
	//		break;
	//	case 4:
	//		r = kvm->callbacks->writel(kvm->opaque, addr, *(uint32_t *)data);
	//		break;
	//	case 8:
	//		r = kvm->callbacks->writeq(kvm->opaque, addr, *(uint64_t *)data);
	//		break;
	//	}
	//}
	//else {
	//	switch (kvm_run->mmio.len) {
	//	case 1:
	//		r = kvm->callbacks->readb(kvm->opaque, addr, (uint8_t *)data);
	//		break;
	//	case 2:
	//		r = kvm->callbacks->readw(kvm->opaque, addr, (uint16_t *)data);
	//		break;
	//	case 4:
	//		r = kvm->callbacks->readl(kvm->opaque, addr, (uint32_t *)data);
	//		break;
	//	case 8:
	//		r = kvm->callbacks->readq(kvm->opaque, addr, (uint64_t *)data);
	//		break;
	//	}
	//	kvm_run->mmio_completed = 1;
	//}
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
	switch (kvm_run.exit_type) {
	case KVM_EXIT_TYPE_FAIL_ENTRY:
		printf("kvm_run: failed entry, reason %u\n",
			kvm_run.exit_reason & 0xffff);
		exit(1);
		break;
	case KVM_EXIT_TYPE_VM_EXIT:
		switch (kvm_run.exit_reason) {
		case KVM_EXIT_UNKNOWN:
			printf("unhandled vm exit:  0x%x\n",
				kvm_run.hw.hardware_exit_reason);
			kvm_show_regs(kvm, vcpu);
			abort();
			break;
		case KVM_EXIT_EXCEPTION:
			printf("exception %d (%x)\n",
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
		default:
			printf("unhandled vm exit: 0x%x\n", kvm_run.exit_reason);
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