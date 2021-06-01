#include <netinet/in.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "kvmctl.h"


kvm_context_t g_kvm;


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
		//kvm_inject_irq(kvm, 0, value);
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
	test_io_window
};


/*
	循环等待r0回传
*/
void * callback_thread(void * arg)
{
	pthread_t newthid;
	newthid = pthread_self();
	printf("this is a new thread,thread ID = %lu\n", newthid);

	int ser_socket = socket(AF_INET, SOCK_STREAM, 0);
	///定义sockaddr_in
	struct sockaddr_in server_sockaddr;
	server_sockaddr.sin_family = AF_INET;
	server_sockaddr.sin_port = htons(12345);
	server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(ser_socket, (struct sockaddr*)&server_sockaddr, sizeof(server_sockaddr)) == -1)
	{
		perror("bind");
		return 0;
	}

	if (listen(ser_socket, 5) == -1)
	{
		perror("listen");
		return 0;
	}

	int recv_size = 0;
	char recve_buffer[1024] = { 0, };
	struct sockaddr_in client_addr;
	socklen_t length = sizeof(client_addr);

	// 假设单线程 - 长连接
	int conn = accept(ser_socket, (struct sockaddr*)&client_addr, &length);
	if (conn < 0)
	{
		perror("connect");
		return 0;
	}

	send(conn, "success", 8, 0);

	while (true) {
		recv(conn, recve_buffer, recv_size, 0);
		if (0 == strcmp("break", recve_buffer))
			break;

		// 接收r0传入的数据
	}

	return NULL;
}


int main(int ac, char **av)
{
	void *vm_mem = NULL;
    printf("hello from kvm_app!\n");

	g_kvm = kvm_init(&test_callbacks, 0);
	kvm_create(g_kvm, 128 * 1024 * 1024, &vm_mem);

	if (ac > 1)
		load_file((void*)((int *)vm_mem + 0xf0000), av[1]);
	if (ac > 2)
		load_file ((void*)((int *)vm_mem + 0x100000), av[2]);
	else {
		load_file((void*)((int *)vm_mem + 0xf0000), "/root/kvm-module/kernel.bin");
	}

	kvm_show_regs(g_kvm, 0);

	//pthread_t thid;
	//printf("main thread,ID is %lu\n", pthread_self());
	//if (pthread_create(&thid, NULL, callback_thread, NULL) != 0)
	//{
	//	printf("thread creation failed\n");
	//	return 0;
	//}

	// 给创建线程的机会
	// sleep(1);

	kvm_run(g_kvm, 0);

    return 0;
}