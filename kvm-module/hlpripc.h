#ifndef __KVM_HLPRIPC_H
#define __KVM_HLPRIPC_H

#include<linux/kernel.h>
#include<linux/module.h>

static __init int init_socket(void)
{
    printk("<0>""init socket\n");
    return 0;
}

static __init void sendbuf(char* buf, int bufsize)
{
    printk("<0>""sendbuf\n");
}

static __init void recvdbuf(void)
{
    printk("<0>""recvdbuf\n");
}

#endif
