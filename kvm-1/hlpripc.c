#include "hlpripc.h"

#include<linux/kernel.h>
#include<linux/module.h> 

int init_socket(void)
{
    printk("<0>""init socket\n");
    return 0;
}

void sendbuf(char* buf, int bufsize)
{
    printk("<0>""sendbuf\n");
}

void recvdbuf(void)
{
    printk("<0>""recvdbuf\n");
}