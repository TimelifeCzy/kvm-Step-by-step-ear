#include "libcflat.h"
#include "apic.h"

static void *g_apic = (void *)0xfee00000;
static void *g_ioapic = (void *)0xfec00000;

struct apic_ops {
    u32 (*reg_read)(unsigned reg);
    void (*reg_write)(unsigned reg, u32 val);
    void (*icr_write)(u32 val, u32 dest);
    u32 (*id)(void);
};

static void outb(unsigned char data, unsigned short port)
{
    asm volatile ("out %0, %1" : : "a"(data), "d"(port));
}

static u32 xapic_read(unsigned reg)
{
    return *(volatile u32 *)(g_apic + reg);
}

static void xapic_write(unsigned reg, u32 val)
{
    *(volatile u32 *)(g_apic + reg) = val;
}

static void xapic_icr_write(u32 val, u32 dest)
{
    while (xapic_read(APIC_ICR) & APIC_ICR_BUSY)
        ;
    xapic_write(APIC_ICR2, dest << 24);
    xapic_write(APIC_ICR, val);
}

static uint32_t xapic_id(void)
{
    return xapic_read(APIC_ID) >> 24;
}

static const struct apic_ops xapic_ops = {
    .reg_read = xapic_read,
    .reg_write = xapic_write,
    .icr_write = xapic_icr_write,
    .id = xapic_id,
};

static const struct apic_ops *apic_ops = &xapic_ops;

static u32 x2apic_read(unsigned reg)
{
    unsigned a, d;

    asm volatile ("rdmsr" : "=a"(a), "=d"(d) : "c"(APIC_BASE_MSR + reg/16));
    return a | (u64)d << 32;
}

static void x2apic_write(unsigned reg, u32 val)
{
    asm volatile ("wrmsr" : : "a"(val), "d"(0), "c"(APIC_BASE_MSR + reg/16));
}

static void x2apic_icr_write(u32 val, u32 dest)
{
    asm volatile ("wrmsr" : : "a"(val), "d"(dest),
                  "c"(APIC_BASE_MSR + APIC_ICR/16));
}

static uint32_t x2apic_id(void)
{
    return xapic_read(APIC_ID);
}

static const struct apic_ops x2apic_ops = {
    .reg_read = x2apic_read,
    .reg_write = x2apic_write,
    .icr_write = x2apic_icr_write,
    .id = x2apic_id,
};

u32 apic_read(unsigned reg)
{
    return apic_ops->reg_read(reg);
}

void apic_write(unsigned reg, u32 val)
{
    apic_ops->reg_write(reg, val);
}

void apic_icr_write(u32 val, u32 dest)
{
    apic_ops->icr_write(val, dest);
}

uint32_t apic_id(void)
{
    return apic_ops->id();
}

#define MSR_APIC_BASE 0x0000001b

int enable_x2apic(void)
{
    unsigned a, b, c, d;

    asm ("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "0"(1));

    if (c & (1 << 21)) {
        asm ("rdmsr" : "=a"(a), "=d"(d) : "c"(MSR_APIC_BASE));
        a |= 1 << 10;
        asm ("wrmsr" : : "a"(a), "d"(d), "c"(MSR_APIC_BASE));
        apic_ops = &x2apic_ops;
        return 1;
    } else {
        return 0;
    }
}

void ioapic_write_reg(unsigned reg, u32 value)
{
    *(volatile u32 *)g_ioapic = reg;
    *(volatile u32 *)(g_ioapic + 0x10) = value;
}

void ioapic_write_redir(unsigned line, ioapic_redir_entry_t e)
{
    ioapic_write_reg(0x10 + line * 2 + 0, ((u32 *)&e)[0]);
    ioapic_write_reg(0x10 + line * 2 + 1, ((u32 *)&e)[1]);
}

void enable_apic(void)
{
    printf("enabling apic\n");
    xapic_write(0xf0, 0x1ff); /* spurious vector register */
}

void mask_pic_interrupts(void)
{
    outb(0xff, 0x21);
    outb(0xff, 0xa1);
}
