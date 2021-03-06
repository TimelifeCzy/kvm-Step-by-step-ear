/* 
 * ARM Versatile Platform/Application Baseboard System emulation.
 *
 * Copyright (c) 2005-2006 CodeSourcery.
 * Written by Paul Brook
 *
 * This code is licenced under the GPL.
 */

#include "vl.h"
#include "arm_pic.h"

#define LOCK_VALUE 0xa05f

/* Primary interrupt controller.  */

typedef struct vpb_sic_state
{
  arm_pic_handler handler;
  uint32_t base;
  uint32_t level;
  uint32_t mask;
  uint32_t pic_enable;
  void *parent;
  int irq;
} vpb_sic_state;

static void vpb_sic_update(vpb_sic_state *s)
{
    uint32_t flags;

    flags = s->level & s->mask;
    pic_set_irq_new(s->parent, s->irq, flags != 0);
}

static void vpb_sic_update_pic(vpb_sic_state *s)
{
    int i;
    uint32_t mask;

    for (i = 21; i <= 30; i++) {
        mask = 1u << i;
        if (!(s->pic_enable & mask))
            continue;
        pic_set_irq_new(s->parent, i, (s->level & mask) != 0);
    }
}

static void vpb_sic_set_irq(void *opaque, int irq, int level)
{
    vpb_sic_state *s = (vpb_sic_state *)opaque;
    if (level)
        s->level |= 1u << irq;
    else
        s->level &= ~(1u << irq);
    if (s->pic_enable & (1u << irq))
        pic_set_irq_new(s->parent, irq, level);
    vpb_sic_update(s);
}

static uint32_t vpb_sic_read(void *opaque, target_phys_addr_t offset)
{
    vpb_sic_state *s = (vpb_sic_state *)opaque;

    offset -= s->base;
    switch (offset >> 2) {
    case 0: /* STATUS */
        return s->level & s->mask;
    case 1: /* RAWSTAT */
        return s->level;
    case 2: /* ENABLE */
        return s->mask;
    case 4: /* SOFTINT */
        return s->level & 1;
    case 8: /* PICENABLE */
        return s->pic_enable;
    default:
        printf ("vpb_sic_read: Bad register offset 0x%x\n", offset);
        return 0;
    }
}

static void vpb_sic_write(void *opaque, target_phys_addr_t offset,
                          uint32_t value)
{
    vpb_sic_state *s = (vpb_sic_state *)opaque;
    offset -= s->base;

    switch (offset >> 2) {
    case 2: /* ENSET */
        s->mask |= value;
        break;
    case 3: /* ENCLR */
        s->mask &= ~value;
        break;
    case 4: /* SOFTINTSET */
        if (value)
            s->mask |= 1;
        break;
    case 5: /* SOFTINTCLR */
        if (value)
            s->mask &= ~1u;
        break;
    case 8: /* PICENSET */
        s->pic_enable |= (value & 0x7fe00000);
        vpb_sic_update_pic(s);
        break;
    case 9: /* PICENCLR */
        s->pic_enable &= ~value;
        vpb_sic_update_pic(s);
        break;
    default:
        printf ("vpb_sic_write: Bad register offset 0x%x\n", offset);
        return;
    }
    vpb_sic_update(s);
}

static CPUReadMemoryFunc *vpb_sic_readfn[] = {
   vpb_sic_read,
   vpb_sic_read,
   vpb_sic_read
};

static CPUWriteMemoryFunc *vpb_sic_writefn[] = {
   vpb_sic_write,
   vpb_sic_write,
   vpb_sic_write
};

static vpb_sic_state *vpb_sic_init(uint32_t base, void *parent, int irq)
{
    vpb_sic_state *s;
    int iomemtype;

    s = (vpb_sic_state *)qemu_mallocz(sizeof(vpb_sic_state));
    if (!s)
        return NULL;
    s->handler = vpb_sic_set_irq;
    s->base = base;
    s->parent = parent;
    s->irq = irq;
    iomemtype = cpu_register_io_memory(0, vpb_sic_readfn,
                                       vpb_sic_writefn, s);
    cpu_register_physical_memory(base, 0x00000fff, iomemtype);
    /* ??? Save/restore.  */
    return s;
}

/* System controller.  */

typedef struct {
    uint32_t base;
    uint32_t leds;
    uint16_t lockval;
    uint32_t cfgdata1;
    uint32_t cfgdata2;
    uint32_t flags;
    uint32_t nvflags;
    uint32_t resetlevel;
} vpb_sys_state;

static uint32_t vpb_sys_read(void *opaque, target_phys_addr_t offset)
{
    vpb_sys_state *s = (vpb_sys_state *)opaque;

    offset -= s->base;
    switch (offset) {
    case 0x00: /* ID */
        return 0x41007004;
    case 0x04: /* SW */
        /* General purpose hardware switches.
           We don't have a useful way of exposing these to the user.  */
        return 0;
    case 0x08: /* LED */
        return s->leds;
    case 0x20: /* LOCK */
        return s->lockval;
    case 0x0c: /* OSC0 */
    case 0x10: /* OSC1 */
    case 0x14: /* OSC2 */
    case 0x18: /* OSC3 */
    case 0x1c: /* OSC4 */
    case 0x24: /* 100HZ */
        /* ??? Implement these.  */
        return 0;
    case 0x28: /* CFGDATA1 */
        return s->cfgdata1;
    case 0x2c: /* CFGDATA2 */
        return s->cfgdata2;
    case 0x30: /* FLAGS */
        return s->flags;
    case 0x38: /* NVFLAGS */
        return s->nvflags;
    case 0x40: /* RESETCTL */
        return s->resetlevel;
    case 0x44: /* PCICTL */
        return 1;
    case 0x48: /* MCI */
        return 0;
    case 0x4c: /* FLASH */
        return 0;
    case 0x50: /* CLCD */
        return 0x1000;
    case 0x54: /* CLCDSER */
        return 0;
    case 0x58: /* BOOTCS */
        return 0;
    case 0x5c: /* 24MHz */
        /* ??? not implemented.  */
        return 0;
    case 0x60: /* MISC */
        return 0;
    case 0x64: /* DMAPSR0 */
    case 0x68: /* DMAPSR1 */
    case 0x6c: /* DMAPSR2 */
    case 0x8c: /* OSCRESET0 */
    case 0x90: /* OSCRESET1 */
    case 0x94: /* OSCRESET2 */
    case 0x98: /* OSCRESET3 */
    case 0x9c: /* OSCRESET4 */
    case 0xc0: /* SYS_TEST_OSC0 */
    case 0xc4: /* SYS_TEST_OSC1 */
    case 0xc8: /* SYS_TEST_OSC2 */
    case 0xcc: /* SYS_TEST_OSC3 */
    case 0xd0: /* SYS_TEST_OSC4 */
        return 0;
    default:
        printf ("vpb_sys_read: Bad register offset 0x%x\n", offset);
        return 0;
    }
}

static void vpb_sys_write(void *opaque, target_phys_addr_t offset,
                          uint32_t val)
{
    vpb_sys_state *s = (vpb_sys_state *)opaque;
    offset -= s->base;

    switch (offset) {
    case 0x08: /* LED */
        s->leds = val;
    case 0x0c: /* OSC0 */
    case 0x10: /* OSC1 */
    case 0x14: /* OSC2 */
    case 0x18: /* OSC3 */
    case 0x1c: /* OSC4 */
        /* ??? */
        break;
    case 0x20: /* LOCK */
        if (val == LOCK_VALUE)
            s->lockval = val;
        else
            s->lockval = val & 0x7fff;
        break;
    case 0x28: /* CFGDATA1 */
        /* ??? Need to implement this.  */
        s->cfgdata1 = val;
        break;
    case 0x2c: /* CFGDATA2 */
        /* ??? Need to implement this.  */
        s->cfgdata2 = val;
        break;
    case 0x30: /* FLAGSSET */
        s->flags |= val;
        break;
    case 0x34: /* FLAGSCLR */
        s->flags &= ~val;
        break;
    case 0x38: /* NVFLAGSSET */
        s->nvflags |= val;
        break;
    case 0x3c: /* NVFLAGSCLR */
        s->nvflags &= ~val;
        break;
    case 0x40: /* RESETCTL */
        if (s->lockval == LOCK_VALUE) {
            s->resetlevel = val;
            if (val & 0x100)
                cpu_abort(cpu_single_env, "Board reset\n");
        }
        break;
    case 0x44: /* PCICTL */
        /* nothing to do.  */
        break;
    case 0x4c: /* FLASH */
    case 0x50: /* CLCD */
    case 0x54: /* CLCDSER */
    case 0x64: /* DMAPSR0 */
    case 0x68: /* DMAPSR1 */
    case 0x6c: /* DMAPSR2 */
    case 0x8c: /* OSCRESET0 */
    case 0x90: /* OSCRESET1 */
    case 0x94: /* OSCRESET2 */
    case 0x98: /* OSCRESET3 */
    case 0x9c: /* OSCRESET4 */
        break;
    default:
        printf ("vpb_sys_write: Bad register offset 0x%x\n", offset);
        return;
    }
}

static CPUReadMemoryFunc *vpb_sys_readfn[] = {
   vpb_sys_read,
   vpb_sys_read,
   vpb_sys_read
};

static CPUWriteMemoryFunc *vpb_sys_writefn[] = {
   vpb_sys_write,
   vpb_sys_write,
   vpb_sys_write
};

static vpb_sys_state *vpb_sys_init(uint32_t base)
{
    vpb_sys_state *s;
    int iomemtype;

    s = (vpb_sys_state *)qemu_mallocz(sizeof(vpb_sys_state));
    if (!s)
        return NULL;
    s->base = base;
    iomemtype = cpu_register_io_memory(0, vpb_sys_readfn,
                                       vpb_sys_writefn, s);
    cpu_register_physical_memory(base, 0x00000fff, iomemtype);
    /* ??? Save/restore.  */
    return s;
}

/* Board init.  */

/* The AB and PB boards both use the same core, just with different
   peripherans and expansion busses.  For now we emulate a subset of the
   PB peripherals and just change the board ID.  */

static void versatile_init(int ram_size, int vga_ram_size, int boot_device,
                     DisplayState *ds, const char **fd_filename, int snapshot,
                     const char *kernel_filename, const char *kernel_cmdline,
                     const char *initrd_filename, int board_id)
{
    CPUState *env;
    void *pic;
    void *sic;
    void *scsi_hba;
    PCIBus *pci_bus;
    NICInfo *nd;
    int n;
    int done_smc = 0;

    env = cpu_init();
    cpu_arm_set_model(env, ARM_CPUID_ARM926);
    /* ??? RAM shoud repeat to fill physical memory space.  */
    /* SDRAM at address zero.  */
    cpu_register_physical_memory(0, ram_size, IO_MEM_RAM);

    vpb_sys_init(0x10000000);
    pic = arm_pic_init_cpu(env);
    pic = pl190_init(0x10140000, pic, ARM_PIC_CPU_IRQ, ARM_PIC_CPU_FIQ);
    sic = vpb_sic_init(0x10003000, pic, 31);
    pl050_init(0x10006000, sic, 3, 0);
    pl050_init(0x10007000, sic, 4, 1);

    pci_bus = pci_vpb_init(sic);
    /* The Versatile PCI bridge does not provide access to PCI IO space,
       so many of the qemu PCI devices are not useable.  */
    for(n = 0; n < nb_nics; n++) {
        nd = &nd_table[n];
        if (!nd->model)
            nd->model = done_smc ? "rtl8139" : "smc91c111";
        if (strcmp(nd->model, "smc91c111") == 0) {
            smc91c111_init(nd, 0x10010000, sic, 25);
        } else {
            pci_nic_init(pci_bus, nd);
        }
    }
    if (usb_enabled) {
        usb_ohci_init(pci_bus, 3, -1);
    }
    scsi_hba = lsi_scsi_init(pci_bus, -1);
    for (n = 0; n < MAX_DISKS; n++) {
        if (bs_table[n]) {
            lsi_scsi_attach(scsi_hba, bs_table[n], n);
        }
    }

    pl011_init(0x101f1000, pic, 12, serial_hds[0]);
    pl011_init(0x101f2000, pic, 13, serial_hds[1]);
    pl011_init(0x101f3000, pic, 14, serial_hds[2]);
    pl011_init(0x10009000, sic, 6, serial_hds[3]);

    pl080_init(0x10130000, pic, 17);
    sp804_init(0x101e2000, pic, 4);
    sp804_init(0x101e3000, pic, 5);

    /* The versatile/PB actually has a modified Color LCD controller
       that includes hardware cursor support from the PL111.  */
    pl110_init(ds, 0x10120000, pic, 16, 1);

    /* Memory map for Versatile/PB:  */
    /* 0x10000000 System registers.  */
    /* 0x10001000 PCI controller config registers.  */
    /* 0x10002000 Serial bus interface.  */
    /*  0x10003000 Secondary interrupt controller.  */
    /* 0x10004000 AACI (audio).  */
    /* 0x10005000 MMCI0.  */
    /*  0x10006000 KMI0 (keyboard).  */
    /*  0x10007000 KMI1 (mouse).  */
    /* 0x10008000 Character LCD Interface.  */
    /*  0x10009000 UART3.  */
    /* 0x1000a000 Smart card 1.  */
    /* 0x1000b000 MMCI1.  */
    /*  0x10010000 Ethernet.  */
    /* 0x10020000 USB.  */
    /* 0x10100000 SSMC.  */
    /* 0x10110000 MPMC.  */
    /*  0x10120000 CLCD Controller.  */
    /*  0x10130000 DMA Controller.  */
    /*  0x10140000 Vectored interrupt controller.  */
    /* 0x101d0000 AHB Monitor Interface.  */
    /* 0x101e0000 System Controller.  */
    /* 0x101e1000 Watchdog Interface.  */
    /* 0x101e2000 Timer 0/1.  */
    /* 0x101e3000 Timer 2/3.  */
    /* 0x101e4000 GPIO port 0.  */
    /* 0x101e5000 GPIO port 1.  */
    /* 0x101e6000 GPIO port 2.  */
    /* 0x101e7000 GPIO port 3.  */
    /* 0x101e8000 RTC.  */
    /* 0x101f0000 Smart card 0.  */
    /*  0x101f1000 UART0.  */
    /*  0x101f2000 UART1.  */
    /*  0x101f3000 UART2.  */
    /* 0x101f4000 SSPI.  */

    arm_load_kernel(ram_size, kernel_filename, kernel_cmdline,
                    initrd_filename, board_id);
}

static void vpb_init(int ram_size, int vga_ram_size, int boot_device,
                     DisplayState *ds, const char **fd_filename, int snapshot,
                     const char *kernel_filename, const char *kernel_cmdline,
                     const char *initrd_filename)
{
    versatile_init(ram_size, vga_ram_size, boot_device,
                   ds, fd_filename, snapshot,
                   kernel_filename, kernel_cmdline,
                   initrd_filename, 0x183);
}

static void vab_init(int ram_size, int vga_ram_size, int boot_device,
                     DisplayState *ds, const char **fd_filename, int snapshot,
                     const char *kernel_filename, const char *kernel_cmdline,
                     const char *initrd_filename)
{
    versatile_init(ram_size, vga_ram_size, boot_device,
                   ds, fd_filename, snapshot,
                   kernel_filename, kernel_cmdline,
                   initrd_filename, 0x25e);
}

QEMUMachine versatilepb_machine = {
    "versatilepb",
    "ARM Versatile/PB (ARM926EJ-S)",
    vpb_init,
};

QEMUMachine versatileab_machine = {
    "versatileab",
    "ARM Versatile/AB (ARM926EJ-S)",
    vab_init,
};
