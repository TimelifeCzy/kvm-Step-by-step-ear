/*
 * QEMU PC System Emulator
 * 
 * Copyright (c) 2003-2004 Fabrice Bellard
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "vl.h"
#ifdef USE_KVM
#include "qemu-kvm.h"
extern int kvm_allowed;
#endif

/* output Bochs bios info messages */
//#define DEBUG_BIOS

#define BIOS_FILENAME "bios.bin"
#define VGABIOS_FILENAME "vgabios.bin"
#define VGABIOS_CIRRUS_FILENAME "vgabios-cirrus.bin"
#define LINUX_BOOT_FILENAME "linux_boot.bin"

#define KERNEL_LOAD_ADDR     0x00100000
#define INITRD_LOAD_ADDR     0x00600000
#define KERNEL_PARAMS_ADDR   0x00090000
#define KERNEL_CMDLINE_ADDR  0x00099000

static fdctrl_t *floppy_controller;
static RTCState *rtc_state;
static PITState *pit;
static IOAPICState *ioapic;
static PCIDevice *i440fx_state;

static void ioport80_write(void *opaque, uint32_t addr, uint32_t data)
{
}

/* MSDOS compatibility mode FPU exception support */
/* XXX: add IGNNE support */
void cpu_set_ferr(CPUX86State *s)
{
    pic_set_irq(13, 1);
}

static void ioportF0_write(void *opaque, uint32_t addr, uint32_t data)
{
    pic_set_irq(13, 0);
}

/* TSC handling */
uint64_t cpu_get_tsc(CPUX86State *env)
{
    /* Note: when using kqemu, it is more logical to return the host TSC
       because kqemu does not trap the RDTSC instruction for
       performance reasons */
#if USE_KQEMU
    if (env->kqemu_enabled) {
        return cpu_get_real_ticks();
    } else 
#endif
    {
        return cpu_get_ticks();
    }
}

/* SMM support */
void cpu_smm_update(CPUState *env)
{
    if (i440fx_state && env == first_cpu)
        i440fx_set_smm(i440fx_state, (env->hflags >> HF_SMM_SHIFT) & 1);
}


/* IRQ handling */
int cpu_get_pic_interrupt(CPUState *env)
{
    int intno;

    intno = apic_get_interrupt(env);
    if (intno >= 0) {
        /* set irq request if a PIC irq is still pending */
        /* XXX: improve that */
        pic_update_irq(isa_pic); 
        return intno;
    }
    /* read the irq from the PIC */
    intno = pic_read_irq(isa_pic);
    return intno;
}

static void pic_irq_request(void *opaque, int level)
{
    CPUState *env = opaque;
    if (level)
        cpu_interrupt(env, CPU_INTERRUPT_HARD);
    else
        cpu_reset_interrupt(env, CPU_INTERRUPT_HARD);
}

/* PC cmos mappings */

#define REG_EQUIPMENT_BYTE          0x14

static int cmos_get_fd_drive_type(int fd0)
{
    int val;

    switch (fd0) {
    case 0:
        /* 1.44 Mb 3"5 drive */
        val = 4;
        break;
    case 1:
        /* 2.88 Mb 3"5 drive */
        val = 5;
        break;
    case 2:
        /* 1.2 Mb 5"5 drive */
        val = 2;
        break;
    default:
        val = 0;
        break;
    }
    return val;
}

static void cmos_init_hd(int type_ofs, int info_ofs, BlockDriverState *hd) 
{
    RTCState *s = rtc_state;
    int cylinders, heads, sectors;
    bdrv_get_geometry_hint(hd, &cylinders, &heads, &sectors);
    rtc_set_memory(s, type_ofs, 47);
    rtc_set_memory(s, info_ofs, cylinders);
    rtc_set_memory(s, info_ofs + 1, cylinders >> 8);
    rtc_set_memory(s, info_ofs + 2, heads);
    rtc_set_memory(s, info_ofs + 3, 0xff);
    rtc_set_memory(s, info_ofs + 4, 0xff);
    rtc_set_memory(s, info_ofs + 5, 0xc0 | ((heads > 8) << 3));
    rtc_set_memory(s, info_ofs + 6, cylinders);
    rtc_set_memory(s, info_ofs + 7, cylinders >> 8);
    rtc_set_memory(s, info_ofs + 8, sectors);
}

/* hd_table must contain 4 block drivers */
static void cmos_init(int ram_size, int boot_device, BlockDriverState **hd_table)
{
    RTCState *s = rtc_state;
    int val;
    int fd0, fd1, nb;
    int i;

    /* various important CMOS locations needed by PC/Bochs bios */

    /* memory size */
    val = 640; /* base memory in K */
    rtc_set_memory(s, 0x15, val);
    rtc_set_memory(s, 0x16, val >> 8);

    val = (ram_size / 1024) - 1024;
    if (val > 65535)
        val = 65535;
    rtc_set_memory(s, 0x17, val);
    rtc_set_memory(s, 0x18, val >> 8);
    rtc_set_memory(s, 0x30, val);
    rtc_set_memory(s, 0x31, val >> 8);

    if (ram_size > (16 * 1024 * 1024))
        val = (ram_size / 65536) - ((16 * 1024 * 1024) / 65536);
    else
        val = 0;
    if (val > 65535)
        val = 65535;
    rtc_set_memory(s, 0x34, val);
    rtc_set_memory(s, 0x35, val >> 8);
    
    switch(boot_device) {
    case 'a':
    case 'b':
        rtc_set_memory(s, 0x3d, 0x01); /* floppy boot */
        if (!fd_bootchk)
            rtc_set_memory(s, 0x38, 0x01); /* disable signature check */
        break;
    default:
    case 'c':
        rtc_set_memory(s, 0x3d, 0x02); /* hard drive boot */
        break;
    case 'd':
        rtc_set_memory(s, 0x3d, 0x03); /* CD-ROM boot */
        break;
    }

    /* floppy type */

    fd0 = fdctrl_get_drive_type(floppy_controller, 0);
    fd1 = fdctrl_get_drive_type(floppy_controller, 1);

    val = (cmos_get_fd_drive_type(fd0) << 4) | cmos_get_fd_drive_type(fd1);
    rtc_set_memory(s, 0x10, val);
    
    val = 0;
    nb = 0;
    if (fd0 < 3)
        nb++;
    if (fd1 < 3)
        nb++;
    switch (nb) {
    case 0:
        break;
    case 1:
        val |= 0x01; /* 1 drive, ready for boot */
        break;
    case 2:
        val |= 0x41; /* 2 drives, ready for boot */
        break;
    }
    val |= 0x02; /* FPU is there */
    val |= 0x04; /* PS/2 mouse installed */
    rtc_set_memory(s, REG_EQUIPMENT_BYTE, val);

    /* hard drives */

    rtc_set_memory(s, 0x12, (hd_table[0] ? 0xf0 : 0) | (hd_table[1] ? 0x0f : 0));
    if (hd_table[0])
        cmos_init_hd(0x19, 0x1b, hd_table[0]);
    if (hd_table[1]) 
        cmos_init_hd(0x1a, 0x24, hd_table[1]);

    val = 0;
    for (i = 0; i < 4; i++) {
        if (hd_table[i]) {
            int cylinders, heads, sectors, translation;
            /* NOTE: bdrv_get_geometry_hint() returns the physical
                geometry.  It is always such that: 1 <= sects <= 63, 1
                <= heads <= 16, 1 <= cylinders <= 16383. The BIOS
                geometry can be different if a translation is done. */
            translation = bdrv_get_translation_hint(hd_table[i]);
            if (translation == BIOS_ATA_TRANSLATION_AUTO) {
                bdrv_get_geometry_hint(hd_table[i], &cylinders, &heads, &sectors);
                if (cylinders <= 1024 && heads <= 16 && sectors <= 63) {
                    /* No translation. */
                    translation = 0;
                } else {
                    /* LBA translation. */
                    translation = 1;
                }
            } else {
                translation--;
            }
            val |= translation << (i * 2);
        }
    }
    rtc_set_memory(s, 0x39, val);
}

void ioport_set_a20(int enable)
{
    /* XXX: send to all CPUs ? */
    cpu_x86_set_a20(first_cpu, enable);
}

int ioport_get_a20(void)
{
    return ((first_cpu->a20_mask >> 20) & 1);
}

static void ioport92_write(void *opaque, uint32_t addr, uint32_t val)
{
    ioport_set_a20((val >> 1) & 1);
    /* XXX: bit 0 is fast reset */
}

static uint32_t ioport92_read(void *opaque, uint32_t addr)
{
    return ioport_get_a20() << 1;
}

/***********************************************************/
/* Bochs BIOS debug ports */

void bochs_bios_write(void *opaque, uint32_t addr, uint32_t val)
{
    static const char shutdown_str[8] = "Shutdown";
    static int shutdown_index = 0;
    
    switch(addr) {
        /* Bochs BIOS messages */
    case 0x400:
    case 0x401:
        fprintf(stderr, "BIOS panic at rombios.c, line %d\n", val);
        exit(1);
    case 0x402:
    case 0x403:
#ifdef DEBUG_BIOS
        fprintf(stderr, "%c", val);
#endif
        break;
    case 0x8900:
        /* same as Bochs power off */
        if (val == shutdown_str[shutdown_index]) {
            shutdown_index++;
            if (shutdown_index == 8) {
                shutdown_index = 0;
                qemu_system_shutdown_request();
            }
        } else {
            shutdown_index = 0;
        }
        break;

        /* LGPL'ed VGA BIOS messages */
    case 0x501:
    case 0x502:
        fprintf(stderr, "VGA BIOS panic, line %d\n", val);
        exit(1);
    case 0x500:
    case 0x503:
#ifdef DEBUG_BIOS
        fprintf(stderr, "%c", val);
#endif
        break;
    }
}

void bochs_bios_init(void)
{
    register_ioport_write(0x400, 1, 2, bochs_bios_write, NULL);
    register_ioport_write(0x401, 1, 2, bochs_bios_write, NULL);
    register_ioport_write(0x402, 1, 1, bochs_bios_write, NULL);
    register_ioport_write(0x403, 1, 1, bochs_bios_write, NULL);
    register_ioport_write(0x8900, 1, 1, bochs_bios_write, NULL);

    register_ioport_write(0x501, 1, 2, bochs_bios_write, NULL);
    register_ioport_write(0x502, 1, 2, bochs_bios_write, NULL);
    register_ioport_write(0x500, 1, 1, bochs_bios_write, NULL);
    register_ioport_write(0x503, 1, 1, bochs_bios_write, NULL);
}


int load_kernel(const char *filename, uint8_t *addr, 
                uint8_t *real_addr)
{
    int fd, size;
    int setup_sects;

    fd = open(filename, O_RDONLY | O_BINARY);
    if (fd < 0)
        return -1;

    /* load 16 bit code */
    if (read(fd, real_addr, 512) != 512)
        goto fail;
    setup_sects = real_addr[0x1F1];
    if (!setup_sects)
        setup_sects = 4;
    if (read(fd, real_addr + 512, setup_sects * 512) != 
        setup_sects * 512)
        goto fail;
    
    /* load 32 bit code */
    size = read(fd, addr, 16 * 1024 * 1024);
    if (size < 0)
        goto fail;
    close(fd);
    return size;
 fail:
    close(fd);
    return -1;
}

static void main_cpu_reset(void *opaque)
{
    CPUState *env = opaque;
    cpu_reset(env);
}

static const int ide_iobase[2] = { 0x1f0, 0x170 };
static const int ide_iobase2[2] = { 0x3f6, 0x376 };
static const int ide_irq[2] = { 14, 15 };

#define NE2000_NB_MAX 6

static int ne2000_io[NE2000_NB_MAX] = { 0x300, 0x320, 0x340, 0x360, 0x280, 0x380 };
static int ne2000_irq[NE2000_NB_MAX] = { 9, 10, 11, 3, 4, 5 };

static int serial_io[MAX_SERIAL_PORTS] = { 0x3f8, 0x2f8, 0x3e8, 0x2e8 };
static int serial_irq[MAX_SERIAL_PORTS] = { 4, 3, 4, 3 };

static int parallel_io[MAX_PARALLEL_PORTS] = { 0x378, 0x278, 0x3bc };
static int parallel_irq[MAX_PARALLEL_PORTS] = { 7, 7, 7 };

#ifdef HAS_AUDIO
static void audio_init (PCIBus *pci_bus)
{
    struct soundhw *c;
    int audio_enabled = 0;

    for (c = soundhw; !audio_enabled && c->name; ++c) {
        audio_enabled = c->enabled;
    }

    if (audio_enabled) {
        AudioState *s;

        s = AUD_init ();
        if (s) {
            for (c = soundhw; c->name; ++c) {
                if (c->enabled) {
                    if (c->isa) {
                        c->init.init_isa (s);
                    }
                    else {
                        if (pci_bus) {
                            c->init.init_pci (pci_bus, s);
                        }
                    }
                }
            }
        }
    }
}
#endif

static void pc_init_ne2k_isa(NICInfo *nd)
{
    static int nb_ne2k = 0;

    if (nb_ne2k == NE2000_NB_MAX)
        return;
    isa_ne2000_init(ne2000_io[nb_ne2k], ne2000_irq[nb_ne2k], nd);
    nb_ne2k++;
}

#ifdef USE_KVM
extern kvm_context_t kvm_context;
extern int kvm_allowed;
#endif

/* PC hardware initialisation */
static void pc_init1(int ram_size, int vga_ram_size, int boot_device,
                     DisplayState *ds, const char **fd_filename, int snapshot,
                     const char *kernel_filename, const char *kernel_cmdline,
                     const char *initrd_filename,
                     int pci_enabled)
{
    char buf[1024];
    int ret, linux_boot, initrd_size, i;
    unsigned long bios_offset, vga_bios_offset, option_rom_offset;
    int bios_size, isa_bios_size;
    PCIBus *pci_bus;
    int piix3_devfn = -1;
    CPUState *env;
    NICInfo *nd;

    linux_boot = (kernel_filename != NULL);

    /* init CPUs */
    for(i = 0; i < smp_cpus; i++) {
        env = cpu_init();
        if (i != 0)
            env->hflags |= HF_HALTED_MASK;
        if (smp_cpus > 1) {
            /* XXX: enable it in all cases */
            env->cpuid_features |= CPUID_APIC;
        }
        register_savevm("cpu", i, 4, cpu_save, cpu_load, env);
        qemu_register_reset(main_cpu_reset, env);
        if (pci_enabled) {
            apic_init(env);
        }
    }

    /* allocate RAM */
    cpu_register_physical_memory(0, ram_size, 0);

    /* BIOS load */
    bios_offset = ram_size + vga_ram_size;
    vga_bios_offset = bios_offset + 256 * 1024;

    snprintf(buf, sizeof(buf), "%s/%s", bios_dir, BIOS_FILENAME);
    bios_size = get_image_size(buf);
    if (bios_size <= 0 || 
        (bios_size % 65536) != 0 ||
        bios_size > (256 * 1024)) {
        goto bios_error;
    }
    ret = load_image(buf, phys_ram_base + bios_offset);
    if (ret != bios_size) {
    bios_error:
        fprintf(stderr, "qemu: could not load PC bios '%s'\n", buf);
        exit(1);
    }

    /* VGA BIOS load */
    if (cirrus_vga_enabled) {
        snprintf(buf, sizeof(buf), "%s/%s", bios_dir, VGABIOS_CIRRUS_FILENAME);
    } else {
        snprintf(buf, sizeof(buf), "%s/%s", bios_dir, VGABIOS_FILENAME);
    }
    ret = load_image(buf, phys_ram_base + vga_bios_offset);
    
    /* setup basic memory access */
    cpu_register_physical_memory(0xc0000, 0x10000, 
                                 vga_bios_offset | IO_MEM_ROM);
#ifdef USE_KVM
    if (kvm_allowed)
	    memcpy(phys_ram_base + 0xc0000, phys_ram_base + vga_bios_offset,
		   0x10000);
#endif

    /* map the last 128KB of the BIOS in ISA space */
    isa_bios_size = bios_size;
    if (isa_bios_size > (128 * 1024))
        isa_bios_size = 128 * 1024;
    cpu_register_physical_memory(0xd0000, (192 * 1024) - isa_bios_size, 
                                 IO_MEM_UNASSIGNED);
    cpu_register_physical_memory(0x100000 - isa_bios_size, 
                                 isa_bios_size, 
                                 (bios_offset + bios_size - isa_bios_size) | IO_MEM_ROM);

#ifdef USE_KVM
    if (kvm_allowed)
	    memcpy(phys_ram_base + 0x100000 - isa_bios_size,
		   phys_ram_base + (bios_offset + bios_size - isa_bios_size),
		   isa_bios_size);
#endif

#ifdef USE_KVM
    if (kvm_allowed) {
	    bios_mem = kvm_create_phys_mem(kvm_context, (uint32_t)(-bios_size),
					   bios_size, 2, 0, 1);
	    if (!bios_mem)
		    exit(1);
	    memcpy(bios_mem, phys_ram_base + bios_offset, bios_size);

	    cpu_register_physical_memory(phys_ram_size - KVM_EXTRA_PAGES * 4096, KVM_EXTRA_PAGES * 4096,
					 (phys_ram_size - KVM_EXTRA_PAGES * 4096) | IO_MEM_ROM);
    }
#endif
    
    option_rom_offset = 0;
    for (i = 0; i < nb_option_roms; i++) {
	int offset = bios_offset + bios_size + option_rom_offset;
	int size;

	size = load_image(option_rom[i], phys_ram_base + offset);
	if ((size + option_rom_offset) > 0x10000) {
	    fprintf(stderr, "Too many option ROMS\n");
	    exit(1);
	}
	cpu_register_physical_memory(0xd0000 + option_rom_offset,
				     size, offset | IO_MEM_ROM);
	option_rom_offset += size + 2047;
	option_rom_offset -= (option_rom_offset % 2048);
    }

    /* map all the bios at the top of memory */
    cpu_register_physical_memory((uint32_t)(-bios_size), 
                                 bios_size, bios_offset | IO_MEM_ROM);
    
    bochs_bios_init();

    if (linux_boot) {
        uint8_t bootsect[512];
        uint8_t old_bootsect[512];

        if (bs_table[0] == NULL) {
            fprintf(stderr, "A disk image must be given for 'hda' when booting a Linux kernel\n");
            exit(1);
        }
        snprintf(buf, sizeof(buf), "%s/%s", bios_dir, LINUX_BOOT_FILENAME);
        ret = load_image(buf, bootsect);
        if (ret != sizeof(bootsect)) {
            fprintf(stderr, "qemu: could not load linux boot sector '%s'\n",
                    buf);
            exit(1);
        }

        if (bdrv_read(bs_table[0], 0, old_bootsect, 1) >= 0) {
            /* copy the MSDOS partition table */
            memcpy(bootsect + 0x1be, old_bootsect + 0x1be, 0x40);
        }

        bdrv_set_boot_sector(bs_table[0], bootsect, sizeof(bootsect));

        /* now we can load the kernel */
        ret = load_kernel(kernel_filename, 
                          phys_ram_base + KERNEL_LOAD_ADDR,
                          phys_ram_base + KERNEL_PARAMS_ADDR);
        if (ret < 0) {
            fprintf(stderr, "qemu: could not load kernel '%s'\n", 
                    kernel_filename);
            exit(1);
        }
        
        /* load initrd */
        initrd_size = 0;
        if (initrd_filename) {
            initrd_size = load_image(initrd_filename, phys_ram_base + INITRD_LOAD_ADDR);
            if (initrd_size < 0) {
                fprintf(stderr, "qemu: could not load initial ram disk '%s'\n", 
                        initrd_filename);
                exit(1);
            }
        }
        if (initrd_size > 0) {
            stl_raw(phys_ram_base + KERNEL_PARAMS_ADDR + 0x218, INITRD_LOAD_ADDR);
            stl_raw(phys_ram_base + KERNEL_PARAMS_ADDR + 0x21c, initrd_size);
        }
        pstrcpy(phys_ram_base + KERNEL_CMDLINE_ADDR, 4096,
                kernel_cmdline);
        stw_raw(phys_ram_base + KERNEL_PARAMS_ADDR + 0x20, 0xA33F);
        stw_raw(phys_ram_base + KERNEL_PARAMS_ADDR + 0x22,
                KERNEL_CMDLINE_ADDR - KERNEL_PARAMS_ADDR);
        /* loader type */
        stw_raw(phys_ram_base + KERNEL_PARAMS_ADDR + 0x210, 0x01);
    }

    if (pci_enabled) {
        pci_bus = i440fx_init(&i440fx_state);
        piix3_devfn = piix3_init(pci_bus, -1);
    } else {
        pci_bus = NULL;
    }

    /* init basic PC hardware */
    register_ioport_write(0x80, 1, 1, ioport80_write, NULL);

    register_ioport_write(0xf0, 1, 1, ioportF0_write, NULL);

    if (cirrus_vga_enabled) {
        if (pci_enabled) {
            pci_cirrus_vga_init(pci_bus, 
                                ds, phys_ram_base + ram_size, ram_size, 
                                vga_ram_size);
        } else {
            isa_cirrus_vga_init(ds, phys_ram_base + ram_size, ram_size, 
                                vga_ram_size);
        }
    } else {
        if (pci_enabled) {
            pci_vga_init(pci_bus, ds, phys_ram_base + ram_size, ram_size, 
                         vga_ram_size, 0, 0);
        } else {
            isa_vga_init(ds, phys_ram_base + ram_size, ram_size, 
                         vga_ram_size);
        }
    }

    rtc_state = rtc_init(0x70, 8);

    register_ioport_read(0x92, 1, 1, ioport92_read, NULL);
    register_ioport_write(0x92, 1, 1, ioport92_write, NULL);

    if (pci_enabled) {
        ioapic = ioapic_init();
    }
    isa_pic = pic_init(pic_irq_request, first_cpu);
    pit = pit_init(0x40, 0);
    pcspk_init(pit);
    if (pci_enabled) {
        pic_set_alt_irq_func(isa_pic, ioapic_set_irq, ioapic);
    }

    for(i = 0; i < MAX_SERIAL_PORTS; i++) {
        if (serial_hds[i]) {
            serial_init(&pic_set_irq_new, isa_pic,
                        serial_io[i], serial_irq[i], serial_hds[i]);
        }
    }

    for(i = 0; i < MAX_PARALLEL_PORTS; i++) {
        if (parallel_hds[i]) {
            parallel_init(parallel_io[i], parallel_irq[i], parallel_hds[i]);
        }
    }

    for(i = 0; i < nb_nics; i++) {
        nd = &nd_table[i];
        if (!nd->model) {
            if (pci_enabled) {
                nd->model = "ne2k_pci";
            } else {
                nd->model = "ne2k_isa";
            }
        }
        if (strcmp(nd->model, "ne2k_isa") == 0) {
            pc_init_ne2k_isa(nd);
        } else if (pci_enabled) {
            pci_nic_init(pci_bus, nd, -1);
        } else {
            fprintf(stderr, "qemu: Unsupported NIC: %s\n", nd->model);
            exit(1);
        }
    }

#define USE_HYPERCALL
#ifdef USE_HYPERCALL
    pci_hypercall_init(pci_bus);
#endif
    if (pci_enabled) {
        pci_piix3_ide_init(pci_bus, bs_table, piix3_devfn + 1);
    } else {
        for(i = 0; i < 2; i++) {
            isa_ide_init(ide_iobase[i], ide_iobase2[i], ide_irq[i],
                         bs_table[2 * i], bs_table[2 * i + 1]);
        }
    }

    kbd_init();
    DMA_init(0);
#ifdef HAS_AUDIO
    audio_init(pci_enabled ? pci_bus : NULL);
#endif

    floppy_controller = fdctrl_init(6, 2, 0, 0x3f0, fd_table);

    cmos_init(ram_size, boot_device, bs_table);

    if (pci_enabled && usb_enabled) {
        usb_uhci_init(pci_bus, piix3_devfn + 2);
    }

    if (pci_enabled && acpi_enabled) {
        uint8_t *eeprom_buf = qemu_mallocz(8 * 256); /* XXX: make this persistent */
        piix4_pm_init(pci_bus, piix3_devfn + 3);
        for (i = 0; i < 8; i++) {
            SMBusDevice *eeprom = smbus_eeprom_device_init(0x50 + i,
                eeprom_buf + (i * 256));
            piix4_smbus_register_device(eeprom, 0x50 + i);
        }
    }
    
    if (i440fx_state) {
        i440fx_init_memory_mappings(i440fx_state);
    }
#if 0
    /* ??? Need to figure out some way for the user to
       specify SCSI devices.  */
    if (pci_enabled) {
        void *scsi;
        BlockDriverState *bdrv;

        scsi = lsi_scsi_init(pci_bus, -1);
        bdrv = bdrv_new("scsidisk");
        bdrv_open(bdrv, "scsi_disk.img", 0);
        lsi_scsi_attach(scsi, bdrv, -1);
        bdrv = bdrv_new("scsicd");
        bdrv_open(bdrv, "scsi_cd.iso", 0);
        bdrv_set_type_hint(bdrv, BDRV_TYPE_CDROM);
        lsi_scsi_attach(scsi, bdrv, -1);
    }
#endif
}

static void pc_init_pci(int ram_size, int vga_ram_size, int boot_device,
                        DisplayState *ds, const char **fd_filename, 
                        int snapshot, 
                        const char *kernel_filename, 
                        const char *kernel_cmdline,
                        const char *initrd_filename)
{
    pc_init1(ram_size, vga_ram_size, boot_device,
             ds, fd_filename, snapshot,
             kernel_filename, kernel_cmdline,
             initrd_filename, 1);
}

static void pc_init_isa(int ram_size, int vga_ram_size, int boot_device,
                        DisplayState *ds, const char **fd_filename, 
                        int snapshot, 
                        const char *kernel_filename, 
                        const char *kernel_cmdline,
                        const char *initrd_filename)
{
    pc_init1(ram_size, vga_ram_size, boot_device,
             ds, fd_filename, snapshot,
             kernel_filename, kernel_cmdline,
             initrd_filename, 0);
}

QEMUMachine pc_machine = {
    "pc",
    "Standard PC",
    pc_init_pci,
};

QEMUMachine isapc_machine = {
    "isapc",
    "ISA-only PC",
    pc_init_isa,
};
