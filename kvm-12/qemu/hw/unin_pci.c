/*
 * QEMU Uninorth PCI host (for all Mac99 and newer machines)
 *
 * Copyright (c) 2006 Fabrice Bellard
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
typedef target_phys_addr_t pci_addr_t;
#include "pci_host.h"

typedef PCIHostState UNINState;

static void pci_unin_main_config_writel (void *opaque, target_phys_addr_t addr,
                                         uint32_t val)
{
    UNINState *s = opaque;
    int i;

#ifdef TARGET_WORDS_BIGENDIAN
    val = bswap32(val);
#endif

    for (i = 11; i < 32; i++) {
        if ((val & (1 << i)) != 0)
            break;
    }
#if 0
    s->config_reg = 0x80000000 | (1 << 16) | (val & 0x7FC) | (i << 11);
#else
    s->config_reg = 0x80000000 | (0 << 16) | (val & 0x7FC) | (i << 11);
#endif
}

static uint32_t pci_unin_main_config_readl (void *opaque,
                                            target_phys_addr_t addr)
{
    UNINState *s = opaque;
    uint32_t val;
    int devfn;

    devfn = (s->config_reg >> 8) & 0xFF;
    val = (1 << (devfn >> 3)) | ((devfn & 0x07) << 8) | (s->config_reg & 0xFC);
#ifdef TARGET_WORDS_BIGENDIAN
    val = bswap32(val);
#endif

    return val;
}

static CPUWriteMemoryFunc *pci_unin_main_config_write[] = {
    &pci_unin_main_config_writel,
    &pci_unin_main_config_writel,
    &pci_unin_main_config_writel,
};

static CPUReadMemoryFunc *pci_unin_main_config_read[] = {
    &pci_unin_main_config_readl,
    &pci_unin_main_config_readl,
    &pci_unin_main_config_readl,
};

static CPUWriteMemoryFunc *pci_unin_main_write[] = {
    &pci_host_data_writeb,
    &pci_host_data_writew,
    &pci_host_data_writel,
};

static CPUReadMemoryFunc *pci_unin_main_read[] = {
    &pci_host_data_readb,
    &pci_host_data_readw,
    &pci_host_data_readl,
};

#if 0

static void pci_unin_config_writel (void *opaque, target_phys_addr_t addr,
                                    uint32_t val)
{
    UNINState *s = opaque;

#ifdef TARGET_WORDS_BIGENDIAN
    val = bswap32(val);
#endif
    s->config_reg = 0x80000000 | (val & ~0x00000001);
}

static uint32_t pci_unin_config_readl (void *opaque,
                                       target_phys_addr_t addr)
{
    UNINState *s = opaque;
    uint32_t val;

    val = (s->config_reg | 0x00000001) & ~0x80000000;
#ifdef TARGET_WORDS_BIGENDIAN
    val = bswap32(val);
#endif

    return val;
}

static CPUWriteMemoryFunc *pci_unin_config_write[] = {
    &pci_unin_config_writel,
    &pci_unin_config_writel,
    &pci_unin_config_writel,
};

static CPUReadMemoryFunc *pci_unin_config_read[] = {
    &pci_unin_config_readl,
    &pci_unin_config_readl,
    &pci_unin_config_readl,
};

static CPUWriteMemoryFunc *pci_unin_write[] = {
    &pci_host_pci_writeb,
    &pci_host_pci_writew,
    &pci_host_pci_writel,
};

static CPUReadMemoryFunc *pci_unin_read[] = {
    &pci_host_pci_readb,
    &pci_host_pci_readw,
    &pci_host_pci_readl,
};
#endif

static void pci_unin_set_irq(PCIDevice *d, void *pic, int irq_num, int level)
{
    openpic_set_irq(pic, d->config[PCI_INTERRUPT_LINE], level);
}

PCIBus *pci_pmac_init(void *pic)
{
    UNINState *s;
    PCIDevice *d;
    int pci_mem_config, pci_mem_data;

    /* Use values found on a real PowerMac */
    /* Uninorth main bus */
    s = qemu_mallocz(sizeof(UNINState));
    s->bus = pci_register_bus(pci_unin_set_irq, NULL, 11 << 3);

    pci_mem_config = cpu_register_io_memory(0, pci_unin_main_config_read, 
                                            pci_unin_main_config_write, s);
    pci_mem_data = cpu_register_io_memory(0, pci_unin_main_read,
                                          pci_unin_main_write, s);
    cpu_register_physical_memory(0xf2800000, 0x1000, pci_mem_config);
    cpu_register_physical_memory(0xf2c00000, 0x1000, pci_mem_data);
    d = pci_register_device(s->bus, "Uni-north main", sizeof(PCIDevice), 
                            11 << 3, NULL, NULL);
    d->config[0x00] = 0x6b; // vendor_id : Apple
    d->config[0x01] = 0x10;
    d->config[0x02] = 0x1F; // device_id
    d->config[0x03] = 0x00;
    d->config[0x08] = 0x00; // revision
    d->config[0x0A] = 0x00; // class_sub = pci host
    d->config[0x0B] = 0x06; // class_base = PCI_bridge
    d->config[0x0C] = 0x08; // cache_line_size
    d->config[0x0D] = 0x10; // latency_timer
    d->config[0x0E] = 0x00; // header_type
    d->config[0x34] = 0x00; // capabilities_pointer

#if 0 // XXX: not activated as PPC BIOS doesn't handle mutiple buses properly
    /* pci-to-pci bridge */
    d = pci_register_device("Uni-north bridge", sizeof(PCIDevice), 0, 13 << 3,
                            NULL, NULL);
    d->config[0x00] = 0x11; // vendor_id : TI
    d->config[0x01] = 0x10;
    d->config[0x02] = 0x26; // device_id
    d->config[0x03] = 0x00;
    d->config[0x08] = 0x05; // revision
    d->config[0x0A] = 0x04; // class_sub = pci2pci
    d->config[0x0B] = 0x06; // class_base = PCI_bridge
    d->config[0x0C] = 0x08; // cache_line_size
    d->config[0x0D] = 0x20; // latency_timer
    d->config[0x0E] = 0x01; // header_type

    d->config[0x18] = 0x01; // primary_bus
    d->config[0x19] = 0x02; // secondary_bus
    d->config[0x1A] = 0x02; // subordinate_bus
    d->config[0x1B] = 0x20; // secondary_latency_timer
    d->config[0x1C] = 0x11; // io_base
    d->config[0x1D] = 0x01; // io_limit
    d->config[0x20] = 0x00; // memory_base
    d->config[0x21] = 0x80;
    d->config[0x22] = 0x00; // memory_limit
    d->config[0x23] = 0x80;
    d->config[0x24] = 0x01; // prefetchable_memory_base
    d->config[0x25] = 0x80;
    d->config[0x26] = 0xF1; // prefectchable_memory_limit
    d->config[0x27] = 0x7F;
    // d->config[0x34] = 0xdc // capabilities_pointer
#endif
#if 0 // XXX: not needed for now
    /* Uninorth AGP bus */
    s = &pci_bridge[1];
    pci_mem_config = cpu_register_io_memory(0, pci_unin_config_read, 
                                            pci_unin_config_write, s);
    pci_mem_data = cpu_register_io_memory(0, pci_unin_read,
                                          pci_unin_write, s);
    cpu_register_physical_memory(0xf0800000, 0x1000, pci_mem_config);
    cpu_register_physical_memory(0xf0c00000, 0x1000, pci_mem_data);

    d = pci_register_device("Uni-north AGP", sizeof(PCIDevice), 0, 11 << 3,
                            NULL, NULL);
    d->config[0x00] = 0x6b; // vendor_id : Apple
    d->config[0x01] = 0x10;
    d->config[0x02] = 0x20; // device_id
    d->config[0x03] = 0x00;
    d->config[0x08] = 0x00; // revision
    d->config[0x0A] = 0x00; // class_sub = pci host
    d->config[0x0B] = 0x06; // class_base = PCI_bridge
    d->config[0x0C] = 0x08; // cache_line_size
    d->config[0x0D] = 0x10; // latency_timer
    d->config[0x0E] = 0x00; // header_type
    //    d->config[0x34] = 0x80; // capabilities_pointer
#endif

#if 0 // XXX: not needed for now
    /* Uninorth internal bus */
    s = &pci_bridge[2];
    pci_mem_config = cpu_register_io_memory(0, pci_unin_config_read, 
                                            pci_unin_config_write, s);
    pci_mem_data = cpu_register_io_memory(0, pci_unin_read,
                                          pci_unin_write, s);
    cpu_register_physical_memory(0xf4800000, 0x1000, pci_mem_config);
    cpu_register_physical_memory(0xf4c00000, 0x1000, pci_mem_data);

    d = pci_register_device("Uni-north internal", sizeof(PCIDevice),
                            3, 11 << 3, NULL, NULL);
    d->config[0x00] = 0x6b; // vendor_id : Apple
    d->config[0x01] = 0x10;
    d->config[0x02] = 0x1E; // device_id
    d->config[0x03] = 0x00;
    d->config[0x08] = 0x00; // revision
    d->config[0x0A] = 0x00; // class_sub = pci host
    d->config[0x0B] = 0x06; // class_base = PCI_bridge
    d->config[0x0C] = 0x08; // cache_line_size
    d->config[0x0D] = 0x10; // latency_timer
    d->config[0x0E] = 0x00; // header_type
    d->config[0x34] = 0x00; // capabilities_pointer
#endif
    return s->bus;
}

