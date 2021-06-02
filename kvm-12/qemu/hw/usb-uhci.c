/*
 * USB UHCI controller emulation
 * 
 * Copyright (c) 2005 Fabrice Bellard
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

//#define DEBUG
//#define DEBUG_PACKET

#define UHCI_CMD_GRESET   (1 << 2)
#define UHCI_CMD_HCRESET  (1 << 1)
#define UHCI_CMD_RS       (1 << 0)

#define UHCI_STS_HCHALTED (1 << 5)
#define UHCI_STS_HCPERR   (1 << 4)
#define UHCI_STS_HSERR    (1 << 3)
#define UHCI_STS_RD       (1 << 2)
#define UHCI_STS_USBERR   (1 << 1)
#define UHCI_STS_USBINT   (1 << 0)

#define TD_CTRL_SPD     (1 << 29)
#define TD_CTRL_ERROR_SHIFT  27
#define TD_CTRL_IOS     (1 << 25)
#define TD_CTRL_IOC     (1 << 24)
#define TD_CTRL_ACTIVE  (1 << 23)
#define TD_CTRL_STALL   (1 << 22)
#define TD_CTRL_BABBLE  (1 << 20)
#define TD_CTRL_NAK     (1 << 19)
#define TD_CTRL_TIMEOUT (1 << 18)

#define UHCI_PORT_RESET (1 << 9)
#define UHCI_PORT_LSDA  (1 << 8)
#define UHCI_PORT_ENC   (1 << 3)
#define UHCI_PORT_EN    (1 << 2)
#define UHCI_PORT_CSC   (1 << 1)
#define UHCI_PORT_CCS   (1 << 0)

#define FRAME_TIMER_FREQ 1000

#define FRAME_MAX_LOOPS  100

#define NB_PORTS 2

typedef struct UHCIPort {
    USBPort port;
    uint16_t ctrl;
} UHCIPort;

typedef struct UHCIState {
    PCIDevice dev;
    uint16_t cmd; /* cmd register */
    uint16_t status;
    uint16_t intr; /* interrupt enable register */
    uint16_t frnum; /* frame number */
    uint32_t fl_base_addr; /* frame list base address */
    uint8_t sof_timing;
    uint8_t status2; /* bit 0 and 1 are used to generate UHCI_STS_USBINT */
    QEMUTimer *frame_timer;
    UHCIPort ports[NB_PORTS];
} UHCIState;

typedef struct UHCI_TD {
    uint32_t link;
    uint32_t ctrl; /* see TD_CTRL_xxx */
    uint32_t token;
    uint32_t buffer;
} UHCI_TD;

typedef struct UHCI_QH {
    uint32_t link;
    uint32_t el_link;
} UHCI_QH;

static void uhci_attach(USBPort *port1, USBDevice *dev);

static void uhci_update_irq(UHCIState *s)
{
    int level;
    if (((s->status2 & 1) && (s->intr & (1 << 2))) ||
        ((s->status2 & 2) && (s->intr & (1 << 3))) ||
        ((s->status & UHCI_STS_USBERR) && (s->intr & (1 << 0))) ||
        ((s->status & UHCI_STS_RD) && (s->intr & (1 << 1))) ||
        (s->status & UHCI_STS_HSERR) ||
        (s->status & UHCI_STS_HCPERR)) {
        level = 1;
    } else {
        level = 0;
    }
    pci_set_irq(&s->dev, 3, level);
}

static void uhci_reset(UHCIState *s)
{
    uint8_t *pci_conf;
    int i;
    UHCIPort *port;

    pci_conf = s->dev.config;

    pci_conf[0x6a] = 0x01; /* usb clock */
    pci_conf[0x6b] = 0x00;
    s->cmd = 0;
    s->status = 0;
    s->status2 = 0;
    s->intr = 0;
    s->fl_base_addr = 0;
    s->sof_timing = 64;
    for(i = 0; i < NB_PORTS; i++) {
        port = &s->ports[i];
        port->ctrl = 0x0080;
        if (port->port.dev)
            uhci_attach(&port->port, port->port.dev);
    }
}

static void uhci_save(QEMUFile *f, void *opaque)
{
    UHCIState *s = opaque;
    uint8_t num_ports = NB_PORTS;
    int i;
    
    generic_pci_save(f, &s->dev);

    qemu_put_8s(f, &num_ports);
    for (i = 0; i < num_ports; ++i)
        qemu_put_be16s(f, &s->ports[i].ctrl);
    qemu_put_be16s(f, &s->cmd);
    qemu_put_be16s(f, &s->status);
    qemu_put_be16s(f, &s->intr);
    qemu_put_be16s(f, &s->frnum);
    qemu_put_be32s(f, &s->fl_base_addr);
    qemu_put_8s(f, &s->sof_timing);
    qemu_put_8s(f, &s->status2);
    qemu_put_timer(f, s->frame_timer);
}

static int uhci_load(QEMUFile* f,void* opaque,int version_id)
{
    UHCIState *s = opaque;
    uint8_t num_ports;
    int i, ret;

    if (version_id > 1)
        return -EINVAL;

    ret = generic_pci_load(f, &s->dev, 1);
    if (ret < 0)
        return ret;

    qemu_get_8s(f, &num_ports);
    if (num_ports != NB_PORTS)
        return -EINVAL;
    
    for (i = 0; i < num_ports; ++i)
        qemu_get_be16s(f, &s->ports[i].ctrl);
    qemu_get_be16s(f, &s->cmd);
    qemu_get_be16s(f, &s->status);
    qemu_get_be16s(f, &s->intr);
    qemu_get_be16s(f, &s->frnum);
    qemu_get_be32s(f, &s->fl_base_addr);
    qemu_get_8s(f, &s->sof_timing);
    qemu_get_8s(f, &s->status2);
    qemu_get_timer(f, s->frame_timer);
    
    return 0;
}

static void uhci_ioport_writeb(void *opaque, uint32_t addr, uint32_t val)
{
    UHCIState *s = opaque;
    
    addr &= 0x1f;
    switch(addr) {
    case 0x0c:
        s->sof_timing = val;
        break;
    }
}

static uint32_t uhci_ioport_readb(void *opaque, uint32_t addr)
{
    UHCIState *s = opaque;
    uint32_t val;

    addr &= 0x1f;
    switch(addr) {
    case 0x0c:
        val = s->sof_timing;
        break;
    default:
        val = 0xff;
        break;
    }
    return val;
}

static void uhci_ioport_writew(void *opaque, uint32_t addr, uint32_t val)
{
    UHCIState *s = opaque;
    
    addr &= 0x1f;
#ifdef DEBUG
    printf("uhci writew port=0x%04x val=0x%04x\n", addr, val);
#endif
    switch(addr) {
    case 0x00:
        if ((val & UHCI_CMD_RS) && !(s->cmd & UHCI_CMD_RS)) {
            /* start frame processing */
            qemu_mod_timer(s->frame_timer, qemu_get_clock(vm_clock));
            s->status &= ~UHCI_STS_HCHALTED;
        } else if (!(val & UHCI_CMD_RS)) {
            s->status |= UHCI_STS_HCHALTED;
        }
        if (val & UHCI_CMD_GRESET) {
            UHCIPort *port;
            USBDevice *dev;
            int i;

            /* send reset on the USB bus */
            for(i = 0; i < NB_PORTS; i++) {
                port = &s->ports[i];
                dev = port->port.dev;
                if (dev) {
                    dev->handle_packet(dev, 
                                       USB_MSG_RESET, 0, 0, NULL, 0);
                }
            }
            uhci_reset(s);
            return;
        }
        if (val & UHCI_CMD_HCRESET) {
            uhci_reset(s);
            return;
        }
        s->cmd = val;
        break;
    case 0x02:
        s->status &= ~val;
        /* XXX: the chip spec is not coherent, so we add a hidden
           register to distinguish between IOC and SPD */
        if (val & UHCI_STS_USBINT)
            s->status2 = 0;
        uhci_update_irq(s);
        break;
    case 0x04:
        s->intr = val;
        uhci_update_irq(s);
        break;
    case 0x06:
        if (s->status & UHCI_STS_HCHALTED)
            s->frnum = val & 0x7ff;
        break;
    case 0x10 ... 0x1f:
        {
            UHCIPort *port;
            USBDevice *dev;
            int n;

            n = (addr >> 1) & 7;
            if (n >= NB_PORTS)
                return;
            port = &s->ports[n];
            dev = port->port.dev;
            if (dev) {
                /* port reset */
                if ( (val & UHCI_PORT_RESET) && 
                     !(port->ctrl & UHCI_PORT_RESET) ) {
                    dev->handle_packet(dev, 
                                       USB_MSG_RESET, 0, 0, NULL, 0);
                }
            }
            port->ctrl = (port->ctrl & 0x01fb) | (val & ~0x01fb);
            /* some bits are reset when a '1' is written to them */
            port->ctrl &= ~(val & 0x000a);
        }
        break;
    }
}

static uint32_t uhci_ioport_readw(void *opaque, uint32_t addr)
{
    UHCIState *s = opaque;
    uint32_t val;

    addr &= 0x1f;
    switch(addr) {
    case 0x00:
        val = s->cmd;
        break;
    case 0x02:
        val = s->status;
        break;
    case 0x04:
        val = s->intr;
        break;
    case 0x06:
        val = s->frnum;
        break;
    case 0x10 ... 0x1f:
        {
            UHCIPort *port;
            int n;
            n = (addr >> 1) & 7;
            if (n >= NB_PORTS) 
                goto read_default;
            port = &s->ports[n];
            val = port->ctrl;
        }
        break;
    default:
    read_default:
        val = 0xff7f; /* disabled port */
        break;
    }
#ifdef DEBUG
    printf("uhci readw port=0x%04x val=0x%04x\n", addr, val);
#endif
    return val;
}

static void uhci_ioport_writel(void *opaque, uint32_t addr, uint32_t val)
{
    UHCIState *s = opaque;

    addr &= 0x1f;
#ifdef DEBUG
    printf("uhci writel port=0x%04x val=0x%08x\n", addr, val);
#endif
    switch(addr) {
    case 0x08:
        s->fl_base_addr = val & ~0xfff;
        break;
    }
}

static uint32_t uhci_ioport_readl(void *opaque, uint32_t addr)
{
    UHCIState *s = opaque;
    uint32_t val;

    addr &= 0x1f;
    switch(addr) {
    case 0x08:
        val = s->fl_base_addr;
        break;
    default:
        val = 0xffffffff;
        break;
    }
    return val;
}

static void uhci_attach(USBPort *port1, USBDevice *dev)
{
    UHCIState *s = port1->opaque;
    UHCIPort *port = &s->ports[port1->index];

    if (dev) {
        if (port->port.dev) {
            usb_attach(port1, NULL);
        }
        /* set connect status */
        port->ctrl |= UHCI_PORT_CCS | UHCI_PORT_CSC;

        /* update speed */
        if (dev->speed == USB_SPEED_LOW)
            port->ctrl |= UHCI_PORT_LSDA;
        else
            port->ctrl &= ~UHCI_PORT_LSDA;
        port->port.dev = dev;
        /* send the attach message */
        dev->handle_packet(dev, 
                           USB_MSG_ATTACH, 0, 0, NULL, 0);
    } else {
        /* set connect status */
        if (port->ctrl & UHCI_PORT_CCS) {
            port->ctrl &= ~UHCI_PORT_CCS;
            port->ctrl |= UHCI_PORT_CSC;
        }
        /* disable port */
        if (port->ctrl & UHCI_PORT_EN) {
            port->ctrl &= ~UHCI_PORT_EN;
            port->ctrl |= UHCI_PORT_ENC;
        }
        dev = port->port.dev;
        if (dev) {
            /* send the detach message */
            dev->handle_packet(dev, 
                               USB_MSG_DETACH, 0, 0, NULL, 0);
        }
        port->port.dev = NULL;
    }
}

static int uhci_broadcast_packet(UHCIState *s, uint8_t pid, 
                                 uint8_t devaddr, uint8_t devep,
                                 uint8_t *data, int len)
{
    UHCIPort *port;
    USBDevice *dev;
    int i, ret;

#ifdef DEBUG_PACKET
    {
        const char *pidstr;
        switch(pid) {
        case USB_TOKEN_SETUP: pidstr = "SETUP"; break;
        case USB_TOKEN_IN: pidstr = "IN"; break;
        case USB_TOKEN_OUT: pidstr = "OUT"; break;
        default: pidstr = "?"; break;
        }
        printf("frame %d: pid=%s addr=0x%02x ep=%d len=%d\n",
               s->frnum, pidstr, devaddr, devep, len);
        if (pid != USB_TOKEN_IN) {
            printf("     data_out=");
            for(i = 0; i < len; i++) {
                printf(" %02x", data[i]);
            }
            printf("\n");
        }
    }
#endif
    for(i = 0; i < NB_PORTS; i++) {
        port = &s->ports[i];
        dev = port->port.dev;
        if (dev && (port->ctrl & UHCI_PORT_EN)) {
            ret = dev->handle_packet(dev, pid, 
                                     devaddr, devep,
                                     data, len);
            if (ret != USB_RET_NODEV) {
#ifdef DEBUG_PACKET
                {
                    printf("     ret=%d ", ret);
                    if (pid == USB_TOKEN_IN && ret > 0) {
                        printf("data_in=");
                        for(i = 0; i < ret; i++) {
                            printf(" %02x", data[i]);
                        }
                    }
                    printf("\n");
                }
#endif
                return ret;
            }
        }
    }
    return USB_RET_NODEV;
}

/* return -1 if fatal error (frame must be stopped)
          0 if TD successful
          1 if TD unsuccessful or inactive
*/
static int uhci_handle_td(UHCIState *s, UHCI_TD *td, int *int_mask)
{
    uint8_t pid;
    uint8_t buf[1280];
    int len, max_len, err, ret;

    if (td->ctrl & TD_CTRL_IOC) {
        *int_mask |= 0x01;
    }
    
    if (!(td->ctrl & TD_CTRL_ACTIVE))
        return 1;

    /* TD is active */
    max_len = ((td->token >> 21) + 1) & 0x7ff;
    pid = td->token & 0xff;
    switch(pid) {
    case USB_TOKEN_OUT:
    case USB_TOKEN_SETUP:
        cpu_physical_memory_read(td->buffer, buf, max_len);
        ret = uhci_broadcast_packet(s, pid, 
                                    (td->token >> 8) & 0x7f,
                                    (td->token >> 15) & 0xf,
                                    buf, max_len);
        len = max_len;
        break;
    case USB_TOKEN_IN:
        ret = uhci_broadcast_packet(s, pid, 
                                    (td->token >> 8) & 0x7f,
                                    (td->token >> 15) & 0xf,
                                    buf, max_len);
        if (ret >= 0) {
            len = ret;
            if (len > max_len) {
                len = max_len;
                ret = USB_RET_BABBLE;
            }
            if (len > 0) {
                /* write the data back */
                cpu_physical_memory_write(td->buffer, buf, len);
            }
        } else {
            len = 0;
        }
        break;
    default:
        /* invalid pid : frame interrupted */
        s->status |= UHCI_STS_HCPERR;
        uhci_update_irq(s);
        return -1;
    }
    if (td->ctrl & TD_CTRL_IOS)
        td->ctrl &= ~TD_CTRL_ACTIVE;
    if (ret >= 0) {
        td->ctrl = (td->ctrl & ~0x7ff) | ((len - 1) & 0x7ff);
        td->ctrl &= ~TD_CTRL_ACTIVE;
        if (pid == USB_TOKEN_IN && 
            (td->ctrl & TD_CTRL_SPD) &&
            len < max_len) {
            *int_mask |= 0x02;
            /* short packet: do not update QH */
            return 1;
        } else {
            /* success */
            return 0;
        }
    } else {
        switch(ret) {
        default:
        case USB_RET_NODEV:
        do_timeout:
            td->ctrl |= TD_CTRL_TIMEOUT;
            err = (td->ctrl >> TD_CTRL_ERROR_SHIFT) & 3;
            if (err != 0) {
                err--;
                if (err == 0) {
                    td->ctrl &= ~TD_CTRL_ACTIVE;
                    s->status |= UHCI_STS_USBERR;
                    uhci_update_irq(s);
                }
            }
            td->ctrl = (td->ctrl & ~(3 << TD_CTRL_ERROR_SHIFT)) | 
                (err << TD_CTRL_ERROR_SHIFT);
            return 1;
        case USB_RET_NAK:
            td->ctrl |= TD_CTRL_NAK;
            if (pid == USB_TOKEN_SETUP)
                goto do_timeout;
            return 1;
        case USB_RET_STALL:
            td->ctrl |= TD_CTRL_STALL;
            td->ctrl &= ~TD_CTRL_ACTIVE;
            return 1;
        case USB_RET_BABBLE:
            td->ctrl |= TD_CTRL_BABBLE | TD_CTRL_STALL;
            td->ctrl &= ~TD_CTRL_ACTIVE;
            /* frame interrupted */
            return -1;
        }
    }
}

static void uhci_frame_timer(void *opaque)
{
    UHCIState *s = opaque;
    int64_t expire_time;
    uint32_t frame_addr, link, old_td_ctrl, val;
    int int_mask, cnt, ret;
    UHCI_TD td;
    UHCI_QH qh;

    if (!(s->cmd & UHCI_CMD_RS)) {
        qemu_del_timer(s->frame_timer);
        /* set hchalted bit in status - UHCI11D 2.1.2 */
        s->status |= UHCI_STS_HCHALTED;
        return;
    }
    frame_addr = s->fl_base_addr + ((s->frnum & 0x3ff) << 2);
    cpu_physical_memory_read(frame_addr, (uint8_t *)&link, 4);
    le32_to_cpus(&link);
    int_mask = 0;
    cnt = FRAME_MAX_LOOPS;
    while ((link & 1) == 0) {
        if (--cnt == 0)
            break;
        /* valid frame */
        if (link & 2) {
            /* QH */
            cpu_physical_memory_read(link & ~0xf, (uint8_t *)&qh, sizeof(qh));
            le32_to_cpus(&qh.link);
            le32_to_cpus(&qh.el_link);
        depth_first:
            if (qh.el_link & 1) {
                /* no element : go to next entry */
                link = qh.link;
            } else if (qh.el_link & 2) {
                /* QH */
                link = qh.el_link;
            } else {
                /* TD */
                if (--cnt == 0)
                    break;
                cpu_physical_memory_read(qh.el_link & ~0xf, 
                                         (uint8_t *)&td, sizeof(td));
                le32_to_cpus(&td.link);
                le32_to_cpus(&td.ctrl);
                le32_to_cpus(&td.token);
                le32_to_cpus(&td.buffer);
                old_td_ctrl = td.ctrl;
                ret = uhci_handle_td(s, &td, &int_mask);
                /* update the status bits of the TD */
                if (old_td_ctrl != td.ctrl) {
                    val = cpu_to_le32(td.ctrl);
                    cpu_physical_memory_write((qh.el_link & ~0xf) + 4, 
                                              (const uint8_t *)&val, 
                                              sizeof(val));
                }
                if (ret < 0)
                    break; /* interrupted frame */
                if (ret == 0) {
                    /* update qh element link */
                    qh.el_link = td.link;
                    val = cpu_to_le32(qh.el_link);
                    cpu_physical_memory_write((link & ~0xf) + 4, 
                                              (const uint8_t *)&val, 
                                              sizeof(val));
                    if (qh.el_link & 4) {
                        /* depth first */
                        goto depth_first;
                    }
                }
                /* go to next entry */
                link = qh.link;
            }
        } else {
            /* TD */
            cpu_physical_memory_read(link & ~0xf, (uint8_t *)&td, sizeof(td));
            le32_to_cpus(&td.link);
            le32_to_cpus(&td.ctrl);
            le32_to_cpus(&td.token);
            le32_to_cpus(&td.buffer);
            old_td_ctrl = td.ctrl;
            ret = uhci_handle_td(s, &td, &int_mask);
            /* update the status bits of the TD */
            if (old_td_ctrl != td.ctrl) {
                val = cpu_to_le32(td.ctrl);
                cpu_physical_memory_write((link & ~0xf) + 4, 
                                          (const uint8_t *)&val, 
                                          sizeof(val));
            }
            if (ret < 0)
                break; /* interrupted frame */
            link = td.link;
        }
    }
    s->frnum = (s->frnum + 1) & 0x7ff;
    if (int_mask) {
        s->status2 |= int_mask;
        s->status |= UHCI_STS_USBINT;
        uhci_update_irq(s);
    }
    /* prepare the timer for the next frame */
    expire_time = qemu_get_clock(vm_clock) + 
        (ticks_per_sec / FRAME_TIMER_FREQ);
    qemu_mod_timer(s->frame_timer, expire_time);
}

static void uhci_map(PCIDevice *pci_dev, int region_num, 
                    uint32_t addr, uint32_t size, int type)
{
    UHCIState *s = (UHCIState *)pci_dev;

    register_ioport_write(addr, 32, 2, uhci_ioport_writew, s);
    register_ioport_read(addr, 32, 2, uhci_ioport_readw, s);
    register_ioport_write(addr, 32, 4, uhci_ioport_writel, s);
    register_ioport_read(addr, 32, 4, uhci_ioport_readl, s);
    register_ioport_write(addr, 32, 1, uhci_ioport_writeb, s);
    register_ioport_read(addr, 32, 1, uhci_ioport_readb, s);
}

void usb_uhci_init(PCIBus *bus, int devfn)
{
    UHCIState *s;
    uint8_t *pci_conf;
    int i;

    s = (UHCIState *)pci_register_device(bus,
                                        "USB-UHCI", sizeof(UHCIState),
                                        devfn, NULL, NULL);
    pci_conf = s->dev.config;
    pci_conf[0x00] = 0x86;
    pci_conf[0x01] = 0x80;
    pci_conf[0x02] = 0x20;
    pci_conf[0x03] = 0x70;
    pci_conf[0x08] = 0x01; // revision number
    pci_conf[0x09] = 0x00;
    pci_conf[0x0a] = 0x03;
    pci_conf[0x0b] = 0x0c;
    pci_conf[0x0e] = 0x00; // header_type
    pci_conf[0x3d] = 4; // interrupt pin 3
    pci_conf[0x60] = 0x10; // release number
    
    for(i = 0; i < NB_PORTS; i++) {
        qemu_register_usb_port(&s->ports[i].port, s, i, uhci_attach);
    }
    s->frame_timer = qemu_new_timer(vm_clock, uhci_frame_timer, s);

    uhci_reset(s);

    /* Use region 4 for consistency with real hardware.  BSD guests seem
       to rely on this.  */
    pci_register_io_region(&s->dev, 4, 0x20, 
                           PCI_ADDRESS_SPACE_IO, uhci_map);

    register_savevm("uhci", 0, 1, uhci_save, uhci_load, s);
}
