/* This is the Linux kernel elf-loading code, ported into user space */

#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>

#include "qemu.h"
#include "disas.h"

/* this flag is uneffective under linux too, should be deleted */
#ifndef MAP_DENYWRITE
#define MAP_DENYWRITE 0
#endif

/* should probably go in elf.h */
#ifndef ELIBBAD
#define ELIBBAD 80
#endif

#ifdef TARGET_I386

#define ELF_PLATFORM get_elf_platform()

static const char *get_elf_platform(void)
{
    static char elf_platform[] = "i386";
    int family = (global_env->cpuid_version >> 8) & 0xff;
    if (family > 6)
        family = 6;
    if (family >= 3)
        elf_platform[1] = '0' + family;
    return elf_platform;
}

#define ELF_HWCAP get_elf_hwcap()

static uint32_t get_elf_hwcap(void)
{
  return global_env->cpuid_features;
}

#define ELF_START_MMAP 0x80000000

/*
 * This is used to ensure we don't load something for the wrong architecture.
 */
#define elf_check_arch(x) ( ((x) == EM_386) || ((x) == EM_486) )

/*
 * These are used to set parameters in the core dumps.
 */
#define ELF_CLASS	ELFCLASS32
#define ELF_DATA	ELFDATA2LSB
#define ELF_ARCH	EM_386

static inline void init_thread(struct target_pt_regs *regs, struct image_info *infop)
{
    regs->esp = infop->start_stack;
    regs->eip = infop->entry;

    /* SVR4/i386 ABI (pages 3-31, 3-32) says that when the program
       starts %edx contains a pointer to a function which might be
       registered using `atexit'.  This provides a mean for the
       dynamic linker to call DT_FINI functions for shared libraries
       that have been loaded before the code runs.

       A value of 0 tells we have no such handler.  */
    regs->edx = 0;
}

#define USE_ELF_CORE_DUMP
#define ELF_EXEC_PAGESIZE	4096

#endif

#ifdef TARGET_ARM

#define ELF_START_MMAP 0x80000000

#define elf_check_arch(x) ( (x) == EM_ARM )

#define ELF_CLASS	ELFCLASS32
#ifdef TARGET_WORDS_BIGENDIAN
#define ELF_DATA	ELFDATA2MSB
#else
#define ELF_DATA	ELFDATA2LSB
#endif
#define ELF_ARCH	EM_ARM

static inline void init_thread(struct target_pt_regs *regs, struct image_info *infop)
{
    target_long stack = infop->start_stack;
    memset(regs, 0, sizeof(*regs));
    regs->ARM_cpsr = 0x10;
    if (infop->entry & 1)
      regs->ARM_cpsr |= CPSR_T;
    regs->ARM_pc = infop->entry & 0xfffffffe;
    regs->ARM_sp = infop->start_stack;
    regs->ARM_r2 = tgetl(stack + 8); /* envp */
    regs->ARM_r1 = tgetl(stack + 4); /* envp */
    /* XXX: it seems that r0 is zeroed after ! */
    regs->ARM_r0 = 0;
    /* For uClinux PIC binaries.  */
    regs->ARM_r10 = infop->start_data;
}

#define USE_ELF_CORE_DUMP
#define ELF_EXEC_PAGESIZE	4096

enum
{
  ARM_HWCAP_ARM_SWP       = 1 << 0,
  ARM_HWCAP_ARM_HALF      = 1 << 1,
  ARM_HWCAP_ARM_THUMB     = 1 << 2,
  ARM_HWCAP_ARM_26BIT     = 1 << 3,
  ARM_HWCAP_ARM_FAST_MULT = 1 << 4,
  ARM_HWCAP_ARM_FPA       = 1 << 5,
  ARM_HWCAP_ARM_VFP       = 1 << 6,
  ARM_HWCAP_ARM_EDSP      = 1 << 7,
};

#define ELF_HWCAP (ARM_HWCAP_ARM_SWP | ARM_HWCAP_ARM_HALF              \
                    | ARM_HWCAP_ARM_THUMB | ARM_HWCAP_ARM_FAST_MULT     \
                    | ARM_HWCAP_ARM_FPA | ARM_HWCAP_ARM_VFP)

#endif

#ifdef TARGET_SPARC
#ifdef TARGET_SPARC64

#define ELF_START_MMAP 0x80000000

#define elf_check_arch(x) ( (x) == EM_SPARCV9 )

#define ELF_CLASS   ELFCLASS64
#define ELF_DATA    ELFDATA2MSB
#define ELF_ARCH    EM_SPARCV9

#define STACK_BIAS		2047

static inline void init_thread(struct target_pt_regs *regs, struct image_info *infop)
{
    regs->tstate = 0;
    regs->pc = infop->entry;
    regs->npc = regs->pc + 4;
    regs->y = 0;
    regs->u_regs[14] = infop->start_stack - 16 * 8 - STACK_BIAS;
}

#else
#define ELF_START_MMAP 0x80000000

#define elf_check_arch(x) ( (x) == EM_SPARC )

#define ELF_CLASS   ELFCLASS32
#define ELF_DATA    ELFDATA2MSB
#define ELF_ARCH    EM_SPARC

static inline void init_thread(struct target_pt_regs *regs, struct image_info *infop)
{
    regs->psr = 0;
    regs->pc = infop->entry;
    regs->npc = regs->pc + 4;
    regs->y = 0;
    regs->u_regs[14] = infop->start_stack - 16 * 4;
}

#endif
#endif

#ifdef TARGET_PPC

#define ELF_START_MMAP 0x80000000

#define elf_check_arch(x) ( (x) == EM_PPC )

#define ELF_CLASS	ELFCLASS32
#ifdef TARGET_WORDS_BIGENDIAN
#define ELF_DATA	ELFDATA2MSB
#else
#define ELF_DATA	ELFDATA2LSB
#endif
#define ELF_ARCH	EM_PPC

/*
 * We need to put in some extra aux table entries to tell glibc what
 * the cache block size is, so it can use the dcbz instruction safely.
 */
#define AT_DCACHEBSIZE          19
#define AT_ICACHEBSIZE          20
#define AT_UCACHEBSIZE          21
/* A special ignored type value for PPC, for glibc compatibility.  */
#define AT_IGNOREPPC            22
/*
 * The requirements here are:
 * - keep the final alignment of sp (sp & 0xf)
 * - make sure the 32-bit value at the first 16 byte aligned position of
 *   AUXV is greater than 16 for glibc compatibility.
 *   AT_IGNOREPPC is used for that.
 * - for compatibility with glibc ARCH_DLINFO must always be defined on PPC,
 *   even if DLINFO_ARCH_ITEMS goes to zero or is undefined.
 */
#define DLINFO_ARCH_ITEMS       5
#define ARCH_DLINFO                                                     \
do {                                                                    \
        NEW_AUX_ENT(AT_DCACHEBSIZE, 0x20);                              \
        NEW_AUX_ENT(AT_ICACHEBSIZE, 0x20);                              \
        NEW_AUX_ENT(AT_UCACHEBSIZE, 0);                                 \
        /*                                                              \
         * Now handle glibc compatibility.                              \
         */                                                             \
	NEW_AUX_ENT(AT_IGNOREPPC, AT_IGNOREPPC);			\
	NEW_AUX_ENT(AT_IGNOREPPC, AT_IGNOREPPC);			\
 } while (0)

static inline void init_thread(struct target_pt_regs *_regs, struct image_info *infop)
{
    target_ulong pos = infop->start_stack;
    target_ulong tmp;

    _regs->msr = 1 << MSR_PR; /* Set user mode */
    _regs->gpr[1] = infop->start_stack;
    _regs->nip = infop->entry;
    /* Note that isn't exactly what regular kernel does
     * but this is what the ABI wants and is needed to allow
     * execution of PPC BSD programs.
     */
    _regs->gpr[3] = tgetl(pos);
    pos += sizeof(target_ulong);
    _regs->gpr[4] = pos;
    for (tmp = 1; tmp != 0; pos += sizeof(target_ulong))
        tmp = ldl(pos);
    _regs->gpr[5] = pos;
}

#define USE_ELF_CORE_DUMP
#define ELF_EXEC_PAGESIZE	4096

#endif

#ifdef TARGET_MIPS

#define ELF_START_MMAP 0x80000000

#define elf_check_arch(x) ( (x) == EM_MIPS )

#define ELF_CLASS   ELFCLASS32
#ifdef TARGET_WORDS_BIGENDIAN
#define ELF_DATA	ELFDATA2MSB
#else
#define ELF_DATA	ELFDATA2LSB
#endif
#define ELF_ARCH    EM_MIPS

static inline void init_thread(struct target_pt_regs *regs, struct image_info *infop)
{
    regs->cp0_status = CP0St_UM;
    regs->cp0_epc = infop->entry;
    regs->regs[29] = infop->start_stack;
}

#endif /* TARGET_MIPS */

#ifdef TARGET_SH4

#define ELF_START_MMAP 0x80000000

#define elf_check_arch(x) ( (x) == EM_SH )

#define ELF_CLASS ELFCLASS32
#define ELF_DATA  ELFDATA2LSB
#define ELF_ARCH  EM_SH

static inline void init_thread(struct target_pt_regs *regs, struct image_info *infop)
{
  /* Check other registers XXXXX */
  regs->pc = infop->entry;
  regs->regs[15] = infop->start_stack - 16 * 4;
}

#define USE_ELF_CORE_DUMP
#define ELF_EXEC_PAGESIZE        4096

#endif

#ifndef ELF_PLATFORM
#define ELF_PLATFORM (NULL)
#endif

#ifndef ELF_HWCAP
#define ELF_HWCAP 0
#endif

#include "elf.h"

struct exec
{
  unsigned int a_info;   /* Use macros N_MAGIC, etc for access */
  unsigned int a_text;   /* length of text, in bytes */
  unsigned int a_data;   /* length of data, in bytes */
  unsigned int a_bss;    /* length of uninitialized data area, in bytes */
  unsigned int a_syms;   /* length of symbol table data in file, in bytes */
  unsigned int a_entry;  /* start address */
  unsigned int a_trsize; /* length of relocation info for text, in bytes */
  unsigned int a_drsize; /* length of relocation info for data, in bytes */
};


#define N_MAGIC(exec) ((exec).a_info & 0xffff)
#define OMAGIC 0407
#define NMAGIC 0410
#define ZMAGIC 0413
#define QMAGIC 0314

/* max code+data+bss space allocated to elf interpreter */
#define INTERP_MAP_SIZE (32 * 1024 * 1024)

/* max code+data+bss+brk space allocated to ET_DYN executables */
#define ET_DYN_MAP_SIZE (128 * 1024 * 1024)

/* from personality.h */

/* Flags for bug emulation. These occupy the top three bytes. */
#define STICKY_TIMEOUTS		0x4000000
#define WHOLE_SECONDS		0x2000000

/* Personality types. These go in the low byte. Avoid using the top bit,
 * it will conflict with error returns.
 */
#define PER_MASK		(0x00ff)
#define PER_LINUX		(0x0000)
#define PER_SVR4		(0x0001 | STICKY_TIMEOUTS)
#define PER_SVR3		(0x0002 | STICKY_TIMEOUTS)
#define PER_SCOSVR3		(0x0003 | STICKY_TIMEOUTS | WHOLE_SECONDS)
#define PER_WYSEV386		(0x0004 | STICKY_TIMEOUTS)
#define PER_ISCR4		(0x0005 | STICKY_TIMEOUTS)
#define PER_BSD			(0x0006)
#define PER_XENIX		(0x0007 | STICKY_TIMEOUTS)

/* Necessary parameters */
#define TARGET_ELF_EXEC_PAGESIZE TARGET_PAGE_SIZE
#define TARGET_ELF_PAGESTART(_v) ((_v) & ~(unsigned long)(TARGET_ELF_EXEC_PAGESIZE-1))
#define TARGET_ELF_PAGEOFFSET(_v) ((_v) & (TARGET_ELF_EXEC_PAGESIZE-1))

#define INTERPRETER_NONE 0
#define INTERPRETER_AOUT 1
#define INTERPRETER_ELF 2

#define DLINFO_ITEMS 12

static inline void memcpy_fromfs(void * to, const void * from, unsigned long n)
{
	memcpy(to, from, n);
}

extern unsigned long x86_stack_size;

static int load_aout_interp(void * exptr, int interp_fd);

#ifdef BSWAP_NEEDED
static void bswap_ehdr(struct elfhdr *ehdr)
{
    bswap16s(&ehdr->e_type);			/* Object file type */
    bswap16s(&ehdr->e_machine);		/* Architecture */
    bswap32s(&ehdr->e_version);		/* Object file version */
    bswaptls(&ehdr->e_entry);		/* Entry point virtual address */
    bswaptls(&ehdr->e_phoff);		/* Program header table file offset */
    bswaptls(&ehdr->e_shoff);		/* Section header table file offset */
    bswap32s(&ehdr->e_flags);		/* Processor-specific flags */
    bswap16s(&ehdr->e_ehsize);		/* ELF header size in bytes */
    bswap16s(&ehdr->e_phentsize);		/* Program header table entry size */
    bswap16s(&ehdr->e_phnum);		/* Program header table entry count */
    bswap16s(&ehdr->e_shentsize);		/* Section header table entry size */
    bswap16s(&ehdr->e_shnum);		/* Section header table entry count */
    bswap16s(&ehdr->e_shstrndx);		/* Section header string table index */
}

static void bswap_phdr(struct elf_phdr *phdr)
{
    bswap32s(&phdr->p_type);			/* Segment type */
    bswaptls(&phdr->p_offset);		/* Segment file offset */
    bswaptls(&phdr->p_vaddr);		/* Segment virtual address */
    bswaptls(&phdr->p_paddr);		/* Segment physical address */
    bswaptls(&phdr->p_filesz);		/* Segment size in file */
    bswaptls(&phdr->p_memsz);		/* Segment size in memory */
    bswap32s(&phdr->p_flags);		/* Segment flags */
    bswaptls(&phdr->p_align);		/* Segment alignment */
}

static void bswap_shdr(struct elf_shdr *shdr)
{
    bswap32s(&shdr->sh_name);
    bswap32s(&shdr->sh_type);
    bswaptls(&shdr->sh_flags);
    bswaptls(&shdr->sh_addr);
    bswaptls(&shdr->sh_offset);
    bswaptls(&shdr->sh_size);
    bswap32s(&shdr->sh_link);
    bswap32s(&shdr->sh_info);
    bswaptls(&shdr->sh_addralign);
    bswaptls(&shdr->sh_entsize);
}

static void bswap_sym(Elf32_Sym *sym)
{
    bswap32s(&sym->st_name);
    bswap32s(&sym->st_value);
    bswap32s(&sym->st_size);
    bswap16s(&sym->st_shndx);
}
#endif

/*
 * 'copy_elf_strings()' copies argument/envelope strings from user
 * memory to free pages in kernel mem. These are in a format ready
 * to be put directly into the top of new user memory.
 *
 */
static unsigned long copy_elf_strings(int argc,char ** argv, void **page,
                                      unsigned long p)
{
    char *tmp, *tmp1, *pag = NULL;
    int len, offset = 0;

    if (!p) {
	return 0;       /* bullet-proofing */
    }
    while (argc-- > 0) {
        tmp = argv[argc];
        if (!tmp) {
	    fprintf(stderr, "VFS: argc is wrong");
	    exit(-1);
	}
        tmp1 = tmp;
	while (*tmp++);
	len = tmp - tmp1;
	if (p < len) {  /* this shouldn't happen - 128kB */
		return 0;
	}
	while (len) {
	    --p; --tmp; --len;
	    if (--offset < 0) {
		offset = p % TARGET_PAGE_SIZE;
                pag = (char *)page[p/TARGET_PAGE_SIZE];
                if (!pag) {
                    pag = (char *)malloc(TARGET_PAGE_SIZE);
                    page[p/TARGET_PAGE_SIZE] = pag;
                    if (!pag)
                        return 0;
		}
	    }
	    if (len == 0 || offset == 0) {
	        *(pag + offset) = *tmp;
	    }
	    else {
	      int bytes_to_copy = (len > offset) ? offset : len;
	      tmp -= bytes_to_copy;
	      p -= bytes_to_copy;
	      offset -= bytes_to_copy;
	      len -= bytes_to_copy;
	      memcpy_fromfs(pag + offset, tmp, bytes_to_copy + 1);
	    }
	}
    }
    return p;
}

unsigned long setup_arg_pages(target_ulong p, struct linux_binprm * bprm,
					      struct image_info * info)
{
    target_ulong stack_base, size, error;
    int i;

    /* Create enough stack to hold everything.  If we don't use
     * it for args, we'll use it for something else...
     */
    size = x86_stack_size;
    if (size < MAX_ARG_PAGES*TARGET_PAGE_SIZE)
        size = MAX_ARG_PAGES*TARGET_PAGE_SIZE;
    error = target_mmap(0, 
                        size + qemu_host_page_size,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS,
                        -1, 0);
    if (error == -1) {
        perror("stk mmap");
        exit(-1);
    }
    /* we reserve one extra page at the top of the stack as guard */
    target_mprotect(error + size, qemu_host_page_size, PROT_NONE);

    stack_base = error + size - MAX_ARG_PAGES*TARGET_PAGE_SIZE;
    p += stack_base;

    for (i = 0 ; i < MAX_ARG_PAGES ; i++) {
	if (bprm->page[i]) {
	    info->rss++;

	    memcpy_to_target(stack_base, bprm->page[i], TARGET_PAGE_SIZE);
	    free(bprm->page[i]);
	}
        stack_base += TARGET_PAGE_SIZE;
    }
    return p;
}

static void set_brk(unsigned long start, unsigned long end)
{
	/* page-align the start and end addresses... */
        start = HOST_PAGE_ALIGN(start);
        end = HOST_PAGE_ALIGN(end);
        if (end <= start)
                return;
        if(target_mmap(start, end - start,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == -1) {
	    perror("cannot mmap brk");
	    exit(-1);
	}
}


/* We need to explicitly zero any fractional pages after the data
   section (i.e. bss).  This would contain the junk from the file that
   should not be in memory. */
static void padzero(unsigned long elf_bss)
{
        unsigned long nbyte;

        /* XXX: this is really a hack : if the real host page size is
           smaller than the target page size, some pages after the end
           of the file may not be mapped. A better fix would be to
           patch target_mmap(), but it is more complicated as the file
           size must be known */
        if (qemu_real_host_page_size < qemu_host_page_size) {
            unsigned long end_addr, end_addr1;
            end_addr1 = (elf_bss + qemu_real_host_page_size - 1) & 
                ~(qemu_real_host_page_size - 1);
            end_addr = HOST_PAGE_ALIGN(elf_bss);
            if (end_addr1 < end_addr) {
                mmap((void *)end_addr1, end_addr - end_addr1,
                     PROT_READ|PROT_WRITE|PROT_EXEC,
                     MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            }
        }

        nbyte = elf_bss & (qemu_host_page_size-1);
        if (nbyte) {
	    nbyte = qemu_host_page_size - nbyte;
	    do {
		tput8(elf_bss, 0);
                elf_bss++;
	    } while (--nbyte);
        }
}


static unsigned long create_elf_tables(target_ulong p, int argc, int envc,
                                       struct elfhdr * exec,
                                       unsigned long load_addr,
                                       unsigned long load_bias,
                                       unsigned long interp_load_addr, int ibcs,
                                       struct image_info *info)
{
        target_ulong sp;
        int size;
        target_ulong u_platform;
        const char *k_platform;
        const int n = sizeof(target_ulong);

        sp = p;
        u_platform = 0;
        k_platform = ELF_PLATFORM;
        if (k_platform) {
            size_t len = strlen(k_platform) + 1;
            sp -= (len + n - 1) & ~(n - 1);
            u_platform = sp;
            memcpy_to_target(sp, k_platform, len);
        }
	/*
	 * Force 16 byte _final_ alignment here for generality.
	 */
        sp = sp &~ (target_ulong)15;
        size = (DLINFO_ITEMS + 1) * 2;
        if (k_platform)
          size += 2;
#ifdef DLINFO_ARCH_ITEMS
	size += DLINFO_ARCH_ITEMS * 2;
#endif
        size += envc + argc + 2;
	size += (!ibcs ? 3 : 1);	/* argc itself */
        size *= n;
        if (size & 15)
            sp -= 16 - (size & 15);
        
#define NEW_AUX_ENT(id, val) do { \
            sp -= n; tputl(sp, val); \
            sp -= n; tputl(sp, id); \
          } while(0)
        NEW_AUX_ENT (AT_NULL, 0);

        /* There must be exactly DLINFO_ITEMS entries here.  */
        NEW_AUX_ENT(AT_PHDR, (target_ulong)(load_addr + exec->e_phoff));
        NEW_AUX_ENT(AT_PHENT, (target_ulong)(sizeof (struct elf_phdr)));
        NEW_AUX_ENT(AT_PHNUM, (target_ulong)(exec->e_phnum));
        NEW_AUX_ENT(AT_PAGESZ, (target_ulong)(TARGET_PAGE_SIZE));
        NEW_AUX_ENT(AT_BASE, (target_ulong)(interp_load_addr));
        NEW_AUX_ENT(AT_FLAGS, (target_ulong)0);
        NEW_AUX_ENT(AT_ENTRY, load_bias + exec->e_entry);
        NEW_AUX_ENT(AT_UID, (target_ulong) getuid());
        NEW_AUX_ENT(AT_EUID, (target_ulong) geteuid());
        NEW_AUX_ENT(AT_GID, (target_ulong) getgid());
        NEW_AUX_ENT(AT_EGID, (target_ulong) getegid());
        NEW_AUX_ENT(AT_HWCAP, (target_ulong) ELF_HWCAP);
        if (k_platform)
            NEW_AUX_ENT(AT_PLATFORM, u_platform);
#ifdef ARCH_DLINFO
	/* 
	 * ARCH_DLINFO must come last so platform specific code can enforce
	 * special alignment requirements on the AUXV if necessary (eg. PPC).
	 */
        ARCH_DLINFO;
#endif
#undef NEW_AUX_ENT

        sp = loader_build_argptr(envc, argc, sp, p, !ibcs);
        return sp;
}


static unsigned long load_elf_interp(struct elfhdr * interp_elf_ex,
				     int interpreter_fd,
				     unsigned long *interp_load_addr)
{
	struct elf_phdr *elf_phdata  =  NULL;
	struct elf_phdr *eppnt;
	unsigned long load_addr = 0;
	int load_addr_set = 0;
	int retval;
	unsigned long last_bss, elf_bss;
	unsigned long error;
	int i;
	
	elf_bss = 0;
	last_bss = 0;
	error = 0;

#ifdef BSWAP_NEEDED
        bswap_ehdr(interp_elf_ex);
#endif
	/* First of all, some simple consistency checks */
	if ((interp_elf_ex->e_type != ET_EXEC && 
             interp_elf_ex->e_type != ET_DYN) || 
	   !elf_check_arch(interp_elf_ex->e_machine)) {
		return ~0UL;
	}
	

	/* Now read in all of the header information */
	
	if (sizeof(struct elf_phdr) * interp_elf_ex->e_phnum > TARGET_PAGE_SIZE)
	    return ~0UL;
	
	elf_phdata =  (struct elf_phdr *) 
		malloc(sizeof(struct elf_phdr) * interp_elf_ex->e_phnum);

	if (!elf_phdata)
	  return ~0UL;
	
	/*
	 * If the size of this structure has changed, then punt, since
	 * we will be doing the wrong thing.
	 */
	if (interp_elf_ex->e_phentsize != sizeof(struct elf_phdr)) {
	    free(elf_phdata);
	    return ~0UL;
        }

	retval = lseek(interpreter_fd, interp_elf_ex->e_phoff, SEEK_SET);
	if(retval >= 0) {
	    retval = read(interpreter_fd,
			   (char *) elf_phdata,
			   sizeof(struct elf_phdr) * interp_elf_ex->e_phnum);
	}
	if (retval < 0) {
		perror("load_elf_interp");
		exit(-1);
		free (elf_phdata);
		return retval;
 	}
#ifdef BSWAP_NEEDED
	eppnt = elf_phdata;
	for (i=0; i<interp_elf_ex->e_phnum; i++, eppnt++) {
            bswap_phdr(eppnt);
        }
#endif

        if (interp_elf_ex->e_type == ET_DYN) {
            /* in order to avoid harcoding the interpreter load
               address in qemu, we allocate a big enough memory zone */
            error = target_mmap(0, INTERP_MAP_SIZE,
                                PROT_NONE, MAP_PRIVATE | MAP_ANON, 
                                -1, 0);
            if (error == -1) {
                perror("mmap");
                exit(-1);
            }
            load_addr = error;
            load_addr_set = 1;
        }

	eppnt = elf_phdata;
	for(i=0; i<interp_elf_ex->e_phnum; i++, eppnt++)
	  if (eppnt->p_type == PT_LOAD) {
	    int elf_type = MAP_PRIVATE | MAP_DENYWRITE;
	    int elf_prot = 0;
	    unsigned long vaddr = 0;
	    unsigned long k;

	    if (eppnt->p_flags & PF_R) elf_prot =  PROT_READ;
	    if (eppnt->p_flags & PF_W) elf_prot |= PROT_WRITE;
	    if (eppnt->p_flags & PF_X) elf_prot |= PROT_EXEC;
	    if (interp_elf_ex->e_type == ET_EXEC || load_addr_set) {
	    	elf_type |= MAP_FIXED;
	    	vaddr = eppnt->p_vaddr;
	    }
	    error = target_mmap(load_addr+TARGET_ELF_PAGESTART(vaddr),
		 eppnt->p_filesz + TARGET_ELF_PAGEOFFSET(eppnt->p_vaddr),
		 elf_prot,
		 elf_type,
		 interpreter_fd,
		 eppnt->p_offset - TARGET_ELF_PAGEOFFSET(eppnt->p_vaddr));
	    
	    if (error == -1) {
	      /* Real error */
	      close(interpreter_fd);
	      free(elf_phdata);
	      return ~0UL;
	    }

	    if (!load_addr_set && interp_elf_ex->e_type == ET_DYN) {
	      load_addr = error;
	      load_addr_set = 1;
	    }

	    /*
	     * Find the end of the file  mapping for this phdr, and keep
	     * track of the largest address we see for this.
	     */
	    k = load_addr + eppnt->p_vaddr + eppnt->p_filesz;
	    if (k > elf_bss) elf_bss = k;

	    /*
	     * Do the same thing for the memory mapping - between
	     * elf_bss and last_bss is the bss section.
	     */
	    k = load_addr + eppnt->p_memsz + eppnt->p_vaddr;
	    if (k > last_bss) last_bss = k;
	  }
	
	/* Now use mmap to map the library into memory. */

	close(interpreter_fd);

	/*
	 * Now fill out the bss section.  First pad the last page up
	 * to the page boundary, and then perform a mmap to make sure
	 * that there are zeromapped pages up to and including the last
	 * bss page.
	 */
	padzero(elf_bss);
	elf_bss = TARGET_ELF_PAGESTART(elf_bss + qemu_host_page_size - 1); /* What we have mapped so far */

	/* Map the last of the bss segment */
	if (last_bss > elf_bss) {
            target_mmap(elf_bss, last_bss-elf_bss,
                        PROT_READ|PROT_WRITE|PROT_EXEC,
                        MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	}
	free(elf_phdata);

	*interp_load_addr = load_addr;
	return ((unsigned long) interp_elf_ex->e_entry) + load_addr;
}

/* Best attempt to load symbols from this ELF object. */
static void load_symbols(struct elfhdr *hdr, int fd)
{
    unsigned int i;
    struct elf_shdr sechdr, symtab, strtab;
    char *strings;
    struct syminfo *s;

    lseek(fd, hdr->e_shoff, SEEK_SET);
    for (i = 0; i < hdr->e_shnum; i++) {
	if (read(fd, &sechdr, sizeof(sechdr)) != sizeof(sechdr))
	    return;
#ifdef BSWAP_NEEDED
	bswap_shdr(&sechdr);
#endif
	if (sechdr.sh_type == SHT_SYMTAB) {
	    symtab = sechdr;
	    lseek(fd, hdr->e_shoff
		  + sizeof(sechdr) * sechdr.sh_link, SEEK_SET);
	    if (read(fd, &strtab, sizeof(strtab))
		!= sizeof(strtab))
		return;
#ifdef BSWAP_NEEDED
	    bswap_shdr(&strtab);
#endif
	    goto found;
	}
    }
    return; /* Shouldn't happen... */

 found:
    /* Now know where the strtab and symtab are.  Snarf them. */
    s = malloc(sizeof(*s));
    s->disas_symtab = malloc(symtab.sh_size);
    s->disas_strtab = strings = malloc(strtab.sh_size);
    if (!s->disas_symtab || !s->disas_strtab)
	return;
	
    lseek(fd, symtab.sh_offset, SEEK_SET);
    if (read(fd, s->disas_symtab, symtab.sh_size) != symtab.sh_size)
	return;

#ifdef BSWAP_NEEDED
    for (i = 0; i < symtab.sh_size / sizeof(struct elf_sym); i++)
	bswap_sym(s->disas_symtab + sizeof(struct elf_sym)*i);
#endif

    lseek(fd, strtab.sh_offset, SEEK_SET);
    if (read(fd, strings, strtab.sh_size) != strtab.sh_size)
	return;
    s->disas_num_syms = symtab.sh_size / sizeof(struct elf_sym);
    s->next = syminfos;
    syminfos = s;
}

int load_elf_binary(struct linux_binprm * bprm, struct target_pt_regs * regs,
                    struct image_info * info)
{
    struct elfhdr elf_ex;
    struct elfhdr interp_elf_ex;
    struct exec interp_ex;
    int interpreter_fd = -1; /* avoid warning */
    unsigned long load_addr, load_bias;
    int load_addr_set = 0;
    unsigned int interpreter_type = INTERPRETER_NONE;
    unsigned char ibcs2_interpreter;
    int i;
    unsigned long mapped_addr;
    struct elf_phdr * elf_ppnt;
    struct elf_phdr *elf_phdata;
    unsigned long elf_bss, k, elf_brk;
    int retval;
    char * elf_interpreter;
    unsigned long elf_entry, interp_load_addr = 0;
    int status;
    unsigned long start_code, end_code, end_data;
    unsigned long elf_stack;
    char passed_fileno[6];

    ibcs2_interpreter = 0;
    status = 0;
    load_addr = 0;
    load_bias = 0;
    elf_ex = *((struct elfhdr *) bprm->buf);          /* exec-header */
#ifdef BSWAP_NEEDED
    bswap_ehdr(&elf_ex);
#endif

    /* First of all, some simple consistency checks */
    if ((elf_ex.e_type != ET_EXEC && elf_ex.e_type != ET_DYN) ||
       				(! elf_check_arch(elf_ex.e_machine))) {
	    return -ENOEXEC;
    }

    bprm->p = copy_elf_strings(1, &bprm->filename, bprm->page, bprm->p);
    bprm->p = copy_elf_strings(bprm->envc,bprm->envp,bprm->page,bprm->p);
    bprm->p = copy_elf_strings(bprm->argc,bprm->argv,bprm->page,bprm->p);
    if (!bprm->p) {
        retval = -E2BIG;
    }

    /* Now read in all of the header information */
    elf_phdata = (struct elf_phdr *)malloc(elf_ex.e_phentsize*elf_ex.e_phnum);
    if (elf_phdata == NULL) {
	return -ENOMEM;
    }

    retval = lseek(bprm->fd, elf_ex.e_phoff, SEEK_SET);
    if(retval > 0) {
	retval = read(bprm->fd, (char *) elf_phdata, 
				elf_ex.e_phentsize * elf_ex.e_phnum);
    }

    if (retval < 0) {
	perror("load_elf_binary");
	exit(-1);
	free (elf_phdata);
	return -errno;
    }

#ifdef BSWAP_NEEDED
    elf_ppnt = elf_phdata;
    for (i=0; i<elf_ex.e_phnum; i++, elf_ppnt++) {
        bswap_phdr(elf_ppnt);
    }
#endif
    elf_ppnt = elf_phdata;

    elf_bss = 0;
    elf_brk = 0;


    elf_stack = ~0UL;
    elf_interpreter = NULL;
    start_code = ~0UL;
    end_code = 0;
    end_data = 0;

    for(i=0;i < elf_ex.e_phnum; i++) {
	if (elf_ppnt->p_type == PT_INTERP) {
	    if ( elf_interpreter != NULL )
	    {
		free (elf_phdata);
		free(elf_interpreter);
		close(bprm->fd);
		return -EINVAL;
	    }

	    /* This is the program interpreter used for
	     * shared libraries - for now assume that this
	     * is an a.out format binary
	     */

	    elf_interpreter = (char *)malloc(elf_ppnt->p_filesz);

	    if (elf_interpreter == NULL) {
		free (elf_phdata);
		close(bprm->fd);
		return -ENOMEM;
	    }

	    retval = lseek(bprm->fd, elf_ppnt->p_offset, SEEK_SET);
	    if(retval >= 0) {
		retval = read(bprm->fd, elf_interpreter, elf_ppnt->p_filesz);
	    }
	    if(retval < 0) {
	 	perror("load_elf_binary2");
		exit(-1);
	    }	

	    /* If the program interpreter is one of these two,
	       then assume an iBCS2 image. Otherwise assume
	       a native linux image. */

	    /* JRP - Need to add X86 lib dir stuff here... */

	    if (strcmp(elf_interpreter,"/usr/lib/libc.so.1") == 0 ||
		strcmp(elf_interpreter,"/usr/lib/ld.so.1") == 0) {
	      ibcs2_interpreter = 1;
	    }

#if 0
	    printf("Using ELF interpreter %s\n", elf_interpreter);
#endif
	    if (retval >= 0) {
		retval = open(path(elf_interpreter), O_RDONLY);
		if(retval >= 0) {
		    interpreter_fd = retval;
		}
		else {
		    perror(elf_interpreter);
		    exit(-1);
		    /* retval = -errno; */
		}
	    }

	    if (retval >= 0) {
		retval = lseek(interpreter_fd, 0, SEEK_SET);
		if(retval >= 0) {
		    retval = read(interpreter_fd,bprm->buf,128);
		}
	    }
	    if (retval >= 0) {
		interp_ex = *((struct exec *) bprm->buf); /* aout exec-header */
		interp_elf_ex=*((struct elfhdr *) bprm->buf); /* elf exec-header */
	    }
	    if (retval < 0) {
		perror("load_elf_binary3");
		exit(-1);
		free (elf_phdata);
		free(elf_interpreter);
		close(bprm->fd);
		return retval;
	    }
	}
	elf_ppnt++;
    }

    /* Some simple consistency checks for the interpreter */
    if (elf_interpreter){
	interpreter_type = INTERPRETER_ELF | INTERPRETER_AOUT;

	/* Now figure out which format our binary is */
	if ((N_MAGIC(interp_ex) != OMAGIC) && (N_MAGIC(interp_ex) != ZMAGIC) &&
	    	(N_MAGIC(interp_ex) != QMAGIC)) {
	  interpreter_type = INTERPRETER_ELF;
	}

	if (interp_elf_ex.e_ident[0] != 0x7f ||
	    	strncmp(&interp_elf_ex.e_ident[1], "ELF",3) != 0) {
	    interpreter_type &= ~INTERPRETER_ELF;
	}

	if (!interpreter_type) {
	    free(elf_interpreter);
	    free(elf_phdata);
	    close(bprm->fd);
	    return -ELIBBAD;
	}
    }

    /* OK, we are done with that, now set up the arg stuff,
       and then start this sucker up */

    {
	char * passed_p;

	if (interpreter_type == INTERPRETER_AOUT) {
	    snprintf(passed_fileno, sizeof(passed_fileno), "%d", bprm->fd);
	    passed_p = passed_fileno;

	    if (elf_interpreter) {
		bprm->p = copy_elf_strings(1,&passed_p,bprm->page,bprm->p);
		bprm->argc++;
	    }
	}
	if (!bprm->p) {
	    if (elf_interpreter) {
	        free(elf_interpreter);
	    }
	    free (elf_phdata);
	    close(bprm->fd);
	    return -E2BIG;
	}
    }

    /* OK, This is the point of no return */
    info->end_data = 0;
    info->end_code = 0;
    info->start_mmap = (unsigned long)ELF_START_MMAP;
    info->mmap = 0;
    elf_entry = (unsigned long) elf_ex.e_entry;

    /* Do this so that we can load the interpreter, if need be.  We will
       change some of these later */
    info->rss = 0;
    bprm->p = setup_arg_pages(bprm->p, bprm, info);
    info->start_stack = bprm->p;

    /* Now we do a little grungy work by mmaping the ELF image into
     * the correct location in memory.  At this point, we assume that
     * the image should be loaded at fixed address, not at a variable
     * address.
     */

    for(i = 0, elf_ppnt = elf_phdata; i < elf_ex.e_phnum; i++, elf_ppnt++) {
        int elf_prot = 0;
        int elf_flags = 0;
        unsigned long error;
        
	if (elf_ppnt->p_type != PT_LOAD)
            continue;
        
        if (elf_ppnt->p_flags & PF_R) elf_prot |= PROT_READ;
        if (elf_ppnt->p_flags & PF_W) elf_prot |= PROT_WRITE;
        if (elf_ppnt->p_flags & PF_X) elf_prot |= PROT_EXEC;
        elf_flags = MAP_PRIVATE | MAP_DENYWRITE;
        if (elf_ex.e_type == ET_EXEC || load_addr_set) {
            elf_flags |= MAP_FIXED;
        } else if (elf_ex.e_type == ET_DYN) {
            /* Try and get dynamic programs out of the way of the default mmap
               base, as well as whatever program they might try to exec.  This
               is because the brk will follow the loader, and is not movable.  */
            /* NOTE: for qemu, we do a big mmap to get enough space
               without harcoding any address */
            error = target_mmap(0, ET_DYN_MAP_SIZE,
                                PROT_NONE, MAP_PRIVATE | MAP_ANON, 
                                -1, 0);
            if (error == -1) {
                perror("mmap");
                exit(-1);
            }
            load_bias = TARGET_ELF_PAGESTART(error - elf_ppnt->p_vaddr);
        }
        
        error = target_mmap(TARGET_ELF_PAGESTART(load_bias + elf_ppnt->p_vaddr),
                            (elf_ppnt->p_filesz +
                             TARGET_ELF_PAGEOFFSET(elf_ppnt->p_vaddr)),
                            elf_prot,
                            (MAP_FIXED | MAP_PRIVATE | MAP_DENYWRITE),
                            bprm->fd,
                            (elf_ppnt->p_offset - 
                             TARGET_ELF_PAGEOFFSET(elf_ppnt->p_vaddr)));
        if (error == -1) {
            perror("mmap");
            exit(-1);
        }

#ifdef LOW_ELF_STACK
        if (TARGET_ELF_PAGESTART(elf_ppnt->p_vaddr) < elf_stack)
            elf_stack = TARGET_ELF_PAGESTART(elf_ppnt->p_vaddr);
#endif
        
        if (!load_addr_set) {
            load_addr_set = 1;
            load_addr = elf_ppnt->p_vaddr - elf_ppnt->p_offset;
            if (elf_ex.e_type == ET_DYN) {
                load_bias += error -
                    TARGET_ELF_PAGESTART(load_bias + elf_ppnt->p_vaddr);
                load_addr += load_bias;
            }
        }
        k = elf_ppnt->p_vaddr;
        if (k < start_code) 
            start_code = k;
        k = elf_ppnt->p_vaddr + elf_ppnt->p_filesz;
        if (k > elf_bss) 
            elf_bss = k;
        if ((elf_ppnt->p_flags & PF_X) && end_code <  k)
            end_code = k;
        if (end_data < k) 
            end_data = k;
        k = elf_ppnt->p_vaddr + elf_ppnt->p_memsz;
        if (k > elf_brk) elf_brk = k;
    }

    elf_entry += load_bias;
    elf_bss += load_bias;
    elf_brk += load_bias;
    start_code += load_bias;
    end_code += load_bias;
    //    start_data += load_bias;
    end_data += load_bias;

    if (elf_interpreter) {
	if (interpreter_type & 1) {
	    elf_entry = load_aout_interp(&interp_ex, interpreter_fd);
	}
	else if (interpreter_type & 2) {
	    elf_entry = load_elf_interp(&interp_elf_ex, interpreter_fd,
					    &interp_load_addr);
	}

	close(interpreter_fd);
	free(elf_interpreter);

	if (elf_entry == ~0UL) {
	    printf("Unable to load interpreter\n");
	    free(elf_phdata);
	    exit(-1);
	    return 0;
	}
    }

    free(elf_phdata);

    if (loglevel)
	load_symbols(&elf_ex, bprm->fd);

    if (interpreter_type != INTERPRETER_AOUT) close(bprm->fd);
    info->personality = (ibcs2_interpreter ? PER_SVR4 : PER_LINUX);

#ifdef LOW_ELF_STACK
    info->start_stack = bprm->p = elf_stack - 4;
#endif
    bprm->p = create_elf_tables(bprm->p,
		    bprm->argc,
		    bprm->envc,
                    &elf_ex,
                    load_addr, load_bias,
		    interp_load_addr,
		    (interpreter_type == INTERPRETER_AOUT ? 0 : 1),
		    info);
    info->start_brk = info->brk = elf_brk;
    info->end_code = end_code;
    info->start_code = start_code;
    info->start_data = end_code;
    info->end_data = end_data;
    info->start_stack = bprm->p;

    /* Calling set_brk effectively mmaps the pages that we need for the bss and break
       sections */
    set_brk(elf_bss, elf_brk);

    padzero(elf_bss);

#if 0
    printf("(start_brk) %x\n" , info->start_brk);
    printf("(end_code) %x\n" , info->end_code);
    printf("(start_code) %x\n" , info->start_code);
    printf("(end_data) %x\n" , info->end_data);
    printf("(start_stack) %x\n" , info->start_stack);
    printf("(brk) %x\n" , info->brk);
#endif

    if ( info->personality == PER_SVR4 )
    {
	    /* Why this, you ask???  Well SVr4 maps page 0 as read-only,
	       and some applications "depend" upon this behavior.
	       Since we do not have the power to recompile these, we
	       emulate the SVr4 behavior.  Sigh.  */
	    mapped_addr = target_mmap(0, qemu_host_page_size, PROT_READ | PROT_EXEC,
                                      MAP_FIXED | MAP_PRIVATE, -1, 0);
    }

    info->entry = elf_entry;

    return 0;
}

static int load_aout_interp(void * exptr, int interp_fd)
{
    printf("a.out interpreter not yet supported\n");
    return(0);
}

void do_init_thread(struct target_pt_regs *regs, struct image_info *infop)
{
    init_thread(regs, infop);
}
