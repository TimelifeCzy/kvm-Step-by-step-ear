/* Code for loading Linux executables.  Mostly linux kenrel code.  */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "qemu.h"

#define NGROUPS 32

/* ??? This should really be somewhere else.  */
void memcpy_to_target(target_ulong dest, const void *src,
                      unsigned long len)
{
    void *host_ptr;

    host_ptr = lock_user(dest, len, 0);
    memcpy(host_ptr, src, len);
    unlock_user(host_ptr, dest, 1);
}

static int in_group_p(gid_t g)
{
    /* return TRUE if we're in the specified group, FALSE otherwise */
    int		ngroup;
    int		i;
    gid_t	grouplist[NGROUPS];

    ngroup = getgroups(NGROUPS, grouplist);
    for(i = 0; i < ngroup; i++) {
	if(grouplist[i] == g) {
	    return 1;
	}
    }
    return 0;
}

static int count(char ** vec)
{
    int		i;

    for(i = 0; *vec; i++) {
        vec++;
    }

    return(i);
}

static int prepare_binprm(struct linux_binprm *bprm)
{
    struct stat		st;
    int mode;
    int retval, id_change;

    if(fstat(bprm->fd, &st) < 0) {
	return(-errno);
    }

    mode = st.st_mode;
    if(!S_ISREG(mode)) {	/* Must be regular file */
	return(-EACCES);
    }
    if(!(mode & 0111)) {	/* Must have at least one execute bit set */
	return(-EACCES);
    }

    bprm->e_uid = geteuid();
    bprm->e_gid = getegid();
    id_change = 0;

    /* Set-uid? */
    if(mode & S_ISUID) {
    	bprm->e_uid = st.st_uid;
	if(bprm->e_uid != geteuid()) {
	    id_change = 1;
	}
    }

    /* Set-gid? */
    /*
     * If setgid is set but no group execute bit then this
     * is a candidate for mandatory locking, not a setgid
     * executable.
     */
    if ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP)) {
	bprm->e_gid = st.st_gid;
	if (!in_group_p(bprm->e_gid)) {
		id_change = 1;
	}
    }

    memset(bprm->buf, 0, sizeof(bprm->buf));
    retval = lseek(bprm->fd, 0L, SEEK_SET);
    if(retval >= 0) {
        retval = read(bprm->fd, bprm->buf, 128);
    }
    if(retval < 0) {
	perror("prepare_binprm");
	exit(-1);
	/* return(-errno); */
    }
    else {
	return(retval);
    }
}

/* Construct the envp and argv tables on the target stack.  */
target_ulong loader_build_argptr(int envc, int argc, target_ulong sp,
                                 target_ulong stringp, int push_ptr)
{
    int n = sizeof(target_ulong);
    target_ulong envp;
    target_ulong argv;

    sp -= (envc + 1) * n;
    envp = sp;
    sp -= (argc + 1) * n;
    argv = sp;
    if (push_ptr) {
        sp -= n; tputl(sp, envp);
        sp -= n; tputl(sp, argv);
    }
    sp -= n; tputl(sp, argc);

    while (argc-- > 0) {
        tputl(argv, stringp); argv += n;
        stringp += target_strlen(stringp) + 1;
    }
    tputl(argv, 0);
    while (envc-- > 0) {
        tputl(envp, stringp); envp += n;
        stringp += target_strlen(stringp) + 1;
    }
    tputl(envp, 0);

    return sp;
}

int loader_exec(const char * filename, char ** argv, char ** envp, 
             struct target_pt_regs * regs, struct image_info *infop)
{
    struct linux_binprm bprm;
    int retval;
    int i;

    bprm.p = TARGET_PAGE_SIZE*MAX_ARG_PAGES-sizeof(unsigned int);
    for (i=0 ; i<MAX_ARG_PAGES ; i++)       /* clear page-table */
            bprm.page[i] = 0;
    retval = open(filename, O_RDONLY);
    if (retval < 0)
        return retval;
    bprm.fd = retval;
    bprm.filename = (char *)filename;
    bprm.argc = count(argv);
    bprm.argv = argv;
    bprm.envc = count(envp);
    bprm.envp = envp;

    retval = prepare_binprm(&bprm);

    if(retval>=0) {
        if (bprm.buf[0] == 0x7f
                && bprm.buf[1] == 'E'
                && bprm.buf[2] == 'L'
                && bprm.buf[3] == 'F') {
            retval = load_elf_binary(&bprm,regs,infop);
#if defined(TARGET_HAS_BFLT)
        } else if (bprm.buf[0] == 'b'
                && bprm.buf[1] == 'F'
                && bprm.buf[2] == 'L'
                && bprm.buf[3] == 'T') {
            retval = load_flt_binary(&bprm,regs,infop);
#endif
        } else {
            fprintf(stderr, "Unknown binary format\n");
            return -1;
        }
    }
    
    if(retval>=0) {
        /* success.  Initialize important registers */
        do_init_thread(regs, infop);
        return retval;
    }

    /* Something went wrong, return the inode and free the argument pages*/
    for (i=0 ; i<MAX_ARG_PAGES ; i++) {
        free(bprm.page[i]);
    }
    return(retval);
}
