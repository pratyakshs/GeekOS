/*
 * Interface constants and typedefs shared between kernel/user space
 * Copyright (c) 2001,2003,2004 David H. Hovemeyer <daveho@cs.umd.edu>
 * Copyright (c) 2003,2013,2014 Jeffrey K. Hollingsworth <hollings@cs.umd.edu>
 *
 * All rights reserved.
 *
 * This code may not be resdistributed without the permission of the copyright holders.
 * Any student solutions using any of this code base constitute derviced work and may
 * not be redistributed in any form.  This includes (but is not limited to) posting on
 * public forums or web sites, providing copies to (past, present, or future) students
 * enrolled in similar operating systems courses the University of Maryland's CMSC412 course.
 *
 * $Revision: 1.21 $
 *
 */

#ifndef GEEKOS_FILEIO_H
#define GEEKOS_FILEIO_H

#include <stddef.h>
#include <geekos/ktypes.h>

/* Maximum name of a path. */
#define VFS_MAX_PATH_LEN 1023

/* Maximum length of the name of a filesystem type: e.g., "pfat", "gosfs", etc. */
#define VFS_MAX_FS_NAME_LEN 15

/* Maximum number of ACL entries in a directory entry. */
#define VFS_MAX_ACL_ENTRIES 10

/* We assume that all block devices have 512 byte sectors.  */
#define SECTOR_SIZE 512

/* Maximum length for the name of a block device, e.g. "ide0".  */
#define BLOCKDEV_MAX_NAME_LEN 15

/*
 * File permissions.
 * These are used as flags for Open() VFS function.
 * O_READ and O_WRITE are also used in the permissions
 * field of struct VFS_ACL_Entry.
 */
#define O_CREATE        0x1     /* Create the file if it doesn't exist. */
#define O_READ          0x2     /* Open file for reading. */
#define O_WRITE         0x4     /* Open file for writing. */
/* conditional to support inclusion from user tools outside geekos */
#ifndef O_EXCL
#define O_EXCL          0x8     /* Don't create file if it already exists. */
#endif
#ifndef O_OWNER
#define O_OWNER         0x10    /* set owner of the file */
#endif
#define O_RECURSIVE     0x20    /* recursively create directories to open files */
int OpenCount(void);
/*
 * An entry in an Access Control List (ACL).
 * Represents a set of permissions for a particular user id.
 */
struct VFS_ACL_Entry {
    uint_t uid:28;
    uint_t permission:4;
};

/*
 * Generic structure representing the metadata for a directory entry.
 * This is filled in by the Stat() and FStat() VFS functions.
 */
struct VFS_File_Stat {
    int size;
    int isDirectory:1;
    int isSetuid:1;
    struct VFS_ACL_Entry acls[VFS_MAX_ACL_ENTRIES];
};

/*
 * Generic directory entry structure.
 * This is filled in by the Read_Entry() VFS function.
 */
struct VFS_Dir_Entry {
    char name[1024];
    struct VFS_File_Stat stats;
};

/*
 * A request to mount a filesystem.
 * This is passed as a struct because it would require too many registers
 * to pass all of the information in registers.
 */
struct VFS_Mount_Request {
    char devname[BLOCKDEV_MAX_NAME_LEN + 1];    /* Name of block device: e.g., "ide1". */
    char prefix[VFS_MAX_PATH_LEN + 1];  /* Directory prefix to mount on: e.g., "/d". */
    char fstype[VFS_MAX_FS_NAME_LEN + 1];       /* Filesystem type: e.g., "gosfs". */
};

#endif
