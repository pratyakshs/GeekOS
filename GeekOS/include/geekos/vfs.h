/*
 * Virtual filesystem structures and routines
 * Copyright (c) 2003, Jeffrey K. Hollingsworth <hollings@cs.umd.edu>
 * Copyright (c) 2003, David H. Hovemeyer <daveho@cs.umd.edu>
 *
 * All rights reserved.
 *
 * This code may not be resdistributed without the permission of the copyright holders.
 * Any student solutions using any of this code base constitute derviced work and may
 * not be redistributed in any form.  This includes (but is not limited to) posting on
 * public forums or web sites, providing copies to (past, present, or future) students
 * enrolled in similar operating systems courses the University of Maryland's CMSC412 course.
 *
 * $Revision: 1.45 $
 * 
 */

#ifndef GEEKOS_VFS_H
#define GEEKOS_VFS_H

#ifdef GEEKOS

#include <geekos/ktypes.h>
#include <geekos/list.h>
#include <geekos/fileio.h>
#include <geekos/blockdev.h>

/*
 * Returned by Read_Entry() function to indicate that there
 * are no more directory entries.
 */
#define VFS_NO_MORE_DIR_ENTRIES 1

struct Mount_Point;
struct File;
struct Mount_Point_Ops;
struct File_Ops;

/*
 * Operations providing support for formatting and mounting
 * filesystem instances.
 */
struct Filesystem_Ops {
    int (*Format) (struct Block_Device * blockDev);
    int (*Mount) (struct Mount_Point * mountPoint);
};

/* A mounted filesystem instance. */
struct Mount_Point {
    struct Mount_Point_Ops *ops;        /* Operations that can be performed on the mount. */
    char *pathPrefix;           /* Path prefix where fs is mounted. */
    struct Block_Device *dev;   /* Block device filesystem is mounted on. */
    void *fsData;               /* For use by the filesystem implementation. */
     DEFINE_LINK(Mount_Point_List, Mount_Point);
};

/* Operations that can be performed on a mounted filesystem. */
struct Mount_Point_Ops {
    int (*Open) (struct Mount_Point * mountPoint, const char *path, int mode,
                 struct File ** pFile);
    int (*Create_Directory) (struct Mount_Point * mountPoint,
                             const char *path);
    int (*Open_Directory) (struct Mount_Point * mountPoint, const char *path,
                           struct File ** pDir);
    int (*Stat) (struct Mount_Point * mountPoint, const char *path,
                 struct VFS_File_Stat * stat);
    int (*Sync) (struct Mount_Point * mountPoint);
    int (*Delete) (struct Mount_Point * mountPoint, const char *path,
                   bool recursive);
    int (*Rename) (struct Mount_Point * mountPoint, const char *oldpath,
                   const char *newpath);
    int (*Link) (struct Mount_Point * mountPoint, const char *oldpath,
                 const char *newpath);
    int (*SymLink) (struct Mount_Point * mountPoint, const char *oldpath,
                    const char *newpath);
    int (*SetSetUid) (struct Mount_Point * mountPoint, const char *path,
                      int setUid);
    int (*SetAcl) (struct Mount_Point * mountPoint, const char *name, int uid,
                   int permissions);
    int (*Disk_Properties) (struct Mount_Point * mountPoint,
                            unsigned int *block_size,
                            unsigned int *blocks_on_disk);
};

/* An opened file or directory. */
struct File {
    /*
     * Filesystem mount function is responsible for initializing
     * the following fields:
     */
    struct File_Ops *ops;       /* Operations that can be performed on the file. */
    ulong_t filePos;            /* Current position in the file. */
    ulong_t endPos;             /* End position (i.e., the length of the file). */
    void *fsData;               /* For use by the filesystem implementation. */

    /*
     * VFS Open(), Create_Directory(), and Open_Directory() functions
     * are responsible for initializing the following fields:
     */
    int mode;                   /* Mode (read vs. write). */
    struct Mount_Point *mountPoint;     /* Mounted filesystem file is part of. */
};

/* Operations that can be performed on a File. */
struct File_Ops {
    int (*FStat) (struct File * file, struct VFS_File_Stat * stat);
    int (*Read) (struct File * file, void *buf, ulong_t numBytes);
    int (*Write) (struct File * file, void *buf, ulong_t numBytes);
    int (*Seek) (struct File * file, ulong_t pos);
    int (*Close) (struct File * file);
    int (*Read_Entry) (struct File * dir, struct VFS_Dir_Entry * entry);        /* Read next directory entry. */
};

/*
 * A mounted filesystem may register a contiguous range of sectors
 * as a paging device.  The disk space in the paging file will be
 * used to store the data of pages that have been temporarily evicted
 * due to a memory shortage.
 */
struct Paging_Device {
    char *fileName;             /* Name of paging file. */
    struct Block_Device *dev;   /* Block device for paging file. */
    ulong_t startSector;        /* Start sector of paging file. */
    ulong_t numSectors;         /* Number of sectors in paging file. */
};

/*
 * VFS functions.
 */

/* Filesystem operations. */
bool Register_Filesystem(const char *fsName, struct Filesystem_Ops *fsOps);
int Format(const char *devname, const char *fstype);
int Mount(const char *devname, const char *pathPrefix, const char *fstype);

/* Mount point operations. */
int Open(const char *path, int mode, struct File **pFile);
int Close(struct File *file);
int Stat(const char *path, struct VFS_File_Stat *stat);
int Sync(void);

/* File operations. */
struct File *Allocate_File(struct File_Ops *ops, int filePos, int endPos,
                           void *fsData, int mode,
                           struct Mount_Point *mountPoint);
int FStat(struct File *file, struct VFS_File_Stat *stat);
int Read(struct File *file, void *buf, ulong_t len);
int Write(struct File *file, void *buf, ulong_t len);
int Seek(struct File *file, ulong_t len);
int Read_Fully(const char *path, void **pBuffer, ulong_t * pLen);
int Delete(const char *path, bool recursive);
int Rename(const char *oldpath, const char *newpath);
int Link(const char *oldpath, const char *newpath);
int SymLink(const char *oldpath, const char *newpath);

/* Directory operations. */
int Create_Directory(const char *path);
int Open_Directory(const char *path, struct File **pDir);
int Read_Entry(struct File *file, struct VFS_Dir_Entry *entry);

/*
 * Paging device functions.
 */
void Register_Paging_Device(struct Paging_Device *pagingDevice);
struct Paging_Device *Get_Paging_Device(void);

/* uid stuff */
int SetSetUid(const char *path, int setUid);
int SetAcl(const char *path, int user, int permissions);

/* Mostly to help the tests, dynamic query to determine file system properties */
int Disk_Properties(const char *path, unsigned int *block_size,
                    unsigned int *blocks_on_disk);

struct Thread_Queue * IOWaitQueue;

// map<int, Kernel_Thread> IOEvents;
static int current_track = 1;
static int NUM_BYTES_PER_TRACK = 4 * 4096;
int get_time(int x);

#endif /* GEEKOS */

#endif /* GEEKOS_VFS_H */
