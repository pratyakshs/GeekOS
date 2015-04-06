/*
 * Paging (virtual memory) support
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
 * $Revision: 1.56 $
 * 
 */

#include <geekos/string.h>
#include <geekos/int.h>
#include <geekos/idt.h>
#include <geekos/kthread.h>
#include <geekos/kassert.h>
#include <geekos/screen.h>
#include <geekos/mem.h>
#include <geekos/malloc.h>
#include <geekos/gdt.h>
#include <geekos/segment.h>
#include <geekos/user.h>
#include <geekos/vfs.h>
#include <geekos/crc32.h>
#include <geekos/paging.h>
#include <geekos/errno.h>
#include <geekos/projects.h>
#include <geekos/smp.h>

#include <libc/mmap.h>

/* ----------------------------------------------------------------------
 * Public data
 * ---------------------------------------------------------------------- */

/* ----------------------------------------------------------------------
 * Private functions/data
 * ---------------------------------------------------------------------- */

#define SECTORS_PER_PAGE (PAGE_SIZE / SECTOR_SIZE)

/*
 * flag to indicate if debugging paging code
 */
 int debugFaults = 0;

#define Debug(args...) if (debugFaults) Print(args)


 const pde_t *Kernel_Page_Dir(void) {
/* 	TODO_P(PROJECT_VIRTUAL_MEMORY_A,
 		"return kernel page directory and page tables");
 	return NULL;*/
return PageDir;
 }



/*
 * Print diagnostic information for a page fault.
 */
 static void Print_Fault_Info(uint_t address, faultcode_t faultCode) {
 	extern uint_t g_freePageCount;

 	Print("Pid %d: ", CURRENT_THREAD->pid);
 	Print("\n Page Fault received, at address %p (%d pages free)\n",
 		(void *)address, g_freePageCount);
 	if (faultCode.protectionViolation)
 		Print("   Protection Violation, ");
 	else
 		Print("   Non-present page, ");
 	if (faultCode.writeFault)
 		Print("Write Fault, ");
 	else
 		Print("Read Fault, ");
 	if (faultCode.userModeFault)
 		Print("in User Mode\n");
 	else
 		Print("in Supervisor Mode\n");
 }


/*
 * Handler for page faults.
 * You should call the Install_Interrupt_Handler() function to
 * register this function as the handler for interrupt 14.
 */
/*static*/ void Page_Fault_Handler(struct Interrupt_State *state) {
 ulong_t address;
 faultcode_t faultCode;

 KASSERT(!Interrupts_Enabled());

    /* Get the address that caused the page fault */
 address = Get_Page_Fault_Address();
 Debug("Page fault @%lx\n", address);

 if (address < 0xfec01000 && address > 0xf0000000) {
 	KASSERT0(0, "page fault address in APIC/IOAPIC range\n");
 }

    /* Get the fault code */
 faultCode = *((faultcode_t *) & (state->errorCode));

    /* rest of your handling code here */
 TODO_P(PROJECT_VIRTUAL_MEMORY_B, "handle page faults");

 TODO_P(PROJECT_MMAP, "handle mmap'd page faults");


 error:
 Print("Unexpected Page Fault received\n");
 Print_Fault_Info(address, faultCode);
 Dump_Interrupt_State(state);
    /* user faults just kill the process */
 if (!faultCode.userModeFault)
 	KASSERT0(0, "unhandled kernel-mode page fault.");

    /* For now, just kill the thread/process. */
 Exit(-1);
}

void Idenity_Map_Page(pde_t * currentPageDir, unsigned int address, int flags) {
}

/* ----------------------------------------------------------------------
 * Public functions
 * ---------------------------------------------------------------------- */


/*
 * Initialize virtual memory by building page tables
 * for the kernel and physical memory.
 */
 void Init_VM(struct Boot_Info *bootInfo) {
    /*
     * Hints:
     * - Build kernel page directory and page tables
     * - Call Enable_Paging() with the kernel page directory
     * - Install an interrupt handler for interrupt 14,
     *   page fault
     * - Do not map a page at address 0; this will help trap
     *   null pointer references
     */
     ulong_t numPages = bootInfo->memSizeKB >> 2;
     //ulong_t numPages = 1024*1024;
     Print("Num pages = %lu\n", numPages);
     ulong_t numPdEnt = numPages/NUM_PAGE_TABLE_ENTRIES;
     
     PageDir=Alloc_Page();
     memset(PageDir, '\0', 4096);
     
     if(numPages%NUM_PAGE_TABLE_ENTRIES!=0)
     {

     	numPdEnt++;
     }

     Print("Initializing Virtual Memory... \n");
     /*Install  page directory entries*/
     uint_t i,j;
     for(i=0;i<numPdEnt;i++){
     	pde_t entry = {0};
     	pte_t *pageTable;
    /* Allocate a page table and clear it */
     	pageTable = Alloc_Page();
     	memset(pageTable, '\0', 4096);

    /* Create a page directory entry pointing to this page table */
     	entry.present = 1;
     	entry.pageTableBaseAddr = ((ulong_t) pageTable) >> 12;
     	entry.flags = VM_USER | VM_WRITE;

    /* Install the PDE in index i of the page directory */
     	PageDir[i] = entry;
     }

     for(i=numPdEnt;i<NUM_PAGE_DIR_ENTRIES;i++){
    /* present bit is set to 0 */
     	pde_t entry = {0};
     	PageDir[i] = entry;
     }

     //Map APIC and IO APIC
     	pde_t entry = {0};
     	pte_t *pageTable;
    /* Allocate a page table and clear it */
     	pageTable = Alloc_Page();
     	memset(pageTable, '\0', 4096);

    /* Create a page directory entry pointing to this page table */
     	entry.present = 1;
     	entry.pageTableBaseAddr = ((ulong_t) pageTable) >> 12;
     	entry.flags =  VM_WRITE;

    /* Install the PDE in index i of the page directory */
     	

     	for(j=0;j<256;j++){
            /*Case when number of pages in memory is not a multiple of NUM_PAGE_TABLE_ENTRIES*/
     		
     			pte_t entry = {0};
     			ulong_t addr;
        /* Create a page table entry pointing to  physical memory frame*/
     			entry.present = 1;
     			entry.flags =  VM_WRITE;
     			addr=1019 << 10;
     			addr=addr | ((ulong_t) j);
     			entry.pageBaseAddr = addr;
                //Print("Address is %x \n", entry.pageBaseAddr);
        /* Install the PDE in index i of the page directory */
     			pageTable[j] = entry;
     		
     	}
     	for(j=512;j<768;j++){
            /*Case when number of pages in memory is not a multiple of NUM_PAGE_TABLE_ENTRIES*/
     		
     			pte_t entry = {0};
     			ulong_t addr;
        /* Create a page table entry pointing to  physical memory frame*/
     			entry.present = 1;
     			entry.flags =  VM_WRITE;
     			addr=1019 << 10;
     			addr=addr | ((ulong_t) j);
     			entry.pageBaseAddr = addr;
                //Print("Address is %x \n", entry.pageBaseAddr);
        /* Install the PDE in index i of the page directory */
     			pageTable[j] = entry;
     		
     	}
     	PageDir[1019] = entry;
     //Map APIC and IO APIC

    /*Install  page table entries*/
     for(i=0;i<numPdEnt;i++){
     	pte_t *PageTable = (pte_t *) (PageDir[i].pageTableBaseAddr << 12);

     	for(j=0;j<NUM_PAGE_TABLE_ENTRIES;j++){
            /*Case when number of pages in memory is not a multiple of NUM_PAGE_TABLE_ENTRIES*/
     		if(numPages%NUM_PAGE_TABLE_ENTRIES!=0 && i==numPdEnt-1 && j==(numPages%NUM_PAGE_TABLE_ENTRIES)){
     			break;
     		}
     		else if (i==0 && j==0)
     		{
				pte_t entry = {0};
				PageTable[j] = entry;
				continue;
     		}
     		else{

     			pte_t entry = {0};
     			ulong_t addr;
        /* Create a page table entry pointing to  physical memory frame*/
     			entry.present = 1;
     			entry.flags = VM_USER | VM_WRITE;
     			addr=((ulong_t) i) << 10;
     			addr=addr | ((ulong_t) j);
     			entry.pageBaseAddr = addr;
                //Print("Address is %x \n", entry.pageBaseAddr);
        /* Install the PDE in index i of the page directory */
     			PageTable[j] = entry;
     		}
     	}
     }

    /*Turn on paging*/
     Enable_Paging(PageDir);

    /* Install page fault handler */
     Install_Interrupt_Handler(14, Page_Fault_Handler);
     Install_Interrupt_Handler(46, Page_Fault_Handler);


 }

 void Init_Secondary_VM() {
 	TODO_P(PROJECT_VIRTUAL_MEMORY_A, "enable paging on secondary cores");
 }

/**
 * Initialize paging file data structures.
 * All filesystems should be mounted before this function
 * is called, to ensure that the paging file is available.
 */
 void Init_Paging(void) {
 	// list of free pages in pagefile
    int i;
    for(i = 0; i < PF_SIZE; i++) {
        struct FreeList_Node * fln = 0;
        fln = Malloc(sizeof(struct FreeList_Node));
        Add_To_Back_Of_PF_FreePages(&g_PF_FreeList, fln);
    }
    
    // initialize the mapping (empty)
    memset(PF_Map, -1, sizeof(ulong_t) * 33504);

    // open the block device for paging file
    Open_Block_Device("ide1",&pdev);

    // TODO_P(PROJECT_VIRTUAL_MEMORY_B,
    //  "Initialize paging file data structures");
 }

/**
 * Find a free bit of disk on the paging file for this page.
 * Interrupts must be disabled.
 * @return index of free page sized chunk of disk space in
 *   the paging file, or -1 if the paging file is full
 */
 int Find_Space_On_Paging_File(void) {
    KASSERT(!Interrupts_Enabled());

    struct FreeList_Node * free_node;
    if (!Is_PF_FreePages_Empty(&g_PF_FreeList)) {
        free_node = Get_Front_Of_PF_FreePages(&g_PF_FreeList); 
        // KASSERT(??)
        Remove_From_Front_Of_PF_FreePages(&g_PF_FreeList);
        return free_node->index;
    }
    else 
        return -1;
    // TODO_P(PROJECT_VIRTUAL_MEMORY_B, "Find free page in paging file");
    // return EUNSUPPORTED;
 }

/**
 * Free a page-sized chunk of disk space in the paging file.
 * Interrupts must be disabled.
 * @param pagefileIndex index of the chunk of disk space
 */
 void Free_Space_On_Paging_File(int pagefileIndex) {
 	KASSERT(!Interrupts_Enabled());
 	TODO_P(PROJECT_VIRTUAL_MEMORY_B, "Free page in paging file");
 }

/**
 * Write the contents of given page to the indicated block
 * of space in the paging file.
 * @param paddr a pointer to the physical memory of the page
 * @param vaddr virtual address where page is mapped in user memory
 * @param pagefileIndex the index of the page sized chunk of space
 *   in the paging file
 */
 void Write_To_Paging_File(void *paddr, ulong_t vaddr, int pagefileIndex) {
 	struct Page *page = Get_Page((ulong_t) paddr);
    KASSERT(!(page->flags & PAGE_PAGEABLE));    /* Page must be locked! */

    int i;
    for(i = 0; i < 8; i++) {
        Block_Write(pdev, 8 * pagefileIndex + i, (void*)page + 512 * i);
    }

    extern struct Page *g_pageList;
    ulong_t index = page - g_pageList;
    PF_Map[index] = pagefileIndex;
    // TODO_P(PROJECT_VIRTUAL_MEMORY_B, "Write page data to paging file");
 }

/**
 * Read the contents of the indicated block
 * of space in the paging file into the given page.
 * @param paddr a pointer to the physical memory of the page
 * @param vaddr virtual address where page will be re-mapped in
 *   user memory
 * @param pagefileIndex the index of the page sized chunk of space
 *   in the paging file
 */
 void Read_From_Paging_File(void *paddr, ulong_t vaddr, int pagefileIndex) {
 	struct Page *page = Get_Page((ulong_t) paddr);
    KASSERT(!(page->flags & PAGE_PAGEABLE));    /* Page must be locked! */
 	TODO_P(PROJECT_VIRTUAL_MEMORY_B, "Read page data from paging file");
 }


 void *Mmap_Impl(void *ptr, unsigned int length, int prot, int flags, int fd) {
 	TODO_P(PROJECT_MMAP, "Mmap setup mapping");
 	return NULL;
 }

 bool Is_Mmaped_Page(struct User_Context * context, ulong_t vaddr) {
 	TODO_P(PROJECT_MMAP,
 		"is this passed vaddr an mmap'd page in the passed user context");
 	return false;
 }

 void Write_Out_Mmaped_Page(struct User_Context *context, ulong_t vaddr) {
 	TODO_P(PROJECT_MMAP, "Mmap write back dirty mmap'd page");
 }

 int Munmap_Impl(ulong_t ptr) {
 	TODO_P(PROJECT_MMAP, "unmapp the pages");
 }
