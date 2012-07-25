/*
 * mem.c - memory manipulation functions
 *
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <linux/kallsyms.h>

#include "mem.h"

extern int (*my_page_is_ram)(unsigned long pagenr);
extern int unhide;
static char have_hidden = 0;

// map highmem if needed
void *xlate_mem_ptr(unsigned long phys)
{
    unsigned long start = phys & PAGE_MASK;
    unsigned long pfn = PFN_DOWN(phys);

    // if a page is RAM, we can use __va or kmap for highmem
    if ((*my_page_is_ram)(start >> PAGE_SHIFT)) {
	if (PageHighMem(pfn_to_page(pfn))) {
	    return kmap_atomic_pfn(pfn);
	}
	return __va(phys);
    }
    return 0;
}

// our own implementation of unxlate_dev_mem_ptr
// unmap highmem if needed
void unxlate_mem_ptr(unsigned long phys, void *addr)
{
    unsigned long pfn = PFN_DOWN(phys); 

    // if page is RAM, check for highmem
    if ((*my_page_is_ram)(phys >> PAGE_SHIFT)) {
	if (PageHighMem(pfn_to_page(pfn))) { 
	    kunmap_atomic(addr);
	}
	return;
    }
}

// unhide hidden lkm
void unhide_module(unsigned long mod_addr)
{
    struct module tmp;
    unsigned long head_offset = (unsigned long)&tmp.list - (unsigned long)&tmp;
    struct list_head *hid_head = (struct list_head *)(mod_addr + head_offset);

    // lock is already installed so it is safe
    hid_head->next = __this_module.list.next;
    hid_head->prev = &__this_module.list;
    __this_module.list.next = hid_head;
}

void scan_page(unsigned char *buf, unsigned long va)
{
    int state;
    unsigned char *ptr = buf, *border = buf + PAGE_SIZE, *tmp;
    unsigned char name[MODULE_NAME_LEN];

    do {
	// module signature checks
	// check module state
	tmp = ptr;
	state = *(int *)tmp;
	if ((state >= MODULE_STATE_LIVE) && (state <= MODULE_STATE_GOING)) {

	    // get module name
	    tmp += MOD_NAME_OFFSET;
	    if (tmp > border) 
		break;

	    // do we have a null-terminated name?
	    memcpy(name, tmp, MODULE_NAME_LEN);
	    if (memchr(name, 0x0, MODULE_NAME_LEN)) {

		if (strlen(name)) {
		    tmp += MOD_ADDR_OFFSET;
		    if(tmp > border) 
			break;
		}

		// compare base address with module_kobject->mod
		if ((va + (ptr - buf)) == *(unsigned long*)tmp) {

		    if (find_module(name) == NULL) {
			printk("\n\n   ! Hidden module \"%s\" detected !\n", name);
			have_hidden = 1;

			// unhide hidden module if requested
			if (unhide) {
			    unhide_module(va + (ptr - buf)); 
			    printk("   + Module \"%s\" was unhided\n\n", name);
			} else
			    printk("\n");
		    }
		}
	    }
	}

	ptr += STEP;
    } while(ptr < border);
}

// get valid pages for vmalloc area & scan them
char check_mem(void)
{
    unsigned long p, va = MODULES_VADDR;
    char *map_addr;
    unsigned char *buf;
    struct page *page;

    buf = kmalloc(PAGE_SIZE, GFP_KERNEL);		// stack is too small
    if (buf == NULL) {
	printk(" - kmalloc\n");
	return 0;
    }

    while (va <= MODULES_END) {
	page = vmalloc_to_page((void *)va);		// get struct page 
	if (page) {
	    p = page_to_phys(page);			// get phys addr

	    map_addr = xlate_mem_ptr(p);		// mmap
	    if (map_addr != NULL) {
		memcpy(buf, map_addr, PAGE_SIZE);
		scan_page(buf, va);
		unxlate_mem_ptr(p, map_addr);		// unmap
	    }
	}
	va += PAGE_SIZE;
    }

    kfree(buf);
    return have_hidden;
}
