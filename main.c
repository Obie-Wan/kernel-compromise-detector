/*
 * main.c - main module routines	 
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kallsyms.h>

#include "checks/nf_check.h"
#include "mem.h"

#define BANNER 			"Kernel Compromise Detector v.0.5"

int (*my_page_is_ram)(unsigned long pagenr); // = 0xaddr;
int unhide = 0;
module_param(unhide, bool, 0400);
MODULE_PARM_DESC(unhide, " If set all hidden modules are unhided.");

struct check_struct {
	unsigned char *what;	// check name
	char (*proc)(void);	// check function
};
typedef struct check_struct check_info;

// check list to perform
static check_info checklist[] = {
	{ "hidden modules	", check_mem	},
	{ "netfilter hooks	", check_nf	}
};

void run_check(check_info *check)
{
    char result = 0;

    printk(" ~ Checking for %s ... ", check->what);
    if(check->proc)
	result = check->proc();

    if(!result)
	printk("nothing\n");
}

unsigned long find_symbols()
{
    // we need only 1 symbol at this moment
    my_page_is_ram = kallsyms_lookup_name("page_is_ram");
    return my_page_is_ram;
}

static int __init init(void)
{
    size_t i;

    // get required symbols
    if(find_symbols() == NULL) {
	printk(" Can't locate symbols, try setting addresses manually!\n");
	return -1;
    }

    // print banner, etc.
    printk("\n %s\n", BANNER);
    printk(" Starting checks ...\n");

    // run each check from the check list
    for(i = 0; i < sizeof(checklist) / sizeof(check_info); i++) {
	run_check(&checklist[i]);
    }

    // printk(" ~ Checking for hidden processes ... ?\n");
    // printk(" . Checking for ptrace rootkits ...\n");
    return 0;
}

static void __exit cleanup(void)
{
}

module_init(init);
module_exit(cleanup);

MODULE_LICENSE("BSD");
MODULE_AUTHOR("Obie-Wan");
MODULE_DESCRIPTION(BANNER);
