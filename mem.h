
// this offsets suck, fix!
#define MOD_NAME_OFFSET		sizeof(int) + sizeof(struct list_head)
#define MOD_ADDR_OFFSET		MODULE_NAME_LEN + sizeof(struct kobject)
#define FULL_ADDR_OFFSET	MOD_NAME_OFFSET + MOD_ADDR_OFFSET
#define STEP			0x10

void *xlate_mem_ptr(unsigned long phys);
void unxlate_mem_ptr(unsigned long phys, void *addr);
void unhide_module(unsigned long mod_addr);
void scan_page(unsigned char *buf, unsigned long va);
char check_mem(void);

