/*
 * nf_check.c - checks for netfilter hooks (used in some lame rootkits)
 *
 */

#include <linux/netfilter.h>

#include "nf_check.h"

DEFINE_MUTEX(nf_hook_mutex);

unsigned char *get_proto_name(size_t proto)
{
    switch(proto) {
    case NFPROTO_UNSPEC:
		return "NFPROTO_UNSPEC";
		break;

    case NFPROTO_IPV4:
		return "NFPROTO_IPV4";
		break;

    case NFPROTO_ARP:   
		return "NFPROTO_ARP";
		break;

    case NFPROTO_BRIDGE:
		return "NFPROTO_BRIDGE";
		break;

    case NFPROTO_IPV6:  
		return "NFPROTO_IPV6";
		break;

    case NFPROTO_DECNET:
		return "NFPROTO_DECNET";
		break;
    default:
		return "UNKNOWN";
    }
}

unsigned char *get_hook_name(size_t hook)
{
    switch(hook) {
    case NF_INET_PRE_ROUTING:
		return "NF_INET_PRE_ROUTING";
		break;
    case NF_INET_LOCAL_IN:
		return "NF_INET_LOCAL_IN";
		break;
    case NF_INET_FORWARD:
		return "NF_INET_FORWARD";
		break;
    case NF_INET_LOCAL_OUT:
		return "NF_INET_LOCAL_OUT";
		break;
    case NF_INET_POST_ROUTING:
		return "NF_INET_POST_ROUTING";
		break;
    default:
		return "UNKNOWN";
    }
}

// show all netfilter hooks
// some hooks may be installed by legitimate modules (SELinux, etc.)
char check_nf(void)
{
	struct nf_hook_ops *elem;
	char result = 0;
	size_t proto, hook;
	//unsigned char name[MODULE_NAME_LEN];

	if (mutex_lock_interruptible(&nf_hook_mutex) < 0) {
	    printk(" - failed acquiring mutex\n");
	    return 0;
	}

	for(proto = 0; proto < NFPROTO_NUMPROTO; proto++) {
	    for(hook = 0; hook < NF_MAX_HOOKS; hook++) {
		list_for_each_entry(elem, &nf_hooks[proto][hook], list) {

		    /*if(elem->owner) {
			strncpy(name, elem->owner->name, MODULE_NAME_LEN);
			name[MODULE_NAME_LEN] = 0;
		    } else {
			strcpy(name, "[unknown]");
		    }*/

		    printk("\n\n   ! netfilter hook detected\n   ! type: %s %s, "
			   "addr: 0x%.8x\n\n", get_proto_name(proto), 
			   get_hook_name(hook), (unsigned int)elem->hook); 
		    result = 1;
		}
	    }
	}
	mutex_unlock(&nf_hook_mutex);
	return result;
}
