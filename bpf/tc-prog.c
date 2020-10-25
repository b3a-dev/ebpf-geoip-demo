/* Include dependencies, as if we were importing needed libraries? */
#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <bpf/types_mapper.h>
#include <lib/common.h>
#include <linux/ip.h>
#include <lib/ipv4.h>
#include <lib/l4.h>

/* tc, much more than just QoS nowadays
There are hooks available in tc (Linux Traffic Control subsystem), that allow to run eBPF programs as both: filters and actions */
#ifndef TC_ACT_PIPE /* I understand this checks if the flag "direct-action" is set for tc, if set then the return value from the filter should be considered as the one of an action instead. */
#define TC_ACT_PIPE 3 /* this is a possible return value as action, means: Iterate to the next action, if available. */
#endif

/* Used later */
#if !defined(NCPUS)
#error "Please define NCPUS macro"
#endif

/* Target port for requests we want to get source IPs from. 
*/
#define TCP_PORT 80

/* kernel data types, u32: unsigned 32-bit value
prefix with a dou-ble underscore as a user-space program needs to use these types 
*/
struct event {
	__u32 ip_addr; /* source IP addr */
};

/* 
A struct bpf_elf_map entry defines a map in the program and contains all relevant information needed to generate a map which is used from BPF programs & userspace app. 
The structure must be placed into the maps section, so that the loader can find it.

When we define this type of map (PF_MAP_TYPE_PERF_EVENT_ARRAY), for performance reasons there is one copy/instance of the datastructure per CPU.

*/
struct bpf_elf_map __section_maps xevents = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY, /* These type of Array maps are used by the kernel to associate tracing output with a specific key. User-space programs associate fds with each key, and can poll() those fds to receive notification that data has been traced. */
	.size_key = sizeof(__u32),
	.size_value = sizeof(struct event),
	.pinning = PIN_GLOBAL_NS, /* Pinning options determine how the map's file descriptor is exported via the filesystem, maps which specify PIN_GLOBAL_NS are found in /sys/fs/bpf/tc/globals/ */
	.max_elem = NCPUS,
};

/*  Type of bpf program: tc (traffic control) subsystem program 
tc_cls_act allows to use BPF programs as classifiers and actions in tc, the Linux QoS subsystem.
tc programs can classify, modify, redirect or drop packets.

we mark to the loader (tc in this case), which part is the map and the bpf program.
*/
__section("bpf-prog")
/* Using direct packet access to read packet data, meaning we can use the  __sk_buff "data" pointer to access packet data like a normal pointer. For safety BPF requires we first test we have not reached the end of the linear portion of the packet (data_end). */
int collect_ips(struct __sk_buff *skb) { /* We pass as context a pointer to the struct __sk_buff containing packet metadata/data. This structure is defined in include/linux/bpf.h*/
	struct event xev;
	void *data, *data_end; /* end of the linear portion of the packet */
	int l4_off;
	__u16 proto;
	__u8 nexthdr;
    
	if (!validate_ethertype(skb, &proto)) { /* if unknown traffic */
		goto end;
	}

	switch (proto) {
		case bpf_htons(ETH_P_IP): { /* ETH_P_IP instead of ETH_P_ALL as we only want to listen for incoming IP packets, ingress. */
			struct iphdr *ip4; /* use an ip hdr because we only want ip/check */
			/* only eth packet:*/
			if (!revalidate_data(skb, &data, &data_end, &ip4)) { /* we wrote all IP heaadaer (function from Cilium) make sure all data we need is in this structure, we are not accessing any other mem position, we are only accesing only packet info We do this for th eip header ,test we have not reached the end of the linear portion of the packet (data_end) */
				goto end;
			}
			nexthdr = ip4->protocol; /* GET protocol, in each header field says which is the next protoco, in this case we want only thoe packet next is TCP */
			if (nexthdr != IPPROTO_TCP) /* continue only if TCP */
				goto end;
			if (ipv4_is_fragment(ip4)) /* If we have fragmented headers we may not have the port info is in other packet, IP heaer has flag metnion is fragmented, so if it is a fragment we don't do anytign, no handle that ,Check if IPv4 fragment matches fragment reassembly buffer.  */
				goto end;
			l4_off = ETH_HLEN + ipv4_hdrlen(ip4); /* packet size, offset = ETH_HLEN (Total octets in header) + ipv4 header length ?*/

			__u16 dport; /* 16 bits, 2Bytes, different ways to write this, a-b-c .. or c-b-a, which order do we restore ip addresses...? no matter which machine reviwe netwrok orer, host order, machine oder */
			ctx_load_bytes(skb, l4_off + TCP_DPORT_OFF, &dport, sizeof(dport)); /* convce verifier we are only looking at data we are allowe dto, an dthis how we do it, same with revalidate_data but nwo we onlly bring port.*/
			if  (bpf_ntohs(dport) != TCP_PORT) { /* want only those accessing defined port TCP_PORT (80)  , this oncversta the host to use the host ordr: network to host sort, */
				goto end;
			}
			xev.ip_addr = ip4->saddr; /* get the source ip from iphdr struct and set the value in the event struct */
			break;
		}

		default:
			goto end;
	}

	/* helper function, push the even in the datasturcture, map, in the instance of the datastructure we are currently running */
	skb_event_output(skb, &xevents, BPF_F_CURRENT_CPU, &xev, sizeof(xev)); 
end:
	return TC_ACT_PIPE; /* this bpf tc classifier programm returns directly an action, means: Iterate to the next action. */
}

BPF_LICENSE("GPL"); /* some bpf helper functions are only available if you set the license of your bpf program to GPL. */
