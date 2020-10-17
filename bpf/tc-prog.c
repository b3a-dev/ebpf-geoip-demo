#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <bpf/types_mapper.h>
#include <lib/common.h>
#include <linux/ip.h>
#include <lib/ipv4.h>
#include <lib/l4.h>

#ifndef TC_ACT_PIPE
#define TC_ACT_PIPE 3
#endif

#if !defined(NCPUS)
#error "Please define NCPUS macro"
#endif

#define TCP_PORT 80

struct event {
	__u32 ip_addr; /* source IP addr */
};

struct bpf_elf_map __section_maps xevents = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.size_key = sizeof(__u32),
	.size_value = sizeof(struct event),
	.pinning = PIN_GLOBAL_NS,
	.max_elem = NCPUS,
};

__section("bpf-prog")
int collect_ips(struct __sk_buff *skb) {
	struct event xev;
	void *data, *data_end;
	int l4_off;
	__u16 proto;
	__u8 nexthdr;

	if (!validate_ethertype(skb, &proto)) {
		goto end;
	}

	switch (proto) {
		case bpf_htons(ETH_P_IP): {
			struct iphdr *ip4;
			if (!revalidate_data(skb, &data, &data_end, &ip4)) {
				goto end;
			}
			nexthdr = ip4->protocol;
			if (nexthdr != IPPROTO_TCP)
				goto end;
			if (ipv4_is_fragment(ip4))
				goto end;
			l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

			__u16 dport;
			ctx_load_bytes(skb, l4_off + TCP_DPORT_OFF, &dport, sizeof(dport));
			if  (bpf_ntohs(dport) != TCP_PORT) {
				goto end;
			}
			xev.ip_addr = ip4->saddr;
			break;
		}

		default:
			goto end;
	}

	skb_event_output(skb, &xevents, BPF_F_CURRENT_CPU, &xev, sizeof(xev));
end:
	return TC_ACT_PIPE;
}

BPF_LICENSE("GPL");
