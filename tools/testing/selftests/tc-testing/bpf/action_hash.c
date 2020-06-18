/* SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2018 Davide Caratti, Red Hat inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include "compiler.h"
#include <asm/types.h>
#include <asm/byteorder.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/filter.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define __section(x) __attribute__((section(x), used))
#define offsetof(x, y) __builtin_offsetof(x, y)
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
/* Some used BPF intrinsics. */
unsigned long long load_byte(void *skb, unsigned long long off)
	asm ("llvm.bpf.load.byte");
unsigned long long load_half(void *skb, unsigned long long off)
	asm ("llvm.bpf.load.half");

static inline int do_hash_ipv4(struct __sk_buff *skb, int nh_off)
{
	__u16 dport, sport;
	__u8 ip_proto, ip_vl;

	ip_proto = load_byte(skb, nh_off +
			     offsetof(struct iphdr, protocol));
	if (ip_proto != IPPROTO_UDP)
		return 0;

	ip_vl = load_byte(skb, nh_off);


	return (dport ^ sport);
}

__attribute__((section("hash-func"),used)) int hash_main(struct __sk_buff *skb)
{
	int ret = 0, nh_off = BPF_LL_OFF + ETH_HLEN;
	__u16 dport, sport;
	__u8 ip_proto, ip_vl;

	if (likely(skb->protocol == __constant_htons(ETH_P_IP))) {
		ip_proto = load_byte(skb, nh_off +
				     offsetof(struct iphdr, protocol));
		if (ip_proto != IPPROTO_UDP)
			return TC_ACT_OK;

		if (likely(ip_vl == 0x45))
			nh_off += sizeof(struct iphdr);
		else
			nh_off += (ip_vl & 0xF) << 2;

		dport = load_half(skb, nh_off + offsetof(struct udphdr, dest));
		sport = load_half(skb, nh_off + offsetof(struct udphdr, source));

		bpf_set_hash(skb, dport ^ sport);
	}

	return TC_ACT_OK;
}
char _license[] __attribute__((section("license"),used)) = "GPL";
