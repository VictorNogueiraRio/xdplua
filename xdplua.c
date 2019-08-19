#include <xdplua.h>

static void switch_eth(struct ethhdr *eth) {
	unsigned char source[ETH_ALEN];

	memcpy(source, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, source, ETH_ALEN);
}

static void switch_ip(struct iphdr *iph) {
	unsigned int source;

	source = iph->saddr;
	iph->saddr = iph->daddr;
	iph->daddr = source;
}

static void switch_udp(struct udphdr *uh) {
	unsigned short source;

	source = uh->source;
	uh->source = uh->dest;
	uh->dest = source;
}

static int xdplua_udp_reply(lua_State *L) {
	int additionallen;
	size_t payloadlen;
	int maclen;
	short iplen;
	short udplen;
	unsigned char *tmp;
	struct iphdr *iph;
	struct udphdr *uh;
	struct ethhdr *eth;
	unsigned char *payload = ldata_topointer(L, 1, &payloadlen);
	int payloadoff = luaL_checkinteger(L, 2);
	struct sk_buff *skb = (struct sk_buff *) lua_topointer(L, 3);

	if (!payload)
		return luaL_error(L, "payload NULL");

	maclen = skb->data - skb_mac_header(skb);

	eth = (struct ethhdr *) skb_mac_header(skb);
	switch_eth(eth);
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	switch_ip(iph);

	payloadoff -= maclen;
	additionallen = payloadoff + payloadlen - skb->len;

	iplen = htons(iph->tot_len);
	iplen += additionallen;
	iph->tot_len = ntohs(iplen);

	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *) iph, iph->ihl);

	if (additionallen != 0) {
		if (additionallen > 0) {
			if (__skb_grow(skb, payloadoff + payloadlen))
				return luaL_error(L, "couldn't expand sk_buff\n");
		} else {
			__skb_set_length(skb, payloadlen + payloadoff);
		}
	}

	tmp = (unsigned char *) skb_tail_pointer(skb);
	tmp -= payloadlen;
	memcpy(tmp, payload, payloadlen);

	skb_set_transport_header(skb, iph->ihl * 4);
	uh = udp_hdr(skb);
	switch_udp(uh);
	udplen = htons(uh->len);
	udplen += additionallen;

	uh->len = ntohs(udplen);
	uh->check = 0;
	uh->check = csum_tcpudp_magic(iph->saddr, iph->daddr, udplen,
		IPPROTO_UDP, csum_partial((unsigned char *)uh, udplen, 0));

	lua_pushinteger(L, XDP_TX);
	return 1;
}

static const luaL_Reg xdplua_lib[] = {
	{"udp_reply", xdplua_udp_reply},
	{NULL, NULL}
};

int luaopen_xdplua(lua_State *L)
{
	luaL_newlib(L, xdplua_lib);
	return 1;
}
