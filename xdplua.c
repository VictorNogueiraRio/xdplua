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

static void switch_tcp(struct tcphdr *tcph) {
	unsigned short source;

	source = tcph->source;
	tcph->source = tcph->dest;
	tcph->dest = source;
}

static void handle_link_layer_reply(struct sk_buff *skb) {
	struct ethhdr *eth;

	eth = (struct ethhdr *) skb_mac_header(skb);
	switch_eth(eth);
}


static void handle_network_layer_reply(struct sk_buff *skb, int lendiff) {
	struct iphdr *iph;

	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	switch_ip(iph);
}

static void adjust_iphdrlen(struct iphdr *iph, int lendiff) {
	short iphdrlen;

	iphdrlen = lendiff;
	iph->tot_len = ntohs(iphdrlen);
}

static void handle_ip_checksum(struct iphdr *iph) {
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *) iph, iph->ihl);
}

static void handle_tcp_checksum(struct iphdr *iph, struct tcphdr *tcph) {
	int tcplen;

	tcplen = tcph->doff * 4;
	tcph->check = 0;
	tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, tcplen,
		IPPROTO_TCP, csum_partial((unsigned char *)tcph, tcplen, 0));
}

static int xdplua_tcp_rst_reply(lua_State *L) {
	struct iphdr *iph;
	struct tcphdr *tcph;
	int maclen;
	int iplen;
	int seqnum;
	struct sk_buff *skb = (struct sk_buff *) lua_topointer(L, -1);

	maclen = skb->data - skb_mac_header(skb);

	handle_link_layer_reply(skb);
	handle_network_layer_reply(skb, 0);
	iph = ip_hdr(skb);
	iplen = iph->ihl * 4;

	skb_set_transport_header(skb, iplen);
	tcph = tcp_hdr(skb);

	switch_tcp(tcph);

	adjust_iphdrlen(iph, sizeof(struct tcphdr) + iplen);
	handle_ip_checksum(iph);

	seqnum = tcph->seq;
	tcph->seq = htonl(ntohl(tcph->ack_seq));
	tcph->ack_seq = htonl(ntohl(seqnum) + tcph->syn + tcph->fin + skb->len - ip_hdrlen(skb) - (tcph->doff << 2));

	tcph->doff = sizeof(struct tcphdr) / 4;
	tcph->res1 = 0;
	tcph->fin = 0;
	tcph->syn = 0;
	tcph->rst = 1;
	tcph->psh = 0;
	tcph->ack = 1;
	tcph->urg = 0;
	tcph->ece = 0;
	tcph->cwr = 0;

	tcph->window = 0;

	__skb_set_length(skb, iplen + sizeof(struct tcphdr));
	handle_tcp_checksum(iph, tcph);

	return 0;
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
static int xdplua_fib_lookup(lua_State *L) {
	struct xdp_rxq_info rxq;
	struct sk_buff *skb;
	struct xdp_buff ctx;
	struct bpf_fib_lookup fib_params;
	static const struct bpf_func_proto *fib_lookup_proto;
	struct iphdr *iph;
	int ret;

	unsigned int ipdaddr = luaL_checkinteger(L, 1);
	luaU_getregval(L, XDPLUA_SKBENTRY, &skb);

	/* work around to use helper */
	rxq.dev = skb->dev;
	ctx.rxq = &rxq;
	fib_lookup_proto = xdp_verifier_ops.get_func_proto(BPF_FUNC_fib_lookup,
				NULL);
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);

	fib_params.family	= AF_INET;
	fib_params.tos		= iph->tos;
	fib_params.l4_protocol	= iph->protocol;
	fib_params.sport	= 0;
	fib_params.dport	= 0;
	fib_params.tot_len	= ntohs(iph->tot_len);
	fib_params.ipv4_src	= iph->saddr;
	fib_params.ipv4_dst	= ntohl(ipdaddr);

	fib_params.ifindex = skb->dev->ifindex;

	ret = fib_lookup_proto->func((u64)&ctx, (u64)&fib_params,
				(u64)sizeof(fib_params), (u64)0, (u64)0);

	if (!ret) {
		struct ethhdr *eth;
		struct in_device* in_dev;
		struct in_ifaddr* if_info;
		struct net_device *fwd;

		eth = (struct ethhdr *) skb_mac_header(skb);
		memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
		memcpy(eth->h_source, fib_params.smac, ETH_ALEN);

		fwd = dev_get_by_index_rcu(dev_net(skb->dev), fib_params.ifindex);
		in_dev = (struct in_device *) fwd->ip_ptr;
		if_info = in_dev->ifa_list;
		for (;if_info;if_info=if_info->ifa_next) {
			if (!(strcmp(if_info->ifa_label, fwd->name))) {
				break;
			}
		}

		iph->saddr = if_info->ifa_address;
		iph->daddr = ntohs(ipdaddr);
		lua_pushinteger(L, fib_params.ifindex);

		return 1;
	}

	return 0;
}

static int xdplua_do_redirect(lua_State *L) {

	struct sk_buff *skb;
	struct iphdr *iph;
	struct udphdr *uh;
	struct bpf_redirect_info *ri = this_cpu_ptr(&bpf_redirect_info);
	unsigned int ifindex = luaL_checkinteger(L, 1);
	short udplen;

	luaU_getregval(L, XDPLUA_SKBENTRY, &skb);

	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *) iph, iph->ihl);

	skb_set_transport_header(skb, iph->ihl * 4);
	uh = udp_hdr(skb);

	udplen = htons(uh->len);
	uh->check = 0;
	uh->check = csum_tcpudp_magic(iph->saddr, iph->daddr, udplen,
		IPPROTO_UDP, csum_partial((unsigned char *)uh, udplen, 0));

	ri->tgt_index = ifindex;
	ri->flags = 0;
	WRITE_ONCE(ri->map, NULL);
	return 0;
}

static int xdplua_get_ifindex(lua_State *L) {
	struct sk_buff *skb;

	luaU_getregval(L, XDPLUA_SKBENTRY, &skb);
	lua_pushinteger(L, skb->dev->ifindex);

	return 1;
}

static int xdplua_map_update_elem(lua_State *L) {
	const struct bpf_func_proto *map_udpate_proto;
	struct bpf_map *map;
	int key;
	int elem;
	int ret;

	map = lua_touserdata(L, 1);
	key = lua_tointeger(L, 2);
	elem = lua_tointeger(L, 3);

	ret = CALLHELPER(map_udpate_proto, map_update_elem, map, &key, &elem, 0, 0);

	lua_pushinteger(L, ret);
	return 1;
}

static int xdplua_map_lookup_elem(lua_State *L) {
	static const struct bpf_func_proto *map_lookup_proto;
	struct bpf_map *map;
	int key;
	int *elem;

	map = lua_touserdata(L, 1);
	key = lua_tointeger(L, 2);

	elem = (int *) CALLHELPER(map_lookup_proto, map_lookup_elem, map, &key,
								0, 0, 0);

	if (!elem)
		return luaL_error(L, "unable to lookup element");

	lua_pushinteger(L, *elem);
	return 1;
}

static const luaL_Reg xdplua_lib[] = {
	{"udp_reply",			xdplua_udp_reply},
	{"tcp_rst_reply",		xdplua_tcp_rst_reply},
	{"fib_lookup",			xdplua_fib_lookup},
	{"get_ifindex",			xdplua_get_ifindex},
	{"do_redirect",			xdplua_do_redirect},
	{"bpf_map_update_elem",		xdplua_map_update_elem},
	{"bpf_map_lookup_elem",		xdplua_map_lookup_elem},
	{NULL, NULL}
};

int luaopen_xdplua(lua_State *L)
{
	luaL_newlib(L, xdplua_lib);
	return 1;
}
