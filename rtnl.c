/*
 * Copyright (C) 2017 John Crispin <john@phrozen.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "ustatusd.h"

static struct status_socket rtnl_status;

static int avl_ip4cmp(const void *k1, const void *k2, void *ptr)
{
	return memcmp(k1, k2, 4);
}

static int avl_ip6cmp(const void *k1, const void *k2, void *ptr)
{
	return memcmp(k1, k2, 16);
}

static struct avl_tree ip4_tree = AVL_TREE_INIT(ip4_tree, avl_ip4cmp, false, NULL);
static struct avl_tree ip6_tree = AVL_TREE_INIT(ip6_tree, avl_ip6cmp, false, NULL);

static void rtnl_list(uint32_t type)
{
	struct rtgenmsg msg = { .rtgen_family = AF_UNSPEC };

	nl_send_simple(rtnl_status.sock, type, NLM_F_DUMP, &msg, sizeof(msg));
	nl_wait_for_ack(rtnl_status.sock);
}

static void neigh_handler(struct nlmsghdr *nh, const char *type, __u16 mask)
{
	struct ip_node *node;
	struct nlattr *nda[__NDA_MAX];
	void *dst;
	uint8_t *lladdr, *dummy[6] = { 0 }, set[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	struct ndmsg *ndm = nlmsg_data(nh);
	struct avl_tree *ip_tree;
	int ip_len;

	if (ndm->ndm_state != mask)
		return;

	nlmsg_parse(nh, sizeof(struct ndmsg), nda, NDA_MAX, NULL);
	if (!nda[NDA_DST])
		return;

	dst = nla_data(nda[NDA_DST]);
	lladdr = nda[NDA_LLADDR] ? nla_data(nda[NDA_LLADDR]) : dummy;

	switch (ndm->ndm_family) {
	case AF_INET:
		if ((*lladdr & 0x01) && memcmp(lladdr, set, 6))
			return;

		ip_tree = &ip4_tree;
		ip_len = 4;
		break;

	case AF_INET6:
		ip_tree = &ip6_tree;
		ip_len = 6;
		break;

	default:
		return;
	}

	node = avl_find_element(ip_tree, dst, node, avl);

	if (!node && !strcmp(type, "neigh.new")) {
		uint8_t *mac_buf, *ip_buf;

		node = calloc_a(sizeof(struct ip_node),
			&ip_buf, ip_len, &mac_buf, 6);
		if (!node)
			return;
		node->mac = memcpy(mac_buf, lladdr, 6);
		node->ip = memcpy(ip_buf, dst, ip_len);
		node->iface = ndm->ndm_ifindex;
		node->avl.key = node->ip;
		node->ip_len = ip_len;
		avl_insert(ip_tree, &node->avl);
	} else if (!strcmp(type, "neigh.del")) {
		if (node) {
			avl_delete(ip_tree, &node->avl);
			free(node);
		}
	} else {
		return;
	}

	blob_buf_init(&b, 0);
	blobmsg_add_iface(&b, "interface", ndm->ndm_ifindex);
	blobmsg_add_mac(&b, "mac", lladdr);
	if (ip_len == 4) {
		blobmsg_add_ipv4(&b, "ip", dst);
		blobmsg_add_u32(&b, "ipv4", 1);
	} else {
		blobmsg_add_ipv6(&b, "ip", dst);
		blobmsg_add_u32(&b, "ipv6", 1);
	}
	ubus_notify(&conn.ctx, &ubus_object, type, b.head, -1);
}

static void link_handler(struct nlmsghdr *nh)
{
	struct nlattr *nla[__IFLA_MAX];
	struct ifinfomsg *imsg = nlmsg_data(nh);

	if (imsg->ifi_index == 1)
		return;

	nlmsg_parse(nh, sizeof(struct ifinfomsg), nla, __IFLA_MAX - 1, NULL);
	if (!nla[IFLA_IFNAME] || !nla[IFLA_CARRIER])
		return;
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "ifname", nla_get_string(nla[IFLA_IFNAME]));
	blobmsg_add_u32(&b, "carrier", nla_get_u32(nla[IFLA_CARRIER]));
	ubus_notify(&conn.ctx, &ubus_object, "network.link", b.head, -1);
}

static void route_handler(struct nlmsghdr *nh, const char *type)
{
	struct nlattr *nla[__RTA_MAX];
	struct rtmsg *rtm = nlmsg_data(nh);
	void *dst = NULL, *gateway = NULL;
	uint32_t oif = 0;

	nlmsg_parse(nh, sizeof(struct rtmsg), nla, __RTA_MAX - 1, NULL);
	if (nla[RTA_DST])
		dst = nla_data(nla[RTA_DST]);
	if (nla[RTA_GATEWAY])
		gateway = nla_data(nla[RTA_GATEWAY]);
	if (nla[RTA_OIF])
		oif = nla_get_u32(nla[RTA_OIF]);

	blob_buf_init(&b, 0);
	if (oif)
		blobmsg_add_iface(&b, "interface", oif);
	if (oif == 1)
		return;
	switch (rtm->rtm_family) {
	case AF_INET:
		if (dst) {
			blobmsg_add_ipv4(&b, "dst", dst);
			blobmsg_add_u32(&b, "netmask", rtm->rtm_dst_len);
		} else {
			blobmsg_add_string(&b, "dst", "0.0.0.0");
			blobmsg_add_u32(&b, "netmask", 0);
		}
		if (gateway)
			blobmsg_add_ipv4(&b, "gateway", gateway);
		blobmsg_add_u32(&b, "ipv4", 1);
		break;

	case AF_INET6:
		if (dst) {
			blobmsg_add_ipv6(&b, "dst", dst);
			blobmsg_add_u32(&b, "netmask", rtm->rtm_dst_len);
		} else {
			blobmsg_add_string(&b, "dst", "::");
			blobmsg_add_u32(&b, "netmask", 0);
		}
		if (gateway)
			blobmsg_add_ipv6(&b, "gateway", gateway);
		blobmsg_add_u32(&b, "ipv6", 1);
		break;

	default:
		return;
	}

	ubus_notify(&conn.ctx, &ubus_object, type, b.head, -1);
}

static int cb_rtnl_status(struct nl_msg *msg, void *arg)
{

	struct nlmsghdr *nh = nlmsg_hdr(msg);

	if (!ubus_object.has_subscribers)
		return 0;

	switch (nh->nlmsg_type) {
	case RTM_NEWLINK:
	case RTM_DELLINK:
		link_handler(nh);
		break;

	case RTM_NEWNEIGH:
		neigh_handler(nh, "neigh.new", NUD_REACHABLE);
		break;

	case RTM_DELNEIGH:
		neigh_handler(nh, "neigh.del", NUD_NOARP);
		break;

	case RTM_NEWROUTE:
		route_handler(nh, "route.new");
		break;

	case RTM_DELROUTE:
		route_handler(nh, "route.del");
		break;

	default:
		fprintf(stderr, "%s:%s[%d]%d\n", __FILE__, __func__, __LINE__, nh->nlmsg_type);
		break;
	}

	return 0;
}

void
handler_nl_status(struct uloop_fd *u, unsigned int statuss)
{
	struct status_socket *ev = container_of(u, struct status_socket, uloop);
	int err;
	socklen_t errlen = sizeof(err);

	if (!u->error) {
		nl_recvmsgs_default(ev->sock);
		return;
	}

	if (getsockopt(u->fd, SOL_SOCKET, SO_ERROR, (void *)&err, &errlen))
		goto abort;

	switch(err) {
	case ENOBUFS:
		ev->bufsize *= 2;
		if (nl_socket_set_buffer_size(ev->sock, ev->bufsize, 0))
			goto abort;
		break;

	default:
		goto abort;
	}
	u->error = false;
	return;

abort:
	uloop_fd_delete(&ev->uloop);
	return;
}

static void rtnl_enum_neigh(struct avl_tree *tree)
{
	struct ip_node *node;

	avl_for_each_element(tree, node, avl) {
		blob_buf_init(&b, 0);
		blobmsg_add_iface(&b, "interface", node->iface);
		blobmsg_add_mac(&b, "mac", node->mac);
		if (node->ip_len == 4) {
			blobmsg_add_ipv4(&b, "ip", node->ip);
			blobmsg_add_u32(&b, "ipv4", 1);
		} else {
			blobmsg_add_ipv6(&b, "ip", (uint16_t *)node->ip);
			blobmsg_add_u32(&b, "ipv6", 1);
		}
		ubus_notify(&conn.ctx, &ubus_object, "neigh.enum", b.head, -1);
	}
}

void rtnl_enum(void)
{

	rtnl_list(RTM_GETLINK);
	rtnl_list(RTM_GETROUTE);
	rtnl_enum_neigh(&ip4_tree);
	rtnl_enum_neigh(&ip6_tree);
}

int rtnl_init(void)
{
	if (!nl_status_socket(&rtnl_status, NETLINK_ROUTE, cb_rtnl_status, NULL))
		return -1;

	nl_socket_add_membership(rtnl_status.sock, RTNLGRP_LINK);
	nl_socket_add_membership(rtnl_status.sock, RTNLGRP_NEIGH);
	nl_socket_add_membership(rtnl_status.sock, RTNLGRP_IPV4_ROUTE);
	nl_socket_add_membership(rtnl_status.sock, RTNLGRP_IPV6_ROUTE);

	return 0;
}
