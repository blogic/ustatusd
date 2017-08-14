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

#define _GNU_SOURCE

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/param.h>

#include <unistd.h>
#include <getopt.h>
#include <libgen.h>
#include <glob.h>

#include <linux/rtnetlink.h>
#include <linux/nl80211.h>

#include <net/if.h>

#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>

#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <libubox/blobmsg_json.h>
#include <libubox/avl.h>
#include <libubox/vlist.h>
#include <libubox/ulog.h>

#include <uci.h>
#include <uci_blob.h>

struct ip_node {
	struct avl_node avl;
	uint8_t *ip;
	uint8_t *mac;
	int ip_len;
	int iface;
};

struct status_socket {
	struct uloop_fd uloop;
	struct nl_sock *sock;
	int bufsize;
};

struct family_data {
	const char *group;
	int id;
};

struct config {
	uint16_t rssi_low;
	uint16_t rssi_high;
	uint32_t tx_rate_low;
	uint32_t tx_rate_high;
	uint32_t tx_retries;
	uint32_t station_status;
	uint32_t station_poll;
};

extern struct config config;

extern bool nl_status_socket(struct status_socket *ev, int protocol,
			    int (*cb)(struct nl_msg *msg, void *arg), void *priv);
extern void nl_handler_nl_status(struct uloop_fd *u, unsigned int statuss);
extern int genl_send_and_recv(struct status_socket *ev, struct nl_msg * msg);

extern int nl80211_init(void);
extern void nl80211_enum(void);

extern int rtnl_init(void);
extern void rtnl_enum(void);

extern struct nl_sock *create_socket(int protocol, int groups);
extern void handler_nl_status(struct uloop_fd *u, unsigned int statuss);

extern struct ubus_object ubus_object;
extern struct ubus_auto_conn conn;
extern void ubus_init(void);
extern void ubus_uninit(void);

extern struct blob_buf b;
extern void blobmsg_add_iface(struct blob_buf *bbuf, char *name, int index);
extern void blobmsg_add_iftype(struct blob_buf *bbuf, const char *name, const uint32_t iftype);
extern void blobmsg_add_ipv4(struct blob_buf *bbuf, const char *name, const uint8_t* addr);
extern void blobmsg_add_ipv6(struct blob_buf *bbuf, const char *name, const uint16_t* addr);
extern void blobmsg_add_mac(struct blob_buf *bbuf, const char *name, const uint8_t* addr);

extern void bridge_init(void);

extern void config_load(void);

extern void resmon_init(void);
extern void resmon_to_blob(struct blob_buf *b);
