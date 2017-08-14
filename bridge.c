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
#include <linux/if_bridge.h>
#include <libubox/vlist.h>

#define BR_MAX_ENTRY	2048

static struct uloop_timeout bridge_timer;
static struct vlist_tree bridge_mac;

struct bridge_mac {
	struct vlist_node vlist;
	char ifname[IF_NAMESIZE];
	uint8_t addr[ETH_ALEN];
};

static void bridge_read(const char *bridge)
{
	FILE *fd;
	int i, cnt;
	struct __fdb_entry fe[BR_MAX_ENTRY];
	char path[PATH_MAX];

	snprintf(path, PATH_MAX, "/sys/class/net/%s/brforward", bridge);
	fd = fopen(path, "r");
	if (!fd)
		return;

	cnt = fread(fe, sizeof(struct __fdb_entry), BR_MAX_ENTRY, fd);
	fclose(fd);

	for (i = 0; i < cnt; i++) {
		struct bridge_mac *b = malloc(sizeof(*b));

		if (!b)
			continue;
		strncpy(b->ifname, bridge, IF_NAMESIZE);
		memcpy(b->addr, fe[i].mac_addr, ETH_ALEN);
		vlist_add(&bridge_mac, &b->vlist, (void *) b);
	}
}

static void bridge_tout(struct uloop_timeout *t)
{
	glob_t gl;
	int i;

	if (glob("/sys/class/net/*", GLOB_MARK | GLOB_ONLYDIR | GLOB_NOSORT, NULL, &gl))
		return;

        vlist_update(&bridge_mac);
	for (i = 0; i < gl.gl_pathc; i++)
		bridge_read(basename(gl.gl_pathv[i]));

	globfree(&gl);
	uloop_timeout_set(&bridge_timer, 1000);

	vlist_flush(&bridge_mac);
}

static int bridge_cmp(const void *k1, const void *k2, void *ptr)
{
	const struct bridge_mac *b1 = (const struct bridge_mac *)k1;
	const struct bridge_mac *b2 = (const struct bridge_mac *)k2;

	if (strcmp(b1->ifname, b2->ifname))
		return 1;
	return memcmp(b1->addr, b2->addr, ETH_ALEN);
}

static void bridge_update(struct vlist_tree *tree, struct vlist_node *node_new, struct vlist_node *node_old)
{
	struct bridge_mac *b1, *b2;

	b1 = container_of(node_old, struct bridge_mac, vlist);
	b2 = container_of(node_new, struct bridge_mac, vlist);

	if (!!b1 != !!b2) {
		struct bridge_mac *_b = b1 ? b1 : b2;

		blob_buf_init(&b, 0);
		blobmsg_add_string(&b, "interface", _b->ifname);
		blobmsg_add_mac(&b, "mac", _b->addr);
		ubus_notify(&conn.ctx, &ubus_object, b1 ? "bridge.mac.del" : "bridge.mac.add", b.head, -1);
	}

	if (b1)
		free(b1);
}

void bridge_init(void)
{
	bridge_timer.cb = bridge_tout;
	uloop_timeout_set(&bridge_timer, 1000);
	vlist_init(&bridge_mac, bridge_cmp, bridge_update);
}
