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

struct ubus_auto_conn conn;
static void ubus_state_handler(struct ubus_context *ctx, struct ubus_object *obj);

static struct ubus_object_type ubus_object_type =
{
	.name = "network.status"
};

struct ubus_object ubus_object = {
	.name = "network.status",
	.type = &ubus_object_type,
	.subscribe_cb = ubus_state_handler,
};

static void
ubus_connect_handler(struct ubus_context *ctx)
{
	ubus_add_object(ctx, &ubus_object);
}

static void ubus_state_handler(struct ubus_context *ctx, struct ubus_object *obj)
{
	if (!ubus_object.has_subscribers)
		return;

	rtnl_enum();
	nl80211_enum();
}

void ubus_init(void)
{
	conn.cb = ubus_connect_handler;
	ubus_auto_connect(&conn);
}

void ubus_uninit(void)
{
	ubus_auto_shutdown(&conn);
}
