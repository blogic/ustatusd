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

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/reboot.h>

#include <unistd.h>
#include <getopt.h>
#include <libgen.h>

#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <libubox/blobmsg_json.h>

static struct ubus_auto_conn conn;
static struct ubus_subscriber subscriber;
static int verbose = 1;

static const struct watch_list {
	const char *path;
	int wildcard;
} watch_list[] = {
	{
		.path = "service",
	}, {
		.path = "dnsmasq",
	}, {
		.path = "network.interface",
	}, {
		.path = "network.status",
	}, {
		.path = "hostapd.wlan",
		.wildcard = 1,
	},
};

enum {
	EVENT_ID,
	EVENT_PATH,
	__EVENT_MAX
};

static const struct blobmsg_policy status_policy[__EVENT_MAX] = {
	[EVENT_ID] = { .name = "id", .type = BLOBMSG_TYPE_INT32 },
	[EVENT_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
};

static int
watch_match(const char *path)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(watch_list); i++) {
		int len = strlen(watch_list[i].path);

		if (watch_list[i].wildcard && strncmp(path, watch_list[i].path, len))
			continue;
		if (!watch_list[i].wildcard && strcmp(path, watch_list[i].path))
			continue;
		return 0;
	}
	return -1;
}

static int
watch_notify_cb(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	if (verbose) {
		char *str;

		str = blobmsg_format_json(msg, true);
		fprintf(stdout, "Received ubus notify '%s': %s\n", method, str);
		free(str);
	}

	return 0;
}

static void
handle_status(struct ubus_context *ctx,  struct ubus_event_handler *ev,
	     const char *type, struct blob_attr *msg)
{
	struct blob_attr *tb[__EVENT_MAX];
	const char *path;
	uint32_t id;

	if (strcmp("ubus.object.add", type))
		return;

	if (verbose) {
		char *str;

		str = blobmsg_format_json(msg, true);
		fprintf(stdout, "Received ubus notify '%s': %s\n", type, str);
		free(str);
	}

	blobmsg_parse(status_policy, __EVENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[EVENT_ID] || !tb[EVENT_PATH])
		return;

	path = blobmsg_get_string(tb[EVENT_PATH]);
	id = blobmsg_get_u32(tb[EVENT_ID]);

	if (!watch_match(path) && !ubus_subscribe(ctx, &subscriber, id))
		fprintf(stdout, "Subscribe to %s (%u)\n", path, id);
}

static struct ubus_event_handler status_handler = { .cb = handle_status };

static void
receive_list_result(struct ubus_context *ctx, struct ubus_object_data *obj,
		    void *priv)
{
	char *path = strdup(obj->path);

	if (!watch_match(path) && !ubus_subscribe(ctx, &subscriber, obj->id))
		fprintf(stdout, "Subscribe to %s (%u)\n", path, obj->id);
	free(path);
}

static void
ubus_connect_handler(struct ubus_context *ctx)
{
	fprintf(stderr, "connected to ubus\n");

	ubus_register_event_handler(ctx, &status_handler, "ubus.object.add");
	ubus_register_event_handler(ctx, &status_handler, "ubus.object.remove");

	subscriber.cb = watch_notify_cb;
	if (ubus_register_subscriber(ctx, &subscriber))
		fprintf(stderr, "failed to register ubus subscriber\n");

	ubus_lookup(ctx, NULL, receive_list_result, NULL);
}

int
main(int argc, char **argv)
{
	uloop_init();
	conn.cb = ubus_connect_handler;
	ubus_auto_connect(&conn);
	uloop_run();
	uloop_done();
	ubus_auto_shutdown(&conn);

	return 0;
}
