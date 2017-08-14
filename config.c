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

struct config config = {
	.rssi_low = 40,
	.rssi_high = 150,
	.tx_rate_low = 64000,
	.tx_rate_high = 144400,
	.tx_retries = 10,
	.station_poll = 5,
	.station_status = 30,
};

enum {
	GLOBAL_ATTR_RSSI_LOW,
	GLOBAL_ATTR_RSSI_HIGH,
	GLOBAL_ATTR_TX_RATE_LOW,
	GLOBAL_ATTR_TX_RATE_HIGH,
	GLOBAL_ATTR_TX_RETRIES,
	GLOBAL_ATTR_STATION_STATUS,
	GLOBAL_ATTR_STATION_POLL,
	__GLOBAL_ATTR_MAX,
};

static const struct blobmsg_policy global_attrs[__GLOBAL_ATTR_MAX] = {
	[GLOBAL_ATTR_RSSI_LOW] = { .name = "rssi_low", .type = BLOBMSG_TYPE_INT32 },
	[GLOBAL_ATTR_RSSI_HIGH] = { .name = "rssi_high", .type = BLOBMSG_TYPE_INT32 },
	[GLOBAL_ATTR_TX_RATE_LOW] = { .name = "tx_rate_low", .type = BLOBMSG_TYPE_INT32 },
	[GLOBAL_ATTR_TX_RATE_HIGH] = { .name = "tx_rate_high", .type = BLOBMSG_TYPE_INT32 },
	[GLOBAL_ATTR_TX_RETRIES] = { .name = "tx_retries", .type = BLOBMSG_TYPE_INT32 },
	[GLOBAL_ATTR_STATION_STATUS] = { .name = "station_status", .type = BLOBMSG_TYPE_INT32 },
	[GLOBAL_ATTR_STATION_POLL] = { .name = "station_poll", .type = BLOBMSG_TYPE_INT32 },
};

const struct uci_blob_param_list global_attr_list = {
	.n_params = __GLOBAL_ATTR_MAX,
	.params = global_attrs,
};

static int config_load_global(struct uci_section *s)
{
	struct blob_attr *tb[__GLOBAL_ATTR_MAX] = { 0 };

	blob_buf_init(&b, 0);
	uci_to_blob(&b, s, &global_attr_list);
	blobmsg_parse(global_attrs, __GLOBAL_ATTR_MAX, tb, blob_data(b.head), blob_len(b.head));

	if (tb[GLOBAL_ATTR_RSSI_LOW])
		config.rssi_low = blobmsg_get_u32(tb[GLOBAL_ATTR_RSSI_LOW]);

	if (tb[GLOBAL_ATTR_RSSI_HIGH])
		config.rssi_low = blobmsg_get_u32(tb[GLOBAL_ATTR_RSSI_HIGH]);

	if (tb[GLOBAL_ATTR_TX_RATE_LOW])
		config.tx_rate_low = blobmsg_get_u32(tb[GLOBAL_ATTR_TX_RATE_LOW]);

	if (tb[GLOBAL_ATTR_TX_RATE_HIGH])
		config.tx_rate_high = blobmsg_get_u32(tb[GLOBAL_ATTR_TX_RATE_HIGH]);

	if (tb[GLOBAL_ATTR_TX_RETRIES])
		config.tx_retries = blobmsg_get_u32(tb[GLOBAL_ATTR_TX_RETRIES]);

	if (tb[GLOBAL_ATTR_STATION_STATUS])
		config.station_status = blobmsg_get_u32(tb[GLOBAL_ATTR_STATION_STATUS]);

	if (tb[GLOBAL_ATTR_STATION_POLL])
		config.station_poll = blobmsg_get_u32(tb[GLOBAL_ATTR_STATION_POLL]);

	return 0;
}

void config_load(void)
{
	struct uci_context *uci = uci_alloc_context();
	struct uci_package *status = NULL;

	if (!uci_load(uci, "ustatus", &status)) {
		struct uci_element *e;

		uci_foreach_element(&status->sections, e) {
			struct uci_section *s = uci_to_section(e);

			if (!strcmp(s->type, "global"))
				config_load_global(s);
		}
	}

	uci_unload(uci, status);
	uci_free_context(uci);
}
