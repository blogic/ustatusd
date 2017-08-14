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

int main(int argc, char **argv)
{
	ulog_open(ULOG_STDIO | ULOG_SYSLOG, LOG_DAEMON, "ustatusd");

	config_load();
	uloop_init();
	bridge_init();
	rtnl_init();
	nl80211_init();
	ubus_init();
	resmon_init();
	uloop_run();
	uloop_done();
	ubus_uninit();

	return 0;
}
