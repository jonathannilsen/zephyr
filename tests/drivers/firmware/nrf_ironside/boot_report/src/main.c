/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/drivers/firmware/nrf_ironside/boot_report.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(app, LOG_LEVEL_INF);

int main(void)
{
	int err;
	const struct ironside_boot_report *report;

	err = ironside_boot_report_get(&report);
	LOG_INF("err:  %d", err);
	LOG_INF("version: %d.%d.%d-%s+%d", report->ironside_se_version.major,
		report->ironside_se_version.minor, report->ironside_se_version.patch,
		report->ironside_se_version.extraversion, report->ironside_se_version.seqnum);
	LOG_INF("recovery version: %d.%d.%d-%s+%d", report->ironside_se_version.major,
		report->ironside_se_version.minor, report->ironside_se_version.patch,
		report->ironside_se_version.extraversion, report->ironside_se_version.seqnum);
	LOG_HEXDUMP_INF((void *)report->random_data, sizeof(report->random_data), "random data");

	return 0;
}
