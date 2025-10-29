/*
 * Copyright (c) 2012-2014 Wind River Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <hal/nrf_gpio.h>
#include <stdio.h>
#include <zephyr/kernel.h>

static int disable_gpio_retention(void)
{
	NRF_GPIO_Type *gpio_regs[GPIO_COUNT] = GPIO_REG_LIST;

	for (int i = 0; i < NRFX_ARRAY_SIZE(gpio_regs); i++) {
		nrf_gpio_port_retain_set(gpio_regs[i], 0);
	}

	return 0;
}

SYS_INIT(disable_gpio_retention, EARLY, 0);

int main(void)
{
	printf("Hello World! %s\n", CONFIG_BOARD_TARGET);

	return 0;
}
