/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/devicetree.h>
#include <zephyr/sys/util.h>
#include <uicr/uicr.h>

#define IS_APP IS_ENABLED(CONFIG_SOC_NRF54H20_CPUAPP)
#define IS_RAD IS_ENABLED(CONFIG_SOC_NRF54H20_CPURAD)

/* Fine: shared entries should not conflict as they are identical. */
UICR_GPIO_PIN_CNF_CTRLSEL_SET(DT_REG_ADDR(DT_NODELABEL(gpio0)), 0, 0);
UICR_GPIO_PIN_CNF_CTRLSEL_SET(DT_REG_ADDR(DT_NODELABEL(gpio0)), 1, 0);

/* Error: conflict in non-lockable regs.
 * both application and radio attempt to get the ADC interrupt.
 */
UICR_IRQMAP_IRQ_SINK_SET(DT_IRQN_BY_IDX(DT_NODELABEL(adc), 0), NRF_PROCESSOR);

/* Error: conflict in lockable regs.
 * both application and radio take ownership of the same pins
 */
UICR_SPU_FEATURE_GPIO_PIN_SET(0x5f920000, DT_PROP(DT_NODELABEL(gpio0), port), 0, true, NRF_OWNER);
UICR_SPU_FEATURE_GPIO_PIN_SET(0x5f920000, DT_PROP(DT_NODELABEL(gpio0), port), 0, true, NRF_OWNER);

#if IS_APP
/* Error: configuring unimplemented DPPI channels. */
UICR_SPU_FEATURE_DPPIC_CH_SET(0x5f990000, DPPIC132_CH_NUM, true, NRF_OWNER);
UICR_SPU_FEATURE_DPPIC_CH_SET(0x5f990000, DPPIC132_CH_NUM + 1, false, NRF_OWNER);

/* Error: configuring OOB IPCMAP channel index, will be considered 'unrecognized'. */
UICR_IPCMAP_CHANNEL_CFG(16, NRF_DOMAIN_APPLICATION, 0, NRF_DOMAIN_GLOBAL, 0);

/* Error: Setting DMASEC=1 for a peripheral without DMA (TIMER120). */
UICR_SPU_PERIPH_PERM_SET(0x5f8e0000UL, 2, true, true, NRF_OWNER_APPLICATION);

#endif
/* TODO: switch ownerid on periph w/o ownerprog */
/* TODO: switch secattr on a periph w/o programmable secattr. */
/* TODO: modify locked SPU PERM register (are there any?). */
/* TODO: modify locked SPU FEATURE register (are there any?) */
/* TODO: modify bad MEMCONF region (need macros first) */

