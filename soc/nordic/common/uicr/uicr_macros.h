/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SOC_NORDIC_COMMON_UICR_UICR_MACROS_H_
#define SOC_NORDIC_COMMON_UICR_UICR_MACROS_H_

#include <stdint.h>
#include <nrfx.h>
#include <uicr/uicr.h>
#include <zephyr/sys/iterable_sections.h>
#include <zephyr/sys/util.h>
#include <zephyr/toolchain.h>

#ifdef __cplusplus
extern "C" {
#endif

struct uicr_periphconf_entry {
	uint32_t address;
	uint32_t value;
} __packed;

#define UICR_PERIPHCONF_ADD(_mod, _address, _value)                                                \
	STRUCT_SECTION_ITERABLE(uicr_periphconf_entry,                                             \
				_UICR_PERIPHCONF_ENTRY_NAME(_mod, __COUNTER__)) = {                \
		.address = (_address),                                                             \
		.value = (_value),                                                                 \
	}

#define _UICR_PERIPHCONF_ENTRY_NAME(_mod, _id)  __UICR_PERIPHCONF_ENTRY_NAME(_mod, _id)
#define __UICR_PERIPHCONF_ENTRY_NAME(_mod, _id) _uicr_periphconf_entry_##_mod##_id

#define UICR_SPU_PERIPH_PERM_SET(_mod, _spu, _index, _secattr, _dmasec, _lock, _ownerid)           \
	UICR_PERIPHCONF_ADD(_mod, (uint32_t) & ((NRF_SPU_Type *)(_spu))->PERIPH[(_index)].PERM,    \
			    (uint32_t)((((_ownerid) << SPU_PERIPH_PERM_OWNERID_Pos) &              \
					SPU_PERIPH_PERM_OWNERID_Msk) |                             \
				       (((_secattr) ? SPU_PERIPH_PERM_SECATTR_Secure               \
						    : SPU_PERIPH_PERM_SECATTR_NonSecure)           \
					<< SPU_PERIPH_PERM_SECATTR_Pos) |                          \
				       (((_dmasec) ? SPU_PERIPH_PERM_DMASEC_Secure                 \
						   : SPU_PERIPH_PERM_DMASEC_NonSecure)             \
					<< SPU_PERIPH_PERM_DMASEC_Pos) |                           \
				       (((_lock) ? SPU_PERIPH_PERM_LOCK_Locked                     \
						 : SPU_PERIPH_PERM_LOCK_Unlocked)                  \
					<< SPU_PERIPH_PERM_LOCK_Pos)))

#define UICR_SPU_FEATURE_SET(_mod, _spu, _index, _secattr, _lock, _ownerid)                        \
	UICR_PERIPHCONF_ADD(                                                                       \
		_mod, ((uint32_t *)&((NRF_SPU_Type *)(_spu))->FEATURE)[(_index)],                  \
		(uint32_t)((((_ownerid) << SPU_FEATURES_OWNERID_Pos) & SPU_FEATURES_OWNERID_Msk) | \
			   (((_secattr) ? SPU_FEATURES_SECATTR_Secure                              \
					: SPU_FEATURES_SECATTR_NonSecure)                          \
			    << SPU_FEATURES_SECATTR_Pos) |                                         \
			   (((_lock) ? SPU_FEATURES_LOCK_Locked : SPU_FEATURES_LOCK_Unlocked)      \
			    << SPU_FEATURES_LOCK_Pos)))

#define UICR_IPCMAP_CHANNEL_SOURCE_SET(_mod, _index, _domain, _ch, _enable)                        \
	UICR_PERIPHCONF_ADD(_mod, (uint32_t)&NRF_IPCMAP->CHANNEL[(_index)].SOURCE,                 \
			    (uint32_t)((((_domain) << IPCMAP_CHANNEL_SOURCE_DOMAIN_Pos) &          \
					IPCMAP_CHANNEL_SOURCE_DOMAIN_Msk) |                        \
				       (((_ch) << IPCMAP_CHANNEL_SOURCE_SOURCE_Pos) &              \
					IPCMAP_CHANNEL_SOURCE_SOURCE_Msk) |                        \
				       (((_enable) ? IPCMAP_CHANNEL_SOURCE_ENABLE_Enabled          \
						   : IPCMAP_CHANNEL_SOURCE_ENABLE_Disabled)        \
					<< IPCMAP_CHANNEL_SOURCE_ENABLE_Pos)))

#define UICR_IPCMAP_CHANNEL_SINK_SET(_mod, _index, _domain, _ch)                                   \
	UICR_PERIPHCONF_ADD(_mod, (uint32_t)&NRF_IPCMAP->CHANNEL[(_index)].SINK,                   \
			    (uint32_t)((((_domain) << IPCMAP_CHANNEL_SINK_DOMAIN_Pos) &            \
					IPCMAP_CHANNEL_SINK_DOMAIN_Msk) |                          \
				       (((_ch) << IPCMAP_CHANNEL_SINK_SINK_Pos) &                  \
					IPCMAP_CHANNEL_SINK_SINK_Msk)))

#define UICR_IPCMAP_CHANNEL_CFG(_mod, _index, _source_domain, _source_ch, _sink_domain, _sink_ch)  \
	UICR_IPCMAP_CHANNEL_SOURCE_SET(_mod, _index, _source_domain, _source_ch, 1);               \
	UICR_IPCMAP_CHANNEL_SINK_SET(_mod, _index, _sink_domain, _sink_ch)

#define UICR_IRQMAP_IRQ_SINK_SET(_mod, _irqnum, _processor)                                        \
	UICR_PERIPHCONF_ADD(_mod, (uint32_t)&NRF_IRQMAP->IRQ[(_irqnum)].SINK,                      \
			    (uint32_t)(((_processor) << IRQMAP_IRQ_SINK_PROCESSORID_Pos) &         \
				       IRQMAP_IRQ_SINK_PROCESSORID_Msk))

#define UICR_GPIO_PIN_CNF_CTRLSEL_SET(_mod, _gpio, _pin, _ctrlsel)                                 \
	UICR_PERIPHCONF_ADD(                                                                       \
		_mod, (uint32_t) & (NRF_GPIO_Type *)(_gpio)->PIN_CNF[(_pin)],                      \
		((GPIO_PIN_CNF_ResetValue) |                                                       \
		 (uint32_t)(((_ctrlsel) << GPIO_PIN_CNF_CTRLSEL_Pos) & GPIO_PIN_CNF_CTRLSEL_Msk)))

#define UICR_PPIB_SUBSCRIBE_SEND_ENABLE(_mod, _ppib, _ppib_ch)                                     \
	UICR_PERIPHCONF_ADD(_mod,                                                                  \
			    (uint32_t) & ((NRF_PPIB_Type *)(_ppib))->SUBSCRIBE_SEND[(_ppib_ch)],   \
			    (uint32_t)PPIB_SUBSCRIBE_SEND_EN_Msk)

#define UICR_PPIB_PUBLISH_RECEIVE_ENABLE(_mod, _ppib, _ppib_ch)                                    \
	UICR_PERIPHCONF_ADD(_mod,                                                                  \
			    (uint32_t) & ((NRF_PPIB_Type *)(_ppib))->PUBLISH_RECEIVE[(_ppib_ch)],  \
			    (uint32_t)PPIB_PUBLISH_RECEIVE_EN_Msk)

#ifdef __cplusplus
}
#endif

#endif /* SOC_NORDIC_COMMON_UICR_UICR_MACROS_H_ */
