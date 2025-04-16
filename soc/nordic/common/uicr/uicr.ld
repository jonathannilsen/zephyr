/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/linker/devicetree_regions.h>
#include <zephyr/linker/iterable_sections.h>

#if defined(CONFIG_NRF_HALTIUM_UICR_PERIPHCONF)
ITERABLE_SECTION_ROM(uicr_periphconf_entry, Z_LINK_ITERABLE_SUBALIGN)
#endif
