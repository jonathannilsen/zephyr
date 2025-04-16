# Copyright (c) 2025 Nordic Semiconductor ASA
# SPDX-License-Identifier: Apache-2.0

zephyr_linker_sources(SECTIONS uicr.ld)

add_library(nrf_haltium_uicr_generate_library uicr.c)
target_link_libraries(nrf_haltium_uicr_generate_library zephyr_interface)

if(CONFIG_NRF_HALTIUM_UICR_PERIPHCONF)
  set(conf_header ${PROJECT_BINARY_DIR}/include/generated/uicr_periphconf_params.h)
  add_custom_command(
    OUTPUT ${conf_header}
    COMMAND
      ${PYTHON_EXECUTABLE}
      ${CMAKE_CURRENT_LIST_DIR}/gen_conf.py
      --input-elf $<TARGET_FILE:${ZEPHYR_FINAL_EXECUTABLE}>
      --conf-section uicr_periphconf_entry_area
      --output-macro-prefix GEN_UICR_PERIPHCONF_
      --output-header ${conf_header}
    DEPENDS $<TARGET_FILE:${ZEPHYR_FINAL_EXECUTABLE}>
  )
  add_custom_target(nrf_haltium_uicr_periphconf_gen_conf DEPENDS ${conf_header})
  add_dependencies(nrf_haltium_uicr_generate_library nrf_haltium_uicr_periphconf_gen_conf)
endif()

dt_nodelabel(uicr_path NODELABEL uicr REQUIRED)
dt_reg_addr(uicr_addr PATH ${uicr_path})
set(uicr_hex_out ${ZEPHYR_BINARY_DIR}/uicr.hex)
add_custom_command(
  TARGET nrf_haltium_uicr_generate_library
  POST_BUILD
  COMMAND
    ${CMAKE_OBJCOPY}
    -O ihex
    --only-section=nrf_haltium_uicr
    --change-section-address nrf_haltium_uicr=${uicr_addr}
    $<TARGET_OBJECTS:nrf_haltium_uicr_generate_library>
    ${uicr_hex_out}
  BYPRODUCTS ${uicr_hex_out}
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
