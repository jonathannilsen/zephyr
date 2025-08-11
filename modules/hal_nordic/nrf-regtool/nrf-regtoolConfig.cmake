# Copyright (c) 2024 Nordic Semiconductor ASA
# SPDX-License-Identifier: Apache-2.0

get_property(version GLOBAL PROPERTY nrf_regtool_version)

foreach(component IN LISTS ${CMAKE_FIND_PACKAGE_NAME}_FIND_COMPONENTS)
  if(NOT component STREQUAL "GENERATE:UICR")
    message(FATAL_ERROR "Unrecognized package component: \"${component}\"")
  endif()

  if(CONFIG_NRF_REGTOOL_PERIPHCONF_MIGRATE)
    set(generated_hex_file ${PROJECT_BINARY_DIR}/uicr_v1.hex)
  else()
    set(generated_hex_file ${PROJECT_BINARY_DIR}/uicr.hex)
  endif()
  string(REPEAT "-v;" ${CONFIG_NRF_REGTOOL_VERBOSITY} verbosity)
  execute_process(
    COMMAND
    ${CMAKE_COMMAND} -E env PYTHONPATH=${ZEPHYR_BASE}/scripts/dts/python-devicetree/src
    ${NRF_REGTOOL} ${verbosity} uicr-compile
    --edt-pickle-file ${EDT_PICKLE}
    --product-name ${CONFIG_SOC}
    --output-file ${generated_hex_file}
    WORKING_DIRECTORY ${APPLICATION_SOURCE_DIR}
    COMMAND_ERROR_IS_FATAL ANY
  )
  message(STATUS "Generated UICR hex file: ${generated_hex_file}")

  if(CONFIG_NRF_REGTOOL_PERIPHCONF_MIGRATE)
    # TODO: explain?
    set(periphconf_migrated_c ${PROJECT_BINARY_DIR}/periphconf_migrated_from_uicr_v1.c)
    execute_process(
      COMMAND
      ${CMAKE_COMMAND} -E env PYTHONPATH=${ZEPHYR_BASE}/scripts/dts/python-devicetree/src
      ${NRF_REGTOOL} ${verbosity} uicr-migrate
      --edt-pickle-file ${EDT_PICKLE}
      --uicr-hex-file ${generated_hex_file}
      --output-periphconf-file ${periphconf_migrated_c}
      WORKING_DIRECTORY ${APPLICATION_SOURCE_DIR}
      COMMAND_ERROR_IS_FATAL ANY
    )
    zephyr_sources(${periphconf_migrated_c})
    message(STATUS "Migrated UICR hex file to PERIPHCONF: ${periphconf_migrated_c}")
  else()
    # UICR must be flashed together with the Zephyr binary.
    set(merged_hex_file ${PROJECT_BINARY_DIR}/uicr_merged.hex)
    set_property(GLOBAL APPEND PROPERTY extra_post_build_commands
      COMMAND ${PYTHON_EXECUTABLE} ${ZEPHYR_BASE}/scripts/build/mergehex.py
      -o ${merged_hex_file}
      ${generated_hex_file}
      ${PROJECT_BINARY_DIR}/${KERNEL_HEX_NAME}
    )
    set_property(TARGET runners_yaml_props_target PROPERTY hex_file ${merged_hex_file})
  endif()
endforeach()
