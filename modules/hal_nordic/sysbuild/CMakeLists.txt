# Copyright (c) 2025 Nordic Semiconductor ASA
# SPDX-License-Identifier: Apache-2.0

function(${SYSBUILD_CURRENT_MODULE_NAME}_post_cmake)
  cmake_parse_arguments(POST_CMAKE "" "" "IMAGES" ${ARGN})
  soc_nordic_haltium_generate_uicr_if_enabled(IMAGES ${POST_CMAKE_IMAGES})
endfunction(${SYSBUILD_CURRENT_MODULE_NAME}_post_cmake)
