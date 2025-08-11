# Copyright (c) 2024 Nordic Semiconductor ASA
# SPDX-License-Identifier: Apache-2.0

function(soc_nordic_haltium_generate_uicr_if_enabled)
  cmake_parse_arguments(GEN_UICR  "" "" "IMAGES" ${ARGN})

  if(SB_CONFIG_NRF_HALTIUM_GENERATE_UICR)
    set(optional_byproducts)

    set(periphconf_elfs)
    set(periphconf_images)
    set(periphconf_args)

    if(SB_CONFIG_NRF_HALTIUM_UICR_PERIPHCONF)
      set(out_periphconf_hex ${APPLICATION_BINARY_DIR}/periphconf.hex)
      set(in_periphconf_elfs)
      foreach(image ${GEN_UICR_IMAGES})
        sysbuild_get(${image}_periphconf IMAGE ${image} VAR CONFIG_NRF_PERIPHCONF_SECTION KCONFIG)
        if(${image}_periphconf)
          sysbuild_get(${image}_elf_name IMAGE ${image} VAR BYPRODUCT_KERNEL_ELF_NAME CACHE)
          list(APPEND periphconf_elfs ${${image}_elf_name})
          list(APPEND periphconf_images ${image})
        endif()
      endforeach()
      list(TRANSFORM periphconf_elfs
        PREPEND "--in-periphconf-elf;"
        OUTPUT_VARIABLE periphconf_args
      )
      list(APPEND periphconf_args --out-periphconf-hex ${out_periphconf_hex})
      list(APPEND optional_byproducts ${out_periphconf_hex})
    endif()

    # TODO: is this OK?
    ExternalProject_Get_Property(${DEFAULT_IMAGE} BINARY_DIR)
    set(default_image_edt_pickle ${BINARY_DIR}/zephyr/edt.pickle)

    set(uicr_hex_file ${APPLICATION_BINARY_DIR}/uicr.hex)
    add_custom_command(
      OUTPUT ${uicr_hex_file} ${optional_byproducts}
      COMMAND ${CMAKE_COMMAND} -E env PYTHONPATH=${ZEPHYR_BASE}/scripts/dts/python-devicetree/src
      ${PYTHON_EXECUTABLE} ${ZEPHYR_BASE}/soc/nordic/common/uicr/gen_uicr.py
      --in-config ${DOTCONFIG}
      --in-edt-pickle ${default_image_edt_pickle}
      ${periphconf_args}
      --out-uicr-hex ${uicr_hex_file}

      DEPENDS ${periphconf_images} ${periphconf_elfs}
      COMMENT "Generating UICR artifacts"
    )
    add_custom_target(gen_uicr ALL DEPENDS ${uicr_hex_file} ${optional_byproducts})
  endif()
endfunction()

if(SB_CONFIG_VPR_LAUNCHER)
  set(launcher_core "cpuapp")
  string(REPLACE "/" ";" launcher_quals ${BOARD_QUALIFIERS})
  list(LENGTH launcher_quals launcher_quals_len)
  list(GET launcher_quals 1 launcher_soc)
  list(GET launcher_quals 2 launcher_vpr)

  string(REPLACE "cpu" "" launcher_vpr ${launcher_vpr})

  if(launcher_quals_len EQUAL 4)
    list(GET launcher_quals 3 launcher_variant)
    set(launcher_vpr ${launcher_vpr}-${launcher_variant})
  endif()

  string(CONCAT launcher_board ${BOARD} "/" ${launcher_soc} "/" ${launcher_core})

  set(image "vpr_launcher")

  ExternalZephyrProject_Add(
    APPLICATION ${image}
    SOURCE_DIR ${ZEPHYR_BASE}/samples/basic/minimal
    BOARD ${launcher_board}
  )

  string(CONCAT launcher_snippet "nordic-" ${launcher_vpr})

  sysbuild_cache_set(VAR ${image}_SNIPPET APPEND REMOVE_DUPLICATES ${launcher_snippet})
endif()
