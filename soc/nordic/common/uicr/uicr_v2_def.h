/*
 * Copyright (c) 2025 Nordic Semiconductor ASA.
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-4-Clause
 */
#ifndef SOC_NORDIC_COMMON_UICR_UICR_V2_DEF_H__
#define SOC_NORDIC_COMMON_UICR_UICR_V2_DEF_H__

#include <nrfx.h>

#ifdef __cplusplus
extern "C" {
#endif

/* clang-format off */

/* ================================================= Struct UICRV2_APPROTECT ================================================= */
/**
  * @brief APPROTECT [UICRV2_APPROTECT] (unspecified)
  */
typedef struct {
  __IOM uint32_t  APPLICATION;                       /*!< (@ 0x00000000) APPLICATION access port protection                    */
  __IOM uint32_t  RADIOCORE;                         /*!< (@ 0x00000004) RADIOCORE access port protection                      */
  __IM  uint32_t  RESERVED;
  __IOM uint32_t  CORESIGHT;                         /*!< (@ 0x0000000C) CoreSight access port protection                      */
} NRF_UICRV2_APPROTECT_Type;                         /*!< Size = 16 (0x010)                                                    */

/* UICRV2_APPROTECT_APPLICATION: APPLICATION access port protection */
  #define UICRV2_APPROTECT_APPLICATION_ResetValue (0xBD2328A8UL) /*!< Reset value of APPLICATION register.                     */

/* PALL @Bits 0..31 : (unspecified) */
  #define UICRV2_APPROTECT_APPLICATION_PALL_Pos (0UL) /*!< Position of PALL field.                                             */
  #define UICRV2_APPROTECT_APPLICATION_PALL_Msk (0xFFFFFFFFUL << UICRV2_APPROTECT_APPLICATION_PALL_Pos) /*!< Bit mask of PALL
                                                                            field.*/
  #define UICRV2_APPROTECT_APPLICATION_PALL_Min (0x1730C77FUL) /*!< Min enumerator value of PALL field.                        */
  #define UICRV2_APPROTECT_APPLICATION_PALL_Max (0xFFFFFFFFUL) /*!< Max enumerator value of PALL field.                        */
  #define UICRV2_APPROTECT_APPLICATION_PALL_Protected (0xFFFFFFFFUL) /*!< (unspecified)                                        */


/* UICRV2_APPROTECT_RADIOCORE: RADIOCORE access port protection */
  #define UICRV2_APPROTECT_RADIOCORE_ResetValue (0xBD2328A8UL) /*!< Reset value of RADIOCORE register.                         */

/* PALL @Bits 0..31 : (unspecified) */
  #define UICRV2_APPROTECT_RADIOCORE_PALL_Pos (0UL)  /*!< Position of PALL field.                                              */
  #define UICRV2_APPROTECT_RADIOCORE_PALL_Msk (0xFFFFFFFFUL << UICRV2_APPROTECT_RADIOCORE_PALL_Pos) /*!< Bit mask of PALL
                                                                            field.*/
  #define UICRV2_APPROTECT_RADIOCORE_PALL_Min (0x1730C77FUL) /*!< Min enumerator value of PALL field.                          */
  #define UICRV2_APPROTECT_RADIOCORE_PALL_Max (0xFFFFFFFFUL) /*!< Max enumerator value of PALL field.                          */
  #define UICRV2_APPROTECT_RADIOCORE_PALL_Unprotected (0xBD2328A8UL) /*!< (unspecified)                                        */
  #define UICRV2_APPROTECT_RADIOCORE_PALL_Protected (0xFFFFFFFFUL) /*!< (unspecified)                                          */


/* UICRV2_APPROTECT_CORESIGHT: CoreSight access port protection */
  #define UICRV2_APPROTECT_CORESIGHT_ResetValue (0xBD2328A8UL) /*!< Reset value of CORESIGHT register.                         */

/* PALL @Bits 0..31 : (unspecified) */
  #define UICRV2_APPROTECT_CORESIGHT_PALL_Pos (0UL)  /*!< Position of PALL field.                                              */
  #define UICRV2_APPROTECT_CORESIGHT_PALL_Msk (0xFFFFFFFFUL << UICRV2_APPROTECT_CORESIGHT_PALL_Pos) /*!< Bit mask of PALL
                                                                            field.*/
  #define UICRV2_APPROTECT_CORESIGHT_PALL_Min (0x1730C77FUL) /*!< Min enumerator value of PALL field.                          */
  #define UICRV2_APPROTECT_CORESIGHT_PALL_Max (0xFFFFFFFFUL) /*!< Max enumerator value of PALL field.                          */
  #define UICRV2_APPROTECT_CORESIGHT_PALL_Unprotected (0xBD2328A8UL) /*!< (unspecified)                                        */
  #define UICRV2_APPROTECT_CORESIGHT_PALL_Protected (0xFFFFFFFFUL) /*!< (unspecified)                                          */



/* =============================================== Struct UICRV2_PROTECTEDMEM ================================================ */
/**
  * @brief PROTECTEDMEM [UICRV2_PROTECTEDMEM] (unspecified)
  */
typedef struct {
  __IOM uint32_t  ENABLE;                            /*!< (@ 0x00000000) Enable the Protected Memory region                    */
  __IOM uint32_t  SIZE4KB;                           /*!< (@ 0x00000004) Protected memory region size                          */
} NRF_UICRV2_PROTECTEDMEM_Type;                      /*!< Size = 8 (0x008)                                                     */

/* UICRV2_PROTECTEDMEM_ENABLE: Enable the Protected Memory region */
  #define UICRV2_PROTECTEDMEM_ENABLE_ResetValue (0xBD2328A8UL) /*!< Reset value of ENABLE register.                            */

/* ENABLE @Bits 0..31 : (unspecified) */
  #define UICRV2_PROTECTEDMEM_ENABLE_ENABLE_Pos (0UL) /*!< Position of ENABLE field.                                           */
  #define UICRV2_PROTECTEDMEM_ENABLE_ENABLE_Msk (0xFFFFFFFFUL << UICRV2_PROTECTEDMEM_ENABLE_ENABLE_Pos) /*!< Bit mask of ENABLE
                                                                            field.*/
  #define UICRV2_PROTECTEDMEM_ENABLE_ENABLE_Min (0xBD2328A8UL) /*!< Min enumerator value of ENABLE field.                      */
  #define UICRV2_PROTECTEDMEM_ENABLE_ENABLE_Max (0xFFFFFFFFUL) /*!< Max enumerator value of ENABLE field.                      */
  #define UICRV2_PROTECTEDMEM_ENABLE_ENABLE_Disabled (0xBD2328A8UL) /*!< (unspecified)                                         */
  #define UICRV2_PROTECTEDMEM_ENABLE_ENABLE_Enabled (0xFFFFFFFFUL) /*!< (unspecified)                                          */


/* UICRV2_PROTECTEDMEM_SIZE4KB: Protected memory region size */
  #define UICRV2_PROTECTEDMEM_SIZE4KB_ResetValue (0xBD2328A8UL) /*!< Reset value of SIZE4KB register.                          */

/* SIZE4KB @Bits 0..31 : (unspecified) */
  #define UICRV2_PROTECTEDMEM_SIZE4KB_SIZE4KB_Pos (0UL) /*!< Position of SIZE4KB field.                                        */
  #define UICRV2_PROTECTEDMEM_SIZE4KB_SIZE4KB_Msk (0xFFFFFFFFUL << UICRV2_PROTECTEDMEM_SIZE4KB_SIZE4KB_Pos) /*!< Bit mask of
                                                                            SIZE4KB field.*/
  #define UICRV2_PROTECTEDMEM_SIZE4KB_SIZE4KB_Min (0xBD2328A8UL) /*!< Min enumerator value of SIZE4KB field.                   */
  #define UICRV2_PROTECTEDMEM_SIZE4KB_SIZE4KB_Max (0xBD2328A8UL) /*!< Max enumerator value of SIZE4KB field.                   */
  #define UICRV2_PROTECTEDMEM_SIZE4KB_SIZE4KB_NotSet (0xBD2328A8UL) /*!< (unspecified)                                         */



/* ==================================================== Struct UICRV2_ITS ==================================================== */
/**
  * @brief ITS [UICRV2_ITS] Internal Trusted Storage
  */
typedef struct {
  __IOM uint32_t  ENABLE;                            /*!< (@ 0x00000000) Enable the Internal Trusted Storage                   */
  __IOM uint32_t  ADDRESS;                           /*!< (@ 0x00000004) Start address of the Internal Trusted storage region  */
  __IOM uint32_t  APPLICATIONSIZE;                   /*!< (@ 0x00000008) Size of the APPLICATION Internal Trusted storage
                                                                         partition*/
  __IOM uint32_t  RADIOCORESIZE;                     /*!< (@ 0x0000000C) Size of the RADIOCORE Internal Trusted storage
                                                                         partition*/
} NRF_UICRV2_ITS_Type;                               /*!< Size = 16 (0x010)                                                    */

/* UICRV2_ITS_ENABLE: Enable the Internal Trusted Storage */
  #define UICRV2_ITS_ENABLE_ResetValue (0xBD2328A8UL) /*!< Reset value of ENABLE register.                                     */

/* ENABLE @Bits 0..31 : (unspecified) */
  #define UICRV2_ITS_ENABLE_ENABLE_Pos (0UL)         /*!< Position of ENABLE field.                                            */
  #define UICRV2_ITS_ENABLE_ENABLE_Msk (0xFFFFFFFFUL << UICRV2_ITS_ENABLE_ENABLE_Pos) /*!< Bit mask of ENABLE field.           */
  #define UICRV2_ITS_ENABLE_ENABLE_Min (0xBD2328A8UL) /*!< Min enumerator value of ENABLE field.                               */
  #define UICRV2_ITS_ENABLE_ENABLE_Max (0xFFFFFFFFUL) /*!< Max enumerator value of ENABLE field.                               */
  #define UICRV2_ITS_ENABLE_ENABLE_Disabled (0xBD2328A8UL) /*!< (unspecified)                                                  */
  #define UICRV2_ITS_ENABLE_ENABLE_Enabled (0xFFFFFFFFUL) /*!< (unspecified)                                                   */


/* UICRV2_ITS_ADDRESS: Start address of the Internal Trusted storage region */
  #define UICRV2_ITS_ADDRESS_ResetValue (0xBD2328A8UL) /*!< Reset value of ADDRESS register.                                   */

/* ADDRESS @Bits 0..31 : (unspecified) */
  #define UICRV2_ITS_ADDRESS_ADDRESS_Pos (0UL)       /*!< Position of ADDRESS field.                                           */
  #define UICRV2_ITS_ADDRESS_ADDRESS_Msk (0xFFFFFFFFUL << UICRV2_ITS_ADDRESS_ADDRESS_Pos) /*!< Bit mask of ADDRESS field.      */
  #define UICRV2_ITS_ADDRESS_ADDRESS_Min (0xBD2328A8UL) /*!< Min enumerator value of ADDRESS field.                            */
  #define UICRV2_ITS_ADDRESS_ADDRESS_Max (0xBD2328A8UL) /*!< Max enumerator value of ADDRESS field.                            */
  #define UICRV2_ITS_ADDRESS_ADDRESS_NotSet (0xBD2328A8UL) /*!< (unspecified)                                                  */


/* UICRV2_ITS_APPLICATIONSIZE: Size of the APPLICATION Internal Trusted storage partition */
  #define UICRV2_ITS_APPLICATIONSIZE_ResetValue (0xBD2328A8UL) /*!< Reset value of APPLICATIONSIZE register.                   */

/* SIZE @Bits 0..31 : (unspecified) */
  #define UICRV2_ITS_APPLICATIONSIZE_SIZE_Pos (0UL)  /*!< Position of SIZE field.                                              */
  #define UICRV2_ITS_APPLICATIONSIZE_SIZE_Msk (0xFFFFFFFFUL << UICRV2_ITS_APPLICATIONSIZE_SIZE_Pos) /*!< Bit mask of SIZE
                                                                            field.*/
  #define UICRV2_ITS_APPLICATIONSIZE_SIZE_Min (0xBD2328A8UL) /*!< Min enumerator value of SIZE field.                          */
  #define UICRV2_ITS_APPLICATIONSIZE_SIZE_Max (0xBD2328A8UL) /*!< Max enumerator value of SIZE field.                          */
  #define UICRV2_ITS_APPLICATIONSIZE_SIZE_NotSet (0xBD2328A8UL) /*!< (unspecified)                                             */


/* UICRV2_ITS_RADIOCORESIZE: Size of the RADIOCORE Internal Trusted storage partition */
  #define UICRV2_ITS_RADIOCORESIZE_ResetValue (0xBD2328A8UL) /*!< Reset value of RADIOCORESIZE register.                       */

/* SIZE @Bits 0..31 : (unspecified) */
  #define UICRV2_ITS_RADIOCORESIZE_SIZE_Pos (0UL)    /*!< Position of SIZE field.                                              */
  #define UICRV2_ITS_RADIOCORESIZE_SIZE_Msk (0xFFFFFFFFUL << UICRV2_ITS_RADIOCORESIZE_SIZE_Pos) /*!< Bit mask of SIZE field.   */
  #define UICRV2_ITS_RADIOCORESIZE_SIZE_Min (0xBD2328A8UL) /*!< Min enumerator value of SIZE field.                            */
  #define UICRV2_ITS_RADIOCORESIZE_SIZE_Max (0xBD2328A8UL) /*!< Max enumerator value of SIZE field.                            */
  #define UICRV2_ITS_RADIOCORESIZE_SIZE_NotSet (0xBD2328A8UL) /*!< (unspecified)                                               */



/* ================================================ Struct UICRV2_PERIPHCONF ================================================= */
/**
  * @brief PERIPHCONF [UICRV2_PERIPHCONF] Global domain peripheral configuration
  */
typedef struct {
  __IOM uint32_t  ENABLE;                            /*!< (@ 0x00000000) Enable the global domain peripheral configuration     */
  __IOM uint32_t  ADDRESS;                           /*!< (@ 0x00000004) Start address of the array of peripheral configuration
                                                                         entries*/
  __IOM uint32_t  COUNT;                             /*!< (@ 0x00000008) Number of peripheral configuration entries            */
} NRF_UICRV2_PERIPHCONF_Type;                        /*!< Size = 12 (0x00C)                                                    */

/* UICRV2_PERIPHCONF_ENABLE: Enable the global domain peripheral configuration */
  #define UICRV2_PERIPHCONF_ENABLE_ResetValue (0xBD2328A8UL) /*!< Reset value of ENABLE register.                              */

/* ENABLE @Bits 0..31 : (unspecified) */
  #define UICRV2_PERIPHCONF_ENABLE_ENABLE_Pos (0UL)  /*!< Position of ENABLE field.                                            */
  #define UICRV2_PERIPHCONF_ENABLE_ENABLE_Msk (0xFFFFFFFFUL << UICRV2_PERIPHCONF_ENABLE_ENABLE_Pos) /*!< Bit mask of ENABLE
                                                                            field.*/
  #define UICRV2_PERIPHCONF_ENABLE_ENABLE_Min (0xBD2328A8UL) /*!< Min enumerator value of ENABLE field.                        */
  #define UICRV2_PERIPHCONF_ENABLE_ENABLE_Max (0xFFFFFFFFUL) /*!< Max enumerator value of ENABLE field.                        */
  #define UICRV2_PERIPHCONF_ENABLE_ENABLE_Disabled (0xBD2328A8UL) /*!< (unspecified)                                           */
  #define UICRV2_PERIPHCONF_ENABLE_ENABLE_Enabled (0xFFFFFFFFUL) /*!< (unspecified)                                            */


/* UICRV2_PERIPHCONF_ADDRESS: Start address of the array of peripheral configuration entries */
  #define UICRV2_PERIPHCONF_ADDRESS_ResetValue (0xBD2328A8UL) /*!< Reset value of ADDRESS register.                            */

/* ADDRESS @Bits 0..31 : (unspecified) */
  #define UICRV2_PERIPHCONF_ADDRESS_ADDRESS_Pos (0UL) /*!< Position of ADDRESS field.                                          */
  #define UICRV2_PERIPHCONF_ADDRESS_ADDRESS_Msk (0xFFFFFFFFUL << UICRV2_PERIPHCONF_ADDRESS_ADDRESS_Pos) /*!< Bit mask of ADDRESS
                                                                            field.*/
  #define UICRV2_PERIPHCONF_ADDRESS_ADDRESS_Min (0xBD2328A8UL) /*!< Min enumerator value of ADDRESS field.                     */
  #define UICRV2_PERIPHCONF_ADDRESS_ADDRESS_Max (0xBD2328A8UL) /*!< Max enumerator value of ADDRESS field.                     */
  #define UICRV2_PERIPHCONF_ADDRESS_ADDRESS_NotSet (0xBD2328A8UL) /*!< (unspecified)                                           */


/* UICRV2_PERIPHCONF_COUNT: Number of peripheral configuration entries */
  #define UICRV2_PERIPHCONF_COUNT_ResetValue (0xBD2328A8UL) /*!< Reset value of COUNT register.                                */

/* COUNT @Bits 0..31 : (unspecified) */
  #define UICRV2_PERIPHCONF_COUNT_COUNT_Pos (0UL)    /*!< Position of COUNT field.                                             */
  #define UICRV2_PERIPHCONF_COUNT_COUNT_Msk (0xFFFFFFFFUL << UICRV2_PERIPHCONF_COUNT_COUNT_Pos) /*!< Bit mask of COUNT field.  */
  #define UICRV2_PERIPHCONF_COUNT_COUNT_Min (0xBD2328A8UL) /*!< Min enumerator value of COUNT field.                           */
  #define UICRV2_PERIPHCONF_COUNT_COUNT_Max (0xBD2328A8UL) /*!< Max enumerator value of COUNT field.                           */
  #define UICRV2_PERIPHCONF_COUNT_COUNT_NotSet (0xBD2328A8UL) /*!< (unspecified)                                               */



/* ================================================== Struct UICRV2_MPCCONF ================================================== */
/**
  * @brief MPCCONF [UICRV2_MPCCONF] Global domain MPC configuration
  */
typedef struct {
  __IOM uint32_t  ENABLE;                            /*!< (@ 0x00000000) Enable the global domain MPC configuration            */
  __IOM uint32_t  ADDRESS;                           /*!< (@ 0x00000004) Start address of the array of MPC configuration
                                                                         entries*/
  __IOM uint32_t  COUNT;                             /*!< (@ 0x00000008) Number of MPC configuration entries                   */
} NRF_UICRV2_MPCCONF_Type;                           /*!< Size = 12 (0x00C)                                                    */

/* UICRV2_MPCCONF_ENABLE: Enable the global domain MPC configuration */
  #define UICRV2_MPCCONF_ENABLE_ResetValue (0xBD2328A8UL) /*!< Reset value of ENABLE register.                                 */

/* ENABLE @Bits 0..31 : (unspecified) */
  #define UICRV2_MPCCONF_ENABLE_ENABLE_Pos (0UL)     /*!< Position of ENABLE field.                                            */
  #define UICRV2_MPCCONF_ENABLE_ENABLE_Msk (0xFFFFFFFFUL << UICRV2_MPCCONF_ENABLE_ENABLE_Pos) /*!< Bit mask of ENABLE field.   */
  #define UICRV2_MPCCONF_ENABLE_ENABLE_Min (0xBD2328A8UL) /*!< Min enumerator value of ENABLE field.                           */
  #define UICRV2_MPCCONF_ENABLE_ENABLE_Max (0xFFFFFFFFUL) /*!< Max enumerator value of ENABLE field.                           */
  #define UICRV2_MPCCONF_ENABLE_ENABLE_Disabled (0xBD2328A8UL) /*!< (unspecified)                                              */
  #define UICRV2_MPCCONF_ENABLE_ENABLE_Enabled (0xFFFFFFFFUL) /*!< (unspecified)                                               */


/* UICRV2_MPCCONF_ADDRESS: Start address of the array of MPC configuration entries */
  #define UICRV2_MPCCONF_ADDRESS_ResetValue (0xBD2328A8UL) /*!< Reset value of ADDRESS register.                               */

/* ADDRESS @Bits 0..31 : (unspecified) */
  #define UICRV2_MPCCONF_ADDRESS_ADDRESS_Pos (0UL)   /*!< Position of ADDRESS field.                                           */
  #define UICRV2_MPCCONF_ADDRESS_ADDRESS_Msk (0xFFFFFFFFUL << UICRV2_MPCCONF_ADDRESS_ADDRESS_Pos) /*!< Bit mask of ADDRESS
                                                                            field.*/
  #define UICRV2_MPCCONF_ADDRESS_ADDRESS_Min (0xBD2328A8UL) /*!< Min enumerator value of ADDRESS field.                        */
  #define UICRV2_MPCCONF_ADDRESS_ADDRESS_Max (0xBD2328A8UL) /*!< Max enumerator value of ADDRESS field.                        */
  #define UICRV2_MPCCONF_ADDRESS_ADDRESS_NotSet (0xBD2328A8UL) /*!< (unspecified)                                              */


/* UICRV2_MPCCONF_COUNT: Number of MPC configuration entries */
  #define UICRV2_MPCCONF_COUNT_ResetValue (0xBD2328A8UL) /*!< Reset value of COUNT register.                                   */

/* COUNT @Bits 0..31 : (unspecified) */
  #define UICRV2_MPCCONF_COUNT_COUNT_Pos (0UL)       /*!< Position of COUNT field.                                             */
  #define UICRV2_MPCCONF_COUNT_COUNT_Msk (0xFFFFFFFFUL << UICRV2_MPCCONF_COUNT_COUNT_Pos) /*!< Bit mask of COUNT field.        */
  #define UICRV2_MPCCONF_COUNT_COUNT_Min (0xBD2328A8UL) /*!< Min enumerator value of COUNT field.                              */
  #define UICRV2_MPCCONF_COUNT_COUNT_Max (0xBD2328A8UL) /*!< Max enumerator value of COUNT field.                              */
  #define UICRV2_MPCCONF_COUNT_COUNT_NotSet (0xBD2328A8UL) /*!< (unspecified)                                                  */


/* ====================================================== Struct UICRV2 ====================================================== */
/**
  * @brief User information configuration registers
  */
  typedef struct {                                   /*!< UICRV2 Structure                                                     */
    __IOM uint32_t VERSION;                          /*!< (@ 0x00000000) Version of the UICR format                            */
    __IM uint32_t RESERVED;
    __IOM uint32_t LOCK;                             /*!< (@ 0x00000008) Lock the UICR from modification                       */
    __IM uint32_t RESERVED1;
    __IOM NRF_UICRV2_APPROTECT_Type APPROTECT;       /*!< (@ 0x00000010) (unspecified)                                         */
    __IOM uint32_t ERASEPROTECT;                     /*!< (@ 0x00000020) Erase protection                                      */
    __IOM NRF_UICRV2_PROTECTEDMEM_Type PROTECTEDMEM; /*!< (@ 0x00000024) (unspecified)                                         */
    __IM uint32_t RESERVED2[3];
    __IOM NRF_UICRV2_ITS_Type ITS;                   /*!< (@ 0x00000038) Internal Trusted Storage                              */
    __IM uint32_t RESERVED3[8];
    __IOM NRF_UICRV2_PERIPHCONF_Type PERIPHCONF;     /*!< (@ 0x00000068) Global domain peripheral configuration                */
    __IOM NRF_UICRV2_MPCCONF_Type MPCCONF;           /*!< (@ 0x00000074) Global domain MPC configuration                       */
  } NRF_UICRV2_Type;                                 /*!< Size = 128 (0x080)                                                   */

/* UICRV2_VERSION: Version of the UICR format */

/* MINOR @Bits 0..15 : Minor version */
  #define UICRV2_VERSION_MINOR_Pos (0UL)             /*!< Position of MINOR field.                                             */
  #define UICRV2_VERSION_MINOR_Msk (0xFFFFUL << UICRV2_VERSION_MINOR_Pos) /*!< Bit mask of MINOR field.                        */

/* MAJOR @Bits 16..31 : Major version */
  #define UICRV2_VERSION_MAJOR_Pos (16UL)            /*!< Position of MAJOR field.                                             */
  #define UICRV2_VERSION_MAJOR_Msk (0xFFFFUL << UICRV2_VERSION_MAJOR_Pos) /*!< Bit mask of MAJOR field.                        */


/* UICRV2_LOCK: Lock the UICR from modification */
  #define UICRV2_LOCK_ResetValue (0xBD2328A8UL)      /*!< Reset value of LOCK register.                                        */

/* PALL @Bits 0..31 : (unspecified) */
  #define UICRV2_LOCK_PALL_Pos (0UL)                 /*!< Position of PALL field.                                              */
  #define UICRV2_LOCK_PALL_Msk (0xFFFFFFFFUL << UICRV2_LOCK_PALL_Pos) /*!< Bit mask of PALL field.                             */
  #define UICRV2_LOCK_PALL_Min (0xBD2328A8UL)        /*!< Min enumerator value of PALL field.                                  */
  #define UICRV2_LOCK_PALL_Max (0xFFFFFFFFUL)        /*!< Max enumerator value of PALL field.                                  */
  #define UICRV2_LOCK_PALL_Unlocked (0xBD2328A8UL)   /*!< NVR page 0 can be written, and is not integrity checked by Nordic
                                                          IRONside SE*/
  #define UICRV2_LOCK_PALL_Locked (0xFFFFFFFFUL)     /*!< NVR page 0 is read-only, and is integrity checked by Nordic IRONside
                                                          SE on boot*/


/* UICRV2_ERASEPROTECT: Erase protection */
  #define UICRV2_ERASEPROTECT_ResetValue (0xBD2328A8UL) /*!< Reset value of ERASEPROTECT register.                             */

/* PALL @Bits 0..31 : (unspecified) */
  #define UICRV2_ERASEPROTECT_PALL_Pos (0UL)         /*!< Position of PALL field.                                              */
  #define UICRV2_ERASEPROTECT_PALL_Msk (0xFFFFFFFFUL << UICRV2_ERASEPROTECT_PALL_Pos) /*!< Bit mask of PALL field.             */
  #define UICRV2_ERASEPROTECT_PALL_Min (0xBD2328A8UL) /*!< Min enumerator value of PALL field.                                 */
  #define UICRV2_ERASEPROTECT_PALL_Max (0xFFFFFFFFUL) /*!< Max enumerator value of PALL field.                                 */
  #define UICRV2_ERASEPROTECT_PALL_Unprotected (0xBD2328A8UL) /*!< (unspecified)                                               */
  #define UICRV2_ERASEPROTECT_PALL_Protected (0xFFFFFFFFUL) /*!< (unspecified)                                                 */

/* clang-format on */


/* TODO: get everything below from the MDK */
#ifndef NRF_IPCMAP

#define NRF_IPCMAP ((NRF_IPCMAP_Type *)0x5F923000UL)

/* ================================================== Struct IPCMAP_CHANNEL
 * ================================================== */
/**
 * @brief CHANNEL [IPCMAP_CHANNEL] (unspecified)
 */
typedef struct {
	__IOM uint32_t SOURCE; /*!< (@ 0x00000000) The IPCT source configuration for the channel [n]
				  from a ICPT.*/
	__IOM uint32_t SINK; /*!< (@ 0x00000004) The IPCT sink configuration for the channel [n] to
						 another ICPT.*/
} NRF_IPCMAP_CHANNEL_Type;   /*!< Size = 8 (0x008)   */
#define IPCMAP_CHANNEL_MaxCount                                                                    \
	(16UL) /*!< Size of CHANNEL[16] array.                                           */
#define IPCMAP_CHANNEL_MaxIndex                                                                    \
	(15UL) /*!< Max index of CHANNEL[16] array.                                      */
#define IPCMAP_CHANNEL_MinIndex                                                                    \
	(0UL) /*!< Min index of CHANNEL[16] array.                                      */

/* IPCMAP_CHANNEL_SOURCE: The IPCT source configuration for the channel [n] from a ICPT. */
#define IPCMAP_CHANNEL_SOURCE_ResetValue                                                           \
	(0x00000000UL) /*!< Reset value of SOURCE register.                                 */

/* SOURCE @Bits 0..3 : Source identification for IPC mapping. */
#define IPCMAP_CHANNEL_SOURCE_SOURCE_Pos                                                           \
	(0UL) /*!< Position of SOURCE field.                                            */
#define IPCMAP_CHANNEL_SOURCE_SOURCE_Msk                                                           \
	(0xFUL << IPCMAP_CHANNEL_SOURCE_SOURCE_Pos) /*!< Bit mask of SOURCE field.          */

/* DOMAIN @Bits 8..11 : Domain identifier. */
#define IPCMAP_CHANNEL_SOURCE_DOMAIN_Pos                                                           \
	(8UL) /*!< Position of DOMAIN field.                                            */
#define IPCMAP_CHANNEL_SOURCE_DOMAIN_Msk                                                           \
	(0xFUL << IPCMAP_CHANNEL_SOURCE_DOMAIN_Pos) /*!< Bit mask of DOMAIN field.          */

/* ENABLE @Bit 31 : Channel enable. */
#define IPCMAP_CHANNEL_SOURCE_ENABLE_Pos                                                           \
	(31UL) /*!< Position of ENABLE field.                                            */
#define IPCMAP_CHANNEL_SOURCE_ENABLE_Msk                                                           \
	(0x1UL << IPCMAP_CHANNEL_SOURCE_ENABLE_Pos) /*!< Bit mask of ENABLE field.          */
#define IPCMAP_CHANNEL_SOURCE_ENABLE_Min                                                           \
	(0x0UL) /*!< Min enumerator value of ENABLE field.                                */
#define IPCMAP_CHANNEL_SOURCE_ENABLE_Max                                                           \
	(0x1UL) /*!< Max enumerator value of ENABLE field.                                */
#define IPCMAP_CHANNEL_SOURCE_ENABLE_Disabled                                                      \
	(0x0UL) /*!< Disable channel.                                                  */
#define IPCMAP_CHANNEL_SOURCE_ENABLE_Enabled                                                       \
	(0x1UL) /*!< Enable channel.                                                    */

/* IPCMAP_CHANNEL_SINK: The IPCT sink configuration for the channel [n] to another ICPT. */
#define IPCMAP_CHANNEL_SINK_ResetValue                                                             \
	(0x00000000UL) /*!< Reset value of SINK register.                                     */

/* SINK @Bits 0..3 : Sink identifiation for IPC mapping. */
#define IPCMAP_CHANNEL_SINK_SINK_Pos                                                               \
	(0UL) /*!< Position of SINK field.                                              */
#define IPCMAP_CHANNEL_SINK_SINK_Msk                                                               \
	(0xFUL << IPCMAP_CHANNEL_SINK_SINK_Pos) /*!< Bit mask of SINK field.                    */

/* DOMAIN @Bits 8..11 : Domain identifier. */
#define IPCMAP_CHANNEL_SINK_DOMAIN_Pos                                                             \
	(8UL) /*!< Position of DOMAIN field.                                            */
#define IPCMAP_CHANNEL_SINK_DOMAIN_Msk                                                             \
	(0xFUL << IPCMAP_CHANNEL_SINK_DOMAIN_Pos) /*!< Bit mask of DOMAIN field.              */

/* ====================================================== Struct IPCMAP
 * ====================================================== */
/**
 * @brief IPCMAP APB registers
 */
typedef struct { /*!< IPCMAP Structure                                                     */
	__IM uint32_t RESERVED[256];
	__IOM NRF_IPCMAP_CHANNEL_Type CHANNEL[16]; /*!< (@ 0x00000400) (unspecified) */
} NRF_IPCMAP_Type; /*!< Size = 1152 (0x480)                                                  */

#endif /* NRF_IPCMAP */

#ifndef NRF_IRQMAP

/* ==================================================== Struct IRQMAP_IRQ
 * ==================================================== */
/**
 * @brief IRQ [IRQMAP_IRQ] (unspecified)
 */
typedef struct {
	__IOM uint32_t SINK; /*!< (@ 0x00000000) The interrupt sink configuration for interrupt [n]
				to a processor.*/
} NRF_IRQMAP_IRQ_Type; /*!< Size = 4 (0x004)                                                     */
#define IRQMAP_IRQ_MaxCount                                                                        \
	(480UL) /*!< Size of IRQ[480] array.                                              */
#define IRQMAP_IRQ_MaxIndex                                                                        \
	(479UL) /*!< Max index of IRQ[480] array.                                         */
#define IRQMAP_IRQ_MinIndex                                                                        \
	(0UL) /*!< Min index of IRQ[480] array.                                         */

/* IRQMAP_IRQ_SINK: The interrupt sink configuration for interrupt [n] to a processor. */
#define IRQMAP_IRQ_SINK_ResetValue (0x00000000UL) /*!< Reset value of SINK register. */

/* PROCESSORID @Bits 8..11 : Processor identifier. */
#define IRQMAP_IRQ_SINK_PROCESSORID_Pos                                                            \
	(8UL) /*!< Position of PROCESSORID field.                                       */
#define IRQMAP_IRQ_SINK_PROCESSORID_Msk                                                            \
	(0xFUL << IRQMAP_IRQ_SINK_PROCESSORID_Pos) /*!< Bit mask of PROCESSORID field.       */


/* ====================================================== Struct IRQMAP ====================================================== */
/**
  * @brief IRQMAP APB registers
  */
  typedef struct {                                   /*!< IRQMAP Structure                                                     */
    __IM uint32_t RESERVED[256];
    __IOM NRF_IRQMAP_IRQ_Type IRQ[480];              /*!< (@ 0x00000400) (unspecified)                                         */
  } NRF_IRQMAP_Type;                                 /*!< Size = 2944 (0xB80)                                                  */

#define NRF_IRQMAP ((NRF_IRQMAP_Type *)0x5F924000UL)

#endif /* NRF_IRQMAP */

#ifndef NRF_GPIO_PIN_CNF_CTRLSEL_Pos

/* CTRLSEL @Bits 28..30 : Select which MCU/Subsystem controls this pin */
#define GPIO_PIN_CNF_CTRLSEL_Pos                                                                   \
	(28UL) /*!< Position of CTRLSEL field.                                           */
#define GPIO_PIN_CNF_CTRLSEL_Msk                                                                   \
	(0x7UL << GPIO_PIN_CNF_CTRLSEL_Pos) /*!< Bit mask of CTRLSEL field. */
#define GPIO_PIN_CNF_CTRLSEL_Min                                                                   \
	(0x0UL) /*!< Min enumerator value of CTRLSEL field.                               */
#define GPIO_PIN_CNF_CTRLSEL_Max                                                                   \
	(0x7UL) /*!< Max enumerator value of CTRLSEL field.                               */

#endif /* NRF_GPIO_PIN_CNF_CTRLSEL_Pos */

#ifdef __cplusplus
}
#endif
#endif /* SOC_NORDIC_COMMON_UICR_UICR_V2_DEF_H__ */
