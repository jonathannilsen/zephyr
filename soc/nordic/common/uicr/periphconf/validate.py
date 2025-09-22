"""
Copyright (c) 2025 Nordic Semiconductor ASA
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass
from enum import Enum, Flag
from functools import cached_property, lru_cache
from itertools import chain, groupby
from textwrap import dedent, indent
from typing import Any, NamedTuple

from pathlib import Path

try:
    from tabulate import tabulate
except ImportError:

    def tabulate(table: list, **kwargs: Any) -> str:
        # TODO
        raise NotImplementedError()


@enum.unique
class ValidationStatus(Flag):
    """Status returned on validation of a PERIPHCONF entry.
    SUCCESS indicates no errors, any other value indicates an error.

    Multiple error statuses can be set simultaneously.
    """

    SUCCESS = 0

    CONFLICTING_VALUES_NON_FATAL = enum.auto()

    CONFLICTING_VALUES_FATAL = enum.auto()

    UNIMPLEMENTED_REGISTER = enum.auto()
    UNRECOGNIZED_REGISTER = enum.auto()

    SPU_PERM_DMASEC_NOT_APPLICABLE = enum.auto()
    SPU_PERM_OWNERID_NOT_APPLICABLE = enum.auto()
    SPU_PERM_SECATTR_NOT_APPLICABLE = enum.auto()
    SPU_REGISTER_LOCKED = enum.auto()

    MEMCONF_POWER_REGION_NOT_PRESENT = enum.auto()

    def is_error(self) -> bool:
        """Check if any error status is set."""
        return self != ValidationStatus.SUCCESS

    def is_fatal_error(self) -> bool:
        """Check if any fatal error status (an error that prevents normal boot) is set."""
        fatal = self & ~ValidationStatus.CONFLICTING_VALUES_NON_FATAL
        return fatal.is_error()


class RegType(Enum):
    """Represents the types of peripheral registers that can be configured through PERIPHCONF."""

    GPIO_PIN_CNF = enum.auto()
    IPCMAP_CHANNEL_SINK = enum.auto()
    IPCMAP_CHANNEL_SOURCE = enum.auto()
    IRQMAP_IRQ_SINK = enum.auto()
    MEMCONF_POWER_CONTROL = enum.auto()
    MEMCONF_POWER_RET = enum.auto()
    MEMCONF_POWER_RET2 = enum.auto()
    PPIB_PUBLISH_RECEIVE = enum.auto()
    PPIB_SUBSCRIBE_SEND = enum.auto()
    SPU_PERIPH_PERM = enum.auto()
    SPU_FEATURE_BELLS_PROCESSOR_EVENTS = enum.auto()
    SPU_FEATURE_BELLS_PROCESSOR_INTERRUPT = enum.auto()
    SPU_FEATURE_BELLS_PROCESSOR_TASKS = enum.auto()
    SPU_FEATURE_DPPIC_CH = enum.auto()
    SPU_FEATURE_DPPIC_CHG = enum.auto()
    SPU_FEATURE_GPIO_PIN = enum.auto()
    SPU_FEATURE_GPIOTE_CH = enum.auto()
    SPU_FEATURE_GPIOTE_INTERRUPT = enum.auto()
    SPU_FEATURE_GRTC_CC = enum.auto()
    SPU_FEATURE_GRTC_CLK = enum.auto()
    SPU_FEATURE_GRTC_INTERRUPT = enum.auto()
    SPU_FEATURE_GRTC_PWMCONFIG = enum.auto()
    SPU_FEATURE_GRTC_SYSCOUNTER = enum.auto()
    SPU_FEATURE_IPCT_CH = enum.auto()
    SPU_FEATURE_IPCT_INTERRUPT = enum.auto()

    def is_spu_register(self) -> bool:
        return (
            RegType.SPU_PERIPH_PERM.value <= self.value <= RegType.SPU_FEATURE_IPCT_INTERRUPT.value
        )


# TODO: unify this with PeriphconfEntry from gen_uicr.py
@dataclass
class ConfEntry:
    regptr: int
    value: int
    info: dict | None

    @property
    def name(self) -> str:
        if self.info is None:
            return f"0x{self.regptr:09_x} (unrecognized)"
        return self.info["name"]

    @property
    def mask(self) -> int:
        if self.info is None:
            # Mask unknown, assume 0xFFFF_FFFF.
            return 0xFFFF_FFFF
        return self.info["mask"]

    @property
    def masked_value(self) -> int:
        return self.value & self.mask

    @property
    def masked_default_value(self) -> int:
        if self.info is None:
            raise ValueError()
        return self.info["default"] & self.info["mask"]

    # TODO: fix the type returned
    @cached_property
    def reg_type_props(self) -> tuple[RegType, str, str | int] | None:
        if self.info is None:
            return None

        data = None
        reg_type = None

        if self.name.startswith("SPU"):
            if data := self._parse_name("PERIPH{0}.PERM"):
                reg_type = RegType.SPU_PERIPH_PERM
            elif data := self._parse_name("FEATURE.BELLS.PROCESSOR{0}.TASKS{0}"):
                reg_type = RegType.SPU_FEATURE_BELLS_PROCESSOR_TASKS
            elif data := self._parse_name("FEATURE.BELLS.PROCESSOR{0}.EVENTS{0}"):
                reg_type = RegType.SPU_FEATURE_BELLS_PROCESSOR_EVENTS
            elif data := self._parse_name("FEATURE.BELLS.PROCESSOR{0}.INTERRUPT{0}"):
                reg_type = RegType.SPU_FEATURE_BELLS_PROCESSOR_INTERRUPT
            elif data := self._parse_name("FEATURE.DPPIC.CH{0}"):
                reg_type = RegType.SPU_FEATURE_DPPIC_CH
            elif data := self._parse_name("FEATURE.DPPIC.CHG{0}"):
                reg_type = RegType.SPU_FEATURE_DPPIC_CHG
            elif data := self._parse_name("FEATURE.GPIO{0}.PIN{0}"):
                reg_type = RegType.SPU_FEATURE_GPIO_PIN
            elif data := self._parse_name("FEATURE.GPIOTE{0}.CH{0}"):
                reg_type = RegType.SPU_FEATURE_GPIOTE_CH
            elif data := self._parse_name("FEATURE.GPIOTE{0}.INTERRUPT{0}"):
                reg_type = RegType.SPU_FEATURE_GPIOTE_INTERRUPT
            elif data := self._parse_name("FEATURE.GRTC.CC{0}"):
                reg_type = RegType.SPU_FEATURE_GRTC_CC
            elif data := self._parse_name("FEATURE.GRTC.PWMCONFIG"):
                reg_type = RegType.SPU_FEATURE_GRTC_PWMCONFIG
            elif data := self._parse_name("FEATURE.GRTC.CLK"):
                reg_type = RegType.SPU_FEATURE_GRTC_CLK
            elif data := self._parse_name("FEATURE.GRTC.SYSCOUNTER"):
                reg_type = RegType.SPU_FEATURE_GRTC_SYSCOUNTER
            elif data := self._parse_name("FEATURE.GRTC.INTERRUPT{0}"):
                reg_type = RegType.SPU_FEATURE_GRTC_INTERRUPT
            elif data := self._parse_name("FEATURE.IPCT.CH{0}"):
                reg_type = RegType.SPU_FEATURE_IPCT_CH
            elif data := self._parse_name("FEATURE.IPCT.INTERRUPT{0}"):
                reg_type = RegType.SPU_FEATURE_IPCT_INTERRUPT
        elif self.name.startswith("IPCMAP"):
            if data := self._parse_name("CHANNEL{0}.SINK"):
                reg_type = RegType.IPCMAP_CHANNEL_SINK
            elif data := self._parse_name("CHANNEL{0}.SOURCE"):
                reg_type = RegType.IPCMAP_CHANNEL_SOURCE
        elif self.name.startswith("IRQMAP"):
            if data := self._parse_name("IRQ{0}.SINK"):
                reg_type = RegType.IRQMAP_IRQ_SINK
        elif self.name.startswith("MEMCONF"):
            if data := self._parse_name("POWER{0}.CONTROL"):
                reg_type = RegType.MEMCONF_POWER_CONTROL
            elif data := self._parse_name("POWER{0}.RET"):
                reg_type = RegType.MEMCONF_POWER_RET
            elif data := self._parse_name("POWER{0}.RET2"):
                reg_type = RegType.MEMCONF_POWER_RET2
        elif self.name.startswith("PPIB"):
            if data := self._parse_name("SUBSCRIBE_SEND{0}"):
                reg_type = RegType.PPIB_SUBSCRIBE_SEND
            elif data := self._parse_name("PUBLISH_RECEIVE{0}"):
                reg_type = RegType.PPIB_PUBLISH_RECEIVE
        elif self.name.startswith("P") and (data := self._parse_name("PIN_CNF{0}")):
            reg_type = RegType.GPIO_PIN_CNF

        if data is None or reg_type is None:
            raise NotImplementedError(f"Failed to parse register name {self.name}")

        return (reg_type, data.periph, *data.array_indices)

    def _parse_name(self, path_str: str) -> PathData | None:
        """Parse a peripheral register path into parts.
        The path_str uses its own syntax for convenience, see _make_path_pattern for details.
        """
        path_pattern = _make_path_pattern(path_str)
        if match := re.fullmatch(path_pattern, self.name):
            groups = match.groups()
            return PathData(groups[0], [int(s) for s in groups[1:]])

    def conf_field_equals_default(self, field_name: str) -> bool:
        """Returns true if the value in the entry for the field equals the default value."""
        return self.get_conf_field(field_name) == self.get_default_field(field_name)

    def get_conf_field(self, field_name: str) -> int:
        """Get the value set in the entry for the field."""
        return self._get_field(field_name, self.value)

    def get_default_field(self, field_name: str) -> int:
        """Get the default value of the field."""
        if self.info is None:
            raise ValueError()
        return self._get_field(field_name, self.info["default"])

    def _get_field(self, field_name: str, reg_value: int) -> int:
        if self.info is None:
            raise ValueError()

        field_mask = self._field_info_by_name[field_name]["mask"]
        lsb_pos = (field_mask & -field_mask).bit_length() - 1
        field_value = (reg_value & field_mask) >> lsb_pos
        return field_value

    @cached_property
    def fields(self) -> str:
        # TODO
        if self.info is None:
            raise ValueError()

    @property
    def field_desc(self) -> str:
        if self.info is None:
            return f"0x{self.value:09_x} (unrecognized)"

        field_desc_parts = []
        for field in self.info["fields"]:
            # Skip printing of read-only fields
            if field["mask"] & ~self.mask == field["mask"]:
                continue
            field_content = self.get_conf_field(field["name"])
            field_desc_parts.append(f"{field['name']}={field_content}")
        return ", ".join(field_desc_parts)

    @property
    def _field_info_by_name(self) -> dict[str, dict]:
        assert self.info is not None
        return {f["name"]: f for f in self.info["fields"]}

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, ConfEntry):
            raise NotImplementedError(f"ConfEntry can not be compared with {type(other)}")
        return (self.regptr, self.value) < (other.regptr, other.value)


@lru_cache
def _make_path_pattern(path_str: str) -> str:
    r"""Create a regex that matches a peripheral register name as defined by the path_str.
    Escapes '.'-characters, replaces instances of {0} with a pattern matching an array index
    like [123], and adds a pattern matching a peripheral name at the start.

    For example:
      "PERIPH{0}.PERM"
    becomes:
      r"^([^\.]+)\.PERIPH\[([0-9]+)\]\.PERM"
    """
    path_pattern = path_str.format(r"\[([0-9]+)\]")
    path_pattern = path_pattern.replace(".", r"\.")
    path_pattern = r"^([^\.]+)\." + path_pattern + "$"
    return path_pattern


@dataclass
class PathData:
    periph: str
    array_indices: list[int]


# TODO: combine this with conf?
@dataclass
class ValidatedConf:
    index: int
    conf: ConfEntry
    status: ValidationStatus = ValidationStatus.SUCCESS


REGPTR_MASK = 0xFFFF_FFFC


def parse_periphconf(register_info: dict, periphconf_raw: bytes) -> list[ConfEntry]:
    """TODO"""
    blob = []

    for i in range(0, len(periphconf_raw), 8):
        regptr = int.from_bytes(periphconf_raw[i : i + 4], "little") & REGPTR_MASK
        # This indicates end of table
        if regptr == REGPTR_MASK:
            break

        value = int.from_bytes(periphconf_raw[i + 4 : i + 8], "little")
        info = register_info.get(str(regptr))
        blob.append(ConfEntry(regptr, value, info))

    return blob


def validate_periphconf(conf_list: list[ConfEntry]) -> tuple[ValidationStatus, list[ValidatedConf]]:
    """Validate the entries in the list of PERIPHCONF entries."""
    status_combined = ValidationStatus.SUCCESS

    indexed_confs = [ValidatedConf(i, c) for i, c in enumerate(conf_list)]
    sorted_indexed_confs = sorted(indexed_confs, key=lambda c: c.conf.regptr)
    indexed_confs_by_regptr = groupby(sorted_indexed_confs, key=lambda c: c.conf.regptr)

    for _, indexed_regptr_confs in indexed_confs_by_regptr:
        # To be able to iterate over it more than once
        indexed_regptr_confs = list(indexed_regptr_confs)

        status_combined |= check_if_conflicting_values(indexed_regptr_confs)

        for indexed_conf in indexed_regptr_confs:
            status_combined |= check_if_unrecognized_register(indexed_conf)
            status_combined |= check_if_unimplemented_register(indexed_conf)
            status_combined |= check_if_invalid_register_config(indexed_conf)

    order_restored_confs = sorted(sorted_indexed_confs, key=lambda c: c.index)

    return status_combined, order_restored_confs


def check_if_conflicting_values(indexed_regptr_confs: list[ValidatedConf]) -> ValidationStatus:
    """Check if the entries, which all target the same register, have values that conflict.
    A conflict is reported whenever the values are different, because the PERIPHCONF is designed
    so that none of the exposed registers require multiple entries.
    The function separates the conflicts into fatal and non-fatal, where fatal conflicts are those
    that lead to a boot error.
    """

    if len(indexed_regptr_confs) < 2:
        # Need at least two confs to have a conflict
        return ValidationStatus.SUCCESS

    indexed_conf_by_masked_value = {}
    for indexed_conf in indexed_regptr_confs:
        indexed_conf_by_masked_value.setdefault(indexed_conf.conf.masked_value, []).append(
            indexed_conf
        )

    if len(indexed_conf_by_masked_value) < 2:
        # All masked values are the same, so no conflict
        return ValidationStatus.SUCCESS

    # We assume that all entries have the same regtype
    reg_type = indexed_regptr_confs[0].conf.reg_type_props[0]

    if reg_type.is_spu_register():
        # SPU registers are locked upon first configuration
        status = ValidationStatus.CONFLICTING_VALUES_FATAL
    else:
        status = ValidationStatus.CONFLICTING_VALUES_NON_FATAL

    for indexed_conf in indexed_regptr_confs:
        indexed_conf.status |= status

    return status


def check_if_unrecognized_register(vconf: ValidatedConf) -> ValidationStatus:
    """Check if the entry points to an unsupported/invalid register."""

    if vconf.conf.info is not None:
        return ValidationStatus.SUCCESS

    # We assume that we have already loaded the info for the supported registers,
    # so if the entry has no info, then it is not supported.
    status = ValidationStatus.UNRECOGNIZED_REGISTER
    vconf.status |= status

    return status


def check_if_unimplemented_register(vconf: ValidatedConf) -> ValidationStatus:
    """Check if the entry points to a register that is valid but not implemented in the hardware.
    Such registers typically read as zero regardless of the value written, which causes a readback
    error when the PERIPHCONF is applied.
    """

    match vconf.conf.reg_type_props:
        case (RegType.IPCMAP_CHANNEL_SINK, *_) | (RegType.IPCMAP_CHANNEL_SOURCE, *_) | None:
            # All IPCMAP registers are implemented.
            # If type is None then the register is not recognized, so we don't report an error
            # here but through the other checks.
            return ValidationStatus.SUCCESS
        case (RegType.PPIB_PUBLISH_RECEIVE, *_) | (RegType.PPIB_SUBSCRIBE_SEND, *_):
            # These don't completely follow the rule below, so we exempt them here for now.
            return ValidationStatus.SUCCESS
        case _:
            assert vconf.conf.info is not None
            # For the registers managed through PERIPHCONF, a default value of 0
            # indicates that the register is not implemented.
            is_implemented = vconf.conf.info["default"] != 0

    if is_implemented:
        return ValidationStatus.SUCCESS

    status = ValidationStatus.UNIMPLEMENTED_REGISTER
    vconf.status |= status

    return status


def check_if_invalid_register_config(vconf: ValidatedConf) -> ValidationStatus:
    """Does register specific checks to see if the entry value is invalid for that register."""
    status_combined = ValidationStatus.SUCCESS
    conf = vconf.conf

    match conf.reg_type_props:
        case (RegType.SPU_PERIPH_PERM, *_):
            fixed_dmasec = conf.get_default_field("DMA") in (
                SpuPermDma.NO_DMA,
                SpuPermDma.NO_SEPARATE_ATTRIBUTE,
            )
            if fixed_dmasec and not conf.conf_field_equals_default("DMASEC"):
                status = ValidationStatus.SPU_PERM_DMASEC_NOT_APPLICABLE
                vconf.status |= status
                status_combined |= status

            fixed_owner = not conf.get_default_field("OWNERPROG")
            if fixed_owner and not conf.conf_field_equals_default("OWNERID"):
                status = ValidationStatus.SPU_PERM_OWNERID_NOT_APPLICABLE
                vconf.status |= status
                status_combined |= status

            fixed_secattr = (
                conf.get_default_field("SECUREMAPPING") != SpuPermSecuremapping.USER_SELECTABLE
            )
            if fixed_secattr and not conf.conf_field_equals_default("SECATTR"):
                status = ValidationStatus.SPU_PERM_SECATTR_NOT_APPLICABLE
                vconf.status |= status
                status_combined |= status

            is_locked = bool(conf.get_default_field("LOCK"))
            if is_locked and conf.masked_value != conf.masked_default_value:
                status = ValidationStatus.SPU_REGISTER_LOCKED
                vconf.status |= status
                status_combined |= status

        case (
            (RegType.SPU_FEATURE_BELLS_PROCESSOR_TASKS, *_)
            | (RegType.SPU_FEATURE_BELLS_PROCESSOR_EVENTS, *_)
            | (RegType.SPU_FEATURE_BELLS_PROCESSOR_INTERRUPT, *_)
            | (RegType.SPU_FEATURE_DPPIC_CH, *_)
            | (RegType.SPU_FEATURE_DPPIC_CHG, *_)
            | (RegType.SPU_FEATURE_GPIO_PIN, *_)
            | (RegType.SPU_FEATURE_GPIOTE_CH, *_)
            | (RegType.SPU_FEATURE_GPIOTE_INTERRUPT, *_)
            | (RegType.SPU_FEATURE_GRTC_CC, *_)
            | (RegType.SPU_FEATURE_GRTC_CLK, *_)
            | (RegType.SPU_FEATURE_GRTC_SYSCOUNTER, *_)
            | (RegType.SPU_FEATURE_GRTC_INTERRUPT, *_)
            | (RegType.SPU_FEATURE_IPCT_CH, *_)
            | (RegType.SPU_FEATURE_IPCT_INTERRUPT, *_)
        ):
            is_locked = bool(conf.get_default_field("LOCK"))
            if is_locked and conf.masked_value != conf.masked_default_value:
                status = ValidationStatus.SPU_REGISTER_LOCKED
                vconf.status |= status
                status_combined |= status

        case (
            (RegType.MEMCONF_POWER_CONTROL, *_)
            | (RegType.MEMCONF_POWER_RET, *_)
            | (RegType.MEMCONF_POWER_RET2, *_)
        ):
            # For these registers the default state should have all user programmable bits set to 1.
            # Therefore, user programmable bits that are zero in the default value can be considered
            # not implemented/programmable.
            conf_bad_bits = (conf.masked_value ^ conf.masked_default_value) & conf.mask
            if conf_bad_bits:
                status = ValidationStatus.MEMCONF_POWER_REGION_NOT_PRESENT
                vconf.status |= status
                status_combined |= status

    return status_combined


class SpuPermSecuremapping(int, Enum):
    """Enum values used in the SPU PERIPH[n].PERM SECUREMAPPING field"""

    NONSECURE = 0
    SECURE = 1
    USER_SELECTABLE = 2
    SPLIT = 3


class SpuPermDma(int, Enum):
    """Enum values used in the SPU PERIPH[n].PERM DMA field"""

    NO_DMA = 0
    NO_SEPARATE_ATTRIBUTE = 1
    SEPARATE_ATTRIBUTE = 2


def render_periphconf_table(entries: list[ValidatedConf], style: str = "regs") -> str:
    """Render validated PERIPHCONF entries in table form."""
    table = []
    for entry in entries:
        error_char = "X" if entry.status != ValidationStatus.SUCCESS else ""
        error_desc = ", ".join(str(s.name) for s in entry.status)
        index = str(entry.index)
        if style == "regs":
            reg_name = entry.conf.name
            field_desc = entry.conf.field_desc
        else:
            reg_name = fmt_addr(entry.conf.regptr)
            field_desc = fmt_addr(entry.conf.value)
        table.append([error_char, index, reg_name, field_desc, error_desc])

    table_str = tabulate(
        table,
        headers=["E", "Index", "Register", "Fields", "Error"],
        tablefmt="simple",
    )

    return table_str


def render_validation_status(status: ValidationStatus) -> str:
    """Render descriptions of each status flag in the combined status."""
    lines = []

    for present_status in status:
        lines.append(f"{present_status.name}:")
        status_description = VALIDATION_STATUS_DESCRIPTIONS[present_status]
        lines.append(indent(status_description, "  "))
        lines.append("")

    return "\n".join(lines)


def fmt_addr(addr: int) -> str:
    """Format an address in a readable way."""
    return f"0x{addr:09_x}"


VALIDATION_STATUS_DESCRIPTIONS = {
    # This is here for completeness
    ValidationStatus.SUCCESS: "No errors",
    ValidationStatus.CONFLICTING_VALUES_NON_FATAL: dedent(
        """\
        Two or more PERIPHCONF entries target the same register but have different values.
        This is likely caused by conflicting configurations in the device tree or source code.
        The targeted register is not lockable, therefore the latest entry in the table will
        take precedence and overwrite previous entries."""
    ),
    ValidationStatus.CONFLICTING_VALUES_FATAL: dedent(
        """\
        Two or more PERIPHCONF entries target the same register but have different values.
        This is likely caused by conflicting configurations in the device tree or source code.
        The targeted register is lockable, therefore the second entry will cause a read-back
        error, preventing the the device from booting normally."""
    ),
    ValidationStatus.UNIMPLEMENTED_REGISTER: dedent(
        """\
        The PERIPHCONF entry targets a register that is not implemented in the hardware.
        This typically means that the hardware feature configured by the entry, e.g. GPIO pin or
        DPPI channel, does not exist. The entry will cause a read-back error, preventing the
        device from booting normally."""
    ),
    ValidationStatus.UNRECOGNIZED_REGISTER: dedent(
        """\
        The PERIPHCONF entry register address is not recognized. Therefore the entry will cause
        a permission error, preventing the the device from booting normally."""
    ),
    ValidationStatus.SPU_PERM_DMASEC_NOT_APPLICABLE: dedent(
        """\
        The PERIPHCONF entry targets a SPU PERIPH[n].PERM register that does not accept
        the DMA security (DMASEC) setting set by the entry. This is either because the peripheral
        governed by this PERM register does not have DMA, or that the DMA security has a fixed
        value. This entry will cause a read-back error, preventing the device from booting
        normally."""
    ),
    ValidationStatus.SPU_PERM_OWNERID_NOT_APPLICABLE: dedent(
        """\
        The PERIPHCONF entry targets a SPU PERIPH[n].PERM register that does not accept
        the Owner ID (OWNERID) setting set by the entry. This is because the peripheral
        governed by this PERM register does not have programmable ownership.
        This entry will cause a read-back error, preventing the device from booting normally."""
    ),
    ValidationStatus.SPU_PERM_SECATTR_NOT_APPLICABLE: dedent(
        """\
        The PERIPHCONF entry targets a SPU PERIPH[n].PERM register that does not accept
        the security (SECATTR) setting set by the entry. This is because the peripheral
        governed by this PERM register does not have programmable security.
        This entry will cause a read-back error, preventing the device from booting normally."""
    ),
    ValidationStatus.SPU_REGISTER_LOCKED: dedent(
        """\
        The PERIPHCONF entry targets a SPU register that is by default locked in the hardware,
        and contains a different value than the default value. This entry will cause a read-back
        error, preventing the device from booting normally."""
    ),
    ValidationStatus.MEMCONF_POWER_REGION_NOT_PRESENT: dedent(
        """\
        The PERIPHCONF entry targets a MEMCONF POWER register, and has enabled a memory region
        index that is not present in the hardware. This entry will cause a read-back
        error, preventing the device from booting normally."""
    ),
}
