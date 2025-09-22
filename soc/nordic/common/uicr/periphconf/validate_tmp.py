


from collections import defaultdict

from .builder import (
    Address,
    ProcessorId,
    EDT,
    dt_reg_addr,
    dt_node_identifier,
    get_spu_addr_for_periph,
)


def conf_describe(conf: ConfEntry, dt: EDT | None = None) -> str | None:
    # TODO: make this a common feature
    periph_lookup = {}
    if dt is not None:
        for node in dt.nodes:
            for reg in node.regs:
                periph_lookup[reg.addr] = dt_node_identifier(node)

    match conf.reg_type_props:
        case (RegType.SPU_PERIPH_PERM, spu, slave_index):
            periph_addr = Address(conf.regptr)
            periph_addr.slave_index = slave_index
            periph_addr.address_space = 0
            periph_name = lookup_periph_name(periph_lookup, periph_addr)
            return f"{periph_name} permissions"

        case (RegType.SPU_FEATURE_BELLS_PROCESSOR_TASKS, spu, processor_raw, idx):
            processor = ProcessorId(processor_raw)
            # FIXME: this affects more than just one register
            return f"{processor.name} BELLBOARD TASK {idx}"

        case (RegType.SPU_FEATURE_BELLS_PROCESSOR_EVENTS, spu, processor_raw, idx):
            processor = ProcessorId(processor_raw)
            # FIXME: this affects more than just one register
            return f"{processor.name} BELLBOARD EVENT {idx}"

        case (RegType.SPU_FEATURE_BELLS_PROCESSOR_INTERRUPT, spu, processor_raw, idx):
            processor = ProcessorId(processor_raw)
            # FIXME: this affects more than just one register??
            return f"{processor.name} BELLBOARD INTERRUPT {idx}"

        case (RegType.SPU_FEATURE_DPPIC_CH, spu, channel):
            spu_addr = Address(conf.regptr)
            spu_addr.address_space = 0
            dppic_name = lookup_name_by_spu(spu_addr, _DPPICS)
            return f"{dppic_name} CH{channel} permissions"

        case (RegType.SPU_FEATURE_DPPIC_CHG, spu, channel_group):
            spu_addr = Address(conf.regptr)
            spu_addr.address_space = 0
            dppic_name = lookup_name_by_spu(spu_addr, _DPPICS)
            return f"{dppic_name} CHG{channel_group} permissions"

        case (RegType.SPU_FEATURE_GPIO_PIN, spu, port, pin):
            return f"P{port}.{pin} permissions"

        case (RegType.SPU_FEATURE_GPIOTE_CH, spu, gpiote_idx, channel):
            # TODO: use indes
            return f"GPIOTE CH{channel} permissions"

        case (RegType.SPU_FEATURE_GPIOTE_INTERRUPT, spu, gpiote_idx, interrupt_idx):
            return f"GPIOTE13{gpiote_idx} INT{interrupt_idx} permissions"

        case (RegType.SPU_FEATURE_GRTC_CC, spu, channel):
            return f"GRTC CC{channel} permissions"

        case (RegType.SPU_FEATURE_GRTC_CLK, spu):
            return "GRTC CLK permissions"

        case (RegType.SPU_FEATURE_GRTC_SYSCOUNTER, spu):
            return "GRTC SYSCOUNTER permissions"

        case (RegType.SPU_FEATURE_GRTC_INTERRUPT, spu, interrupt_idx):
            return f"GRTC INT{interrupt_idx} permissions"

        case (RegType.SPU_FEATURE_IPCT_CH, spu, channel):
            spu_addr = Address(conf.regptr)
            spu_addr.address_space = 0
            ipct_name = lookup_name_by_spu(spu_addr, _IPCTS)
            return f"{ipct_name} CH{channel} permissions"

        case (RegType.SPU_FEATURE_IPCT_INTERRUPT, spu, interrupt_idx):
            spu_addr = Address(conf.regptr)
            spu_addr.address_space = 0
            ipct_name = lookup_name_by_spu(spu_addr, _IPCTS)
            return f"{ipct_name} INT{interrupt_idx} permissions"

        case (RegType.IPCMAP_CHANNEL_SINK, _, channel):
            return f"IPCMAP CH{channel} sink domain"

        case (RegType.IPCMAP_CHANNEL_SOURCE, _, channel):
            return f"IPCMAP CH{channel} source domain"

        case (RegType.IRQMAP_IRQ_SINK, _, interrupt):
            ...

        case (RegType.MEMCONF_POWER_CONTROL, memconf, _):
            ...

        case (RegType.MEMCONF_POWER_RET, memconf, _):
            ...

        case (RegType.MEMCONF_POWER_RET2, memconf, _):
            ...

        case (RegType.PPIB_SUBSCRIBE_SEND, ppib, channel):
            ...

        case (RegType.PPIB_PUBLISH_RECEIVE, ppib, channel):
            ...

        case (RegType.GPIO_PIN_CNF, gpio, pin):
            ...

        case _:
            raise NotImplementedError()


def lookup_name_by_spu(spu_addr: Address | int, periphs: dict[int, str]) -> str:
    for addr, name in periphs.items():
        if get_spu_addr_for_periph(addr) == spu_addr:
            return name
    raise NotImplementedError()


# TODO: take from somewhere else
_DPPICS = {
    0x5F8E_1000: "DPPIC120",
    0x5F92_2000: "DPPIC130",
    0x5F98_1000: "DPPIC131",
    0x5F99_1000: "DPPIC132",
    0x5F9A_1000: "DPPIC133",
    0x5F9B_1000: "DPPIC134",
    0x5F9C_1000: "DPPIC135",
    0x5F9D_1000: "DPPIC136",
}

_IPCTS = {
    0x5F8D_1000: "IPCT120",
    0x5F92_1000: "IPCT130",
}


def lookup_periph_name(lut: dict[int, str], periph_addr: Address) -> str:
    if name := lut.get(int(periph_addr.as_secure())):
        return name
    if name := lut.get(int(periph_addr.as_nonsecure())):
        return name
    return f"peripheral at {fmt_addr(int(periph_addr))}"

