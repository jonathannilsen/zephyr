#include <zephyr/devicetree.h>
#include <uicr/uicr.h>

#define CONFIGURE_DT_SPU_PERIPH(_node_id) \
	DT_PROP_FOREACH_ELEM


DT_FOREACH_STATUS_OKAY(nordic_nrf_spu_v2, TODO_SPU_PERIPH)

#define UICR_RESERVE_PERIPH()
