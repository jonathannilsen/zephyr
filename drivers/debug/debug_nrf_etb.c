/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/cache.h>
#include <zephyr/shell/shell.h>
#include <zephyr/logging/log.h>
#include <zephyr/logging/log_output.h>
#include <zephyr/logging/log_frontend_stmesp.h>
#include <zephyr/logging/log_frontend_stmesp_demux.h>
#include <zephyr/debug/coresight/cs_trace_defmt.h>
#include <zephyr/debug/mipi_stp_decoder.h>
#include <zephyr/linker/devicetree_regions.h>
#include <zephyr/drivers/serial/uart_async_rx.h>
#include <zephyr/sys/printk.h>
#include <dmm.h>
#include <stdio.h>
#include "coresight_arm.h"
LOG_MODULE_REGISTER(cs_etb, LOG_LEVEL_ERR);

#define UART_NODE DT_CHOSEN(zephyr_console)

#define ETB_DUMP_PERIOD_MS K_MSEC(1000)

/* Counts number of new messages completed in the current formatter frame decoding. */
static uint32_t new_msg_cnt;

static bool volatile use_async_uart;

static struct k_sem uart_sem;
static const struct device *uart_dev = DEVICE_DT_GET(UART_NODE);

K_KERNEL_STACK_DEFINE(etb_stack, KB(16));
static struct k_thread etb_dump_thread;

static uint32_t etb_decode_buffer[KB(16) / sizeof(uint32_t)];

/* Domain details and prefixes. */
static const uint16_t stm_m_id[] = {0x21, 0x22, 0x23, 0x2c, 0x2d, 0x2e, 0x24, 0x80};
static uint32_t source_id_buf[ARRAY_SIZE(stm_m_id) * 8];
static const char *const stm_m_name[] = {"sec", "app", "rad", "sys", "flpr", "ppr", "mod", "hw"};
static const char *const hw_evts[] = {
	"CTI211_0",    /* 0 CTI211 triger out 1 */
	"CTI211_1",    /* 1 CTI211 triger out 1 inverted */
	"CTI211_2",    /* 2 CTI211 triger out 2 */
	"CTI211_3",    /* 3 CTI211 triger out 2 inverted*/
	"Sec up",      /* 4 Secure Domain up */
	"Sec down",    /* 5 Secure Domain down */
	"App up",      /* 6 Application Domain up */
	"App down",    /* 7 Application Domain down */
	"Rad up",      /* 8 Radio Domain up */
	"Rad down",    /* 9 Radio Domain down */
	"Radf up",     /* 10 Radio fast up */
	"Radf down",   /* 11 Radio fast down */
	NULL,          /* Reserved */
	NULL,          /* Reserved */
	NULL,          /* Reserved */
	NULL,          /* Reserved */
	NULL,          /* Reserved */
	NULL,          /* Reserved */
	NULL,          /* Reserved */
	NULL,          /* Reserved */
	NULL,          /* Reserved */
	NULL,          /* Reserved */
	NULL,          /* Reserved */
	NULL,          /* Reserved */
	NULL,          /* Reserved */
	NULL,          /* Reserved */
	"GD LL up",    /* 26 Global domain low leakage up */
	"GD LL down",  /* 27 Global domain low leakage down */
	"GD1 HS up",   /* 28 Global domain high speed 1 up */
	"GD1 HS up",   /* 29 Global domain high speed 1 up */
	"GD0 HS down", /* 30 Global domain high speed 0 down */
	"GD0 HS down", /* 31 Global domain high speed 0 down */
};

static int log_output_func(uint8_t *buf, size_t size, void *ctx)
{
	for (int i = 0; i < size; i++) {
		uart_poll_out(uart_dev, buf[i]);
	}

	return size;
}

static uint8_t log_output_buf[4096];
LOG_OUTPUT_DEFINE(log_output, log_output_func, log_output_buf, sizeof(log_output_buf));

/** @brief Process a log message. */
static void log_message_process(struct log_frontend_stmesp_demux_log *packet)
{
	uint32_t flags = LOG_OUTPUT_FLAG_COLORS | LOG_OUTPUT_FLAG_LEVEL |
			 LOG_OUTPUT_FLAG_TIMESTAMP | LOG_OUTPUT_FLAG_FORMAT_TIMESTAMP;
	uint64_t ts = packet->timestamp;
	uint8_t level = packet->hdr.level;
	uint16_t plen = packet->hdr.package_len;
	const char *dname = stm_m_name[packet->hdr.major];
	const uint8_t *package = packet->data;
	const char *sname = &packet->data[plen];
	size_t sname_len = strlen(sname) + 1;
	uint16_t dlen = packet->hdr.total_len - (plen + sname_len);
	uint8_t *data = dlen ? &packet->data[plen + sname_len] : NULL;

	log_output_process(&log_output, ts, dname, sname, NULL, level, package, data, dlen, flags);
}

/** @brief Process a trace point message. */
static void trace_point_process(struct log_frontend_stmesp_demux_trace_point *packet)
{
	static const uint32_t flags = LOG_OUTPUT_FLAG_TIMESTAMP | LOG_OUTPUT_FLAG_FORMAT_TIMESTAMP |
				      LOG_OUTPUT_FLAG_LEVEL;
	static const char *tp = "%d";
	static const char *tp_d32 = "%d %08x";
	const char *dname = stm_m_name[packet->major];
	static const char *sname = "tp";
	const char *lptr;

	if (packet->id >= CONFIG_LOG_FRONTEND_STMESP_TURBO_LOG_BASE) {
		lptr = log_frontend_stmesp_demux_str_get(
			packet->major, packet->id - CONFIG_LOG_FRONTEND_STMESP_TURBO_LOG_BASE);
		uint8_t level = (uint8_t)(lptr[0]) - (uint8_t)'0';
		const char *ptr = lptr + 1;
		static const union cbprintf_package_hdr desc0 = {
			.desc = {.len = 2 /* hdr + fmt */}};
		static const union cbprintf_package_hdr desc1 = {
			.desc = {.len = 3 /* hdr + fmt + data */}};
		uint32_t tp_log[] = {packet->has_data ? (uint32_t)desc1.raw : (uint32_t)desc0.raw,
				     (uint32_t)ptr, packet->data};
		const char *source =
			log_frontend_stmesp_demux_sname_get(packet->major, packet->source_id);

		log_output_process(&log_output, packet->timestamp, dname, source, NULL, level,
				   (const uint8_t *)tp_log, NULL, 0, flags);
		return;
	} else if (packet->has_data) {
		uint32_t id = (uint32_t)packet->id - CONFIG_LOG_FRONTEND_STMESP_TP_CHAN_BASE;
		static const union cbprintf_package_hdr desc = {
			.desc = {.len = 4 /* hdr + fmt + id + data */}};
		uint32_t tp_d32_p[] = {(uint32_t)desc.raw, (uint32_t)tp_d32, id, packet->data};

		log_output_process(&log_output, packet->timestamp, dname, sname, NULL, 1,
				   (const uint8_t *)tp_d32_p, NULL, 0, flags);
		return;
	}

	static const union cbprintf_package_hdr desc = {.desc = {.len = 3 /* hdr + fmt + id */}};
	uint32_t tp_p[] = {(uint32_t)desc.raw, (uint32_t)tp, packet->id};

	log_output_process(&log_output, packet->timestamp, dname, sname, NULL, 1,
			   (const uint8_t *)tp_p, NULL, 0, flags);
}

/** @brief Process a HW event message. */
static void hw_event_process(struct log_frontend_stmesp_demux_hw_event *packet)
{
	static const uint32_t flags = LOG_OUTPUT_FLAG_TIMESTAMP | LOG_OUTPUT_FLAG_FORMAT_TIMESTAMP;
	static const char *tp = "%s";
	static const char *dname = "hw";
	static const char *sname = "event";
	const char *evt_name = packet->evt < ARRAY_SIZE(hw_evts) ? hw_evts[packet->evt] : "invalid";
	static const union cbprintf_package_hdr desc = {.desc = {.len = 3 /* hdr + fmt + id */}};
	uint32_t tp_p[] = {(uint32_t)desc.raw, (uint32_t)tp, (uint32_t)evt_name};

	log_output_process(&log_output, packet->timestamp, dname, sname, NULL, 1,
			   (const uint8_t *)tp_p, NULL, 0, flags);
}

static void message_process(union log_frontend_stmesp_demux_packet packet)
{
	switch (packet.generic_packet->type) {
	case LOG_FRONTEND_STMESP_DEMUX_TYPE_TRACE_POINT:
		// trace_point_process(packet.trace_point);
		break;
	case LOG_FRONTEND_STMESP_DEMUX_TYPE_HW_EVENT:
		hw_event_process(packet.hw_event);
		break;
	default:
		// log_message_process(packet.log);
		break;
	}
}

/** @brief Function called when potential STPv2 stream data drop is detected.
 *
 * When that occurs all active messages in the demultiplexer are marked as invalid and
 * stp_decoder is switching to re-synchronization mode where data is decoded in
 * search for ASYNC opcode.
 */
static void sync_loss(void)
{
	mipi_stp_decoder_sync_loss();
	log_frontend_stmesp_demux_reset();
}

/** @brief Indicate that STPv2 decoder is synchronized.
 *
 * That occurs when ASYNC opcode is found.
 */
static void on_resync(void)
{
}

static void process_messages(void)
{
	static union log_frontend_stmesp_demux_packet curr_msg;

	/* Process any new messages. curr_msg remains the same if panic
	 * interrupts currently ongoing processing (curr_msg is not NULL then).
	 * In such a case it is processed once again, which may lead to
	 * a partial repetition of that message on the output.
	 */
	while (new_msg_cnt || curr_msg.generic_packet) {
		if (!curr_msg.generic_packet) {
			curr_msg = log_frontend_stmesp_demux_claim();
		}
		if (curr_msg.generic_packet) {
			message_process(curr_msg);
			log_frontend_stmesp_demux_free(curr_msg);
			curr_msg.generic_packet = NULL;
		} else {
			break;
		}
	}
	new_msg_cnt = 0;
}

static void decoder_cb(enum mipi_stp_decoder_ctrl_type type, union mipi_stp_decoder_data data,
		       uint64_t *ts, bool marked)
{
	int rv = 0;

	switch (type) {
	case STP_DECODER_ASYNC:
		on_resync();
		break;
	case STP_DECODER_MAJOR:
		log_frontend_stmesp_demux_major(data.id);
		break;
	case STP_DECODER_CHANNEL:
		log_frontend_stmesp_demux_channel(data.id);
		break;
	case STP_DATA8:
		if (marked) {
			rv = log_frontend_stmesp_demux_packet_start((uint32_t *)&data.data, ts);
			new_msg_cnt += rv;
		} else {
			log_frontend_stmesp_demux_data((char *)&data.data, 1);
		}
		break;
	case STP_DATA16:
		if (marked) {
			if (ts) {
				rv = log_frontend_stmesp_demux_log0((uint16_t)data.data, ts);
				new_msg_cnt += rv;
			} else {
				log_frontend_stmesp_demux_source_id((uint16_t)data.data);
			}
		} else {
			log_frontend_stmesp_demux_data((char *)&data.data, 2);
		}
		break;
	case STP_DATA32:
		if (marked) {
			rv = log_frontend_stmesp_demux_packet_start((uint32_t *)&data.data, ts);
			new_msg_cnt += rv;
		} else {
			log_frontend_stmesp_demux_data((char *)&data.data, 4);
			if (ts) {
				log_frontend_stmesp_demux_timestamp(*ts);
			}
		}
		break;
	case STP_DATA64:
		log_frontend_stmesp_demux_data((char *)&data.data, 8);
		break;
	case STP_DECODER_FLAG:
		if (ts) {
			log_frontend_stmesp_demux_packet_start(NULL, ts);
		} else {
			log_frontend_stmesp_demux_packet_end();
		}
		new_msg_cnt++;
		break;
	case STP_DECODER_FREQ: {
		static uint32_t freq;
		/* Avoid calling log_output function multiple times as frequency
		 * is sent periodically.
		 */
		if (freq != (uint32_t)data.freq) {
			freq = (uint32_t)data.freq;
			log_output_timestamp_freq_set(freq);
		}
		break;
	}
	case STP_DECODER_MERROR: {
		sync_loss();
		break;
	}
	default:
		break;
	}

	/* Only -ENOMEM is accepted failure. */
	__ASSERT_NO_MSG((rv >= 0) || (rv == -ENOMEM));
}

static int decoder_init(void)
{
	int err;
	static bool once;

	if (once) {
		return -EALREADY;
	}

	once = true;

	static const struct log_frontend_stmesp_demux_config config = {
		.m_ids = stm_m_id,
		.m_ids_cnt = ARRAY_SIZE(stm_m_id),
		.source_id_buf = source_id_buf,
		.source_id_buf_len = ARRAY_SIZE(source_id_buf)};

	err = log_frontend_stmesp_demux_init(&config);
	if (err < 0) {
		return err;
	}

	static const struct mipi_stp_decoder_config stp_decoder_cfg = {.cb = decoder_cb,
								       .start_out_of_sync = false};

	mipi_stp_decoder_init(&stp_decoder_cfg);

	return 0;
}

/** @brief Attempt to process data pending in the ETR circular buffer.
 *
 * Data is processed in 16 bytes packages. Each package is a STPv2 frame which
 * contain data generated by STM stimulus ports.
 *
 */
static void etb_dump_thread_func(void *dummy1, void *dummy2, void *dummy3)
{
	static const mem_addr_t etb = DT_REG_ADDR(DT_NODELABEL(etb));

	decoder_init();

	while (true) {
		coresight_unlock(etb);

		/* Wait for AcqComp */
		for (int i = 0; i < 10000; i++) {
			if ((sys_read32(etb + ETB_STS_OFFSET) & BIT(2)) == 0) {
				break;
			}
		}

		/* Disable trace */
		sys_write32(0, etb + ETB_CTL_OFFSET);

		/* Wait for DFEmpty */
		for (int i = 0; i < 10000; i++) {
			if ((sys_read32(etb + ETB_STS_OFFSET) & BIT(3)) == 0) {
				break;
			}
		}

		size_t num_words = 0;
		size_t num_trailing_zero = 0;
		const uintptr_t write_pointer = sys_read32(etb + ETB_RWP_OFFSET);

		while ((sys_read32(etb + ETB_RRP_OFFSET) != write_pointer) &&
		       num_words < ARRAY_SIZE(etb_decode_buffer)) {
			const uint32_t val = sys_read32(etb + ETB_RRD_OFFSET);

			etb_decode_buffer[num_words] = val;
			num_words++;
			if (val == 0) {
				num_trailing_zero++;
			} else {
				num_trailing_zero = 0;
			}
		}

		mipi_stp_decoder_decode((void *)etb_decode_buffer, num_words * sizeof(uint32_t));
		process_messages();
		// log_frontend_stmesp_demux_reset();

		/* Re-enable trace */
		sys_write32(1, etb + ETB_CTL_OFFSET);

		coresight_lock(etb);

		k_sleep(ETB_DUMP_PERIOD_MS);
	}
}

static void uart_event_handler(const struct device *dev, struct uart_event *evt, void *user_data)
{
	ARG_UNUSED(dev);

	switch (evt->type) {
	case UART_TX_ABORTED:
		/* An intentional fall-through to UART_TX_DONE. */
	case UART_TX_DONE:
		k_sem_give(&uart_sem);
		break;
	default:
		__ASSERT_NO_MSG(0);
	}
}

static int etb_process_init(void)
{
	int err;

	k_sem_init(&uart_sem, 1, 1);

	err = uart_callback_set(uart_dev, uart_event_handler, NULL);
	use_async_uart = (err == 0);

	k_thread_create(&etb_dump_thread, etb_stack, K_KERNEL_STACK_SIZEOF(etb_stack),
			etb_dump_thread_func, NULL, NULL, NULL, K_LOWEST_APPLICATION_THREAD_PRIO, 0,
			ETB_DUMP_PERIOD_MS);
	k_thread_name_set(&etb_dump_thread, "etb_dump");

	return 0;
}

#define ETB_PROCESS_INIT_PRIORITY UTIL_INC(UTIL_INC(CONFIG_NRF_IRONSIDE_CALL_INIT_PRIORITY))

SYS_INIT(etb_process_init, POST_KERNEL, ETB_PROCESS_INIT_PRIORITY);
