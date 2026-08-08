/* librist. Copyright © 2019-2020 SipRadius LLC. All right reserved.
 * Author: Daniele Lacamera <root@danielinux.net>
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata <sergio@ammirata.net>
 * Author: Gijs Peskens <gijs@in2inip.nl>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#define LIBRIST_INTERNAL 1
#include "rist-private.h"
#include "log-private.h"
#include "udp-private.h"
#include "vcs_version.h"
#include "rist-thread.h"
#include "proto/rist_time.h"
#include <librist/version.h>
#include "crypto/crypto-private.h"
#include "crypto/psk.h"
#if HAVE_SRP_SUPPORT
#include "proto/eap.h"
#endif
#include <assert.h>
#include "librist/tun.h"
#include "librist/tunnel.h"
#ifdef _WIN32
#include <processthreadsapi.h>
#else
#include <unistd.h>
#include <poll.h>
#endif

#undef RIST_DEPRECATED

/* Receiver functions */

int rist_receiver_create(struct rist_ctx **_ctx, enum rist_profile profile,
						 struct rist_logging_settings *logging_settings)
{
	struct rist_ctx *rist_ctx = calloc(1, sizeof(*rist_ctx));
	if (!rist_ctx)
	{
		rist_log_priv2(logging_settings, RIST_LOG_ERROR, "Could not create ctx object, OOM!\n");
		return -1;
	}
	if (profile == RIST_PROFILE_ADVANCED)
	{
		rist_log_priv2(logging_settings, RIST_LOG_INFO, "Using Advanced profile (VSF TR-06-3)\n");
	}
	struct rist_receiver *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
	{
		rist_log_priv2(logging_settings, RIST_LOG_ERROR, "Could not create ctx object, OOM!\n");
		free(rist_ctx);
		return -1;
	}
	rist_ctx->mode = RIST_RECEIVER_MODE;
	rist_ctx->receiver_ctx = ctx;
	ctx->receiver_data_fd = -1;
	ctx->id = (intptr_t)ctx;
	if (init_common_ctx(&ctx->common, profile))
		goto fail;

	ctx->common.recovery_rtt_multiplier = 7;
	ctx->common.logging_settings = logging_settings;
	ctx->common.stats_report_time = (uint64_t)1000 * (uint64_t)RIST_CLOCK;
	ctx->fifo_queue_size = RIST_DATAOUT_QUEUE_BUFFERS;
	rist_log_priv(&ctx->common, RIST_LOG_INFO, "RIST Receiver Library version:%s \n", LIBRIST_VERSION);

	if (logging_settings && logging_settings->log_level == RIST_LOG_SIMULATE)
	{
		ctx->simulate_loss = true;
		ctx->loss_percentage = 1;//Actually 0.1%
		rist_log_priv(&ctx->common, RIST_LOG_WARN, "RIST receiver has been configured with self-imposed (outgoing) packet loss (0.1%%)\n");
	}

	ctx->common.receiver_id = ctx->id;
	ctx->common.sender_id = 0;

	if (logging_settings && logging_settings->log_level >= RIST_LOG_DEBUG)
		ctx->common.debug = true;

	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Starting in receiver mode\n");

	int ret = pthread_cond_init(&ctx->condition, NULL);
	if (ret)
	{
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Error %d calling pthread_cond_init\n", ret);
		goto fail;
	}
	ret = pthread_mutex_init(&ctx->mutex, NULL);
	if (ret)
	{
		pthread_cond_destroy(&ctx->condition);
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Error %d calling pthread_mutex_init\n", ret);
		goto fail;
	}

	*_ctx = rist_ctx;

	return 0;

fail:
	free(ctx);
	free(rist_ctx);
	ctx = NULL;
	return -1;
}

int rist_receiver_nack_type_set(struct rist_ctx *rist_ctx, enum rist_nack_type nack_type)
{
	if (RIST_UNLIKELY(!rist_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "ctx is null on rist_receiver_nack_type_set call!\n");
		return -1;
	}
	if (RIST_UNLIKELY(rist_ctx->mode != RIST_RECEIVER_MODE || !rist_ctx->receiver_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_receiver_nack_type_set call with CTX not set up for receiving\n");
		return -1;
	}
	struct rist_receiver *ctx = rist_ctx->receiver_ctx;
	ctx->nack_type = nack_type;
	return 0;
}

/* Find the flow with the most queued data.  Caller MUST hold
 * ctx->common.flows_lock on entry; the lock remains held on return so
 * the returned pointer stays valid until the caller releases it. */
static struct rist_flow *rist_get_longest_flow_locked(struct rist_receiver *ctx, ssize_t *num)
{
	ssize_t num_loop = 0;
	struct rist_flow *f = NULL;
	struct rist_flow *f_loop = ctx->common.FLOWS;
	while (f_loop) {
		struct rist_flow *nextflow = f_loop->next;
		unsigned long reader_index = atomic_load_explicit(&f_loop->dataout_fifo_queue_read_index, memory_order_relaxed);
		unsigned long write_index = atomic_load_explicit(&f_loop->dataout_fifo_queue_write_index, memory_order_acquire);

		num_loop = (write_index - reader_index)&(ctx->fifo_queue_size -1);
		if (num_loop > *num)
		{
			f = f_loop;
			*num = num_loop;
		}
		f_loop = nextflow;
	}
	return f;
}

int rist_receiver_data_read(struct rist_ctx *ctx, const struct rist_data_block **data_block, int timeout)
{
	return rist_receiver_data_read2(ctx, (struct rist_data_block **)data_block, timeout);
}

int rist_receiver_data_read2(struct rist_ctx *rist_ctx, struct rist_data_block **data_buffer, int timeout)
{
	if (RIST_UNLIKELY(!rist_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "ctx is null on rist_receiver_data_read call!\n");
		return -1;
	}
	if (RIST_UNLIKELY(rist_ctx->mode != RIST_RECEIVER_MODE || !rist_ctx->receiver_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_receiver_data_read call with CTX not set up for receiving\n");
		return -2;
	}

	struct rist_receiver *ctx = rist_ctx->receiver_ctx;

	struct rist_data_block *data_block = NULL;

	ssize_t num = 0;
	/* Hold flows_lock across the flow lookup and data read to prevent
	 * rist_delete_flow from freeing the flow underneath us. */
	pthread_mutex_lock(&ctx->common.flows_lock);
	struct rist_flow *f = rist_get_longest_flow_locked(ctx, &num);
	if (!num && timeout > 0)
	{
		pthread_mutex_unlock(&ctx->common.flows_lock);
		pthread_mutex_lock(&(ctx->mutex));
		pthread_cond_timedwait_ms(&(ctx->condition), &(ctx->mutex), timeout);
		pthread_mutex_unlock(&(ctx->mutex));
		num = 0;
		pthread_mutex_lock(&ctx->common.flows_lock);
		f = rist_get_longest_flow_locked(ctx, &num);
	}

	if (RIST_UNLIKELY(!num || !f))
	{
		pthread_mutex_unlock(&ctx->common.flows_lock);
		return 0;
	}

	/* Lock the flow's own mutex while still holding flows_lock, then
	 * release flows_lock.  This guarantees the flow pointer is valid
	 * when we dereference it: rist_delete_flow takes flows_lock before
	 * unlinking and freeing the flow. */
	pthread_mutex_lock(&f->mutex);
	pthread_mutex_unlock(&ctx->common.flows_lock);

	unsigned long dataout_read_index = atomic_load_explicit(&f->dataout_fifo_queue_read_index, memory_order_relaxed);
	size_t write_index = atomic_load_explicit(&f->dataout_fifo_queue_write_index, memory_order_acquire);
	if (write_index != dataout_read_index)
	{
		do {
			num = (atomic_load_explicit(&f->dataout_fifo_queue_write_index, memory_order_acquire) - dataout_read_index) &(ctx->fifo_queue_size -1);
			if (atomic_compare_exchange_weak(&f->dataout_fifo_queue_read_index, &dataout_read_index, (dataout_read_index +1)&(ctx->fifo_queue_size -1)))
			{
				data_block = f->dataout_fifo_queue[dataout_read_index];
				f->dataout_fifo_queue[dataout_read_index] = NULL;
				break;
			}
		} while (num > 0);
	}
	bool overflow = atomic_load_explicit(&f->fifo_overflow, memory_order_relaxed);
	pthread_mutex_unlock(&f->mutex);

	if (data_block == NULL && num > 0)
	{
		rist_log_priv3(RIST_LOG_ERROR, "[rist_receiver_data_read2] data_block is NULL but num > 0 ! num=%zd, dataout_read_index=%lu, write_index=%zu\n", num, dataout_read_index, write_index);
		return -3;
	}

	*data_buffer = data_block;

	if (RIST_UNLIKELY(overflow))
		data_block->flags |= RIST_DATA_FLAGS_OVERFLOW;

	return (int)num;
}

void rist_receiver_data_block_free(struct rist_data_block **const block)
{
	rist_receiver_data_block_free2((struct rist_data_block **)block);
}

void rist_receiver_data_block_free2(struct rist_data_block **block)
{
	/* free(NULL)-style no-op: *block may already be NULL on the data_fd
	 * delivery path (free_data_block nulls it). Mirror its guard. */
	if (block == NULL)
		return;
	struct rist_data_block *b = *block;
	if (b == NULL)
		return;
	if (b->ref != NULL)
		free_data_block(block);
}

uint32_t rist_flow_id_create(void)
{
	uint32_t u32 = prand_u32();
	u32 &= ~(1UL << 0);

	return u32;
}

int rist_receiver_data_notify_fd_set(struct rist_ctx *rist_ctx, int fd)
{
	if (RIST_UNLIKELY(!rist_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "ctx is null on rist_receiver_data_notify_fd_set call!\n");
		return -1;
	}
	if (RIST_UNLIKELY(rist_ctx->mode != RIST_RECEIVER_MODE || !rist_ctx->receiver_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_receiver_data_notify_fd_set call with CTX not set up for receiving\n");
		return -1;
	}
	struct rist_receiver *ctx = rist_ctx->receiver_ctx;
	ctx->receiver_data_ready_notify_fd = fd;
	return 0;
}

int rist_connection_status_callback_set(struct rist_ctx *ctx, connection_status_callback_t connection_status_callback,
										void *arg)
{
	if (RIST_UNLIKELY(!ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "ctx is null on rist_connection_status_callback_set call!\n");
		return -1;
	}
	struct rist_common_ctx *cctx = NULL;
	if (ctx->mode == RIST_RECEIVER_MODE && ctx->receiver_ctx) {
		cctx = &ctx->receiver_ctx->common;
	}
	else if (ctx->mode == RIST_SENDER_MODE && ctx->sender_ctx) {
		cctx = &ctx->sender_ctx->common;
	}
	else {
		rist_log_priv3(RIST_LOG_ERROR, "Unknown error in rist_connection_status_callback_set call!\n");
		return -1;
	}
	cctx->connection_status_callback = connection_status_callback;
	cctx->connection_status_callback_argument = arg;
	return 0;
}

int rist_receiver_data_callback_set(struct rist_ctx *rist_ctx,receiver_data_callback_t data_callback, void *arg)
{
  return rist_receiver_data_callback_set2(
      rist_ctx, (receiver_data_callback2_t)data_callback, arg);
}

int rist_receiver_data_callback_set2(struct rist_ctx *rist_ctx,
                                     receiver_data_callback2_t data_callback,
                                     void *arg) {
  if (RIST_UNLIKELY(!rist_ctx)) {
    rist_log_priv3(RIST_LOG_ERROR,
                   "ctx is null on rist_receiver_data_callback_set call!\n");
    return -1;
  }
  if (RIST_UNLIKELY(rist_ctx->mode != RIST_RECEIVER_MODE ||
                    !rist_ctx->receiver_ctx)) {
    rist_log_priv3(RIST_LOG_ERROR, "rist_receiver_data_callback_set call with "
                                   "CTX not set up for receiving\n");
    return -1;
  }
  struct rist_receiver *ctx = rist_ctx->receiver_ctx;
  ctx->receiver_data_callback = data_callback;
  ctx->receiver_data_callback_argument = arg;
  return 0;
}

int rist_receiver_session_timeout_callback_set(struct rist_ctx *rist_ctx,
                                     receiver_session_timeout_callback_t session_timeout_callback,
                                     void *arg) {
  if (RIST_UNLIKELY(!rist_ctx)) {
    rist_log_priv3(RIST_LOG_ERROR,
                   "ctx is null on rist_session_timeout_callback_set call!\n");
    return -1;
  }
  if (RIST_UNLIKELY(rist_ctx->mode != RIST_RECEIVER_MODE ||
                    !rist_ctx->receiver_ctx)) {
    rist_log_priv3(RIST_LOG_ERROR, "rist_receiver_session_timeout_callback_set call with "
                                   "CTX not set up for receiving\n");
    return -1;
  }
  struct rist_receiver *ctx = rist_ctx->receiver_ctx;
  ctx->receiver_session_timeout_callback = session_timeout_callback;
  ctx->receiver_session_timeout_callback_argument = arg;
  return 0;
}

int rist_receiver_flow_attr_callback_set(struct rist_ctx *rist_ctx,
                                         receiver_flow_attr_callback_t cb,
                                         void *arg)
{
  if (RIST_UNLIKELY(!rist_ctx)) {
    rist_log_priv3(RIST_LOG_ERROR,
                   "ctx is null on rist_receiver_flow_attr_callback_set call!\n");
    return -1;
  }
  if (RIST_UNLIKELY(rist_ctx->mode != RIST_RECEIVER_MODE ||
                    !rist_ctx->receiver_ctx)) {
    rist_log_priv3(RIST_LOG_ERROR, "rist_receiver_flow_attr_callback_set call with "
                                   "CTX not set up for receiving\n");
    return -1;
  }
  struct rist_receiver *ctx = rist_ctx->receiver_ctx;
  ctx->receiver_flow_attr_callback = cb;
  ctx->receiver_flow_attr_callback_argument = arg;
  return 0;
}

/* Sender functions */
int rist_sender_create(struct rist_ctx **_ctx, enum rist_profile profile,
					   uint32_t flow_id, struct rist_logging_settings *logging_settings)
{
	int ret;

	if (profile == RIST_PROFILE_ADVANCED)
	{
		rist_log_priv2(logging_settings, RIST_LOG_INFO, "Using Advanced profile (VSF TR-06-3)\n");
	}

	if (flow_id % 2 != 0)
	{
		rist_log_priv2(logging_settings, RIST_LOG_ERROR, "Flow ID must be an even number!\n");
		return -1;
	}

	struct rist_ctx *rist_ctx = calloc(1, sizeof(*rist_ctx));
	if (!rist_ctx)
	{
		rist_log_priv2(logging_settings, RIST_LOG_ERROR, "Could not create ctx object, OOM!\n");
		return -1;
	}
	struct rist_sender *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
	{
		rist_log_priv2(logging_settings, RIST_LOG_ERROR, "Could not create ctx object, OOM!\n");
		free(rist_ctx);
		return -1;
	}
	rist_ctx->mode = RIST_SENDER_MODE;
	rist_ctx->sender_ctx = ctx;
	ctx->data_fd = -1;

	ctx->id = (intptr_t)ctx;
	if (init_common_ctx(&ctx->common, profile))
	{
		free(ctx);
		free(rist_ctx);
		ctx = NULL;
		return -1;
	}

	ctx->common.recovery_rtt_multiplier = 7;
	ctx->common.logging_settings = logging_settings;
	ctx->common.stats_report_time = (uint64_t)1000 * (uint64_t)RIST_CLOCK;
	//ctx->common.seq = 9159579;
	//ctx->common.seq = RIST_SERVER_QUEUE_BUFFERS - 25000;

	if (!ctx->sender_retry_queue)
	{
		ctx->sender_retry_queue = calloc(RIST_RETRY_QUEUE_BUFFERS, sizeof(*ctx->sender_retry_queue));
		if (RIST_UNLIKELY(!ctx->sender_retry_queue))
		{
			rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Could not create sender retry buffer of size %u MB, OOM\n",
						  (unsigned)(RIST_RETRY_QUEUE_BUFFERS * sizeof(ctx->sender_retry_queue[0])) / 1000000);
			ret = -1;
			goto free_ctx_and_ret;
		}

		ctx->sender_retry_queue_write_index = 1;
		ctx->sender_retry_queue_read_index = 0;
		ctx->sender_retry_queue_size = RIST_RETRY_QUEUE_BUFFERS;
	}

	ctx->sender_queue_delete_index = 1;
	/* Advanced uses the (runtime-tunable) configured capacity; Simple/Main
	 * keep the default ring. Heap-allocated so the size can be tuned via
	 * rist_recovery_depth_set() before rist_start(). */
	ctx->sender_queue_max = (ctx->common.profile == RIST_PROFILE_ADVANCED)
			? ctx->common.recovery_queue_max : RIST_SERVER_QUEUE_BUFFERS;
	ctx->sender_queue = calloc(ctx->sender_queue_max, sizeof(*ctx->sender_queue));
	ctx->seq_index = calloc(ctx->sender_queue_max, sizeof(*ctx->seq_index));
	if (RIST_UNLIKELY(!ctx->sender_queue || !ctx->seq_index))
	{
		rist_log_priv(&ctx->common, RIST_LOG_ERROR,
					  "Could not allocate sender recovery ring (%zu entries), OOM\n",
					  ctx->sender_queue_max);
		ret = -1;
		goto free_ctx_and_ret;
	}
	/* Advanced sender keeps a parallel 16-bit-RTP retransmit index so a
	 * peer that negotiated down to Main (which NACKs in the RTP domain) can
	 * still be served. Main/Simple senders index by RTP directly already. */
	if (ctx->common.profile == RIST_PROFILE_ADVANCED) {
		ctx->seq_rtp_index = calloc((size_t)UINT16_MAX + 1, sizeof(*ctx->seq_rtp_index));
		if (RIST_UNLIKELY(!ctx->seq_rtp_index)) {
			rist_log_priv(&ctx->common, RIST_LOG_ERROR,
						  "Could not allocate sender RTP recovery index, OOM\n");
			ret = -1;
			goto free_ctx_and_ret;
		}
	}
	atomic_init(&ctx->sender_queue_write_index, 1);
	atomic_init(&ctx->sender_queue_read_index, 0);

	rist_log_priv(&ctx->common, RIST_LOG_INFO, "RIST Sender Library %s\n", LIBRIST_VERSION);

	ctx->common.sender_id = ctx->id;
	ctx->common.receiver_id = 0;

	if (logging_settings && logging_settings->log_level == RIST_LOG_SIMULATE)
	{
		ctx->simulate_loss = true;
		ctx->loss_percentage = 1;//Actually 0.1%
		rist_log_priv(&ctx->common, RIST_LOG_WARN, "RIST Sender has been configured with self-imposed (outgoing) packet loss (0.1%%)\n");
	}

	if (logging_settings && logging_settings->log_level >= RIST_LOG_DEBUG)
	{
		ctx->common.debug = true;
	}

	if (flow_id == 0)
		flow_id = rist_flow_id_create();

	ctx->adv_flow_id = flow_id;

	ret = pthread_cond_init(&ctx->condition, NULL);
	if (ret)
	{
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Error %d initializing pthread_condition\n", ret);
		goto free_ctx_and_ret;
	}

	ret = pthread_mutex_init(&ctx->mutex, NULL);
	if (ret)
	{
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Error %d initializing pthread_mutex\n", ret);
		goto free_ctx_and_ret;
	}

	ret = pthread_mutex_init(&ctx->queue_lock, NULL);
	if (ret)
	{
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Error %d initializing pthread_mutex\n", ret);
		goto free_ctx_and_ret;
	}

	ctx->sender_initialized = true;

	*_ctx = rist_ctx;
	return 0;

	// Failed!
free_ctx_and_ret:
	if (ctx) {
		free(ctx->sender_retry_queue);
		free(ctx->sender_queue);
		free(ctx->seq_index);
		free(ctx->seq_rtp_index);
	}
	free(ctx);
	free(rist_ctx);
	return ret;
}

int rist_sender_flow_id_get(struct rist_ctx *rist_ctx, uint32_t *flow_id)
{
	if (RIST_UNLIKELY(!rist_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_sender_flow_id_get call with null context");
		return -1;
	}
	if (RIST_UNLIKELY(rist_ctx->mode != RIST_SENDER_MODE || !rist_ctx->sender_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_sender_flow_id_get call with ctx not set up for sending\n");
		return -1;
	}
	struct rist_sender *ctx = rist_ctx->sender_ctx;
	*flow_id = ctx->adv_flow_id;
	return 0;
}

int rist_sender_npd_get(const struct rist_ctx *rist_ctx, bool *npd)
{
	if (RIST_UNLIKELY(!rist_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_sender_npd_get call with null context");
		return -1;
	}
	if (RIST_UNLIKELY(rist_ctx->mode != RIST_SENDER_MODE || !rist_ctx->sender_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_sender_npd_get call with ctx not set up for sending\n");
		return -1;
	}
	const struct rist_sender *ctx = rist_ctx->sender_ctx;
	*npd = ctx->null_packet_suppression;
	return 0;
}

int rist_sender_npd_enable(struct rist_ctx *rist_ctx)
{
	if (RIST_UNLIKELY(!rist_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_sender_npd_enable call with null context");
		return -1;
	}
	if (RIST_UNLIKELY(rist_ctx->mode != RIST_SENDER_MODE || !rist_ctx->sender_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_sender_npd_enable call with ctx not set up for sending\n");
		return -1;
	}
	struct rist_sender *ctx = rist_ctx->sender_ctx;
	ctx->null_packet_suppression = true;
	rist_log_priv2(ctx->common.logging_settings, RIST_LOG_INFO, "Enabled NULL Packet deletion\n");
	return 0;
}

int rist_sender_npd_disable(struct rist_ctx *rist_ctx)
{
	if (RIST_UNLIKELY(!rist_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_sender_npd_disable call with null context");
		return -1;
	}
	if (RIST_UNLIKELY(rist_ctx->mode != RIST_SENDER_MODE || !rist_ctx->sender_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_sender_npd_disable call with ctx not set up for sending\n");
		return -1;
	}
	struct rist_sender *ctx = rist_ctx->sender_ctx;
	ctx->null_packet_suppression = false;
	rist_log_priv2(ctx->common.logging_settings, RIST_LOG_INFO, "Disabled NULL Packet deletion\n");
	return 0;
}

int rist_sender_flow_id_set(struct rist_ctx *rist_ctx, uint32_t flow_id)
{
	if (RIST_UNLIKELY(!rist_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_sender_flow_id_set call with null context");
		return -1;
	}
	if (RIST_UNLIKELY(rist_ctx->mode != RIST_SENDER_MODE || !rist_ctx->sender_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_sender_flow_id_set call with ctx not set up for sending\n");
		return -1;
	}
	struct rist_sender *ctx = rist_ctx->sender_ctx;
	//Make sure LSB = 0
	flow_id &= ~1UL;
	ctx->adv_flow_id = flow_id;
	for (size_t i = 0; i < ctx->peer_lst_len; i++)
	{
		ctx->peer_lst[i]->peer_ssrc = ctx->peer_lst[i]->adv_flow_id = flow_id;
	}
	return 0;
}

int rist_sender_data_write(struct rist_ctx *rist_ctx, const struct rist_data_block *data_block)
{
	if (RIST_UNLIKELY(!rist_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_sender_data_write call with null context\n");
		return -1;
	}
	if (RIST_UNLIKELY(rist_ctx->mode != RIST_SENDER_MODE || !rist_ctx->sender_ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_sender_data_write call with ctx not set up for sending\n");
		return -1;
	}
	struct rist_sender *ctx = rist_ctx->sender_ctx;
	// max protocol overhead for data is gre-header plus gre-reduced-mode-header plus rtp-header
	// 16 + 4 + 12 = 32

	if (data_block->payload_len <= 0 || data_block->payload_len > (RIST_MAX_PACKET_SIZE - 32))
	{
		rist_log_priv(&ctx->common, RIST_LOG_ERROR,
					  "Dropping pipe packet of size %d, max is %d.\n", data_block->payload_len, RIST_MAX_PACKET_SIZE - 32);
		return -1;
	}

	if (RIST_UNLIKELY((data_block->flags & RIST_DATA_FLAGS_USE_SEQ) &&
	                  ctx->split_mode != LIBRIST_SPLIT_MODE_OFF)) {
		rist_log_priv(&ctx->common, RIST_LOG_ERROR,
			"RIST_DATA_FLAGS_USE_SEQ cannot be used with split mode; "
			"the library must control the wire sequence for pair "
			"splitting. Use ts_ntp to preserve source timestamps.\n");
		return -1;
	}

	uint64_t ts_ntp = data_block->ts_ntp == 0 ? timestampNTP_u64() : data_block->ts_ntp;

	const uint8_t *payload_to_send = data_block->payload;
	size_t payload_len = data_block->payload_len;

	bool actually_split = (ctx->split_mode != LIBRIST_SPLIT_MODE_OFF);
	size_t first_len = 0;
	size_t last_len = 0;
	if (actually_split) {
		if (ctx->split_mode == LIBRIST_SPLIT_MODE_AUTO) {
			const uint8_t *p = payload_to_send;
			if (payload_len >= 2 * 188 && payload_len % 188 == 0 && p[0] == 0x47) {
				size_t ts_count = payload_len / 188;
				size_t first_ts = ts_count / 2;
				if (first_ts == 0)
					first_ts = 1;
				first_len = first_ts * 188;
				last_len = payload_len - first_len;
			} else {
				ctx->stats_split_fallback_not_ts++;
				first_len = payload_len / 2;
				last_len = payload_len - first_len;
			}
		} else {
			first_len = payload_len / 2;
			last_len = payload_len - first_len;
		}
	}

	uint32_t seq_rtp_first;
	uint32_t seq_rtp_last = 0;
	if (data_block->flags & RIST_DATA_FLAGS_USE_SEQ) {
		seq_rtp_first = (uint32_t)data_block->seq;
	} else if (actually_split) {
		if (ctx->common.seq_rtp & 1)
			ctx->common.seq_rtp++;
		seq_rtp_first = ctx->common.seq_rtp++;
		seq_rtp_last = ctx->common.seq_rtp++;
	} else {
		seq_rtp_first = ctx->common.seq_rtp++;
	}
	seq_rtp_first &= UINT16_MAX;
	seq_rtp_last &= UINT16_MAX;

	int ret;
	if (actually_split) {
		ret = rist_sender_enqueue(ctx, payload_to_send, first_len, ts_ntp,
		                          data_block->virt_src_port,
		                          data_block->virt_dst_port, seq_rtp_first);
		if (ret == 0) {
			ret = rist_sender_enqueue(ctx, payload_to_send + first_len, last_len,
			                          ts_ntp, data_block->virt_src_port,
			                          data_block->virt_dst_port, seq_rtp_last);
			if (ret == 0) {
				ctx->stats_pairs_emitted++;
			} else {
				rist_log_priv(&ctx->common, RIST_LOG_WARN,
					"Split write: first half (seq %u) enqueued but second "
					"half (seq %u) failed (ret=%d); receiver will see an "
					"orphan.\n", seq_rtp_first, seq_rtp_last, ret);
			}
		}
	} else {
		ret = rist_sender_enqueue(ctx, payload_to_send, payload_len, ts_ntp,
		                          data_block->virt_src_port,
		                          data_block->virt_dst_port, seq_rtp_first);
	}
	// Wake up data/nack output thread when data comes in
	if (pthread_cond_signal(&ctx->condition))
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Call to pthread_cond_signal failed.\n");

	if (ret < 0)
		return ret;
	else
		return (int)data_block->payload_len;
}

/* Shared OOB functions -> Tunneled IP packets within GRE */
int rist_oob_read(struct rist_ctx *ctx, const struct rist_oob_block **oob_block)
{
	if (!ctx)
	{
		rist_log_priv3(RIST_LOG_ERROR, "ctx is null on rist_oob_read call!\n");
		return -1;
	}
	if (!oob_block)
	{
		rist_log_priv3(RIST_LOG_ERROR, "oob_block is null on rist_oob_read call!\n");
		return -1;
	}
	struct rist_common_ctx *cctx = rist_struct_get_common(ctx);
	if (!cctx)
		return -1;

	*oob_block = NULL;

	if (!cctx->oob_data_enabled)
	{
		rist_log_priv(cctx, RIST_LOG_ERROR,
				"rist_oob_read called but oob data is not enabled; call rist_oob_callback_set first\n");
		return -1;
	}
	if (cctx->oob_data_callback)
	{
		rist_log_priv(cctx, RIST_LOG_ERROR,
				"rist_oob_read cannot be used while an oob callback is installed\n");
		return -1;
	}

	return rist_oob_dequeue_rx(cctx, oob_block);
}

int rist_oob_write(struct rist_ctx *ctx, const struct rist_oob_block *oob_block)
{
	if (RIST_UNLIKELY(!ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_oob_write call with null ctx!\n");
		return -1;
	}
	struct rist_common_ctx *cctx = rist_struct_get_common(ctx);
	if (RIST_UNLIKELY(!cctx))
		return -1;
	// max protocol overhead for data is gre-header, 16 max
	if (oob_block->payload_len <= 0 || oob_block->payload_len > (RIST_MAX_PACKET_SIZE - 16))
	{
		rist_log_priv(cctx, RIST_LOG_ERROR,
					  "Dropping oob packet of size %d, max is %d.\n", oob_block->payload_len, RIST_MAX_PACKET_SIZE - 16);
		return -1;
	}
	struct rist_peer *peer = oob_block->peer;
	if (peer == NULL)
		peer = cctx->oob_current_peer;
	if (peer)
		return rist_oob_enqueue(cctx, peer, oob_block->payload, oob_block->payload_len);
	else
	{
		rist_log_priv(cctx, RIST_LOG_WARN,
			"No oob peer, dropping packet of size %d\n", oob_block->payload_len);
		return 0;
	}
}

int rist_oob_callback_set(struct rist_ctx *ctx,
						  int (*oob_callback)(void *arg, const struct rist_oob_block *oob_block),
						  void *arg)
{
	if (RIST_UNLIKELY(!ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_oob_callback_set call with null ctx!\n");
		return -1;
	}
	struct rist_common_ctx *cctx = rist_struct_get_common(ctx);
	if (RIST_UNLIKELY(!cctx))
		return -1;
	else if (cctx->profile == RIST_PROFILE_SIMPLE)
	{
		rist_log_priv(cctx, RIST_LOG_ERROR, "Out-of-band data is not support for simple profile\n");
		return -1;
	}
	if (pthread_rwlock_init(&cctx->oob_queue_lock, NULL) != 0)
	{
		rist_log_priv(cctx, RIST_LOG_ERROR, "Failed to init ctx->common.oob_queue_lock\n");
		return -1;
	}
	cctx->oob_data_enabled = true;
	cctx->oob_data_callback = oob_callback;
	cctx->oob_data_callback_argument = arg;
	cctx->oob_queue_write_index = 0;
	cctx->oob_queue_read_index = 0;
	cctx->oob_rx_queue_write_index = 0;
	cctx->oob_rx_queue_read_index = 0;
	cctx->oob_rx_current = NULL;

	return 0;
}

/* Shared functions */

int rist_jitter_max_set(struct rist_ctx *ctx, int t)
{
	struct rist_common_ctx *cctx = rist_struct_get_common(ctx);
	if (!cctx)
		return -1;
	return rist_max_jitter_set(cctx, t);
}

int rist_recovery_rtt_multiplier_set(struct rist_ctx *ctx, int multiplier)
{
	struct rist_common_ctx *cctx = rist_struct_get_common(ctx);
	if (!cctx)
		return -1;
	return rist_recovery_rtt_multiplier_set_internal(cctx, multiplier);
}

/* Translate a recovery-depth exponent into ring capacity in packets
 * (65536 << depth), clamped to [MIN, MAX] and to the platform maximum
 * (rist_recovery_depth_platform_max) so the result always fits size_t.
 * Returned as uint64_t so the arithmetic is exact regardless of size_t width. */
static uint64_t rist_recovery_depth_to_packets(int depth)
{
	if (depth < RIST_RECOVERY_DEPTH_MIN)
		depth = RIST_RECOVERY_DEPTH_MIN;
	if (depth > RIST_RECOVERY_DEPTH_MAX)
		depth = RIST_RECOVERY_DEPTH_MAX;
	int platform_max = rist_recovery_depth_platform_max();
	if (depth > platform_max)
		depth = platform_max;
	return (uint64_t)UINT16_SIZE << depth;
}

/* Resize the context recovery ring to `packets` (already a power of two in
 * [UINT16_SIZE, 2^32]). The caller MUST guarantee rist_start() has not
 * completed, so the sender ring can be reallocated with no data in flight.
 * Returns 0 on success, -2 on OOM / size unrepresentable on this platform. */
static int rist_recovery_depth_apply(struct rist_ctx *ctx, struct rist_common_ctx *cctx, uint64_t packets)
{
	if (packets > (uint64_t)(SIZE_MAX / (sizeof(struct rist_buffer *) + sizeof(uint32_t)))) {
		rist_log_priv(cctx, RIST_LOG_ERROR,
			"Recovery depth too large to allocate on this platform (%llu packets)\n",
			(unsigned long long)packets);
		return -2;
	}
	size_t want = (size_t)packets;

	if (cctx->profile != RIST_PROFILE_ADVANCED) {
		cctx->recovery_queue_max = want;
		rist_log_priv(cctx, RIST_LOG_INFO,
			"Recovery depth request stored (%zu packets); only the Advanced "
			"profile uses it (Simple/Main are 16-bit, capped at %u packets).\n",
			want, (unsigned)UINT16_SIZE);
		return 0;
	}

	/* The receiver allocates its ring per-flow and reads recovery_queue_max
	 * directly, so nothing more to do there. The sender allocates its ring
	 * at create time, so resize it now - safe because rist_start() has not
	 * run yet and no data is flowing. On OOM the old ring (and
	 * recovery_queue_max) is left untouched. */
	if (ctx->mode == RIST_SENDER_MODE && ctx->sender_ctx) {
		struct rist_sender *sender = ctx->sender_ctx;
		if (sender->sender_queue_max != want) {
			struct rist_buffer **nq = calloc(want, sizeof(*nq));
			uint32_t *ni = calloc(want, sizeof(*ni));
			if (!nq || !ni) {
				free(nq);
				free(ni);
				rist_log_priv(cctx, RIST_LOG_ERROR,
					"OOM resizing sender recovery ring to %zu packets\n", want);
				return -2;
			}
			free(sender->sender_queue);
			free(sender->seq_index);
			sender->sender_queue = nq;
			sender->seq_index = ni;
			sender->sender_queue_max = want;
			sender->sender_queue_delete_index = 1;
			atomic_store_explicit(&sender->sender_queue_write_index, 1, memory_order_release);
			atomic_store_explicit(&sender->sender_queue_read_index, 0, memory_order_release);
		}
	}

	cctx->recovery_queue_max = want;
	rist_log_priv(cctx, RIST_LOG_INFO,
		"Advanced recovery buffer set to %zu packets (NACK window ~%zu packets, "
		"~%zu MB of index arrays per context)\n",
		want, want / 2,
		(want * (sizeof(struct rist_buffer *) + sizeof(uint32_t))) / (1024 * 1024));
	return 0;
}

int rist_recovery_depth_set(struct rist_ctx *ctx, uint8_t depth)
{
	struct rist_common_ctx *cctx = rist_struct_get_common(ctx);
	if (!cctx)
		return -1;

	if (atomic_load_explicit(&cctx->startup_complete, memory_order_acquire)) {
		rist_log_priv(cctx, RIST_LOG_ERROR,
			"rist_recovery_depth_set must be called before rist_start()\n");
		return -1;
	}

	if (depth > RIST_RECOVERY_DEPTH_MAX) {
		rist_log_priv(cctx, RIST_LOG_WARN,
			"recovery depth %u out of range, clamping to %u\n",
			(unsigned)depth, (unsigned)RIST_RECOVERY_DEPTH_MAX);
		depth = RIST_RECOVERY_DEPTH_MAX;
	}

	int platform_max = rist_recovery_depth_platform_max();
	if (depth > platform_max) {
		rist_log_priv(cctx, RIST_LOG_WARN,
			"recovery depth %u exceeds what this platform can address, "
			"capping to %d\n", (unsigned)depth, platform_max);
		depth = platform_max;
	}

	return rist_recovery_depth_apply(ctx, cctx, rist_recovery_depth_to_packets(depth));
}

int rist_auth_handler_set(struct rist_ctx *ctx,
						  int (*conn_cb)(void *arg, const char *connecting_ip, uint16_t connecting_port, const char *local_ip, uint16_t local_port, struct rist_peer *peer),
						  int (*disconn_cb)(void *arg, struct rist_peer *peer),
						  void *arg)
{
	if (RIST_UNLIKELY(!ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_auth_handler_set call with null ctx!\n");
		return -1;
	}
	struct rist_common_ctx *cctx = rist_struct_get_common(ctx);
	if (RIST_UNLIKELY(!cctx))
		return -1;
	return rist_auth_handler(cctx, conn_cb, disconn_cb, arg);
}

int rist_srp_auth_callback_set(struct rist_ctx *ctx,
		rist_srp_auth_callback_t callback, void *arg)
{
	if (!ctx)
		return -1;
	struct rist_common_ctx *cctx = rist_struct_get_common(ctx);
	if (!cctx)
		return -1;
	cctx->srp_auth_callback = callback;
	cctx->srp_auth_callback_argument = arg;
	return 0;
}

int rist_receiver_flow_authorize_callback_set(struct rist_ctx *ctx,
		receiver_flow_authorize_callback_t callback, void *arg)
{
	if (!ctx || ctx->mode != RIST_RECEIVER_MODE || !ctx->receiver_ctx)
		return -1;
	struct rist_common_ctx *cctx = &ctx->receiver_ctx->common;
	cctx->receiver_flow_authorize_callback = callback;
	cctx->receiver_flow_authorize_callback_argument = arg;
	return 0;
}

int rist_stats_free(const struct rist_stats *stats_container)
{
	if (!stats_container)
		return -1;
	free(stats_container->stats_json);
	if (stats_container->stats_type == RIST_STATS_RECEIVER_FLOW) 
		free(stats_container->stats.receiver_flow.peers);
	free((void *)stats_container);
	return 0;
}

uint32_t rist_peer_get_id(const struct rist_peer *peer)
{
    if (!peer)
        return 0;
    return peer->adv_peer_id;
}

uint32_t rist_peer_get_cname(const struct rist_peer *peer, const char **cname)
{
	if (peer && cname)
	{
		*cname = &peer->cname[0];
		return (uint32_t)strnlen(*cname, sizeof(peer->cname));
	}
	else
		return 0;
}

int rist_peer_config_free(const struct rist_peer_config **peer_config)
{
  return rist_peer_config_free2((struct rist_peer_config **)peer_config);
}

int rist_peer_config_free2(struct rist_peer_config **peer_config)
{
	if (*peer_config) {
		free((void *)*peer_config);
		*peer_config = NULL;
	}
	return 0;
}

#if HAVE_SRP_SUPPORT
int rist_peer_update_secret(struct rist_peer *peer, const char* password) {
	pthread_mutex_lock(&peer->peer_lock);
	size_t password_len = strlen(password);
	struct rist_key *inactive_key = (peer->key_rx_odd_active) ? &peer->key_tx : &peer->key_tx_odd;
	rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Updating passphrase for peer #%u\n", peer->adv_peer_id);
	_librist_crypto_psk_set_passphrase(inactive_key, (const uint8_t *)password, password_len);
	struct rist_peer *child = peer->child;
	while (child != NULL) {
		pthread_mutex_lock(&child->peer_lock);
		inactive_key = (child->key_rx_odd_active) ? &child->key_tx : &child->key_tx_odd;
		_librist_crypto_psk_set_passphrase(inactive_key, (const uint8_t *)password, password_len);
		child->rolling_over_passphrase = true;
		pthread_mutex_unlock(&child->peer_lock);
		rist_eap_send_passphrase(child->eap_ctx, password);
		child = child->sibling_next;
	}
	peer->rolling_over_passphrase = true;
	pthread_mutex_unlock(&peer->peer_lock);
	rist_eap_send_passphrase(peer->eap_ctx, password);
	return 0;
}
#endif

int rist_logging_settings_free(const struct rist_logging_settings **logging_settings)
{
	return rist_logging_settings_free2((struct rist_logging_settings **)logging_settings);
}

int rist_logging_settings_free2(struct rist_logging_settings **logging_settings)
{
	if (*logging_settings) {
		rist_logging_unset_global_if_matches(*logging_settings);
		free((void *)*logging_settings);
		*logging_settings = NULL;
	}
	return 0;
}

int rist_udp_config_free(const struct rist_udp_config **udp_config)
{
	return rist_udp_config_free2((struct rist_udp_config **)udp_config);
}

int rist_udp_config_free2(struct rist_udp_config **udp_config)
{
	if (*udp_config) {
		free((void *)*udp_config);
		*udp_config = NULL;
	}
	return 0;
}

int rist_sender_stats_callback_set(struct rist_ctx *ctx, int statsinterval, int (*stats_cb)(void *arg, uint16_t version, char *stats_json, uint32_t json_size), void *arg)
{
	if (RIST_UNLIKELY(!ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_sender_stats_callback_set call with null ctx!\n");
		return -1;
	}

	if (ctx->mode == RIST_SENDER_MODE && statsinterval != 0)
	{
		ctx->sender_ctx->sender_stats_callback = stats_cb;
		ctx->sender_ctx->sender_stats_callback_argument = arg;
		ctx->sender_ctx->stats_report_time = statsinterval * RIST_CLOCK;
	}

	return 0;
}

int rist_stats_callback_set(struct rist_ctx *ctx, int statsinterval, int (*stats_cb)(void *arg, const struct rist_stats *stats_container), void *arg)
{
	if (RIST_UNLIKELY(!ctx))
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_stats_callback_set call with null ctx!\n");
		return -1;
	}
	struct rist_common_ctx *cctx = rist_struct_get_common(ctx);
	if (RIST_UNLIKELY(!cctx))
		return -1;
	pthread_mutex_lock(&cctx->stats_lock);

	if (statsinterval != 0)
	{
		cctx->stats_callback = stats_cb;
		cctx->stats_callback_argument = arg;
		cctx->stats_report_time = statsinterval * RIST_CLOCK;
		if (ctx->mode == RIST_RECEIVER_MODE)
		{
			struct rist_flow *f = cctx->FLOWS;
			while (f)
			{
				f->stats_report_time = statsinterval * RIST_CLOCK;
				f = f->next;
			}
		}
		else if (ctx->mode == RIST_SENDER_MODE && ctx->sender_ctx)
		{
			/* sender loop reads its own copy, not the common one */
			ctx->sender_ctx->stats_report_time = statsinterval * RIST_CLOCK;
		}
	}
	pthread_mutex_unlock(&cctx->stats_lock);
	return 0;
}

/* Utility functions */
const char *librist_version(void)
{
	return LIBRIST_VERSION;
}

const char *librist_api_version(void)
{
	return STR(LIBRIST_API_VERSION_MAJOR)"."STR(LIBRIST_API_VERSION_MINOR)"."STR(LIBRIST_API_VERSION_PATCH);
}

int rist_parse_udp_address(const char *url, const struct rist_udp_config **udp_config)
{
  	return rist_parse_udp_address2(url, (struct rist_udp_config **)udp_config);
}

int rist_parse_udp_address2(const char *url, struct rist_udp_config **udp_config)
{

	int ret = 0;
	if (*udp_config == NULL)
	{
		// Default options on new struct (specific for udp url)
		struct rist_udp_config *output_udp_config = calloc(1, sizeof(struct rist_udp_config));
		if (!output_udp_config)
			return -1;
		output_udp_config->version = RIST_UDP_CONFIG_VERSION;
		output_udp_config->stream_id = 0; // Accept all on receiver, auto-generate on sender
		ret = parse_url_udp_options(url, output_udp_config);
		*udp_config = output_udp_config;
	}
	else
	{
		// Update incoming object with url data
		struct rist_udp_config *existing_udp_config = (void *)*udp_config;
		ret = parse_url_udp_options(url, existing_udp_config);
		*udp_config = existing_udp_config;
	}

	return ret;
}

int rist_peer_config_defaults_set_versioned(struct rist_peer_config *peer_config, int version)
{
	if (peer_config)
	{
		peer_config->version = version;
		peer_config->virt_dst_port = RIST_DEFAULT_VIRT_DST_PORT;
		peer_config->recovery_mode = RIST_DEFAULT_RECOVERY_MODE;
		peer_config->recovery_maxbitrate = RIST_DEFAULT_RECOVERY_MAXBITRATE;
		peer_config->recovery_maxbitrate_return = RIST_DEFAULT_RECOVERY_MAXBITRATE_RETURN;
		peer_config->recovery_length_min = RIST_DEFAULT_RECOVERY_LENGTH_MIN;
		peer_config->recovery_length_max = RIST_DEFAULT_RECOVERY_LENGTH_MAX;
		peer_config->recovery_reorder_buffer = RIST_DEFAULT_RECOVERY_REORDER_BUFFER;
		peer_config->recovery_rtt_min = RIST_DEFAULT_RECOVERY_RTT_MIN;
		peer_config->recovery_rtt_max = RIST_DEFAULT_RECOVERY_RTT_MAX;
		peer_config->congestion_control_mode = RIST_DEFAULT_CONGESTION_CONTROL_MODE;
		peer_config->min_retries = RIST_DEFAULT_MIN_RETRIES;
		peer_config->max_retries = RIST_DEFAULT_MAX_RETRIES;
		if (version >= 1)
		{
			peer_config->split_mode = LIBRIST_SPLIT_MODE_OFF;
			peer_config->merge_mode = LIBRIST_MERGE_MODE_OFF;
		}
		if (version >= 4)
		{
			peer_config->profile = RIST_DEFAULT_PROFILE;
			peer_config->profile_set = 0;
		}
		if (version >= 5)
		{
			peer_config->recovery_priority = RIST_DEFAULT_RECOVERY_PRIORITY;
			peer_config->recovery_depth = RIST_RECOVERY_DEPTH_DEFAULT;
		}
		if (version >= 6)
		{
			peer_config->rtt_drop = RIST_DEFAULT_RTT_DROP;
			peer_config->rtt_restore = RIST_DEFAULT_RTT_RESTORE;
			peer_config->rtt_drop_settle = RIST_DEFAULT_RTT_DROP_SETTLE;
			peer_config->rtt_drop_trickle = RIST_DEFAULT_RTT_DROP_TRICKLE;
		}
		return 0;
	}
	else
		return -1;
}

/* Legacy API wrapper symbol exported for ABI compatibility.
 * Since pre-existing compiled binaries calling this function do not pass their
 * struct size or compile-time version, we assume version 0 (baseline layout)
 * to guarantee that we never write out-of-bounds on legacy client structures. */
int rist_peer_config_defaults_set(struct rist_peer_config *peer_config)
{
	return rist_peer_config_defaults_set_versioned(peer_config, 0);
}

int rist_parse_address(const char *url, const struct rist_peer_config **peer_config)
{
	return rist_parse_address2(url, (struct rist_peer_config **)peer_config);
}

int rist_parse_address2(const char *url, struct rist_peer_config **peer_config)
{
	if (!url)
		return -1;
	char * url_local = strdup(url);
	int ret = 0;
	if (*peer_config == NULL)
	{
		// Default options on new struct (rist url)
		struct rist_peer_config *output_peer_config = calloc(1, sizeof(struct rist_peer_config));
		rist_peer_config_defaults_set_versioned(output_peer_config, RIST_PEER_CONFIG_VERSION);
		ret = parse_url_options(url_local, output_peer_config);
		*peer_config = output_peer_config;
	}
	else
	{
		// Update incoming object with url data
		struct rist_peer_config *existing_peer_config = (void *)*peer_config;
		ret = parse_url_options(url_local, existing_peer_config);
		*peer_config = existing_peer_config;
	}
	free(url_local);

	return ret;
}


/* Shared functions with specific implementations, implementations first */
static int rist_receiver_peer_create(struct rist_receiver *ctx,
									 struct rist_peer **peer, const struct rist_peer_config *config)
{
	struct rist_peer *p_rtcp;
	struct rist_peer *p = rist_receiver_peer_insert_local(ctx, config);
	if (!p)
		return -1;

	if (config->version >= 1) {
		if (ctx->common.PEERS == NULL) {
			ctx->merge_mode = config->merge_mode;
		} else if (ctx->merge_mode != config->merge_mode) {
			rist_log_priv(&ctx->common, RIST_LOG_WARN,
				"peer added with merge_mode=%u but the receiver is already "
				"running with merge_mode=%u; new peer's merge config ignored\n",
				config->merge_mode, ctx->merge_mode);
		}
	}

	p->peer_ssrc = prand_u32();
	if (ctx->common.profile == RIST_PROFILE_SIMPLE)
	{
		if (p->local_port % 2 != 0)
		{
			rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Could not create peer, port must be even!\n");
			udpsocket_close(p->sd);
			free(p);
			return -1;
		}

		snprintf((char *)config->address, sizeof(config->address), "%s:%d", p->url, p->local_port + 1);
		p_rtcp = rist_receiver_peer_insert_local(ctx, config);
		p_rtcp->peer_ssrc = p->peer_ssrc;
		if (!p_rtcp)
		{
			udpsocket_close(p->sd);
			free(p);
			return -1;
		}
		p_rtcp->is_rtcp = true;
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "Created RTCP peer: host %s, port %d, new_url %s, %" PRIu32 "\n", p_rtcp->url, p_rtcp->local_port, config->address, p_rtcp->adv_peer_id);

		p->peer_rtcp = p_rtcp;
		p_rtcp->peer_data = p;
		peer_append(p_rtcp);
		/* jumpstart communication */
		rist_fsm_init_comm(p_rtcp);
	}
	else
	{
		p->rist_gre_version = RIST_GRE_VERSION_MIN;
		p->is_rtcp = true;
	}

	p->is_data = true;
	peer_append(p);
	/* jumpstart communication */
	rist_fsm_init_comm(p);

	*peer = p;

	return 0;
}

static int rist_sender_peer_create(struct rist_sender *ctx,
								   struct rist_peer **peer, const struct rist_peer_config *config)
{
	struct rist_peer *newpeer = rist_sender_peer_insert_local(ctx, config, false);

	if (!newpeer)
		return -1;

	if (config->version >= 1) {
		if (ctx->peer_lst_len == 0) {
			ctx->split_mode = config->split_mode;
		} else if (ctx->split_mode != config->split_mode) {
			rist_log_priv(&ctx->common, RIST_LOG_WARN,
				"peer added with split_mode=%u but the session is already "
				"running with split_mode=%u; new peer's split config ignored\n",
				config->split_mode, ctx->split_mode);
		}
		if (ctx->split_mode == LIBRIST_SPLIT_MODE_HALF) {
			rist_log_priv(&ctx->common, RIST_LOG_WARN,
				"split=half is active; the receiver MUST be configured with "
				"merge=pairs or merge=auto, otherwise downstream consumers "
				"will see runt payloads.\n");
		}
	}

	// TODO: Validate config data (virt_dst_port != 0 for example)

	newpeer->is_data = true;
	if (config->weight != RIST_PEER_WEIGHT_DUPLICATE)
		newpeer->w_count = config->weight;
	peer_append(newpeer);

	if (ctx->common.profile == RIST_PROFILE_SIMPLE)
	{
		struct rist_peer *peer_rtcp = rist_sender_peer_insert_local(ctx, config, true);
		if (!peer_rtcp)
		{
			rist_peer_remove(&ctx->common, newpeer, NULL);
			return -1;
		}
		peer_rtcp->peer_data = newpeer;
		newpeer->peer_rtcp = peer_rtcp;
		peer_append(peer_rtcp);
		/* jumpstart communication */
		rist_fsm_init_comm(peer_rtcp);
		/* Authenticate right away */
		if (!peer_rtcp->listening)
		{
			sender_peer_append(ctx, peer_rtcp);
			rist_peer_authenticate(peer_rtcp);
		}
	}
	else
	{
		newpeer->rist_gre_version = RIST_GRE_VERSION_MIN;
		newpeer->peer_data = newpeer;
		newpeer->is_rtcp = true;
		newpeer->compression = config->compression;
	}

	/* jumpstart communication */
	rist_fsm_init_comm(newpeer);
	/* Authenticate right away */
	if (!newpeer->listening)
	{
		sender_peer_append(ctx, newpeer);
		rist_peer_authenticate(newpeer);
	}

	*peer = newpeer;

	return 0;
}

/* If config carries a ?profile= request (version >= 4 && profile_set),
 * either apply it to the context (if unlocked and different) or refuse
 * the peer (if locked and different).  Caller must hold peerlist_lock.
 * Returns 0 on success/no-op, -1 on conflict (caller must abort). */
static int apply_url_profile_override(struct rist_common_ctx *cctx,
                                      const struct rist_peer_config *config)
{
	if (config->version < 4 || !config->profile_set)
		return 0;
	if (config->profile == cctx->profile)
		return 0;
	if (atomic_load_explicit(&cctx->profile_locked, memory_order_acquire)) {
		rist_log_priv(cctx, RIST_LOG_WARN,
			"?profile=%d in URL refused: context profile is locked to %d "
			"(rist_start has run or a prior peer fixed the profile).\n",
			(int)config->profile, (int)cctx->profile);
		return -1;
	}
	enum rist_profile old = cctx->profile;
	cctx->profile = config->profile;
	if (config->profile == RIST_PROFILE_ADVANCED && old != RIST_PROFILE_ADVANCED)
		init_advanced_state(cctx);
	rist_log_priv(cctx, RIST_LOG_INFO,
		"Context profile changed from %d to %d by ?profile= URL parameter\n",
		(int)old, (int)config->profile);
	return 0;
}

/* Latch the context-wide CBR output setting; a second request for a different
 * value is refused rather than resolved. Applied after rist_start() too, since
 * flows copy the value as they are created. Caller must hold peerlist_lock.
 * Returns 0 on success or no-op, -1 on conflict. */
static int set_cbr_output_locked(struct rist_common_ctx *cctx, bool want,
                                 const char *origin)
{
	if (cctx->cbr_output_set) {
		if (want == cctx->cbr_output)
			return 0;
		rist_log_priv(cctx, RIST_LOG_ERROR,
			"CBR output pacing %d from %s refused: already set to %d, and a "
			"context's outputs share one release schedule.\n",
			want ? 1 : 0, origin, cctx->cbr_output ? 1 : 0);
		return -1;
	}

	/* Latch even on a value equal to the default, else 0 then 1 both succeed. */
	cctx->cbr_output_set = true;
	if (want == cctx->cbr_output)
		return 0;
	cctx->cbr_output = want;
	rist_log_priv(cctx, RIST_LOG_INFO,
		"CBR output pacing %s by %s\n", want ? "enabled" : "disabled", origin);
	return 0;
}

int rist_receiver_set_cbr_output(struct rist_ctx *rist_ctx, bool enable)
{
	if (RIST_UNLIKELY(!rist_ctx)) {
		rist_log_priv3(RIST_LOG_ERROR,
			"ctx is null on rist_receiver_set_cbr_output call!\n");
		return -1;
	}
	if (RIST_UNLIKELY(rist_ctx->mode != RIST_RECEIVER_MODE ||
	                  !rist_ctx->receiver_ctx)) {
		rist_log_priv3(RIST_LOG_ERROR,
			"rist_receiver_set_cbr_output: CTX not set up for receiving\n");
		return -1;
	}
	struct rist_common_ctx *cctx = &rist_ctx->receiver_ctx->common;
	pthread_mutex_lock(&cctx->peerlist_lock);
	int ret = set_cbr_output_locked(cctx, enable, "rist_receiver_set_cbr_output()");
	pthread_mutex_unlock(&cctx->peerlist_lock);
	return ret;
}

/* If config carries a ?recovery-depth= request (version >= 5 and not
 * DEFAULT), apply it to the context. Best-effort: ignored with a warning if
 * rist_start has run (the sender ring cannot be resized with data in flight)
 * since it must be set up front. Caller must hold peerlist_lock. Runs after
 * apply_url_profile_override so a combined ?profile=2&recovery-depth=5
 * URL sees the Advanced profile already in effect. */
static void apply_url_recovery_depth(struct rist_common_ctx *cctx, struct rist_ctx *ctx,
                                     const struct rist_peer_config *config)
{
	if (config->version < 5 || config->recovery_depth == RIST_RECOVERY_DEPTH_DEFAULT)
		return;
	if (atomic_load_explicit(&cctx->startup_complete, memory_order_acquire)) {
		rist_log_priv(cctx, RIST_LOG_WARN,
			"?recovery-depth in URL ignored: it must be set before rist_start().\n");
		return;
	}
	rist_recovery_depth_apply(ctx, cctx, rist_recovery_depth_to_packets(config->recovery_depth));
}

int rist_peer_create(struct rist_ctx *ctx, struct rist_peer **peer, const struct rist_peer_config *config) {
	if (!ctx) {
		rist_log_priv3(RIST_LOG_ERROR, "rist_peer_create call with null ctx\n");
		return -1;
	}
	int ret = 0;
	struct rist_common_ctx *cctx = NULL;
	if (ctx->mode == RIST_RECEIVER_MODE && ctx->receiver_ctx) {
		cctx = &ctx->receiver_ctx->common;
		pthread_mutex_lock(&cctx->peerlist_lock);
		if (apply_url_profile_override(cctx, config) < 0) {
			pthread_mutex_unlock(&cctx->peerlist_lock);
			return -1;
		}
		apply_url_recovery_depth(cctx, ctx, config);
		ret = rist_receiver_peer_create(ctx->receiver_ctx, peer, config);
	}
	else if (ctx->mode == RIST_SENDER_MODE && ctx->sender_ctx) {
		cctx = &ctx->sender_ctx->common;
		pthread_mutex_lock(&cctx->peerlist_lock);
		if (apply_url_profile_override(cctx, config) < 0) {
			pthread_mutex_unlock(&cctx->peerlist_lock);
			return -1;
		}
		apply_url_recovery_depth(cctx, ctx, config);
		ret  =rist_sender_peer_create(ctx->sender_ctx, peer, config);
	}
	else
		return -1;
	if (ret == 0)
		atomic_store_explicit(&cctx->profile_locked, true, memory_order_release);
	pthread_mutex_unlock(&cctx->peerlist_lock);
	return ret;
}

int rist_peer_get_socket(struct rist_peer *peer, int *socket, int *socket_extra) {
	if (peer == NULL || socket == NULL)
		return -1;
	if (peer->parent != NULL)
		return -1;
	*socket = peer->sd;
	int ret = 0;
	if (socket_extra != NULL && get_cctx(peer)->profile == RIST_PROFILE_SIMPLE) {
		*socket_extra = peer->peer_rtcp->sd;
		ret = 1;
	}
	return ret;
}

int rist_peer_weight_set(struct rist_ctx *ctx, struct rist_peer *peer, const uint32_t weight)
{
	if (!ctx)
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_peer_weight_set call with null ctx\n");
		return -1;
	}

	if (peer->parent != NULL)
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_peer_weight_set cannot be applied to peer with parent\n");
		return -1;
	}

	if (ctx->mode == RIST_RECEIVER_MODE && ctx->receiver_ctx)
	{
		struct rist_receiver *rctx = ctx->receiver_ctx;
		pthread_mutex_lock(&rctx->common.peerlist_lock);
		peer->config.weight = weight;
		peer->w_count = weight;
		pthread_mutex_unlock(&rctx->common.peerlist_lock);
	}
	else if (ctx->mode == RIST_SENDER_MODE && ctx->sender_ctx)
	{
		struct rist_sender *sctx = ctx->sender_ctx;
		pthread_mutex_lock(&sctx->mutex);
		pthread_mutex_lock(&sctx->common.peerlist_lock);
		uint32_t cur_weight = peer->config.weight;
		peer->config.weight = weight;
		if ((peer->listening && peer->child != NULL) || !peer->listening) {
			sctx->total_weight -= cur_weight;
			peer->w_count = peer->config.weight;
			sctx->total_weight += peer->config.weight;
		}
		pthread_mutex_unlock(&sctx->common.peerlist_lock);
		pthread_mutex_unlock(&sctx->mutex);
	}
	else
		return -1;

	return 0;
}

int rist_peer_destroy(struct rist_ctx *ctx, struct rist_peer *peer) {
	if (!ctx) {
		rist_log_priv3(RIST_LOG_ERROR, "rist_peer_destroy call with null ctx\n");
		return -1;
	}
	struct rist_common_ctx *cctx = NULL;
	if (ctx->mode == RIST_RECEIVER_MODE && ctx->receiver_ctx)
		cctx = &ctx->receiver_ctx->common;
	else if (ctx->mode == RIST_SENDER_MODE && ctx->sender_ctx)
		cctx = &ctx->sender_ctx->common;
	else
		return -1;
	assert(cctx != NULL);
	pthread_mutex_lock(&cctx->peerlist_lock);
	int ret = rist_peer_remove(cctx, peer, NULL);
	pthread_mutex_unlock(&cctx->peerlist_lock);
	return ret;
}

static PTHREAD_START_FUNC(sender_data_fd_read_loop, arg)
{
	struct rist_sender *ctx = (struct rist_sender *)arg;
	struct rist_ctx sender_wrapper = { .mode = RIST_SENDER_MODE, .sender_ctx = ctx, .receiver_ctx = NULL };
	const size_t bufsize = ctx->data_fd_max_packet_size > 0 ? ctx->data_fd_max_packet_size : 1500;
	uint8_t *buf = malloc(bufsize);
	if (!buf)
		return 0;

	const bool is_tun = (ctx->data_fd_flags & RIST_DATA_FD_FLAG_TUN) != 0;

#if defined(__unix) || defined(__APPLE__)
	struct pollfd pfd = { .fd = ctx->data_fd, .events = POLLIN };
#endif

	while (!atomic_load_explicit(&ctx->common.shutdown, memory_order_acquire)) {
#if defined(__unix) || defined(__APPLE__)
		int ret = poll(&pfd, 1, 100);
		if (ret <= 0)
			continue;
#endif
		int nread;
		if (is_tun)
			nread = rist_tun_read(ctx->data_fd, buf, bufsize);
		else
			nread = (int)read(ctx->data_fd, buf, bufsize);

		if (nread <= 0)
			continue;

		struct rist_data_block data_block = {0};
		data_block.payload = buf;
		data_block.payload_len = nread;
		int sent = rist_sender_data_write(&sender_wrapper, &data_block);
		if (sent > 0) {
			atomic_fetch_add_explicit(&ctx->data_fd_tx_packets, 1, memory_order_relaxed);
			atomic_fetch_add_explicit(&ctx->data_fd_tx_bytes, (uint_fast64_t)nread, memory_order_relaxed);
		}
	}

	free(buf);
	return 0;
}

static int rist_sender_start(struct rist_sender *ctx)
{
	atomic_store_explicit(&ctx->common.profile_locked, true, memory_order_release);
	pthread_mutex_lock(&ctx->mutex);
	if (!ctx->protocol_running) {
		if (rist_thread_create(&ctx->common, &ctx->sender_thread, NULL, sender_pthread_protocol, (void *)ctx) != 0)
		{
			rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Could not created sender thread.\n");
			goto unlock_failed;
		}
		ctx->protocol_running = true;

		if (ctx->data_fd >= 0) {
			if (pthread_create(&ctx->data_fd_thread, NULL, sender_data_fd_read_loop, (void *)ctx) != 0) {
				rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Could not create data fd reader thread.\n");
				goto unlock_failed;
			}
			ctx->data_fd_thread_started = true;
		}
	} else {
		goto unlock_failed;
	}
	if (ctx->total_weight > 0)
	{
		ctx->weight_counter = ctx->total_weight;
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "Total weight: %lu\n", ctx->total_weight);
	}
	atomic_store_explicit(&ctx->common.startup_complete, true, memory_order_release);

	pthread_mutex_unlock(&ctx->mutex);
	return 0;

unlock_failed:
	pthread_mutex_unlock(&ctx->mutex);
	return -1;
}

static int rist_receiver_start(struct rist_receiver *ctx)
{
	atomic_store_explicit(&ctx->common.profile_locked, true, memory_order_release);
	pthread_mutex_lock(&ctx->mutex);
	if (!ctx->protocol_running)
	{
		if (rist_thread_create(&ctx->common, &ctx->receiver_thread, NULL, receiver_pthread_protocol, (void *)ctx) != 0)
		{
			rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Could not create receiver protocol thread.\n");
			goto unlock_failed;
		}
		ctx->protocol_running = true;
	} else {
		goto unlock_failed;
	}

	pthread_mutex_unlock(&ctx->mutex);
	return 0;

unlock_failed:
	pthread_mutex_unlock(&ctx->mutex);
	return -1;
}

int rist_start(struct rist_ctx *ctx) {
	if (!ctx) {
		rist_log_priv3(RIST_LOG_ERROR, "rist_start call with null ctx\n");
		return -1;
	}
	if (ctx->mode == RIST_RECEIVER_MODE && ctx->receiver_ctx)
		return rist_receiver_start(ctx->receiver_ctx);
	else if (ctx->mode == RIST_SENDER_MODE && ctx->sender_ctx)
		return rist_sender_start(ctx->sender_ctx);
	else
		return -1;
}

static int rist_sender_destroy(struct rist_sender *ctx)
{
	if (!ctx)
	{
		return -1;
	}

	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Triggering protocol loop termination\n");
	atomic_store_explicit(&ctx->common.shutdown, 1, memory_order_release);

	if (ctx->data_fd_thread_started)
		pthread_join(ctx->data_fd_thread, NULL);

	pthread_mutex_lock(&ctx->mutex);
	bool running = ctx->protocol_running;
	pthread_mutex_unlock(&ctx->mutex);
	if (running)
		pthread_join(ctx->sender_thread, NULL);
	rist_sender_destroy_local(ctx);

	return 0;
}

static int rist_receiver_destroy(struct rist_receiver *ctx)
{
	if (!ctx)
	{
		return -1;
	}

	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Triggering protocol loop termination\n");
	atomic_store_explicit(&ctx->common.shutdown, 1, memory_order_release);
	pthread_mutex_lock(&ctx->mutex);
	bool running = ctx->protocol_running;
	pthread_mutex_unlock(&ctx->mutex);
	if (running)
		pthread_join(ctx->receiver_thread, NULL);
	rist_receiver_destroy_local(ctx);

	return 0;
}

int rist_destroy(struct rist_ctx *ctx) {
	if (!ctx) {
		rist_log_priv3(RIST_LOG_ERROR, "rist_destroy call with null ctx\n");
		return -1;
	}
	if (ctx->mode == RIST_RECEIVER_MODE && ctx->receiver_ctx)
		rist_receiver_destroy(ctx->receiver_ctx);
	else if (ctx->mode == RIST_SENDER_MODE && ctx->sender_ctx)
		rist_sender_destroy(ctx->sender_ctx);
	else
		return -1;
	free(ctx);
	return 0;
}

/* Data fd tunnel API */

int rist_sender_data_fd_set(struct rist_ctx *rist_ctx, int fd,
                            size_t max_packet_size, uint32_t flags)
{
	if (RIST_UNLIKELY(!rist_ctx)) {
		rist_log_priv3(RIST_LOG_ERROR, "ctx is null on rist_sender_data_fd_set call!\n");
		return -1;
	}
	if (RIST_UNLIKELY(rist_ctx->mode != RIST_SENDER_MODE || !rist_ctx->sender_ctx)) {
		rist_log_priv3(RIST_LOG_ERROR, "rist_sender_data_fd_set call with CTX not set up for sending\n");
		return -1;
	}
	struct rist_sender *ctx = rist_ctx->sender_ctx;
	ctx->data_fd = fd;
	ctx->data_fd_max_packet_size = max_packet_size;
	ctx->data_fd_flags = flags;
	return 0;
}

int rist_receiver_data_fd_set(struct rist_ctx *rist_ctx, int fd, uint32_t flags)
{
	if (RIST_UNLIKELY(!rist_ctx)) {
		rist_log_priv3(RIST_LOG_ERROR, "ctx is null on rist_receiver_data_fd_set call!\n");
		return -1;
	}
	if (RIST_UNLIKELY(rist_ctx->mode != RIST_RECEIVER_MODE || !rist_ctx->receiver_ctx)) {
		rist_log_priv3(RIST_LOG_ERROR, "rist_receiver_data_fd_set call with CTX not set up for receiving\n");
		return -1;
	}
	struct rist_receiver *ctx = rist_ctx->receiver_ctx;
	ctx->receiver_data_fd = fd;
	ctx->receiver_data_fd_flags = flags;
	return 0;
}

int rist_data_fd_stats_get(struct rist_ctx *ctx, struct rist_data_fd_stats *stats)
{
	if (RIST_UNLIKELY(!ctx || !stats))
		return -1;

	memset(stats, 0, sizeof(*stats));

	if (ctx->mode == RIST_SENDER_MODE && ctx->sender_ctx) {
		stats->tx_packets = atomic_load_explicit(&ctx->sender_ctx->data_fd_tx_packets, memory_order_relaxed);
		stats->tx_bytes = atomic_load_explicit(&ctx->sender_ctx->data_fd_tx_bytes, memory_order_relaxed);
	} else if (ctx->mode == RIST_RECEIVER_MODE && ctx->receiver_ctx) {
		stats->rx_packets = atomic_load_explicit(&ctx->receiver_ctx->data_fd_rx_packets, memory_order_relaxed);
		stats->rx_bytes = atomic_load_explicit(&ctx->receiver_ctx->data_fd_rx_bytes, memory_order_relaxed);
	} else {
		return -1;
	}
	return 0;
}

int rist_receiver_set_output_fifo_size(struct rist_ctx *ctx, uint32_t desired_size)
{
	if (!ctx)
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_receiver_set_fifo_size called with null ctx\n");
		return -1;
	}
	if (ctx->mode != RIST_RECEIVER_MODE || !ctx->receiver_ctx)
	{
		rist_log_priv3(RIST_LOG_ERROR, "rist_receiver_set_fifo_size can only be called on receiver\n");
		return -2;
	}
	if (ctx->receiver_ctx->receiver_thread)
	{
		rist_log_priv2(ctx->receiver_ctx->common.logging_settings, RIST_LOG_ERROR, "rist_receiver_set_fifo_size must be called before starting\n");
		return -3;
	}
	if (desired_size == 0 || desired_size > 65536)
	{
		rist_log_priv2(ctx->receiver_ctx->common.logging_settings, RIST_LOG_ERROR, "Desired fifo size must be between 1 and 65536\n");
		return -4;
	}
	if ((desired_size & (desired_size -1)) != 0)
	{
		rist_log_priv2(ctx->receiver_ctx->common.logging_settings, RIST_LOG_ERROR, "Desired fifo size must be a power of 2\n");
		return -4;
	}
	ctx->receiver_ctx->fifo_queue_size = desired_size;
	return 0;
}

int rist_set_opt(struct rist_ctx *ctx, enum rist_opt opt, void* optval1, void* optval2, void* optval3)
{
	struct rist_common_ctx *cctx = NULL;
	if (ctx->mode == RIST_RECEIVER_MODE && ctx->receiver_ctx != NULL)
		cctx = &ctx->receiver_ctx->common;
	else if (ctx->mode == RIST_SENDER_MODE && ctx->sender_ctx != NULL)
		cctx = &ctx->sender_ctx->common;
	else
		return -1;

	switch(opt) {
	case RIST_OPT_THREAD_CALLBACK:
		;
		rist_thread_callback_t *thread_callback  = optval1;
		if (thread_callback == NULL || thread_callback->thread_callback == NULL || optval3 != NULL)
			return -1;
		if (atomic_load_explicit(&cctx->startup_complete, memory_order_acquire))
			return -1;
		cctx->thread_callback = thread_callback->thread_callback;
		cctx->thread_callback_arg = optval2;
		break;
	default:
		return -1;
	}
	return 0;
}
