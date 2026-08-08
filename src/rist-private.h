/* librist. Copyright © 2019-2020 SipRadius LLC. All right reserved.
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef RIST_RIST_PRIVATE_H
#define RIST_RIST_PRIVATE_H

#include "common/attributes.h"

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "stdio-shim.h"
#include <fcntl.h>
#include <inttypes.h>
#include <stddef.h>
#include "time-shim.h"
#include "pthread-shim.h"
#include "socket-shim.h"
#include "rist_pacer.h"
#include "libevsocket.h"
#include "librist.h"
#include "librist/transport.h"
#include "udpsocket.h"
#include "crypto/psk.h"
#include <errno.h>
#include <stdatomic.h>
#include "librist/logging.h"
#include "proto/gre.h"
#include "proto/adv.h"
#include "rist-adv-ts.h"
#include "rist-reanchor.h"
#include "rist-send-grace.h"
#include "rist-bandwidth-guard.h"
#include "rist-rtt-mute.h"

struct cJSON;

#undef RIST_DEPRECATED

#define UINT16_SIZE (UINT16_MAX + 1)

/* Forward sequence-number gap. short_seq (Simple/Main) flows wrap at 16 bits;
 * full 32-bit (Advanced) flows use the true difference so a genuine >64k gap is
 * not truncated. Inputs are modular counters, so the subtraction is unsigned
 * (well-defined wrap) before the optional 16-bit mask. */
static inline uint32_t rist_seq_gap(uint32_t current, uint32_t last,
                                    bool short_seq)
{
	uint32_t gap = current - last;
	return short_seq ? (gap & UINT16_MAX) : gap;
}

/* Next expected sequence number after `last`. short_seq (Simple/Main) flows
 * wrap at 16 bits; 32-bit (Advanced) flows use the natural successor. */
static inline uint32_t rist_seq_next(uint32_t last, bool short_seq)
{
	uint32_t next = last + 1;
	return short_seq ? (next & UINT16_MAX) : next;
}

// These control the memory footprint and buffer capacity of the lib
// They MUST be a power of two or wrap-around index calculations will break
// RIST_SERVER_QUEUE_BUFFERS is the DEFAULT Advanced-profile recovery-ring
// capacity (in packets), == UINT16_SIZE << RIST_RECOVERY_DEPTH_DEFAULT (8x).
// The ring is heap-allocated per flow/sender and can be resized at runtime to
// UINT16_SIZE << depth via rist_recovery_depth_set() / ?recovery-depth=, up to
// RIST_RECOVERY_QUEUE_MAX (depth 16, the full 32-bit space). Large depths are
// limited by available RAM. Simple/Main are always UINT16_SIZE.
#define RIST_SERVER_QUEUE_BUFFERS ((UINT16_SIZE) * 8)
#define RIST_RECOVERY_QUEUE_MAX ((uint64_t)(UINT16_SIZE) << 16)
#define RIST_RETRY_QUEUE_BUFFERS ((UINT16_SIZE) * 4)
#define RIST_OOB_QUEUE_BUFFERS ((UINT16_SIZE) * 2)
#define RIST_DATAOUT_QUEUE_BUFFERS (1024)
// This will restrict the use of the library to the configured maximum packet size
#define RIST_MAX_PACKET_SIZE (10000)
#define RIST_RTT_MIN (3)

/* nack requests are sent every time a data packet is received. */
/* this timer will be triggered to ensure we output nacks even when there is no data coming in */
#define RIST_MAX_JITTER (5) /* In milliseconds */

/* Bounds on the output loop's wake interval when CBR pacing is on, trading CPU
 * against spacing: residual burst is ceil(floor / datagram interval). The working
 * floor tracks the measured interval and is clamped to these. */
#define RIST_CBR_OUTPUT_MIN_US_DEFAULT (250)
#define RIST_CBR_OUTPUT_MIN_US_FLOOR (20)
/* Pacing gives way once a packet is this far past its release deadline, so it can
 * never age a packet out of the recovery buffer. A floor: the working value has to
 * cover a burst's drain time, which the output jitter ceiling bounds. */
#define RIST_CBR_MAX_HOLD_US (1000)
#define RIST_CBR_HOLD_JITTER_MULT (2)

static inline uint32_t rist_cbr_hold_us(uint32_t max_output_jitter_ms)
{
	uint32_t hold = RIST_CBR_HOLD_JITTER_MULT * max_output_jitter_ms * 1000;
	return hold > RIST_CBR_MAX_HOLD_US ? hold : RIST_CBR_MAX_HOLD_US;
}
#define RIST_PING_INTERVAL (100)  /* In milliseconds, how long to space ping requests */
/* Missed RTCP/ping intervals before a bonded leg is pulled from the rotation
 * (fast, reversible); kept well under the liveness timeout, the real teardown. */
#define RIST_STALL_MUTE_PINGS (3)
/* Floor for the per-peer liveness timeout, in missed RTCP/ping intervals. */
#define RIST_LIVENESS_MIN_PINGS (4)
/* How much better a sibling must measure before it takes the sole-carrier role
 * from the incumbent, as a divisor of the incumbent's smoothed RTT. */
#define RIST_SOLE_CARRIER_MARGIN (2)
#define RIST_PBKDF2_HMAC_SHA256_ITERATIONS (1024)
#define RIST_AES_KEY_REUSE_TIMES UINT32_MAX
#define RIST_MAX_HOSTNAME (128)
#define RTCP_FB_FCI_GENERIC_NACK_SIZE (4)
#define RIST_MAX_NACKS (200)
#define RIST_MAX_NACKS_BYTES RIST_MAX_NACKS*RTCP_FB_FCI_GENERIC_NACK_SIZE
// Maximum offset before the payload that the code can use to put in headers
//#define RIST_MAX_PAYLOAD_OFFSET (sizeof(struct rist_gre_key_seq) + sizeof(struct rist_protocol_hdr))
#define RIST_MAX_HEADER_SIZE 32
#define CHECK_BIT(var,pos) !!((var) & (1<<(pos)))

#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)  \
	(byte & 0x80 ? '1' : '0'), \
	(byte & 0x40 ? '1' : '0'), \
	(byte & 0x20 ? '1' : '0'), \
	(byte & 0x10 ? '1' : '0'), \
	(byte & 0x08 ? '1' : '0'), \
	(byte & 0x04 ? '1' : '0'), \
	(byte & 0x02 ? '1' : '0'), \
	(byte & 0x01 ? '1' : '0')

#define STALE_FLOW_TIME (60L * 1000L * RIST_CLOCK) /* in milliseconds */

enum rist_peer_state {
	RIST_PEER_STATE_IDLE = 0,
	RIST_PEER_STATE_PING = 1,
	RIST_PEER_STATE_CONNECT = 2
};
struct rist_buffer {
	void *data;
	size_t size;
	uint8_t type;
	uint16_t src_port;
	uint16_t dst_port;
	uint64_t source_time;
	int8_t use_seq;
	uint32_t seq;
	uint16_t seq_rtp;

	uint64_t time;//Time we received the packet
	uint64_t packet_time;//Timestamp based on the RTP time of the packet
	uint64_t target_output_time;//packet_time + buffer

	uint8_t fragment_number;
	uint8_t fragment_final;
	// TODO: These four are only used by sender ... do I split buffer into sender and receiver?
	uint64_t last_retry_request;
	uint8_t transmit_count;
	uint16_t ts_null_bytes;
	struct rist_peer *peer;

	struct rist_buffer *next_free;
	size_t alloc_size;
	bool free;
	bool retry_queued;
};

/* Largest recovery depth whose ring (UINT16_SIZE << depth packets) is
 * addressable as size_t: the two parallel index arrays cost
 * sizeof(ptr) + sizeof(uint32_t) per slot. Depth 16 (2^32) only fits a 64-bit
 * size_t; on a 32-bit size_t the exponent is reduced until it fits. Shared with
 * the recovery-depth unit test. */
static inline int rist_recovery_depth_platform_max(void)
{
	const uint64_t per = (uint64_t)sizeof(struct rist_buffer *) + sizeof(uint32_t);
	const uint64_t limit = (uint64_t)SIZE_MAX / per;
	int depth = RIST_RECOVERY_DEPTH_MAX;
	while (depth > RIST_RECOVERY_DEPTH_MIN &&
	       ((uint64_t)UINT16_SIZE << depth) > limit)
		depth--;
	return depth;
}

struct rist_missing_buffer {
	uint32_t seq;
	uint64_t next_nack;
	uint64_t insertion_time;
	uint32_t nack_count;
	struct rist_peer *peer;
	struct rist_missing_buffer *next;
};

struct rist_bandwidth_estimation {
	size_t bytes;
	size_t bytes_fast;
	uint64_t last_bitrate_calctime;
	uint64_t last_bitrate_calctime_fast;
	size_t eight_times_bitrate_fast;
	size_t eight_times_bitrate;
	size_t bitrate;
	size_t bitrate_fast;
};

struct rist_peer_flow_stats {
	uint32_t lost;
	uint32_t received;
	uint32_t dupe;
	uint32_t dropped_full;
	uint32_t dropped_late;
	size_t buffer_duration_count;
	uint32_t buffer_duration[2048];

	uint32_t missing;
	uint32_t retries;
	uint32_t recovered;
	uint32_t reordered;
	uint32_t dups;
	uint32_t recovered_0nack;
	uint32_t recovered_1nack;
	uint32_t recovered_2nack;
	uint32_t recovered_3nack;
	uint32_t recovered_morenack;
	uint32_t recovered_sum;
	uint32_t recovered_average;
	int32_t  recovered_slope;
	uint32_t recovered_slope_inverted;

	/* Inter-packet spacing */
	uint64_t min_ips;
	uint64_t max_ips;
	uint64_t cur_ips;
	uint32_t avg_count;
	uint64_t total_ips;

	/* Per-byte counters */
	uint64_t received_bytes;
};

struct rist_peer_sender_stats {
	uint64_t sent;
	uint32_t received;
	uint32_t retrans;
	uint32_t bloat_skip;
	uint32_t bandwidth_skip;
	uint32_t retrans_skip;
	uint64_t ts_null;
	uint64_t sent_bytes;
	uint64_t retransmitted_bytes;
};

struct rist_peer_receiver_stats {
	uint32_t sent_rtcp;
	uint32_t received_rtcp;
	uint64_t received;
	uint64_t ts_null;
	uint64_t received_bytes;
};

struct nacks {
	uint32_t array[RIST_MAX_NACKS];
	size_t counter;
};

struct rist_flow {
	atomic_int shutdown;
	int max_output_jitter;

	struct rist_buffer **receiver_queue; /* output queue, heap-allocated to receiver_queue_max */

	pthread_rwlock_t queue_lock;

	bool receiver_queue_has_items;
	bool flow_auto_buffer_scaling;
	bool currently_scaling_buffer;
	atomic_ulong receiver_queue_size;  /* size in bytes */
	uint64_t recovery_buffer_ticks;    /* size in ticks */
	uint64_t stats_report_time; 	   /* in ticks */
	atomic_ulong receiver_queue_output_idx;  /* next packet to output */
	size_t receiver_queue_max;
	bool flag_flow_buffer_start;

	/* Constant-bitrate output pacing; see rist_pacer.h. cbr_arrived_bytes is
	 * written by the receive threads and drained by the output thread: the
	 * estimate must come from arrivals, since measuring the paced output would
	 * make the rate an output of itself. */
	bool cbr_output;
	uint32_t cbr_output_min_us;
	atomic_uint_least64_t cbr_arrived_bytes;
	uint64_t cbr_arrived_seen;
	struct rist_pacer_rate cbr_rate;
	struct rist_pacer cbr_pacer;
	uint64_t cbr_overdue_releases;   /* pacer yielded to the buffer deadline */
	uint32_t cbr_max_hold_us;        /* longest a paced packet may wait */
	bool cbr_paced_hold;             /* last output pass stopped on the pacer */
	uint64_t cbr_interval_ns;        /* last paced interval, sizes the wake floor */

	/* Missing incoming packets, waiting for retransmission */
	struct rist_missing_buffer *missing;
	struct rist_missing_buffer *missing_tail;
	uint32_t missing_counter;

	struct rist_peer_flow_stats stats_instant;
	struct rist_peer_flow_stats stats_total;//TODO: use the total stats!
	struct rist_bandwidth_estimation bw;
	struct rist_bandwidth_estimation bw_tsnull;
	struct rist_bandwidth_estimation bw_rejected;
	struct rist_bandwidth_estimation bw_retries;
	uint64_t stats_next_time;
	uint64_t checks_next_time;

	/* Missing queue max size */
	uint32_t missing_counter_max;

	uint32_t flow_id;
	uint32_t flow_id_actual;
	int dead;
	struct rist_flow *next;
	struct rist_peer **peer_lst;
	size_t peer_lst_len;
	uint32_t last_seq_output;
	uint64_t last_seq_output_source_time;
	uint32_t last_seq_found;
	intptr_t receiver_id;
	intptr_t sender_id;
	uint64_t last_ipstats_time;
	uint64_t last_output_time;
	uint64_t max_source_time;
	uint64_t too_late_ctr;
	/* When we started holding off a re-anchor for want of a current packet.
	 * Zero while not holding off. */
	uint64_t reanchor_wait_since;

	size_t offset_recalc_sample_count;
	uint64_t offset_recalc_samples[2048];

	int64_t time_offset;//Current offset between our clock and RTP packets.
	int64_t time_offset_old;//Old offset between our clock and RTP packets.
	uint64_t time_offset_changed_ts;//Timestamp the RTP counter last wrapped
	uint64_t last_packet_ts;//Last packet time
	bool rtc_timing_mode;

	bool authenticated;

	/* Receiver thread variables */
	pthread_t receiver_thread;
	bool receiver_thread_running;
	/* data out thread signaling */
	pthread_cond_t condition;
	pthread_mutex_t mutex;

	/* variable used for seq number length (16bit or 32bit) */
	bool short_seq;

	/* Scope-B merge auto-detection: set by keepalive L bit */
	bool merge_auto_enabled;

	/* Session timeouts variables */
	uint64_t session_timeout;
	uint64_t flow_timeout;
	uint64_t last_recv_ts;

	/* Receiver timed async data output */
	struct rist_data_block **dataout_fifo_queue;
	size_t dataout_fifo_queue_bytesize;
	atomic_ulong dataout_fifo_queue_read_index;
	atomic_ulong dataout_fifo_queue_write_index;
	atomic_bool fifo_overflow;

	/* Temporary buffer for grouping and sending nacks */
	struct nacks nacks;
	struct rist_logging_settings *logging_settings;
};

struct rist_retry {
	struct rist_peer *peer;
	uint64_t insert_time;
	uint32_t seq;
	bool active;//signal whether this retry has been consumed (false) or not
};

struct rist_common_ctx {
	atomic_int shutdown;
	atomic_bool startup_complete;

	/* Used by logging */
	intptr_t sender_id;
	intptr_t receiver_id;
	struct rist_logging_settings *logging_settings;


	/* Flows */
	struct rist_flow *FLOWS;
	pthread_mutex_t flows_lock;

	/* evsocket */
	struct evsocket_ctx *evctx;

	/* Timers */
	int rist_max_jitter;
	/* CBR output pacing, per context: a flow's legs share one output, so this is
	 * not a per-peer property. */
	bool cbr_output;
	bool cbr_output_set;   /* a value was stated; later conflicts refused */
	uint32_t cbr_output_min_us;

	/* Recovery buffer RTT multiplier (default 7, per RIST spec) */
	int recovery_rtt_multiplier;

	/* Advanced-profile recovery-ring capacity in packets (power of two).
	 * Default RIST_SERVER_QUEUE_BUFFERS; tunable before rist_start() via
	 * rist_recovery_depth_set(). Simple/Main ignore this and use
	 * UINT16_SIZE. */
	size_t recovery_queue_max;

	/* Peer list sync - RW locks */
	struct rist_peer *PEERS;
	pthread_mutex_t peerlist_lock;

	/* buffers */
	/* these are pre-allocated buffers, not pre-allocated aligned stack */
	struct {
		uint8_t enc[RIST_MAX_PACKET_SIZE];
		uint8_t dec[RIST_MAX_PACKET_SIZE];
		uint8_t recv[RIST_MAX_PACKET_SIZE];
		uint8_t recv_npd[RIST_MAX_PACKET_SIZE];
		uint8_t rtcp[RIST_MAX_PACKET_SIZE];
	} buf;
	struct rist_buffer *rist_free_buffer;
	pthread_mutex_t rist_free_buffer_mutex;
	uint64_t rist_free_buffer_count;

	/* timers */
	uint64_t nacks_next_time;
	uint64_t stats_report_time;

	enum rist_profile profile;
	/* Set by rist_*_start() and by rist_peer_create() once a peer with
	 * a definite profile has been inserted.  When set, rist_peer_create
	 * refuses any peer whose ?profile= disagrees with cctx->profile. */
	atomic_bool profile_locked;
	uint8_t cname[RIST_MAX_HOSTNAME];

	/* seq variables */
	uint32_t seq;
	uint16_t seq_rtp;

	/* Advanced Profile (TR-06-3) state */
	uint32_t adv_ssrc_base;       /* Even SSRC for Protected flow */
	uint32_t adv_seq_protected;   /* 32-bit seq counter for even SSRC */
	uint32_t adv_seq_unprotected; /* 32-bit seq counter for odd SSRC */

	/* Peer counter (only the ones created by the API) */
	uint32_t peer_counter;

	/* Auth callback variables */
	struct {
		int (*conn_cb)(void *arg, const char* connecting_ip, uint16_t connecting_port, const char* local_ip, uint16_t local_port, struct rist_peer *peer);
		int (*disconn_cb)(void *arg, struct rist_peer *peer);
		void *arg;
	} auth;

	/* Out-of-band data variables */
	int (*oob_data_callback)(void *arg, const struct rist_oob_block *oob_block);
	void *oob_data_callback_argument;
	bool oob_data_enabled;
	struct rist_peer *oob_current_peer;

	int (*stats_callback)(void *arg, const struct rist_stats *stats_container);
	void *stats_callback_argument;
	pthread_mutex_t stats_lock;

	pthread_rwlock_t oob_queue_lock;
	struct rist_buffer *oob_queue[RIST_OOB_QUEUE_BUFFERS]; /* oob transmit queue */
	size_t oob_queue_bytesize;
	uint16_t oob_queue_read_index;
	uint16_t oob_queue_write_index;

	/* oob receive fifo: populated by the protocol thread when oob is
	 * enabled but no callback is set, drained by rist_oob_read(). */
	struct rist_buffer *oob_rx_queue[RIST_OOB_QUEUE_BUFFERS];
	uint16_t oob_rx_queue_read_index;
	uint16_t oob_rx_queue_write_index;
	struct rist_buffer *oob_rx_current; /* backs the block handed out by the last rist_oob_read */
	struct rist_oob_block oob_rx_block; /* borrowed view returned to the caller */

	bool debug;
	uint32_t birthtime_rtp_offset;

	/* Pluggable transport (default: POSIX sockets) */
	struct rist_transport_ops transport;
	bool transport_active;

	/* Connection status callback */
	connection_status_callback_t connection_status_callback;
	void *connection_status_callback_argument;
	rist_srp_auth_callback_t srp_auth_callback;
	void *srp_auth_callback_argument;
	receiver_flow_authorize_callback_t receiver_flow_authorize_callback;
	void *receiver_flow_authorize_callback_argument;

	rist_thread_callback_func_t thread_callback;
	void *thread_callback_arg;
};

struct rist_receiver {
	/* data out thread signaling for fifo */
	pthread_cond_t condition;
	pthread_mutex_t mutex;

	/* Receiver data callback */
	receiver_data_callback2_t receiver_data_callback;
	void *receiver_data_callback_argument;
	int receiver_data_ready_notify_fd;

	/* Data fd output (tunnel mode) — write received data directly to fd */
	int receiver_data_fd;
	uint32_t receiver_data_fd_flags;
	atomic_uint_fast64_t data_fd_rx_packets;
	atomic_uint_fast64_t data_fd_rx_bytes;

	/* Receiver session timeout callback */
	receiver_session_timeout_callback_t receiver_session_timeout_callback;
	void *receiver_session_timeout_callback_argument;

	/* Receiver flow attribute callback (Advanced Profile CI=0x8001) */
	receiver_flow_attr_callback_t receiver_flow_attr_callback;
	void *receiver_flow_attr_callback_argument;

	/* Receiver thread variables */
	bool protocol_running;
	pthread_t receiver_thread;

	/* Reporting id */
	intptr_t id;

	/* Common stuff */
	struct rist_common_ctx common;

	enum rist_nack_type nack_type;

	bool simulate_loss;
	uint16_t loss_percentage;
	uint32_t fifo_queue_size;

	uint32_t merge_mode;
	uint64_t stats_pairs_merged;
	uint64_t stats_orphan_first_delivered;
	uint64_t stats_orphan_last_delivered;
};

struct rist_sender {
	/* Advertised flow for this context */
	uint32_t adv_flow_id;

	/* max bitrate of all sender peers (sets the buffer size on sender queue) */
	uint32_t recovery_maxbitrate_max;
	uint32_t max_nacksperloop;
	bool null_packet_suppression;

	uint32_t split_mode;
	uint64_t stats_pairs_emitted;
	uint64_t stats_split_fallback_not_ts;

	/* Sender thread variables */
	bool protocol_running;
	pthread_t sender_thread;
	/* data/nacks out thread signaling */
	pthread_cond_t condition;
	pthread_mutex_t mutex;

	bool sender_initialized;
	uint32_t total_weight;
	struct rist_buffer **sender_queue; /* input queue, heap-allocated to sender_queue_max */
	size_t sender_queue_bytesize;
	size_t sender_queue_size;
	size_t sender_queue_timelength;
	size_t sender_buffer_size;           /* dynamic buffer size for retry window */
	size_t sender_queue_delete_index;
	atomic_ulong sender_queue_read_index;
	atomic_ulong sender_queue_write_index;
	size_t sender_queue_max;
	int weight_counter;
	uint64_t last_datagram_time;
	bool simulate_loss;
	uint16_t loss_percentage;
	uint64_t stats_next_time;
	uint64_t checks_next_time;
	uint32_t session_timeout;

	/* retry queue */
	struct rist_retry *sender_retry_queue;
	size_t sender_retry_queue_write_index;
	size_t sender_retry_queue_read_index;
	size_t sender_retry_queue_size;
	uint64_t cooldown_time;
	int cooldown_mode;

	/* Recovery - heap-allocated to sender_queue_max so Advanced Profile
	 * can index with the full 32-bit seq space (seq & (queue_max - 1)). */
	uint32_t *seq_index;
	/* Parallel 16-bit-RTP index (65536 entries), allocated only for an
	 * Advanced-context sender. A peer that negotiated down to Main NACKs in
	 * the 16-bit RTP sequence domain (nack_seq_msb = 0), which never matches
	 * the 32-bit advanced seq_index; this lets the Advanced sender still find
	 * and retransmit the requested packet for that peer. NULL on Main/Simple
	 * senders (their primary seq_index is already the 16-bit domain). */
	uint32_t *seq_rtp_index;
	size_t sender_recover_min_time;
	size_t sender_queue_buffer_size;

	/* Reporting id */
	intptr_t id;

	/* flow_id time-related */
	struct timeval time;

	/* Common stuff */
	struct rist_common_ctx common;

	/* Peer tracking */
	struct rist_peer **peer_lst;
	size_t peer_lst_len;

	/* Queue lock for fifo buffer */
	pthread_mutex_t queue_lock;

	/* sender stats callback */
	int (*sender_stats_callback)(void *arg, uint16_t version, char *stats_json, uint32_t json_size);
	void *sender_stats_callback_argument;
	uint64_t stats_report_time; /* in ticks */

	/* Data fd input (tunnel mode) — read from fd and send as RIST data */
	int data_fd;
	size_t data_fd_max_packet_size;
	uint32_t data_fd_flags;
	pthread_t data_fd_thread;
	bool data_fd_thread_started;
	atomic_uint_fast64_t data_fd_tx_packets;
	atomic_uint_fast64_t data_fd_tx_bytes;
};

enum rist_ctx_mode {
	RIST_SENDER_MODE,
	RIST_RECEIVER_MODE
};

struct rist_ctx {
	enum rist_ctx_mode mode;
	struct rist_sender *sender_ctx;
	struct rist_receiver *receiver_ctx;
};

struct rist_peer {
	/* linked list */
	pthread_mutex_t peer_lock;//Currently only used for setting password & in sending/receiving
	struct rist_peer *next;
	struct rist_peer *prev;

	/* For simple profile authentication chain (data and rtcp on different ports) */
	struct rist_peer *peer_rtcp;
	struct rist_peer *peer_data;
	bool handled_first;
	bool is_rtcp;
	bool is_data;
	/* sender only: peer is known to respond to echo requests use those to calculate RTT instead */
	bool echo_enabled;

	/* For keeping track of the connection that initiated a peer */
	struct rist_peer *parent;
	struct rist_peer *sibling_prev;
	struct rist_peer *sibling_next;
	struct rist_peer *child;
	uint32_t child_alive_count;

	/* Flow for incoming traffic */
	struct rist_flow *flow;

	/* Advertised flow id to force peer selection */
	uint32_t adv_flow_id;

	/* Identifiers for multipeer links */
	uint32_t adv_peer_id;
	uint32_t peer_ssrc;

	char receiver_name[RIST_MAX_HOSTNAME];

	/* Config */
	struct rist_peer_config config;
	uint64_t sender_max_buffer_ticks;
	uint64_t recovery_buffer_ticks;

	bool buffer_bloat_active;

	bool receiver_mode;

	int sd;

	/* State */
	bool authenticated;

	/* Data sending */
	uint32_t seq;
	uint64_t eight_times_rtt;
	uint32_t w_count; /* Counter for weight in distributed send */

	/* RTT statistics */
	uint64_t last_rtt;

	/* Dynamic RTT-based muting (sender bonding, ?rtt-drop=). When muted the
	 * leg is skipped in the weighted payload rotation but its connection and
	 * RTCP probing continue so RTT keeps updating for the restore decision. */
	bool rtt_muted;
	struct rist_rtt_mute_state rtt_mute_state;
	uint32_t rtt_trickle_counter; /* 1-in-N counter for redundant trickle sends */
	uint32_t rtt_mute_count; /* cumulative count of RTT-triggered mute events */
	/* Elected to keep carrying while every leg wants mute. Sticky: held until
	 * the leg recovers or a sibling is clearly better, so the payload path
	 * does not ping-pong between two equally bad legs. */
	bool rtt_sole_carrier;
	uint64_t rtt_sole_since;
	/* Start of the post-restore weight ramp. A leg that was muted for high RTT
	 * has an empty queue, so it measures well until it is loaded again;
	 * rejoining at full share re-floods it. Zero when no ramp is in progress. */
	uint64_t rtt_ramp_start;

	/* Last time this peer was warned that its payload rate leaves no
	 * retransmission budget under its bandwidth ceiling; 0 if never. */
	uint64_t bandwidth_warn_ts;

	/* Briefly-silent bonded leg: skipped in the payload rotation but kept
	 * authenticated, so it resumes without re-auth if it returns before the
	 * liveness timeout (rist_sender_stall_check / rist_peer_liveness_timeout). */
	bool stalled;

	/* Missing queue max size */
	uint32_t missing_counter_max;

	/* Encryption */
	bool supports_otf_passphrase_change;
	struct rist_key key_tx; // used for transmitted packets
	struct rist_key key_rx; // used for received packets
	bool key_rx_odd_active;
	bool key_tx_odd_active;
	struct rist_key key_tx_odd; // used for transmitted packets
	struct rist_key key_rx_odd; // used for received packets
	bool rolling_over_passphrase;
	struct eapsrp_ctx *eap_ctx;
	int eap_authentication_state;
	uint8_t rist_gre_version;

	/* Advanced Profile (TR-06-3) peer state */
	bool is_advanced;              /* Peer operating in Advanced Profile mode */
	bool remote_supports_advanced; /* Remote advertised I=1 in keep-alive */
	struct rist_adv_ts_state rx_adv_ts; /* receive-side 1 MHz source-clock rebuild */

	/* compression flag (sender only) */
	bool compression;

	/* Addressing */
	uint16_t local_port;
	uint16_t remote_port;
	union {
		struct sockaddr address;
        struct sockaddr_in inaddr;
        struct sockaddr_in6 inaddr6;
		struct sockaddr_storage storage;
	} u;
	socklen_t address_len;
	uint16_t address_family;
	uint16_t state;
	char miface[128];

	/* Events */
	struct timeval expire;
	bool send_keepalive;
	struct evsocket_event *event_recv;

	/* listening mode with @ */
	bool listening;
	/* multicast */
	bool multicast_sender;
	bool multicast_receiver;

	/* rist ctx */
	struct rist_sender *sender_ctx;
	struct rist_receiver *receiver_ctx;

	/* Reflector role flags */
	bool is_reflector_publisher;

	/* rist buffer bloating counteract */
	uint64_t cooldown_time;

	/* Statistics Sender */
	struct rist_peer_sender_stats stats_sender_instant;
	struct rist_peer_sender_stats stats_sender_total;


	/* Statistics Receiver */
	struct rist_peer_receiver_stats stats_receiver_instant;
	struct rist_peer_receiver_stats stats_receiver_total;

	int dead;
	int timed_out;
	uint64_t dead_since;
	/* Caller-side socket rebind bookkeeping. */
	uint64_t last_rebind_time;
	uint32_t rebind_attempts;
	uint64_t birthtime_peer;
	uint64_t birthtime_local;

	/* bw estimation */
	struct rist_bandwidth_estimation bw;
	struct rist_bandwidth_estimation retry_bw;
	struct rist_bandwidth_estimation ts_nulls_bw;

	/* shutting down flag */
	atomic_bool shutdown;

	/* Timers */
	uint32_t rtcp_keepalive_interval;
	uint64_t next_periodic_rtcp;
	uint64_t next_keepalive_packet;
	uint64_t next_flow_attr;
	uint64_t session_timeout;
	uint64_t last_pkt_received;
	uint64_t last_sender_report_time;
	uint64_t last_sender_report_ts;
	uint64_t ts_null_bytes;

	char *url;
	char cname[RIST_MAX_HOSTNAME];
	uint8_t mac_addr[6];
	bool send_first_connection_event;

	/* Rate-limit for EMSGSIZE/PMTU-too-large send errors so a flow of
	 * oversized packets doesn't drown the log. Holds the last log time
	 * in NTP ticks. */
	uint64_t last_pmtu_error_log;

	uint64_t log_repeat_timer;

	uint8_t data[SIZEOF_GRE_KEEPALIVE];

};

static inline struct rist_common_ctx *rist_struct_get_common(struct rist_ctx *ctx) {
	if (RIST_UNLIKELY(!ctx))
		return NULL;
	if (ctx->mode == RIST_SENDER_MODE && ctx->sender_ctx)
		return &ctx->sender_ctx->common;
	else if (ctx->mode == RIST_RECEIVER_MODE && ctx->receiver_ctx)
		return &ctx->receiver_ctx->common;
	else
		return NULL;
}

/* defined in flow.c */
RIST_PRIV void rist_receiver_flow_statistics(struct rist_receiver *ctx, struct rist_flow *flow);
RIST_PRIV struct cJSON *rist_sender_peer_statistics(struct rist_peer *peer);
RIST_PRIV void rist_sender_flow_statistics(struct rist_sender *ctx);
RIST_PRIV void rist_delete_flow(struct rist_receiver *ctx, struct rist_flow *f);
RIST_PRIV void rist_receiver_missing(struct rist_flow *f, struct rist_peer *peer,uint64_t nack_time, uint32_t seq, uint64_t rtt);
RIST_PRIV int rist_receiver_associate_flow(struct rist_peer *p, uint32_t flow_id);
RIST_PRIV size_t rist_best_rtt_index(struct rist_flow *f);
RIST_PRIV struct rist_buffer *rist_new_buffer(struct rist_common_ctx *ctx, const void *buf, size_t len, uint8_t type, uint32_t seq, uint64_t source_time, uint16_t src_port, uint16_t dst_port);
RIST_PRIV void free_rist_buffer(struct rist_common_ctx *ctx, struct rist_buffer *b);
RIST_PRIV void rist_calculate_bitrate(size_t len, struct rist_bandwidth_estimation *bw);
RIST_PRIV void rist_refresh_flow_bitrate(struct rist_bandwidth_estimation *bw);
RIST_PRIV void empty_receiver_queue(struct rist_flow *f, struct rist_common_ctx *ctx);
RIST_PRIV void rist_flush_missing_flow_queue(struct rist_flow *flow);

/* defined in rist-common.c */
RIST_PRIV void rist_peer_authenticate(struct rist_peer *peer);
RIST_PRIV void rist_shutdown_peer(struct rist_peer *peer);
RIST_PRIV void rist_print_inet_info(char *prefix, struct rist_peer *peer);
RIST_PRIV void rist_peer_rtcp(struct evsocket_ctx *ctx, void *arg);
RIST_PRIV void rist_populate_cname(struct rist_peer *peer);
RIST_PRIV void free_data_block(struct rist_data_block **const block);

/* needed after splitting up */
RIST_PRIV PTHREAD_START_FUNC(sender_pthread_protocol, arg);
RIST_PRIV PTHREAD_START_FUNC(receiver_pthread_protocol, arg);
RIST_PRIV int rist_max_jitter_set(struct rist_common_ctx *ctx, int t);
RIST_PRIV int rist_recovery_rtt_multiplier_set_internal(struct rist_common_ctx *ctx, int multiplier);
RIST_PRIV int parse_url_options(const char *url, struct rist_peer_config *output_peer_config);
RIST_PRIV int parse_url_udp_options(const char *url, struct rist_udp_config *output_udp_config);
RIST_PRIV struct rist_peer *rist_receiver_peer_insert_local(struct rist_receiver *ctx,
															const struct rist_peer_config *config);
RIST_PRIV void rist_sender_destroy_local(struct rist_sender *ctx);
RIST_PRIV void rist_receiver_destroy_local(struct rist_receiver *ctx);
RIST_PRIV struct rist_peer *rist_sender_peer_insert_local(struct rist_sender *ctx,
														  const struct rist_peer_config *config, bool b_rtcp);
RIST_PRIV void rist_fsm_init_comm(struct rist_peer *peer);
RIST_PRIV int rist_oob_enqueue(struct rist_common_ctx *ctx, struct rist_peer *peer, const void *buf, size_t len);

RIST_PRIV int rist_oob_dequeue_rx(struct rist_common_ctx *ctx, const struct rist_oob_block **oob_block);
RIST_PRIV int init_common_ctx(struct rist_common_ctx *ctx, enum rist_profile profile);
RIST_PRIV void init_advanced_state(struct rist_common_ctx *ctx);
RIST_PRIV int rist_peer_remove(struct rist_common_ctx *ctx, struct rist_peer *peer, struct rist_peer **next);
RIST_PRIV int rist_auth_handler(struct rist_common_ctx *ctx,
								int (*conn_cb)(void *arg, const char *connecting_ip, uint16_t connecting_port, const char *local_ip, uint16_t local_port, struct rist_peer *peer),
								int (*disconn_cb)(void *arg, struct rist_peer *peer),
								void *arg);
RIST_PRIV void sender_peer_append(struct rist_sender *ctx, struct rist_peer *peer);

/* Get common context */
RIST_PRIV struct rist_common_ctx *get_cctx(struct rist_peer *peer);

/* Fold a fresh RTT measurement into the peer's 8-tap smoothed average. RTT is
 * measured on whichever peer object receives the response, so mirror it onto
 * the data leg: that is where the balancer and the stats read it from. */
static inline void rist_peer_rtt_update(struct rist_peer *peer, uint64_t rtt)
{
	peer->last_rtt = rtt;
	peer->eight_times_rtt -= peer->eight_times_rtt / 8;
	peer->eight_times_rtt += peer->last_rtt;
	if (peer->peer_data && peer->peer_data != peer)
	{
		peer->peer_data->last_rtt = peer->last_rtt;
		peer->peer_data->eight_times_rtt = peer->eight_times_rtt;
	}
}

/*static inline in header file */
static inline void peer_append(struct rist_peer *p)
{
	struct rist_common_ctx *cctx = get_cctx(p);
	struct rist_peer **PEERS = &cctx->PEERS;
	struct rist_peer *plist = *PEERS;
	if (!plist)
	{
		*PEERS = p;
		return;
	}
	if (p->parent)
	{
		struct rist_peer *peer = p->parent;
		if (!peer->child) {
			peer->child = p;
			if (peer->sender_ctx)
				peer->sender_ctx->total_weight += p->config.weight;
		}
		else
		{
			struct rist_peer *child = peer->child;
			while (child)
			{
				if (!child->sibling_next)
				{
					child->sibling_next = p;
					p->sibling_prev = child;
					break;
				}
				child = child->sibling_next;
			}
		}
		++peer->child_alive_count;
	}
	while (plist)
	{
		if (!plist->next)
		{
			p->prev = plist;
			plist->next = p;
			return;
		}
		plist = plist->next;
	}
}

#endif
