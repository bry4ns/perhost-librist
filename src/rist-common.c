/* librist. Copyright © 2019-2020 SipRadius LLC. All right reserved.
 * Author: Daniele Lacamera <root@danielinux.net>
 * Author: Antonio Cardace <anto.cardace@gmail.com>
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "proto/gre.h"
#include "rist-private.h"
#include <limits.h>
#include "log-private.h"
#include "crypto/psk.h"
#include <lz4.h>
#include "crypto/random.h"
#include "udp-private.h"
#include "transport-private.h"
#include "udpsocket.h"
#include "endian-shim.h"
#include "time-shim.h"
#include "proto/rist_time.h"
#include "network.h"
#include "librist/tun.h"
#include "librist/tunnel.h"
#include <sys/types.h>
#include "proto/protocol_gre.h"
#if HAVE_SRP_SUPPORT
#include "proto/eap.h"
#endif
#include "mpegts.h"
#include "rist_ref.h"
#include "config.h"
#include "rist-thread.h"
#include "rist-nack-select.h"
#include "peer.h"
#include <stdbool.h>
#include "stdio-shim.h"
#include <assert.h>
#include "proto/gre.h"

static void rist_peer_recv(struct evsocket_ctx *evctx, int fd, short revents, void *arg, bool *again);
static void rist_peer_recv_wrap(struct evsocket_ctx *evctx, int fd, short revents, void *arg);
static void rist_peer_sockerr(struct evsocket_ctx *evctx, int fd, short revents, void *arg);
static PTHREAD_START_FUNC(receiver_pthread_dataout,arg);
static void store_peer_settings(const struct rist_peer_config *settings, struct rist_peer *peer);
static struct rist_peer *peer_initialize(const char *url, struct rist_sender *sender_ctx,
										struct rist_receiver *receiver_ctx);
void remove_peer_from_flow(struct rist_peer *peer);

int parse_url_udp_options(const char* url, struct rist_udp_config *output_udp_config)
{
	uint32_t clean_url_len = 0;
	const char* query = NULL;
	uint32_t prefix_len = 0;
	struct udpsocket_url_param url_params[32];
	int num_params = 0;
	int i = 0;
	int ret = 0;

	if (!url || !url[0] || !output_udp_config)
		return -1;

	char *tmp_url = strdup( url );
	if (!tmp_url)
		return -1;

	query = strchr( tmp_url, '/' );
	if (query != NULL) {
		prefix_len = (uint32_t)(query - tmp_url);
		/* clamp copy length and terminator to prefix[]; prefix_len may be 0 */
		size_t prefix_copy = prefix_len > 0 ? (size_t)(prefix_len - 1) : 0;
		if (prefix_copy > sizeof(output_udp_config->prefix) - 1)
			prefix_copy = sizeof(output_udp_config->prefix) - 1;
		memcpy((void *)output_udp_config->prefix, tmp_url, prefix_copy);
		output_udp_config->prefix[prefix_copy] = '\0';
		// Convert to lower
		char *p =(char *)output_udp_config->prefix;
		for(i = 0; i < 16; i++)
			p[i] = p[i] > 0x40 && p[i] < 0x5b ? p[i] | 0x60 : p[i];
		if (!strncmp(output_udp_config->prefix, "rtp", 3))
			output_udp_config->rtp = true;
		else
			output_udp_config->rtp = false;
	} else {
		// default is udp
		char src[] = "udp";
		strcpy((void *)output_udp_config->prefix, src);
		output_udp_config->rtp = false;
	}

	// Parse URL parameters
	num_params = udpsocket_parse_url_parameters( tmp_url, url_params,
			sizeof(url_params) / sizeof(struct udpsocket_url_param), &clean_url_len );
	if (num_params > 0) {
		for (i = 0; i < num_params; ++i) {
			char* val = url_params[i].val;
			if (!val)
				continue;

			if (strcmp( url_params[i].key, RIST_URL_PARAM_MIFACE ) == 0) {
				strncpy((void *)output_udp_config->miface, val, RIST_MAX_STRING_SHORT - 1);
			} else if (strcmp(url_params[i].key, RIST_URL_PARAM_MCAST_TTL) == 0) {
				int temp = atoi(val);
				if (temp > 0 && temp <= 255)
					output_udp_config->multicast_ttl = (uint32_t)temp;
			} else if (output_udp_config->version >= 2 &&
			           strcmp(url_params[i].key, RIST_URL_PARAM_CBR_OUTPUT) == 0) {
				if (strcmp(val, "0") && strcmp(val, "1")) {
					ret = -1;
				} else {
					output_udp_config->cbr_output = atoi(val);
					output_udp_config->cbr_output_set = 1;
				}
			} else if (strcmp(url_params[i].key, RIST_URL_PARAM_MCAST_SOURCE) == 0) {
				strncpy((void *)output_udp_config->multicast_source, val, RIST_MAX_STRING_LONG - 1);
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_STREAM_ID ) == 0) {
				int temp = atoi( val );
				if (temp > 0)
					output_udp_config->stream_id = (uint16_t)temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_RTP_TIMESTAMP ) == 0) {
				int temp = atoi( val );
				if (temp >= 0)
					output_udp_config->rtp_timestamp = (uint16_t)temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_RTP_SEQUENCE ) == 0) {
				int temp = atoi( val );
				if (temp >= 0)
					output_udp_config->rtp_sequence = (uint16_t)temp;
			} else if (output_udp_config->version >= 1 && strcmp( url_params[i].key, RIST_URL_PARAM_RTP_OUTPUT_PTYPE) == 0) {
				int temp = atoi( val );
				if (temp >= 0)
					output_udp_config->rtp_ptype = (uint8_t)temp;
			} else if (output_udp_config->version >= 1 && strcmp( url_params[i].key, RIST_URL_PARAM_MULTIPLEX_MODE) == 0) {
				int temp = atoi( val );
				if (temp >= 0)
					output_udp_config->multiplex_mode = (uint8_t)temp;
/*UNUSED TODO} else if (output_udp_config->version >= 1 && strcmp( url_params[i].key, RIST_URL_PARAM_MULTIPLEX_FILTER) == 0) {
				strncpy((void *)output_udp_config->multiplex_filter, val, RIST_MAX_STRING_SHORT -1); */
			} else {
				ret = -1;
				fprintf(stderr, "Unknown or invalid parameter %s\n", url_params[i].key);
			}
		}
	}
	strncpy((void *)output_udp_config->address, url, clean_url_len >= RIST_MAX_STRING_LONG ? RIST_MAX_STRING_LONG-1 : clean_url_len - 1);

	free( tmp_url );

	if (ret != 0)
		return num_params;
	else
		return 0;
}

int parse_url_options(const char* url, struct rist_peer_config *output_peer_config)
{
	uint32_t clean_url_len = 0;
	struct udpsocket_url_param url_params[32];
	int num_params = 0;
	int i = 0;
	int ret = 0;

	if (!url || !url[0] || !output_peer_config)
		return -1;

	// Parse URL parameters
	char *tmp_url = strdup( url );
	if (!tmp_url)
		return -1;

	num_params = udpsocket_parse_url_parameters( tmp_url, url_params,
			sizeof(url_params) / sizeof(struct udpsocket_url_param), &clean_url_len );
	if (num_params > 0) {
		for (i = 0; i < num_params; ++i) {
			char* val = url_params[i].val;
			if (!val)
				continue;

			if (strcmp( url_params[i].key, RIST_URL_PARAM_BUFFER_SIZE ) == 0) {
				int temp = atoi( val );
				/* 0 is meaningless as a recovery buffer and divides by zero
				 * in init_peer_settings (SIGFPE at peer creation). */
				if (temp > 0) {
					output_peer_config->recovery_length_min = temp;
					output_peer_config->recovery_length_max = temp;
				}
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_BUFFER_SIZE_MIN ) == 0) {
				int temp = atoi( val );
				if (temp >= 0)
					output_peer_config->recovery_length_min = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_BUFFER_SIZE_MAX ) == 0) {
				int temp = atoi( val );
				if (temp > 0)
					output_peer_config->recovery_length_max = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_MIFACE ) == 0) {
				strncpy((void *)output_peer_config->miface, val, 128-1);
			} else if (output_peer_config->version >= 2 && strcmp(url_params[i].key, RIST_URL_PARAM_MCAST_TTL) == 0) {
				int temp = atoi(val);
				if (temp > 0 && temp <= 255)
					output_peer_config->multicast_ttl = (uint32_t)temp;
			} else if (output_peer_config->version >= 2 && strcmp(url_params[i].key, RIST_URL_PARAM_MCAST_SOURCE) == 0) {
				strncpy((void *)output_peer_config->multicast_source, val, RIST_MAX_STRING_LONG - 1);
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_SECRET ) == 0) {
				strncpy((void *)output_peer_config->secret, val, 128-1);
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_SRP_USERNAME) == 0) {
				strncpy((void *)output_peer_config->srp_username, val, 256 -1);
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_SRP_PASSWORD) == 0) {
				strncpy((void *)output_peer_config->srp_password, val, 256 -1);
			} else if (output_peer_config->version >= 3 && strcmp( url_params[i].key, RIST_URL_PARAM_SRP_COMPAT) == 0) {
				char *endp = NULL;
				long temp = strtol(val, &endp, 10);
				if (endp == val || *endp != '\0' || (temp != 0 && temp != 1)) {
					ret = -1;
					fprintf(stderr, "Invalid srp-compat '%s'; expected 0|1\n", val);
					continue;
				}
				output_peer_config->srp_compat_legacy = (int)temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_CNAME ) == 0) {
				strncpy((void *)output_peer_config->cname, val, 128-1);
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_AES_TYPE ) == 0) {
				int temp = atoi( val );
				if (temp == 0 || temp == 128 || temp == 192 || temp == 256) {
					output_peer_config->key_size = temp;
				}
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_AES_KEY_ROTATION ) == 0) {
				int temp = atoi( val );
				if (temp > 0)
					output_peer_config->key_rotation = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_BANDWIDTH ) == 0) {
				int temp = atoi( val );
				if (temp > 0)
					output_peer_config->recovery_maxbitrate = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_RET_BANDWIDTH ) == 0) {
				int temp = atoi( val );
				if (temp >= 0)
					output_peer_config->recovery_maxbitrate_return = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_RTT ) == 0) {
				int temp = atoi( val );
				if (temp >= 0) {
					output_peer_config->recovery_rtt_min = temp;
					output_peer_config->recovery_rtt_max = temp;
				}
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_RTT_MIN ) == 0) {
				int temp = atoi( val );
				if (temp >= 0)
					output_peer_config->recovery_rtt_min = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_RTT_MAX ) == 0) {
				int temp = atoi( val );
				if (temp >= 0)
					output_peer_config->recovery_rtt_max = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_REORDER_BUFFER ) == 0) {
				int temp = atoi( val );
				if (temp >= 0)
					output_peer_config->recovery_reorder_buffer = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_COMPRESSION ) == 0) {
				int temp = atoi( val );
				if (temp >= 0)
					output_peer_config->compression = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_VIRT_DST_PORT ) == 0) {
				int temp = atoi( val );
				if (temp > 0)
					output_peer_config->virt_dst_port = (uint16_t)temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_WEIGHT ) == 0) {
				int temp = atoi( val );
				if (temp >= 0)
					output_peer_config->weight = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_RECOVERY_PRIORITY ) == 0) {
				int temp = atoi( val );
				if (temp >= 0)
					output_peer_config->recovery_priority = (uint32_t)temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_RTT_DROP ) == 0) {
				int temp = atoi( val );
				if (temp >= 0)
					output_peer_config->rtt_drop = (uint32_t)temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_RTT_RESTORE ) == 0) {
				int temp = atoi( val );
				if (temp >= 0)
					output_peer_config->rtt_restore = (uint32_t)temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_RTT_DROP_SETTLE ) == 0) {
				int temp = atoi( val );
				if (temp >= 0)
					output_peer_config->rtt_drop_settle = (uint32_t)temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_RTT_DROP_TRICKLE ) == 0) {
				int temp = atoi( val );
				if (temp >= 0)
					output_peer_config->rtt_drop_trickle = (uint32_t)temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_SESSION_TIMEOUT ) == 0) {
				int temp = atoi( val );
				if (temp > 0)
					output_peer_config->session_timeout = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_KEEPALIVE_INT ) == 0) {
				int temp = atoi( val );
				if (temp > 0)
					output_peer_config->keepalive_interval = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_CONGESTION_CONTROL ) == 0) {
				int temp = atoi( val );
				if (temp >= 0 && temp <= 2)
					output_peer_config->congestion_control_mode = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_TIMING_MODE ) == 0) {
				int temp = atoi( val );
				if (temp >= 0 && temp <= 2)
					output_peer_config->timing_mode = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_MIN_RETRIES ) == 0) {
				int temp = atoi( val );
				if (temp > 0)
					output_peer_config->min_retries = temp;
			} else if (strcmp( url_params[i].key, RIST_URL_PARAM_MAX_RETRIES ) == 0) {
				int temp = atoi( val );
				if (temp > 0)
					output_peer_config->max_retries = temp;
			} else if (output_peer_config->version >= 1 &&
			           strcmp( url_params[i].key, RIST_URL_PARAM_SPLIT_MODE ) == 0) {
				if (strcmp(val, "off") == 0)
					output_peer_config->split_mode = LIBRIST_SPLIT_MODE_OFF;
				else if (strcmp(val, "auto") == 0 || strcmp(val, "ts") == 0)
					output_peer_config->split_mode = LIBRIST_SPLIT_MODE_AUTO;
				else if (strcmp(val, "half") == 0)
					output_peer_config->split_mode = LIBRIST_SPLIT_MODE_HALF;
				else {
					ret = -1;
					fprintf(stderr, "Unknown split mode '%s'; expected off|auto|half\n", val);
				}
			} else if (output_peer_config->version >= 1 &&
			           strcmp( url_params[i].key, RIST_URL_PARAM_MERGE_MODE ) == 0) {
				if (strcmp(val, "off") == 0)
					output_peer_config->merge_mode = LIBRIST_MERGE_MODE_OFF;
				else if (strcmp(val, "pairs") == 0)
					output_peer_config->merge_mode = LIBRIST_MERGE_MODE_PAIRS;
				else if (strcmp(val, "auto") == 0)
					output_peer_config->merge_mode = LIBRIST_MERGE_MODE_AUTO;
				else {
					ret = -1;
					fprintf(stderr, "Unknown merge mode '%s'; expected off|auto|pairs\n", val);
				}
			} else if (output_peer_config->version >= 2 && strcmp( url_params[i].key, RIST_URL_PARAM_REFLECTOR ) == 0) {
				int temp = atoi( val );
				if (temp >= 0 && temp <= 1)
					output_peer_config->reflector = temp;
			} else if (output_peer_config->version >= 2 && strcmp( url_params[i].key, RIST_URL_PARAM_LOCAL_PORT ) == 0) {
				int temp = atoi( val );
				if (temp > 0 && temp <= 65535)
					output_peer_config->local_port = (uint16_t)temp;
			} else if (output_peer_config->version >= 5 &&
			           strcmp( url_params[i].key, RIST_URL_PARAM_RECOVERY_DEPTH ) == 0) {
				char *endp = NULL;
				long temp = strtol(val, &endp, 10);
				if (endp == val || *endp != '\0' ||
				    temp < RIST_RECOVERY_DEPTH_MIN || temp > RIST_RECOVERY_DEPTH_MAX) {
					ret = -1;
					fprintf(stderr, "Invalid recovery-depth '%s'; expected %d..%d "
						"(ring = 65536 << depth packets; default %d)\n", val,
						RIST_RECOVERY_DEPTH_MIN, RIST_RECOVERY_DEPTH_MAX,
						RIST_RECOVERY_DEPTH_DEFAULT);
				} else {
					output_peer_config->recovery_depth = (uint8_t)temp;
				}
			} else if (output_peer_config->version >= 4 &&
			           strcmp( url_params[i].key, RIST_URL_PARAM_PROFILE ) == 0) {
				/* version >= 4: writing profile fields on a
				 * struct sized for an older version would
				 * overflow the caller's allocation. */
				char *endp = NULL;
				long temp = strtol(val, &endp, 10);
				if (endp == val || *endp != '\0' ||
				    temp < RIST_PROFILE_SIMPLE || temp > RIST_PROFILE_ADVANCED) {
					ret = -1;
					fprintf(stderr, "Invalid profile '%s'; expected 0|1|2\n", val);
					continue;
				}
				output_peer_config->profile = (enum rist_profile)temp;
				output_peer_config->profile_set = 1;
			} else {
				ret = -1;
				fprintf(stderr, "Unknown or invalid parameter %s\n", url_params[i].key);
			}
		}
	}
	strncpy((void *)output_peer_config->address, url, clean_url_len >= RIST_MAX_STRING_LONG ? RIST_MAX_STRING_LONG-1 : clean_url_len - 1);

	free( tmp_url );

	if (ret != 0)
		return num_params;
	else
		return 0;
}

struct rist_common_ctx *get_cctx(struct rist_peer *peer)
{
	if (peer->sender_ctx) {
		return &peer->sender_ctx->common;
	} else {
		return &peer->receiver_ctx->common;
	}
}

int rist_max_jitter_set(struct rist_common_ctx *ctx, int t)
{
	if (t > 0) {
		ctx->rist_max_jitter = t * RIST_CLOCK;
		return 0;
	}

	return -1;
}

int rist_recovery_rtt_multiplier_set_internal(struct rist_common_ctx *ctx, int multiplier)
{
	if (multiplier >= 1) {
		ctx->recovery_rtt_multiplier = multiplier;
		return 0;
	}
	return -1;
}

/* Reference packet size for the config-time recovery-window sanity check.
 * 7x188 MPEG-TS over RTP is the common RIST framing. Smaller packets put
 * MORE packets in the buffer and make the window tighter, so this estimate
 * is deliberately optimistic: it only warns when the configuration clearly
 * overruns the window even with full-size packets. */
#define RIST_RECOVERY_REF_PKT_BYTES 1316

/* Warn (once, at peer-config time) if the configured recovery-maxbitrate and
 * max buffer would queue more packets than the recovery window can address.
 * Packets beyond the window cannot be retransmitted regardless of how many
 * NACKs are sent. window is the addressable window in packets for this role
 * (receiver NACK window or sender retransmit window). */
static void rist_warn_recovery_window(struct rist_peer *peer, size_t window, bool sender)
{
	uint32_t maxbitrate = peer->config.recovery_maxbitrate;   /* kbps */
	uint32_t length_max = peer->config.recovery_length_max;    /* ms   */
	if (maxbitrate == 0 || length_max == 0 || window == 0)
		return;
	uint64_t pkts_in_buffer =
		(uint64_t)maxbitrate * length_max / (RIST_RECOVERY_REF_PKT_BYTES * 8);
	if (pkts_in_buffer <= window)
		return;
	struct rist_common_ctx *cctx = get_cctx(peer);
	bool advanced = (cctx->profile == RIST_PROFILE_ADVANCED);
	rist_log_priv(cctx, RIST_LOG_WARN,
		"Peer #%"PRIu32": recovery config exceeds the %s recovery window. "
		"At %u kbps a %u ms buffer holds ~%"PRIu64" packets (assuming ~%d-byte "
		"packets; smaller packets are worse), but the %s-profile %s window "
		"addresses only %zu packets - packets beyond it cannot be retransmitted. %s\n",
		peer->adv_peer_id,
		sender ? "sender" : "receiver",
		maxbitrate, length_max, pkts_in_buffer, RIST_RECOVERY_REF_PKT_BYTES,
		advanced ? "Advanced" : (cctx->profile == RIST_PROFILE_MAIN ? "Main" : "Simple"),
		sender ? "retransmit" : "NACK",
		window,
		advanced
			? "Lower recovery-maxbitrate/buffer, or enlarge the ring via ?recovery-depth= (or rist_recovery_depth_set()) before rist_start()."
			: "Lower recovery-maxbitrate/buffer, or use the Advanced profile for a 32-bit sequence space.");
}

static void init_peer_settings(struct rist_peer *peer)
{
	/* 0 means unset, not unlimited: every reader below takes it as a literal
	 * ceiling of zero. ?bandwidth=0 is ignored the same way. */
	if (peer->config.recovery_maxbitrate == 0) {
		rist_log_priv(get_cctx(peer), RIST_LOG_WARN,
			"Peer #%"PRIu32": a recovery-maxbitrate of 0 disables retransmission "
			"instead of lifting the ceiling, so using the %d kbps default. Set it "
			"to the ceiling you want for payload plus retransmissions.\n",
			peer->adv_peer_id, RIST_DEFAULT_RECOVERY_MAXBITRATE);
		peer->config.recovery_maxbitrate = RIST_DEFAULT_RECOVERY_MAXBITRATE;
	}

	peer->eight_times_rtt = peer->config.recovery_rtt_min * 8;
	/* Midpoint of the configured buffer range, and the same on both ends so the
	 * two sides agree on how long a silent peer has to come back. The receiver
	 * scales its reorder buffer from here; the sender holds a dead peer's place
	 * in the send rotation for this long, and floors its liveness timeout on it. */
	peer->recovery_buffer_ticks =
		((uint64_t)(peer->config.recovery_length_max - peer->config.recovery_length_min) / 2 +
		 peer->config.recovery_length_min) * RIST_CLOCK;
	if (peer->receiver_mode) {
		assert(peer->receiver_ctx != NULL);
		uint32_t recovery_maxbitrate_mbps = peer->config.recovery_maxbitrate < 1000 ? 1 : peer->config.recovery_maxbitrate / 1000;
		peer->missing_counter_max =
			(uint32_t)(peer->recovery_buffer_ticks / RIST_CLOCK) * recovery_maxbitrate_mbps /
			(sizeof(struct rist_gre_seq) + sizeof(struct rist_rtp_hdr) + sizeof(uint32_t));

		{
			struct rist_common_ctx *cctx = get_cctx(peer);
			size_t rwin = ((cctx->profile == RIST_PROFILE_ADVANCED)
				? cctx->recovery_queue_max : UINT16_SIZE) / 2;
			rist_warn_recovery_window(peer, rwin, false);
		}

		rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
				"New peer with id #%"PRIu32" was configured with maxrate=%d/%d bufmin=%d bufmax=%d reorder=%d rttmin=%d rttmax=%d congestion_control=%d min_retries=%d max_retries=%d\n",
				peer->adv_peer_id, peer->config.recovery_maxbitrate, peer->config.recovery_maxbitrate_return, peer->config.recovery_length_min, peer->config.recovery_length_max, peer->config.recovery_reorder_buffer,
				peer->config.recovery_rtt_min /RIST_CLOCK, peer->config.recovery_rtt_max /RIST_CLOCK, peer->config.congestion_control_mode, peer->config.min_retries, peer->config.max_retries);
		if (peer->config.recovery_length_min != peer->config.recovery_length_max)
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Enabling automatic buffer scaling\n");
	}
	else {
		assert(peer->sender_ctx != NULL);
		struct rist_sender *ctx = peer->sender_ctx;
		{
			size_t swin = ((ctx->common.profile == RIST_PROFILE_ADVANCED)
				? ctx->sender_queue_max : UINT16_SIZE) / 2;
			rist_warn_recovery_window(peer, swin, true);
		}
		/* Global context settings */
		if (peer->config.recovery_maxbitrate > ctx->recovery_maxbitrate_max) {
			ctx->recovery_maxbitrate_max = peer->config.recovery_maxbitrate;
			int max_jitter_ms = ctx->common.rist_max_jitter / RIST_CLOCK;
			// Asume MTU of 1400 for now
			uint32_t max_nacksperloop = ctx->recovery_maxbitrate_max * max_jitter_ms / (8*1400);
			// Normalize against the total buffer size; guard the divisor in
			// case a 0 buffer ever gets past URL/API validation (SIGFPE).
			if (peer->config.recovery_length_max == 0)
				peer->config.recovery_length_max = 1;
			max_nacksperloop = max_nacksperloop * 1000 / peer->config.recovery_length_max;
			// Anything less that 2240Kbps at 5ms will round down to zero (100Mbps is 44)
			if (max_nacksperloop == 0)
				max_nacksperloop = 1;
			// The effective buffer is 50% the total buffer size
			max_nacksperloop = max_nacksperloop  * 2;
			if (max_nacksperloop > ctx->max_nacksperloop) {
				ctx->max_nacksperloop = (uint32_t)max_nacksperloop;
				rist_log_priv(&ctx->common, RIST_LOG_INFO, "Setting max nacks per cycle to %"PRIu32"\n",
				max_nacksperloop);
			}
		}

		if (!peer->listening && peer->config.weight != RIST_PEER_WEIGHT_DUPLICATE && !peer->parent) {
			ctx->total_weight += peer->config.weight;
			rist_log_priv(&ctx->common, RIST_LOG_INFO, "Peer weight: %lu\n", peer->config.weight);
		}

		/* Set target recover size (buffer) */
		if ((peer->config.recovery_length_max + (2 * peer->config.recovery_rtt_min)) > ctx->sender_recover_min_time) {
			ctx->sender_recover_min_time = peer->config.recovery_length_max + (2 * peer->config.recovery_rtt_min / RIST_CLOCK);
			rist_log_priv(&ctx->common, RIST_LOG_INFO, "Setting buffer size to %zums (Max buffer size + 2 * Min RTT, %zu+2*%zu)\n", ctx->sender_recover_min_time,
			peer->config.recovery_length_max,peer->config.recovery_rtt_min / RIST_CLOCK);
			// TODO: adjust this size based on the dynamic RTT measurement
		}

	}
}

struct rist_buffer *rist_new_buffer(struct rist_common_ctx *ctx, const void *buf, size_t len, uint8_t type, uint32_t seq, uint64_t source_time, uint16_t src_port, uint16_t dst_port)
{
	RIST_MARK_UNUSED(ctx);
	// TODO: we will ran out of stack before heap and when that happens malloc will crash not just
	// return NULL ... We need to find and remove all heap allocations
	struct rist_buffer *b;
	b = malloc(sizeof(*b));
	if (!b) {
		fprintf(stderr, "OOM\n");
		return NULL;
	}

	b->data = malloc(len + RIST_MAX_PAYLOAD_OFFSET);
	if (!b->data) {
		free(b);
		fprintf(stderr, "OOM\n");
		return NULL;
	}
	b->alloc_size = len;
	if (buf != NULL && len > 0)
	{
		memcpy((uint8_t *)b->data + RIST_MAX_PAYLOAD_OFFSET, buf, len);
	}
	b->alloc_size = len;
	b->next_free = NULL;
	b->free = false;
	b->size = len;
	b->source_time = source_time;
	b->seq = seq;
	b->time = timestampNTP_u64();
	b->type = type;
	b->src_port = src_port;
	b->dst_port = dst_port;
	b->last_retry_request = 0;
	b->transmit_count = 0;
	b->use_seq = 0;
	b->retry_queued = false;
	return b;
}

void free_rist_buffer(struct rist_common_ctx *ctx, struct rist_buffer *b)
{
	RIST_MARK_UNUSED(ctx);
	free(b->data);
	free(b);

}

static uint64_t receiver_calculate_packet_time(struct rist_flow *f, const uint64_t source_time, uint64_t now, bool retry, uint8_t payload_type)
{
	//Check and correct timing
	uint64_t packet_time = source_time + f->time_offset;
	if (RIST_UNLIKELY(!retry && source_time < f->max_source_time && ((f->max_source_time - source_time) > (UINT32_MAX /2)) && (now - f->time_offset_changed_ts) > 3 * f->recovery_buffer_ticks))
	{
		int64_t new_offset = (int64_t)now - (int64_t)source_time;
		int64_t offset_diff = llabs(new_offset - f->time_offset);
		//Make sure the new and old offsets differ at least by 10 hrs, otherwise something is wrong.
		if (offset_diff > (int64_t)(10LL * 3600LL * 1000LL * RIST_CLOCK)) {
			f->time_offset_old = f->time_offset;
			//Calculate new offset by getting max time for payload type and adding it to old offset
			//Fast path for mpegts payload type with clock of 90khz
			if (RIST_UNLIKELY(payload_type != RTP_PTYPE_RIST))
				f->time_offset += convertRTPtoNTP(payload_type, 0, UINT32_MAX);
			else
				f->time_offset += ((uint64_t)UINT32_MAX << 32) / RTP_PTYPE_MPEGTS_CLOCKHZ;
			rist_log_priv(get_cctx(f->peer_lst[0]), RIST_LOG_INFO, "Clock wrapped, old offset: %" PRId64 " new offset %" PRId64 "\n", f->time_offset / RIST_CLOCK, f->time_offset_old / RIST_CLOCK);
			f->offset_recalc_sample_count = 0;
			f->max_source_time = 0;
			f->time_offset_changed_ts = now;
		}
		packet_time = source_time + f->time_offset;
		//Packets with old clock will be too big due to the wrong offset.
	} else 	if (RIST_UNLIKELY(packet_time > f->last_packet_ts && ((packet_time - f->last_packet_ts) > UINT32_MAX / 2) && (now - f->time_offset_changed_ts) < 3 * f->recovery_buffer_ticks))
	{
		packet_time = source_time + f->time_offset_old;
	} else if (source_time > f->max_source_time)
	{
		f->last_packet_ts = packet_time;
		f->max_source_time = source_time;
	}
	return packet_time;
}

static int receiver_insert_queue_packet(struct rist_flow *f, struct rist_peer *peer, size_t idx, const void *buf, size_t len, uint32_t seq, uint64_t source_time, uint16_t src_port, uint16_t dst_port, uint64_t packet_time)
{
	/*
	   rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
	   "Inserting seq %"PRIu32" len %zu source_time %"PRIu32" at idx %zu\n",
	   seq, len, source_time, idx);
	   */
	f->receiver_queue[idx] = rist_new_buffer(get_cctx(peer), buf, len, RIST_PAYLOAD_TYPE_DATA_RAW, seq, source_time, src_port, dst_port);
	if (RIST_UNLIKELY(!f->receiver_queue[idx])) {
		rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Could not create packet buffer inside receiver buffer, OOM, decrease max bitrate or buffer time length\n");
		return -1;
	}
	f->receiver_queue[idx]->peer = peer;
	f->receiver_queue[idx]->packet_time = packet_time;
	f->receiver_queue[idx]->target_output_time = packet_time + f->recovery_buffer_ticks;
	atomic_fetch_add_explicit(&f->receiver_queue_size, len, memory_order_release);
	if (f->cbr_output) {
		/* Counted on the way in, so the estimate measures the source. */
		atomic_fetch_add_explicit(&f->cbr_arrived_bytes, len, memory_order_relaxed);
	}

	return 0;
}

static inline void receiver_mark_missing(struct rist_flow *f, struct rist_peer *peer, uint32_t current_seq, uint64_t rtt) {
	uint32_t counter = 1;
	uint64_t packet_time_last = 0;
	/* Index the ring exactly as receiver_enqueue() does. 16-bit flows had a
	 * sequence range equal to receiver_queue_max so a raw seq was always a
	 * valid index, but a 32-bit (Advanced) seq can exceed receiver_queue_max
	 * and run off the array -> OOB read of a stale/NULL slot, then a NULL
	 * deref. */
	size_t last_idx = f->last_seq_found & (f->receiver_queue_max - 1);
	size_t cur_idx = current_seq & (f->receiver_queue_max - 1);
	if (RIST_UNLIKELY(!f->receiver_queue[last_idx]))
		if (RIST_LIKELY(!f->rtc_timing_mode))
			packet_time_last = timestampNTP_u64();
		else
			packet_time_last = timestampNTP_RTC_u64();
	else
		packet_time_last = f->receiver_queue[last_idx]->packet_time;
	uint64_t packet_time_now;
	if (RIST_UNLIKELY(!f->receiver_queue[cur_idx])) {
		if (RIST_LIKELY(!f->rtc_timing_mode))
			packet_time_now = timestampNTP_u64();
		else
			packet_time_now = timestampNTP_RTC_u64();
	} else {
		packet_time_now = f->receiver_queue[cur_idx]->packet_time;
	}
	/* short_seq (Simple/Main) flows wrap at 16 bits; 32-bit (Advanced) flows
	 * use the true gap so a real >64k loss is not truncated. Cap mirrors the
	 * recovery-walk hole cap (UINT16_SIZE/2 short, receiver_queue_max/2 else). */
	uint32_t missing_count = rist_seq_gap(current_seq, f->last_seq_found,
	                                      f->short_seq);
	uint32_t missing_count_cap = f->short_seq
	        ? (UINT16_SIZE / 2)
	        : (uint32_t)(f->receiver_queue_max / 2);
	if (missing_count > missing_count_cap)
		return;
	uint64_t interpacket_time = (packet_time_now - packet_time_last) / (missing_count +1);
	uint32_t missing_seq = (f->last_seq_found + counter);

	if (f->short_seq)
		missing_seq = (uint16_t)missing_seq;

	uint64_t nack_time = packet_time_last;
	while (missing_seq != current_seq)
	{
		nack_time += interpacket_time;
		if (RIST_UNLIKELY(peer->buffer_bloat_active || f->missing_counter > peer->missing_counter_max))
		{
			if (f->missing_counter > peer->missing_counter_max)
				rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG,
					"Retry buffer is already too large (%d) for the configured "
					"bandwidth ... ignoring missing packet(s).\n",
					f->missing_counter);
			if (peer->buffer_bloat_active)
				rist_log_priv(get_cctx(peer), RIST_LOG_ERROR,
					"Link has collapsed. Not queuing new retries until it recovers.\n");
			break;
		}
		rist_receiver_missing(f, peer, nack_time, missing_seq, rtt);
		if (RIST_UNLIKELY(counter == f->receiver_queue_max))
			break;
		counter++;
		missing_seq = (f->last_seq_found + counter);
		if (f->short_seq)
			missing_seq = (uint16_t)missing_seq;
	}
}

int compare(const void *a, const void *b)
{
	uint64_t ua = *(const uint64_t *)a;
	uint64_t ub = *(const uint64_t *)b;
	return (ua > ub) - (ua < ub);
}

static void recalculate_clock_offset(struct rist_flow *flow)
{
	//arbitrarily chosen minimal sample count
	if (flow->offset_recalc_sample_count < 100)
		return;

	/* to counter clock drift we are recalculating our offset every 2048 inserted
	   packets. Every "correctly" (in-order, no-discontinuities) packet's clock offset
	   is inserted into an array. Of which we will take the median. */
	qsort(flow->offset_recalc_samples, flow->offset_recalc_sample_count, sizeof(uint64_t), compare);
	size_t middle = flow->offset_recalc_sample_count / 2;
	uint64_t median_offset = flow->offset_recalc_samples[middle];
	flow->offset_recalc_sample_count = 0;
	uint64_t diff = 0;
	uint64_t negative = (median_offset < (uint64_t)flow->time_offset);
	if (negative)
		diff = flow->time_offset - median_offset;
	else
		diff = median_offset - flow->time_offset;
	rist_log_priv2(flow->logging_settings, RIST_LOG_DEBUG, "Recalculated clock offset, old offset: %lu, new offset: %lu difference: %c%lu usec\n",
							flow->time_offset, median_offset, negative? '-': '+', (diff * 1000 / RIST_CLOCK));
	flow->time_offset = median_offset;
}


static int receiver_enqueue(struct rist_peer *peer, uint64_t source_time, uint64_t packet_recv_time, const void *buf, size_t len, uint32_t seq, uint64_t rtt, bool retry, uint16_t src_port, uint16_t dst_port, uint8_t payload_type)
{
	struct rist_flow *f = peer->flow;

	//	fprintf(stderr,"receiver enqueue seq is %"PRIu32", source_time %"PRIu64"\n",
	//	seq, source_time);
	uint64_t now;
	uint64_t now_monotonic = packet_recv_time;
	if (RIST_LIKELY(!f->rtc_timing_mode))
		now = now_monotonic;
	else
		now = timestampNTP_RTC_u64();
	//fprintf(stderr, "Offset would've been: %llu\n", now - source_time);
	if (RIST_UNLIKELY((!f->receiver_queue_has_items && retry) || (f->rtc_timing_mode && f->time_offset == 0)))
		return -1;
	if (RIST_UNLIKELY(!f->receiver_queue_has_items)) {
		/* we just received our first packet for this flow */
		switch (rist_flow_reanchor_check(source_time, f->max_source_time,
						 f->recovery_buffer_ticks,
						 f->reanchor_wait_since, now_monotonic)) {
		case RIST_REANCHOR_WAIT:
			if (!f->reanchor_wait_since) {
				f->reanchor_wait_since = now_monotonic;
				rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
						"Waiting for a current packet to anchor flow on, peer %"PRIu32" is %" PRIu64 " ms behind\n",
						peer->adv_peer_id, (f->max_source_time - source_time) / RIST_CLOCK);
			}
			return -1;
		case RIST_REANCHOR_FORCED:
			rist_log_priv(get_cctx(peer), RIST_LOG_WARN,
					"No current packet to anchor flow on, using seq %" PRIu32 " from peer %"PRIu32", %" PRIu64 " ms behind\n",
					seq, peer->adv_peer_id, (f->max_source_time - source_time) / RIST_CLOCK);
			break;
		case RIST_REANCHOR_OK:
			break;
		}
		f->reanchor_wait_since = 0;
		pthread_mutex_lock(&f->mutex);
		if (atomic_load_explicit(&f->receiver_queue_size, memory_order_acquire) > 0)
		{
			/* Clear the queue if the queue had data */
			/* f->receiver_queue_has_items can be reset to false when the output queue is emptied */
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
					"Clearing up old %zu bytes of old buffer data\n", atomic_load_explicit(&f->receiver_queue_size, memory_order_acquire));
			/* Delete all buffer data (if any) */
			empty_receiver_queue(f, get_cctx(peer));
		}
		rist_flush_missing_flow_queue(f);
		/* Initialize flow session timeout and stats timers */
		f->flag_flow_buffer_start = true;
		f->last_recv_ts = now_monotonic;
		f->checks_next_time = now_monotonic;
		/* Calculate and store clock offset with respect to source */
		if (!f->rtc_timing_mode)
			f->time_offset = (int64_t)now_monotonic - (int64_t)source_time;
		/* This ensures the next packet does not trigger nacks */
		f->last_seq_output = seq - 1;
		f->last_seq_found = seq;
		f->max_source_time = source_time;
		/* This will synchronize idx and seq so we can insert packets into receiver buffer based on seq number */
		size_t idx_initial = seq & (f->receiver_queue_max -1);
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
				"Storing first packet seq %" PRIu32 ", idx %zu, %" PRIu64 ", offset %" PRId64 " ms, output_idx %zu\n",
				seq, idx_initial, source_time, peer->flow->time_offset / RIST_CLOCK, idx_initial);
		uint64_t packet_time = source_time + f->time_offset;

		f->last_packet_ts = packet_time;
		f->time_offset_changed_ts = 0;
		f->time_offset_old = f->time_offset;
		/* Discard clock-drift samples gathered against the previous
		 * baseline.  A flow-id change or a Main<->Advanced wire-framing
		 * switch (the two framings carry source_time in different
		 * timestamp domains) lands here with stale samples still queued;
		 * blending them into the median yields a bogus multi-second
		 * offset correction that releases the whole buffer at once and
		 * overflows the data-out fifo.  Matches the clock-wrap reset. */
		f->offset_recalc_sample_count = 0;

		receiver_insert_queue_packet(f, peer, idx_initial, buf, len, seq, source_time, src_port, dst_port, packet_time);
		atomic_store_explicit(&f->receiver_queue_output_idx, idx_initial, memory_order_release);

		/* reset stats and timing state */
		pthread_mutex_lock(&(get_cctx(peer)->stats_lock));
		memset(&f->stats_instant, 0, sizeof(f->stats_instant));
		pthread_mutex_unlock(&(get_cctx(peer)->stats_lock));
		f->last_output_time = 0;
		f->too_late_ctr = 0;
		f->receiver_queue_has_items = true;
		pthread_mutex_unlock(&f->mutex);
		return 0; // not a dupe
	}

	uint64_t packet_time = receiver_calculate_packet_time(f, source_time, now, retry, payload_type);
    size_t idx = seq & (f->receiver_queue_max - 1);
    if (RIST_UNLIKELY(peer->config.timing_mode == RIST_TIMING_MODE_ARRIVAL && retry))
	{
		//arrival packet time would be incorrect for a retry packet, so instead we interpolate between packets.
		//this does assume CBR
		struct rist_buffer *previous = NULL;
		size_t index = (idx -1)& (f->receiver_queue_max - 1);
		while (previous == NULL && index != idx)
		{
			previous = f->receiver_queue[index];
			index = (index -1)& (f->receiver_queue_max - 1);
		}
		struct rist_buffer *next = NULL;
		index = (idx +1)& (f->receiver_queue_max -1);
		while (next == NULL && index != idx)
		{
			next = f->receiver_queue[index];
			index = (index +1)& (f->receiver_queue_max -1);
		}
		//interpolate the arrival time, assuming CBR
		/* Neighbours can be non-monotonic under arrival-based timing;
		 * clamp the CBR estimate into the interval instead of asserting. */
		if (next && previous && next->packet_time > previous->packet_time)
		{
			uint32_t steps = (next->seq - previous->seq);
			if (f->short_seq)
				steps = (uint16_t)steps;
			uint32_t steps_since_previous = seq - previous->seq;
			if (f->short_seq)
				steps_since_previous = (uint16_t)steps_since_previous;
			if (steps > 1 && steps_since_previous > 0 && steps_since_previous < steps) {
				/* multiply before dividing so integer rounding cannot push
				 * the estimate up to or past next->packet_time */
				uint64_t span = next->packet_time - previous->packet_time;
				packet_time = previous->packet_time + (span * steps_since_previous) / steps;
			} else {
				/* seq is not strictly between the neighbours (gap, reorder
				 * or sequence-number wrap): place it next to next. */
				packet_time = next->packet_time - 1;
			}
			if (packet_time < previous->packet_time)
				packet_time = previous->packet_time;
			else if (packet_time > next->packet_time)
				packet_time = next->packet_time;
		} else if (next)
		{
			/* No usable previous neighbour, or neighbours whose times are
			 * non-monotonic: use next's time. */
			packet_time = next->packet_time;
		}
	}

	// Now, get the new position and check what is there
	/* We need to check if the reader queue has progressed passed this packet, if
	   this is the case we silently drop the packet as it would not be output in a
	   valid way anyway.
	   We only check this for packets that arrive out of order (i.e.: with a lower
	   output time than the highest known output time) */
	size_t reader_idx;
	bool out_of_order = false;
	uint32_t expected_seq = rist_seq_next(f->last_seq_found, f->short_seq);
	if (RIST_UNLIKELY(packet_time < f->last_packet_ts && seq != expected_seq)) {
		if (now > (packet_time + (f->recovery_buffer_ticks *1.1)))
		{
			rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG, "Packet %"PRIu32" too late, dropping!\n", seq);
			pthread_mutex_lock(&(get_cctx(peer)->stats_lock));
			f->stats_instant.dropped_late++;
			/* This soft reset is intentional anti-stall behavior: when a
			 * flow re-bases (received falls back toward 0) it lets the
			 * queue re-anchor onto the changed path instead of stalling.
			 * A crafted late-packet burst can trip it early, but the queue
			 * just rebuilds from the next in-window packet (no persistent
			 * effect), so it is deliberately left without a received floor
			 * here; the hard reset below keeps its received > 100 floor. */
			if (f->stats_instant.dropped_late > 5 * f->stats_instant.received)
				f->receiver_queue_has_items = false;
			if ((f->stats_instant.dropped_late > (f->stats_instant.received * 5) && f->stats_instant.received > 100) ||
				(f->stats_instant.dropped_late > 100 && f->stats_instant.received == 0)) {
					rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Too many late packets received, resetting flow");
					f->receiver_queue_has_items = false;
			}
			pthread_mutex_unlock(&(get_cctx(peer)->stats_lock));
			return -1;
		}
		if (!retry) {
			rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG,
				"Out of order packet received, seq %" PRIu32 " / age %" PRIu64 " ms\n",
				seq, (timestampNTP_u64() - packet_time) / RIST_CLOCK);
			out_of_order = true;
		}
	}
	reader_idx = atomic_load_explicit(&f->receiver_queue_output_idx, memory_order_acquire);
	if (RIST_UNLIKELY(idx == ((reader_idx -1) &(f->receiver_queue_max -1))))
	{
		//Buffer full!
		rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG, "Buffer is full, dropping packet %"PRIu32"/%zu\n", seq, idx);
		if (packet_time > f->last_packet_ts)
			f->last_seq_found  = seq;
		pthread_mutex_lock(&(get_cctx(peer)->stats_lock));
		f->stats_instant.dropped_full++;
		pthread_mutex_unlock(&(get_cctx(peer)->stats_lock));
		//Something is wrong, and we should reset
		if (f->stats_instant.dropped_full > 100) {
			rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Buffer is full, resetting buffer\n");
			f->receiver_queue_has_items = false;
		}
		return -1;
	}
	if (RIST_UNLIKELY(f->receiver_queue[idx])) {
		// TODO: record stats
		struct rist_buffer *b = f->receiver_queue[idx];
		/* Match on seq: the slot index is derived from the sequence number,
		 * and source_time need not be unique per packet, so it cannot
		 * identify a genuine duplicate. A different seq in this slot is a
		 * stale entry from an earlier ring cycle and is replaced below. */
		if (b->seq == seq) {
			rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG, "Dupe! %"PRIu32"/%zu\n", seq, idx);
			pthread_mutex_lock(&(get_cctx(peer)->stats_lock));
			f->stats_instant.dupe++;
			pthread_mutex_unlock(&(get_cctx(peer)->stats_lock));
			return 1;
		}
		else {
			rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG, "Invalid Dupe (possible seq discontinuity)! %"PRIu32", freeing buffer ...\n", seq);
			free_rist_buffer(get_cctx(peer), b);
			f->receiver_queue[idx] = NULL;
		}
	}


	/* Now, we insert the packet into receiver queue */
	if (receiver_insert_queue_packet(f, peer, idx, buf, len, seq, source_time, src_port, dst_port, packet_time)) {
		// only error is OOM, safe to exit here ...
		return 0;
	}
	pthread_mutex_lock(&(get_cctx(peer)->stats_lock));
	if (out_of_order)
		f->stats_instant.reordered++;
	f->stats_instant.received++;
	f->stats_instant.received_bytes += (uint64_t)len;
	pthread_mutex_unlock(&(get_cctx(peer)->stats_lock));
	// Check for missing data and queue retries
	if (!retry) {
		/* check for missing packets */
		// We start at the last known good packet, and look forwards till we hit this seq
		uint32_t missing_seq = seq - 1;
		if (f->short_seq)
			missing_seq = (uint16_t)missing_seq;

		if (!out_of_order && missing_seq != f->last_seq_found)
		{
			receiver_mark_missing(f, peer, seq, rtt);
		} else if (RIST_LIKELY(!f->rtc_timing_mode && !out_of_order))
		{
			//packet received in order, use it's offset as a sample in calculation to
			//correct clock drift
			f->offset_recalc_samples[f->offset_recalc_sample_count] = (int64_t)now - (int64_t)source_time;
			f->offset_recalc_sample_count++;
			if (f->offset_recalc_sample_count == 2048)
				recalculate_clock_offset(f);
		}
		//If we stopped due to bloat or missing count max this will be incorrect.
		if (!out_of_order)
			f->last_seq_found = seq;
	}
	return 0;
}

static int rist_process_nack(struct rist_flow *f, struct rist_missing_buffer *b)
{
	uint64_t now;
	if (RIST_LIKELY(!f->rtc_timing_mode))
		now = timestampNTP_u64();
	else
		now = timestampNTP_RTC_u64();
	struct rist_peer *peer = b->peer;

	pthread_mutex_lock(&f->mutex);
	uint64_t recovery_buffer_ticks = f->recovery_buffer_ticks;
	pthread_mutex_unlock(&f->mutex);

	if (b->nack_count >= peer->config.max_retries) {
		rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG, "Datagram %"PRIu32
				" is missing, but nack count is too large (%u), age is %"PRIu64"ms, retry #%lu, max_retries %d, congestion_control_mode %d, stats_receiver_total.recovered_average %d\n",
				b->seq,
				b->nack_count,
				(now - b->insertion_time) / RIST_CLOCK,
				b->nack_count,
				peer->config.max_retries,
				peer->config.congestion_control_mode,
				f->stats_total.recovered_average);
		return 8;
	} else {
		if ((uint64_t)(now - b->insertion_time) > (recovery_buffer_ticks *1.1)) {
			rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG,
					"Datagram %" PRIu32 " is missing but it is too late (%" PRIu64
					"ms) to send NACK!, retry #%lu, retry queue %d, max time %"PRIu64"\n",
					b->seq, (now - b->insertion_time)/RIST_CLOCK, b->nack_count,
					f->missing_counter, recovery_buffer_ticks / RIST_CLOCK);
			return 9;
		} else if (now >= b->next_nack) {
			uint64_t rtt = (peer->eight_times_rtt / 8);
			if (rtt < peer->config.recovery_rtt_min) {
				rtt = peer->config.recovery_rtt_min;
			} else if (rtt > peer->config.recovery_rtt_max) {
				rtt = peer->config.recovery_rtt_max;
			}
			if (b->nack_count == 0) {
				pthread_mutex_lock(&(get_cctx(peer)->stats_lock));
				f->stats_instant.missing++;
				pthread_mutex_unlock(&(get_cctx(peer)->stats_lock));
			}

			// TODO: make this 10% overhead configurable?
			// retry more when we are running out of time (proportional)
			/* start with 1.1 * 1000 and go down from there */
			//uint32_t ratio = 1100 - (b->nack_count * 1100)/(2*b->peer->config.max_retries);
			//b->next_nack = now + (uint64_t)rtt * (uint64_t)ratio * (uint64_t)RIST_CLOCK;
			b->next_nack = now + (uint64_t)(rtt * 1.1);
			b->nack_count++;

			if (get_cctx(peer)->debug)
				rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG, "Datagram %" PRIu32 " is missing, sending NACK!, next retry in %" PRIu64 "ms, age is %" PRIu64 "ms, retry #%lu, max_size is %" PRIu64 "ms\n",
					b->seq, (b->next_nack - now) / RIST_CLOCK,
					(now - b->insertion_time) / RIST_CLOCK,
					b->nack_count,
					recovery_buffer_ticks / RIST_CLOCK);

			// update peer information
			f->nacks.array[f->nacks.counter] = b->seq;
			f->nacks.counter++;
			pthread_mutex_lock(&(get_cctx(peer)->stats_lock));
			f->stats_instant.retries++;
			pthread_mutex_unlock(&(get_cctx(peer)->stats_lock));
		}
	}

	return 0;
}

void free_data_block(struct rist_data_block **const block)
{
	assert(block != NULL);
	struct rist_data_block *b = *block;
	if (!b)
		return;

	if (atomic_fetch_sub(&b->ref->refcnt, 1) == 1)
	{
		assert(b->ref->ptr == b);
		uint8_t *payload = ((uint8_t*)b->payload - RIST_MAX_PAYLOAD_OFFSET);//this is extremely ugly, though these offsets will stop existing in next release
		free(payload);
		free((void *)b->ref);
		free(b);
	}
	*block = NULL;
}

static struct rist_data_block *new_data_block(struct rist_data_block *output_buffer_current, struct rist_buffer *b, uint8_t *payload, uint32_t flow_id, uint32_t flags)
{
	struct rist_data_block *output_buffer;
	if (output_buffer_current) {
		if (rist_ref_iswritable(output_buffer_current->ref)) {
			output_buffer = output_buffer_current;
			uint8_t *p = ((uint8_t*)output_buffer_current->payload - RIST_MAX_PAYLOAD_OFFSET);
			free(p);
		} else {
			free_data_block(&output_buffer_current);
			output_buffer = calloc(1, sizeof(*output_buffer));
		}
	}
	else
		output_buffer = calloc(1, sizeof(struct rist_data_block));
	if (!output_buffer) {
		rist_log_priv2(get_cctx(b->peer)->logging_settings, RIST_LOG_ERROR, "Error (re)allocating rist_data_block.");
		return NULL;
	}
	if (!output_buffer->ref) {
		output_buffer->ref = rist_ref_create(output_buffer);
		if (!output_buffer->ref) {
			rist_log_priv2(get_cctx(b->peer)->logging_settings, RIST_LOG_ERROR, "Error allocating rist_ref.");
			free(output_buffer);
			return NULL;
		}
	}
	output_buffer->peer = b->peer;
	output_buffer->flow_id = flow_id;
	output_buffer->payload = payload;
	output_buffer->payload_len = b->size;
	output_buffer->virt_src_port = b->src_port;
	output_buffer->virt_dst_port = b->dst_port;
	output_buffer->ts_ntp = b->source_time;
	output_buffer->seq = b->seq;
	output_buffer->flags = flags;
	return output_buffer;
}

static void receiver_output(struct rist_receiver *ctx, struct rist_flow *f)
{

	uint64_t recovery_buffer_ticks = f->recovery_buffer_ticks;
	uint64_t now;
	if (RIST_LIKELY(!f->rtc_timing_mode))
		now = timestampNTP_u64();
	else
		now = timestampNTP_RTC_u64();
	size_t output_idx = atomic_load_explicit(&f->receiver_queue_output_idx, memory_order_acquire);
	while (atomic_load_explicit(&f->receiver_queue_size, memory_order_acquire) > 0 && atomic_load_explicit(&f->shutdown, memory_order_acquire) == 0) {
		// Find the first non-null packet in the queuecounter loop
		struct rist_buffer *b = f->receiver_queue[output_idx];
		size_t holes = 0;
		if (!b) {
			//rist_log_priv(&ctx->common, RIST_LOG_ERROR, "\tLooking for first non-null packet (%zu)\n", f->receiver_queue_size);
			size_t counter = 0;
			counter = output_idx;
			while (!b) {
				counter = (counter + 1)& (f->receiver_queue_max -1);
				holes++;
				b = f->receiver_queue[counter];
				if (counter == output_idx) {
					// This should never happen, if this fires queue size is out of sync with reality.
					rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Did not find any data after a full counter loop (%zu)\n", atomic_load_explicit(&f->receiver_queue_size, memory_order_acquire));
					// if the entire buffer is empty, something is very wrong, reset the queue ...
					f->receiver_queue_has_items = false;
					atomic_store_explicit(&f->receiver_queue_size, 0, memory_order_release);
					// exit the function and wait 5ms (max jitter time)
					return;
				}
			}
			if (b) {
				uint64_t delay1 = (now - b->time);
				if (RIST_UNLIKELY(delay1 > (2LLU * recovery_buffer_ticks))) {
					// According to the real time clock, it is too late, continue.
				} else if (b->target_output_time > now) {
					// The block we found is not ready for output, so we wait.
					break;
				}
			}
			/* Count the sequence gap, not the ring slots we stepped over:
			 * the two only agree while the reader sits right behind the
			 * data, and after an idle source or a re-anchor the walk spans
			 * far more slots than there are missing packets. */
			uint32_t gap = rist_seq_gap(b->seq, rist_seq_next(f->last_seq_output, f->short_seq),
						    f->short_seq);
			size_t max_holes = f->short_seq ? (UINT16_SIZE / 2) : (f->receiver_queue_max / 2);
			if (gap <= max_holes) {
				pthread_mutex_lock(&ctx->common.stats_lock);
				f->stats_instant.lost += gap;
				pthread_mutex_unlock(&ctx->common.stats_lock);
			}
			output_idx = counter;
			rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
					"Empty buffer element, flushing %zu hole(s), now at index %zu, size is %zu\n",
					holes, counter, atomic_load_explicit(&f->receiver_queue_size, memory_order_acquire));
		}
		if (b) {
			bool merged = false;
			if (b->type == RIST_PAYLOAD_TYPE_DATA_RAW) {

				now = timestampNTP_u64();
				uint64_t delay_rtc = (now - b->time);
				if (RIST_UNLIKELY(delay_rtc > (1.1 * recovery_buffer_ticks) )) {
					// Double check the age of the packet within our receiver queue
					// Safety net for discontinuities in source timestamp, clock drift or improperly scaled timestamp
					uint64_t delay = now > b->packet_time ? (now - b->packet_time) : 0;
					bool drop = false;
					//This should be impossible as we should catch it with the normal case
					if (RIST_UNLIKELY(delay_rtc > (2ULL * recovery_buffer_ticks))) {
						f->too_late_ctr++;
						drop = true;
						if (f->too_late_ctr > 100) {
							rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Too many old packets, resetting buffer\n");
							/* clear the latch, else it re-fires every output cycle */
							f->too_late_ctr = 0;
							f->receiver_queue_has_items = false;
							return;
						}
						goto next;
					}
					rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
							"Packet %"PRIu32" (%zu bytes) is too old %"PRIu64"/%"PRIu64" ms, deadline = %"PRIu64", offset = %"PRId64" ms, %s data\n",
							b->seq, b->size,
							delay_rtc / RIST_CLOCK, delay / RIST_CLOCK,
							recovery_buffer_ticks / RIST_CLOCK, f->time_offset / RIST_CLOCK,
							drop? "dropping" : "releasing");

				}
				else if (b->target_output_time > now && (!f->currently_scaling_buffer || (f->currently_scaling_buffer && (b->packet_time + f->recovery_buffer_ticks) > now))) {
					// This is how we keep the buffer at the correct level
					//rist_log_priv(&ctx->common, RIST_LOG_WARN, "age is %"PRIu64"/%"PRIu64" < %"PRIu64", size %zu\n",
					//	delay_rtc / RIST_CLOCK , delay / RIST_CLOCK, recovery_buffer_ticks / RIST_CLOCK, f->receiver_queue_size);
					break;
				}
				/* The buffer has cleared this packet; pacing decides whether it
				 * is its turn in the measured cadence yet. Delay only, and it
				 * yields below rather than hold a packet past its deadline. */
				if (f->cbr_output) {
					uint64_t iv = rist_pacer_interval_ns(&f->cbr_pacer,
									rist_pacer_rate_bps(&f->cbr_rate), b->size, 0);
					if (iv) {
						uint64_t now_ns = timestampNTP_to_ns(now);
						f->cbr_interval_ns = iv;
						if (rist_pacer_due_ns(&f->cbr_pacer, now_ns) > now_ns) {
							uint64_t overdue = now > b->target_output_time ?
									(now - b->target_output_time) : 0;
							if (overdue < ((uint64_t)f->cbr_max_hold_us * RIST_CLOCK) / 1000) {
								f->cbr_paced_hold = true; /* waiting its turn, not idle */
								break;
							}
							/* Re-anchor, else every later packet lands here too. */
							f->cbr_overdue_releases++;
							rist_pacer_reset(&f->cbr_pacer);
							rist_pacer_due_ns(&f->cbr_pacer, now_ns);
						}
						rist_pacer_advance(&f->cbr_pacer, iv);
					}
				}
				if (holes > 0)
				{
					rist_log_priv(&ctx->common, RIST_LOG_DEBUG, "Did not find any data after %zu holes (%zu bytes in queue)\n",
							holes, atomic_load_explicit(&f->receiver_queue_size, memory_order_acquire));
				}
				f->too_late_ctr = 0;
				// Check sequence number and report lost packet
				uint32_t next_seq = f->last_seq_output + 1;
				f->last_output_time = now;
				if (f->short_seq)
					next_seq = (uint16_t)next_seq;
				if (b->seq != next_seq && !holes) {
					rist_log_priv(&ctx->common, RIST_LOG_ERROR,
							"Discontinuity, expected %" PRIu32 " got %" PRIu32 "\n",
							f->last_seq_output + 1, b->seq);
					pthread_mutex_lock(&ctx->common.stats_lock);
					f->stats_instant.lost++;
					pthread_mutex_unlock(&ctx->common.stats_lock);
					holes = 1;
				}
				if (b->type == RIST_PAYLOAD_TYPE_DATA_RAW) {
					uint32_t flags = 0;
					if (holes)
						flags = RIST_DATA_FLAGS_DISCONTINUITY;
					if (f->flag_flow_buffer_start) {
						f->flag_flow_buffer_start = false;
						flags |= RIST_DATA_FLAGS_FLOW_BUFFER_START;
					}

					bool merge_active = (ctx->merge_mode == LIBRIST_MERGE_MODE_PAIRS) ||
					                    (ctx->merge_mode == LIBRIST_MERGE_MODE_AUTO &&
					                     f->merge_auto_enabled);

					struct rist_data_block *block = NULL;

					if (merge_active && (b->seq & 1) == 0) {
						size_t partner_idx = (output_idx + 1) & (f->receiver_queue_max - 1);
						struct rist_buffer *b2 = f->receiver_queue[partner_idx];
						if (b2 && b2->type == RIST_PAYLOAD_TYPE_DATA_RAW &&
						    b2->seq == rist_seq_next(b->seq, f->short_seq) &&
						    b2->source_time == b->source_time) {
							size_t combined_len = b->size + b2->size;
							uint8_t *combined = malloc(RIST_MAX_PAYLOAD_OFFSET + combined_len);
							if (combined) {
								memcpy(combined + RIST_MAX_PAYLOAD_OFFSET,
								       (uint8_t *)b->data + RIST_MAX_PAYLOAD_OFFSET, b->size);
								memcpy(combined + RIST_MAX_PAYLOAD_OFFSET + b->size,
								       (uint8_t *)b2->data + RIST_MAX_PAYLOAD_OFFSET, b2->size);
								block = calloc(1, sizeof(*block));
								if (block) {
									block->ref = rist_ref_create(block);
									block->peer = b->peer;
									block->flow_id = f->flow_id;
									block->payload = combined + RIST_MAX_PAYLOAD_OFFSET;
									block->payload_len = combined_len;
									block->virt_src_port = b->src_port;
									block->virt_dst_port = b->dst_port;
									block->ts_ntp = b->source_time;
									block->seq = b->seq / 2;
									block->flags = flags;
									merged = true;
									ctx->stats_pairs_merged++;
								} else {
									free(combined);
								}
							}
							if (merged) {
								b->data = NULL;
								f->last_seq_output = b2->seq;
								atomic_fetch_sub_explicit(&f->receiver_queue_size, b2->size, memory_order_relaxed);
								f->receiver_queue[partner_idx] = NULL;
								free_rist_buffer(&ctx->common, b2);
							}
						} else {
							ctx->stats_orphan_first_delivered++;
						}
					} else if (merge_active && (b->seq & 1) == 1) {
						ctx->stats_orphan_last_delivered++;
					}

					if (!merged) {
						uint8_t *payload = b->data;
						block = new_data_block(
								NULL, b,
								&payload[RIST_MAX_PAYLOAD_OFFSET], f->flow_id, flags);
						b->data = NULL;
					}
					if (ctx->receiver_data_fd >= 0 && block) {
						int written;
						if (ctx->receiver_data_fd_flags & RIST_DATA_FD_FLAG_TUN)
							written = rist_tun_write(ctx->receiver_data_fd, block->payload, block->payload_len);
						else
							written = (int)write(ctx->receiver_data_fd, block->payload, block->payload_len);
						if (written > 0) {
							atomic_fetch_add_explicit(&ctx->data_fd_rx_packets, 1, memory_order_relaxed);
							atomic_fetch_add_explicit(&ctx->data_fd_rx_bytes, (uint_fast64_t)written, memory_order_relaxed);
						}
						rist_receiver_data_block_free2(&block);
					} else if (ctx->receiver_data_callback && block) {
						rist_ref_inc(block->ref);
						// send to callback synchronously
						ctx->receiver_data_callback(ctx->receiver_data_callback_argument,
								block);
					}

					size_t dataout_fifo_write_index = atomic_load_explicit(&f->dataout_fifo_queue_write_index, memory_order_relaxed);
					size_t dataout_fifo_read_index = atomic_load_explicit(&f->dataout_fifo_queue_read_index, memory_order_acquire);
					uint32_t fifo_count = (dataout_fifo_write_index - dataout_fifo_read_index)&(ctx->fifo_queue_size -1);
					if (fifo_count +1 == ctx->fifo_queue_size || !ctx->fifo_queue_size) {
						if (!ctx->receiver_data_callback && ctx->receiver_data_fd < 0)
							rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Rist data out fifo queue overflow\n");
						rist_receiver_data_block_free2(&block);
						atomic_store_explicit(&f->fifo_overflow, true, memory_order_release);
					} else {
						if (RIST_UNLIKELY(atomic_load_explicit(&f->fifo_overflow, memory_order_relaxed) == true)) {
							atomic_store_explicit(&f->fifo_overflow, false, memory_order_release);
						}
						f->dataout_fifo_queue[dataout_fifo_write_index] = block;
						atomic_store_explicit(&f->dataout_fifo_queue_write_index, (dataout_fifo_write_index + 1)& (ctx->fifo_queue_size-1), memory_order_relaxed);
						// Wake up the fifo read thread (poll)
						if (ctx->receiver_data_ready_notify_fd) {
							// send a data ready signal by writing a single byte of value 0
							char empty = '\0';
							if(write(ctx->receiver_data_ready_notify_fd, &empty, 1) == -1)
							{
								// We ignore the error condition as missing data is not harmful here
								// It is only a signaling mechanism
							}
						}
					}
					pthread_mutex_lock(&ctx->common.stats_lock);
					if (f->stats_instant.buffer_duration_count < 2048)
					{
						f->stats_instant.buffer_duration[f->stats_instant.buffer_duration_count] = (uint32_t)(delay_rtc / RIST_CLOCK);
						f->stats_instant.buffer_duration_count++;
					}
					pthread_mutex_unlock(&ctx->common.stats_lock);
					if (pthread_cond_signal(&(ctx->condition)))
						rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Call to pthread_cond_signal failed.\n");
				}
				// Track this one only for data
				f->last_seq_output_source_time = b->source_time;
			}
			//else
			//	fprintf(stderr, "rtcp skip at %"PRIu32", just removing it from queue\n", b->seq);

next:
			if (!merged)
				f->last_seq_output = b->seq;
			atomic_fetch_sub_explicit(&f->receiver_queue_size, b->size, memory_order_relaxed);
			f->receiver_queue[output_idx] = NULL;
			free_rist_buffer(&ctx->common, b);
			output_idx = (output_idx + 1)& (f->receiver_queue_max -1);
			if (merged) {
				/* partner already freed and NULLed above; skip its slot */
				output_idx = (output_idx + 1) & (f->receiver_queue_max - 1);
			}
			atomic_store_explicit(&f->receiver_queue_output_idx, output_idx, memory_order_release);
			if (atomic_load_explicit(&f->receiver_queue_size, memory_order_acquire) == 0) {
				if (f->last_output_time == 0)
					f->last_output_time = now;
				uint64_t delta = now - f->last_output_time;
				rist_log_priv(&ctx->common, RIST_LOG_DEBUG, "Buffer is empty, it has been for %"PRIu64" < %"PRIu64" (ms)!\n",
						delta / RIST_CLOCK, recovery_buffer_ticks / RIST_CLOCK);
				// if the entire buffer is empty, something is very wrong, reset the queue ...
				if (delta > recovery_buffer_ticks)
				{
					rist_log_priv(&ctx->common, RIST_LOG_ERROR, "stream is dead (%"PRIu64" ms), re-initializing flow\n",
						delta/ RIST_CLOCK);
					f->receiver_queue_has_items = false;
				}
				// exit the function and wait 5ms (max jitter time)
				return;
			}
			f->last_output_time = now;
		}
	}

}

static void send_nack_group(struct rist_receiver *ctx, struct rist_flow *f)
{
	// Now actually send all the nack IP packets for this flow (the above routing will process/group them)
	if (f->nacks.counter == 0)
		return;
	/* Lock order: peerlist_lock outside, f->mutex inside. */
	pthread_mutex_lock(&ctx->common.peerlist_lock);
	pthread_mutex_lock(&f->mutex);
	struct rist_peer *peer = NULL;
	uint64_t best_rtt = UINT64_MAX;
	uint32_t best_priority = 0;
	if (f->peer_lst_len == 0 || f->peer_lst == NULL)
		goto out;
	/* Route NACKs to the eligible peer with the highest recovery_priority,
	 * tie-broken by lowest RTT.  With the default priority of 0 on every
	 * peer this reduces to the historical lowest-RTT selection. */
	for (size_t i = 0; i < f->peer_lst_len; i++)
	{
		struct rist_peer *check = f->peer_lst[i];
		if (!check->is_rtcp || check->dead)
			continue;
		uint32_t priority = check->config.recovery_priority;
		if (rist_nack_peer_preferred(priority, check->last_rtt,
		                             best_priority, best_rtt))
		{
			peer = check;
			best_priority = priority;
			best_rtt = check->last_rtt;
		}
	}
	if (peer != NULL)
		rist_receiver_send_nacks(peer,f->nacks.array, f->nacks.counter);
	else
	{
		for (size_t i = 0; i < f->peer_lst_len; i++)
		{
			struct rist_peer *check = f->peer_lst[i];
			uint64_t dead_since = 0;
			if (check->is_rtcp && check->dead_since > dead_since)
			{
				peer = check;
			}
			if (peer != NULL)
				rist_receiver_send_nacks(peer,f->nacks.array, f->nacks.counter);
		}
	}
	f->nacks.counter = 0;
out:
	pthread_mutex_unlock(&f->mutex);
	pthread_mutex_unlock(&ctx->common.peerlist_lock);
}

void receiver_nack_output(struct rist_receiver *ctx, struct rist_flow *f)
{

	if (!f->authenticated) {
		return;
	}

	const size_t maxcounter = RIST_MAX_NACKS;

	/* Now loop through missing queue and process items */
	struct rist_missing_buffer *mb = f->missing;
	struct rist_missing_buffer **prev = &f->missing;
	struct rist_missing_buffer *previous = NULL;
	int empty = 0;
	while (mb) {
		int remove_from_queue_reason = 0;
		struct rist_peer *peer = mb->peer;
		ssize_t idx = mb->seq& (f->receiver_queue_max -1);
		if (peer->config.recovery_mode == RIST_RECOVERY_MODE_DISABLED) {
			rist_log_priv(&ctx->common, RIST_LOG_ERROR,
					"Nack processing is disabled for this peer, removing seq %"PRIu32" from queue ...\n",
					mb->seq);
			remove_from_queue_reason = 10;
			f->stats_instant.missing--;
			goto nack_loop_continue;
		} else if (f->receiver_queue[idx]) {
			if (f->receiver_queue[idx]->seq == mb->seq) {
				pthread_mutex_lock(&ctx->common.stats_lock);
				// We filled in the hole already ... packet has been recovered
				remove_from_queue_reason = 3;
				if (mb->nack_count > 0)
					f->stats_instant.recovered++;
				switch(mb->nack_count) {
					case 0:
						break;
					case 1:
						f->stats_instant.recovered_0nack++;
						break;
					case 2:
						f->stats_instant.recovered_1nack++;
						break;
					case 3:
						f->stats_instant.recovered_2nack++;
						break;
					case 4:
						f->stats_instant.recovered_3nack++;
						break;
					default:
						f->stats_instant.recovered_morenack++;
						break;
				}
				f->stats_instant.recovered_sum += mb->nack_count;
				pthread_mutex_unlock(&ctx->common.stats_lock);
			}
			else {
				// Message with wrong seq!!!
				rist_log_priv(&ctx->common, RIST_LOG_ERROR,
						"Retry queue has the wrong seq %"PRIu32" != %"PRIu32", removing ...\n",
						f->receiver_queue[idx]->seq, mb->seq);
				remove_from_queue_reason = 4;
				pthread_mutex_lock(&ctx->common.stats_lock);
				f->stats_instant.missing--;
				pthread_mutex_unlock(&ctx->common.stats_lock);
				goto nack_loop_continue;
			}
		} else if (peer->buffer_bloat_active) {
			if (peer->config.congestion_control_mode == RIST_CONGESTION_CONTROL_MODE_AGGRESSIVE) {
				if (empty == 0) {
					rist_log_priv(&ctx->common, RIST_LOG_ERROR,
							"Retry queue is too large, %d, collapsed link (%u), flushing all nacks ...\n", f->missing_counter,
							f->stats_total.recovered_average/8);
				}
				remove_from_queue_reason = 5;
				empty = 1;
			} else if (peer->config.congestion_control_mode == RIST_CONGESTION_CONTROL_MODE_NORMAL) {
				if (mb->nack_count > 4) {
					if (empty == 0) {
						rist_log_priv(&ctx->common, RIST_LOG_ERROR,
								"Retry queue is too large, %d, collapsed link (%u), flushing old nacks (%u > %u) ...\n",
								f->missing_counter, f->stats_total.recovered_average/8, mb->nack_count, 4);
					}
					remove_from_queue_reason = 6;
					empty = 1;
				}
			}
		} else {
			// Packet is still missing, re-stamp the expiration time so we can re-add to queue
			// We reject the next retry for a number of reasons checked inside the function,
			// in which case the nack will never be resent and we signal a queue removal
			if (f->nacks.counter == (maxcounter - 1)) {
				rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
						"nack max counter per packet (%d) exceeded. Skipping the rest\n",
						maxcounter);
				send_nack_group(ctx, f);
			}
			else if (f->nacks.counter >= maxcounter) {
				rist_log_priv(&ctx->common, RIST_LOG_ERROR,
						"nack max counter per packet (%zu) exceeded. Something is very wrong and"
						" there is a strong chance memory is corrupt because we wrote past the end"
						"of the nacks.array max size!!!\n", f->nacks.counter );
				f->nacks.counter = 0;
				//TODO: maybe assert is more appropriate here?
			}
			remove_from_queue_reason = rist_process_nack(f, mb);
		}
nack_loop_continue:
		if (remove_from_queue_reason != 0) {
			if (ctx->common.debug)
				rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
						"Removing seq %" PRIu32 " from missing, queue size is %d, retry #%u, age %"PRIu64"ms, reason %d\n",
						mb->seq, f->missing_counter, mb->nack_count, (timestampNTP_u64() - mb->insertion_time) / RIST_CLOCK, remove_from_queue_reason);
			struct rist_missing_buffer *next = mb->next;
			if (!next)
				f->missing_tail = previous;
			*prev = next;
			f->missing_counter--;
			free(mb);
			mb = next;
		} else {
			/* Move it to the end of the queue */
			// TODO: I think this is wrong and we loose nacks when we get here
			previous = mb;
			prev = &mb->next;
			mb = mb->next;
		}
	}

	// Empty all peer nack queues, i.e. send them
	send_nack_group(ctx, f);

}

static int rist_set_manual_sockdata(struct rist_peer *peer, const struct rist_peer_config *config)
{
	peer->address_family = (uint16_t)config->address_family;//TODO: should it not just be a uint16_t then?
	peer->listening = !config->initiate_conn;
	const char *hostname = config->address;
	int ret;
	if ((!hostname || !*hostname) && peer->listening) {
		if (peer->address_family == AF_INET) {
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "No hostname specified: listening to 0.0.0.0\n");
			peer->address_len = sizeof(struct sockaddr_in);
			((struct sockaddr_in *)&peer->u.address)->sin_family = AF_INET;
			((struct sockaddr_in *)&peer->u.address)->sin_addr.s_addr = INADDR_ANY;
		} else {
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "No hostname specified: listening to [::0]\n");
			peer->address_len = sizeof(struct sockaddr_in6);
			((struct sockaddr_in6 *)&peer->u.address)->sin6_family = AF_INET6;
			((struct sockaddr_in6 *)&peer->u.address)->sin6_addr = in6addr_any;
		}
	} else {
		ret = udpsocket_resolve_host(hostname, config->physical_port, &peer->u.address);
		if (ret != 0) {
			rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Error trying to resolve hostname %s\n", hostname);
			goto err;
		}
		peer->address_family = ((struct sockaddr_in *)&peer->u.address)->sin_family;
		if (peer->address_family == AF_INET)
			peer->address_len = sizeof(struct sockaddr_in);
		else
			peer->address_len = sizeof(struct sockaddr_in6);
	}
	if (peer->listening)
		peer->local_port = config->physical_port;
	else
		peer->remote_port = config->physical_port;

	return 0;

err:
	peer->address_family = AF_LOCAL;
	peer->address_len = 0;
	return -1;
}



struct rist_peer *_librist_peer_create_common(struct rist_common_ctx *cctx, struct rist_receiver *rctx, struct rist_sender *sctx, const struct rist_peer_config *config)
{
	int key_size = config->key_size;
	if (strlen(config->secret) && !key_size) {
		rist_log_priv(cctx, RIST_LOG_NOTICE, "PSK Set but key size not explicitly configured, defaulting to AES256");
		key_size = 256;
	}
	if (key_size) {
		if (key_size != 128 && key_size != 192 && key_size != 256) {
			rist_log_priv(cctx, RIST_LOG_ERROR, "Invalid encryption key length: %d\n", key_size);
			return NULL;
		}
		if (!strlen(config->secret)) {

			rist_log_priv(cctx, RIST_LOG_ERROR, "Invalid secret passphrase\n");
			return NULL;
		}
		rist_log_priv(cctx, RIST_LOG_INFO, "Using %d bits secret key\n", key_size);
	}
	else {
		rist_log_priv(cctx, RIST_LOG_INFO, "Encryption is disabled for this peer\n");
	}

	/* Initialize peer */
	struct rist_peer *p = peer_initialize(config->address, sctx, rctx);
	if (!p) {
		return NULL;
	}

	strncpy(&p->miface[0], config->miface, RIST_MAX_STRING_SHORT);
	p->miface[RIST_MAX_STRING_SHORT - 1] = '\0';
	strncpy(&p->cname[0], config->cname, RIST_MAX_STRING_SHORT);
	p->cname[RIST_MAX_STRING_SHORT - 1] = '\0';
	if (config->address_family && rist_set_manual_sockdata(p, config)) {
		free(p);
		return NULL;
	}

	_librist_crypto_psk_rist_key_init(&p->key_tx, key_size, config->key_rotation, config->secret, false);
	_librist_crypto_psk_rist_key_init(&p->key_tx_odd, key_size, config->key_rotation, config->secret, true);
	_librist_crypto_psk_rist_key_clone(&p->key_tx, &p->key_rx);
	_librist_crypto_psk_rist_key_clone(&p->key_tx_odd, &p->key_rx_odd);

	if (config->keepalive_interval > 0) {
		p->rtcp_keepalive_interval = config->keepalive_interval * RIST_CLOCK;
	}

	/* Unset session_timeout means the documented default; floored at a few
	 * RTCP intervals so a peer is never declared dead before its heartbeat
	 * could have arrived. */
	uint64_t min_liveness = RIST_LIVENESS_MIN_PINGS * p->rtcp_keepalive_interval;
	if (config->session_timeout > 0)
		p->session_timeout = (uint64_t)config->session_timeout * RIST_CLOCK;
	else
		p->session_timeout = (uint64_t)RIST_DEFAULT_SESSION_TIMEOUT * RIST_CLOCK;
	if (p->session_timeout < min_liveness) {
		rist_log_priv(cctx, RIST_LOG_WARN, "The configured (%"PRIu64" ms) peer session timeout is below %"PRIu64" ms (%d RTCP intervals), using the floor instead\n",
			p->session_timeout / RIST_CLOCK, min_liveness / RIST_CLOCK, RIST_LIVENESS_MIN_PINGS);
		p->session_timeout = min_liveness;
	}

	if (cctx->profile > RIST_PROFILE_SIMPLE) {
		if (_librist_network_get_macaddr(p->mac_addr) < 0)
			rist_log_priv(cctx, RIST_LOG_WARN, "Couldn't get a mac address for peer, keepalive will not contain a mac address\n");
	}
	/* Initialize socket */
	rist_create_socket(p);
	if (p->sd < 0) {
		rist_log_priv(cctx, RIST_LOG_ERROR, "Could not create socket\n");
		free(p);
		return NULL;
	}
	store_peer_settings(config, p);
	return p;
}

struct rist_peer *rist_receiver_peer_insert_local(struct rist_receiver *ctx,
		const struct rist_peer_config *config)
{
	struct rist_peer *p = _librist_peer_create_common(&ctx->common, ctx, NULL, config);
	if (!p)
		return NULL;
	if (config->virt_dst_port != 0) {
		p->remote_port = config->virt_dst_port + 1;
	}

	p->adv_peer_id = ++ctx->common.peer_counter;
	return p;
}

/* PEERS are created at startup. The default state is RIST_PEER_STATE_IDLE
 * This function will initiate the connection to the peer if a peer address is available.
 * If no address is configured for the endpoint, the peer is put in wait mode.
 */
void rist_fsm_init_comm(struct rist_peer *peer)
{

	peer->authenticated = false;

	if (!peer->receiver_mode) {
		if (peer->listening) {
			/* sender mode listening/waiting for receiver */
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
					"Initialized Sender Peer, listening mode ...\n");
		} else {
			/* sender mode connecting to receiver */
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
					"Initialized Sender Peer, connecting to receiver ...\n");
		}
	} else {
		if (peer->listening) {
			/* receiver mode listening/waiting for sender */
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
					"Initialized Receiver Peer, listening mode ...\n");
		} else {
			/* receiver mode connecting to sender */
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
					"Initialized Receiver Peer, connecting to sender ...\n");
		}
	}
	peer->authenticated = false;
	rist_print_inet_info("Active ", peer);

	/* Start the timer that reads data from this peer */
	if (!peer->event_recv) {
		struct evsocket_ctx *evctx = get_cctx(peer)->evctx;
		peer->event_recv = evsocket_addevent(evctx, peer->sd, EVSOCKET_EV_READ,
				rist_peer_recv_wrap, rist_peer_sockerr, peer);
	}

	/* Enable RTCP timer and jump start it */
	if (!peer->listening && peer->is_rtcp) {
		if (!peer->send_keepalive) {
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Enabling keepalive for peer %"PRIu32"\n", peer->adv_peer_id);
			peer->send_keepalive = true;
		}
		if (get_cctx(peer)->profile > RIST_PROFILE_SIMPLE && !peer->eap_ctx) {
			//Try version 2 first
			_librist_proto_gre_send_keepalive(peer, 2);
			_librist_proto_gre_send_keepalive(peer, 2);
			_librist_proto_gre_send_keepalive(peer, 2);
			_librist_proto_gre_send_keepalive(peer, 1);
			_librist_proto_gre_send_keepalive(peer, 1);
			_librist_proto_gre_send_keepalive(peer, 1);
			if (peer->sender_ctx != NULL) {
				_librist_proto_gre_send_buffer_negotiation(peer, peer->sender_ctx->sender_recover_min_time, 0);
				_librist_proto_gre_send_buffer_negotiation(peer, peer->sender_ctx->sender_recover_min_time, 0);
				_librist_proto_gre_send_buffer_negotiation(peer, peer->sender_ctx->sender_recover_min_time, 0);
			}
		}
		/* call it the first time manually to speed up the handshake */
		rist_peer_rtcp(NULL, peer);
		/* send 3 echo requests to jumpstart accurate RTT calculation */
		rist_request_echo(peer);
		rist_request_echo(peer);
		rist_request_echo(peer);
	}
}

void rist_peer_authenticate(struct rist_peer *peer)
{
	peer->authenticated = true;
	if (peer->peer_data)
		peer->peer_data->authenticated = true;

	/* Re-auth means any prior caller rebind converged; clear the backoff so
	 * the next outage retries promptly instead of from an ever-growing gap. */
	peer->rebind_attempts = 0;
	peer->last_rebind_time = 0;
	if (peer->peer_data) {
		peer->peer_data->rebind_attempts = 0;
		peer->peer_data->last_rebind_time = 0;
	}
	if (peer->peer_rtcp) {
		peer->peer_rtcp->rebind_attempts = 0;
		peer->peer_rtcp->last_rebind_time = 0;
	}

	rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
			"Successfully Authenticated peer %"PRIu32"\n", peer->adv_peer_id);
}

void rist_calculate_bitrate(size_t len, struct rist_bandwidth_estimation *bw)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	uint64_t now = (uint64_t)tv.tv_sec * 1000000;
	now += tv.tv_usec;
	uint64_t time = now - bw->last_bitrate_calctime;
	uint64_t time_fast = now - bw->last_bitrate_calctime_fast;

	if (!bw->last_bitrate_calctime) {
		bw->last_bitrate_calctime = now;
		bw->last_bitrate_calctime_fast = now;
		bw->eight_times_bitrate = 0;
		bw->eight_times_bitrate_fast = 0;
		bw->bytes = 0;
		bw->bytes_fast = 0;
		bw->bitrate = 0;
		bw->bitrate_fast = 0;
		return;
	}

	if (time_fast < 100000 /* 100 ms */) {
		bw->bytes_fast += len;
	}
	else {
		bw->bytes_fast += len;
		bw->bitrate_fast = (size_t)((8 * bw->bytes_fast * 1000000) / time_fast);
		bw->eight_times_bitrate_fast += bw->bitrate_fast - bw->eight_times_bitrate_fast / 8;
		bw->last_bitrate_calctime_fast = now;
		bw->bytes_fast = 0;
	}

	if (time < 1000000 /* 1 second */) {
		bw->bytes += len;
		return;
	}
	else {
		bw->bytes += len;
		bw->bitrate = (size_t)((8 * bw->bytes * 1000000) / time);
		bw->eight_times_bitrate += bw->bitrate - bw->eight_times_bitrate / 8;
		bw->last_bitrate_calctime = now;
		bw->bytes = 0;
	}
}

/* Recompute bw->bitrate using zero new bytes so the value decays to
 * zero when the stats tick fires but no packets have arrived on this
 * counter since the last tick. Mirrors what rist_calculate_bitrate(0,
 * ...) does for peer-side counters, deliberately skipping the per-flow
 * inter-packet-spacing bookkeeping that lives in
 * rist_calculate_flow_bitrate(). */
void rist_refresh_flow_bitrate(struct rist_bandwidth_estimation *bw)
{
	if (!bw->last_bitrate_calctime)
		return;

	struct timeval tv;
	gettimeofday(&tv, NULL);
	uint64_t now = (uint64_t)tv.tv_sec * 1000000;
	now += tv.tv_usec;

	uint64_t time_fast = now - bw->last_bitrate_calctime_fast;
	if (time_fast >= 100000 /* 100 ms */) {
		bw->bitrate_fast = (size_t)((8 * bw->bytes_fast * 1000000) / time_fast);
		bw->eight_times_bitrate_fast += bw->bitrate_fast - bw->eight_times_bitrate_fast / 8;
		bw->last_bitrate_calctime_fast = now;
		bw->bytes_fast = 0;
	}

	uint64_t time = now - bw->last_bitrate_calctime;
	if (time >= 1000000 /* 1 second */) {
		bw->bitrate = (size_t)((8 * bw->bytes * 1000000) / time);
		bw->eight_times_bitrate += bw->bitrate - bw->eight_times_bitrate / 8;
		bw->last_bitrate_calctime = now;
		bw->bytes = 0;
	}
}

static void rist_calculate_flow_bitrate(struct rist_flow *flow, size_t len, struct rist_bandwidth_estimation *bw)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	uint64_t now = (uint64_t)tv.tv_sec * 1000000;
	now += tv.tv_usec;
	uint64_t time = now - bw->last_bitrate_calctime;
	uint64_t time_fast = now - bw->last_bitrate_calctime_fast;

	if (!bw->last_bitrate_calctime) {
		bw->last_bitrate_calctime = now;
		bw->eight_times_bitrate = 0;
		bw->bitrate = 0;
		bw->bytes = 0;
		bw->eight_times_bitrate_fast = 0;
		bw->bitrate_fast = 0;
		bw->bytes_fast = 0;
		return;
	}

	if (flow->last_ipstats_time == 0ULL) {
		// Initial values
		flow->stats_instant.cur_ips = 0ULL;
		flow->stats_instant.min_ips = 0xFFFFFFFFFFFFFFFFULL;
		flow->stats_instant.max_ips = 0ULL;
		flow->stats_instant.avg_count = 0UL;
	} else {
		flow->stats_instant.cur_ips = now - flow->last_ipstats_time;
		/* Set new min */
		if (flow->stats_instant.cur_ips < flow->stats_instant.min_ips)
			flow->stats_instant.min_ips = flow->stats_instant.cur_ips;
		/* Set new max */
		if (flow->stats_instant.cur_ips > flow->stats_instant.max_ips)
			flow->stats_instant.max_ips = flow->stats_instant.cur_ips;

		/* Avg calculation */
		flow->stats_instant.total_ips += flow->stats_instant.cur_ips;
		flow->stats_instant.avg_count++;
	}
	flow->last_ipstats_time = now;


	if (time_fast < 100000 /* 100 ms */) {
		bw->bytes_fast += len;
	}
	else {
		bw->bitrate_fast = (size_t)((8 * bw->bytes_fast * 1000000) / time_fast);
		bw->eight_times_bitrate_fast += bw->bitrate_fast - bw->eight_times_bitrate_fast / 8;
		bw->last_bitrate_calctime_fast = now;
		bw->bytes_fast = 0;
	}

	if (time < 1000000 /* 1 second */) {
		bw->bytes += len;
		return;
	}
	else {
		bw->bitrate = (size_t)((8 * bw->bytes * 1000000) / time);
		bw->eight_times_bitrate += bw->bitrate - bw->eight_times_bitrate / 8;
		bw->last_bitrate_calctime = now;
		bw->bytes = 0;
	}
}

static void rist_sender_recv_nack(struct rist_peer *peer,
		uint32_t flow_id, uint16_t src_port, uint16_t dst_port, const uint8_t *payload,
		size_t payload_len, uint32_t nack_seq_msb)
{
	RIST_MARK_UNUSED(flow_id);
	RIST_MARK_UNUSED(src_port);
	RIST_MARK_UNUSED(dst_port);

	assert(payload_len >= sizeof(struct rist_rtcp_hdr));

	if (peer->receiver_mode) {
		rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG,
				"Received nack packet on receiver, ignoring ...\n");
		return;
	} else if (!peer->authenticated) {
		rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG,
				"Received nack packet but handshake is still pending, ignoring ...\n");
		return;
	}
	assert(peer->sender_ctx != NULL);

	struct rist_rtcp_hdr *rtcp = (struct rist_rtcp_hdr *) payload;
	uint32_t i,j;

	if ((rtcp->flags & 0xc0) != 0x80) {
		rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Malformed nack packet flags=%d.\n", rtcp->flags);
		return;
	}

	if (rtcp->ptype == PTYPE_NACK_CUSTOM) {
		if (payload_len < sizeof(struct rist_rtcp_nack_range))
			return;
		struct rist_rtcp_nack_range *rtcp_nack = (struct rist_rtcp_nack_range *) payload;
		if (memcmp(rtcp_nack->name, "RIST", 4) != 0) {
			rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Non-Rist nack packet (%.4s).\n", rtcp_nack->name);
			return; /* Ignore app-type not RIST */
		}
		uint16_t raw_len = ntohs(rtcp->len);
		if (raw_len < 2)
			return;
		uint16_t nrecords = raw_len - 2;
		size_t needed = sizeof(struct rist_rtcp_nack_range) + (size_t)nrecords * sizeof(struct rist_rtp_nack_record);
		if (needed > payload_len)
			return;
		//rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Nack (RbRR), %d record(s)\n", nrecords);
		/* Cap the per-record range and the per-packet total: a ~10 KB NACK
		 * otherwise drives ~1.6e8 retry-queue operations from one packet.
		 * 256 covers any honest loss burst; 4096/packet ~16 full records. */
		size_t enqueued = 0;
		for (i = 0; i < nrecords; i++) {
			uint16_t missing;
			uint16_t additional;
			struct rist_rtp_nack_record *nr = (struct rist_rtp_nack_record *)(payload + sizeof(struct rist_rtcp_nack_range) + i * sizeof(struct rist_rtp_nack_record));
			missing =  ntohs(nr->start);
			additional = ntohs(nr->extra);
			if (additional > 256)
				additional = 256;
			rist_retry_enqueue(peer->sender_ctx, nack_seq_msb + (uint32_t)missing, peer);
			if (++enqueued >= 4096)
				return;
			//rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Record %"PRIu32": base packet: %"PRIu32" range len: %d\n", i, nack_seq_msb + missing, additional);
			for (j = 0; j < additional; j++) {
				rist_retry_enqueue(peer->sender_ctx, nack_seq_msb + (uint32_t)missing + j + 1, peer);
				if (++enqueued >= 4096)
					return;
			}
		}
	} else if (rtcp->ptype == PTYPE_NACK_BITMASK) {
		struct rist_rtcp_nack_bitmask *rtcp_nack = (struct rist_rtcp_nack_bitmask *) payload;
		(void)rtcp_nack;
		uint16_t raw_len = ntohs(rtcp->len);
		if (raw_len < 2)
			return;
		uint16_t nrecords = raw_len - 2;
		size_t needed = sizeof(struct rist_rtcp_nack_bitmask) + (size_t)nrecords * sizeof(struct rist_rtp_nack_record);
		if (needed > payload_len)
			return;
		//rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Nack (BbRR), %d record(s)\n", nrecords);
		for (i = 0; i < nrecords; i++) {
			uint16_t missing;
			uint16_t bitmask;
			struct rist_rtp_nack_record *nr = (struct rist_rtp_nack_record *)(payload + sizeof(struct rist_rtcp_nack_bitmask) + i * sizeof(struct rist_rtp_nack_record));
			missing = ntohs(nr->start);
			bitmask = ntohs(nr->extra);
			rist_retry_enqueue(peer->sender_ctx, nack_seq_msb + (uint32_t)missing, peer);
			//rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Record %"PRIu32": base packet: %"PRIu32" bitmask: %04x\n", i, nack_seq_msb + missing, bitmask);
			for (j = 0; j < 16; j++) {
				if ((bitmask & (1 << j)) == (1 << j))
					rist_retry_enqueue(peer->sender_ctx, nack_seq_msb + missing + j + 1, peer);
			}
		}
	} else {
		rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Unsupported Type %d\n", rtcp->ptype);
	}

}

static bool address_compare(struct sockaddr* addr1, struct sockaddr* addr2) {
	if (addr1->sa_family != addr2->sa_family)
		return false;
	if (addr1->sa_family == AF_INET) {
		struct sockaddr_in *sa, *sb;
		sa = (struct sockaddr_in *)addr1;
		sb = (struct sockaddr_in *)addr2;
		return !(sa->sin_addr.s_addr - sb->sin_addr.s_addr);
	} else if (addr1->sa_family == AF_INET6) {
		struct sockaddr_in6 *sa, *sb;
		sa = (struct sockaddr_in6 *)addr1;
		sb = (struct sockaddr_in6 *)addr2;
		return !(memcmp(&sa->sin6_addr, &sb->sin6_addr, sizeof(sa->sin6_addr)));
	}
	return false;
}

static bool rist_receiver_data_authenticate(struct rist_peer *peer,uint64_t packet_recv_time, uint32_t flow_id)
{
	struct rist_receiver *ctx = peer->receiver_ctx;

	if (ctx->common.profile == RIST_PROFILE_SIMPLE && !peer->authenticated)
	{
		//assert(0);
		if (peer->parent->peer_rtcp && peer->parent->peer_rtcp->authenticated) {
			peer->flow = peer->parent->peer_rtcp->flow;
			/* find correct rtcp */
			peer->peer_rtcp = NULL;
			struct rist_peer *tmp = peer->parent->peer_rtcp->child;
			uint16_t rtcp_port = peer->local_port+1;
			while (tmp) {
				if (tmp->is_rtcp) {
					if (tmp->local_port == rtcp_port && peer->adv_flow_id == tmp->adv_flow_id && address_compare(&peer->u.address, &tmp->u.address)) {
						if (tmp->dead)
						{
							tmp = tmp->sibling_next;
							continue;
						}
						peer->peer_rtcp = tmp;
						tmp->peer_data = peer;
						break;
					}
				}
				tmp = tmp->sibling_next;
			}
			if (!peer->peer_rtcp) {
				tmp = peer->parent->peer_rtcp->child;
				while (tmp) {
					if (tmp->is_rtcp) {
						if (tmp->local_port == rtcp_port && address_compare(&peer->u.address, &tmp->u.address)) {
							if (tmp->dead)
							{
								tmp = tmp->sibling_next;
								continue;
							}
							peer->peer_rtcp = tmp;
							tmp->peer_data = peer;
							break;
						}
					}
					tmp = tmp->sibling_next;
				}
			}
			peer->adv_flow_id = flow_id; // store the original ssrc here
			rist_peer_authenticate(peer);
			rist_log_priv(&ctx->common, RIST_LOG_INFO,
				"Authenticated RTP peer %d and ssrc %"PRIu32" for connection with flowid %"PRIu32"\n",
					peer->adv_peer_id, peer->adv_flow_id, peer->flow->flow_id);
		} else {
			if (packet_recv_time > (peer->log_repeat_timer + RIST_LOG_QUIESCE_TIMER)) {
				rist_log_priv(&ctx->common, RIST_LOG_WARN,
					"Received data packet (%"PRIu32") but handshake is still pending (waiting for an RTCP packet with SDES on it), ignoring ...\n",
						flow_id);
					peer->log_repeat_timer = packet_recv_time;
			}
			return false;
		}
	}
	else if (ctx->common.profile > RIST_PROFILE_SIMPLE) {
		if (!peer->authenticated) {
			// rist_peer_authenticate is done during rtcp authentication (same peer)
			rist_log_priv(&ctx->common, RIST_LOG_WARN,
				"Received data packet (%"PRIu32") but handshake is still pending (waiting for an RTCP packet with SDES on it), ignoring ...\n",
					flow_id);
			return false;
		} else if (!peer->peer_rtcp) {
			peer->peer_rtcp = peer;
			peer->adv_flow_id = flow_id; // store the original ssrc here
			rist_log_priv(&ctx->common, RIST_LOG_INFO,
				"Authenticated RTP peer %d and ssrc %"PRIu32" for connection with flowid %"PRIu32"\n",
					peer->adv_peer_id, peer->adv_flow_id, peer->peer_rtcp->adv_flow_id);
		}
	}

	if (!peer->flow) {
		rist_log_priv(&ctx->common, RIST_LOG_WARN,
				"Received data packet but this peer (%d) is not associated with a flow, ignoring ...\n",
				peer->adv_peer_id);
		return false;
	} else if (!peer->flow->authenticated) {
		rist_log_priv(&ctx->common, RIST_LOG_WARN,
				"Flow %"PRIu32" has not yet been authenticated by an RTCP peer, %"PRIu32"!\n", flow_id);
		return false;
	}
	if (peer->parent && ctx->common.profile == RIST_PROFILE_SIMPLE)
		peer->parent->authenticated = true;
	return true;
}

static bool rist_receiver_rtcp_authenticate(struct rist_peer *peer, uint32_t seq,
		uint32_t flow_id)
{
	RIST_MARK_UNUSED(seq);
	assert(peer->receiver_ctx != NULL);
	struct rist_receiver *ctx = peer->receiver_ctx;

	if (!strlen(peer->receiver_name)) {
		snprintf(peer->receiver_name, 128, "empty-sdes-name peer id#%i", peer->adv_peer_id);
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "Peer has empty cname in SDES packet, generating default name");
	}

	// Check to see if this peer's flowid changed
	// (sender was restarted and we are in callback mode or sender happened to reuse the same port)
	if (peer->flow && (flow_id != peer->flow->flow_id)) {
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "Updating peer's flowid %"PRIu32"->%"PRIu32" (%zu)\n", peer->flow->flow_id, flow_id, peer->flow->peer_lst_len);
		if (peer->flow->peer_lst_len > 1) {
			remove_peer_from_flow(peer);
		}
		else {
			// Delete the flow and all of its resources
			rist_log_priv(&ctx->common, RIST_LOG_INFO,
					"Old flow (%"PRIu32") has no peers left, deleting ...\n", peer->flow->flow_id);
			rist_delete_flow(ctx, peer->flow);
			rist_log_priv(&ctx->common, RIST_LOG_INFO,
					"Old flow deletion complete\n");
		}
		// Reset the peer parameters
		peer->authenticated = false;
		peer->flow = NULL;
	}

	if (!peer->authenticated) {

		// the peer could already be part of a flow and it came back after timing out
		if (!peer->flow) {
			/* Main/Advanced can complete EAP on a sibling data peer while the
			 * RTCP peer is the one that announces the flow. Publish the same
			 * authenticated principal for the peer about to be authorized. */
			if (ctx->common.srp_auth_callback) {
				const char *username = eap_get_username(peer->eap_ctx);
				if ((!username || !username[0]) && peer->parent)
					username = eap_get_username(peer->parent->eap_ctx);
				if (username && username[0])
					ctx->common.srp_auth_callback(ctx->common.srp_auth_callback_argument,
						peer, username);
			}
			if (ctx->common.receiver_flow_authorize_callback &&
				ctx->common.receiver_flow_authorize_callback(
					ctx->common.receiver_flow_authorize_callback_argument,
					peer, flow_id) != 0) {
				rist_log_priv(&ctx->common, RIST_LOG_WARN,
					"Application rejected peer %u for flow %"PRIu32"\n",
					peer->adv_peer_id, flow_id);
				return false;
			}
			if (rist_receiver_associate_flow(peer, flow_id) != 1) {
				rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Could not create/associate peer to flow.\n");
				return false;
			}
			if (ctx->common.profile == RIST_PROFILE_SIMPLE && peer->parent->peer_data->authenticated)
			{
				/* find correct data */
				struct rist_peer *tmp = peer->parent->peer_data->child;
				peer->is_data = false;
				peer->peer_data = NULL;
				peer->is_rtcp = true;
				uint16_t data_port = peer->local_port -1;
				while (tmp) {
					if (tmp->is_data) {
						if (tmp->local_port == data_port && peer->adv_flow_id == tmp->adv_flow_id && address_compare(&peer->u.address, &tmp->u.address)) {
							if (tmp->dead)
							{
								tmp = tmp->sibling_next;
								continue;
							}
							peer->peer_data = tmp;
							tmp->peer_rtcp = peer;
							break;
						}
					}
					tmp = tmp->sibling_next;
				}
				if (!peer->peer_data) {
					tmp = peer->parent->peer_data->child;
					while (tmp) {
						if (tmp->is_data) {
							if (tmp->local_port == data_port && address_compare(&peer->u.address, &tmp->u.address)) {
								if (tmp->dead)
								{
									tmp = tmp->sibling_next;
									continue;
								}
								peer->peer_data = tmp;
								tmp->peer_rtcp = peer;
								break;
							}
						}
						tmp = tmp->sibling_next;
					}
				}
				//randomly associate with first data peer without rtcp peer (ignores IP matching requirement)
				if (!peer->peer_data) {
					tmp = peer->parent->peer_data->child;
					while (tmp) {
						if (tmp->is_data) {
							if (tmp->local_port == data_port && tmp->peer_rtcp == NULL) {
								peer->peer_data = tmp;
								tmp->peer_rtcp = peer;
								break;
							}
						}
						tmp = tmp->sibling_next;
					}
				}
				peer->authenticated = true;
				return true;
			}
		}

		if (peer->flow) {
			// We do multiple ifs to make these checks stateless
			pthread_mutex_lock(&peer->flow->mutex);
			if (!peer->flow->receiver_thread_running) {
				// Make sure this data out thread is created only once per flow
				if (rist_thread_create(&ctx->common, &peer->flow->receiver_thread, NULL, receiver_pthread_dataout, (void *)peer->flow) != 0) {
					rist_log_priv(&ctx->common, RIST_LOG_ERROR,
							"Could not created receiver data output thread.\n");
					return false;
				}
				peer->flow->receiver_thread_running = true;
			}
			pthread_mutex_unlock(&peer->flow->mutex);
			rist_peer_authenticate(peer);
			peer->flow->authenticated = true;
			rist_log_priv(&ctx->common, RIST_LOG_INFO,
					"Authenticated RTCP peer %d and flow %"PRIu32" for connection with cname: %s\n",
					peer->adv_peer_id, peer->adv_flow_id, peer->receiver_name);
			if (ctx->common.profile == RIST_PROFILE_SIMPLE)
			{
				peer->parent->authenticated = true;
				if (peer->parent->flow == NULL) {
					peer->parent->flow = peer->flow;
					peer->parent->flow->authenticated = true;
				}
			}
		}
	}

	// The flow is added after we completed authentication
	if (peer->flow) {
		return true;
	} else {
		return false;
	}
}

static void rist_receiver_recv_data(struct rist_peer *peer, uint32_t seq, uint32_t flow_id,
		uint64_t source_time, uint64_t packet_recv_time, struct rist_buffer *payload, uint8_t retry, uint8_t payload_type, size_t ingest_size, size_t ts_null_bytes, bool pkt_short_seq)
{
	assert(peer->receiver_ctx != NULL);
	struct rist_receiver *ctx = peer->receiver_ctx;

	if (!rist_receiver_data_authenticate(peer, packet_recv_time, flow_id)) {
		// Error logging happens inside the function
		return;
	}

	/* Advanced contexts default to 32-bit framing but interoperate with a
	 * Main-framed (16-bit) source: track the actual wire framing of the data
	 * so the seq/wrap math matches. Simple/Main are always 16-bit.
	 *
	 * TR-06-3 Section 9 lets a flow switch framing mid-stream (Main->Advanced
	 * upgrade once the peer advertises I=1, or a legacy Main-only source that
	 * never upgrades). The two framings carry different seq widths AND
	 * timestamp encodings, so mixing them in one flow corrupts the timing
	 * baseline. Treat a framing change like a flow-id change: drop the old
	 * baseline so the next enqueue re-derives time_offset and the seq->idx
	 * mapping from the new framing instead of blending the two. */
	if (ctx->common.profile >= RIST_PROFILE_ADVANCED && peer->flow &&
	    peer->flow->short_seq != pkt_short_seq) {
		rist_log_priv(&ctx->common, RIST_LOG_INFO,
			"Flow %u wire framing changed to %s sequence numbers, "
			"resetting flow timing baseline\n",
			peer->flow->flow_id, pkt_short_seq ? "16-bit" : "32-bit");
		peer->flow->short_seq = pkt_short_seq;
		peer->flow->receiver_queue_has_items = false;
	}

	//rist_log_priv(&ctx->common, RIST_LOG_ERROR,
	//	"rist_recv_data, seq %"PRIu32", retry=%d\n", seq, retry);

	//	Just some debug output
	//	if ((seq - peer->flow->last_seq_output) != 1)
	//		rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Received seq %"PRIu32" and last %"PRIu32"\n\n\n", seq, peer->flow->last_seq_output);

	/**************** WIP *****************/
	/* * * * * * * * * * * * * * * * * * * */
	/** Heuristics for receiver  * * * * * */
	/* * * * * * * * * * * * * * * * * * * */
	/**************** WIP *****************/
	peer->stats_receiver_instant.received++;
	peer->stats_receiver_instant.received_bytes += (uint64_t)ingest_size;

	uint64_t rtt;
	rtt = peer->eight_times_rtt / 8;
	if (rtt < peer->config.recovery_rtt_min) {
		rtt = peer->config.recovery_rtt_min;
	}
	else if (rtt > peer->config.recovery_rtt_max) {
		rtt = peer->config.recovery_rtt_max;
	}
	// Optimal dynamic time for first retry (reorder buffer) is rtt/2
	rtt = rtt / 2;
	if (rtt < peer->config.recovery_reorder_buffer)
	{
		rtt = peer->config.recovery_reorder_buffer;
	}

	if (peer->peer_rtcp != NULL &&
		peer->peer_ssrc != peer->peer_rtcp->peer_ssrc &&
		peer->flow->flow_id_actual != flow_id)
	{
          rist_log_priv(&ctx->common, RIST_LOG_NOTICE,
                        "Detected flow id change, old flow id: %u new id: %u, "
                        "resetting state\n",
                        peer->flow->flow_id_actual, flow_id);
        peer->flow->receiver_queue_has_items = false;
        peer->flow->flow_id_actual = flow_id;
	}

	// Wake up output thread when data comes in
	if (pthread_cond_signal(&(peer->flow->condition)))
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Call to pthread_cond_signal failed.\n");
	if (!receiver_enqueue(peer, source_time, packet_recv_time, payload->data, payload->size, seq, rtt, retry, payload->src_port, payload->dst_port, payload_type)) {
		pthread_mutex_lock(&ctx->common.stats_lock);
		// bitrate only if not a dupe or other failures
		if (retry)
			rist_calculate_flow_bitrate(peer->flow, ingest_size, &peer->flow->bw_retries); 
		else
			rist_calculate_flow_bitrate(peer->flow, ingest_size, &peer->flow->bw);
		rist_calculate_flow_bitrate(peer->flow, ts_null_bytes, &peer->flow->bw_tsnull);
		pthread_mutex_unlock(&ctx->common.stats_lock);
	}
	else
	{
		pthread_mutex_lock(&ctx->common.stats_lock);
		if (retry)
			rist_calculate_flow_bitrate(peer->flow, ingest_size, &peer->flow->bw_retries);
		else
			rist_calculate_flow_bitrate(peer->flow, ingest_size, &peer->flow->bw_rejected);
		pthread_mutex_unlock(&ctx->common.stats_lock);
	}
}

static void rist_recv_oob_data(struct rist_peer *peer, struct rist_buffer *payload)
{
	// TODO: if the calling app locks the thread for long, the protocol management thread will suffer
	// either use a new thread with a fifo or write warning on documentation
	struct rist_common_ctx *ctx = get_cctx(peer);
	if (!ctx->oob_data_enabled)
		return;

	if (ctx->oob_current_peer == NULL || ctx->oob_current_peer->dead)
		ctx->oob_current_peer = peer;

	if (ctx->oob_data_callback)
	{
		struct rist_oob_block oob_block;
		oob_block.peer = peer;
		oob_block.payload = payload->data;
		oob_block.payload_len = payload->size;
		oob_block.ts_ntp = payload->source_time;
		ctx->oob_data_callback(ctx->oob_data_callback_argument, &oob_block);
		return;
	}

	/* No callback installed: stash the packet in the receive fifo so the
	 * application can pull it via rist_oob_read(). */
	pthread_rwlock_wrlock(&ctx->oob_queue_lock);
	if ((uint16_t)(ctx->oob_rx_queue_write_index + 1) == ctx->oob_rx_queue_read_index)
	{
		pthread_rwlock_unlock(&ctx->oob_queue_lock);
		rist_log_priv(ctx, RIST_LOG_WARN,
				"oob receive queue is full, dropping packet of size %zu\n", payload->size);
		return;
	}
	struct rist_buffer *b = rist_new_buffer(ctx, payload->data, payload->size,
			RIST_PAYLOAD_TYPE_DATA_OOB, 0, payload->source_time, 0, 0);
	if (RIST_UNLIKELY(!b))
	{
		pthread_rwlock_unlock(&ctx->oob_queue_lock);
		rist_log_priv(ctx, RIST_LOG_ERROR, "Could not allocate oob receive buffer, OOM\n");
		return;
	}
	b->peer = peer;
	ctx->oob_rx_queue[ctx->oob_rx_queue_write_index] = b;
	ctx->oob_rx_queue_write_index = (uint16_t)(ctx->oob_rx_queue_write_index + 1);
	pthread_rwlock_unlock(&ctx->oob_queue_lock);
}

/* Pull one packet from the oob receive fifo.  The returned block is owned by
 * the library and stays valid until the next rist_oob_dequeue_rx() call.
 * Returns the number of packets that were available (>=1) when data is
 * returned, 0 when the fifo is empty. */
int rist_oob_dequeue_rx(struct rist_common_ctx *ctx, const struct rist_oob_block **oob_block)
{
	*oob_block = NULL;

	pthread_rwlock_wrlock(&ctx->oob_queue_lock);

	/* release the buffer handed out by the previous call */
	if (ctx->oob_rx_current)
	{
		free_rist_buffer(ctx, ctx->oob_rx_current);
		ctx->oob_rx_current = NULL;
	}

	if (ctx->oob_rx_queue_read_index == ctx->oob_rx_queue_write_index)
	{
		pthread_rwlock_unlock(&ctx->oob_queue_lock);
		return 0;
	}

	struct rist_buffer *b = ctx->oob_rx_queue[ctx->oob_rx_queue_read_index];
	ctx->oob_rx_queue[ctx->oob_rx_queue_read_index] = NULL;
	ctx->oob_rx_queue_read_index = (uint16_t)(ctx->oob_rx_queue_read_index + 1);
	int available = (uint16_t)(ctx->oob_rx_queue_write_index - ctx->oob_rx_queue_read_index) + 1;

	ctx->oob_rx_current = b;
	ctx->oob_rx_block.peer = b->peer;
	ctx->oob_rx_block.payload = (uint8_t *)b->data + RIST_MAX_PAYLOAD_OFFSET;
	ctx->oob_rx_block.payload_len = b->size;
	ctx->oob_rx_block.ts_ntp = b->source_time;
	*oob_block = &ctx->oob_rx_block;

	pthread_rwlock_unlock(&ctx->oob_queue_lock);
	return available;
}

static void rist_rtcp_handle_echo_request(struct rist_peer *peer, struct rist_rtcp_echoext *echoreq) {
	if (RIST_UNLIKELY(!peer->echo_enabled))
		peer->echo_enabled = true;
	uint64_t echo_request_time = ((uint64_t)be32toh(echoreq->ntp_msw) << 32) | be32toh(echoreq->ntp_lsw);
	uint32_t ssrc = be32toh(echoreq->ssrc);
	rist_respond_echoreq(peer, echo_request_time, ssrc);
}

static void rist_rtcp_handle_echo_response(struct rist_peer *peer, struct rist_rtcp_echoext *echoreq) {
	peer->echo_enabled = true;
	if (be32toh(echoreq->ssrc) != peer->peer_ssrc)
		return;
	uint64_t request_time = ((uint64_t)be32toh(echoreq->ntp_msw) << 32) | be32toh(echoreq->ntp_lsw);
	uint64_t rtt = calculate_rtt_delay(request_time, timestampNTP_u64(), be32toh(echoreq->delay));
	rist_peer_rtt_update(peer, rtt);
}

static void rist_handle_sr_pkt(struct rist_peer *peer, struct rist_rtcp_sr_pkt *sr) {
	uint64_t ntp_time = ((uint64_t)be32toh(sr->ntp_msw) << 32) | be32toh(sr->ntp_lsw);
	peer->last_sender_report_time = ntp_time;
	peer->last_sender_report_ts = timestampNTP_u64();
	if (peer->config.timing_mode == RIST_TIMING_MODE_RTC)
	{
		if (peer->flow && peer->flow->time_offset == 0)
		{
			uint64_t packet_timestamp = convertRTPtoNTP(RTP_PTYPE_MPEGTS, 0, be32toh(sr->rtp_ts));
			peer->flow->time_offset = ntp_time - packet_timestamp;
		}
	}
}

static void rist_handle_rr_pkt(struct rist_peer *peer, struct rist_rtcp_rr_pkt *rr) {
	if (peer->echo_enabled)
		return;
	uint64_t lsr_tmp = (peer->last_sender_report_time >> 16) & 0xFFFFFFFF;
	uint64_t lsr_ntp = be32toh(rr->lsr);
	uint64_t rtt;
	if (!peer->last_sender_report_ts)
		return;
	uint64_t dlsr = (uint64_t)be32toh(rr->dlsr) << 16;
	if (lsr_ntp == lsr_tmp) {
		uint64_t now = timestampNTP_u64();
		// guard the unsigned subtraction; dlsr comes from the wire
		if (peer->last_sender_report_ts + dlsr > now)
			return;
		rtt = now - peer->last_sender_report_ts - dlsr;

	} else {
		if (!lsr_ntp)//this can happen on the first time
			return;
		//Slightly less accurate, needed when RTT is bigger than our RTCP interval.
		// lsr in SR is populated from RTC, so be sure to use that when comparing.
		uint64_t now_rtc = timestampNTP_RTC_u64();
		lsr_ntp = (lsr_ntp << 16) & 0x0000FFFFFFFF0000;
		lsr_ntp |= (now_rtc & 0xFFFF000000000000);
		if (lsr_ntp > now_rtc || lsr_ntp + dlsr > now_rtc)
			return;
		rtt  = now_rtc - lsr_ntp  - dlsr;
	}
	rist_peer_rtt_update(peer, rtt);
}

static void rist_handle_xr_pkt(struct rist_peer *peer, uint8_t xr_pkt[], size_t pkt_len)
{
	size_t offset = 0;
	if (pkt_len < sizeof(struct rist_rtcp_hdr))
		return;
	struct rist_rtcp_hdr *hdr = (struct rist_rtcp_hdr *)&xr_pkt[offset];
	// clamp the declared len to what we actually received
	size_t payload_len = ((size_t)be16toh(hdr->len) + 1) * 4;
	if (payload_len > pkt_len)
		payload_len = pkt_len;
	if (payload_len < sizeof(struct rist_rtcp_hdr))
		return;
	size_t bytes_remaining = payload_len - sizeof(struct rist_rtcp_hdr);
	offset += sizeof(struct rist_rtcp_hdr);
	while (bytes_remaining >= sizeof(struct rist_rtcp_xr_block_hdr))
	{
		struct rist_rtcp_xr_block_hdr *block = (struct rist_rtcp_xr_block_hdr *)&xr_pkt[offset];
		uint8_t block_type = block->type;
		size_t block_length = ((size_t)be16toh(block->length) + 1) * 4;
		if (block_length < sizeof(struct rist_rtcp_xr_block_hdr) ||
		    block_length > bytes_remaining)
			return;
		if (block_type == 5)
		{
			if (block_length < sizeof(struct rist_rtcp_xr_dlrr))
				return;
			struct rist_rtcp_xr_dlrr *dlrr = (struct rist_rtcp_xr_dlrr *)&xr_pkt[offset];
			uint32_t ssrc  = be32toh(dlrr->ssrc);
			if (ssrc != peer->peer_ssrc)
				return;
			uint64_t lrr_tmp = (peer->last_sender_report_ts >> 16) & 0xFFFFFFFF;
			uint64_t lrr = be32toh(dlrr->lrr);
			uint64_t delay = (uint64_t)be32toh(dlrr->delay) << 16;
			uint64_t rtt;
			if (lrr == lrr_tmp)
			{
				uint64_t now = timestampNTP_u64();
				// guard the unsigned subtraction; delay comes from the wire
				if (peer->last_sender_report_ts + delay > now)
					return;
				rtt = now - peer->last_sender_report_ts - delay;
			} else {
				//Slightly less accurate, needed when RTT is bigger than our RTCP interval.
				uint64_t now = timestampNTP_u64();
				lrr = (lrr << 16) & 0x0000FFFFFFFF0000;
				lrr |= (now & 0xFFFF000000000000);
				if (lrr > now || lrr + delay > now)
					return;
				rtt  = now - lrr - delay;
			}
			rist_peer_rtt_update(peer, rtt);
		}
		offset += block_length;
		bytes_remaining -= block_length;
	}
}

static char *get_ip_str(struct sockaddr *sa, char *s, size_t maxlen)
{
	switch(sa->sa_family) {
		case AF_INET:
			inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
					s, (socklen_t)maxlen);
			break;

		case AF_INET6:
			inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
						s, (socklen_t)maxlen);
			break;

		default:
			strncpy(s, "Unknown AF", maxlen);
			return NULL;
	}
	return s;
}

static bool try_listener_reassociate_by_cname(struct rist_peer *new_peer, uint64_t now);
static bool try_caller_socket_rebind(struct rist_peer *peer, uint64_t now);

static void rist_recv_rtcp(struct rist_peer *peer, uint32_t seq,
		uint32_t flow_id, struct rist_buffer *payload)
{
	uint8_t *pkt;
	uint8_t  ptype;
	uint16_t processed_bytes = 0;
	uint16_t records;
	uint8_t subtype;
	peer->stats_receiver_instant.received_rtcp++;
	struct rist_common_ctx *ctx = get_cctx(peer);

	while (processed_bytes < payload->size) {
		pkt = (uint8_t*)payload->data + processed_bytes;
		struct rist_rtcp_hdr *rtcp = (struct rist_rtcp_hdr *)pkt;
		/* safety checks */
		size_t bytes_left = payload->size - processed_bytes;

		if ( bytes_left < 4 )
		{
			/* we must have at least 4 bytes */
			rist_log_priv(ctx, RIST_LOG_ERROR, "Rist rtcp packet must have at least 4 bytes, we have %zu\n",
					bytes_left);
			return;
		}

		ptype = rtcp->ptype;
		subtype = rtcp->flags & 0x1f;
		records = be16toh(rtcp->len);
		// in size_t so 4*(1+0xFFFF) cannot wrap to 0 and spin the loop
		size_t bytes = (size_t)4 * ((size_t)1 + records);
		if (bytes < 4 || bytes > bytes_left)
		{
			/* check for a sane number of bytes */
			rist_log_priv(ctx, RIST_LOG_ERROR, "Malformed feedback packet, expecting %zu bytes in the" \
					" packet, got a buffer of %zu bytes. ptype = %d\n", bytes,
					bytes_left, ptype);
			return;
		}

		switch(ptype) {
			case PTYPE_NACK_CUSTOM:
				if (subtype == ECHO_RESPONSE) {
					if (bytes < sizeof(struct rist_rtcp_echoext))
						break;
					struct rist_rtcp_echoext *echoresponse = (struct rist_rtcp_echoext *) pkt;
					rist_rtcp_handle_echo_response(peer, echoresponse);
					break;
				}
				else if (subtype == ECHO_REQUEST) {
					if (bytes < sizeof(struct rist_rtcp_echoext))
						break;
					struct rist_rtcp_echoext *echorequest = (struct rist_rtcp_echoext *)pkt;
					rist_rtcp_handle_echo_request(peer, echorequest);
					break;
				}
				else if (subtype == NACK_FMT_RANGE)	{
					//Fallthrough
					RIST_FALLTHROUGH;
				}
				else {
					rist_log_priv(ctx, RIST_LOG_DEBUG, "Unsupported rtcp custom subtype %d, ignoring ...\n", subtype);
					break;
				}
			case PTYPE_NACK_BITMASK:
				//Also FMT Range
				rist_sender_recv_nack(peer, flow_id, payload->src_port, payload->dst_port, pkt, bytes_left, 0);
				break;
			case PTYPE_RR:
				if (ntohs(rtcp->len) == 7) {
					struct rist_rtcp_rr_pkt *rr = (struct rist_rtcp_rr_pkt *)pkt;
					rist_handle_rr_pkt(peer, rr);
				}
				break;

			case PTYPE_SDES:
				{
					peer->stats_sender_instant.received++;
					if (bytes_left < RTCP_SDES_SIZE)
					{
						rist_log_priv(ctx, RIST_LOG_ERROR, "Malformed SDES packet, %zu bytes < SDES header size\n",
								bytes_left);
						return;
					}
					uint8_t name_length = pkt[9];
					// must fit the remaining packet AND receiver_name (incl NUL)
					if ((size_t)name_length + RTCP_SDES_SIZE > bytes_left ||
					    name_length >= sizeof(peer->receiver_name))
					{
						rist_log_priv(ctx, RIST_LOG_ERROR, "Malformed SDES packet, cname len %u out of bounds (left %zu, max %zu)\n",
								name_length, bytes_left, sizeof(peer->receiver_name) - 1);
						return;
					}
					if (memcmp(pkt + RTCP_SDES_SIZE, peer->receiver_name, name_length) != 0)
					{
						memcpy(peer->receiver_name, pkt + RTCP_SDES_SIZE, name_length);
						peer->receiver_name[name_length] = '\0';
						rist_log_priv(ctx, RIST_LOG_INFO, "Peer %"PRIu32" receiver name is now: %s\n",
								peer->adv_peer_id, peer->receiver_name);
					}
					bool peer_authenticated = peer->authenticated;
					int connection_message = 0;
					if (peer->receiver_mode) {
						rist_receiver_rtcp_authenticate(peer, seq, flow_id);
						connection_message = RIST_CLIENT_CONNECTED;
					} else if (peer->sender_ctx && peer->listening) {
						// TODO: create rist_sender_recv_rtcp
						if (!peer->authenticated) {
							rist_peer_authenticate(peer);
						}
						connection_message = RIST_CLIENT_CONNECTED;
					}
					else {
						connection_message = RIST_CONNECTION_ESTABLISHED;
						/* Re-associate by cname before announcing a
						 * brand-new caller.  On success this kills the
						 * new peer and returns, dropping any RTCP records
						 * that followed the SDES in the same compound
						 * packet. */
						if (!peer->send_first_connection_event &&
						    try_listener_reassociate_by_cname(peer, timestampNTP_u64()))
							return;
					}
					if (peer->timed_out || !peer->send_first_connection_event || (!peer_authenticated && peer->authenticated)) {
						if (!peer->send_first_connection_event)
							rist_log_priv(ctx, RIST_LOG_INFO, "Peer %"PRIu32" receiver with name %s reconnected\n",
								peer->adv_peer_id, peer->receiver_name);
						peer->timed_out = 0;
						peer->send_first_connection_event = true;
						if (ctx->connection_status_callback)
							ctx->connection_status_callback(ctx->connection_status_callback_argument, peer, connection_message);
					}
				break;
			}
			case PTYPE_SR:;
				if (bytes < sizeof(struct rist_rtcp_sr_pkt))
					break;
				struct rist_rtcp_sr_pkt *sr = (struct rist_rtcp_sr_pkt *)pkt;
				rist_handle_sr_pkt(peer, sr);
				break;
			case PTYPE_XR:
				rist_handle_xr_pkt(peer, pkt, bytes);
				break;
			default:
				rist_log_priv(ctx, RIST_LOG_DEBUG, "Unrecognized RTCP packet with PTYPE=%02x!!\n", ptype);
		}
		processed_bytes += (uint16_t)bytes;
	}

}

void rist_peer_rtcp(struct evsocket_ctx *evctx, void *arg)
{
	RIST_MARK_UNUSED(evctx);
	struct rist_peer *peer = (struct rist_peer *)arg;
	//struct rist_common_ctx *ctx = get_cctx(peer);

	if (!peer || atomic_load_explicit(&peer->shutdown, memory_order_acquire) || !peer->is_rtcp) {
		return;
	}

	if (peer->dead && peer->parent != NULL)
		return;//Don't send to peers that connect to us and have dropped silent

	if (peer->receiver_mode) {
		rist_receiver_periodic_rtcp(peer);
	} else {
		rist_sender_periodic_rtcp(peer);
	}
}

static void rist_peer_sockerr(struct evsocket_ctx *evctx, int fd, short revents, void *arg)
{
	RIST_MARK_UNUSED(evctx);
	RIST_MARK_UNUSED(fd);
	RIST_MARK_UNUSED(revents);
	struct rist_peer *peer = (struct rist_peer *) arg;
#ifdef _WIN32
	/* WSAECONNRESET indications are disabled at socket creation time via
	 * WSAIoctl(SIO_UDP_CONNRESET, FALSE) - see udpsocket_open(). The earlier
	 * recvfrom(drain[1], ...) drain has been removed because it could
	 * cannibalise (or truncate via WSAEMSGSIZE) a real datagram queued
	 * ahead of - or instead of - the synthetic error indication, leading
	 * to malformed EAPOL packets and other downstream failures. */
	int wsa_err = WSAGetLastError();
	if (wsa_err == WSAECONNRESET)
		return;
#endif
	rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "\tSocket error!\n");

	//rist_peer_remove(get_cctx(peer), peer, NULL);
}

void sender_peer_append(struct rist_sender *ctx, struct rist_peer *peer)
{
	/* Add a reference to ctx->peer_lst */
	ctx->peer_lst = realloc(ctx->peer_lst, (ctx->peer_lst_len + 1) * sizeof(*ctx->peer_lst));
	ctx->peer_lst[ctx->peer_lst_len] = peer;
	ctx->peer_lst_len++;
}

static void peer_copy_settings(struct rist_peer *peer_src, struct rist_peer *peer)
{
	_librist_crypto_psk_rist_key_clone(&peer_src->key_rx, &peer->key_rx);
	_librist_crypto_psk_rist_key_clone(&peer_src->key_rx_odd, &peer->key_rx_odd);
	_librist_crypto_psk_rist_key_clone(&peer_src->key_tx, &peer->key_tx);
	_librist_crypto_psk_rist_key_clone(&peer_src->key_tx, &peer->key_tx_odd);
	peer->key_tx_odd_active = peer_src->key_tx_odd_active;
	strncpy(&peer->cname[0], &peer_src->cname[0], RIST_MAX_STRING_SHORT);
	peer->cname[RIST_MAX_STRING_SHORT - 1] = '\0';
	strncpy(&peer->miface[0], &peer_src->miface[0], RIST_MAX_STRING_SHORT);
	peer->miface[RIST_MAX_STRING_SHORT - 1] = '\0';
	peer->config.weight = peer_src->config.weight;
	peer->config.recovery_priority = peer_src->config.recovery_priority;
	peer->config.virt_dst_port = peer_src->config.virt_dst_port;
	peer->config.recovery_mode = peer_src->config.recovery_mode;
	peer->config.recovery_maxbitrate = peer_src->config.recovery_maxbitrate;
	peer->config.recovery_maxbitrate_return = peer_src->config.recovery_maxbitrate_return;
	peer->config.recovery_length_min = peer_src->config.recovery_length_min;
	peer->config.recovery_length_max = peer_src->config.recovery_length_max;
	peer->config.recovery_reorder_buffer = peer_src->config.recovery_reorder_buffer;
	peer->config.recovery_rtt_min = peer_src->config.recovery_rtt_min;
	peer->config.recovery_rtt_max = peer_src->config.recovery_rtt_max;
	peer->config.congestion_control_mode = peer_src->config.congestion_control_mode;
	peer->config.min_retries = peer_src->config.min_retries;
	peer->config.max_retries = peer_src->config.max_retries;
	peer->config.timing_mode = peer_src->config.timing_mode;
	peer->config.reflector = peer_src->config.reflector;
	peer->config.multicast_ttl = peer_src->config.multicast_ttl;
	strncpy(peer->config.multicast_source, peer_src->config.multicast_source, RIST_MAX_STRING_LONG - 1);
	peer->config.multicast_source[RIST_MAX_STRING_LONG - 1] = '\0';
	peer->config.local_port = peer_src->config.local_port;
	peer->config.rtt_drop = peer_src->config.rtt_drop;
	peer->config.rtt_restore = peer_src->config.rtt_restore;
	peer->config.rtt_drop_settle = peer_src->config.rtt_drop_settle;
	peer->config.rtt_drop_trickle = peer_src->config.rtt_drop_trickle;
	peer->rtcp_keepalive_interval = peer_src->rtcp_keepalive_interval;
	peer->peer_ssrc = peer_src->peer_ssrc;
	peer->session_timeout = peer_src->session_timeout;
	peer->rist_gre_version = RIST_GRE_VERSION_MIN;
	memcpy(peer->mac_addr, peer_src->mac_addr, sizeof(peer->mac_addr));
	init_peer_settings(peer);
}

static void kill_peer(struct rist_peer *peer)
{
	bool current_state = peer->dead;
	peer->dead = true;
	if (peer->peer_data && (current_state != peer->peer_data->dead && peer->peer_data->parent))
		--peer->peer_data->parent->child_alive_count;
	peer->dead_since = timestampNTP_u64();
}

/* Listener-side cname re-association for a NAT source-port rebind.
 * SRP only: the cname is not a per-peer secret, so an authenticated
 * per-peer session is required before migrating an identity to a new
 * source tuple.  Returns true after killing new_peer. */
static bool try_listener_reassociate_by_cname(struct rist_peer *new_peer, uint64_t now)
{
	struct rist_peer *parent = new_peer->parent;
	if (!parent || !parent->listening || !new_peer->sender_ctx ||
	    new_peer->receiver_mode || new_peer->receiver_name[0] == '\0')
		return false;

#if HAVE_SRP_SUPPORT
	if (!new_peer->eap_ctx || !eap_is_authenticated(new_peer->eap_ctx))
		return false;
#else
	/* No SRP: there is no authenticated per-peer session to gate on, and
	 * the cname is not a per-peer secret, so reassociation is unsafe. */
	return false;
#endif

	uint64_t ka = new_peer->rtcp_keepalive_interval
	              ? new_peer->rtcp_keepalive_interval
	              : (uint64_t)RIST_PING_INTERVAL * RIST_CLOCK;
	uint64_t silent_threshold = 2 * ka;

	struct rist_peer *candidate = NULL;
	int alive_duplicates = 0;
	struct rist_peer *sib = parent->child;
	while (sib) {
		if (sib != new_peer &&
		    sib->is_rtcp == new_peer->is_rtcp &&
		    sib->is_data == new_peer->is_data &&
		    sib->adv_flow_id == new_peer->adv_flow_id &&
		    sib->receiver_name[0] != '\0' &&
		    strncmp(sib->receiver_name, new_peer->receiver_name,
		            RIST_MAX_HOSTNAME) == 0) {
			bool silent = sib->last_pkt_received > 0 &&
			              now > sib->last_pkt_received &&
			              (now - sib->last_pkt_received) > silent_threshold;
			if (sib->dead || silent) {
				if (candidate == NULL)
					candidate = sib;
			} else {
				alive_duplicates++;
			}
		}
		sib = sib->sibling_next;
	}

	if (!candidate || alive_duplicates > 0)
		return false;

	memcpy(&candidate->u.address, &new_peer->u.address, new_peer->address_len);
	candidate->address_len = new_peer->address_len;
	candidate->address_family = new_peer->address_family;
	candidate->remote_port = new_peer->remote_port;
	candidate->dead = 0;
	candidate->timed_out = 0;
	candidate->last_pkt_received = now;
	rist_log_priv(get_cctx(new_peer), RIST_LOG_INFO,
	    "cname \"%s\" matched existing peer %"PRIu32
	    "; migrated source tuple from new peer %"PRIu32
	    " and retired it (NAT-rebind recovery, SRP).\n",
	    new_peer->receiver_name, candidate->adv_peer_id,
	    new_peer->adv_peer_id);

#if HAVE_SRP_SUPPORT
	/* Kick a fresh EAPOL START so re-auth fires now, not up to
	 * EAP_REAUTH_PERIOD later. */
	if (candidate->eap_ctx)
		_librist_proto_eap_start(candidate->eap_ctx);
#endif

	kill_peer(new_peer);
	return true;
}

/* Caller-side recovery when a peer goes silent past session_timeout.
 * Receiver-mode callers rebind the local socket (NAT rebind / listener
 * restart); SRP callers also reset EAP and re-handshake on the fresh socket.
 * Sender-mode callers only reach the SRP path: their miface-bound socket
 * survives a flap, so they reset EAP without rebinding (see the branches).
 * Linear backoff capped at REBIND_BACKOFF_CAP. */
#define REBIND_BACKOFF_CAP 10
static bool try_caller_socket_rebind(struct rist_peer *peer, uint64_t now)
{
	struct rist_common_ctx *cctx = get_cctx(peer);
	if (!peer || peer->parent || peer->listening ||
	    peer->multicast_sender || peer->multicast_receiver)
		return false;
	if (cctx->profile <= RIST_PROFILE_SIMPLE)
		return false;
	if (peer->config.local_port != 0)
		return false;

	/* Require silence beyond max(session_timeout, 4*keepalive) so a
	 * misconfigured short session_timeout against a slower keepalive
	 * cadence does not trigger a flap loop on legitimate streams. */
	uint64_t ka = peer->rtcp_keepalive_interval
	              ? peer->rtcp_keepalive_interval
	              : (uint64_t)RIST_PING_INTERVAL * RIST_CLOCK;
	uint64_t min_silence = peer->session_timeout > 4 * ka
	                       ? peer->session_timeout : 4 * ka;
	if (peer->last_pkt_received == 0 ||
	    now <= peer->last_pkt_received ||
	    (now - peer->last_pkt_received) <= min_silence)
		return false;

	uint32_t backoff_mult = peer->rebind_attempts > REBIND_BACKOFF_CAP
	                        ? REBIND_BACKOFF_CAP : peer->rebind_attempts;
	uint64_t min_gap = (uint64_t)backoff_mult * peer->session_timeout;
	if (peer->last_rebind_time != 0 && now > peer->last_rebind_time &&
	    (now - peer->last_rebind_time) < min_gap)
		return false;

	if (!peer->receiver_mode) {
#if HAVE_SRP_SUPPORT
		/* Sender-mode leg: the miface-bound socket survives a flap, so
		 * don't rebind it -- just reset EAP and re-drive the handshake on
		 * the existing socket.  Only SRP deadlocks like this; plaintext/PSK
		 * recover via normal reconnect.
		 *
		 * De-authenticate the leg so it drops out of the weighted sender
		 * balancing while it is silent (the balancer keeps a leg in rotation
		 * only while authenticated) and re-drives the connection handshake.
		 * eap_authentication_state is rewound to 1 so the "EAP Authentication
		 * succeeded" transition fires again when re-auth completes; that path
		 * restores authenticated and folds the leg back into the bond at full
		 * weight (without this, the leg re-authenticates but never rejoins
		 * balancing, streaming only NACK retransmits). */
		if (peer->eap_ctx == NULL)
			return false;
		peer->authenticated = false;
		peer->eap_authentication_state = 1;
		peer->dead = 0;
		peer->timed_out = 0;
		peer->last_pkt_received = now;
		eap_reset_authenticatee(peer->eap_ctx);
		peer->rebind_attempts++;
		peer->last_rebind_time = now;
		rist_log_priv(cctx, RIST_LOG_WARN,
		    "Sender caller peer %"PRIu32" silent past session_timeout "
		    "(attempt %"PRIu32"); reset EAP and re-initiated the SRP "
		    "handshake to recover the leg without operator intervention.\n",
		    peer->adv_peer_id, peer->rebind_attempts);
		return true;
#else
		return false;
#endif
	}

	struct evsocket_ctx *evctx = cctx->evctx;
	int old_sd = peer->sd;
	uint16_t old_local_port = peer->local_port;

	if (peer->event_recv) {
		evsocket_delevent(evctx, peer->event_recv);
		peer->event_recv = NULL;
	}
	if (old_sd >= 0) {
		udpsocket_close(old_sd);
		peer->sd = -1;
	}

	rist_create_socket(peer);
	if (peer->sd < 0) {
		rist_log_priv(cctx, RIST_LOG_ERROR,
		    "Caller socket rebind failed for peer %"PRIu32
		    " (errno=%d), falling through to kill_peer.\n",
		    peer->adv_peer_id, errno);
		return false;
	}

	peer->event_recv = evsocket_addevent(evctx, peer->sd, EVSOCKET_EV_READ,
	                                     rist_peer_recv_wrap,
	                                     rist_peer_sockerr, peer);

	/* Force a fresh handshake on the new tuple. */
	peer->authenticated = false;
	peer->dead = 0;
	peer->timed_out = 0;
	peer->last_pkt_received = now;
	peer->next_periodic_rtcp = now;
	peer->next_keepalive_packet = now;
	peer->send_keepalive = true;
	peer->send_first_connection_event = false;

#if HAVE_SRP_SUPPORT
	/* SRP callers: the authenticated session is bound to the old source
	 * tuple and (after a listener restart) to state the far end no longer
	 * has.  Reset EAP back to UNAUTH and re-send EAPOL START on the new
	 * socket so the authenticator re-challenges us immediately, exactly as
	 * on a cold connect.  Non-SRP callers just resume via the keepalives
	 * armed above. */
	if (peer->eap_ctx != NULL)
		eap_reset_authenticatee(peer->eap_ctx);
#endif

	peer->rebind_attempts++;
	peer->last_rebind_time = now;

	rist_log_priv(cctx, RIST_LOG_WARN,
	    "Receiver peer %"PRIu32" silent past session_timeout "
	    "(attempt %"PRIu32"); rebound caller socket %d->%d "
	    "(local_port %u->%u) for NAT/dynamic-IP recovery.\n",
	    peer->adv_peer_id, peer->rebind_attempts, old_sd, peer->sd,
	    (unsigned)old_local_port, (unsigned)peer->local_port);

	return true;
}

static void rist_peer_recv_wrap(struct evsocket_ctx *evctx, int fd, short revents, void *arg) {
	bool again = true;
	while (true) {
		rist_peer_recv(evctx, fd, revents, arg, &again);
		if (!again)
			return;
	}
}

static void rist_new_connection(struct rist_peer *peer, struct rist_peer *p, uint32_t flow_id) {
	const char *peer_type = "?";
	const char *id_name = "?";
	if (peer->is_rtcp) {
		peer_type = "RTCP";
		id_name = "flow_id";
	} else if (peer->is_data) {
		peer_type = "RTP";
		id_name = "ssrc";
	}
	if (peer->receiver_mode) {
		rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "New %s peer connecting, %s %"PRIu32", peer_id %"PRIu32", ports %u <- %u\n",
		peer_type, id_name, flow_id, p->adv_peer_id, p->local_port, p->remote_port);
		p->adv_flow_id = flow_id;
	}
	else {
		if (flow_id) {
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "New reverse %s peer connecting with old flow_id %"PRIu32", peer_id %"PRIu32", ports %u <- %u\n",
			peer_type, flow_id, p->adv_peer_id, p->local_port, p->remote_port);
		} else {
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "New reverse %s peer connecting, peer_id %"PRIu32", ports %u <- %u\n",
			peer_type, p->adv_peer_id, p->local_port, p->remote_port);
		}
		p->peer_ssrc = p->adv_flow_id = p->sender_ctx->adv_flow_id;
	}
}

static void rist_peer_recv(struct evsocket_ctx *evctx, int fd, short revents, void *arg, bool *again)
{
	RIST_MARK_UNUSED(evctx);
	RIST_MARK_UNUSED(revents);
	RIST_MARK_UNUSED(fd);

	struct rist_peer *peer = (struct rist_peer *) arg;
	if (atomic_load_explicit(&peer->shutdown, memory_order_acquire)) {
		return;
	}
	uint64_t now = timestampNTP_u64();
	struct rist_common_ctx *cctx = get_cctx(peer);

	socklen_t addrlen = peer->address_len;
	size_t recv_bufsize = 0;
	uint16_t family = peer->address_family;
	struct sockaddr_storage ss = {0};
	struct sockaddr *addr = (struct sockaddr *)&ss;
	struct rist_peer *p = NULL;
	uint8_t *recv_buf = cctx->buf.recv;
	uint8_t *recv_buf_npd = cctx->buf.recv_npd;
	uint16_t port = 0;

	ssize_t ret = rist_transport_recvfrom(peer, recv_buf, RIST_MAX_PACKET_SIZE, MSG_DONTWAIT, addr, &addrlen);
	if (ss.ss_family == AF_INET)
		port = htons(((struct sockaddr_in *)addr)->sin_port);
	else
		port = htons(((struct sockaddr_in6 *)addr)->sin6_port);

#ifndef _WIN32
	if (ret <= 0) {
		*again = false;
		int errorcode = errno;
		/* Custom transports compiled in a different TU may have EAGAIN
		 * resolve to a different numeric value than this TU; match both
		 * canonical values defensively. */
		if (errno == EAGAIN || errno == EWOULDBLOCK ||
		    (ret == -1 && (errorcode == 11 || errorcode == 35)))
				return;
#else
	if (ret == SOCKET_ERROR) {
		*again = false;
		int errorcode = WSAGetLastError();
		if (errorcode == WSAEWOULDBLOCK)
			return;
#endif
		rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Receive failed: errno=%d, ret=%d, socket=%d\n", errorcode, recv_bufsize, fd);
		rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "%s\n", strerror(errorcode));
		return;
	}

	recv_bufsize = ret;

	/* Transparent one-to-many reflector: forward raw packets between
	 * publisher and subscriber children before any decryption or
	 * protocol processing.  Only active when ?reflector=1 is set. */
	if (peer->config.reflector && peer->listening && !peer->multicast_receiver) {
		struct rist_peer *p_sender = _librist_peer_match_peer_addr(peer, family, addr);
		if (p_sender && p_sender->parent == peer) {
			struct rist_peer *child = peer->child;
			while (child) {
				if (child != p_sender) {
					if (p_sender->is_reflector_publisher) {
						/* Forward publisher's packet (RTP/RTCP) to subscriber children */
						if (!child->is_reflector_publisher) {
							sendto(peer->sd, (const char *)recv_buf, recv_bufsize, 0, &child->u.address, child->address_len);
						}
					} else {
						/* Forward subscriber's packet (NACK/RTCP) to publisher children */
						if (child->is_reflector_publisher) {
							sendto(peer->sd, (const char *)recv_buf, recv_bufsize, 0, &child->u.address, child->address_len);
						}
					}
				}
				child = child->sibling_next;
			}
		}
	}

	struct rist_key *k = &peer->key_rx;
	uint32_t seq = 0;
	uint32_t time_extension = 0;
	uint8_t retry = 0;
	size_t payload_offset = 0;
	struct rist_buffer payload = { .data = NULL, .size = 0, .type = 0, .src_port = 0, .dst_port = 0 };
	uint32_t flow_id = 0;
	uint16_t gre_proto = 0;
	uint8_t rist_gre_version = RIST_GRE_VERSION_MIN;
	if (cctx->profile > RIST_PROFILE_SIMPLE)
	{
		/* Section 9 (TR-06-3): Auto-detect GRE vs RTP framing.
		 * First byte bits [7:6]:
		 *   0b0x = GRE (bit 7 = 0 → Main/Advanced GRE tunnel)
		 *   0b10 = RTP V=2 → Advanced Profile if PT=127 */
		if (cctx->profile == RIST_PROFILE_ADVANCED &&
		    recv_bufsize >= RIST_ADV_HEADER_MIN &&
		    (recv_buf[0] & 0xC0) == 0x80) {
			/* Looks like RTP V=2. Check PT field for Advanced Profile. */
			uint8_t pt = recv_buf[1] & 0x7F;
			if (pt == RIST_ADV_PT || pt >= 96) {
				struct rist_adv_parsed adv_parsed;
				if (rist_adv_parse(recv_buf, recv_bufsize, &adv_parsed) == 0) {
					p = _librist_peer_match_peer_addr(peer, family, addr);
					if (!p) {
						if (peer->listening || peer->multicast_sender) {
							p = peer_initialize(NULL, peer->sender_ctx, peer->receiver_ctx);
							p->handled_first = false;
							p->adv_peer_id = ++cctx->peer_counter;
							p->parent = peer;
							peer_copy_settings(peer, p);
							if (peer->receiver_ctx) {
								p->remote_port = port;
								p->local_port = peer->local_port;
							} else {
								p->remote_port = peer->remote_port;
								p->local_port = peer->local_port;
							}
							p->address_family = family;
							p->address_len = addrlen;
							p->listening = 0;
							p->is_rtcp = peer->is_rtcp;
							p->is_data = peer->is_data;
							p->peer_data = p;
							p->is_advanced = true;
							memcpy(&p->u.address, addr, addrlen);
							p->sd = peer->sd;
							p->authenticated = false;
							p->event_recv = peer->event_recv;
							p->send_keepalive = true;
							if (cctx->auth.conn_cb) {
								char incoming_ip_str[INET6_ADDRSTRLEN];
								char *ip_str = get_ip_str(&p->u.address, incoming_ip_str, INET6_ADDRSTRLEN);
								char parent_ip_str[INET6_ADDRSTRLEN];
								char *parent_str = get_ip_str(&p->parent->u.address, parent_ip_str, INET6_ADDRSTRLEN);
								if (!parent_str) parent_str = "";
								uint16_t parent_port = 0;
								if (p->parent->u.storage.ss_family == AF_INET)
									parent_port = htons(p->parent->u.inaddr.sin_port);
								else
									parent_port = htons(p->parent->u.inaddr6.sin6_port);
								if (ip_str && cctx->auth.conn_cb(cctx->auth.arg, ip_str, port, parent_str, parent_port, p)) {
									free(p);
									return;
								}
							}
							peer_append(p);
#if HAVE_SRP_SUPPORT
							eap_clone_ctx(peer->eap_ctx, p);
							{
								char ip_buf[INET6_ADDRSTRLEN];
								char *ip = get_ip_str(&p->u.address, ip_buf, INET6_ADDRSTRLEN);
								if (ip)
									eap_set_ip_string(p->eap_ctx, ip_buf);
							}
#endif
						} else {
							return;
						}
					}
					p->is_advanced = true;
					p->last_pkt_received = now;

					/* Dispatch by encapsulation type */
					if (adv_parsed.enc_type == RIST_ADV_TYPE_CONTROL) {
						rist_calculate_bitrate(recv_bufsize, &p->bw);
						rist_adv_recv_control(p, adv_parsed.payload,
						                      adv_parsed.payload_len);
						return;
					}

					uint32_t adv_flow_id = adv_parsed.ssrc & ~(uint32_t)1;
					retry = adv_parsed.retransmit ? 1 : 0;

					if (adv_parsed.enc_type == RIST_ADV_TYPE_DIRECT) {
						/* PSK decryption for Advanced Profile */
						uint8_t adv_dec_buf[RIST_MAX_PACKET_SIZE];
						const uint8_t *adv_data = adv_parsed.payload;
						size_t adv_data_len = adv_parsed.payload_len;

						if (adv_parsed.psk_mode == RIST_ADV_PSK_AES_CTR) {
							if (!p->key_rx.key_size) {
								if (now > (peer->log_repeat_timer + RIST_LOG_QUIESCE_TIMER)) {
									rist_log_priv(get_cctx(peer), RIST_LOG_ERROR,
										"Advanced Profile: encrypted data but no PSK configured\n");
									peer->log_repeat_timer = now;
								}
								return;
							}
							if (!adv_parsed.psk_nonce || !adv_parsed.psk_iv) {
								rist_log_priv(get_cctx(peer), RIST_LOG_ERROR,
									"Advanced Profile: PSK AES-CTR missing nonce/IV\n");
								return;
							}
							bool odd_nonce_adv = CHECK_BIT(adv_parsed.psk_nonce[0], 7);
							struct rist_key *ak = &p->key_rx;
							if (odd_nonce_adv)
								ak = &p->key_rx_odd;
							pthread_mutex_lock(&p->peer_lock);
							uint32_t seq_nbe;
							memcpy(&seq_nbe, adv_parsed.psk_iv, sizeof(seq_nbe));
							_librist_crypto_psk_decrypt(ak,
								(uint8_t *)adv_parsed.psk_nonce, seq_nbe, 1,
								adv_parsed.payload, adv_dec_buf, adv_data_len);
							pthread_mutex_unlock(&p->peer_lock);
							if (ak->bad_decryption)
								return;
							adv_data = adv_dec_buf;
						} else if (adv_parsed.psk_mode != RIST_ADV_PSK_NONE) {
							if (now > (peer->log_repeat_timer + RIST_LOG_QUIESCE_TIMER)) {
								rist_log_priv(get_cctx(peer), RIST_LOG_WARN,
									"Advanced Profile: unsupported PSK mode %u\n",
									adv_parsed.psk_mode);
								peer->log_repeat_timer = now;
							}
							return;
						} else if (p->key_rx.key_size) {
							if (now > (peer->log_repeat_timer + RIST_LOG_QUIESCE_TIMER)) {
								rist_log_priv(get_cctx(peer), RIST_LOG_ERROR,
									"Advanced Profile: expect encrypted data but received clear\n");
								peer->log_repeat_timer = now;
							}
							return;
						}

						uint8_t adv_lz4_buf[RIST_MAX_PACKET_SIZE];
						if (adv_parsed.lpc_mode == RIST_ADV_LPC_LZ4 && adv_data_len > 0) {
							int dlen = LZ4_decompress_safe(
								(const char *)adv_data, (char *)adv_lz4_buf,
								(int)adv_data_len, RIST_MAX_PACKET_SIZE);
							if (dlen <= 0) {
								rist_log_priv(get_cctx(peer), RIST_LOG_ERROR,
									"Advanced Profile: LZ4 decompress failed\n");
								return;
							}
							adv_data = adv_lz4_buf;
							adv_data_len = (size_t)dlen;
						} else if (adv_parsed.lpc_mode != RIST_ADV_LPC_NONE) {
							if (now > (peer->log_repeat_timer + RIST_LOG_QUIESCE_TIMER)) {
								rist_log_priv(get_cctx(peer), RIST_LOG_WARN,
									"Advanced Profile: unsupported LPC mode %u\n",
									adv_parsed.lpc_mode);
								peer->log_repeat_timer = now;
							}
							return;
						}

						/* Stamp with the sender's timeline rebuilt from the 1 MHz
						 * RTP timestamp so the dejitter buffer smooths off the
						 * source clock like the Main path, not raw arrival. ARRIVAL
						 * mode keeps arrival; otherwise the reconstruct dejitters off
						 * the source clock immediately and, because older releases
						 * emitted a broken clock, corrects to arrival after the first
						 * second if the sender's clock is not advancing at real time. */
						uint64_t adv_source_time;
						if (RIST_UNLIKELY(p->config.timing_mode == RIST_TIMING_MODE_ARRIVAL))
							adv_source_time = now;
						else
							adv_source_time = rist_adv_ts_reconstruct(&p->rx_adv_ts,
								adv_parsed.timestamp, now,
								ONE_SECOND, !retry);

						if (peer->receiver_ctx) {
							rist_calculate_bitrate(recv_bufsize, &p->bw);
							uint16_t adv_src_port = (uint16_t)(32768 + p->adv_peer_id);
							uint16_t adv_dst_port = p->config.virt_dst_port;
							if (adv_parsed.has_flow_id && adv_parsed.flow_id) {
								adv_dst_port = rist_adv_flow_outer(adv_parsed.flow_id);
								adv_src_port = rist_adv_flow_inner(adv_parsed.flow_id);
							}
							struct rist_buffer adv_payload = {
								.data = (void *)adv_data,
								.size = adv_data_len,
								.type = RIST_PAYLOAD_TYPE_DATA_RAW,
								.src_port = adv_src_port,
								.dst_port = adv_dst_port,
							};
							/* Pass the delivered payload size (adv_data_len), not
							 * the full datagram, so received_bytes and bitrate
							 * match the Main path's payload-only accounting.
							 * ts_null_bytes is 0: the Advanced receive path does
							 * no ts-null reinsertion. */
							rist_receiver_recv_data(p, adv_parsed.seq, adv_flow_id,
								adv_source_time, now, &adv_payload, retry,
								RIST_PAYLOAD_TYPE_DATA_RAW, adv_data_len, 0, false);
						}
						return;
					}

					if (adv_parsed.enc_type == RIST_ADV_TYPE_GRE_MAIN) {
						/* Type 8: Strip Advanced Profile header, process inner GRE.
						 * The payload is a Main Profile GRE packet — feed it back
						 * through the existing GRE receive path by updating the
						 * buffer pointer and falling through. */
						recv_buf = (uint8_t *)adv_parsed.payload;
						recv_bufsize = adv_parsed.payload_len;
						/* Fall through to GRE processing below */
					} else {
						rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG,
							"Advanced Profile: unsupported encapsulation type %u\n",
							adv_parsed.enc_type);
						return;
					}
				}
			}
		}

		struct rist_gre_hdr *gre = NULL;
		// Make sure we have enough bytes
		if (recv_bufsize < (int)sizeof(*gre)) {
			rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Packet too small: %d bytes, ignoring ...\n", recv_bufsize);
			return;
		}

		gre = (void *) recv_buf;
		payload_offset += sizeof(*gre);
		gre_proto = be16toh(gre->prot_type);
		if (CHECK_BIT(gre->flags1,  6) != 0 || (gre->flags2 & 0x7) != 0) {
			if (now > (peer->log_repeat_timer + RIST_LOG_QUIESCE_TIMER)) {
				rist_log_priv(get_cctx(peer), RIST_LOG_ERROR,
						"Non conformant main profile packet received\n");
				peer->log_repeat_timer = now;
			}
			return;
		}
		uint8_t has_checksum = CHECK_BIT(gre->flags1, 7);
		uint8_t has_key = CHECK_BIT(gre->flags1, 5);
		uint8_t has_seq = CHECK_BIT(gre->flags1, 4);
		rist_gre_version = (gre->flags2 >> 3) & 0x7;

		if (recv_bufsize < (sizeof(*gre) + has_checksum*4 + has_key *4 + has_seq *4)) {
			rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Packet too small: %d bytes, ignoring ...\n", recv_bufsize);
			return;
		}

		if (has_checksum) {
			payload_offset += 4;
		}

		size_t nonce_offset = 0;
		bool odd_nonce = false;
		if (has_key) {
			nonce_offset = payload_offset;
			odd_nonce = CHECK_BIT(recv_buf[nonce_offset], 7);
			payload_offset += 4;
		}

		if (has_seq) {
			seq =  recv_buf[payload_offset] << 24 | recv_buf[payload_offset+ 1] << 16 | recv_buf[payload_offset+ 2] << 8 | recv_buf[payload_offset+ 3];
			payload_offset += 4;
		}

		p = _librist_peer_match_peer_addr(peer, family, addr);

		if (has_seq && has_key && gre_proto != RIST_GRE_PROTOCOL_TYPE_EAPOL) {
			// Key bit is set, that means the other side want to send
			// encrypted data.
			//
			// make sure we have a key before attempting to decrypt
			if (!k->key_size) {
				if (now > (peer->log_repeat_timer + RIST_LOG_QUIESCE_TIMER)) {
					rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Receiving encrypted data, but configured without keysize!\n");
					peer->log_repeat_timer = now;
				}
				return;
			}



			if (!p)
				p = peer;
#if ALLOW_INSECURE_IV_FALLBACK == 1
			if (rist_gre_version < 1)
				p->rist_gre_version = rist_gre_version;
#endif
			pthread_mutex_lock(&p->peer_lock);
			k = &p->key_rx;
			if (odd_nonce)
				k = &p->key_rx_odd;
			p->key_rx_odd_active = odd_nonce;
			//Read H bit and set keysize accordingly
			if (p->rist_gre_version)
			{
				int bits = (CHECK_BIT(gre->flags2, 6))? 256 : 128;
				/* Honor the H bit only when it agrees with the configured
				 * size (or none was configured): it is unauthenticated wire
				 * data, and letting it rewrite key_size (e.g. a 192 config
				 * clobbered to 128/256) desyncs every later rekey. */
				if (k->key_size == 0 || k->key_size == (uint32_t)bits)
					k->key_size = bits;
			}
			_librist_crypto_psk_decrypt(k, &recv_buf[nonce_offset], htobe32(seq), rist_gre_version,&recv_buf[payload_offset],  &recv_buf[payload_offset], (recv_bufsize - payload_offset));
			pthread_mutex_unlock(&p->peer_lock);

			if (p == peer)
				p = NULL;

			if (k->bad_decryption)
				return;
		} else if (k->key_size && gre_proto != RIST_GRE_PROTOCOL_TYPE_EAPOL && (!has_seq || !has_key)) {
			if (now > (peer->log_repeat_timer + RIST_LOG_QUIESCE_TIMER)) {
				rist_log_priv(get_cctx(peer), RIST_LOG_ERROR,
						"We expect encrypted data and the peer sent clear communication, ignoring ...\n");
				peer->log_repeat_timer = now;
			}
			return;
		}

		if (gre_proto == RIST_GRE_PROTOCOL_TYPE_FULL)
		{
			payload.type = RIST_PAYLOAD_TYPE_DATA_OOB;
			goto protocol_bypass;
		}
		if (gre_proto == RIST_GRE_PROTOCOL_TYPE_EAPOL)
		{
			payload.type = RIST_PAYLOAD_TYPE_EAPOL;
			goto protocol_bypass;
		}

		if (gre_proto == RIST_GRE_PROTOCOL_TYPE_VSF) {
			if (recv_bufsize < payload_offset + 4) {
				rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Packet too small: %d bytes, ignoring ...\n", recv_bufsize);
				return;
			}

			uint16_t vsf_proto = 0;
			uint16_t vsf_subtype = 0;
			vsf_proto = recv_buf[payload_offset] << 8 | recv_buf[payload_offset +1];
			vsf_subtype = recv_buf[payload_offset + 2] << 8 | recv_buf[payload_offset +3];

			payload_offset += 4;

			if (vsf_proto != 0) {//0 = RIST, rest: reserved
				rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG, "Receiving unknown VSF Proto\n");
				return;
			}

			if (vsf_subtype == 0) {
				gre_proto = RIST_GRE_PROTOCOL_TYPE_REDUCED;
			} else if (vsf_subtype >= 0x8000){//Control messages
				if (vsf_subtype == 0x8000) {
					gre_proto = RIST_GRE_PROTOCOL_TYPE_KEEPALIVE;
			} else if (vsf_subtype == 0x8001) {
				/* Flow Attribute (Main Profile VSF extension) — not parsed here */
				return;
				} else if (vsf_subtype == RIST_VSF_PROTOCOL_SUBTYPE_BUFFER_NEGOTIATION) {
					gre_proto = RIST_VSF_PROTOCOL_SUBTYPE_BUFFER_NEGOTIATION;
				} else {
					rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG, "Receiving unknown RIST control packet\n");
					return;
				}
			} else {
				rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG, "Receiving unknown RIST packet\n");
				return;
			}
		}

		if (gre_proto != RIST_GRE_PROTOCOL_TYPE_REDUCED)
			goto protocol_bypass;

		if (recv_bufsize < payload_offset + 4) {
			rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Packet too small: %d bytes, ignoring ...\n", recv_bufsize);
			return;
		}

		/* Map the first subheader and rtp payload area to our structure */
		payload.src_port = recv_buf[payload_offset] << 8 | recv_buf[payload_offset +1];
		payload.dst_port = recv_buf[payload_offset +2] << 8 | recv_buf[payload_offset +3];
		payload_offset += 4;
	}

protocol_bypass:
	if (!p)
		p = _librist_peer_match_peer_addr(peer, family, addr);

	/* The RTP header only exists on the data path (Simple profile or
	 * Main-profile REDUCED); leave the pointer NULL elsewhere so a
	 * stray deref shows up at compile/run time instead of silently
	 * reading past recv_bufsize on a short FULL/EAPOL/KEEPALIVE
	 * datagram. */
	struct rist_rtp_hdr *rtp = NULL;
	if (cctx->profile == RIST_PROFILE_SIMPLE || gre_proto == RIST_GRE_PROTOCOL_TYPE_REDUCED) {
		if (recv_bufsize < payload_offset + sizeof(struct rist_rtp_hdr))
		{
			rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Packet too small for RTP header: %zu bytes, ignoring ...\n", recv_bufsize);
			return;
		}
		rtp = (struct rist_rtp_hdr *)&recv_buf[payload_offset];
		/* Double check for a valid rtp header */
		if ((rtp->flags & 0xc0) != 0x80)
		{
			if (!p)
				p = peer;
			if (now > (p->log_repeat_timer + RIST_LOG_QUIESCE_TIMER)) {
				rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Malformed packet, rtp flag value is %02x instead of 0x80.\n",
						rtp->flags);
						p->log_repeat_timer = now;
			}

			if (k && k->key_size > 0) {
				if (k->bad_count++ > 5) {
					rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Disabling packet processing till new NONCE\n");
					k->bad_decryption = true;
				}
			}
			return;
		}
		/* A packet that decrypts to a valid RTP header proves the key is
		 * healthy; decay the strike counter so a few garbage packets mixed
		 * into good traffic can't accumulate into a lockout. */
		if (k && k->bad_count)
			k->bad_count = 0;
	}


	/* An authenticatee may send EAPOL START before its first keepalive. Create
	 * the dynamic listener peer so the authenticator can return its challenge. */
	if (!p && (peer->listening || peer->multicast_sender) && (gre_proto == RIST_GRE_PROTOCOL_TYPE_REDUCED || gre_proto == RIST_GRE_PROTOCOL_TYPE_KEEPALIVE || gre_proto == RIST_GRE_PROTOCOL_TYPE_FULL || gre_proto == RIST_GRE_PROTOCOL_TYPE_EAPOL || cctx->profile == RIST_PROFILE_SIMPLE)) {
		/* No match, new peer creation when on listening mode */
		p = peer_initialize(NULL, peer->sender_ctx, peer->receiver_ctx);
		p->handled_first = false;
		p->adv_peer_id = ++cctx->peer_counter;
		// Copy settings and init/update global variables that depend on settings
		p->parent = peer;
		peer_copy_settings(peer, p);
		if (cctx->profile == RIST_PROFILE_SIMPLE) {
			if (peer->address_family == AF_INET) {
				p->remote_port = htons( ((struct sockaddr_in *)addr)->sin_port);
			} else {
				p->remote_port = htons( ((struct sockaddr_in6 *)addr)->sin6_port);
			}
				p->local_port = peer->local_port;
			}
		else if (peer->receiver_ctx){
			// TODO: what happens if the first packet is a keepalive?? are we caching the wrong port?
			p->remote_port = payload.src_port;
			p->local_port = payload.dst_port;
		} else {
			p->remote_port = peer->remote_port;
			p->local_port = peer->local_port;
		}

		// TODO: what if sender mode and flow_id != 0 and p->adv_flow_id != flow_id
		p->address_family = family;
		p->address_len = addrlen;
		p->listening = 0;
		p->is_rtcp = peer->is_rtcp;
		p->is_data = peer->is_data;
		p->peer_data = p;
		if (peer->multicast_sender)
			p->peer_data = peer->peer_data;
		memcpy(&p->u.address, addr, addrlen);
		p->sd = peer->sd;
		p->authenticated = false;
		// Copy the event handler reference to prevent the creation of a new one (they are per socket)
		p->event_recv = peer->event_recv;
		char incoming_ip_string_buffer[INET6_ADDRSTRLEN];
		char *incoming_ip_string = get_ip_str(&p->u.address, &incoming_ip_string_buffer[0], INET6_ADDRSTRLEN);
#if HAVE_SRP_SUPPORT
		eap_clone_ctx(peer->eap_ctx, p);
		eap_set_ip_string(p->eap_ctx, incoming_ip_string_buffer);
		/* Some Main-profile senders announce themselves with KEEPALIVE but do
		 * not send EAPOL START. Prompt them as soon as their dynamic peer is
		 * addressable instead of waiting for an authentication that never starts. */
		if (p->eap_ctx)
			eap_request_identity(p->eap_ctx);
		if (p->multicast_receiver && p->eap_ctx) {
			_librist_proto_eap_start(p->eap_ctx);
		}
#endif
		// Optional validation of connecting sender
		if (cctx->auth.conn_cb) {

			char parent_ip_string_buffer[INET6_ADDRSTRLEN];
			char *parent_ip_string = get_ip_str(&p->parent->u.address, &parent_ip_string_buffer[0], INET6_ADDRSTRLEN);
			if (!parent_ip_string){
				parent_ip_string = "";
			}

			uint16_t parent_port = 0;
			if (p->parent->u.storage.ss_family == AF_INET)
				parent_port = htons(p->parent->u.inaddr.sin_port);
			else
				parent_port = htons(p->parent->u.inaddr6.sin6_port);

			// Real source port vs virtual source port
			if (cctx->profile == RIST_PROFILE_SIMPLE)
				port = p->remote_port;
			if (incoming_ip_string) {
				if (cctx->auth.conn_cb(cctx->auth.arg,incoming_ip_string,port,parent_ip_string, parent_port, p)) {
					free(p->eap_ctx);
					free(p);
					return;
				}
			}
		}

		if (peer->receiver_mode)
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Enabling keepalive for peer %d\n", p->adv_peer_id);
		else {
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Enabling reverse keepalive for peer %d\n", p->adv_peer_id);
			if (p->is_rtcp)
				sender_peer_append(peer->sender_ctx, p);
		}
		p->send_keepalive = true;
		p->rist_gre_version = rist_gre_version;
		if (cctx->profile > RIST_PROFILE_SIMPLE
#if HAVE_SRP_SUPPORT
			&& ((p->eap_ctx && eap_is_authenticated(p->eap_ctx)) || !p->eap_ctx)
#endif
			) {
			//Answer their keep alive with one from us
			_librist_proto_gre_send_keepalive(p, p->rist_gre_version);
			_librist_proto_gre_send_keepalive(p, p->rist_gre_version);
			_librist_proto_gre_send_keepalive(p, p->rist_gre_version);
			if (p->rist_gre_version >= 2) {
				uint16_t sender_max_buffer = 0;
				if (p->sender_ctx != NULL) {
					sender_max_buffer = p->sender_ctx->sender_recover_min_time;
				} else if (peer->config.reflector && peer->listening && !peer->multicast_receiver) {
					struct rist_peer *child = peer->child;
					while (child) {
						if (child->is_reflector_publisher && child->sender_max_buffer_ticks > 0) {
							sender_max_buffer = (uint16_t)(child->sender_max_buffer_ticks / RIST_CLOCK);
							break;
						}
						child = child->sibling_next;
					}
				}
				if (sender_max_buffer > 0) {
					_librist_proto_gre_send_buffer_negotiation(p, sender_max_buffer, 0);
					_librist_proto_gre_send_buffer_negotiation(p, sender_max_buffer, 0);
					_librist_proto_gre_send_buffer_negotiation(p, sender_max_buffer, 0);
				}
			}
		}
		peer_append(p);
	}
	if (!p)
		return;

	//Only allow upgrade of gre version
	if (p->rist_gre_version < rist_gre_version
#if HAVE_SRP_SUPPORT
			&& ((p->eap_ctx && eap_is_authenticated(p->eap_ctx)) || !p->eap_ctx)
#endif
	) {
		//Our GRE version got upgraded, try kickstarting buffer negotiation
		if (p->rist_gre_version == RIST_GRE_VERSION_MIN) {
			uint16_t sender_max_buffer = 0;
			if (p->sender_ctx != NULL) {
				sender_max_buffer = p->sender_ctx->sender_recover_min_time;
			} else if (peer->config.reflector && peer->listening && !peer->multicast_receiver) {
				struct rist_peer *child = peer->child;
				while (child) {
					if (child->is_reflector_publisher && child->sender_max_buffer_ticks > 0) {
						sender_max_buffer = (uint16_t)(child->sender_max_buffer_ticks / RIST_CLOCK);
						break;
					}
					child = child->sibling_next;
				}
			}
			if (sender_max_buffer > 0) {
				_librist_proto_gre_send_buffer_negotiation(p, sender_max_buffer, 0);
				_librist_proto_gre_send_buffer_negotiation(p, sender_max_buffer, 0);
				_librist_proto_gre_send_buffer_negotiation(p, sender_max_buffer, 0);
			}
		}
		p->rist_gre_version = rist_gre_version;
	}

	if (gre_proto == RIST_GRE_PROTOCOL_TYPE_KEEPALIVE) {
		struct rist_keepalive_info info;
		if (_librist_proto_gre_parse_keepalive(&recv_buf[payload_offset], recv_bufsize - payload_offset, &info) != 0) {
			p->last_pkt_received = now;
			return;
		}
		if (memcmp(&info.ka, &p->data, sizeof(peer->data)) != 0) {
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
				"New keepalive received. MAC: %x:%x:%x:%x:%x:%x"
				" X: %d R: %d B: %d A: %d P: %d E: %d L: %d: N: %d"
				" D: %d T: %d V: %d: J: %d F: %d\n",
				info.mac[0], info.mac[1], info.mac[2],
				info.mac[3], info.mac[4], info.mac[5],
				info.x, info.r, info.b, info.a,
				info.p, info.e, info.l, info.e,
				info.n, info.d, info.t, info.v,
				info.j, info.f);
			if (info.json_len) {
				/* %.*s precision must be int. Truncate the log line if some
				 * weird future caller hands us a giant blob. */
				int json_log_len = info.json_len > (size_t)INT_MAX ? INT_MAX : (int)info.json_len;
				rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Keepalive JSON:\n%.*s\n", json_log_len, info.json);
			}
			//TODO: add callback?
			/* TR-06-3 Section 9: detect Advanced Profile support via I bit */
			if (info.adv_i && !p->remote_supports_advanced) {
				p->remote_supports_advanced = true;
				rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
					"Peer %u advertises Advanced Profile capability (I=1)\n",
					p->adv_peer_id);
			}
			memcpy(&p->data, &info.ka, sizeof(peer->data));
		}
		if (p->receiver_ctx &&
		    p->receiver_ctx->merge_mode == LIBRIST_MERGE_MODE_AUTO) {
			struct rist_flow *fl = cctx->FLOWS;
			while (fl) {
				if (fl->merge_auto_enabled != (bool)info.l) {
					fl->merge_auto_enabled = (bool)info.l;
					rist_log_priv(cctx, RIST_LOG_INFO,
						"merge=auto: peer %s pair-split; "
						"merge %s for flow %u\n",
						info.l ? "advertises" : "stopped advertising",
						info.l ? "enabled" : "disabled",
						fl->flow_id);
				}
				fl = fl->next;
			}
		}
		p->last_pkt_received = now;
		return;
	}

	if (gre_proto == RIST_VSF_PROTOCOL_SUBTYPE_BUFFER_NEGOTIATION) {
		uint16_t sender_max_buffer;
		uint16_t client_current_buffer;
		if (_librist_proto_gre_parse_buffer_negotiation(p, &recv_buf[payload_offset], recv_bufsize - payload_offset, &sender_max_buffer, &client_current_buffer) != 0)
			return;

		p->is_reflector_publisher = sender_max_buffer != 0;

		if (p->receiver_ctx != NULL && sender_max_buffer != 0) {
			if (sender_max_buffer < p->config.recovery_length_min) {
				rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Sender max buffer %u smaller than min buffer %u, disabling buffer negotiation!\n", sender_max_buffer, p->config.recovery_length_min);
				p->sender_max_buffer_ticks = 0;
			} else {
				p->sender_max_buffer_ticks = sender_max_buffer * RIST_CLOCK;
				if (peer->config.reflector && peer->listening && !peer->multicast_receiver) {
					struct rist_peer *child = peer->child;
					while (child) {
						if (child != p && !child->is_reflector_publisher && child->rist_gre_version >= 2) {
							_librist_proto_gre_send_buffer_negotiation(child, sender_max_buffer, 0);
						}
						child = child->sibling_next;
					}
				}
			}
		}
		return;
	}

	uint32_t rtp_time = 0;
	uint64_t source_time = 0;
	uint8_t payload_type = 0;
	int ts_null_bytes = 0;

	if (cctx->profile == RIST_PROFILE_SIMPLE || gre_proto == RIST_GRE_PROTOCOL_TYPE_REDUCED) {
		// This is for legacy compatibility (to be removed later)
		if (rtp->payload_type == PTYPE_XR_LEGACY)
			rtp->payload_type = PTYPE_XR;
		payload_type = rtp->payload_type;
		uint8_t payload_type_nomarker_bit = rtp->payload_type & 127;
		// Finish defining the payload (we assume reduced header)
		// The check is for 200-205 and 72-77 (payload type minus 128)
		if(payload_type_nomarker_bit < 72 || payload_type_nomarker_bit > 77) {
			// This will mis-clasify rtp packets with payload types 72-77 as rtcp. However,
			// this range is reserved for "RTCP conflict avoidance” on RFC4855. Furthermore,
			// we are already using 77 for PTYPE_XR
			// Remove the marker bit as it is not part of the payload type for non-rtcp data
			payload_type = payload_type_nomarker_bit;
			flow_id = be32toh(rtp->ssrc);
			// If this is a retry, extract the information and restore correct flow_id
			if (flow_id & 1UL)
			{
				flow_id ^= 1UL;
				retry = 1;
			}
            payload_offset += sizeof(*rtp);
            uint8_t *data_payload = &recv_buf[payload_offset];
			payload.size = recv_bufsize - (payload_offset);
			payload.data = (void *)data_payload;

			if (CHECK_BIT(rtp->flags, 4)) {
				// X bit promises an extension header, the packet may not actually have it
				if (payload.size < sizeof(struct rist_rtp_hdr_ext)) {
					rist_log_priv(get_cctx(peer), RIST_LOG_ERROR,
						"Packet too small for RTP extension header: %zu bytes, ignoring ...\n",
						payload.size);
					return;
				}
				uint8_t *data_payload_out = &recv_buf_npd[0];
				//RTP extension header
				struct rist_rtp_hdr_ext * hdr_ext = (struct rist_rtp_hdr_ext *)(&recv_buf[payload_offset]);
				payload.size -= sizeof(*hdr_ext);
				data_payload += sizeof(*hdr_ext);
				payload.data = (void *)data_payload;
				if (memcmp(&hdr_ext->identifier, "RI", 2) == 0 && be16toh(hdr_ext->length) == 1)
				{
					// Null packet expansion (use a separate buffer and replace it when we had nulls)
					if (CHECK_BIT(hdr_ext->flags, 7)) {
						ts_null_bytes = expand_null_packets(data_payload, data_payload_out, &payload.size, hdr_ext->npd_bits);
						if (ts_null_bytes < 0)
							ts_null_bytes = 0; /* expansion failed; deliver unexpanded */
						else
							payload.data = (void *)data_payload_out;
					}
				}
			}
			payload.type = RIST_PAYLOAD_TYPE_DATA_RAW;
		} else {
			// remap the rtp payload to the correct rtcp header
			struct rist_rtcp_hdr *rtcp = (struct rist_rtcp_hdr *)rtp;
            //payload_offset += sizeof(*rtcp);
            uint8_t *data_payload = &recv_buf[payload_offset];
			payload.size = recv_bufsize - (payload_offset);
			payload.data = (void *)data_payload;
			flow_id = be32toh(rtcp->ssrc);
			payload.type = RIST_PAYLOAD_TYPE_RTCP;
		}
	}

	// We need this protocol bypass to manage keepalives of any kind,
	// they need to trigger peering at the bottom of this function

	;
	bool failed_eap = false;
	if (p->eap_authentication_state != 1 && p->dead) {
		uint64_t dead_time = (now - p->last_pkt_received);
		p->dead = false;
		//Only used on main profile
		if (p->parent)
			++p->parent->child_alive_count;
		rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
				"Peer %u was dead for %"PRIu64" ms and it is now alive again\n",
					p->adv_peer_id, dead_time / RIST_CLOCK);
		if (p->peer_data)
			p->peer_data->dead = 0;
	}
	p->last_pkt_received = now;
	if (ts_null_bytes)
		p->stats_receiver_instant.ts_null++;
	if (p->flow)
		p->flow->last_recv_ts = now;
	payload.peer = p;
	if (cctx->profile == RIST_PROFILE_SIMPLE)
	{
		payload.src_port = p->remote_port;
		payload.dst_port = p->local_port;
	}
	//rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Port is %d !!!!!\n", addr4.sin_port);
#if HAVE_SRP_SUPPORT
	if (payload.type != RIST_PAYLOAD_TYPE_EAPOL && p->eap_ctx && !eap_is_authenticated(p->eap_ctx))
	{
		if (now > (p->log_repeat_timer + RIST_LOG_QUIESCE_TIMER)) {
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Waiting for EAP authentication to happen for peer connecting on port %u\n", ((struct sockaddr_in *)addr)->sin_port);
			p->log_repeat_timer = now;
		}
		// Do not process non EAP packets until the peer has been authenticated!
		return;
	}
#endif
	//Cobalt's implementation has an identity crisis in it's response to our echo packets & set's the wrong SSRC (ours) on the RTP packet. Work around this flaw.
	if (peer && peer->receiver_ctx && flow_id == peer->peer_ssrc && peer->flow && peer->flow->flow_id && peer->flow->flow_id != flow_id)
		flow_id = peer->flow->flow_id;

	switch(payload.type) {
		case RIST_PAYLOAD_TYPE_UNKNOWN:
			// Do nothing ...TODO: check for port changes?
			break;
		case RIST_PAYLOAD_TYPE_DATA_OOB:
			payload.size = recv_bufsize - payload_offset;
			payload.data = (void *)(recv_buf + payload_offset);
			rist_recv_oob_data(p, &payload);
			break;
		case RIST_PAYLOAD_TYPE_RTCP:
			if (p->is_rtcp && !p->handled_first) {
				rist_new_connection(peer, p, flow_id);
				if (!peer->receiver_mode) {
					// only profile > simple
					// authenticate sender now that we have an address
					rist_peer_authenticate(p);
				}
				p->handled_first = true;
			}
			RIST_FALLTHROUGH;
		case RIST_PAYLOAD_TYPE_RTCP_NACK:
		/* Need this for interop, we should move this to a per flow level eventually once we support multiple flows on a single peer*/
			if (RIST_UNLIKELY(p->receiver_ctx && p->local_port != payload.dst_port)) {
				rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Updating peer virt dst port to match remote source port: %u\n", payload.src_port);
				p->local_port = payload.dst_port;
				p->remote_port = payload.src_port;
			}
			rist_recv_rtcp(p, seq, flow_id, &payload);
			break;
		case RIST_PAYLOAD_TYPE_DATA_RAW:
			if (p->is_data && !p->handled_first) {
				rist_new_connection(peer, p, flow_id);
				p->handled_first = true;
			}
			rtp_time = be32toh(rtp->ts);
			if (RIST_UNLIKELY(p->config.timing_mode == RIST_TIMING_MODE_ARRIVAL))
				source_time = timestampNTP_u64();
			else
				source_time = convertRTPtoNTP(payload_type, time_extension, rtp_time);
			seq = (uint32_t)be16toh(rtp->seq);
			if (RIST_UNLIKELY(!p->receiver_mode))
				rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG,
						"Received data packet on sender, ignoring (%d bytes)...\n", payload.size);
			else {
				size_t received_bytes = recv_bufsize - payload_offset; //use the unexpanded size to show real BW
				rist_calculate_bitrate(received_bytes, &p->bw);
				rist_receiver_recv_data(p, seq, flow_id, source_time, now, &payload, retry, payload_type, received_bytes, ts_null_bytes, true);
			}
			break;
		case RIST_PAYLOAD_TYPE_EAPOL:
#if HAVE_SRP_SUPPORT
			if (p->eap_ctx == NULL) {
				rist_log_priv(get_cctx(p), RIST_LOG_ERROR, "EAP authentication requested but credentials have not been configured!\n");
			}
			else {
				int eapret = 0;
				if ((eapret = eap_process_eapol(p->eap_ctx,
												(recv_buf + payload_offset),
												(recv_bufsize - payload_offset))) < 0) {
					rist_log_priv(get_cctx(p), RIST_LOG_ERROR, "Failed to process EAPOL pkt, return code: %i\n", eapret);
					/* eap_process_eapol returns a negative code; was being
					 * compared against +255 and never matched, so failed_eap
					 * was effectively dead. */
					if (eapret == EAP_AUTH_TERMINATED)
						failed_eap = true;
				}
				else if (p->eap_authentication_state != 2 && eap_is_authenticated(p->eap_ctx)) {
					rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
						"Peer %d EAP Authentication succeeded\n", peer->adv_peer_id);
					p->eap_authentication_state = 2;
					if (cctx->srp_auth_callback) {
						cctx->srp_auth_callback(cctx->srp_auth_callback_argument, p,
							eap_get_username(p->eap_ctx));
					}
					/* A caller-sender leg that re-authenticated after going
					 * silent (see try_caller_socket_rebind) cleared its
					 * connection-level authenticated flag to leave the bond
					 * while down.  Restore it now so the weighted balancer
					 * folds the leg back in at full weight. */
					if (!p->receiver_mode && !p->listening && !p->authenticated)
						rist_peer_authenticate(p);
					//First authentication, so send keepalive
					_librist_proto_gre_send_keepalive(p, p->rist_gre_version);
					_librist_proto_gre_send_keepalive(p, p->rist_gre_version);
					_librist_proto_gre_send_keepalive(p, p->rist_gre_version);
					if (p->rist_gre_version >= 2 && p->sender_ctx != NULL) {
						_librist_proto_gre_send_buffer_negotiation(p, peer->sender_ctx->sender_recover_min_time, 0);
						_librist_proto_gre_send_buffer_negotiation(p, peer->sender_ctx->sender_recover_min_time, 0);
						_librist_proto_gre_send_buffer_negotiation(p, peer->sender_ctx->sender_recover_min_time, 0);
					}
					/* Emit the binding SDES now, not on the next periodic
					 * tick, so it precedes this leg's first forwarded data. */
					if (!p->receiver_mode)
						rist_sender_periodic_rtcp(p);
				}
			}
#else
			if (peer->eap_ctx == NULL) {
				rist_log_priv(get_cctx(p), RIST_LOG_ERROR, "EAP authentication requested but EAP support not available!\n");
				failed_eap = true;
			}
#endif
			if (failed_eap) {
				//A previously authenticated client fails authentication, and we're running multicast, so we need to rollover the passphrase
#if HAVE_SRP_SUPPORT
				if (p->eap_authentication_state == 2 && p->parent && p->parent->multicast_sender)  {
					char newpass[65];
					newpass[64] = '\0';
					if (_librist_crypto_random_get_string(newpass, sizeof(newpass)-1) == 0) {
						rist_peer_update_secret(p->parent, newpass);
					}
				}
#endif
				p->eap_authentication_state = 1;
				kill_peer(p);
			}
			// Never create new peers using EAP packets (exit loop here)
			return;
			break;
		default:
			rist_recv_rtcp(p, seq, flow_id, &payload);
			break;
	}
	return;
}

int rist_oob_enqueue(struct rist_common_ctx *ctx, struct rist_peer *peer, const void *buf, size_t len)
{
	if (RIST_UNLIKELY(!ctx->oob_data_enabled)) {
		rist_log_priv(get_cctx(peer), RIST_LOG_ERROR,
				"Trying to send oob but oob was not enabled\n");
		return -1;
	}
	else if ((ctx->oob_queue_write_index + 1) == ctx->oob_queue_read_index)
	{
		rist_log_priv(get_cctx(peer), RIST_LOG_ERROR,
				"oob queue is full (%zu bytes), try again later\n", ctx->oob_queue_bytesize);
		return -1;
	}

	/* insert into oob fifo queue */
	pthread_rwlock_wrlock(&ctx->oob_queue_lock);
	ctx->oob_queue[ctx->oob_queue_write_index] = rist_new_buffer(ctx, buf, len, RIST_PAYLOAD_TYPE_DATA_OOB, 0, 0, 0, 0);
	if (RIST_UNLIKELY(!ctx->oob_queue[ctx->oob_queue_write_index])) {
		rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "\t Could not create oob packet buffer, OOM\n");
		pthread_rwlock_unlock(&ctx->oob_queue_lock);
		return -1;
	}
	ctx->oob_queue[ctx->oob_queue_write_index]->peer = peer;
	ctx->oob_queue_write_index = (ctx->oob_queue_write_index + 1);
	ctx->oob_queue_bytesize += len;
	pthread_rwlock_unlock(&ctx->oob_queue_lock);

	return 0;
}

static void rist_oob_dequeue(struct rist_common_ctx *ctx, int maxcount)
{
	int counter = 0;

	while (1) {
		// If we fall behind, only empty 100 every 5ms (master loop)
		if (counter++ > maxcount) {
			break;
		}

		if (ctx->oob_queue_read_index == ctx->oob_queue_write_index) {
			//rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
			//	"\tWe are all up to date, index is %u/%u and bytes = %zu\n",
			//	ctx->oob_queue_read_index, ctx->oob_queue_write_index, ctx->oob_queue_bytesize);
			break;
		}

		struct rist_buffer *oob_buffer = ctx->oob_queue[ctx->oob_queue_read_index];
		if (!oob_buffer->data) {
			rist_log_priv(ctx, RIST_LOG_ERROR, "Null oob buffer, skipping!!!\n");
			ctx->oob_queue_read_index++;
			continue;
		}

		uint8_t *payload = oob_buffer->data;
		struct rist_peer *p = oob_buffer->peer;

		/* The stashed peer may have been freed (NAT rebind / timeout) since
		 * rist_oob_write() queued it; verify it is still live and hold
		 * peerlist_lock across the send so it can't be freed under us. */
		pthread_mutex_lock(&ctx->peerlist_lock);
		bool peer_alive = false;
		for (struct rist_peer *pp = ctx->PEERS; pp != NULL; pp = pp->next) {
			if (pp == p) {
				peer_alive = true;
				break;
			}
		}
		if (!peer_alive) {
			pthread_mutex_unlock(&ctx->peerlist_lock);
			rist_log_priv(ctx, RIST_LOG_WARN, "OOB: target peer no longer exists, dropping packet\n");
			ctx->oob_queue_bytesize -= oob_buffer->size;
			ctx->oob_queue_read_index++;
			continue;
		}
		if (p->listening) {
			/* Listener peer: send OOB to all alive child peers. */
			struct rist_peer *child = p->child;
			bool sent = false;
			while (child) {
				if (!child->dead) {
					rist_send_common_rtcp(child, RIST_PAYLOAD_TYPE_DATA_OOB, &payload[RIST_MAX_PAYLOAD_OFFSET],
							oob_buffer->size, 0, 0, 0, 0, 0);
					sent = true;
				}
				child = child->sibling_next;
			}
			if (!sent)
				rist_log_priv(ctx, RIST_LOG_WARN, "OOB: listener peer has no alive children, dropping\n");
		} else {
			rist_send_common_rtcp(p, RIST_PAYLOAD_TYPE_DATA_OOB, &payload[RIST_MAX_PAYLOAD_OFFSET],
					oob_buffer->size, 0, 0, 0, 0, 0);
		}
		pthread_mutex_unlock(&ctx->peerlist_lock);
		ctx->oob_queue_bytesize -= oob_buffer->size;
		ctx->oob_queue_read_index++;
	}

	return;
}

static void sender_send_nacks(struct rist_sender *ctx)
{
	// Send retries from the queue (if any)
	uint32_t counter = 1;
	int errors = 0;
	size_t total_bytes = 0;

	if (ctx->max_nacksperloop == 0)
		return; // No peers yet

	// Send nack retries. Stop when the retry queue is empty or when the data in the
	// send fifo queue grows to 10 packets (we do not want to harm real-time data)
	// We also stop on maxcounter (jitter control and max bandwidth protection)
	size_t queued_items = (atomic_load_explicit(&ctx->sender_queue_write_index, memory_order_acquire) - atomic_load_explicit(&ctx->sender_queue_read_index, memory_order_acquire)) &ctx->sender_queue_max;
	uint64_t start_time = timestampNTP_u64();
	while (queued_items < 10) {
		ssize_t ret = rist_retry_dequeue(ctx);
		if (ret == 0) {
			// ret == 0 is valid (nothing to send)
			break;
		} else if (ret < 0) {
			errors++;
		} else {
			total_bytes += ret;
			counter++;
		}
		if (counter > ctx->max_nacksperloop) {
			break;
		}
		if (((timestampNTP_u64() - start_time) / RIST_CLOCK) > 100)
		{
			rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Nack processing loop took longer than 100ms. Something is wrong!\n");
			// TODO: clear out the nack queue here?
			break;
		}
		queued_items = (atomic_load_explicit(&ctx->sender_queue_write_index, memory_order_acquire) - atomic_load_explicit(&ctx->sender_queue_read_index, memory_order_acquire)) & ctx->sender_queue_max;
	}
	if (ctx->common.debug && 2 * (counter - 1) > ctx->max_nacksperloop)
	{
		rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
				"Had to process multiple fifo nacks: c=%d, e=%d, b=%zu, s=%zu, m=%zu\n",
				counter - 1, errors, total_bytes, rist_get_sender_retry_queue_size(ctx),
				ctx->max_nacksperloop);
	}

}

static void sender_send_data(struct rist_sender *ctx, int maxcount)
{
	int counter = 0;

	while (1) {
		// If we fall behind, only empty 100 every 5ms (master loop)
		if (counter++ > maxcount) {
			break;
		}

		size_t idx = ((size_t)atomic_load_explicit(&ctx->sender_queue_read_index, memory_order_acquire) + 1)& (ctx->sender_queue_max-1);

		if (idx == (size_t)atomic_load_explicit(&ctx->sender_queue_write_index, memory_order_relaxed)) {
			//rist_log_priv(&ctx->common, RIST_LOG_ERROR,
			//    "\t[GOOD] We are all up to date, index is %d\n",
			//    ctx->sender_queue_read_index);
			break;
		}

		atomic_store_explicit(&ctx->sender_queue_read_index, idx, memory_order_release);
		if (RIST_UNLIKELY(ctx->sender_queue[idx] == NULL)) {
			ctx->sender_queue_size--;
			// This should never happen!
			rist_log_priv(&ctx->common, RIST_LOG_ERROR,
					"FIFO data block was null (read/write) (%zu/%zu)\n",
					idx, atomic_load_explicit(&ctx->sender_queue_write_index, memory_order_relaxed));
			continue;
		} else {
			struct rist_buffer *buffer =  ctx->sender_queue[idx];
			// Send  fifo data (handshake and data payloads)
			if (buffer->type == RIST_PAYLOAD_TYPE_RTCP) {
				// TODO can we ever have a null or dead buffer->peer?
				uint8_t *payload = buffer->data;
				rist_send_common_rtcp(buffer->peer, buffer->type, &payload[RIST_MAX_PAYLOAD_OFFSET], buffer->size, buffer->source_time, buffer->src_port, buffer->dst_port, 0, ctx->sender_queue[idx]->ts_null_bytes);
				buffer->seq = ctx->common.seq;
				buffer->seq_rtp = ctx->common.seq_rtp;
			}
			else {
				rist_sender_send_data_balanced(ctx, buffer);
				if (ctx->common.profile == RIST_PROFILE_ADVANCED) {
					ctx->seq_index[buffer->seq & (ctx->sender_queue_max - 1)] = (uint32_t)idx;
					/* Mirror into the RTP index so a Main-downgraded peer's
					 * 16-bit NACK can still resolve this packet. Dead data for
					 * Advanced-negotiated peers (never read for them). */
					if (ctx->seq_rtp_index)
						ctx->seq_rtp_index[buffer->seq_rtp] = (uint32_t)idx;
				} else
					ctx->seq_index[buffer->seq_rtp] = (uint32_t)idx;
			}
		}

		// Keep only sender_buffer_size items in buffer (this controls the size of the sender queue used on retries)
		int reduce = 0;
		do {
			size_t delete_idx = ((size_t)atomic_load_explicit(&ctx->sender_queue_read_index, memory_order_acquire) - ctx->sender_buffer_size) & (ctx->sender_queue_max - 1);
			ctx->sender_queue_delete_index = delete_idx;
			if (ctx->sender_queue[delete_idx] && ctx->sender_queue[delete_idx]->data) {
				/* perform the deletion based on the buffer size plus twice the configured/measured avg_rtt */
				uint64_t delay = (timestampNTP_u64() - ctx->sender_queue[delete_idx]->time) / RIST_CLOCK;
				ctx->sender_queue_timelength = delay;
				if (delay < ctx->sender_recover_min_time) {
					if (ctx->sender_buffer_size < ctx->sender_queue_max - 1)
						ctx->sender_buffer_size++;
					reduce = 0;
					break;
				}
				else if (reduce == 0 && delay > ctx->sender_recover_min_time * 1.1) {
					// Shrink the buffer size by one (packet is old enough)
					if (ctx->sender_buffer_size > 0) {
						reduce = 1;
						ctx->sender_buffer_size--;
					}
				}
				else {
					// We are not reducing the buffer size a second time
					reduce = 0;
				}
				ctx->sender_queue_bytesize -= ctx->sender_queue[delete_idx]->size;
				ctx->sender_queue_size--;
				free(ctx->sender_queue[delete_idx]->data);
				ctx->sender_queue[delete_idx]->data = NULL;
			}
			if (ctx->sender_queue[delete_idx]) {
				free(ctx->sender_queue[delete_idx]);
				ctx->sender_queue[delete_idx] = NULL;
			}
		} while (reduce && ctx->sender_queue_size > 0);

	}
}

static struct rist_peer *peer_initialize(const char *url, struct rist_sender *sender_ctx,
		struct rist_receiver *receiver_ctx)
{
	struct rist_common_ctx *cctx;
	if (receiver_ctx)
		cctx = &receiver_ctx->common;
	else
		cctx = &sender_ctx->common;

	struct rist_peer *p = calloc(1, sizeof(*p));
	if (!p) {
		rist_log_priv(cctx, RIST_LOG_ERROR, "\tNot enough memory creating peer!\n");
		return NULL;
	}

	if (pthread_mutex_init(&p->peer_lock, NULL) != 0) {
		rist_log_priv(cctx, RIST_LOG_ERROR, "\tError initializing peer lock!\n");
		free(p);
		return NULL;
	}

	if (url) {
		p->url = strdup(url);
	}

	p->receiver_mode = (receiver_ctx != NULL);
	p->config.recovery_mode = RIST_RECOVERY_MODE_UNCONFIGURED;
	p->rtcp_keepalive_interval = RIST_PING_INTERVAL * RIST_CLOCK;
	p->sender_ctx = sender_ctx;
	p->receiver_ctx = receiver_ctx;
	p->birthtime_local = timestampNTP_u64();
	p->handled_first = true;
	p->sd = -1;

	return p;
}

static PTHREAD_START_FUNC(receiver_pthread_dataout, arg)
{
	struct rist_flow *flow = (struct rist_flow *)arg;
	struct rist_receiver *receiver_ctx = (void *)flow->receiver_id;

#ifndef _WIN32
	int prio_max = sched_get_priority_max(SCHED_RR);
	struct sched_param param = { 0 };
	param.sched_priority = prio_max;
	if (pthread_setschedparam(pthread_self(), SCHED_RR, &param) != 0)
		rist_log_priv(&receiver_ctx->common, RIST_LOG_WARN, "Failed to set data output thread to RR scheduler with prio of %i\n", prio_max);
#else
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
#endif
	// Default max jitter is 5ms
	int max_output_jitter_ms = flow->max_output_jitter / RIST_CLOCK;
	if (max_output_jitter_ms > 100)
		max_output_jitter_ms = 100;

	rist_log_priv(&receiver_ctx->common, RIST_LOG_INFO, "Starting data output thread with %d ms max output jitter\n", max_output_jitter_ms);

	/* Keep one source of truth for the wake ceiling. */
	flow->cbr_pacer.max_sleep_ns = (uint64_t)max_output_jitter_ms * 1000000ULL;
	flow->cbr_max_hold_us = rist_cbr_hold_us((uint32_t)max_output_jitter_ms);
	if (flow->cbr_output)
		rist_log_priv(&receiver_ctx->common, RIST_LOG_INFO,
			"CBR output pacing enabled, wake interval %u us to %d ms, hold %u us\n",
			flow->cbr_output_min_us, max_output_jitter_ms,
			flow->cbr_max_hold_us);

	pthread_mutex_lock(&(flow->mutex));
	uint64_t target_recovery_buffer_size = flow->recovery_buffer_ticks;
	pthread_mutex_unlock(&(flow->mutex));

	uint64_t next_buffer_adjust_step = timestampNTP_u64() + ONE_SECOND;
	uint64_t buffer_adjust_step_time = 0;
	int64_t buffer_adjust_step_size = 0;
	int buffer_adjust_steps_left = 0;

	while (true) {
		pthread_mutex_lock(&(flow->mutex));
		uint64_t wait_us = (uint64_t)max_output_jitter_ms * 1000;
		if (flow->cbr_output) {
			uint64_t now_ntp = timestampNTP_u64();
			uint64_t arrived = atomic_load_explicit(&flow->cbr_arrived_bytes,
								memory_order_relaxed);
			uint64_t delta = arrived - flow->cbr_arrived_seen;
			flow->cbr_arrived_seen = arrived;
			/* Only on real arrivals: feeding zero would close windows during a
			 * signal loss and average the rate away, and the estimator's outage
			 * detection keys off the gap between calls. */
			if (delta)
				rist_pacer_rate_add(&flow->cbr_rate, (size_t)delta,
						    timestampNTP_to_us(now_ntp));
			/* Wake at least twice per datagram interval, once one is known. */
			if (flow->cbr_interval_ns) {
				uint64_t floor_ns = flow->cbr_interval_ns / 2;
				uint64_t ceil_ns = (uint64_t)flow->cbr_output_min_us * 1000;
				if (floor_ns < RIST_CBR_OUTPUT_MIN_US_FLOOR * 1000ULL)
					floor_ns = RIST_CBR_OUTPUT_MIN_US_FLOOR * 1000ULL;
				if (floor_ns > ceil_ns)
					floor_ns = ceil_ns;
				flow->cbr_pacer.min_sleep_ns = floor_ns;
			}
			wait_us = rist_pacer_sleep_ns(&flow->cbr_pacer,
						      timestampNTP_to_ns(now_ntp)) / 1000;
			if (!wait_us)
				wait_us = 1;
		}
		int ret = pthread_cond_timedwait_us(&flow->condition, &flow->mutex, wait_us);
		if (ret && ret != ETIMEDOUT)
			rist_log_priv(&receiver_ctx->common, RIST_LOG_ERROR, "Error %d in receiver data out loop\n", ret);
		if (atomic_load_explicit(&flow->shutdown,memory_order_acquire) > 0)
			break;
		flow->cbr_paced_hold = false;
		if (atomic_load_explicit(&flow->receiver_queue_size, memory_order_acquire) > 0) {
			receiver_output(receiver_ctx, flow);
		}
		/* Nothing sent and the pacer was not holding: idle, so don't let the
		 * schedule accrue due times through the gap. */
		if (flow->cbr_output && !flow->cbr_paced_hold)
			rist_pacer_reset(&flow->cbr_pacer);

		if (flow->flow_auto_buffer_scaling) {
			uint64_t now = timestampNTP_u64();
			if (target_recovery_buffer_size == flow->recovery_buffer_ticks) {
				if (now >= next_buffer_adjust_step) {
					if (flow->currently_scaling_buffer) {
						flow->currently_scaling_buffer = false;
						rist_log_priv(&receiver_ctx->common, RIST_LOG_INFO, "Done rescaling buffer\n");
					}
					next_buffer_adjust_step += ONE_SECOND;
					uint64_t tmp_target_buffer_size = 0;
					for (size_t i=0; i < flow->peer_lst_len; i++) {
						struct rist_peer *p = flow->peer_lst[i];
						if (p->recovery_buffer_ticks > tmp_target_buffer_size) {
							tmp_target_buffer_size = p->recovery_buffer_ticks;
						}
					}

					uint64_t diff = target_recovery_buffer_size - tmp_target_buffer_size;
					if (tmp_target_buffer_size > target_recovery_buffer_size)
						diff = tmp_target_buffer_size - target_recovery_buffer_size;

					if (diff > RIST_CLOCK * 15) {
						target_recovery_buffer_size = tmp_target_buffer_size;
						buffer_adjust_step_size = diff / 100;
						buffer_adjust_steps_left = 100;
						buffer_adjust_step_time = buffer_adjust_step_size * 8;//Magic factor of 8 to ensure our changes aren't too dramatic
						if (flow->recovery_buffer_ticks > target_recovery_buffer_size)
							buffer_adjust_step_size *= -1;
						next_buffer_adjust_step = now + buffer_adjust_step_time;
						if ((target_recovery_buffer_size *2ULL) > flow->session_timeout)
							flow->session_timeout = 2ULL * target_recovery_buffer_size;
						flow->currently_scaling_buffer = true;
						rist_log_priv(&receiver_ctx->common, RIST_LOG_INFO, "Adjusting flow buffer time to %"PRIu64"ms, flow timeout is  %"PRIu64"ms\n", tmp_target_buffer_size/ RIST_CLOCK, flow->session_timeout/ RIST_CLOCK);

					}
				}
			} else if (now >= next_buffer_adjust_step) {
				flow->recovery_buffer_ticks += buffer_adjust_step_size;
				buffer_adjust_steps_left--;
				next_buffer_adjust_step += buffer_adjust_step_time;
				if (buffer_adjust_steps_left == 0) {
					flow->recovery_buffer_ticks = target_recovery_buffer_size;
					uint64_t next_min = 2 * ONE_SECOND;
					if (flow->recovery_buffer_ticks *1.5 > next_min)
						next_min = flow->recovery_buffer_ticks *1.5;
					next_buffer_adjust_step = now +  2 *ONE_SECOND;// We don't want to adjust to often, so keep 2 seconds between adjustments
				}
			}
		}

		pthread_mutex_unlock(&(flow->mutex));
	}
	rist_log_priv(&receiver_ctx->common, RIST_LOG_INFO, "Data output thread shutting down\n");
	atomic_store_explicit(&flow->shutdown, 2, memory_order_release);
	pthread_mutex_unlock(&flow->mutex);
	return 0;
}

static void rist_peer_periodic(struct rist_peer *p, uint64_t now) {
	bool adv_negotiated = (get_cctx(p)->profile == RIST_PROFILE_ADVANCED &&
	                       p->is_advanced && p->remote_supports_advanced);
	if (p->send_keepalive) {
		if (now > p->next_periodic_rtcp) {
			p->next_periodic_rtcp = now + p->rtcp_keepalive_interval;
			if (p->remote_port != 0) {
				rist_peer_rtcp(NULL, p);
				if (adv_negotiated)
					rist_adv_send_rtt_echo_request(p);
			}
		}
		if (get_cctx(p)->profile >= RIST_PROFILE_MAIN && p->next_keepalive_packet <= now) {
			p->next_keepalive_packet = now + ONE_SECOND;
			if (adv_negotiated) {
				rist_adv_send_keepalive(p);
				if (p->sender_ctx && p->next_flow_attr <= now) {
					p->next_flow_attr = now + ONE_SECOND;
					rist_adv_send_flow_attr(p);
				}
			} else
				_librist_proto_gre_send_keepalive(p, p->rist_gre_version);
#if HAVE_SRP_SUPPORT
			if (!p->child && !eap_is_authenticated(p->eap_ctx) && p->eap_authentication_state == 2 && p->parent && p->parent->multicast_sender)  {
				p->eap_authentication_state = 1;
				char newpass[65];
				newpass[64] = '\0';
				if (_librist_crypto_random_get_string(newpass, sizeof(newpass)-1) == 0) {
					rist_peer_update_secret(p->parent, newpass);
				}
			}
#endif
		}
	}
#if HAVE_SRP_SUPPORT
	if ((!p->listening || p->parent) && !p->multicast_sender)
		eap_periodic(p->eap_ctx);
#endif
}

static void sender_peer_events(struct rist_sender *ctx, uint64_t now)
{
	pthread_mutex_lock(&ctx->common.peerlist_lock);
	for (size_t j = 0; j < ctx->peer_lst_len; j++) {
		rist_peer_periodic(ctx->peer_lst[j], now);
	}
	pthread_mutex_unlock(&ctx->common.peerlist_lock);
}


static void receiver_peer_events(struct rist_receiver *ctx, uint64_t now)
{
	pthread_mutex_lock(&ctx->common.peerlist_lock);

	for (struct rist_peer *p = ctx->common.PEERS; p != NULL; p = p->next) {
		rist_peer_periodic(p, now);
	}
	pthread_mutex_unlock(&ctx->common.peerlist_lock);
}

/* Silence before an authenticated leg is torn down and re-handshaked: the
 * configured session_timeout, or twice the receiver buffer when that is larger
 * (a leg returning within the buffer window can still contribute packets). */
static inline uint64_t rist_peer_liveness_timeout(const struct rist_peer *peer)
{
	uint64_t buf = 2 * peer->recovery_buffer_ticks;
	return buf > peer->session_timeout ? buf : peer->session_timeout;
}

void rist_timeout_check(struct rist_common_ctx *cctx, uint64_t now)
{
	struct rist_peer *peer = cctx->PEERS;
	while (peer)
	{
		struct rist_peer *next = peer->next;
		uint64_t last_rtcp_received = peer->last_pkt_received;
		if (cctx->profile == RIST_PROFILE_SIMPLE &&
			!peer->is_rtcp && peer->peer_rtcp != NULL &&
			peer->peer_rtcp->last_pkt_received > last_rtcp_received)
			last_rtcp_received = peer->peer_rtcp->last_pkt_received;
		if (!peer->dead && now > last_rtcp_received && last_rtcp_received > 0)
		{
			if ((now - last_rtcp_received) > rist_peer_liveness_timeout(peer))
			{
				rist_log_priv2(cctx->logging_settings, RIST_LOG_WARN, "Listening peer %u timed out after %"PRIu64" ms\n", peer->adv_peer_id,
					(now - last_rtcp_received)/ RIST_CLOCK);
				if (try_caller_socket_rebind(peer, now))
				{
					/* Rebind kept the peer alive with a fresh
					 * socket; skip kill_peer. */
					peer = next;
					continue;
				}
				kill_peer(peer);
			}
		} else if (peer->dead && peer->parent)
		{
			if ( peer->dead_since < now && (now - peer->dead_since) > 5000 * RIST_CLOCK)
			{
				rist_log_priv2(cctx->logging_settings, RIST_LOG_INFO, "Removing timed-out peer %u\n", peer->adv_peer_id);
				rist_peer_remove(cctx, peer, NULL);
			}
		} else if (!peer->timed_out && peer->dead && peer->dead_since < now && (now - peer->dead_since) > 5000 * RIST_CLOCK) {
			peer->timed_out = 1;
			if (cctx->connection_status_callback && peer->send_first_connection_event)
				cctx->connection_status_callback( cctx->connection_status_callback_argument, peer, RIST_CONNECTION_TIMED_OUT);
		}
		peer = next;
	}
}

/* True for a bonded data leg that participates in weighted balancing.
 * Listeners, children, and duplicate (weight 0) legs are out of scope. */
static inline bool rist_peer_bonded_data_leg(const struct rist_peer *peer)
{
	return peer->is_data && !peer->parent && !peer->listening
		&& peer->config.weight != RIST_PEER_WEIGHT_DUPLICATE;
}

/* True for a bonded data leg that also has RTT auto-mute configured.
 * Caller must hold peerlist_lock. */
static inline bool rist_peer_rtt_mute_eligible(const struct rist_peer *peer)
{
	return rist_peer_bonded_data_leg(peer) && peer->config.rtt_drop > 0;
}

/* Silent for a few probe intervals: well short of the liveness timeout, since
 * fast-mute only reroutes payload rather than tearing the session down. Scales
 * with the configured keepalive_interval. */
static inline bool rist_peer_stall_silent(const struct rist_peer *peer, uint64_t now)
{
	uint64_t thr = RIST_STALL_MUTE_PINGS * peer->rtcp_keepalive_interval;
	return peer->last_pkt_received > 0 && now > peer->last_pkt_received
		&& (now - peer->last_pkt_received) > thr;
}

/* Fast-mute briefly-silent bonded legs so their payload reroutes to a healthy
 * sibling rather than pouring into a stalled path until the liveness timeout
 * tears the session down. Any bonded leg qualifies (no rtt-drop needed); the
 * flag is recomputed each tick, so a resumed leg clears at once. The last leg
 * with a live return path is never muted. Short tick, peerlist_lock held. */
static void rist_sender_stall_check(struct rist_sender *ctx, uint64_t now)
{
	struct rist_peer *peer;
	int eligible = 0, live = 0;

	for (peer = ctx->common.PEERS; peer; peer = peer->next) {
		if (!rist_peer_bonded_data_leg(peer))
			continue;
		eligible++;
		if (!rist_peer_stall_silent(peer, now))
			live++;
	}
	/* Nothing to fail over to: never stall-mute a single leg. */
	if (eligible < 2) {
		for (peer = ctx->common.PEERS; peer; peer = peer->next)
			peer->stalled = false;
		return;
	}
	for (peer = ctx->common.PEERS; peer; peer = peer->next) {
		if (!rist_peer_bonded_data_leg(peer)) {
			peer->stalled = false;
			continue;
		}
		bool silent = rist_peer_stall_silent(peer, now);
		/* keep every leg sending if all are silent, rather than black out */
		bool stall = silent && live > 0;
		if (stall && !peer->stalled)
			rist_log_priv(&ctx->common, RIST_LOG_INFO,
				"Peer %"PRIu32" stalled: silent %"PRIu64"ms, rerouting payload to healthy leg(s)\n",
				peer->adv_peer_id, (now - peer->last_pkt_received) / RIST_CLOCK);
		else if (!stall && peer->stalled)
			rist_log_priv(&ctx->common, RIST_LOG_INFO,
				"Peer %"PRIu32" resumed from stall\n", peer->adv_peer_id);
		peer->stalled = stall;
	}
}

/* Advance the RTT hysteresis for every eligible bonded leg, then decide which
 * legs are actually pulled from the payload rotation. rtt_mute_state.muted is
 * the *desired* state; peer->rtt_muted (what the balancer skips) is only set
 * when pulling the leg still leaves a carrier -- a bonded leg that is neither
 * muted nor stalled. Since the stall check runs first, a leg that wants mute
 * but whose only sibling is stalled is simply kept carrying, never actually
 * muted: that avoids blacking out the bond and, because the hysteresis state is
 * left untouched, avoids re-muting (and re-counting/logging) it every dwell.
 * Caller holds peerlist_lock; runs on a short tick (see the sender loop). */
static void rist_sender_rtt_mute_check(struct rist_sender *ctx, uint64_t now)
{
	struct rist_peer *peer;
	int eligible = 0;

	for (peer = ctx->common.PEERS; peer; peer = peer->next)
		if (rist_peer_rtt_mute_eligible(peer))
			eligible++;
	/* Nothing to fail over to: never mute a single leg. */
	if (eligible < 2)
		return;

	for (peer = ctx->common.PEERS; peer; peer = peer->next) {
		if (!rist_peer_rtt_mute_eligible(peer))
			continue;
		if (peer->eight_times_rtt == 0)
			continue; /* no RTT sample yet */

		uint64_t smoothed = peer->eight_times_rtt / 8;
		uint64_t drop = (uint64_t)peer->config.rtt_drop * RIST_CLOCK;
		uint64_t restore = peer->config.rtt_restore
			? (uint64_t)peer->config.rtt_restore * RIST_CLOCK
			: (drop * 4) / 5;
		if (restore >= drop)
			restore = (drop * 4) / 5;
		uint64_t drop_settle = (uint64_t)peer->config.rtt_drop_settle * RIST_CLOCK;
		/* Rejoin dwell is twice the drop dwell so a still-marginal link
		 * cannot immediately flap back in. */
		uint64_t restore_settle = drop_settle * 2;
		rist_rtt_mute_step(&peer->rtt_mute_state, smoothed, drop, restore,
				   drop_settle, restore_settle, now);
	}

	/* Count natural carriers; among the legs that want mute but could still
	 * carry (not stalled), find the incumbent sole carrier and the best
	 * challenger. */
	int carriers = 0;
	struct rist_peer *incumbent = NULL, *best = NULL;
	uint64_t incumbent_rtt = UINT64_MAX, best_rtt = UINT64_MAX;
	for (peer = ctx->common.PEERS; peer; peer = peer->next) {
		if (!rist_peer_bonded_data_leg(peer))
			continue;
		bool want = rist_peer_rtt_mute_eligible(peer) && peer->rtt_mute_state.muted;
		if (!want && !peer->stalled) {
			carriers++;
		} else if (want && !peer->stalled) {
			uint64_t smoothed = peer->eight_times_rtt ? peer->eight_times_rtt / 8 : UINT64_MAX;
			if (smoothed < best_rtt) { best_rtt = smoothed; best = peer; }
			if (peer->rtt_sole_carrier) { incumbent = peer; incumbent_rtt = smoothed; }
		}
	}

	/* Pick the leg to keep when nothing else can carry. Re-running this from
	 * the instantaneous RTT every tick made the payload path ping-pong between
	 * two equally bad legs roughly once a second, which is worse for the stream
	 * than staying on either one, so the incumbent holds the role until it
	 * recovers, goes stalled, or a sibling measures several times better and
	 * the incumbent has served at least one drop dwell. */
	struct rist_peer *keep = NULL;
	if (carriers == 0) {
		keep = incumbent ? incumbent : best;
		if (incumbent && best && best != incumbent
		    && rist_rtt_sole_carrier_handover(incumbent_rtt, best_rtt,
				now - incumbent->rtt_sole_since,
				(uint64_t)incumbent->config.rtt_drop_settle * RIST_CLOCK,
				RIST_SOLE_CARRIER_MARGIN))
			keep = best;
	}
	for (peer = ctx->common.PEERS; peer; peer = peer->next) {
		if (!rist_peer_bonded_data_leg(peer))
			continue;
		if (peer != keep)
			peer->rtt_sole_carrier = false;
		else if (!peer->rtt_sole_carrier) {
			peer->rtt_sole_carrier = true;
			peer->rtt_sole_since = now;
		}
	}

	/* Apply, counting/logging only genuine peer->rtt_muted transitions. */
	for (peer = ctx->common.PEERS; peer; peer = peer->next) {
		if (!rist_peer_rtt_mute_eligible(peer))
			continue;
		bool mute = peer->rtt_mute_state.muted && peer != keep;
		if (mute && !peer->rtt_muted) {
			uint64_t smoothed = (peer->eight_times_rtt / 8) / RIST_CLOCK;
			peer->rtt_muted = true;
			peer->rtt_mute_count++;
			/* Below the ceiling means the leg spiked earlier and is still
			 * serving out its rejoin dwell, not that it just crossed. */
			if (smoothed > peer->config.rtt_drop)
				rist_log_priv(&ctx->common, RIST_LOG_INFO,
					"Peer %"PRIu32" muted: smoothed RTT %"PRIu64"ms over %ums ceiling\n",
					peer->adv_peer_id, smoothed, peer->config.rtt_drop);
			else
				rist_log_priv(&ctx->common, RIST_LOG_INFO,
					"Peer %"PRIu32" muted: smoothed RTT %"PRIu64"ms, rejoin dwell not met\n",
					peer->adv_peer_id, smoothed);
		} else if (!mute && peer->rtt_muted) {
			peer->rtt_muted = false;
			peer->rtt_trickle_counter = 0;
			/* Rejoin gradually: an idle leg measures well until it carries
			 * again, so ramp its share back instead of re-flooding it. */
			peer->rtt_ramp_start = now;
			if (peer->rtt_mute_state.muted)
				rist_log_priv(&ctx->common, RIST_LOG_INFO,
					"Peer %"PRIu32" kept as sole carrier (all bonded legs muted or stalled)\n",
					peer->adv_peer_id);
			else
				rist_log_priv(&ctx->common, RIST_LOG_INFO,
					"Peer %"PRIu32" restored to bond: smoothed RTT %"PRIu64"ms\n",
					peer->adv_peer_id,
					(peer->eight_times_rtt / 8) / RIST_CLOCK);
		}
	}
}

PTHREAD_START_FUNC(sender_pthread_protocol, arg)
{
	struct rist_sender *ctx = (struct rist_sender *) arg;
	// loop behavior parameters
	int max_dataperloop = 100;
	int max_oobperloop = 100;

	int max_jitter_ms = ctx->common.rist_max_jitter / RIST_CLOCK;

	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Starting master sender loop at %d ms max jitter\n",
			max_jitter_ms);

	uint64_t now  = timestampNTP_u64();
	ctx->stats_next_time = now;
	ctx->checks_next_time = now;
	uint64_t nacks_next_time = now;
	uint64_t mute_check_next_time = now;
	while(!atomic_load_explicit(&ctx->common.shutdown, memory_order_acquire)) {
		// Conditional 5ms sleep that is woken by data coming in
		pthread_mutex_lock(&(ctx->mutex));
		int ret = pthread_cond_timedwait_ms(&(ctx->condition), &(ctx->mutex), max_jitter_ms);
		if (RIST_UNLIKELY(!atomic_load_explicit(&ctx->common.startup_complete, memory_order_acquire))) {
			pthread_mutex_unlock(&(ctx->mutex));
			continue;
		}
		pthread_mutex_unlock(&(ctx->mutex));
		if (ret && ret != ETIMEDOUT)
			rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Error %d in sender protocol loop, loop time was %d us\n", ret, (timestampNTP_u64() - now));

		now  = timestampNTP_u64();

		/* marks peer as dead, run every second */
		if (now > ctx->checks_next_time)
		{
			ctx->checks_next_time += (uint64_t)1000 * (uint64_t)RIST_CLOCK;
			pthread_mutex_lock(&ctx->common.peerlist_lock);
			rist_timeout_check(&ctx->common, now);
			pthread_mutex_unlock(&ctx->common.peerlist_lock);
		}

		/* Short tick so the configured settle is honoured, not quantised
		 * to the 1 s check cadence. */
		if (now > mute_check_next_time)
		{
			mute_check_next_time = now + (uint64_t)250 * (uint64_t)RIST_CLOCK;
			pthread_mutex_lock(&ctx->common.peerlist_lock);
			/* Stall first so the mute check sees this tick's stalled
			 * flags and can keep a carrier when a sibling is silent. */
			rist_sender_stall_check(ctx, now);
			rist_sender_rtt_mute_check(ctx, now);
			pthread_mutex_unlock(&ctx->common.peerlist_lock);
		}

		// stats timer; 0 == disabled.  Read fresh so a callback registered
		// after loop start takes effect.
		uint64_t rist_stats_interval = ctx->stats_report_time;
		if (rist_stats_interval == 0) {
			ctx->stats_next_time = now; // keep current to avoid a catch-up burst
		} else if (now > ctx->stats_next_time) {
			ctx->stats_next_time += rist_stats_interval;
			rist_sender_flow_statistics(ctx);
			// TODO: remove dead peers after stale flow time (both sender list and peer chain)
			// sender_peer_delete(peer->sender_ctx, peer);
		}

		// socket polls (returns as fast as possible and processes the next 100 socket events)
		pthread_mutex_lock(&ctx->common.peerlist_lock);
		evsocket_loop_single(ctx->common.evctx, 0, 100);
		pthread_mutex_unlock(&ctx->common.peerlist_lock);

		// keepalive timer
		sender_peer_events(ctx, now);


		// Send data and process nacks
		pthread_mutex_lock(&ctx->queue_lock);
		if (ctx->sender_queue_bytesize > 0) {
			pthread_mutex_lock(&ctx->common.peerlist_lock);
			sender_send_data(ctx, max_dataperloop);
			// Group nacks and send them all at rist_max_jitter intervals.
			// sender_send_nacks() dereferences retry->peer for every
			// entry in the retry queue; the peer list (and hence any
			// given peer) can be torn down from rist_peer_destroy()
			// concurrently, so we must hold peerlist_lock across the
			// whole dequeue loop to prevent a use-after-free.
			if (now > nacks_next_time) {
				sender_send_nacks(ctx);
				nacks_next_time += ctx->common.rist_max_jitter;
			}
			pthread_mutex_unlock(&ctx->common.peerlist_lock);
		}
		pthread_mutex_unlock(&ctx->queue_lock);
		// Send oob data
		if (ctx->common.oob_queue_bytesize > 0)
			rist_oob_dequeue(&ctx->common, max_oobperloop);

	}

#ifdef _WIN32
	WSACleanup();
#endif
	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Exiting master sender loop\n");
	atomic_store_explicit(&ctx->common.shutdown, 2, memory_order_release);

	return 0;
}

/* Idempotent: re-init is fine if cctx->profile is upgraded to Advanced
 * after the original init_common_ctx ran (e.g. via ?profile= URL override
 * in rist_peer_create).  Re-rolls SSRC base and clears the seq counters. */
void init_advanced_state(struct rist_common_ctx *ctx)
{
	/* Generate a random even SSRC base for the Protected flow.
	 * The Unprotected flow uses ssrc_base | 1 (Section 5.2.1). */
	uint32_t rnd = 0;
	_librist_crypto_ramdom_get_bytes((uint8_t *)&rnd, sizeof(rnd));
	ctx->adv_ssrc_base = rnd & ~(uint32_t)1;
	ctx->adv_seq_protected = 0;
	ctx->adv_seq_unprotected = 0;
}

int init_common_ctx(struct rist_common_ctx *ctx, enum rist_profile profile)
{
#ifdef _WIN32
	int ret;
	WSADATA wsaData;
	ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (ret < 0) {
		rist_log_priv3(RIST_LOG_ERROR, "Failed to initialize WSA\n");
		return -1;
	}
#endif
	ctx->evctx = evsocket_create();
	ctx->rist_max_jitter = RIST_MAX_JITTER * RIST_CLOCK;
	ctx->cbr_output = false;
	ctx->cbr_output_min_us = RIST_CBR_OUTPUT_MIN_US_DEFAULT;
	ctx->recovery_queue_max = RIST_SERVER_QUEUE_BUFFERS;
	if (profile > RIST_PROFILE_ADVANCED) {
		rist_log_priv3( RIST_LOG_ERROR, "Profile not supported (%d), using main profile instead\n", profile);
		profile = RIST_PROFILE_MAIN;
	}
	if (profile == RIST_PROFILE_SIMPLE)
		rist_log_priv3( RIST_LOG_INFO, "Starting in Simple Profile Mode\n");
	else if (profile == RIST_PROFILE_MAIN)
		rist_log_priv3( RIST_LOG_INFO, "Starting in Main Profile Mode\n");
	else if (profile == RIST_PROFILE_ADVANCED)
		rist_log_priv3( RIST_LOG_INFO, "Starting in Advanced Profile Mode\n");

	ctx->profile = profile;
	atomic_store_explicit(&ctx->profile_locked, false, memory_order_release);
	ctx->stats_report_time = 0;

	if (profile == RIST_PROFILE_ADVANCED)
		init_advanced_state(ctx);

	if (pthread_mutex_init(&ctx->peerlist_lock, NULL) != 0) {
		rist_log_priv3( RIST_LOG_ERROR, "Failed to init ctx->peerlist_lock\n");
		return -1;
	}
	if (pthread_mutex_init(&ctx->rist_free_buffer_mutex, NULL) != 0) {
		rist_log_priv3( RIST_LOG_ERROR, "Failed to init ctx->rist_free_buffer_mutex\n");
		return -1;
	}
	if (pthread_mutex_init(&ctx->flows_lock, NULL) != 0) {
		rist_log_priv3( RIST_LOG_ERROR, "Failed to init ctx->flows_lock\n");
		return -1;
	}
	if (pthread_mutex_init(&ctx->stats_lock, NULL) != 0) {
		rist_log_priv3( RIST_LOG_ERROR, "Failed to init ctx->stats_lock\n");
		return -1;
	}
	return 0;
}

static inline void peer_remove_child(struct rist_peer *peer) {
	assert(peer->parent);
	//head
	if (!peer->sibling_prev) {
		peer->parent->child = peer->sibling_next;
	//middle or tail
	} else {
		peer->sibling_prev->sibling_next = peer->sibling_next;
	}
	if (peer->sibling_next)
		peer->sibling_next->sibling_prev = peer->sibling_prev;
	return;
}

static inline void peer_remove_linked_list(struct rist_peer *peer) {
	assert(peer);
	struct rist_common_ctx *ctx = get_cctx(peer);
	if (!peer->prev) {
		ctx->PEERS = peer->next;
	} else {
		peer->prev->next = peer->next;
	}
	if (peer->next)
		peer->next->prev = peer->prev;
	return;
}


void remove_peer_from_flow(struct rist_peer *peer)
{
	struct rist_flow *f = peer->flow;
	if (f == NULL)
		return;
	pthread_mutex_lock(&f->mutex);
	bool found = false;
	for (size_t i = 0; i < f->peer_lst_len; i++)
	{
		if (f->peer_lst[i] == peer)
		{
			f->peer_lst[i] = f->peer_lst[(f->peer_lst_len -1)];
			found = true;
			break;
		}
	}
	if (found)
	{
		if (f->peer_lst_len > 1)
		{
			struct rist_peer **shrunk = realloc(f->peer_lst, sizeof(peer) * (f->peer_lst_len -1));
			/* Shrink realloc may fail; keep the oversized allocation. */
			if (shrunk)
				f->peer_lst = shrunk;
			f->peer_lst_len--;
		} else
		{
			free(f->peer_lst);
			f->peer_lst_len = 0;
			f->peer_lst = NULL;
		}
	}
	pthread_mutex_unlock(&f->mutex);
}

int rist_peer_remove(struct rist_common_ctx *ctx, struct rist_peer *peer, struct rist_peer **next)
{
	if (peer == NULL) {
		if (next)
			*next = NULL;
		return -1;
	}
	atomic_store_explicit(&peer->shutdown, true, memory_order_release);
	if (peer->send_first_connection_event  && !peer->timed_out && ctx->connection_status_callback && (ctx->profile != RIST_PROFILE_SIMPLE || peer->is_rtcp))
		ctx->connection_status_callback(ctx->connection_status_callback_argument, peer, RIST_CONNECTION_TIMED_OUT);
	if (peer->child)
	{
		while (peer->child) {
			rist_log_priv2(ctx->logging_settings, RIST_LOG_INFO, "[CLEANUP] removing child peer %u from peer %u\n", peer->child->adv_peer_id, peer->adv_peer_id);
			rist_peer_remove(ctx, peer->child, NULL);
		}
	}

	struct rist_peer *check = ctx->PEERS;
	while (check)
	{
		if (check->peer_data == peer)
			check->peer_data = NULL;
		if (check->peer_rtcp == peer)
			check->peer_rtcp = NULL;
		check = check->next;
	}

	/* Defensive: scrub any references to this peer from the sender's
	 * retry queue. The protocol thread now drains that queue under
	 * peerlist_lock, so it will never see a dangling retry->peer from
	 * here, but clearing the slot makes later triage easier and keeps
	 * the invariant explicit. */
	if (peer->sender_ctx && peer->sender_ctx->sender_retry_queue) {
		struct rist_sender *sctx = peer->sender_ctx;
		for (size_t i = 0; i < sctx->sender_retry_queue_size; i++) {
			if (sctx->sender_retry_queue[i].peer == peer) {
				sctx->sender_retry_queue[i].peer = NULL;
				sctx->sender_retry_queue[i].active = false;
			}
		}
	}
	if (peer->parent) {
		peer_remove_child(peer);
		if (peer->parent->child == NULL) {
			peer->parent->authenticated = false;
			if (peer->sender_ctx)
				peer->sender_ctx->total_weight -= peer->parent->config.weight;
		}
	}
	peer_remove_linked_list(peer);

	if (peer->parent && peer->flow && peer->flow->peer_lst_len > 0 && peer->flow->peer_lst != NULL) {
		remove_peer_from_flow(peer);
	}

	if (peer->sender_ctx && peer->sender_ctx->peer_lst_len > 0) {
		bool found = false;
        for (size_t i = 0; i < peer->sender_ctx->peer_lst_len; i++) {
            if (peer->sender_ctx->peer_lst[i] == peer) {
              peer->sender_ctx->peer_lst[i] = peer->sender_ctx->peer_lst[(peer->sender_ctx->peer_lst_len -1)];
              found = true;
              break;
            }
		}
		if (found) {
			if (peer->sender_ctx->peer_lst_len > 1)
			{
				peer->sender_ctx->peer_lst = realloc(peer->sender_ctx->peer_lst, sizeof(peer) * (peer->sender_ctx->peer_lst_len -1));
				peer->sender_ctx->peer_lst_len--;
			} else
			{
				free(peer->sender_ctx->peer_lst);
				peer->sender_ctx->peer_lst_len = 0;
				peer->sender_ctx->peer_lst = NULL;
			}
		}
    }

	if (peer->receiver_ctx != NULL && peer->flow != NULL) {
		pthread_mutex_lock(&peer->flow->mutex);
		bool found = false;
		for (size_t i=0; i < peer->flow->peer_lst_len; i++) {
			if (peer->flow->peer_lst[i] == peer) {
				peer->flow->peer_lst[i] = peer->flow->peer_lst[(peer->flow->peer_lst_len -1)];
				found = true;
				break;
			}
		}

		if (found) {
			if (peer->flow->peer_lst_len > 1) {
				/* Shrink realloc may fail; keep the oversized allocation. */
				struct rist_peer **shrunk = realloc(peer->flow->peer_lst, sizeof(peer) * (peer->flow->peer_lst_len -1));
				if (shrunk)
					peer->flow->peer_lst = shrunk;
				peer->flow->peer_lst_len--;
			} else {
				free(peer->flow->peer_lst);
				peer->flow->peer_lst_len = 0;
				peer->flow->peer_lst = NULL;
			}
		}
		pthread_mutex_unlock(&peer->flow->mutex);
	}


	/* data receive event */
	if (!peer->parent && peer->event_recv)
	{
		rist_log_priv2(ctx->logging_settings, RIST_LOG_INFO, "[CLEANUP] Removing peer data received event\n");
		struct evsocket_ctx *evctx = ctx->evctx;
		evsocket_delevent(evctx, peer->event_recv);
	}

	/* rtcp timer */
	if (peer->send_keepalive)
	{
		rist_log_priv2(ctx->logging_settings, RIST_LOG_INFO, "[CLEANUP] Removing peer handshake/ping timer\n");
		peer->send_keepalive = false;
	}


	if (!peer->parent && peer->sd > -1)
	{
		rist_log_priv2(ctx->logging_settings, RIST_LOG_INFO, "[CLEANUP] Closing peer socket on port %d\n", peer->local_port);
		udpsocket_close(peer->sd);
		peer->sd = -1;
	}
	_librist_crypto_psk_rist_key_destroy(&peer->key_rx);
	_librist_crypto_psk_rist_key_destroy(&peer->key_rx_odd);
	_librist_crypto_psk_rist_key_destroy(&peer->key_tx);
	_librist_crypto_psk_rist_key_destroy(&peer->key_tx_odd);
#if HAVE_SRP_SUPPORT
	eap_delete_ctx(&peer->eap_ctx);
#endif
	if (peer->url)
		free(peer->url);

	if (peer->parent != NULL && ctx->auth.disconn_cb) {
		ctx->auth.disconn_cb(ctx->auth.arg, peer);
	}
	if (next != NULL)
		*next = peer->next;
	rist_log_priv2(ctx->logging_settings, RIST_LOG_INFO, "[CLEANUP] cleanup done for peer %u\n", peer->adv_peer_id);

	if (ctx->oob_current_peer == peer) {
		ctx->oob_current_peer = NULL;
	}

	free(peer);
	return 0;
}

int rist_auth_handler(struct rist_common_ctx *ctx,
		int (*conn_cb)(void *arg, const char* connecting_ip, uint16_t connecting_port, const char* local_ip, uint16_t local_port, struct rist_peer *peer),
		int (*disconn_cb)(void *arg, struct rist_peer *peer),
		void *arg)
{
	ctx->auth.conn_cb = conn_cb;
	ctx->auth.disconn_cb = disconn_cb;
	ctx->auth.arg = arg;
	return 0;
}

static void store_peer_settings(const struct rist_peer_config *settings, struct rist_peer *peer)
{
	uint32_t recovery_rtt_min;
	uint32_t min_retries;
	uint32_t max_retries;

	// TODO: Consolidate the two settings objects into one

	/* Set recovery options */
	peer->config.recovery_mode = settings->recovery_mode;
	peer->config.recovery_maxbitrate = settings->recovery_maxbitrate;
	peer->config.recovery_maxbitrate_return = settings->recovery_maxbitrate_return;
	peer->config.recovery_length_min = settings->recovery_length_min;
	peer->config.recovery_length_max = settings->recovery_length_max;
	peer->config.recovery_reorder_buffer = settings->recovery_reorder_buffer;
	/* Set buffer-bloating */
	if (settings->min_retries < 2 || settings->min_retries > 100) {
		rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
				"The configured value for min_retries 2 <= %u <= 100 is invalid, using %u instead\n",
				settings->min_retries, 6);
		min_retries = 6;
	} else {
		min_retries = settings->min_retries;
	}
	if (settings->max_retries < 2 || settings->max_retries > 100) {
		rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
				"The configured value for max_retries 2 <= %u <= 100 is invalid, using %u instead\n",
				settings->max_retries, 20);
		max_retries = 20;
	} else {
		max_retries = settings->max_retries;
	}
	if (settings->recovery_rtt_min < RIST_RTT_MIN) {
		rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "rtt_min is too small (%u), using %dms instead\n",
				settings->recovery_rtt_min, RIST_RTT_MIN);
		recovery_rtt_min = RIST_RTT_MIN;
	} else {
		recovery_rtt_min = settings->recovery_rtt_min;
	}
	// Override rtt min if value is unreasonable
	uint32_t min_rtt = settings->recovery_length_min / max_retries;
	if (recovery_rtt_min < min_rtt) {
		rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "rtt_min is too small (%u) for the buffer size, using %u/%u = %dms instead\n",
			recovery_rtt_min, settings->recovery_length_min, max_retries, min_rtt);
		recovery_rtt_min = min_rtt;
	}
	if (settings->recovery_rtt_max < recovery_rtt_min)
	{
		rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "rtt_max is too small (%u), using %u instead\n",
				settings->recovery_rtt_max, recovery_rtt_min);
				peer->config.recovery_rtt_max = recovery_rtt_min * RIST_CLOCK;
	}
	else
		peer->config.recovery_rtt_max = settings->recovery_rtt_max * RIST_CLOCK;
	peer->config.recovery_rtt_min = recovery_rtt_min * RIST_CLOCK;
	peer->config.congestion_control_mode = settings->congestion_control_mode;
	peer->config.min_retries = min_retries;
	peer->config.max_retries = max_retries;
	peer->config.weight = settings->weight;
	peer->config.recovery_priority = settings->recovery_priority;
	peer->config.timing_mode = settings->timing_mode;
	peer->config.virt_dst_port = settings->virt_dst_port;
	if (settings->version >= 2)
		peer->config.reflector = settings->reflector;
	else
		peer->config.reflector = 0;
	if (settings->version >= 3)
		peer->config.srp_compat_legacy = settings->srp_compat_legacy; //read by rist_enable_eap_srp_2 after peer_create
	else
		peer->config.srp_compat_legacy = 0;
	if (settings->version >= 6) {
		peer->config.rtt_drop = settings->rtt_drop;
		peer->config.rtt_restore = settings->rtt_restore;
		peer->config.rtt_drop_settle = settings->rtt_drop_settle;
		peer->config.rtt_drop_trickle = settings->rtt_drop_trickle;
	} else {
		peer->config.rtt_drop = 0;
		peer->config.rtt_restore = 0;
		peer->config.rtt_drop_settle = RIST_DEFAULT_RTT_DROP_SETTLE;
		peer->config.rtt_drop_trickle = 0;
	}

	init_peer_settings(peer);
}

struct rist_peer *rist_sender_peer_insert_local(struct rist_sender *ctx,
		const struct rist_peer_config *config, bool b_rtcp)
{
	struct rist_peer *newpeer = _librist_peer_create_common(&ctx->common, NULL, ctx, config);
	if (!newpeer)
		return NULL;
	if (b_rtcp)
	{
		if (newpeer->u.address.sa_family == AF_INET) {
			struct sockaddr_in *addrv4 = (struct sockaddr_in *)&(newpeer->u);
			newpeer->remote_port = htons(addrv4->sin_port) + 1;
			addrv4->sin_port = be16toh(newpeer->remote_port);
		} else {
			struct sockaddr_in6 *addrv6 = (struct sockaddr_in6 *)&(newpeer->u);
			newpeer->remote_port = htons(addrv6->sin6_port) + 1;
			addrv6->sin6_port = be16toh(newpeer->remote_port);
		}
	}
	else
	{
		newpeer->local_port = 32768 + (ctx->common.peer_counter % 28232);
		// This overrides the physical port populate in rist_create_socket with the gre dst port
		if (ctx->common.profile != RIST_PROFILE_SIMPLE && config->virt_dst_port != 0)
			newpeer->remote_port = config->virt_dst_port + 1;
	}

	newpeer->cooldown_time = 0;
	newpeer->is_rtcp = b_rtcp;
	newpeer->adv_peer_id = ++ctx->common.peer_counter;
	newpeer->peer_ssrc = newpeer->adv_flow_id = ctx->adv_flow_id;

	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Advertising flow_id  %" PRIu64 " and peer_id %u, %u/%u\n",
			newpeer->adv_flow_id, newpeer->adv_peer_id, newpeer->local_port, newpeer->remote_port);

	return newpeer;

}


void rist_empty_oob_queue(struct rist_common_ctx *ctx)
{
	uint16_t index = 0;
	while (1) {
		if (index == ctx->oob_queue_write_index) {
			break;
		}
		struct rist_buffer *oob_buffer = ctx->oob_queue[index];
		if (oob_buffer->data) {
			free(oob_buffer->data);
			oob_buffer->data = NULL;
		}
		if (oob_buffer) {
			free(oob_buffer);
			oob_buffer = NULL;
		}
		index++;
	}
	ctx->oob_queue_bytesize = 0;

	/* drain the oob receive fifo and the last handed-out buffer */
	while (ctx->oob_rx_queue_read_index != ctx->oob_rx_queue_write_index) {
		struct rist_buffer *rx_buffer = ctx->oob_rx_queue[ctx->oob_rx_queue_read_index];
		ctx->oob_rx_queue[ctx->oob_rx_queue_read_index] = NULL;
		if (rx_buffer)
			free_rist_buffer(ctx, rx_buffer);
		ctx->oob_rx_queue_read_index = (uint16_t)(ctx->oob_rx_queue_read_index + 1);
	}
	if (ctx->oob_rx_current) {
		free_rist_buffer(ctx, ctx->oob_rx_current);
		ctx->oob_rx_current = NULL;
	}
}

void rist_receiver_destroy_local(struct rist_receiver *ctx)
{

	pthread_mutex_lock(&ctx->common.peerlist_lock);

	// Destroy all flows
	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Starting Flows cleanup\n");
	struct rist_flow *f = ctx->common.FLOWS;
	while (f) {
		struct rist_flow *nextflow = f->next;
		rist_delete_flow(ctx, f);
		f = nextflow;
	}
	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Flows cleanup complete\n");

	// Destroy all peers
	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Starting Peers cleanup\n");
	struct rist_peer *peer, *next;
	peer = ctx->common.PEERS;
	for (;;) {
		if (!peer)
			break;
		rist_peer_remove(&ctx->common, peer, &next);
		peer = next;
	}
	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Peers cleanup complete\n");

	pthread_mutex_unlock(&ctx->common.peerlist_lock);

	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Freeing main data buffers\n");
	struct rist_buffer *b = ctx->common.rist_free_buffer;
	struct rist_buffer *next_buf;
	while (b) {
		next_buf = b->next_free;
		free_rist_buffer(&ctx->common, b);
		b = next_buf;
	}
	evsocket_destroy(ctx->common.evctx);

	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Removing peerlist_lock\n");
	pthread_mutex_destroy(&ctx->common.peerlist_lock);
	if (ctx->common.oob_data_enabled) {
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "Freeing oob fifo queue\n");
		rist_empty_oob_queue(&ctx->common);
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "Removing oob_queue_lock\n");
		pthread_rwlock_destroy(&ctx->common.oob_queue_lock);
	}

	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Removing data fifo signaling variables (condition and mutex)\n");
	pthread_cond_destroy(&ctx->condition);
	pthread_mutex_destroy(&ctx->mutex);

	rist_logging_unset_global_if_matches(ctx->common.logging_settings);

	free(ctx);
	ctx = NULL;
}

void _librist_receiver_buffer_calc(struct rist_receiver *ctx) {
	pthread_mutex_lock(&ctx->common.peerlist_lock);
	struct rist_peer *p = ctx->common.PEERS;
	while (p != NULL) {
		if (p->config.recovery_length_max != p->config.recovery_length_min && !p->listening && p->sender_max_buffer_ticks > 0 && p->flow && p->rist_gre_version >= 2) {
			//Optimal default according to rist spec (multiplier configurable via API):
			int rtt_mult = ctx->common.recovery_rtt_multiplier > 0 ? ctx->common.recovery_rtt_multiplier : 7;
			uint64_t desired_buffer_level = (p->eight_times_rtt / 8) * rtt_mult + p->config.recovery_reorder_buffer;

			bool has_high_loss = false;
			double modifier = 1.0;

			//Modify our buffersize based on some magic numbers, these likely still need tuning
			pthread_mutex_lock(&p->flow->mutex);
			modifier += p->flow->stats_instant.lost * 0.05;//5% extra per packet lost
			if (p->flow->stats_instant.lost > 25)
				has_high_loss = true;

			modifier += p->flow->stats_instant.recovered_morenack * 0.02;
			modifier += p->flow->stats_instant.recovered_3nack * 0.01;
			pthread_mutex_unlock(&p->flow->mutex);

			desired_buffer_level *= modifier;

			if (has_high_loss)
				desired_buffer_level = p->sender_max_buffer_ticks;


			if (desired_buffer_level < p->recovery_buffer_ticks && (p->recovery_buffer_ticks - desired_buffer_level) > 50 * RIST_CLOCK) {
				desired_buffer_level = p->recovery_buffer_ticks - 50 * RIST_CLOCK;
			}

			uint64_t recovery_base_min = p->config.recovery_length_min * RIST_CLOCK;
			uint64_t recovery_base_max = p->config.recovery_length_max * RIST_CLOCK;

			if (desired_buffer_level < recovery_base_min)
				desired_buffer_level = recovery_base_min;
			else if (desired_buffer_level > recovery_base_max)
				desired_buffer_level = recovery_base_max;

			if (desired_buffer_level > p->sender_max_buffer_ticks)
				desired_buffer_level = p->sender_max_buffer_ticks;

			if (p->recovery_buffer_ticks != desired_buffer_level)
				_librist_proto_gre_send_buffer_negotiation(p, 0, desired_buffer_level/ RIST_CLOCK);

			p->recovery_buffer_ticks = desired_buffer_level;
        }
		p = p->next;
	}
	pthread_mutex_unlock(&ctx->common.peerlist_lock);
}

PTHREAD_START_FUNC(receiver_pthread_protocol, arg)
{
	struct rist_receiver *ctx = (struct rist_receiver *) arg;
	uint64_t now = timestampNTP_u64();
	int max_oobperloop = 100;
	uint64_t no_flow_time_check = timestampNTP_u64();

	uint64_t rist_nack_interval = (uint64_t)ctx->common.rist_max_jitter;
	int max_jitter_ms = ctx->common.rist_max_jitter / RIST_CLOCK;
	ctx->common.nacks_next_time = timestampNTP_u64();
	uint64_t checks_next_time = now;
	uint64_t buffer_check_next_time = now + ONE_SECOND;
	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Starting receiver protocol loop with %d ms timer\n", max_jitter_ms);

	while (!atomic_load_explicit(&ctx->common.shutdown, memory_order_acquire)) {
		now  = timestampNTP_u64();
		pthread_mutex_lock(&ctx->common.peerlist_lock);
		if (ctx->common.PEERS == NULL) {
			pthread_mutex_unlock(&ctx->common.peerlist_lock);
			usleep(5000);
			continue;
		}
		pthread_mutex_unlock(&ctx->common.peerlist_lock);

		// Limit scope of `struct rist_flow *f` for clarity since it is used again later in this loop.
		{
			// stats and session timeout timer
			struct rist_flow *f = ctx->common.FLOWS;
			if (!f)
			{
				// no flow timeout callback
				if ((now - no_flow_time_check) > ONE_SECOND && ctx->receiver_session_timeout_callback) {
					no_flow_time_check = now;
					ctx->receiver_session_timeout_callback(ctx->receiver_session_timeout_callback_argument, 0);
				}
			}
			while (f) {
				no_flow_time_check = now;
				pthread_mutex_lock(&f->mutex);
				if (!f->receiver_queue_has_items) {
					pthread_mutex_unlock(&f->mutex);
					f = f->next;
					continue;
				}
				if (now > f->checks_next_time) {
					if (f->last_recv_ts == 0)
						f->last_recv_ts = now;
					uint64_t flow_age = (now - f->last_recv_ts);
					f->checks_next_time += f->recovery_buffer_ticks;
					if (flow_age > f->flow_timeout) {
						if (f->dead != 1) {
							f->dead = 1;
							rist_log_priv(&ctx->common, RIST_LOG_WARN,
								"Flow with id %"PRIu32" is dead, age is %"PRIu64"ms\n",
									f->flow_id, flow_age / RIST_CLOCK);
						}
					}
					else {
						if (f->dead != 0) {
							f->dead = 0;
							rist_log_priv(&ctx->common, RIST_LOG_INFO,
								"Flow with id %"PRIu32" was dead and is now alive again\n", f->flow_id);
						}
					}
					if (flow_age > f->session_timeout) {
						f->dead = 2;
						struct rist_flow *next = f->next;
						rist_receiver_flow_statistics(ctx, f);
						rist_log_priv(&ctx->common, RIST_LOG_INFO,
								"\t************** Session Timeout after %" PRIu64 "s of no data, deleting flow with id %"PRIu32" ***************\n",
								flow_age / RIST_CLOCK / 1000, f->flow_id);
						if (ctx->receiver_session_timeout_callback) {
							ctx->receiver_session_timeout_callback(ctx->receiver_session_timeout_callback_argument, f->flow_id);
						}
						pthread_mutex_unlock(&f->mutex);
						pthread_mutex_lock(&ctx->common.peerlist_lock);
						pthread_mutex_lock(&f->mutex);
						for (size_t i = 0; i < f->peer_lst_len; i++) {
							struct rist_peer *peer = f->peer_lst[i];
							peer->flow = NULL;
						}
						pthread_mutex_unlock(&f->mutex);
						rist_delete_flow(ctx, f);
						pthread_mutex_unlock(&ctx->common.peerlist_lock);
						f = next;
						continue;
					}
				}
				if (now > f->stats_next_time) {
					f->stats_next_time += f->stats_report_time;
					rist_receiver_flow_statistics(ctx, f);
				}
				pthread_mutex_unlock(&f->mutex);
				f = f->next;
			}
		}

		// TODO: rist_max_jitter should be proportional to the max bitrate according to the
		// following table
		//Mbps  ms
		//125	8.00
		//250	4.00
		//520	1.92
		//1000	1.00

		// socket polls (returns in max_jitter_ms max and processes the next 100 socket events)
		pthread_mutex_lock(&ctx->common.peerlist_lock);
		evsocket_loop_single(ctx->common.evctx, max_jitter_ms, 100);
		pthread_mutex_unlock(&ctx->common.peerlist_lock);
		// keepalive timer
		receiver_peer_events(ctx, now);

		// nacks timer
		if (now > ctx->common.nacks_next_time) {
			ctx->common.nacks_next_time += rist_nack_interval;
			// process nacks on every loop (5 ms interval max)
			struct rist_flow *f = ctx->common.FLOWS;
			while (f) {
				receiver_nack_output(ctx, f);
				f = f->next;
			}
		}
		/* marks peer as dead, run every second */
		if (now > checks_next_time)
		{
			checks_next_time += (uint64_t)50 * (uint64_t)RIST_CLOCK;
			pthread_mutex_lock(&ctx->common.peerlist_lock);
			rist_timeout_check(&ctx->common, now);
			pthread_mutex_unlock(&ctx->common.peerlist_lock);
		}
		// Send oob data
		if (ctx->common.oob_queue_bytesize > 0)
			rist_oob_dequeue(&ctx->common, max_oobperloop);

		if (now >= buffer_check_next_time) {
			_librist_receiver_buffer_calc(ctx);
			buffer_check_next_time += 2 * ONE_SECOND;
		}

	}
#ifdef _WIN32
	WSACleanup();
#endif
	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Exiting master receiver loop\n");
	atomic_store_explicit(&ctx->common.shutdown, 2, memory_order_release);

	return 0;
}

void rist_sender_destroy_local(struct rist_sender *ctx)
{
	rist_log_priv(&ctx->common, RIST_LOG_INFO,
			"Starting peers cleanup, count %d\n",
			(unsigned) ctx->peer_lst_len);

	pthread_mutex_lock(&ctx->common.peerlist_lock);	// Destroy all peers
	while (ctx->peer_lst_len > 0) {
		rist_peer_remove(&ctx->common, ctx->peer_lst[0], NULL);
	}
	struct rist_peer *peer, *next;
	peer = ctx->common.PEERS;
	for (;;) {
		if (!peer)
			break;
		rist_peer_remove(&ctx->common, peer, &next);
		peer = next;
	}
	evsocket_destroy(ctx->common.evctx);

	pthread_mutex_unlock(&ctx->common.peerlist_lock);
	pthread_mutex_destroy(&ctx->common.peerlist_lock);
	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Peers cleanup complete\n");

	if (ctx->common.oob_data_enabled) {
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "Freeing oob fifo queue\n");
		rist_empty_oob_queue(&ctx->common);
		rist_log_priv(&ctx->common, RIST_LOG_INFO, "Removing oob_queue_lock\n");
		pthread_rwlock_destroy(&ctx->common.oob_queue_lock);
	}

	rist_log_priv(&ctx->common, RIST_LOG_INFO, "Freeing up context memory allocations\n");
	free(ctx->sender_retry_queue);
	ctx->sender_retry_queue = NULL;
	struct rist_buffer *b = NULL;
	while(1) {
		b = ctx->sender_queue[ctx->sender_queue_delete_index];
		while (!b) {
			ctx->sender_queue_delete_index = (ctx->sender_queue_delete_index + 1)& (ctx->sender_queue_max -1);
			b = ctx->sender_queue[ctx->sender_queue_delete_index];
			if ((size_t)atomic_load_explicit(&ctx->sender_queue_write_index, memory_order_relaxed) == ctx->sender_queue_delete_index)
				break;
		}
		if (b) {
			ctx->sender_queue_bytesize -= b->size;
			ctx->sender_queue_size--;
			free_rist_buffer(&ctx->common, b);
			ctx->sender_queue[ctx->sender_queue_delete_index] = NULL;
		}
		if ((size_t)atomic_load_explicit(&ctx->sender_queue_write_index, memory_order_acquire) == ctx->sender_queue_delete_index) {
			break;
		}
		ctx->sender_queue_delete_index = (ctx->sender_queue_delete_index + 1)& (ctx->sender_queue_max -1);
	}

	rist_logging_unset_global_if_matches(ctx->common.logging_settings);

	free(ctx->sender_queue);
	ctx->sender_queue = NULL;
	free(ctx->seq_index);
	ctx->seq_index = NULL;
	free(ctx->seq_rtp_index);
	ctx->seq_rtp_index = NULL;
	free(ctx);
	ctx = NULL;
}
