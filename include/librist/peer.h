/*
 * Copyright © 2020, VideoLAN and librist authors
 * Copyright © 2019-2020 SipRadius LLC
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef LIBRIST_PEER_H
#define LIBRIST_PEER_H

#include "common.h"
#include "headers.h"
#include "librist_config.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rist_peer;

/* Default peer config values */
#define RIST_DEFAULT_VIRT_SRC_PORT (1971)
#define RIST_DEFAULT_VIRT_DST_PORT (1968)
#define RIST_DEFAULT_RECOVERY_MODE RIST_RECOVERY_MODE_TIME
#define RIST_DEFAULT_RECOVERY_MAXBITRATE (100000)
#define RIST_DEFAULT_RECOVERY_MAXBITRATE_RETURN (0)
#define RIST_DEFAULT_RECOVERY_LENGTH_MIN (1000)
#define RIST_DEFAULT_RECOVERY_LENGHT_MIN _Pragma ("GCC warning \"'RIST_DEFAULT_RECOVERY_LENGHT_MIN' is deprecated, use RIST_DEFAULT_RECOVERY_LENGTH_MIN\"")  RIST_DEFAULT_RECOVERY_LENGTH_MIN
#define RIST_DEFAULT_RECOVERY_LENGTH_MAX (1000)
#define RIST_DEFAULT_RECOVERY_LENGHT_MAX _Pragma ("GCC warning \"'RIST_DEFAULT_RECOVERY_LENGHT_MAX' is deprecated, use RIST_DEFAULT_RECOVERY_LENGTH_MAX\"")  RIST_DEFAULT_RECOVERY_LENGTH_MAX
#define RIST_DEFAULT_RECOVERY_REORDER_BUFFER (15)
#define RIST_DEFAULT_RECOVERY_RTT_MIN (5)
#define RIST_DEFAULT_RECOVERY_RTT_MAX (500)
#define RIST_DEFAULT_CONGESTION_CONTROL_MODE RIST_CONGESTION_CONTROL_MODE_NORMAL
#define RIST_DEFAULT_MIN_RETRIES (6)
#define RIST_DEFAULT_MAX_RETRIES (20)
#define RIST_DEFAULT_VERBOSE_LEVEL RIST_LOG_INFO
#define RIST_DEFAULT_PROFILE RIST_PROFILE_ADVANCED
#define RIST_DEFAULT_SESSION_TIMEOUT (2000)
#define RIST_DEFAULT_KEEPALIVE_INTERVAL (1000)
#define RIST_DEFAULT_TIMING_MODE RIST_TIMING_MODE_SOURCE
#define RIST_DEFAULT_RECOVERY_PRIORITY (0)
/* Dynamic RTT-based bonded-leg muting (sender). Disabled by default. */
#define RIST_DEFAULT_RTT_DROP (0)           /* smoothed-RTT ceiling ms; 0 = disabled */
#define RIST_DEFAULT_RTT_RESTORE (0)        /* restore low-water ms; 0 = derive (80% of drop) */
#define RIST_DEFAULT_RTT_DROP_SETTLE (2000) /* dwell ms before a drop/restore transition */
#define RIST_DEFAULT_RTT_DROP_TRICKLE (100) /* 1-in-N duplicate rate while muted (~1%, warm restore); 0 = hard mute */

/* Special value for rist_peer_config.weight: a peer configured with this
 * weight receives a duplicate of every packet instead of taking part in
 * the weighted load-balancing rotation. */
#define RIST_PEER_WEIGHT_DUPLICATE (0)

enum rist_timing_mode
{
	RIST_TIMING_MODE_SOURCE = 0,
	RIST_TIMING_MODE_ARRIVAL = 1,
	RIST_TIMING_MODE_RTC = 2
};

enum rist_recovery_mode
{
	RIST_RECOVERY_MODE_UNCONFIGURED = 0,
	RIST_RECOVERY_MODE_DISABLED = 1,
	RIST_RECOVERY_MODE_TIME = 2,
};

enum rist_congestion_control_mode
{
	RIST_CONGESTION_CONTROL_MODE_OFF = 0,
	RIST_CONGESTION_CONTROL_MODE_NORMAL = 1,
	RIST_CONGESTION_CONTROL_MODE_AGGRESSIVE = 2
};

enum librist_split_mode
{
	LIBRIST_SPLIT_MODE_OFF  = 0,
	LIBRIST_SPLIT_MODE_AUTO = 1,
	LIBRIST_SPLIT_MODE_HALF = 2,
};

enum librist_merge_mode
{
	LIBRIST_MERGE_MODE_OFF   = 0,
	LIBRIST_MERGE_MODE_PAIRS = 1,
	LIBRIST_MERGE_MODE_AUTO  = 2,
};

#define RIST_PEER_CONFIG_VERSION (6)

/* Advanced-profile recovery depth: the base-2 exponent of the retransmission
 * ring size. The ring holds (65536 << depth) packets, i.e. 2^depth times the
 * 16-bit base buffer (65536), and the addressable NACK window is roughly half
 * the ring. Each step doubles the buffer:
 *
 *   depth  multiplier   ring packets   approx NACK window
 *     0       1x            65536            32768
 *     3       8x           524288           262144   (default, legacy behavior)
 *     6      64x          4194304          2097152
 *    16   65536x      4294967296       2147483648   (full 32-bit seq space)
 *
 * Simple/Main are inherently 16-bit and ignore this setting. */
#define RIST_RECOVERY_DEPTH_MIN     (0)
#define RIST_RECOVERY_DEPTH_DEFAULT (3)   /* 8x the 16-bit base = legacy default */
#define RIST_RECOVERY_DEPTH_MAX     (16)  /* full 32-bit sequence space */

struct rist_peer_config
{
	int version;

	/* Communication parameters */
	// If a value of 0 is specified for address family, the library
	// will parse the address and populate all communication parameters.
	// Alternatively, use either AF_INET or AF_INET6 and address will be
	// treated like an IP address or hostname
	int address_family;
	int initiate_conn;
	char address[RIST_MAX_STRING_LONG];
	char miface[RIST_MAX_STRING_SHORT];
	uint16_t physical_port;

	/* The virtual destination port is not used for simple profile */
	uint16_t virt_dst_port;

	/* Recovery options */
	enum rist_recovery_mode recovery_mode;
	/* Ceiling on payload plus retransmissions, not on payload alone. 0 means
	 * unset, not unlimited, and is replaced with the default. */
	uint32_t recovery_maxbitrate; /* kbps */
	uint32_t recovery_maxbitrate_return; /* kbps */
	uint32_t recovery_length_min; /* ms */
	uint32_t recovery_length_max; /* ms */
	uint32_t recovery_reorder_buffer; /* ms */
	uint32_t recovery_rtt_min; /* ms */
	uint32_t recovery_rtt_max; /* ms */

	/* Load balancing weight (use RIST_PEER_WEIGHT_DUPLICATE for duplication) */
	uint32_t weight;

	/* Encryption */
	char secret[RIST_MAX_STRING_SHORT];
	int key_size;
	uint32_t key_rotation;

	/* Compression (sender only as receiver is auto detect) */
	int compression;

	/* cname identifier for rtcp packets */
	char cname[RIST_MAX_STRING_SHORT];

	/* Congestion control */
	enum rist_congestion_control_mode congestion_control_mode;
	uint32_t min_retries;
	uint32_t max_retries;

	/* Connection options */
	uint32_t session_timeout;
	uint32_t keepalive_interval;
	enum rist_timing_mode timing_mode;
	char srp_username[RIST_MAX_STRING_LONG];
	char srp_password[RIST_MAX_STRING_LONG];

	uint32_t split_mode;      /* enum librist_split_mode (sender) */
	uint32_t merge_mode;      /* enum librist_merge_mode (receiver) */

	/* Reflector mode: when enabled on a receiver listener, incoming data
	 * packets are transparently forwarded to all other connected peers
	 * (one-to-many fan-out).  Disabled by default; enable via URL parameter
	 * ?reflector=1.  Main Profile only.
	 *
	 * Trade-offs vs rist2rist (per-subscriber ARQ relay):
	 * - No per-subscriber retry buffer: the reflector does not cache
	 *   data; retransmissions rely entirely on the publisher's buffer.
	 * - Retransmissions fan out to ALL subscribers, not just the one
	 *   that NACKed — bandwidth cost scales with subscriber count.
	 * - Recovery RTT ~ RTT(sub<->reflector) + RTT(reflector<->pub),
	 *   roughly 2x a direct connection.
	 * - No per-subscriber congestion control or stats: all NACKs
	 *   appear to the publisher as coming from a single peer.
	 *
	 * Best suited for low subscriber counts with clean last-mile links.
	 * For high fan-out, lossy last-mile, or per-subscriber buffer
	 * tuning, use rist2rist instead. */
	int reflector;

	/* Multicast TTL / hop limit (0 = platform default, typically 1) */
	uint32_t multicast_ttl;

	/* SSM source address for IGMPv3 source-specific multicast (empty = ASM) */
	char multicast_source[RIST_MAX_STRING_LONG];

	/* Local UDP port for caller (non-listening) peers.
	 * 0 = ephemeral (OS-assigned), non-zero = bind to this port.
	 * Not all platforms support binding caller sockets to a fixed port. */
	uint16_t local_port;

	int srp_compat_legacy;    /* 0 = RFC 5054 PAD (default), 1 = pre-0.2.16 unpadded */

	/* Wire profile parsed from ?profile=.  Test profile_set first:
	 * profile == RIST_PROFILE_SIMPLE on a zero-initialised config is
	 * indistinguishable from "value not provided". */
	enum rist_profile profile;
	int profile_set;

	/* Retransmission (NACK) routing preference for the receiver.
	 * When a flow is carried by more than one RTCP-capable peer, the
	 * receiver sends each NACK to the eligible peer with the highest
	 * recovery_priority (ties broken by lowest measured RTT).  0
	 * (default) preserves the legacy behaviour of selecting the
	 * lowest-RTT eligible peer regardless of priority.  Set this >0 on
	 * the peer that holds the retransmission buffer when a lower-RTT
	 * peer carrying the same flow cannot answer NACKs (e.g. a
	 * duplicate/relay feed with no retransmit cache). */
	uint32_t recovery_priority;

	/* Advanced-profile recovery depth (?recovery-depth= URL knob): base-2
	 * exponent of the retransmission ring size, RIST_RECOVERY_DEPTH_MIN..MAX.
	 * Defaults to RIST_RECOVERY_DEPTH_DEFAULT. Only meaningful on the Advanced
	 * profile and only before rist_start(). Version 5+. */
	uint8_t recovery_depth;

	/* Dynamic RTT-based bonded-leg muting (sender, Version 6+). A leg whose
	 * smoothed RTT holds above rtt_drop for rtt_drop_settle is pulled from the
	 * payload rotation (retransmits reroute to a healthy leg) and rejoins once
	 * it holds below rtt_restore for a longer dwell (quick to drop, slow to
	 * rejoin). The last healthy leg is never muted. All ms; 0 disables. */
	uint32_t rtt_drop;         /* smoothed-RTT ceiling; 0 = disabled */
	uint32_t rtt_restore;      /* restore low-water; 0 = derive as 80% of rtt_drop */
	uint32_t rtt_drop_settle;  /* dwell before muting (rejoin waits longer) */
	uint32_t rtt_drop_trickle; /* 1-in-N redundant duplicate on a muted leg; 0 = hard mute */
};

/**
 * @brief Populate a preallocated peer_config structure with library default values (versioned)
 *
 * @return 0 on success or non-zero on error.
 */
RIST_API int rist_peer_config_defaults_set_versioned(struct rist_peer_config *peer_config, int version);

/**
 * @brief Populate a preallocated peer_config structure with library default values
 *
 * @return 0 on success or non-zero on error.
 */
#ifdef LIBRIST_INTERNAL
RIST_API int rist_peer_config_defaults_set(struct rist_peer_config *peer_config);
#else
#if defined(__cplusplus) || (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L)
static inline int rist_peer_config_defaults_set(struct rist_peer_config *peer_config) {
	return rist_peer_config_defaults_set_versioned(peer_config, RIST_PEER_CONFIG_VERSION);
}
#else
#define rist_peer_config_defaults_set(peer_config) \
	rist_peer_config_defaults_set_versioned((peer_config), RIST_PEER_CONFIG_VERSION)
#endif
#endif

/**
 * @brief Parses rist url for peer config data (encryption, compression, etc)
 *
 * Use this API to parse a generic URL string and turn it into a meaninful peer_config structure
 *
 * @param url a pointer to a url to be parsed, i.e. rist://myserver.net:1234?buffer=100&cname=hello
 * @param[out] peer_config a pointer to a the rist_peer_config structure (NULL is allowed).
 * When passing NULL, the library will allocate a new rist_peer_config structure with the latest
 * default values and it expects the application to free it when it is done using it.
 * @return 0 on success or non-zero on error. The value returned is actually the number
 * of parameters that are valid
 */
RIST_DEPRECATED RIST_API int rist_parse_address(const char *url, const struct rist_peer_config **peer_config);
RIST_API int rist_parse_address2(const char *url, struct rist_peer_config **peer_config);

/**
 * @brief Free the rist_peer_config structure memory allocation
 *
 * @return 0 on success or non-zero on error.
 */
RIST_DEPRECATED RIST_API int rist_peer_config_free(const struct rist_peer_config **peer_config);
RIST_API int rist_peer_config_free2(struct rist_peer_config **peer_config);

/**
 * @brief Add a peer to the RIST session
 *
 * One sender can send data to multiple peers.
 *
 * If config->profile_set is non-zero (version >= 4), the call may
 * change the context wire profile to config->profile when invoked
 * before rist_start() and before any other peer has fixed it.  Once
 * fixed, any later call whose ?profile= disagrees returns -1.
 *
 * @param ctx RIST context
 * @param[out] peer Store the new peer pointer
 * @param config a pointer to the struct rist_peer_config, which contains
 *        the configuration parameters for the peer endpoint.
 * @return 0 on success, -1 in case of error.
 */
RIST_API int rist_peer_create(struct rist_ctx *ctx,
		struct rist_peer **peer, const struct rist_peer_config *config);

/**
 * @brief Removes a peer from the RIST session.
 *
 * @param ctx RIST context
 * @param peer a pointer to the struct rist_peer, which
 *        points to the peer endpoint.
 * @return 0 on success, -1 in case of error.
 */
RIST_API int rist_peer_destroy(struct rist_ctx *ctx,
		struct rist_peer *peer);

/**
 * @brief Set the weight of a given peer.
 *
 * @param ctx RIST context
 * @param peer The peer to set the weight for
 * @param weight The weight to assign to the peer
 * @return 0 on success, -1 in case of error.
 */
RIST_API int rist_peer_weight_set(struct rist_ctx *ctx, struct rist_peer *peer, const uint32_t weight);

RIST_API int rist_peer_get_socket(struct rist_peer *peer, int *socket, int *socket_extra);

enum rist_connection_status
{
	RIST_CONNECTION_ESTABLISHED = 0,
	RIST_CONNECTION_TIMED_OUT = 1,
	RIST_CLIENT_CONNECTED = 2,
	RIST_CLIENT_TIMED_OUT = 3
};

/**
 * @brief Connection status callback function
 *
 * Optional calling application provided function for receiving connection status changes for peers.
 *
 * @param arg optional user data set via rist_connection_status_callback_set
 * @param peer peer associated with the event
 * @param rist_peer_connection_status status value
 * @return void.
 */
typedef void (*connection_status_callback_t)(void *arg, struct rist_peer *peer, enum rist_connection_status peer_connection_status);

/**
 * @brief Set callback for receiving connection status change events
 *
 * @param ctx RIST context
 * @param connection_status_callback_t Callback function that will be called.
 * @param arg extra arguments for callback function
 */
RIST_API int rist_connection_status_callback_set(struct rist_ctx *ctx, connection_status_callback_t, void *arg);

typedef int (*rist_auth_handler_connect_cb)(void *arg, const char* conn_ip, uint16_t conn_port, const char* local_ip, uint16_t local_port,struct rist_peer *peer);
typedef int (*rist_auth_handler_disconnect_cb)(void *arg, struct rist_peer *peer);

/*
 * Called once after a peer completes EAP-SRP authentication. The username is
 * owned by libRIST and is valid only for the duration of this callback.
 * Applications can use this to bind their authenticated principal to peer.
 */
typedef void (*rist_srp_auth_callback_t)(void *arg, struct rist_peer *peer,
		const char *username);

/**
 * @brief Assign dynamic authentication handler
 *
 * Whenever a new peer is connected, @a connect_cb is called.
 * Whenever a new peer is disconnected, @a disconn_cb is called.
 *
 * @param ctx RIST context
 * @param connect_cb A pointer to the function that will be called when a new peer
 * connects. Return 0 or -1 to authorize or decline (NULL function pointer is valid)
 * @param disconn_cb A pointer to the function that will be called when a new peer
 * is marked as dead (NULL function pointer is valid)
 * @param arg is an the extra argument passed to the `conn_cb` and `disconn_cb`
 */
RIST_API int rist_auth_handler_set(struct rist_ctx *ctx,
		rist_auth_handler_connect_cb connect_cb,
		rist_auth_handler_disconnect_cb disconnect_cb,
		void *arg);

/** Set the callback invoked after EAP-SRP authentication succeeds. */
RIST_API int rist_srp_auth_callback_set(struct rist_ctx *ctx,
		rist_srp_auth_callback_t callback, void *arg);


RIST_API uint32_t rist_peer_get_id(const struct rist_peer *peer);

/**
 * @brief Retrieve the cname associated to a peer (if any)
 *
 * @param peer The peer to extract the cname from
 * @param[out] cname a pointer to the string containing the cname
 * @return the length of the cname string
 */
RIST_API uint32_t rist_peer_get_cname(const struct rist_peer *peer, const char **cname);

#if HAVE_SRP_SUPPORT
/*
	@brief Update the shared passphrase for the peer
*/
RIST_API int rist_peer_update_secret(struct rist_peer *peer, const char* password);
#endif
#ifdef __cplusplus
}
#endif

#endif /* LIBRIST_PEER_H */
