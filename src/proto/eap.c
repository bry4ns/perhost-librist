/* librist. Copyright © 2020 SipRadius LLC. All right reserved.
 * Author: Gijs Peskens <gijs@in2ip.nl>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "eap.h"
#include "common/attributes.h"
#include "config.h"
#include "crypto/psk.h"
#include "crypto/eap_v4_crypto.h"
#include "endian-shim.h"
#include "crypto/crypto-private.h"
#include "crypto/srp.h"
#include "crypto/srp_constants.h"
#include "librist_srp.h"
#include "rist-private.h"
#include "udp-private.h"
#include "transport-private.h"
#include "log-private.h"
#include "proto/rist_time.h"
#include "peer.h"
#include "protocol_gre.h"

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <limits.h>
#include <inttypes.h>

#define HASH_ALGO SRP_SHA256
#define DIGEST_LENGTH SHA256_DIGEST_LENGTH
#define EAP_LOG_PREFIX "[EAP-SRP] "
#define EAP_AUTH_RETRY_MAX 3
#define EAP_AUTH_TIMEOUT_RETRY_MAX 5
#define EAP_AUTH_TIMEOUT 500//ms
#define EAP_REAUTH_PERIOD 60000 // ms
#define EAP_AUTH_FAILED_RECOVERY 30000 // ms, soft-FAILED -> UNAUTH after this quiet
#define EAP_IDENTITY_REPLY_INTERVAL 200 // ms, rate-limit pre-auth IDENTITY replies
#define EAP_SRP_OP_INTERVAL 200 // ms, rate-limit pre-auth SRP modexp operations
#define EAP_REAUTH_PROBE_MAX 2000 // ms, forget a stale authenticated-side identity-request probe after this gap
#define EAP_MAX_MODULUS_BYTES 1024 // largest RFC 5054 group (NG_8192) is 1024 bytes

/* Permanent-failure sentinel for ctx->tries; fixed point under eap_tries_inc(). */
#define EAP_AUTH_TRIES_PERMANENT UINT_MAX

/* v4 (AES-256-GCM passphrase channel) needs a real crypto backend; else stay v3. */
#if HAVE_MBEDTLS || HAVE_NETTLE
#define EAP_V4_GCM_AVAILABLE 1
#else
#define EAP_V4_GCM_AVAILABLE 0
#endif
/* Highest EAP version we originate; -DEAP_VERSION_MAX=3 forces a v3 peer for interop. */
#ifndef EAP_VERSION_MAX
#define EAP_VERSION_MAX (EAP_V4_GCM_AVAILABLE ? 4 : 3)
#endif
#define EAP_V4_NONCE_LEN 12
#define EAP_V4_TAG_LEN 16
#define EAP_V4_AAD_LEN (5 + EAP_V4_NONCE_LEN)
/* Max v4 plaintext in one EAPOL frame; the send bound and receive buffer share it. */
#define EAP_V4_MAX_PLAINTEXT (1500 - (EAPOL_EAP_HDRS_OFFSET + sizeof(struct eap_srp_hdr) + 1 + EAP_V4_NONCE_LEN + EAP_V4_TAG_LEN))

static int eap_request_passphrase(struct eapsrp_ctx *ctx, bool start);

struct eapsrp_ctx
{
	pthread_mutex_t eap_lock;
	struct {
		char username[256];
		char password[256];
		user_verifier_lookup_t lookup_func_old;
		user_verifier_lookup_2_t lookup_func;
		void *lookup_func_userdata_old;
		void *lookup_func_userdata;
        struct rist_logging_settings *logging_settings;
        bool use_key_as_passphrase;
        uint8_t role;
    } config;

    int authentication_state;
    uint8_t last_identifier;
    unsigned int tries;
    bool may_rollover_passphrase;
    bool did_first_auth;

    uint64_t failed_state_timestamp; /* 0 = not in soft-FAILED */
    uint64_t last_identity_reply_timestamp; /* rate-limit pre-auth IDENTITY replies */
    uint64_t last_srp_op_timestamp; /* rate-limit pre-auth SRP modexp operations */

    /* Authenticatee-only bounded EAPOL START retransmit; 0 = idle. */
    uint64_t authee_start_timer;
    int authee_start_tries;

    /* Authenticatee-only: start of the current run of identity requests seen
     * while already authenticated; 0 = none in progress. Gates re-auth after
     * an authenticator restart without honoring a lone forged reset packet. */
    uint64_t reauth_probe_timer;

    uint64_t passphrase_request_timer;
    int passphrase_request_times;
    uint8_t passphrase_request_identifier;

    uint64_t unsollicited_passphrase_response_timer;
    int unsollicited_passphrase_response_times;
    uint8_t unsollicited_passphrase_response_identifier;
    uint8_t unsollicited_passphrase[128];
    size_t unsollicited_passphrase_len;
    int unsollicited_passphrase_state;

    uint8_t *last_pkt;
    size_t last_pkt_size;
    uint8_t timeout_retries;
    uint64_t last_timestamp;
    uint64_t last_auth_timestamp;

    uint64_t generation;
    struct librist_crypto_srp_authenticator_ctx *auth_ctx;
    struct librist_crypto_srp_client_ctx *client_ctx;
    bool authenticated;

    struct rist_peer *peer;
    char ip_string[46];

    // authenticator data (single user mode) this doesn't need to be in config &
    // cloned because the lookup function keeps a pointer to the original
    // eap_ctx
    char authenticator_username[256];
#if HAVE_MBEDTLS
	size_t authenticator_len_verifier_old;
	uint8_t *authenticator_bytes_verifier_old;
	size_t authenticator_len_salt_old;
	uint8_t *authenticator_bytes_salt_old;
#endif
	size_t authenticator_len_verifier;
	uint8_t *authenticator_bytes_verifier;
	size_t authenticator_len_salt;
	uint8_t *authenticator_bytes_salt;

	bool eapversion3;//EAPv3 signalled. old libRIST used v2, so use this to ensure compat with broken hashing

	bool srp_legacy_pad;         //srp-compat=1 URL opt-in
	bool srp_legacy_peer_warned; //one-shot latch for the M1/M2 hint

	/* EAP v4 (AEAD passphrase channel) state. */
	uint8_t peer_eap_version;                 //highest EAP version the peer has advertised
	uint64_t tx_nonce_counter;                //next 96-bit GCM nonce to assign for our send direction
	uint64_t unsollicited_passphrase_nonce;   //cached nonce for the unsolicited push (stable across retransmits)
	uint64_t rx_last_nonce;                   //highest v4 nonce accepted from the peer (this direction)
	bool rx_nonce_seen;                       //whether rx_last_nonce is valid yet
};

static inline void eap_tries_inc(struct eapsrp_ctx *ctx)
{
	/* Saturating: stays parked at EAP_AUTH_TRIES_PERMANENT instead of wrapping. */
	if (ctx->tries < EAP_AUTH_TRIES_PERMANENT)
		ctx->tries++;
}

/* v2 for a legacy session, else the highest we support. A v3 peer reads a
 * v4-tagged packet as v3 (checks only >= 3), so advertising 4 is safe. */
static inline uint8_t eap_tx_version(struct eapsrp_ctx *ctx)
{
	if (!ctx->eapversion3)
		return 2;
	return (uint8_t)EAP_VERSION_MAX;
}

/* Print a wire-supplied username safely: replace anything outside
 * printable ASCII so CR/LF can't forge log lines. */
static const char *eap_sanitize_log(const char *in, char *buf, size_t buflen)
{
	size_t i;
	for (i = 0; i + 1 < buflen && in[i]; i++) {
		char c = in[i];
		buf[i] = (c >= 32 && c < 127) ? c : '?';
	}
	buf[i] = '\0';
	return buf;
}

/* Both ends can run v4: we originate it, the session is v3-hashed, and the peer
 * advertised >= 4. Version is negotiated in the clear (outside the SRP proof),
 * so a MITM can force a v3 downgrade -- integrity, not confidentiality. */
static inline bool eap_use_v4(struct eapsrp_ctx *ctx)
{
	return EAP_VERSION_MAX >= 4 && ctx->eapversion3 && ctx->peer_eap_version >= 4;
}

/* Per-direction v4 key from K via HKDF-Expand-SHA256; the label separates the
 * two directions so they never share a (key, nonce) pair. */
static int eap_v4_dir_key(struct eapsrp_ctx *ctx, bool client_to_server, uint8_t out[32])
{
	const uint8_t *K = (ctx->config.role == EAP_ROLE_AUTHENTICATOR)
		? librist_crypto_srp_authenticator_get_key(ctx->auth_ctx)
		: librist_crypto_srp_client_get_key(ctx->client_ctx);
	if (K == NULL)
		return -1;
	const char *label = client_to_server ? "RIST-EAP-v4 pass c2s" : "RIST-EAP-v4 pass s2c";
	return _librist_crypto_hkdf_expand_sha256(K, SHA256_DIGEST_LENGTH,
		(const uint8_t *)label, strlen(label), out, 32);
}

/* AAD binds the wire-carried fields (identifier, flags, nonce). code/type/subtype
 * are fixed constants pinned by both ends, so they frame the tag, not detect edits. */
static void eap_v4_build_aad(uint8_t aad[EAP_V4_AAD_LEN], uint8_t identifier,
                             uint8_t flags, const uint8_t nonce[EAP_V4_NONCE_LEN])
{
	aad[0] = EAP_CODE_RESPONSE;
	aad[1] = identifier;
	aad[2] = EAP_TYPE_SRP_SHA1;
	aad[3] = EAP_SRP_SUBTYPE_PASSWORD_REQUEST_RESPONSE;
	aad[4] = flags;
	memcpy(&aad[5], nonce, EAP_V4_NONCE_LEN);
}

static void eap_v4_encode_nonce(uint64_t counter, uint8_t nonce[EAP_V4_NONCE_LEN])
{
	memset(nonce, 0, EAP_V4_NONCE_LEN); //top 4 octets stay zero
	for (int i = 0; i < 8; i++)
		nonce[EAP_V4_NONCE_LEN - 1 - i] = (uint8_t)(counter >> (8 * i));
}

static uint64_t eap_v4_decode_nonce(const uint8_t nonce[EAP_V4_NONCE_LEN])
{
	uint64_t v = 0;
	for (int i = 0; i < 8; i++)
		v = (v << 8) | nonce[EAP_V4_NONCE_LEN - 8 + i];
	return v;
}

void eap_reset_data(struct eapsrp_ctx *ctx)
{
	if (ctx->config.role == EAP_ROLE_AUTHENTICATOR)
	{
#if HAVE_MBEDTLS
		free(ctx->authenticator_bytes_salt_old);
		free(ctx->authenticator_bytes_verifier_old);
		ctx->authenticator_bytes_salt_old = NULL;
		ctx->authenticator_bytes_verifier_old = NULL;
#endif
		free(ctx->authenticator_bytes_salt);
		free(ctx->authenticator_bytes_verifier);
		ctx->authenticator_bytes_salt = NULL;
		ctx->authenticator_bytes_verifier = NULL;
	}
	librist_crypto_srp_authenticator_ctx_free(ctx->auth_ctx);
	ctx->auth_ctx = NULL;
	librist_crypto_srp_client_ctx_free(ctx->client_ctx);
	ctx->client_ctx = NULL;
	free(ctx->last_pkt);

	ctx->last_pkt = NULL;

	ctx->authenticated = false;

	/* Re-auth derives a fresh K, so restart the v4 nonce space; the new epoch
	 * re-baselines rx_last_nonce (else a re-authing ctx rejects the peer's
	 * restarted nonces despite a valid tag). */
	ctx->tx_nonce_counter = 0;
	ctx->rx_last_nonce = 0;
	ctx->rx_nonce_seen = false;

	/* Drop any armed unsolicited-passphrase retransmit: it caches the old
	 * epoch's plaintext and nonce, and resending it under the new K would
	 * reuse that nonce value once the restarted counter catches up -- the
	 * GCM forbidden state. The app layer can re-push after re-auth. */
	ctx->unsollicited_passphrase_response_timer = 0;
	ctx->unsollicited_passphrase_response_times = 0;
	ctx->unsollicited_passphrase_state = 0;
}

static int send_eapol_pkt(struct eapsrp_ctx *ctx, uint8_t eapoltype, uint8_t eapcode, uint8_t identifier, size_t payload_len, uint8_t buf[], uint8_t eap_version)
{
	size_t offset = 0;
	struct eapol_hdr *eapol_hdr = (struct eapol_hdr *)&buf[offset];
	offset += sizeof(*eapol_hdr);
	struct eap_hdr *eap_hdr = (struct eap_hdr *)&buf[offset];
	offset += sizeof(*eap_hdr);
	eapol_hdr->eapversion = eap_version;
	eapol_hdr->eaptype = eapoltype;
	eap_hdr->code = eapcode;
	eap_hdr->identifier = identifier;
	eapol_hdr->length = eap_hdr->length = htobe16(payload_len + sizeof(*eap_hdr));

	//Store last pkt so we can retransmit it if needed
	if (identifier == ctx->last_identifier)
	{
		free(ctx->last_pkt);
		ctx->last_pkt = malloc((payload_len + EAPOL_EAP_HDRS_OFFSET));
		if (ctx->last_pkt == NULL) {
			// OOM: skip caching the retransmit copy
			ctx->last_pkt_size = 0;
		} else {
			memcpy(ctx->last_pkt, buf, (payload_len + EAPOL_EAP_HDRS_OFFSET));
			ctx->last_pkt_size = (payload_len + EAPOL_EAP_HDRS_OFFSET);
			ctx->last_timestamp = timestampNTP_u64();
			ctx->timeout_retries = 0;
		}
	}
	if (_librist_proto_gre_send_data(ctx->peer, 0, RIST_GRE_PROTOCOL_TYPE_EAPOL, buf, (EAPOL_EAP_HDRS_OFFSET + payload_len), 0, 0, ctx->peer->rist_gre_version) < 0)
		return -1;

	return 0;
}


//EAP REQUEST HANDLING
static int process_eap_request_identity(struct eapsrp_ctx *ctx, uint8_t identifier)
{
	if (ctx->config.role == EAP_ROLE_AUTHENTICATOR)
		return EAP_UNEXPECTEDREQUEST;
	uint64_t now = timestampNTP_u64();
	/* An identity request while authenticated is either a forged reset or a sign
	 * the authenticator lost our session; we can't tell on the wire. Don't tear
	 * down inline (a lone forged packet must not): arm reauth_probe_timer and
	 * keep refusing, letting eap_periodic_impl drive one bounded re-auth if it
	 * persists. */
	if (ctx->authentication_state >= EAP_AUTH_STATE_SUCCESS) {
		if (ctx->reauth_probe_timer == 0 ||
		    now - ctx->reauth_probe_timer > (uint64_t)EAP_REAUTH_PROBE_MAX * RIST_CLOCK)
			ctx->reauth_probe_timer = now;
		return EAP_UNEXPECTEDREQUEST;
	}
	/* Rate-limit pre-auth replies (caps username echo + eap_reset_data work). */
	if (ctx->last_identity_reply_timestamp != 0 &&
	    now < ctx->last_identity_reply_timestamp + (uint64_t)EAP_IDENTITY_REPLY_INTERVAL * RIST_CLOCK) {
		rist_log_priv2(ctx->config.logging_settings, RIST_LOG_DEBUG,
			EAP_LOG_PREFIX"Rate-limiting EAP IDENTITY response (last sent %u ms ago)\n",
			(unsigned)((now - ctx->last_identity_reply_timestamp) / RIST_CLOCK));
		return 0;
	}
	ctx->last_identity_reply_timestamp = now;
	eap_reset_data(ctx);
	uint8_t eapolpkt[512];
	size_t offset = EAPOL_EAP_HDRS_OFFSET;
	eapolpkt[offset] = EAP_TYPE_IDENTITY;
	offset += 1;
	memcpy(&eapolpkt[offset], ctx->config.username, strlen(ctx->config.username));
	offset += strlen(ctx->config.username);
	size_t len = offset;
	len -= EAPOL_EAP_HDRS_OFFSET;
	return send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_RESPONSE, identifier, len, eapolpkt, eap_tx_version(ctx));
}

static int process_eap_request_srp_challenge(struct eapsrp_ctx *ctx, uint8_t identifier, size_t len, uint8_t pkt[], uint8_t eap_version)
{
	if (len < 6)
		return EAP_LENERR;

	/* Rate-limit: each challenge costs a full client-side modexp (g^a) and
	 * the packet is forgeable pre-auth. */
	uint64_t now = timestampNTP_u64();
	if (ctx->last_srp_op_timestamp != 0 &&
	    now < ctx->last_srp_op_timestamp + (uint64_t)EAP_SRP_OP_INTERVAL * RIST_CLOCK)
		return 0;
	ctx->last_srp_op_timestamp = now;

#if HAVE_MBEDTLS
	ctx->eapversion3 = (eap_version >= 3);
#elif HAVE_NETTLE
	(void)(eap_version);
#endif
	// each TLV is prefixed with a 2-byte big-endian length, account for it
	size_t offset = 0;
	if (offset + 2 > len)
		return EAP_LENERR;
	uint16_t *tmp_swap = (uint16_t *)&pkt[offset];
	size_t name_len = be16toh(*tmp_swap);
	offset += 2;
	//name can be ignored
	if (name_len > len - offset)
		return EAP_LENERR;
	offset += name_len;
	if (offset + 2 > len)
		return EAP_LENERR;
	tmp_swap = (uint16_t *)&pkt[offset];
	size_t salt_len = be16toh(*tmp_swap);
	offset += 2;
	if (salt_len > len - offset)
		return EAP_LENERR;

	uint8_t *salt = &pkt[offset];
	uint8_t *g = NULL;
	uint8_t *N = NULL;
	size_t N_len = 0;
	offset += salt_len;
	if (offset + 2 > len)
		return EAP_LENERR;
	tmp_swap = (uint16_t *)&pkt[offset];
	size_t generator_len = be16toh(*tmp_swap);
	offset += 2;
	if (generator_len != 0)
	{
		if (generator_len > len - offset)
			return EAP_LENERR;
		if (generator_len > EAP_MAX_MODULUS_BYTES)
			return EAP_LENERR;

		g = &pkt[offset];
		offset += generator_len;
		N = &pkt[offset];
		N_len = len - offset;
		if (N_len > EAP_MAX_MODULUS_BYTES)
			return EAP_LENERR;
	}
	bool use_default_ng = (generator_len == 0);
	librist_crypto_srp_client_ctx_free(ctx->client_ctx);
	ctx->client_ctx = librist_crypto_srp_client_ctx_create(use_default_ng, N, N_len, g, generator_len, salt, salt_len, ctx->eapversion3, ctx->srp_legacy_pad);
	if (ctx->client_ctx == NULL)
		return EAP_INTERNALERR;
	uint8_t response[1500] = {0};
	struct eap_srp_hdr *hdr = (struct eap_srp_hdr *)&response[EAPOL_EAP_HDRS_OFFSET];
	hdr->type = EAP_TYPE_SRP_SHA1;
	hdr->subtype = EAP_SRP_SUBTYPE_CHALLENGE;
	int len_A = librist_crypto_srp_client_write_A_bytes(ctx->client_ctx, &response[EAPOL_EAP_HDRS_OFFSET + sizeof(*hdr)], sizeof(response) -(EAPOL_EAP_HDRS_OFFSET + sizeof(*hdr)));
	if (len_A < 0)
		return -1;
	return send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_RESPONSE, identifier, ((size_t)len_A + sizeof(*hdr)), response, eap_tx_version(ctx));
}

static int process_eap_request_srp_server_key(struct eapsrp_ctx *ctx, uint8_t identifier, size_t len, uint8_t pkt[])
{
	if (!ctx->client_ctx)
	{
		/* No SRP client state: either no CHALLENGE was processed or the
		 * state was reset. A spoofed SERVER_KEY request must not reach
		 * the bignum layer with a NULL ctx. */
		ctx->authentication_state = EAP_AUTH_STATE_FAILED;
		return EAP_INTERNALERR;
	}
	if (librist_crypto_srp_client_handle_B(ctx->client_ctx, pkt, len, ctx->config.username, ctx->config.password) != 0)
	{
		ctx->authentication_state = EAP_AUTH_STATE_FAILED;
		//"must disconnect immediately, set tries past limit"
		ctx->tries = EAP_AUTH_TRIES_PERMANENT;
		return EAP_AUTH_TERMINATED;
	}
	size_t out_len = sizeof(struct eap_srp_hdr) + 4 + DIGEST_LENGTH;
	uint8_t response[(EAPOL_EAP_HDRS_OFFSET + sizeof(struct eap_srp_hdr) + 4 + DIGEST_LENGTH)];
	size_t offset = EAPOL_EAP_HDRS_OFFSET;
	struct eap_srp_hdr *hdr = (struct eap_srp_hdr *)&response[offset];
	offset += sizeof(*hdr);
	memset(&response[offset], 0, 4);
	offset += 4;
	hdr->type = EAP_TYPE_SRP_SHA1;
	hdr->subtype = EAP_SRP_SUBTYPE_SERVER_KEY;
	if (ctx->config.use_key_as_passphrase && ctx->eapversion3) {
		SET_BIT(response[(EAPOL_EAP_HDRS_OFFSET + sizeof(*hdr) + 3)], 0);
		librist_peer_update_tx_passphrase(ctx->peer, librist_crypto_srp_client_get_key(ctx->client_ctx), SHA256_DIGEST_LENGTH, !ctx->did_first_auth);
		ctx->did_first_auth = true;
	}
	librist_crypto_srp_client_write_M1_bytes(ctx->client_ctx, &response[offset]);
	int ret = send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_RESPONSE, identifier, out_len, response, eap_tx_version(ctx));
	return ret;
}

static int process_eap_request_srp_server_validator(struct eapsrp_ctx *ctx, uint8_t identifier, size_t len, uint8_t pkt[])
{
	if (len < (4 + DIGEST_LENGTH))
		return EAP_LENERR;
	if (!ctx->client_ctx)
	{
		ctx->authentication_state = EAP_AUTH_STATE_FAILED;
		return EAP_INTERNALERR;
	}
	if (librist_crypto_srp_client_verify_m2(ctx->client_ctx, &pkt[4]) == 0)
	{
		if (ctx->authentication_state < EAP_AUTH_STATE_SUCCESS)
			rist_log_priv2(ctx->config.logging_settings, RIST_LOG_INFO, EAP_LOG_PREFIX"Successfully authenticated\n");
		bool set_passphrase = CHECK_BIT(pkt[3], 0);
		if (set_passphrase && ctx->eapversion3) {
			librist_peer_update_rx_passphrase(ctx->peer, librist_crypto_srp_client_get_key(ctx->client_ctx), SHA256_DIGEST_LENGTH, !ctx->did_first_auth);
		}

		if (ctx->config.use_key_as_passphrase && ctx->eapversion3)
			ctx->may_rollover_passphrase = true;

		ctx->did_first_auth = true;
		ctx->authentication_state = EAP_AUTH_STATE_SUCCESS;
		ctx->last_auth_timestamp = timestampNTP_u64();
		ctx->tries = 0;
		ctx->failed_state_timestamp = 0;
		uint8_t outpkt[(EAPOL_EAP_HDRS_OFFSET + sizeof(struct eap_srp_hdr))] = {0};
		struct eap_srp_hdr *hdr = (struct eap_srp_hdr *)&outpkt[EAPOL_EAP_HDRS_OFFSET];
		if (ctx->eapversion3) {
			int ret = send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_SUCCESS, identifier, sizeof(*hdr), outpkt, eap_tx_version(ctx));
			eap_request_passphrase(ctx, true);
			return ret;
		}
		hdr->type = EAP_TYPE_SRP_SHA1;
		hdr->subtype = EAP_SRP_SUBTYPE_SERVER_VALIDATOR;
		return send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_RESPONSE, identifier, sizeof(*hdr), outpkt, eap_tx_version(ctx));
	}
	//perm failure
	rist_log_priv2(ctx->config.logging_settings, RIST_LOG_WARN,
		EAP_LOG_PREFIX"Server M2 verification failed for server@%s\n", ctx->ip_string);
	/* Advisory hint, latched: see srp-compat note in NEWS for v0.2.18. */
	if (!ctx->srp_legacy_peer_warned) {
		ctx->srp_legacy_peer_warned = true;
		if (ctx->srp_legacy_pad) {
			rist_log_priv2(ctx->config.logging_settings, RIST_LOG_INFO,
				EAP_LOG_PREFIX"  Hint: this side is configured with srp-compat=1. If the server is running librist 0.2.16+ (PAD-compliant, the default), drop ?srp-compat=1 on both sides.\n");
		} else {
			rist_log_priv2(ctx->config.logging_settings, RIST_LOG_INFO,
				EAP_LOG_PREFIX"  Hint: if the server is running librist 0.2.15 or earlier, the SRP wire format changed in 0.2.16 for RFC 5054 / TR-06-2 compliance. To interoperate with an older server, add ?srp-compat=1 on BOTH URLs. Otherwise check the password.\n");
		}
	}
	ctx->authentication_state = EAP_AUTH_STATE_FAILED;
	ctx->tries = EAP_AUTH_TRIES_PERMANENT;

	return -1;
}

/* Send an EAP SRP Passphrase Response: AES-256-GCM for v4 (per-direction key,
 * caller-supplied nonce, header as AAD), else the v3 AES-CTR form. The nonce is
 * used only on v4; reuse it verbatim when retransmitting identical plaintext. */
static int eap_srp_send_password(struct eapsrp_ctx *ctx, uint8_t identifier, const uint8_t *password, size_t password_len, uint64_t nonce) {
	bool v4 = (password_len > 0) && eap_use_v4(ctx);
	size_t overhead = EAPOL_EAP_HDRS_OFFSET + sizeof(struct eap_srp_hdr) + 1 +
		(v4 ? (EAP_V4_NONCE_LEN + EAP_V4_TAG_LEN) : 0);
	if (password_len > (1500 - overhead))
		return -1;
	uint8_t outpkt[1500] = {0};
	struct eap_srp_hdr *hdr = (struct eap_srp_hdr *)&outpkt[EAPOL_EAP_HDRS_OFFSET];
	hdr->type = EAP_TYPE_SRP_SHA1;
	hdr->subtype = EAP_SRP_SUBTYPE_PASSWORD_REQUEST_RESPONSE;
	uint8_t *flags = &outpkt[EAPOL_EAP_HDRS_OFFSET + sizeof(*hdr)];
	size_t payload_len;
	uint8_t send_version = eap_tx_version(ctx);
	if (password_len == 0) { //Use session key (U bit); no ciphertext either version
		SET_BIT(*flags, 7);
		payload_len = sizeof(*hdr) + 1;
	} else if (v4) {
		SET_BIT(*flags, 6); //H = 256-bit (reserved-1 in v4)
		uint8_t *noncep = flags + 1;
		uint8_t *ct = noncep + EAP_V4_NONCE_LEN;
		uint8_t *tag = ct + password_len;
		eap_v4_encode_nonce(nonce, noncep);
		uint8_t key[32];
		bool c2s = (ctx->config.role == EAP_ROLE_AUTHENTICATEE); //we send client->server
		if (eap_v4_dir_key(ctx, c2s, key) != 0)
			return -1;
		uint8_t aad[EAP_V4_AAD_LEN];
		eap_v4_build_aad(aad, identifier, *flags, noncep);
		int rc = _librist_crypto_aes_gcm_encrypt(key, noncep, EAP_V4_NONCE_LEN,
			aad, sizeof(aad), password, password_len, ct, tag, EAP_V4_TAG_LEN);
		_librist_crypto_secure_zero(key, sizeof(key));
		if (rc != 0) {
			rist_log_priv2(ctx->config.logging_settings, RIST_LOG_ERROR,
				EAP_LOG_PREFIX"v4 passphrase GCM encrypt failed\n");
			return -1;
		}
		payload_len = sizeof(*hdr) + 1 + EAP_V4_NONCE_LEN + password_len + EAP_V4_TAG_LEN;
		send_version = 4; //payload format must match the version byte
		rist_log_priv2(ctx->config.logging_settings, RIST_LOG_DEBUG,
			EAP_LOG_PREFIX"v4 passphrase sent under AES-256-GCM (nonce=%" PRIu64 ", %zu bytes)\n",
			nonce, password_len);
	} else { //v3 AES-CTR
		SET_BIT(*flags, 6); //aes_256
		const uint8_t *key = (ctx->config.role == EAP_ROLE_AUTHENTICATOR)
			? librist_crypto_srp_authenticator_get_key(ctx->auth_ctx)
			: librist_crypto_srp_client_get_key(ctx->client_ctx);
		uint8_t iv[AES_BLOCK_SIZE] = {0};
		iv[AES_BLOCK_SIZE-1] = identifier;
		_librist_crypto_aes_ctr(key, 256, iv, password, flags + 1, password_len);
		payload_len = sizeof(*hdr) + 1 + password_len;
		send_version = ctx->eapversion3 ? 3 : 2; //never tag a v3 payload as v4
	}
	return send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_RESPONSE, identifier, payload_len, outpkt, send_version);
}

static int process_eap_request_srp_passphrase(struct eapsrp_ctx *ctx, uint8_t identifier) {
	if (ctx->authentication_state == EAP_AUTH_STATE_SUCCESS) {
		if (ctx->config.use_key_as_passphrase)
			return eap_srp_send_password(ctx, identifier, NULL, 0, 0);

		const uint8_t *passphrase = NULL;
		size_t passphrase_len = 0;
		librist_peer_get_current_tx_passphrase(ctx->peer, &passphrase, &passphrase_len);
		/* Solicited response: fresh nonce per send. Same-plaintext-different-nonce
		 * is safe under GCM; this path is not self-retransmitted (the peer re-requests). */
		return eap_srp_send_password(ctx, identifier, passphrase, passphrase_len, ctx->tx_nonce_counter++);
	}

	uint8_t buf[EAPOL_EAP_HDRS_OFFSET];
	return send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_FAILURE, identifier, 0, buf, eap_tx_version(ctx));
}

static int process_eap_request(struct eapsrp_ctx *ctx, uint8_t pkt[], size_t len, uint8_t identifier, uint8_t eap_version)
{
	if (len < 1)
		return EAP_LENERR;
	uint8_t type = pkt[0];
	if (type == EAP_TYPE_IDENTITY)
		return process_eap_request_identity(ctx, identifier);
	if (type == EAP_TYPE_SRP_SHA1)
	{
		if (len < 2)
			return EAP_LENERR;
		uint8_t subtype = pkt[1];
		if (subtype != EAP_SRP_SUBTYPE_PASSWORD_REQUEST_RESPONSE && ctx->config.role == EAP_ROLE_AUTHENTICATOR)
			return EAP_UNEXPECTEDREQUEST;

		/* Record identifier for FAILURE matching only after validation
		 * passes.  Moving this out of the prologue prevents an
		 * unauthenticated spoofed REQUEST from priming last_identifier
		 * and defeating the FAILURE-identifier gate. */
		ctx->last_identifier = identifier;
		switch (subtype)
		{
			case EAP_SRP_SUBTYPE_CHALLENGE:
				return process_eap_request_srp_challenge(ctx, identifier, (len -2), &pkt[2], eap_version);
				break;
			case EAP_SRP_SUBTYPE_SERVER_KEY:
				return process_eap_request_srp_server_key(ctx, identifier, (len -2), &pkt[2]);
				break;
			case EAP_SRP_SUBTYPE_SERVER_VALIDATOR:
				return process_eap_request_srp_server_validator(ctx, identifier, (len -2), &pkt[2]);
				break;
			case EAP_SRP_SUBTYPE_LWRECHALLENGE:
				//handle SRP lw rechallenge
				break;
			case EAP_SRP_SUBTYPE_PASSWORD_REQUEST_RESPONSE:
				return process_eap_request_srp_passphrase(ctx, identifier);
				break;
			default:
				return EAP_SRP_WRONGSUBTYPE;
		}
	}
	return -1;
}

//EAP RESPONSE HANDLING

static int process_eap_response_identity(struct eapsrp_ctx *ctx, size_t len, uint8_t pkt[], uint8_t eap_version)
{
	if (len > 255)
		return -1;
	/* On the authenticatee side ctx->config.lookup_func is NULL (calloc'd
	 * in rist_enable_eap_srp_2 and never assigned for that role); refuse the
	 * IDENTITY response here so we don't deref it further down. */
	if (ctx->config.role != EAP_ROLE_AUTHENTICATOR || !ctx->config.lookup_func)
		return -1;
	memcpy(ctx->config.username, pkt, len);
	ctx->config.username[len] = '\0';
#if HAVE_MBEDTLS
	int hashversion = eap_version >= 3 ? 1 : 0;
#elif HAVE_NETTLE
	(void)eap_version;
	int hashversion = 1;
#endif
	uint64_t generation = 0;
	librist_verifier_lookup_data_t verifier_data = {0};
	ctx->config.lookup_func(ctx->config.username, &verifier_data, &hashversion, &generation, ctx->config.lookup_func_userdata);
#if HAVE_NETTLE
	if (hashversion == 0) {
		rist_log_priv2(ctx->config.logging_settings, RIST_LOG_ERROR, EAP_LOG_PREFIX"Lookup from SRP File got hashversion 0 response, Nettle backend does not support this, authentication likely to fail\n");
	}
	hashversion = 1;
#endif
	ctx->generation = generation;
	ctx->eapversion3 = (hashversion >= 1);
	const char *n_hex = verifier_data.n_modulus_ascii;
	const char *g_hex = verifier_data.generator_ascii;
	bool found = (verifier_data.verifier_len != 0 && verifier_data.verifier && verifier_data.salt_len != 0 && verifier_data.salt);
	uint8_t outpkt[1500] = { 0 };//TUNE THIS
	size_t offset = EAPOL_EAP_HDRS_OFFSET;
	struct eap_srp_hdr *hdr = (struct eap_srp_hdr *)&outpkt[offset];
	offset += sizeof(*hdr);
	hdr->type = EAP_TYPE_SRP_SHA1;
	hdr->subtype = EAP_SRP_SUBTYPE_CHALLENGE;
	int rc = -1;
	if (found)
	{
		struct librist_crypto_srp_authenticator_ctx *auth_ctx = NULL;
		if (verifier_data.default_ng)
			librist_get_ng_constants(LIBRIST_SRP_NG_DEFAULT, &n_hex, &g_hex);

		auth_ctx = librist_crypto_srp_authenticator_ctx_create(n_hex, g_hex, verifier_data.verifier, verifier_data.verifier_len, verifier_data.salt, verifier_data.salt_len, ctx->eapversion3, ctx->srp_legacy_pad);
		if (!auth_ctx)
			goto out;
		librist_crypto_srp_authenticator_ctx_free(ctx->auth_ctx);
		ctx->auth_ctx = auth_ctx;
		memset(&outpkt[offset], 0, 2);
		offset += 2;//we dont send the server name
		uint16_t *tmp_swap = (uint16_t *)&outpkt[offset];
		*tmp_swap = htobe16(verifier_data.salt_len);
		offset += 2;
		memcpy(&outpkt[offset], verifier_data.salt, verifier_data.salt_len);
		offset += verifier_data.salt_len;
		if (verifier_data.default_ng)
		{
			memset(&outpkt[offset], 0, 2);
			offset += 2;
		} else {
			tmp_swap = (uint16_t *)&outpkt[offset];
			offset += 2;
			int g_size = librist_crypto_srp_authenticator_write_g_bytes(auth_ctx, &outpkt[offset], sizeof(outpkt) -offset);
			if (g_size < 0)
				goto out;
			*tmp_swap = htobe16(g_size);
			offset += g_size;

			int n_len = librist_crypto_srp_authenticator_write_n_bytes(auth_ctx, &outpkt[offset], sizeof(outpkt) -offset);
			if (n_len < 0)
				goto out;
			offset += n_len;
		}
		ctx->last_identifier++;
		size_t out_len = offset - EAPOL_EAP_HDRS_OFFSET;
		rc = send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_REQUEST, ctx->last_identifier, out_len, outpkt, eap_tx_version(ctx));
	}
out:
	free(verifier_data.verifier);
	free(verifier_data.salt);
	free(verifier_data.generator_ascii);
	free(verifier_data.n_modulus_ascii);
	return rc;
}

static int process_eap_response_client_key(struct eapsrp_ctx *ctx, size_t len, uint8_t pkt[])
{
	if (!ctx->auth_ctx) {
		ctx->authentication_state = EAP_AUTH_STATE_FAILED;
		return EAP_INTERNALERR;
	}

	/* Rate-limit: each client key costs a full server-side modexp
	 * (B = kv + g^b) and the packet is forgeable pre-auth. */
	uint64_t now = timestampNTP_u64();
	if (ctx->last_srp_op_timestamp != 0 &&
	    now < ctx->last_srp_op_timestamp + (uint64_t)EAP_SRP_OP_INTERVAL * RIST_CLOCK)
		return 0;
	ctx->last_srp_op_timestamp = now;

	if (librist_crypto_srp_authenticator_handle_A(ctx->auth_ctx, pkt, len) != 0) {
		ctx->authentication_state = EAP_AUTH_STATE_FAILED;
		ctx->tries = EAP_AUTH_TRIES_PERMANENT;
		return EAP_AUTH_TERMINATED;
	}

	uint8_t outpkt[1500];
	struct eap_srp_hdr *hdr = (struct eap_srp_hdr *)&outpkt[EAPOL_EAP_HDRS_OFFSET];
	hdr->type = EAP_TYPE_SRP_SHA1;
	hdr->subtype = EAP_SRP_SUBTYPE_SERVER_KEY;
	int len_B = librist_crypto_srp_authenticator_write_B_bytes(ctx->auth_ctx, &outpkt[(EAPOL_EAP_HDRS_OFFSET + sizeof(*hdr))], sizeof(outpkt) - (EAPOL_EAP_HDRS_OFFSET + sizeof(*hdr)));
	if (len_B < 0)
		return -1;
	ctx->last_identifier++;
	return send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_REQUEST, ctx->last_identifier, (sizeof(struct eap_srp_hdr) + (size_t)len_B), outpkt, eap_tx_version(ctx));
}

static int process_eap_response_client_validator(struct eapsrp_ctx *ctx, size_t len, uint8_t pkt[])
{
	if (len < (4 + DIGEST_LENGTH))
		return EAP_LENERR;

	if (!ctx->auth_ctx) {
		ctx->authentication_state = EAP_AUTH_STATE_FAILED;
		return EAP_INTERNALERR;
	}

	if (librist_crypto_srp_authenticator_verify_m1(ctx->auth_ctx, ctx->config.username, &pkt[4]) != 0) {
		char ubuf[256];
		rist_log_priv2(ctx->config.logging_settings, RIST_LOG_WARN, EAP_LOG_PREFIX"Authentication failed for %s@%s\n", eap_sanitize_log(ctx->config.username, ubuf, sizeof(ubuf)), ctx->ip_string);
		/* Advisory hint, latched: see srp-compat note in NEWS for v0.2.18. */
		if (!ctx->srp_legacy_peer_warned) {
			ctx->srp_legacy_peer_warned = true;
			if (ctx->srp_legacy_pad) {
				rist_log_priv2(ctx->config.logging_settings, RIST_LOG_INFO,
					EAP_LOG_PREFIX"  Hint: this side is configured with srp-compat=1. If %s is running librist 0.2.16+ (PAD-compliant, the default), drop ?srp-compat=1 on both sides.\n",
					ctx->ip_string);
			} else {
				rist_log_priv2(ctx->config.logging_settings, RIST_LOG_INFO,
					EAP_LOG_PREFIX"  Hint: if %s is running librist 0.2.15 or earlier, the SRP wire format changed in 0.2.16 for RFC 5054 / TR-06-2 compliance. To interoperate with an older peer, add ?srp-compat=1 on BOTH URLs. Otherwise check the password.\n",
					ctx->ip_string);
			}
		}
		ctx->authentication_state = EAP_AUTH_STATE_FAILED;
		eap_tries_inc(ctx);
		int ret = EAP_AUTH_FAILED;
		if (ctx->tries > EAP_AUTH_RETRY_MAX) {
			rist_log_priv2(ctx->config.logging_settings, RIST_LOG_ERROR, EAP_LOG_PREFIX"Authentication retry count exceeded\n");
			ret = EAP_AUTH_TERMINATED;
		}
		uint8_t buf[EAPOL_EAP_HDRS_OFFSET];
		send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_FAILURE, ctx->last_identifier, 0, buf, eap_tx_version(ctx));
		eap_reset_data(ctx);
		return ret;
	}
	ctx->authenticated = true;
	bool set_passphrase = CHECK_BIT(pkt[3], 0);
	if (set_passphrase) {
		librist_peer_update_rx_passphrase(ctx->peer, librist_crypto_srp_authenticator_get_key(ctx->auth_ctx), SHA256_DIGEST_LENGTH, !ctx->did_first_auth);
	}
	ctx->did_first_auth = true;
	uint8_t outpkt[(EAPOL_EAP_HDRS_OFFSET + sizeof(struct eap_srp_hdr) + 4 + DIGEST_LENGTH)];
	struct eap_srp_hdr *hdr = (struct eap_srp_hdr *)&outpkt[EAPOL_EAP_HDRS_OFFSET];
	hdr->type = EAP_TYPE_SRP_SHA1;
	hdr->subtype = EAP_SRP_SUBTYPE_SERVER_VALIDATOR;
	memset(&outpkt[EAPOL_EAP_HDRS_OFFSET + sizeof(struct eap_srp_hdr)], 0, 4);
	if (ctx->config.use_key_as_passphrase) {
		SET_BIT(outpkt[(EAPOL_EAP_HDRS_OFFSET + sizeof(*hdr) + 3)], 0);
		librist_peer_update_tx_passphrase(ctx->peer, librist_crypto_srp_authenticator_get_key(ctx->auth_ctx), SHA256_DIGEST_LENGTH, !ctx->did_first_auth);
		ctx->did_first_auth = true;
	}
	librist_crypto_srp_authenticator_write_M2_bytes(ctx->auth_ctx, &outpkt[(EAPOL_EAP_HDRS_OFFSET + sizeof(*hdr) + 4)]);
	ctx->last_identifier++;
	return send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_REQUEST, ctx->last_identifier, (sizeof(*hdr) + 4 + DIGEST_LENGTH), outpkt, eap_tx_version(ctx));
}

static int process_eap_response_srp_server_validator(struct eapsrp_ctx *ctx)
{
	if (ctx->authenticated)
	{
		if (ctx->authentication_state < EAP_AUTH_STATE_SUCCESS) {
			char ubuf[256];
			rist_log_priv2(ctx->config.logging_settings, RIST_LOG_INFO, EAP_LOG_PREFIX"Successfully authenticated %s@%s\n", eap_sanitize_log(ctx->config.username, ubuf, sizeof(ubuf)), ctx->ip_string);
		}

		if (ctx->config.use_key_as_passphrase && ctx->eapversion3)
			ctx->may_rollover_passphrase = true;

		ctx->authentication_state = EAP_AUTH_STATE_SUCCESS;
		ctx->last_auth_timestamp = timestampNTP_u64();
		ctx->tries = 0;
		ctx->failed_state_timestamp = 0;
		ctx->last_identifier++;
	}
	return 0;
}

static int process_eap_response_passphrase(struct eapsrp_ctx *ctx, uint8_t identifier, size_t len, uint8_t pkt[], uint8_t eap_version) {
	if (ctx->authentication_state != EAP_AUTH_STATE_SUCCESS)
		return 0;

	/* If a solicited passphrase request is outstanding, only accept a
	 * response whose identifier matches the request.  This prevents
	 * replay or spoofed RESPONSEs from hijacking an active exchange.
	 *
	 * When no request is active the RESPONSE is an unsolicited
	 * passphrase push (the protocol explicitly allows this — see
	 * rist_eap_send_passphrase).  Its payload is encrypted under the SRP
	 * session key: v3 AES-CTR (confidentiality only) or, when both peers
	 * are v4, AES-256-GCM (integrity + authenticity + replay protection). */
	bool matches_request = (ctx->passphrase_request_timer != 0 &&
	                        identifier == ctx->passphrase_request_identifier);
	if (ctx->passphrase_request_timer != 0 && !matches_request)
		return 0;

	if (len < 1)
		return EAP_LENERR;
	bool use_derived_key = CHECK_BIT(pkt[0], 7);
	const uint8_t *skey = (ctx->config.role == EAP_ROLE_AUTHENTICATOR)
		? librist_crypto_srp_authenticator_get_key(ctx->auth_ctx)
		: librist_crypto_srp_client_get_key(ctx->client_ctx);
	/* Dispatch on the NEGOTIATED session version, never on the per-packet
	 * EAPOL version byte (cleartext, attacker-controlled): once v4 is
	 * negotiated, downgraded frames (v3 CTR, no integrity) and the U-bit
	 * derived-key install (no verification at all) are refused. */
	bool session_v4 = eap_use_v4(ctx);
	bool installed = false;
	if (use_derived_key) {
		if (session_v4)
			return 0;
		installed = (librist_peer_update_rx_passphrase(ctx->peer, skey, SHA256_DIGEST_LENGTH, matches_request) == 0);
	} else if (session_v4) {
		if (eap_version < 4)
			return 0;
		/* v4 layout after the SRP header: [flags][nonce 12][ciphertext..][tag 16] */
		if (len < (size_t)(1 + EAP_V4_NONCE_LEN + EAP_V4_TAG_LEN))
			return EAP_LENERR;
		size_t ct_len = len - 1 - EAP_V4_NONCE_LEN - EAP_V4_TAG_LEN;
		const uint8_t *noncep = &pkt[1];
		const uint8_t *ct = noncep + EAP_V4_NONCE_LEN;
		const uint8_t *tag = ct + ct_len;
		uint8_t plain[EAP_V4_MAX_PLAINTEXT];
		if (ct_len == 0 || ct_len > sizeof(plain))
			return EAP_LENERR;
		uint8_t key[32];
		bool c2s = (ctx->config.role == EAP_ROLE_AUTHENTICATOR); //we receive client->server
		if (eap_v4_dir_key(ctx, c2s, key) != 0)
			return EAP_INTERNALERR;
		uint8_t aad[EAP_V4_AAD_LEN];
		eap_v4_build_aad(aad, identifier, pkt[0], noncep);
		if (_librist_crypto_aes_gcm_decrypt(key, noncep, EAP_V4_NONCE_LEN,
			aad, sizeof(aad), ct, ct_len, tag, EAP_V4_TAG_LEN, plain) != 0) {
			/* Tag failed: drop without ACK so the sender retransmits; never
			 * install unverified material (plain already zeroed by decrypt). */
			_librist_crypto_secure_zero(key, sizeof(key));
			rist_log_priv2(ctx->config.logging_settings, RIST_LOG_WARN,
				EAP_LOG_PREFIX"v4 passphrase authentication tag failed; dropping\n");
			return 0;
		}
		uint64_t rx_nonce = eap_v4_decode_nonce(noncep);
		/* Strictly-increasing nonces only; a byte-identical retransmit is
		 * re-ACKed without reinstalling. */
		if (!ctx->rx_nonce_seen || rx_nonce > ctx->rx_last_nonce) {
			ctx->rx_last_nonce = rx_nonce;
			ctx->rx_nonce_seen = true;
			installed = (librist_peer_update_rx_passphrase(ctx->peer, plain, ct_len, matches_request) == 0);
			if (installed)
				rist_log_priv2(ctx->config.logging_settings, RIST_LOG_DEBUG,
					EAP_LOG_PREFIX"v4 passphrase verified and installed (AES-256-GCM, nonce=%" PRIu64 ")\n",
					rx_nonce);
		} else {
			installed = true;
		}
		_librist_crypto_secure_zero(key, sizeof(key));
		_librist_crypto_secure_zero(plain, sizeof(plain));
	} else {
		bool aes_256 = CHECK_BIT(pkt[0], 6);
		uint8_t iv[16] = {0};
		iv[15] = identifier;
		_librist_crypto_aes_ctr(skey, aes_256? 256: 128, iv, &pkt[1], &pkt[1], len -1);
		installed = (librist_peer_update_rx_passphrase(ctx->peer, &pkt[1], len-1, matches_request) == 0);
	}
	uint8_t buf[EAPOL_EAP_HDRS_OFFSET];
	if (ctx->passphrase_request_timer)
		ctx->passphrase_request_timer = 0;
	if (!installed) {
		/* The key slot refused the passphrase (e.g. oversize): answer
		 * FAILURE, never confirm a rotation that did not happen. */
		rist_log_priv2(ctx->config.logging_settings, RIST_LOG_WARN,
			EAP_LOG_PREFIX"passphrase install failed; answering FAILURE\n");
		return send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_FAILURE, identifier, 0, buf, eap_tx_version(ctx));
	}
	return send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_SUCCESS, identifier, 0, buf, eap_tx_version(ctx));
}

static int eap_request_passphrase(struct eapsrp_ctx *ctx, bool start) {
	if (start) {
		ctx->unsollicited_passphrase_response_times = 0;
		ctx->passphrase_request_identifier++;
		if (ctx->config.role == EAP_ROLE_AUTHENTICATEE)
			SET_BIT(ctx->passphrase_request_identifier, 7);
		SET_BIT(ctx->passphrase_request_identifier, 6);
	}
	uint8_t outpkt[(EAPOL_EAP_HDRS_OFFSET + sizeof(struct eap_srp_hdr))];
	struct eap_srp_hdr *hdr = (struct eap_srp_hdr *)&outpkt[EAPOL_EAP_HDRS_OFFSET];
	hdr->type = EAP_TYPE_SRP_SHA1;
	hdr->subtype = EAP_SRP_SUBTYPE_PASSWORD_REQUEST_RESPONSE;
	ctx->passphrase_request_times++;
	ctx->passphrase_request_timer = timestampNTP_u64();
	return send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_REQUEST, ctx->passphrase_request_identifier, sizeof(*hdr), outpkt, eap_tx_version(ctx));
}

static int process_eap_response(struct eapsrp_ctx *ctx, uint8_t pkt[], size_t len, uint8_t identifier, uint8_t eap_version)
{
	if (len < 1)
		return EAP_LENERR;
	uint8_t type = pkt[0];
	/* Invalidate the retransmit cache only for a response matching the
	 * in-flight exchange identifier; junk responses (spoofed or stale)
	 * must not flush it, otherwise a spoofer blasting one response per
	 * retransmit period starves the cache and stalls the handshake
	 * indefinitely. */
	if (identifier == ctx->last_identifier) {
		ctx->timeout_retries = 0;
		free(ctx->last_pkt);
		ctx->last_pkt_size = 0;
		ctx->last_pkt = NULL;
	}
	if (type == EAP_TYPE_IDENTITY) {
		/* Only an authenticator should ever process IDENTITY RESPONSE; on the
		 * authenticatee side ctx->config.lookup_func is NULL (set up via
		 * calloc + role/username/password assignment in rist_enable_eap_srp_2)
		 * and process_eap_response_identity would dereference it. */
		if (ctx->config.role != EAP_ROLE_AUTHENTICATOR || !ctx->config.lookup_func)
			return EAP_UNEXPECTEDRESPONSE;
		if (identifier != ctx->last_identifier)
			return EAP_WRONGIDENTIFIER;
		return process_eap_response_identity(ctx, (len -1), &pkt[1], eap_version);
	}
	if (type == EAP_TYPE_SRP_SHA1)
	{
		if (len < 2)
			return EAP_LENERR;
		uint8_t subtype = pkt[1];

		if (subtype != EAP_SRP_SUBTYPE_PASSWORD_REQUEST_RESPONSE && ctx->config.role == EAP_ROLE_AUTHENTICATEE)
			return EAP_UNEXPECTEDRESPONSE;

		//A password response can be send unsollicited!
		if (subtype != EAP_SRP_SUBTYPE_PASSWORD_REQUEST_RESPONSE && identifier != ctx->last_identifier)
			return EAP_WRONGIDENTIFIER;

		switch (subtype)
		{
			case EAP_SRP_SUBTYPE_CLIENT_KEY:
				return process_eap_response_client_key(ctx, (len -2), &pkt[2]);
				break;
			case EAP_SRP_SYPTYPE_CLIENT_VALIDATOR:
				return process_eap_response_client_validator(ctx, (len -2), &pkt[2]);
				break;
			case EAP_SRP_SUBTYPE_SERVER_VALIDATOR:
				return process_eap_response_srp_server_validator(ctx);
				break;
			case EAP_SRP_SUBTYPE_LWRECHALLENGE:
				//handle SRP lw rechallenge
				break;
			case EAP_SRP_SUBTYPE_PASSWORD_REQUEST_RESPONSE:
				return process_eap_response_passphrase(ctx, identifier, (len -2), &pkt[2], eap_version);
				break;
			default:
				return EAP_SRP_WRONGSUBTYPE;
		}
	}
	return -1;
}

static int process_eap_succes(struct eapsrp_ctx *ctx, uint8_t identifier) {
	if (identifier == ctx->unsollicited_passphrase_response_identifier && ctx->unsollicited_passphrase_response_timer != 0) {
		ctx->unsollicited_passphrase_state = EAP_PASSPHRASE_STATE_SUCCESS;
		ctx->unsollicited_passphrase_response_identifier = 0;
		ctx->unsollicited_passphrase_response_timer = 0;
		ctx->unsollicited_passphrase_response_times = 0;
		return 0;
	}
	if (identifier ==ctx->last_identifier)//The spec mandates we use the success packet on reception of the server_validator
		return process_eap_response_srp_server_validator(ctx);
	return 0;
}

static int process_eap_pkt(struct eapsrp_ctx *ctx, uint8_t pkt[], size_t len, uint8_t eap_version)
{
	if (ctx == NULL)
		return -1;
	if (ctx->authentication_state == EAP_AUTH_STATE_FAILED && ctx->tries >EAP_AUTH_RETRY_MAX)
		return EAP_AUTH_TERMINATED;
	if (len < sizeof(struct eap_hdr))
		return EAP_LENERR;
	/* Record the peer's advertised EAP version for v4 negotiation. */
	if (eap_version > ctx->peer_eap_version)
		ctx->peer_eap_version = eap_version;
	struct eap_hdr *hdr = (struct eap_hdr *)pkt;
	uint8_t code = hdr->code;
	uint8_t identifier = hdr->identifier;
	uint16_t length = be16toh(hdr->length);
	if (length != len)
		return EAP_LENERR;

	switch (code)
	{
		case EAP_CODE_REQUEST:
			return process_eap_request(ctx, &pkt[sizeof(*hdr)], (len - sizeof(*hdr)), identifier, eap_version);
			break;
		case EAP_CODE_RESPONSE:
			return process_eap_response(ctx, &pkt[sizeof(*hdr)], (len - sizeof(*hdr)),identifier, eap_version);
			break;
		case EAP_CODE_SUCCESS:
			return process_eap_succes(ctx, identifier);
			break;
		case EAP_CODE_FAILURE:
			/* Drop FAILUREs whose identifier doesn't match the in-flight exchange. */
			if (identifier != ctx->last_identifier) {
				rist_log_priv2(ctx->config.logging_settings, RIST_LOG_DEBUG,
					EAP_LOG_PREFIX"Dropping FAILURE with stale identifier %u (expected %u)\n",
					identifier, ctx->last_identifier);
				return 0;
			}
			// rate-limit, otherwise a spoofed FAILURE can loop us forever
			eap_tries_inc(ctx);
			eap_reset_data(ctx);
			rist_log_priv2(ctx->config.logging_settings, RIST_LOG_ERROR, EAP_LOG_PREFIX"Authentication failed\n");
			if (ctx->tries > EAP_AUTH_RETRY_MAX) {
				ctx->authentication_state = EAP_AUTH_STATE_FAILED;
				ctx->failed_state_timestamp = timestampNTP_u64();
				return EAP_AUTH_TERMINATED;
			}
			return _librist_proto_eap_start(ctx);//try to restart the process
		default:
			return -1;
	}
	return -1;
}

int eap_request_identity(struct eapsrp_ctx *ctx)
{
	uint8_t outpkt[EAPOL_EAP_HDRS_OFFSET +1];
	outpkt[EAPOL_EAP_HDRS_OFFSET] = EAP_TYPE_IDENTITY;
	uint32_t id_rand;
	if (_librist_crypto_random_u32(&id_rand) != 0)
		return -1;
	ctx->last_identifier = (uint8_t)(id_rand >> 24);
	return send_eapol_pkt(ctx, EAPOL_TYPE_EAP, EAP_CODE_REQUEST, ctx->last_identifier, 1, outpkt, eap_tx_version(ctx));
}

/* EAPOL is exempt from encryption, so START still reaches a peer that has
 * lost our session key (e.g. a restarted authenticator). */
static int eap_send_start_pkt(struct eapsrp_ctx *ctx)
{
	struct eapol_hdr eapol;
	eapol.eapversion = 3;
	eapol.eaptype = EAPOL_TYPE_START;
	eapol.length = 0;
	if (_librist_proto_gre_send_data(ctx->peer, 0, RIST_GRE_PROTOCOL_TYPE_EAPOL, (uint8_t*)&eapol, sizeof(eapol), 0, 0, ctx->peer->rist_gre_version) < 0)
		return -1;
	return 0;
}

int _librist_proto_eap_start(struct eapsrp_ctx *ctx)
{
	if (ctx->authentication_state == EAP_AUTH_STATE_SUCCESS)
		ctx->authentication_state = EAP_AUTH_STATE_REAUTH;
	int ret = eap_send_start_pkt(ctx);
	/* Authenticatees have no other periodic START driver; arm the bounded
	 * retransmit (eap_periodic_impl). Inbound EAP re-arms it. */
	if (ctx->config.role == EAP_ROLE_AUTHENTICATEE) {
		ctx->authee_start_timer = timestampNTP_u64();
		ctx->authee_start_tries = 0;
	}
	return ret;
}

/* Force an authenticatee (caller/supplicant) to re-run the full SRP
 * handshake from scratch and re-initiate it right now.
 *
 * Used after a caller socket rebind (NAT source-port change or a peer
 * restart): the previously authenticated session is bound to the old
 * source tuple and to per-session crypto the far end no longer has (a
 * restarted listener has forgotten everything). Keeping the stale
 * SUCCESS state would leave us sending data the authenticator drops as
 * unauthenticated, and the authenticator-driven re-auth never fires for
 * a peer it does not know about. So drop all per-session state back to
 * UNAUTH and send a fresh EAPOL START, exactly as on a cold connect, so
 * the authenticator challenges us immediately on the new socket.
 *
 * Authenticator contexts are left untouched (re-auth there is driven by
 * eap_periodic and the listener-side reassociation path). */
void eap_reset_authenticatee(struct eapsrp_ctx *ctx)
{
	if (ctx == NULL)
		return;
	pthread_mutex_lock(&ctx->eap_lock);
	if (ctx->config.role == EAP_ROLE_AUTHENTICATEE) {
		eap_reset_data(ctx);        /* frees client crypto, authenticated=false */
		ctx->authentication_state = EAP_AUTH_STATE_UNAUTH;
		ctx->tries = 0;             /* clear any parked failure count */
		ctx->timeout_retries = 0;
		ctx->failed_state_timestamp = 0;
		ctx->last_identity_reply_timestamp = 0; /* don't rate-limit the fresh handshake */
		ctx->last_identifier = 0;
		ctx->did_first_auth = false;/* install the new session key as a first auth */
		if (_librist_proto_eap_start(ctx) < 0)
			rist_log_priv2(ctx->config.logging_settings, RIST_LOG_WARN,
				EAP_LOG_PREFIX"Failed to send EAPOL START after socket rebind; "
				"periodic retransmit will retry\n");
	}
	pthread_mutex_unlock(&ctx->eap_lock);
}

void eap_set_ip_string(struct eapsrp_ctx *ctx, char ip_string[])
{
	if (ctx != NULL) {
		strncpy(ctx->ip_string, ip_string, sizeof(ctx->ip_string) - 1);
		ctx->ip_string[sizeof(ctx->ip_string) - 1] = '\0';
	}
}

int eap_clone_ctx(struct eapsrp_ctx *in, struct rist_peer *peer)
{
	if (in == NULL)
		return 0;
	if (peer->eap_ctx != NULL)
		return -1;
	struct eapsrp_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return -1;

	if (pthread_mutex_init(&ctx->eap_lock, NULL) != 0) {
		free(ctx);
		return -1;
	}
    memcpy(&ctx->config, &in->config, sizeof(in->config));
	ctx->srp_legacy_pad = in->srp_legacy_pad;
	peer->eap_ctx = ctx;
	ctx->peer = peer;
	ctx->eapversion3 = true;
	return 0;
}

void eap_delete_ctx(struct eapsrp_ctx **in)
{
	if (*in == NULL)
		return;

	struct eapsrp_ctx *ctx = *in;
	eap_reset_data(ctx);

	free(ctx);
	*in = NULL;
}

int eap_process_eapol(struct eapsrp_ctx* ctx, uint8_t pkt[], size_t len)
{
	assert(ctx != NULL);
	if (len < sizeof(struct eapol_hdr))
		return EAP_LENERR;
	struct eapol_hdr *hdr = (struct eapol_hdr *)pkt;
	uint8_t eap_version = hdr->eapversion;
	size_t body_len = be16toh(hdr->length);
	// the on-the-wire body_len must fit inside what we actually received
	if (body_len + sizeof(struct eapol_hdr) > len)
		return EAP_LENERR;

	pthread_mutex_lock(&ctx->eap_lock);
	int ret = -1;
	switch (hdr->eaptype)
	{
		case EAPOL_TYPE_EAP:
			ret = process_eap_pkt(ctx, &pkt[sizeof(*hdr)], body_len, eap_version);
			break;
		case EAPOL_TYPE_START:
			/* START (re)drives the handshake; only an authenticatee sends it.
			 * Always re-challenge with IDENTITY and reset the retransmit
			 * bookkeeping so a caller recovering from a restart or rebind is
			 * driven anew rather than ignored for a stale last_pkt. Do NOT
			 * reset tries: it is the brute-force cap, and START is reachable
			 * pre-auth, so clearing it here would hand an attacker unlimited
			 * online password guesses (and unlimited server-side modexps). */
			if (ctx->config.role == EAP_ROLE_AUTHENTICATOR) {
				if (ctx->authentication_state == EAP_AUTH_STATE_SUCCESS)
					ctx->authentication_state = EAP_AUTH_STATE_REAUTH;
				ctx->timeout_retries = 0;
				ret = eap_request_identity(ctx);
			} else {
				ret = 0;
			}
			break;
		case EAPOL_TYPE_LOGOFF:
			/* Refuse LOGOFF once authenticated; re-auth runs from eap_periodic.
			 * A soft-FAILED ctx stays FAILED: walking it back to UNAUTH from
			 * the wire bypasses the brute-force kill path, and clearing tries
			 * would hand out unlimited online guesses. Recovery stays with
			 * the quiet-period path in eap_periodic. */
			if (ctx->authentication_state >= EAP_AUTH_STATE_SUCCESS) {
				ret = EAP_UNEXPECTEDREQUEST;
				break;
			}
			if (ctx->authentication_state != EAP_AUTH_STATE_FAILED)
				ctx->authentication_state = EAP_AUTH_STATE_UNAUTH;
			ret = 0;
			break;
		default:
			break;
	}
	/* Far end is engaged: while still handshaking (UNAUTH) push the START
	 * retransmit timer out so it only fires on true silence; once
	 * authenticated, disarm it. */
	if (ctx->config.role == EAP_ROLE_AUTHENTICATEE) {
		if (ctx->authentication_state == EAP_AUTH_STATE_UNAUTH) {
			ctx->authee_start_timer = timestampNTP_u64();
			ctx->authee_start_tries = 0;
		} else {
			ctx->authee_start_timer = 0;
		}
	}
	pthread_mutex_unlock(&ctx->eap_lock);
	return ret;
}

bool eap_is_authenticated(struct eapsrp_ctx *ctx)
{
	if (ctx == NULL)
		return true;

	pthread_mutex_lock(&ctx->eap_lock);
	bool authenticated = (ctx->authentication_state >= EAP_AUTH_STATE_SUCCESS);
	pthread_mutex_unlock(&ctx->eap_lock);
	return authenticated;
}

const char *eap_get_username(const struct eapsrp_ctx *ctx)
{
	if (!ctx)
		return NULL;
	return ctx->config.username;
}

static void eap_periodic_impl(struct eapsrp_ctx *ctx)
{
	uint64_t now = timestampNTP_u64();
	uint64_t retry_period = EAP_AUTH_TIMEOUT * RIST_CLOCK;
	uint64_t reauth_period = EAP_REAUTH_PERIOD * RIST_CLOCK;//3 seconds

	/* Authenticator-restart recovery: once the identity-request probe armed by
	 * process_eap_request_identity has persisted one retry period, drop to UNAUTH
	 * and re-run the SRP handshake (bounds a lone forged packet to one re-auth). */
	if (ctx->config.role == EAP_ROLE_AUTHENTICATEE &&
	    ctx->authentication_state >= EAP_AUTH_STATE_SUCCESS &&
	    ctx->reauth_probe_timer != 0 &&
	    now > ctx->reauth_probe_timer + retry_period) {
		rist_log_priv2(ctx->config.logging_settings, RIST_LOG_INFO,
			EAP_LOG_PREFIX"Authenticator re-requested identity while authenticated "
			"(it likely restarted); re-authenticating\n");
		ctx->reauth_probe_timer = 0;
		eap_reset_data(ctx);
		ctx->authentication_state = EAP_AUTH_STATE_UNAUTH;
		ctx->tries = 0;
		ctx->timeout_retries = 0;
		ctx->failed_state_timestamp = 0;
		ctx->last_identity_reply_timestamp = 0;
		ctx->did_first_auth = false;
		if (_librist_proto_eap_start(ctx) < 0)
			rist_log_priv2(ctx->config.logging_settings, RIST_LOG_WARN,
				EAP_LOG_PREFIX"Failed to send EAPOL START for re-auth; "
				"periodic retransmit will retry\n");
	}

	/* Retransmit START while stuck UNAUTH and the authenticator is silent
	 * (e.g. a restarted listener that missed our first START). Bounded; when
	 * exhausted the caller-side socket rebind re-arms us on its next cycle. */
	if (ctx->config.role == EAP_ROLE_AUTHENTICATEE &&
	    ctx->authentication_state == EAP_AUTH_STATE_UNAUTH &&
	    ctx->authee_start_timer != 0 &&
	    now > ctx->authee_start_timer + retry_period) {
		if (ctx->authee_start_tries >= EAP_AUTH_TIMEOUT_RETRY_MAX) {
			ctx->authee_start_timer = 0;
		} else {
			eap_send_start_pkt(ctx);
			ctx->authee_start_timer = now;
			ctx->authee_start_tries++;
		}
	}

	if (ctx->authentication_state == EAP_AUTH_STATE_SUCCESS && ctx->passphrase_request_timer != 0 && ctx->passphrase_request_timer + retry_period < now) {
		if (ctx->passphrase_request_times > EAP_AUTH_TIMEOUT_RETRY_MAX) {
			rist_log_priv2(ctx->config.logging_settings, RIST_LOG_WARN, EAP_LOG_PREFIX"Failed to receive requested passphrase in a timely manner\n");
			ctx->passphrase_request_timer = 0;
		} else {
			eap_request_passphrase(ctx, false);
		}
	}

	if (ctx->authentication_state == EAP_AUTH_STATE_SUCCESS && ctx->unsollicited_passphrase_response_timer != 0 && ctx->unsollicited_passphrase_response_timer + retry_period < now) {
		if (ctx->unsollicited_passphrase_response_times > EAP_AUTH_TIMEOUT_RETRY_MAX) {
			rist_log(ctx->config.logging_settings, RIST_LOG_ERROR, EAP_LOG_PREFIX"Failed to update passphrase for client\n");
			ctx->unsollicited_passphrase_response_timer = 0;
			ctx->unsollicited_passphrase_state = EAP_PASSPHRASE_STATE_FAILED;
		} else {
			/* Retransmit reuses the cached nonce so a v4 payload is byte-identical. */
			eap_srp_send_password(ctx, ctx->unsollicited_passphrase_response_identifier, ctx->unsollicited_passphrase, ctx->unsollicited_passphrase_len, ctx->unsollicited_passphrase_nonce);
			ctx->unsollicited_passphrase_response_timer = timestampNTP_u64();
			ctx->unsollicited_passphrase_response_times++;
		}
    }

	if (ctx->unsollicited_passphrase_response_timer == 0 &&
		ctx->passphrase_request_timer &&
		((ctx->unsollicited_passphrase_response_identifier & 0x3f) == 0x3f ||
		(ctx->unsollicited_passphrase_response_identifier & 0x3f) == 0x3f)) {
			if (ctx->config.role == EAP_ROLE_AUTHENTICATEE)
				_librist_proto_eap_start(ctx);
			else
				eap_request_identity(ctx);
		}
	if (ctx->config.role == EAP_ROLE_AUTHENTICATOR && ctx->authentication_state != 1 && ctx->last_timestamp + retry_period < now &&
		ctx->timeout_retries < EAP_AUTH_TIMEOUT_RETRY_MAX && ctx->tries <= EAP_AUTH_RETRY_MAX)
	{
		if (ctx->last_pkt)
		{
			rist_transport_sendto(ctx->peer, ctx->last_pkt, ctx->last_pkt_size, 0);
			//check
			ctx->timeout_retries++;
			ctx->last_timestamp = now;
			return;
		} else {
			eap_request_identity(ctx);
			return;
		}
	} else if (ctx->config.role == EAP_ROLE_AUTHENTICATOR && ctx->authentication_state == EAP_AUTH_STATE_SUCCESS &&
	           now > ctx->last_auth_timestamp + reauth_period) {
		if (ctx->generation > 0) {
			uint64_t generation = ctx->generation;
			int hashversion = ctx->eapversion3? 1 : 0;
			//If our cached data matches whatever lookup function would return re-auth is pointless.
			ctx->config.lookup_func(ctx->config.username, NULL, &hashversion, &generation, ctx->config.lookup_func_userdata);
			if (generation == ctx->generation) {
				ctx->last_auth_timestamp = now;
				return;
			}
		}
		ctx->authentication_state = EAP_AUTH_STATE_REAUTH;
		eap_request_identity(ctx);
		return;
	}
	uint64_t reauth_time_out = ctx->last_auth_timestamp + reauth_period + EAP_AUTH_RETRY_MAX * retry_period;
	if (ctx->authentication_state == EAP_AUTH_STATE_REAUTH && now > reauth_time_out) {
		ctx->authentication_state = EAP_AUTH_STATE_UNAUTH;
		return;
	}
	/* Soft-FAILED (tries bumped past max but not parked at PERMANENT) -> UNAUTH after quiet. */
	if (ctx->authentication_state == EAP_AUTH_STATE_FAILED &&
	    ctx->tries > EAP_AUTH_RETRY_MAX &&
	    ctx->tries < EAP_AUTH_TRIES_PERMANENT &&
	    ctx->failed_state_timestamp != 0 &&
	    now > ctx->failed_state_timestamp + (uint64_t)EAP_AUTH_FAILED_RECOVERY * RIST_CLOCK) {
		rist_log_priv2(ctx->config.logging_settings, RIST_LOG_INFO,
			EAP_LOG_PREFIX"Recovered from soft FAILED state after %d ms of quiet\n",
			EAP_AUTH_FAILED_RECOVERY);
		ctx->tries = 0;
		ctx->failed_state_timestamp = 0;
		ctx->authentication_state = EAP_AUTH_STATE_UNAUTH;
	}
}
void eap_periodic(struct eapsrp_ctx *ctx) {
	if (ctx == NULL)
		return;
	pthread_mutex_lock(&ctx->eap_lock);
	eap_periodic_impl(ctx);
	pthread_mutex_unlock(&ctx->eap_lock);
}

static void internal_user_verifier_lookup(char * username,
							librist_verifier_lookup_data_t *lookup_data,
							int *hashversion,
							uint64_t *generation,
							void *user_data)
{
	if (user_data == NULL)
		return;

	if (*generation == 1)
		return;
	//This is static data so it can be permanently cached
	*generation = 1;

	struct eapsrp_ctx *ctx = (struct eapsrp_ctx *)user_data;

	uint8_t *decoded_verifier = NULL;
	uint8_t *decoded_salt = NULL;

	if (strcmp(username, ctx->authenticator_username) != 0)
		goto fail_decode;

	if (*hashversion == 0 && HAVE_MBEDTLS) {
#if HAVE_MBEDTLS
		decoded_verifier = malloc(ctx->authenticator_len_verifier_old);
		decoded_salt = malloc(ctx->authenticator_len_salt_old);
		if (!decoded_verifier || !decoded_salt)
			goto fail_decode;
		memcpy(decoded_verifier, ctx->authenticator_bytes_verifier_old, ctx->authenticator_len_verifier_old);
		memcpy(decoded_salt, ctx->authenticator_bytes_salt_old, ctx->authenticator_len_salt_old);
		lookup_data->verifier_len = ctx->authenticator_len_verifier_old;
		lookup_data->salt_len = ctx->authenticator_len_salt_old;
#endif
	} else {
		decoded_verifier = malloc(ctx->authenticator_len_verifier);
		decoded_salt = malloc(ctx->authenticator_len_salt);
		if (!decoded_verifier || !decoded_salt)
			goto fail_decode;
		memcpy(decoded_verifier, ctx->authenticator_bytes_verifier, ctx->authenticator_len_verifier);
		memcpy(decoded_salt, ctx->authenticator_bytes_salt, ctx->authenticator_len_salt);
		lookup_data->verifier_len = ctx->authenticator_len_verifier;
		lookup_data->salt_len = ctx->authenticator_len_salt;
	}
	lookup_data->verifier = decoded_verifier;
	lookup_data->salt = decoded_salt;

	lookup_data->default_ng = true;
	goto out;

fail_decode:
	lookup_data->verifier_len = 0;
	lookup_data->salt_len = 0;
	free(decoded_verifier);
	free(decoded_salt);
out:
	return;
}

static void old_user_verifier_lookup_wrapper(char * username,
							librist_verifier_lookup_data_t *lookup_data,
							int *hashversion,
							uint64_t *generation,
							void *user_data)
{
	*hashversion = 0;
	*generation = 0;
	struct eapsrp_ctx *ctx = (struct eapsrp_ctx *)user_data;
	ctx->config.lookup_func_old(username, &lookup_data->verifier_len,(char **)&lookup_data->verifier, &lookup_data->salt_len, (char **)&lookup_data->salt, &lookup_data->default_ng, &lookup_data->n_modulus_ascii, &lookup_data->generator_ascii, user_data);
}

//PUBLIC
int rist_enable_eap_srp_2(struct rist_peer *peer, const char *username, const char *password, user_verifier_lookup_2_t lookup_func, void *userdata) {
	if (!peer)
		return RIST_ERR_NULL_PEER;
	struct rist_common_ctx *cctx = get_cctx(peer);
	if (cctx->profile == RIST_PROFILE_SIMPLE)
		return RIST_ERR_INVALID_PROFILE;
	if ((peer->listening && !peer->multicast_receiver) || peer->multicast_sender)
	{
		struct eapsrp_ctx *ctx = calloc(1, sizeof(*ctx));
		if (ctx == NULL)
			return RIST_ERR_MALLOC;
		ctx->config.logging_settings = get_cctx(peer)->logging_settings;
		if (pthread_mutex_init(&ctx->eap_lock, NULL) != 0) {
			free(ctx);
			return RIST_ERR_MALLOC;
		}
		if (lookup_func == NULL && username != NULL && password != NULL)
		{
			size_t u_len = strlen(username);
			size_t p_len = strlen(password);
			if (u_len == 0 || u_len > 255 || p_len == 0 || p_len > 255) {
				free(ctx);
				return RIST_ERR_INVALID_STRING_LENGTH;
			}
			lookup_func = internal_user_verifier_lookup;
			const char *n = NULL;
			const char *g = NULL;
			int ret;
			ret = librist_get_ng_constants(LIBRIST_SRP_NG_2048, &n, &g);
			assert(ret == 0);
#if HAVE_MBEDTLS
			ret = librist_crypto_srp_create_verifier(n, g, username, password, &ctx->authenticator_bytes_salt_old, &ctx->authenticator_len_salt_old, &ctx->authenticator_bytes_verifier_old, &ctx->authenticator_len_verifier_old, false);
			assert(ret == 0);
#endif
			ret = librist_crypto_srp_create_verifier(n, g, username, password, &ctx->authenticator_bytes_salt, &ctx->authenticator_len_salt, &ctx->authenticator_bytes_verifier, &ctx->authenticator_len_verifier, true);
			assert(ret == 0);
			strcpy(ctx->authenticator_username, username);
			userdata = (void *)ctx;
			rist_log_priv2(ctx->config.logging_settings, RIST_LOG_INFO, EAP_LOG_PREFIX"EAP Authentication enabled, role = authenticator, single user\n");
		}
		else if (lookup_func == NULL) {
			free(ctx);
			return RIST_ERR_MISSING_CALLBACK_FUNCTION;
		}
		else
			rist_log_priv2(ctx->config.logging_settings, RIST_LOG_INFO, EAP_LOG_PREFIX"EAP Authentication enabled, role = authenticator, srp file\n");
		ctx->config.lookup_func = lookup_func;
		ctx->config.lookup_func_userdata = userdata;
		ctx->config.role = EAP_ROLE_AUTHENTICATOR;
		ctx->config.use_key_as_passphrase = peer->key_tx.password_len == 0;
		ctx->eapversion3 = true;
		ctx->srp_legacy_pad = (peer->config.srp_compat_legacy != 0);
		if (ctx->srp_legacy_pad)
			rist_log_priv2(ctx->config.logging_settings, RIST_LOG_WARN,
				EAP_LOG_PREFIX"SRP legacy compat mode ACTIVE on this authenticator (srp-compat=1). Wire format is the pre-0.2.16 unpadded form — NOT TR-06-2 / RFC 5054 compliant. For transitional interop only.\n");
		peer->eap_ctx = ctx;
		struct rist_peer *child = peer->child;
		peer->eap_authentication_state = 1;
		ctx->peer = peer;
		while (child != NULL)
		{
			eap_clone_ctx(ctx, child);
			child = child->sibling_next;
		}
		return 0;
	}
	if (username == NULL || password == NULL)
		return RIST_ERR_NULL_CREDENTIALS;
	size_t u_len = strlen(username);
	size_t p_len = strlen(password);
	if (u_len == 0 || u_len > 255 || p_len == 0 || p_len > 255)
		return RIST_ERR_INVALID_STRING_LENGTH;
	struct eapsrp_ctx *ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL)
		return RIST_ERR_MALLOC;
	if (pthread_mutex_init(&ctx->eap_lock, NULL) != 0) {
		free(ctx);
		return RIST_ERR_MALLOC;
	}
	ctx->peer = peer;
	ctx->config.logging_settings = get_cctx(peer)->logging_settings;
	ctx->config.role = EAP_ROLE_AUTHENTICATEE;
	strcpy(ctx->config.username, username);
	strcpy(ctx->config.password, password);
	ctx->srp_legacy_pad = (peer->config.srp_compat_legacy != 0);
	peer->eap_ctx = ctx;
	rist_log_priv2(ctx->config.logging_settings, RIST_LOG_INFO, EAP_LOG_PREFIX"EAP Authentication enabled, role = authenticatee\n");
	if (ctx->srp_legacy_pad)
		rist_log_priv2(ctx->config.logging_settings, RIST_LOG_WARN,
			EAP_LOG_PREFIX"SRP legacy compat mode ACTIVE on this client (srp-compat=1). Wire format is the pre-0.2.16 unpadded form — NOT TR-06-2 / RFC 5054 compliant. For transitional interop only.\n");
	ctx->eapversion3 = true;
	if (!peer->multicast_receiver)
		_librist_proto_eap_start(ctx);
	return 0;
}

int rist_enable_eap_srp(struct rist_peer *peer, const char *username, const char *password, user_verifier_lookup_t lookup_func, void *userdata)
{
	if (!peer)
		return RIST_ERR_NULL_PEER;

	user_verifier_lookup_2_t pass_lookup = lookup_func? old_user_verifier_lookup_wrapper : NULL;
	int ret = rist_enable_eap_srp_2(peer, username, password, pass_lookup, NULL);
	if (ret == 0) {
		peer->eap_ctx->config.lookup_func_old = lookup_func;
		peer->eap_ctx->config.lookup_func_userdata = peer->eap_ctx;
		peer->eap_ctx->config.lookup_func_userdata_old = userdata;
	}
	return ret;
}

//returns true when either succesfull or failed
bool rist_eap_password_sending_done(struct eapsrp_ctx *ctx) {
	pthread_mutex_lock(&ctx->eap_lock);
	bool success = ctx->unsollicited_passphrase_state >= EAP_PASSPHRASE_STATE_SUCCESS;
	pthread_mutex_unlock(&ctx->eap_lock);
	return success;
}

bool rist_eap_may_rollover_tx(struct eapsrp_ctx *ctx) {
	pthread_mutex_lock(&ctx->eap_lock);
	bool rollover = ctx->may_rollover_passphrase;
	ctx->may_rollover_passphrase = false;
	pthread_mutex_unlock(&ctx->eap_lock);
	return rollover;
}

void rist_eap_send_passphrase(struct eapsrp_ctx *ctx, const char *passphrase) {
	pthread_mutex_lock(&ctx->eap_lock);
	/* Sending pre-auth would derive direction keys from a crypto ctx that
	 * does not exist yet (NULL) and install nothing meaningful; the peer
	 * version byte can even be pre-armed by a spoofed packet. Require a
	 * completed authentication. */
	if (ctx->authentication_state != EAP_AUTH_STATE_SUCCESS) {
		rist_log_priv2(ctx->config.logging_settings, RIST_LOG_ERROR,
			EAP_LOG_PREFIX"Passphrase push refused: not authenticated\n");
		pthread_mutex_unlock(&ctx->eap_lock);
		return;
	}
	size_t plen = strlen(passphrase);
	if (plen > sizeof(ctx->unsollicited_passphrase)) {
		rist_log_priv2(ctx->config.logging_settings, RIST_LOG_ERROR,
			EAP_LOG_PREFIX"Passphrase too long (%zu > %zu), dropping\n",
			plen, sizeof(ctx->unsollicited_passphrase));
		pthread_mutex_unlock(&ctx->eap_lock);
		return;
	}
	ctx->unsollicited_passphrase_len = plen;
	memcpy(ctx->unsollicited_passphrase, passphrase, plen);
	ctx->unsollicited_passphrase_response_timer = timestampNTP_u64();
	ctx->unsollicited_passphrase_response_times = 1;
	ctx->unsollicited_passphrase_response_identifier++;
	ctx->unsollicited_passphrase_state = 0;
	if (ctx->config.role == EAP_ROLE_AUTHENTICATOR)
		SET_BIT(ctx->unsollicited_passphrase_response_identifier, 7);
	UNSET_BIT(ctx->unsollicited_passphrase_response_identifier, 6);
	/* Assign a fresh nonce for this new passphrase; retransmits reuse it. */
	ctx->unsollicited_passphrase_nonce = ctx->tx_nonce_counter++;
    eap_srp_send_password(ctx, ctx->unsollicited_passphrase_response_identifier, ctx->unsollicited_passphrase, ctx->unsollicited_passphrase_len, ctx->unsollicited_passphrase_nonce);
    pthread_mutex_unlock(&ctx->eap_lock);
}
