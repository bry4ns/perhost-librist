/*
 * Copyright © 2020, VideoLAN and librist authors
 * Copyright © 2019-2020 SipRadius LLC
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef LIBRIST_RECEIVER_H
#define LIBRIST_RECEIVER_H

#include "common.h"
#include "logging.h"
#include "headers.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Receiver specific functions, use rist_receiver_create to create a receiver rist_ctx */
/**
 * Create a RIST receiver instance
 *
 * @param[out] ctx a context representing the receiver instance
 * @param profile RIST profile
 * @param logging_settings Optional struct containing the logging settings.
 * @return 0 on success, -1 on error
 */
RIST_API int rist_receiver_create(struct rist_ctx **ctx, enum rist_profile profile,
			struct rist_logging_settings *logging_settings);

enum rist_nack_type
{
	RIST_NACK_RANGE = 0,
	RIST_NACK_BITMASK = 1,
};

/**
 * @brief Configure nack type
 *
 * Choose the nack type used by the receiver.
 *
 * @param ctx RIST receiver context
 * @param nack_type 0 for range (default), 1 for bitmask
 * @return 0 on success, -1 on error
 */
RIST_API int rist_receiver_nack_type_set(struct rist_ctx *ctx, enum rist_nack_type nacks_type);

/**
 * @brief Set output fifo size
 *
 * Set the output fifo size to the desired maximum, can be set to 0 to disable
 * desired size must be a power of 2. When enabled libRIST will output packets
 * into the fifo queue for reading by the calling application.
 * The fifo buffer size can only be set before starting, and defaults to 1024
 *
 * @param ctx RIST receiver context
 * @param desired_size max number of packets to keep in fifo buffer, 0 to disable
 * @return 0 for success
 */
RIST_API int rist_receiver_set_output_fifo_size(struct rist_ctx *ctx, uint32_t desired_size);

/**
 * @brief Reads rist data
 *
 * Use this API to read data from an internal fifo queue instead of the callback
 *
 * @param ctx RIST receiver context
 * @param[out] reference counted data_blockstructure MUST be freed via rist_receiver_data_block_free
 * @param timeout How long to wait for queue data (ms), 0 for no wait
 * @return num buffers remaining on queue +1 (0 if no buffer returned), -1 on error
 */
RIST_DEPRECATED RIST_API int rist_receiver_data_read(struct rist_ctx *ctx, const struct rist_data_block **data_block, int timeout);
RIST_API int rist_receiver_data_read2(struct rist_ctx *ctx, struct rist_data_block **data_block, int timeout);

/**
 * @brief Data callback function
 *
 * Optional calling application provided function for receiving callbacks upon data reception.
 * Can be used to directly process data, or signal the calling application to read within it's own context.
 * Stalling in this function will hinder data-reception of the libRIST library.
 * This function will be called from a per-flow output thread and must be thread-safe.
 *
 * @param arg optional user data set via rist_receiver_data_callback_set
 * @param data_block reference counted data_block structure MUST be freed via rist_receiver_data_block_free
 * @return int, ignored.
 */
typedef int (*receiver_data_callback_t)(void *arg, const struct rist_data_block *data_block);
typedef int (*receiver_data_callback2_t)(void *arg, struct rist_data_block *data_block);

/**
 * @brief Enable data callback channel
 *
 * Call to enable data callback channel.
 *
 * @param ctx RIST receiver context
 * @param data_callback The function that will be called when a data frame is
 * received from a sender.
 * @param arg the extra argument passed to the `data_callback`
 * @return 0 on success, -1 on error
 */
RIST_DEPRECATED RIST_API int rist_receiver_data_callback_set(struct rist_ctx *ctx, receiver_data_callback_t, void *arg);
RIST_API int rist_receiver_data_callback_set2(struct rist_ctx *ctx, receiver_data_callback2_t, void *arg);

/**
 * @brief Session Timeout callback function
 *
 * This function will notify the app that a session timeout has occured
 *
 * @param arg optional user data set via rist_session_timeout_callback_set
 * @param flow_id id of the flow that is timing out
 * @return int, ignored.
 */
typedef int (*receiver_session_timeout_callback_t)(void *arg, uint32_t flow_id);

/*
 * Called before a receiver associates an authenticated peer with a flow. A
 * non-zero return value rejects the association and prevents flow creation.
 */
typedef int (*receiver_flow_authorize_callback_t)(void *arg,
		struct rist_peer *peer, uint32_t flow_id);

/**
 * @brief Enable Session Timeout callback channel
 *
 * Call to enable session timeout callback channel.
 *
 * @param ctx RIST receiver context
 * @param session_timeout_callback The function that will be called when a session times out
 * @param arg the extra argument passed to the `session_timeout_callback`
 * @return 0 on success, -1 on error
 */
RIST_API int rist_receiver_session_timeout_callback_set(struct rist_ctx *ctx, receiver_session_timeout_callback_t, void *arg);

RIST_API int rist_receiver_flow_authorize_callback_set(struct rist_ctx *ctx,
		receiver_flow_authorize_callback_t callback, void *arg);

/**
 * @brief Free rist data block
 *
 * Must be called whenever a received data block is no longer needed by the calling application.
 *
 * @param block double pointer to rist_data_block, containing pointer will be set to NULL
 */
RIST_DEPRECATED RIST_API void rist_receiver_data_block_free(struct rist_data_block **const block);
RIST_API void rist_receiver_data_block_free2(struct rist_data_block **block);

/**
 * @brief Set data ready signalling fd
 *
 * Calling applications can provide an fd that will be written to whenever a packet
 * is ready for reading via FIFO read function (rist_receiver_data_read).
 * This allows calling applications to poll an fd (i.e.: in event loops).
 * Whenever a packet is ready for reading, a byte (with undefined value) will
 * be written to the FD. Calling application should make no assumptions
 * whatsoever based on the number of bytes available for reading.
 * It is highly recommended that the fd is setup to operate in non blocking mode.
 * A call with a 0 value fd disables the notify fd functionality. And must be
 * made before a calling application closes the fd.
 * @param ctx RIST receiver context
 * @param file_handle The file descriptor to be written to
 * @return 0 on success, -1 on error
 */
RIST_API int rist_receiver_data_notify_fd_set(struct rist_ctx *ctx, int fd);

/**
 * @brief Flow Attribute callback function (Advanced Profile, TR-06-3 Section 5.3.7)
 *
 * Called when a Flow Attribute message (CI=0x8001) is received from a sender.
 * The JSON string contains session/flow metadata as defined by TR-06-3 Section 5.4.
 * The json pointer is valid only for the duration of the callback.
 *
 * @param arg optional user data set via rist_receiver_flow_attr_callback_set
 * @param peer the peer that sent the flow attribute
 * @param json NUL-terminated JSON string containing flow attributes
 * @param json_len length of the JSON string (excluding NUL terminator)
 * @return int, ignored.
 */
typedef int (*receiver_flow_attr_callback_t)(void *arg, struct rist_peer *peer,
                                             const char *json, size_t json_len);

/**
 * @brief Enable flow attribute callback channel
 *
 * Call to enable reception of Advanced Profile Flow Attribute messages.
 * When set, the callback is invoked each time a CI=0x8001 control message
 * arrives from a sender.
 *
 * @param ctx RIST receiver context
 * @param cb The function that will be called when a flow attribute is received
 * @param arg the extra argument passed to the callback
 * @return 0 on success, -1 on error
 */
RIST_API int rist_receiver_flow_attr_callback_set(struct rist_ctx *ctx,
                                                   receiver_flow_attr_callback_t cb,
                                                   void *arg);

/**
 * @brief Enable or disable CBR output pacing
 *
 * The output loop releases every packet whose deadline has passed, so packets
 * that arrived together leave together. With pacing on, they are spread at the
 * stream's measured rate instead, which matters wherever the consumer recovers
 * a clock from output timing.
 *
 * The setting is context-wide, not per output target: pacing happens in the
 * flow's output loop, before any fan-out to individual destinations, so all of
 * them share one release schedule. Only flows created after this call are
 * affected, so call it before rist_start().
 *
 * Equivalent to ?cbr-output= on an output URL, and the two must agree;
 * whichever is applied first wins and a later disagreement is refused.
 *
 * @param ctx RIST receiver context
 * @param enable true to pace the output, false to release on arrival
 * @return 0 on success, -1 on error or on conflict with an earlier setting
 */
RIST_API int rist_receiver_set_cbr_output(struct rist_ctx *ctx, bool enable);

#ifdef __cplusplus
}
#endif

#endif /* LIBRIST_RECEIVER_H */
