/*
 *	BIRD -- The Resource Public Key Infrastructure (RPKI) to Router Protocol
 *
 *	(c) 2015 CZ.NIC
 *
 *	This file was part of RTRlib: http://rpki.realmv6.org/
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef RTR_H
#define RTR_H
#include <time.h>
#include <stdbool.h>
#include <stdint.h>
#include "transport.h"

#include "nest/bird.h"

static const uint8_t RTR_PROTOCOL_VERSION_0 = 0;
static const uint8_t RTR_PROTOCOL_VERSION_1 = 1;

static const uint8_t RTR_PROTOCOL_MIN_SUPPORTED_VERSION = 0;
static const uint8_t RTR_PROTOCOL_MAX_SUPPORTED_VERSION = 1;

enum rtr_rtvals {
    RTR_SUCCESS = 0,
    RTR_ERROR = -1
};

/**
 * @brief States of the RTR socket.
 */
enum rtr_socket_state {
    /* State between request for open new socket and asynchronous finish the opening socket */
    RTR_OPENING,

    /** Socket is establishing the transport connection. */
    RTR_CONNECTING,

    /** Connection is established, socket is waiting for a Serial Notify or expiration of the refresh_interval timer */
    RTR_ESTABLISHED,

    /** Resetting RTR connection. */
    RTR_RESET,

    /** Receiving validation records from the RTR server.  */
    RTR_SYNC,

    /** Reconnect without any waiting period */
    RTR_FAST_RECONNECT,

    /** No validation records are available on the RTR server. */
    RTR_ERROR_NO_DATA_AVAIL,

    /** Server was unable to answer the last serial or reset query. */
    RTR_ERROR_NO_INCR_UPDATE_AVAIL,

    /** Fatal protocol error occurred. */
    RTR_ERROR_FATAL,

    /** Error on the transport socket occurred. */
    RTR_ERROR_TRANSPORT,

    /** RTR Socket is stopped. */
    RTR_SHUTDOWN,
};

struct rtr_socket;

/**
 * @brief A function pointer that is called if the state of the rtr socket has changed.
 */
typedef void (*rtr_connection_state_fp)(const struct rtr_socket *rtr_socket, const enum rtr_socket_state state, void *connection_state_fp_param);

/**
 * @brief A RTR socket.
 * @param tr_socket Pointer to an initialized tr_socket that will be used to communicate with the RTR server.
 * @param refresh_interval Time period in seconds. Tells the router how long to wait before next attempting to poll the cache, using a Serial Query or
 * Reset Query PDU.
 * @param last_update Timestamp of the last validation record update. Is 0 if the pfx_table doesn't stores any
 * validation reords from this rtr_socket.
 * @param expire_interval Time period in seconds. Received records are deleted if the client was unable to refresh data for this time period.
 * If 0 is specified, the expire_interval is twice the refresh_interval.
 * @param retry_interval Time period in seconds between a faild quary and the next attempt.
 * @param state Current state of the socket.
 * @param session_id session_id of the RTR session.
 * @param request_session_id True, if the rtr_client have to request a new none from the server.
 * @param serial_number Last serial number of the obtained validation records.
 */
struct rtr_socket {
    struct tr_socket *tr_socket;
    struct rpki_cache *cache;
    bird_clock_t last_update;
    unsigned int retry_interval;		/* Use if the cache server is down */
    unsigned int refresh_interval;
    unsigned int expire_interval;		/* After this period from last refresh will be ROAs discard */
    enum rtr_socket_state state;
    uint32_t session_id;
    bool request_session_id;
    uint32_t serial_number;
    unsigned int version;
};

/**
 * @brief Initializes a rtr_socket.
 * @param[out] rtr_socket Pointer to the allocated rtr_socket that will be initialized.
 * @param[in] refresh_interval Interval in seconds between serial queries that are sent to the server. Must be <= 3600
 * @param[in] expire_interval Stored validation records will be deleted if cache was unable to refresh data for this period.\n
 * The default value is twice the refresh_interval.
 */
void rtr_init(struct rtr_socket *rtr_socket, const unsigned int refresh_interval, const unsigned int expire_interval, const unsigned int retry_interval);

/**
 * @brief Stops the RTR connection and terminate the transport connection.
 * @param[in] rtr_socket rtr_socket that will be used.
 */
void rtr_stop(struct rtr_socket *rtr_socket);

/**
 * @brief Converts a rtr_socket_state to a String.
 * @param[in] state state to convert to a string
 * @return NULL If state isn't a valid rtr_socket_state
 * @return !=NULL The rtr_socket_state as String.
 */
const char *rtr_state_to_str(enum rtr_socket_state state);

void rtr_purge_records_if_outdated(struct rpki_cache *cache);
void rtr_change_socket_state(struct rtr_socket *rtr_socket, const enum rtr_socket_state new_state);

void rpki_retry_hook(struct timer *tm);
void rpki_expire_hook(struct timer *tm);
void rpki_refresh_hook(struct timer *tm);

void rtr_schedule_next_refresh(struct rpki_cache *cache);
void rtr_schedule_next_retry(struct rpki_cache *cache);
void rtr_schedule_next_expire_check(struct rpki_cache *cache);

#endif
/* @} */
