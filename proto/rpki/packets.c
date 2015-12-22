/*
 *	BIRD -- The Resource Public Key Infrastructure (RPKI) to Router Protocol
 *
 *	(c) 2015 CZ.NIC
 *
 *	This file was part of RTRlib: http://rpki.realmv6.org/
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#undef LOCAL_DEBUG

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "rpki.h"

#include "transport.h"
#include "packets.h"
#include "utils.h"
#include "rtr.h"

enum rpki_transmit_type {
  RPKI_RECV = 0,
  RPKI_SEND = 1,
};

enum pdu_error_type {
  CORRUPT_DATA = 0,
  INTERNAL_ERROR = 1,
  NO_DATA_AVAIL = 2,
  INVALID_REQUEST = 3,
  UNSUPPORTED_PROTOCOL_VER = 4,
  UNSUPPORTED_PDU_TYPE = 5,
  WITHDRAWAL_OF_UNKNOWN_RECORD = 6,
  DUPLICATE_ANNOUNCEMENT = 7,
  PDU_TOO_BIG = 32
};

enum pdu_type {
  SERIAL_NOTIFY = 0,
  SERIAL_QUERY = 1,
  RESET_QUERY = 2,
  CACHE_RESPONSE = 3,
  IPV4_PREFIX = 4,
  IPV6_PREFIX = 6,
  END_OF_DATA = 7,
  CACHE_RESET = 8,
  ROUTER_KEY = 9,
  ERROR = 10
};

static const char *str_pdu_type[] = {
    [SERIAL_NOTIFY] = "Serial Notify",
    [SERIAL_QUERY] = "Serial Query",
    [RESET_QUERY] = "Reset Query",
    [CACHE_RESPONSE] = "Cache Response",
    [IPV4_PREFIX] = "IPv4 Prefix",
    [IPV6_PREFIX] = "IPv6 Prefix",
    [END_OF_DATA] = "End of Data",
    [CACHE_RESET] = "Cache Reset",
    [ROUTER_KEY] = "Router Key",
    [ERROR] = "Error"
};

struct pdu_header {
  uint8_t ver;
  uint8_t type;
  uint16_t reserved;
  uint32_t len;
};

struct pdu_cache_response {
  uint8_t ver;
  uint8_t type;
  uint16_t session_id;
  uint32_t len;
};

struct pdu_serial_notify {
  uint8_t ver;
  uint8_t type;
  uint16_t session_id;
  uint32_t len;
  uint32_t sn;
};

struct pdu_serial_query {
  uint8_t ver;
  uint8_t type;
  uint16_t session_id;
  uint32_t len;
  uint32_t sn;
};

struct pdu_ipv4 {
  uint8_t ver;
  uint8_t type;
  uint16_t reserved;
  uint32_t len;
  uint8_t flags;
  uint8_t prefix_len;
  uint8_t max_prefix_len;
  uint8_t zero;
  uint32_t prefix;
  uint32_t asn;
};

struct pdu_ipv6 {
  uint8_t ver;
  uint8_t type;
  uint16_t reserved;
  uint32_t len;
  uint8_t flags;
  uint8_t prefix_len;
  uint8_t max_prefix_len;
  uint8_t zero;
  uint32_t prefix[4];
  uint32_t asn;
};

struct pdu_error {
  uint8_t ver;
  uint8_t type;
  uint16_t error_code;
  uint32_t len;
  uint32_t len_enc_pdu;
  uint8_t rest[];
};

/*
   0          8          16         24        31
   .-------------------------------------------.
   | Protocol |   PDU    |                     |
   | Version  |   Type   |    reserved = zero  |
   |    0     |    2     |                     |
   +-------------------------------------------+
   |                                           |
   |                 Length=8                  |
   |                                           |
   `-------------------------------------------'
 */
struct pdu_reset_query {
  uint8_t ver;
  uint8_t type;
  uint16_t flags;
  uint32_t len;
};

struct pdu_end_of_data_v0 {
  uint8_t ver;
  uint8_t type;
  uint16_t session_id;
  uint32_t len;
  uint32_t sn;
};

struct pdu_end_of_data_v1 {
  uint8_t ver;
  uint8_t type;
  uint16_t session_id;
  uint32_t len;
  uint32_t sn;
  uint32_t refresh_interval;
  uint32_t retry_interval;
  uint32_t expire_interval;
};

/* @brief pfx_record.
 * @param asn Origin AS number.
 * @param prefix IP prefix.
 * @param min_len Minimum prefix length.
 * @param max_len Maximum prefix length.
 */
struct pfx_record {
    uint32_t asn;
    ip_addr prefix;
    uint8_t min_len;
    uint8_t max_len;
};

static int rtr_send_error_pdu(struct rpki_cache *cache, const void *erroneous_pdu, const uint32_t pdu_len, const enum pdu_error_type error, const char *text, const uint32_t text_len);

static inline enum pdu_type rtr_get_pdu_type(const void *pdu)
{
  return *((char *) pdu + 1);
}

static int
pfx_table_add(struct rpki_cache *cache, const struct pfx_record *pfxr)
{
  CACHE_TRACE(D_EVENTS, cache, "Import %I/%u max %u as %u", pfxr->prefix, pfxr->min_len, pfxr->max_len, pfxr->asn);
  roa_add_item(cache->p->cf->roa_table_cf->table, pfxr->prefix, pfxr->min_len, pfxr->max_len, pfxr->asn, cache->roa_src);
  return RTR_SUCCESS;
}

static int
pfx_table_remove(struct rpki_cache *cache, const struct pfx_record *pfxr)
{
  CACHE_TRACE(D_EVENTS, cache, "Remove %I/%u max %u as %u", pfxr->prefix, pfxr->min_len, pfxr->max_len, pfxr->asn);
  roa_delete_item(cache->p->cf->roa_table_cf->table, pfxr->prefix, pfxr->min_len, pfxr->max_len, pfxr->asn, cache->roa_src);
  return RTR_SUCCESS;
}

void
pfx_table_src_remove(struct rpki_cache *cache)
{
  CACHE_TRACE(D_EVENTS, cache, "Remove all ROA entries learned from %s", get_cache_ident(cache));
  roa_flush(cache->p->cf->roa_table_cf->table, cache->roa_src);
}

void
rtr_change_socket_state(struct rtr_socket *rtr_socket, const enum rtr_socket_state new_state)
{
  const enum rtr_socket_state old_state = rtr_socket->state;

  if (old_state == new_state)
    return;

  rtr_socket->state = new_state;

  struct rpki_cache *cache = rtr_socket->cache;
  CACHE_TRACE(D_EVENTS, cache, "Change state %s -> %s", rtr_state_to_str(old_state), rtr_state_to_str(new_state));

  switch (new_state)
  {
    case RTR_CONNECTING:
      if (cache->sk == NULL || cache->sk->fd < 0)
      {
	if (rpki_open_connection(cache) == TR_SUCCESS)
	  cache->rtr_socket->state = RTR_SYNC; /* Need call a setup the bird socket in io.c loop */
      }
      else
	rtr_change_socket_state(rtr_socket, RTR_SYNC);
      break;

    case RTR_ESTABLISHED:
      /* Connection is established, socket is waiting for a Serial Notify or expiration of the refresh_interval timer */
      break;

    case RTR_RESET:
      /* Resetting RTR connection. */
      rtr_socket->request_session_id = true;
      rtr_socket->serial_number = 0;
      rtr_change_socket_state(rtr_socket, RTR_SYNC);
      break;

    case RTR_SYNC:
      /* Requesting for receive validation records from the RTR server.  */
      if (rtr_socket->request_session_id)
      {
	//change to state RESET, if socket dont has a session_id
	if (rtr_send_reset_query(cache) != RTR_SUCCESS)
	  rtr_change_socket_state(rtr_socket, RTR_ERROR_FATAL);
      }
      else
      {
	//if we already have a session_id, send a serial query and start to sync
	if (rtr_send_serial_query(cache) != RTR_SUCCESS)
	  rtr_change_socket_state(rtr_socket, RTR_ERROR_FATAL);
      }
      break;

    case RTR_ERROR_NO_INCR_UPDATE_AVAIL:
      /* Server was unable to answer the last serial or reset query. */
      rtr_purge_records_if_outdated(cache);
      /* Fall through */

    case RTR_ERROR_NO_DATA_AVAIL:
      /* No validation records are available on the RTR server. */
      rtr_change_socket_state(rtr_socket, RTR_RESET);
      break;

    case RTR_ERROR_FATAL:
      /* Fatal protocol error occurred. */
      rtr_socket->request_session_id = true;
      rtr_socket->serial_number = 0;
      rtr_socket->last_update = 0;
      pfx_table_src_remove(cache);
      /* Fall through */

    case RTR_ERROR_TRANSPORT:
      /* Error on the transport socket occurred. */
      rpki_close_connection(cache);
      rtr_schedule_next_retry(cache);
      break;

    case RTR_FAST_RECONNECT:
      /* Reconnect without any waiting period */
      rpki_close_connection(cache);
      rtr_change_socket_state(rtr_socket, RTR_CONNECTING);
      break;

    case RTR_SHUTDOWN:
      /* RTR Socket is stopped. */
      rpki_close_connection(cache);
      rtr_socket->request_session_id = true;
      rtr_socket->serial_number = 0;
      rtr_socket->last_update = 0;
      pfx_table_src_remove(cache);
      break;
  };
}

static void rtr_pdu_to_network_byte_order(void *pdu)
{
  struct pdu_header *header = pdu;

  header->reserved = htons(header->reserved);
  header->len = htonl(header->len);

  const enum pdu_type type = rtr_get_pdu_type(pdu);
  switch (type) {
    case SERIAL_QUERY:
      ((struct pdu_serial_query *) pdu)->sn = htonl(((struct pdu_serial_query *) pdu)->sn);
      break;
    case ERROR:
      ((struct pdu_error *) pdu)->len_enc_pdu = htonl(((struct pdu_error *) pdu)->len_enc_pdu);
      break;
    default:
      break;
  }
}

static void rtr_pdu_footer_to_host_byte_order(void *pdu)
{
  const enum pdu_type type = rtr_get_pdu_type(pdu);
  struct pdu_header *header = pdu;

  uint32_t addr6[4];

  switch (type)
  {
    case SERIAL_NOTIFY:
    {
      struct pdu_serial_notify *sn_pdu = pdu;
      sn_pdu->sn = ntohl(sn_pdu->sn);
      break;
    }

    case END_OF_DATA:
    {
      struct pdu_end_of_data_v0 *eod0 = pdu;
      eod0->sn = ntohl(eod0->sn); /* same either for version 1 */

      if (header->ver == RTR_PROTOCOL_VERSION_1)
      {
	struct pdu_end_of_data_v1 *eod1 = pdu;
	eod1->expire_interval = ntohl(eod1->expire_interval);
	eod1->refresh_interval = ntohl(eod1->refresh_interval);
	eod1->retry_interval = ntohl(eod1->retry_interval);
      }
      break;
    }

    case IPV4_PREFIX:
    {
      struct pdu_ipv4 *ipv4 = pdu;
      ipv4->prefix = ntohl(ipv4->prefix);
      ipv4->asn = ntohl(ipv4->asn);
      break;
    }

    case IPV6_PREFIX:
    {
      struct pdu_ipv6 *ipv6 = pdu;
      ip6_addr addr6 = ip6_ntoh(ip6_build(ipv6->prefix[0], ipv6->prefix[1], ipv6->prefix[2], ipv6->prefix[3]));
      memcpy(ipv6->prefix, &addr6, sizeof(ipv6->prefix));
      ipv6->asn = ntohl(ipv6->asn);
      break;
    }

    case ERROR:
    {
      struct pdu_error *err = pdu;
      err->len_enc_pdu = ntohl(err->len_enc_pdu);
      break;
    }
  }
}

static void rtr_pdu_header_to_host_byte_order(void *pdu)
{
  struct pdu_header *header = pdu;

  //The ROUTER_KEY PDU has two 1 Byte fields instead of the 2 Byte reserved field.
  if (header->type != ROUTER_KEY)
  {
    uint16_t reserved_tmp =  ntohs(header->reserved);
    header->reserved = reserved_tmp;
  }

  uint32_t len_tmp = ntohl(header->len);
  header->len = len_tmp;
}

static void
rpki_log_packet(struct rpki_cache *cache, const void *pdu, const size_t len, const enum rpki_transmit_type action)
{
  const char *str_type = str_pdu_type[rtr_get_pdu_type(pdu)];
  const struct pdu_header *header = pdu;

  /* Append session id and serial number */
  char additional_info[100];
  switch (header->type)
  {
    case SERIAL_NOTIFY:
    case SERIAL_QUERY:
    case END_OF_DATA:
      bsnprintf(additional_info, 100, "(session id: %u, serial number: %u)", header->reserved, ((struct pdu_end_of_data_v0 *)header)->sn);
      break;

    case CACHE_RESPONSE:
      bsnprintf(additional_info, 100, "(session id: %u)", header->reserved);
      break;

    default:
      *additional_info = '\0';
  }

  if (action == RPKI_RECV)
  {
    CACHE_TRACE(D_PACKETS, cache, "Receive a %s packet %s", str_type, additional_info);
  }
  else
  {
    CACHE_TRACE(D_PACKETS, cache, "Send a %s packet %s", str_type, additional_info);
  }

  int seq = 0;
  for(const byte *c = pdu; c != pdu + len; c++)
  {
    if ((seq % 4) == 0)
      DBG("%2d: ", seq);

    DBG("  0x%02X %-3u", *c, *c);

    if ((++seq % 4) == 0)
      DBG("\n");
  }
  if ((seq % 4) != 0)
    DBG("\n");
}

static int
rtr_send_pdu(struct rpki_cache *cache, const void *pdu, const unsigned len)
{
  const struct rtr_socket *rtr_socket = cache->rtr_socket;
  struct rpki_proto *p = cache->p;
  sock *sk = cache->sk;

  if (!sk)
  {
    RPKI_WARN(p, "Want send a %s packet, but the bird socket is NULL!", str_pdu_type[rtr_get_pdu_type(pdu)]);
    ASSERT(0);
    return RTR_ERROR;
  }

  if (sk->fd < 0)
  {
    RPKI_WARN(p, "Want send a %s packet, but the bird socket FD is %d!", str_pdu_type[rtr_get_pdu_type(pdu)], sk->fd);
    ASSERT(0);
    return RTR_ERROR;
  }

  if (rtr_socket->state == RTR_SHUTDOWN)
  {
    RPKI_WARN(p, "Want send a %s packet, but the rtr_socket state is SHUTDOWN!", str_pdu_type[rtr_get_pdu_type(pdu)]);
    ASSERT(0);
    return RTR_ERROR;
  }

  rpki_log_packet(cache, pdu, len, RPKI_SEND);

  byte pdu_converted[len];
  memcpy(pdu_converted, pdu, len);
  rtr_pdu_to_network_byte_order(pdu_converted);

  sk->tbuf = pdu_converted;
  if (!sk_send(sk, len))
  {
    DBG("Cannot send just the whole data. It will be sended via a call of tx_hook()");
  }

  return RTR_SUCCESS;
}

/**
 * rtr_check_receive_packet - Make a basic validation of received RPKI PDU header:
 *  - check protocol version
 *  - check pdu type
 *  - check size
 *
 * @cache cache connection
 * @param len must <= RTR_MAX_PDU_LEN bytes
 * @return RTR_SUCCESS
 * @return RTR_ERROR, error pdu was sent
 */
static int
rtr_check_receive_packet(struct rpki_cache *cache, void *pdu, const size_t len)
{
  struct rtr_socket *rtr_socket = cache->rtr_socket;
  struct rpki_proto *p = cache->p;
  int error = RTR_SUCCESS;

  // header in hostbyte order, retain original received pdu, in case we need to detach it to an error pdu
  struct pdu_header header;
  memcpy(&header, pdu, sizeof(header));
  rtr_pdu_header_to_host_byte_order(&header);

  if (rtr_socket->state == RTR_SHUTDOWN)
  {
    RPKI_WARN(p, "Received %s packet, but rtr_socket->state == RTR_SHUTDOWN", str_pdu_type[header.type]);
    ASSERT(rtr_socket->state != RTR_SHUTDOWN);
    return RTR_ERROR;
  }

  // Do not handle error PDUs here, leave this task to rtr_handle_error_pdu()
  if (header.ver != rtr_socket->version && header.type != ERROR)
  {
    // If this is the first PDU we have received -> Downgrade.
    if (rtr_socket->request_session_id == true && rtr_socket->last_update == 0
	&& header.ver >= RTR_PROTOCOL_MIN_SUPPORTED_VERSION
	&& header.ver <= RTR_PROTOCOL_MAX_SUPPORTED_VERSION
	&& header.ver < rtr_socket->version)
    {
      CACHE_TRACE(D_EVENTS, cache, "Downgrade session to %s from %u to %u version", get_cache_ident(cache), rtr_socket->version, header.ver);
      rtr_socket->version = header.ver;
    }
    else
    {
      // If this is not the first PDU we have received, something is wrong with
      // the server implementation -> Error
      error = UNSUPPORTED_PROTOCOL_VER;
      goto error;
    }
  }

  if ((header.type > 10) || (header.ver == RTR_PROTOCOL_VERSION_0 && header.type == ROUTER_KEY))
  {
    error = UNSUPPORTED_PDU_TYPE;
    goto error;
  }

  if (header.len < sizeof(header))
  {
    //if header->len is < packet_header = corrupt data received
    error = CORRUPT_DATA;
    goto error;
  }
  else if (header.len > RPKI_PDU_MAX_LEN)
  {
    //PDU too big, > than MAX_PDU_LEN Bytes
    error = PDU_TOO_BIG;
    goto error;
  }

  if (header.type == IPV4_PREFIX || header.type == IPV6_PREFIX) {
    if (((struct pdu_ipv4 *) pdu)->zero != 0)
      CACHE_TRACE(D_PACKETS, cache, "Warning: Zero field of received Prefix PDU doesn't contain 0");
  }

  return RTR_SUCCESS;

 error:
  //send error msg to server, including unmodified pdu header(pdu variable instead header)
  switch (error)
  {
    case CORRUPT_DATA:
    {
      const char *txt = "Corrupt data received, length value in PDU is too small";
      CACHE_TRACE(D_PACKETS, cache, "%s", txt);
      rtr_send_error_pdu(cache, pdu, sizeof(header), CORRUPT_DATA, txt, sizeof(txt));
      break;
    }

    case PDU_TOO_BIG:
    {
      char txt2[64];
      snprintf(txt2, sizeof(txt2),"PDU too big, max. PDU size is: %u bytes", RPKI_PDU_MAX_LEN);
      CACHE_TRACE(D_EVENTS, cache, "%s", txt2);
      rtr_send_error_pdu(cache, pdu, sizeof(header), CORRUPT_DATA, txt2, strlen(txt2)+1);
      break;
    }

    case UNSUPPORTED_PDU_TYPE:
      CACHE_DBG(cache, "Unsupported PDU type %zu received", header.type);
      rtr_send_error_pdu(cache, pdu, header.len, UNSUPPORTED_PDU_TYPE, NULL, 0);
      break;

    case UNSUPPORTED_PROTOCOL_VER:
      CACHE_TRACE(D_EVENTS, cache, "PDU with unsupported Protocol version received");
      rtr_send_error_pdu(cache, pdu, header.len, UNSUPPORTED_PROTOCOL_VER, NULL, 0);
      break;

    default:
      bug("Uncatched error");
  }

  return RTR_ERROR;
}

static int
rtr_handle_error_pdu(struct rtr_socket *rtr_socket, const void *buf)
{
  struct rpki_cache *cache = rtr_socket->cache;
  struct rpki_proto *p = cache->p;
  const struct pdu_error *pdu = buf;

  const uint32_t len_err_txt = ntohl(*((uint32_t *) (pdu->rest + pdu->len_enc_pdu)));
  if (len_err_txt > 0)
  {
    if ((sizeof(pdu->ver) + sizeof(pdu->type) + sizeof(pdu->error_code) + sizeof(pdu->len) + sizeof(pdu->len_enc_pdu) + pdu->len_enc_pdu + 4 + len_err_txt) != pdu->len)
      CACHE_TRACE(D_PACKETS, cache, "Error: Length of error text contains an incorrect value");
    else
    {
      //assure that the error text contains an terminating \0 char
      char txt[len_err_txt + 1];
      char *pdu_txt = (char *) pdu->rest + pdu->len_enc_pdu + 4;
      snprintf(txt, len_err_txt + 1, "%s", pdu_txt);
      CACHE_TRACE(D_PACKETS, cache, "Error PDU included the following error msg: \'%s\'", txt);
    }
  }

  switch (pdu->error_code)
  {
    case CORRUPT_DATA:
      CACHE_TRACE(D_PACKETS, cache, "Corrupt data received");
      rtr_change_socket_state(rtr_socket, RTR_ERROR_FATAL);
      break;

    case INTERNAL_ERROR:
      CACHE_TRACE(D_PACKETS, cache, "Internal error on server-side");
      rtr_change_socket_state(rtr_socket, RTR_ERROR_FATAL);
      break;

    case NO_DATA_AVAIL:
      CACHE_TRACE(D_PACKETS, cache, "No data available");
      rtr_change_socket_state(rtr_socket, RTR_ERROR_NO_DATA_AVAIL);
      break;

    case INVALID_REQUEST:
      CACHE_TRACE(D_PACKETS, cache, "Invalid request from client");
      rtr_change_socket_state(rtr_socket, RTR_ERROR_FATAL);
      break;

    case UNSUPPORTED_PROTOCOL_VER:
      CACHE_TRACE(D_PACKETS, cache, "Client uses unsupported protocol version");
      if (pdu->ver <= RTR_PROTOCOL_MAX_SUPPORTED_VERSION &&
	  pdu->ver >= RTR_PROTOCOL_MIN_SUPPORTED_VERSION &&
	  pdu->ver < rtr_socket->version)
      {
	CACHE_TRACE(D_EVENTS, cache, "Downgrading from %i to version %i", rtr_socket->version, pdu->ver);
	rtr_socket->version = pdu->ver;
	rtr_change_socket_state(rtr_socket, RTR_FAST_RECONNECT);
      }
      else
      {
	CACHE_TRACE(D_PACKETS, cache, "Got UNSUPPORTED_PROTOCOL_VER error PDU with invalid values, " \
		   "current version: %i, PDU version: %i", rtr_socket->version, pdu->ver);
	rtr_change_socket_state(rtr_socket, RTR_ERROR_FATAL);
      }
      break;

    case UNSUPPORTED_PDU_TYPE:
      CACHE_TRACE(D_PACKETS, cache, "Client set unsupported PDU type");
      rtr_change_socket_state(rtr_socket, RTR_ERROR_FATAL);
      break;

    default:
      CACHE_TRACE(D_PACKETS, cache, "error unknown, server sent unsupported error code %u", pdu->error_code);
      rtr_change_socket_state(rtr_socket, RTR_ERROR_FATAL);
      break;
  }

  return RTR_SUCCESS;
}

static int rtr_handle_cache_response_pdu(struct rpki_cache *cache, char *pdu)
{
  struct rtr_socket *rtr_socket = cache->rtr_socket;
  struct pdu_cache_response *cr_pdu = (struct pdu_cache_response *) pdu;
  //set connection session_id
  if (rtr_socket->request_session_id)
  {
    if (rtr_socket->last_update != 0)
    {
      //if this isnt the first sync, but we already received records, delete old records in the pfx_table
      roa_flush(cache->p->cf->roa_table_cf->table, cache->roa_src);
      rtr_socket->last_update = 0;
    }
    rtr_socket->session_id = cr_pdu->session_id;
    rtr_socket->request_session_id = false;
  }
  else
  {
    if (rtr_socket->session_id != cr_pdu->session_id)
    {
      char txt[100];
      snprintf(txt, 100, "Wrong session_id %u in Cache Response PDU", cr_pdu->session_id);
      rtr_send_error_pdu(cache, NULL, 0, CORRUPT_DATA, txt, strlen(txt)+1);
      rtr_change_socket_state(rtr_socket, RTR_ERROR_FATAL);
      return RTR_ERROR;
    }
  }
  return RTR_SUCCESS;
}

static void
rtr_prefix_pdu_2_pfx_record(const struct rtr_socket *rtr_socket, const void *pdu, struct pfx_record *pfxr, const enum pdu_type type)
{
  assert(type == IPV4_PREFIX || type == IPV6_PREFIX);
  if (type == IPV4_PREFIX)
  {
    const struct pdu_ipv4 *ipv4 = pdu;
    pfxr->prefix = ip4_from_u32(ipv4->prefix);
    pfxr->asn = ipv4->asn;
    pfxr->min_len = ipv4->prefix_len;
    pfxr->max_len = ipv4->max_prefix_len;
  }
  else if (type == IPV6_PREFIX)
  {
    const struct pdu_ipv6 *ipv6 = pdu;
    memcpy(&pfxr->prefix, ipv6->prefix, sizeof(pfxr->prefix));
    pfxr->asn = ipv6->asn;
    pfxr->min_len = ipv6->prefix_len;
    pfxr->max_len = ipv6->max_prefix_len;
  }
}

static int
rtr_update_pfx_table(struct rpki_cache *cache, const void *pdu)
{
  struct rtr_socket *rtr_socket = cache->rtr_socket;
  struct rpki_proto *p = cache->p;

  const enum pdu_type type = rtr_get_pdu_type(pdu);
  assert(type == IPV4_PREFIX || type == IPV6_PREFIX);

#ifdef IPV6
  if (type == IPV4_PREFIX)
#else
  if (type == IPV6_PREFIX)
#endif
  {
    CACHE_DBG(cache, "Skip %s prefix", (type == IPV4_PREFIX) ? "IPv4" : "IPv6");
    return RTR_ERROR;
  }

  struct pfx_record pfxr;
  size_t pdu_size = (type == IPV4_PREFIX ? sizeof(struct pdu_ipv4) : sizeof(struct pdu_ipv6));
  rtr_prefix_pdu_2_pfx_record(rtr_socket, pdu, &pfxr, type);

  int rtval;
  switch (((struct pdu_ipv4 *) pdu)->flags)
  {
    case 1:
      rtval = pfx_table_add(cache, &pfxr);
      break;

    case 0:
      rtval = pfx_table_remove(cache, &pfxr);
      break;

    default:
    {
      const char *txt = "Prefix PDU with invalid flags value received";
      CACHE_DBG(cache, "%s", txt);
      rtr_send_error_pdu(cache, pdu, pdu_size, CORRUPT_DATA, txt, sizeof(txt));
      return RTR_ERROR;
    }
  }

  return RTR_SUCCESS;
}

static void
rtr_handle_end_of_data_pdu(struct rpki_cache *cache, void *pdu)
{
  struct rtr_socket *rtr_socket = cache->rtr_socket;
  struct pdu_end_of_data_v1 *eod_pdu = pdu;
  struct rpki_proto *p = cache->p;

  if (eod_pdu->ver == RTR_PROTOCOL_VERSION_1)
  {
    rtr_socket->expire_interval = eod_pdu->expire_interval;
    rtr_socket->refresh_interval = eod_pdu->refresh_interval;
    rtr_socket->retry_interval = eod_pdu->retry_interval;
    CACHE_TRACE(D_EVENTS, cache, "New interval values: " 	\
	       "expire_interval: %us, " 			\
	       "refresh_interval: %us, " 			\
	       "retry_interval: %us", 				\
	       rtr_socket->expire_interval, rtr_socket->refresh_interval, rtr_socket->retry_interval);
  }

  if (eod_pdu->session_id != rtr_socket->session_id)
  {
    char txt[67];
    snprintf(txt, sizeof(txt),"Received session_id %u, but expected was session_id %u", eod_pdu->session_id, rtr_socket->session_id);
    CACHE_TRACE(D_EVENTS, cache, "%s", txt);
    rtr_send_error_pdu(cache, pdu, eod_pdu->len, CORRUPT_DATA, txt, strlen(txt) + 1);
    rtr_change_socket_state(rtr_socket, RTR_ERROR_FATAL);
  }

  rtr_socket->last_update = now;
  rtr_socket->serial_number = eod_pdu->sn;
  rtr_change_socket_state(rtr_socket, RTR_ESTABLISHED);
  rtr_schedule_next_refresh(cache);
  rtr_schedule_next_expire_check(cache);
}

static void
rtr_transform_pdu_to_host_byte_order(byte *pdu)
{
  rtr_pdu_header_to_host_byte_order(pdu);
  rtr_pdu_footer_to_host_byte_order(pdu);
}

static void
rpki_rx_packet(struct rpki_cache *cache, byte *pdu, uint len)
{
  struct rtr_socket *rtr_socket = cache->rtr_socket;
  struct rpki_proto *p = cache->p;
  enum pdu_type type = rtr_get_pdu_type(pdu);

  if (rtr_check_receive_packet(cache, pdu, len) == RTR_ERROR)
  {
    rtr_change_socket_state(rtr_socket, RTR_ERROR_FATAL);
    return;
  }

  rtr_transform_pdu_to_host_byte_order(pdu);
  rpki_log_packet(cache, pdu, len, RPKI_RECV);

  switch (type)
  {
    case RESET_QUERY:
    case SERIAL_QUERY:
      RPKI_WARN(p, "Received a %s packet that is destined for cache server", str_pdu_type[type]);
      break;

    case SERIAL_NOTIFY:
      /* Need synchronize with cache server right now */
      rtr_change_socket_state(rtr_socket, RTR_SYNC);
      break;

    case CACHE_RESPONSE:
      rtr_handle_cache_response_pdu(cache, pdu);
      break;

    case IPV4_PREFIX:
    case IPV6_PREFIX:
      rtr_update_pfx_table(cache, pdu);
      break;

    case END_OF_DATA:
      rtr_handle_end_of_data_pdu(cache, pdu);
      break;

    case CACHE_RESET:
      /* The cache may respond to a Serial Query informing the router that the
       * cache cannot provide an incremental update starting from the Serial
       * Number specified by the router.  The router must decide whether to
       * issue a Reset Query or switch to a different cache. */
      rtr_change_socket_state(rtr_socket, RTR_ERROR_NO_INCR_UPDATE_AVAIL);
      break;

    case ERROR:
      rtr_handle_error_pdu(cache->rtr_socket, pdu);
      break;

    case ROUTER_KEY:
    default:
      CACHE_TRACE(D_PACKETS, cache, "Received unsupported type of RPKI PDU (%u)", type);
  };
}

int
rpki_rx_hook(struct birdsock *sk, int size)
{
  struct rpki_cache *cache = sk->data;
  struct rpki_proto *p = cache->p;

  byte *pkt_start = sk->rbuf;
  byte *end = pkt_start + size;
  unsigned i, len;

  DBG("Rx hook got %d bytes", size);

  while (end >= pkt_start + RPKI_PDU_HEADER_LEN)
  {
    struct pdu_header header;
    memcpy(&header, pkt_start, sizeof(header));
    rtr_pdu_header_to_host_byte_order(&header);

    if (header.len < RPKI_PDU_HEADER_LEN || header.len > RPKI_PDU_MAX_LEN)
    {
      RPKI_WARN(p, "Received invalid packet length %u. Purge the whole receive buffer.", header.len);
      return 1; /* Purge recv buffer */
    }

    if (end < pkt_start + header.len)
      break;

    rpki_rx_packet(cache, pkt_start, header.len);

    /* It is possible that bird socket was freed/closed */
    if (sk != cache->sk)
      return 0;

    pkt_start += header.len;
  }

  if (pkt_start != sk->rbuf)
  {
    memmove(sk->rbuf, pkt_start, end - pkt_start);
    sk->rpos = sk->rbuf + (end - pkt_start);
  }

  return 0; /* Not purge sk->rbuf */
}

void
rpki_err_hook(struct birdsock *sk, int error_num)
{
  struct rpki_cache *cache = sk->data;
  struct rpki_proto *p = cache->p;

  if (error_num && sk->err == NULL)
  {
    CACHE_TRACE(D_EVENTS, cache, "Connection lost %s: %M", get_cache_ident(cache), error_num);
  }
  else
  {
    CACHE_TRACE(D_EVENTS, cache, "Connection lost %s: %s", get_cache_ident(cache), sk->err);
  }

  rtr_change_socket_state(cache->rtr_socket, RTR_ERROR_TRANSPORT);
}

static int
rpki_fire_tx(struct rpki_cache *cache)
{
  struct rpki_proto *p = cache->p;
  sock *sk = cache->sk;

  uint bytes_to_send = sk->tpos - sk->tbuf;
  DBG("Sending %u bytes", bytes_to_send);
  return sk_send(sk, bytes_to_send);
}

void
rpki_kick_tx(sock *sk)
{
  struct rpki_cache *cache = sk->data;
  struct rpki_proto *p = cache->p;
  struct tr_socket *tr = cache->rtr_socket->tr_socket;

  while (rpki_fire_tx(cache) > 0)
    ;
}

void
rpki_tx_hook(sock *sk)
{
  struct rpki_cache *cache = sk->data;
  struct rpki_proto *p = cache->p;
  struct tr_socket *tr = cache->rtr_socket->tr_socket;

  while (rpki_fire_tx(cache) > 0)
    ;
}

void
rpki_connected_hook(sock *sk)
{
  struct rpki_cache *cache = sk->data;
  struct rpki_proto *p = cache->p;

  CACHE_TRACE(D_EVENTS, cache, "Connected to %s", get_cache_ident(cache));

  sk->rx_hook = rpki_rx_hook;
  sk->tx_hook = rpki_tx_hook;

  rtr_change_socket_state(cache->rtr_socket, RTR_CONNECTING);
}

int rtr_send_error_pdu(struct rpki_cache *cache, const void *erroneous_pdu, const uint32_t pdu_len, const enum pdu_error_type error, const char *text, const uint32_t text_len)
{
  const struct rtr_socket *rtr_socket = cache->rtr_socket;

  //dont send errors for erroneous error PDUs
  if (pdu_len >= 2)
  {
    if (rtr_get_pdu_type(erroneous_pdu) == ERROR)
      return RTR_SUCCESS;
  }

  unsigned int msg_size = 16 + pdu_len + text_len;
  char msg[msg_size];
  struct pdu_header *header = (struct pdu_header *) msg;
  header->ver = rtr_socket->version;
  header->type = 10;
  header->reserved = error;
  header->len = msg_size;

  memcpy(msg+8, &pdu_len, sizeof(pdu_len));
  if (pdu_len > 0)
    memcpy(msg + 12, erroneous_pdu, pdu_len);
  *(msg + 12 + pdu_len) = htonl(text_len);
  if (text_len > 0)
    memcpy(msg+16+pdu_len, text, text_len);

  return rtr_send_pdu(cache, msg, msg_size);
}

int rtr_send_serial_query(struct rpki_cache *cache)
{
  struct rtr_socket *rtr_socket = cache->rtr_socket;
  struct pdu_serial_query pdu;
  pdu.ver = rtr_socket->version;
  pdu.type = SERIAL_QUERY;
  pdu.session_id = rtr_socket->session_id;
  pdu.len = sizeof(pdu);
  pdu.sn = rtr_socket->serial_number;

  if (rtr_send_pdu(cache, &pdu, sizeof(pdu)) != RTR_SUCCESS) {
    rtr_change_socket_state(rtr_socket, RTR_ERROR_TRANSPORT);
    return RTR_ERROR;
  }
  return RTR_SUCCESS;
}

int rtr_send_reset_query(struct rpki_cache *cache)
{
  struct rtr_socket *rtr_socket = cache->rtr_socket;
  CACHE_TRACE(D_EVENTS, cache, "Sending reset query");
  struct pdu_reset_query pdu = {
      .ver = rtr_socket->version,
      .type = RESET_QUERY,
      .len = 8,
  };

  if (rtr_send_pdu(cache, &pdu, sizeof(pdu)) != RTR_SUCCESS) {
    rtr_change_socket_state(rtr_socket, RTR_ERROR_TRANSPORT);
    return RTR_ERROR;
  }
  return RTR_SUCCESS;
}
