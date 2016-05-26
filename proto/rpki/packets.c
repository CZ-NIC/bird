/*
 *	BIRD -- The Resource Public Key Infrastructure (RPKI) to Router Protocol
 *
 *	(c) 2015 CZ.NIC
 *
 *	This file was a part of RTRlib: http://rpki.realmv6.org/
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>

#undef LOCAL_DEBUG

#include "rpki.h"
#include "transport.h"
#include "packets.h"

#define RPKI_ADD_FLAG 		1
#define RPKI_DELETE_FLAG	0

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

/*
   0          8          16         24        31
   .-------------------------------------------.
   | Protocol |   PDU    |                     |
   | Version  |   Type   |    reserved = zero  |
   |  0 or 1  |  0 - 10  |                     |
   +-------------------------------------------+
   |                                           |
   |                 Length >= 8               |
   |                                           |
   `-------------------------------------------'
 */

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

struct pdu_router_key {
    uint8_t ver;
    uint8_t type;
    uint8_t flags;
    uint8_t zero;
    uint32_t len;
    uint8_t ski[RPKI_SKI_SIZE];
    uint32_t asn;
    uint8_t spki[RPKI_SPKI_SIZE];
};

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

static int rpki_send_error_pdu(struct rpki_cache *cache, const void *erroneous_pdu, const uint32_t pdu_len, const enum pdu_error_type error, const char *text, const uint32_t text_len);

static inline enum
pdu_type get_pdu_type(const void *pdu)
{
  return *((char *) pdu + 1);
}

static void
rpki_table_add_roa(struct rpki_cache *cache, struct channel *channel, const net_addr_union *pfxr)
{
  struct rpki_proto *p = cache->p;

  CACHE_TRACE(D_ROUTES, cache, "Importing route %N", pfxr);

  net *n = net_get(channel->table, &pfxr->n);

  rta a0 = {
      .src = p->p.main_source,
      .source = RTS_RPKI,
      .scope = SCOPE_UNIVERSE,
      .cast = RTC_UNICAST,
      .dest = RTD_BLACKHOLE,
  };

  rta *a = rta_lookup(&a0);
  rte *e = rte_get_temp(a);

  e->net = n;
  e->pflags = 0;

  rte_update2(channel, &pfxr->n, e, a0.src);
}

static void
rpki_table_remove_roa(struct rpki_cache *cache, struct channel *channel, const net_addr_union *pfxr)
{
  struct rpki_proto *p = cache->p;

  CACHE_TRACE(D_ROUTES, cache, "Removing route %N", pfxr);

  rte_update(&p->p, &pfxr->n, NULL);
}

void
rpki_table_remove_all(struct rpki_cache *cache)
{
  CACHE_TRACE(D_ROUTES, cache, "Removing all routes");

  if (cache->roa4_channel && cache->roa4_channel->channel_state != CS_DOWN)
    channel_close(cache->roa4_channel);

  if (cache->roa6_channel && cache->roa6_channel->channel_state != CS_DOWN)
    channel_close(cache->roa6_channel);
}

static void
rpki_pdu_to_network_byte_order(void *pdu)
{
  struct pdu_header *header = pdu;

  header->reserved = htons(header->reserved);
  header->len = htonl(header->len);

  const enum pdu_type type = get_pdu_type(pdu);
  switch (type)
  {
  case SERIAL_QUERY:
  {
    struct pdu_serial_query *sq_pdu = pdu;
    sq_pdu->sn = htonl(sq_pdu->sn);
    break;
  }

  case ERROR:
  {
    struct pdu_error *err_pdu = pdu;
    err_pdu->len_enc_pdu = htonl(err_pdu->len_enc_pdu);
    break;
  }

  case RESET_QUERY:
    break;

  default:
    bug("PDU type %s should not be sent by router!", str_pdu_type[type]);
  }
}

static void
rpki_pdu_header_to_host_byte_order(void *pdu)
{
  struct pdu_header *header = pdu;

  /* The ROUTER_KEY PDU has two 1 Byte fields instead of the 2 Byte reserved field. */
  if (header->type != ROUTER_KEY)
  {
    uint16_t reserved_tmp =  ntohs(header->reserved);
    header->reserved = reserved_tmp;
  }

  uint32_t len_tmp = ntohl(header->len);
  header->len = len_tmp;
}

static void
rpki_pdu_body_to_host_byte_order(void *pdu)
{
  const enum pdu_type type = get_pdu_type(pdu);
  struct pdu_header *header = pdu;

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

    if (header->ver == RPKI_VERSION_1)
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

  case ROUTER_KEY:
  {
    struct pdu_router_key *rk = pdu;
    rk->asn = ntohl(rk->asn);
    break;
  }

  case SERIAL_QUERY:
  case RESET_QUERY:
  case CACHE_RESPONSE:
  case CACHE_RESET:
    break;
  }
}

static void
rpki_log_packet(struct rpki_cache *cache, const void *pdu, const size_t len, const enum rpki_transmit_type action)
{
  if (!(cache->p->p.debug & D_PACKETS))
    return;

  const char *str_type = str_pdu_type[get_pdu_type(pdu)];
  const struct pdu_header *header = pdu;

  char detail[100];
  switch (header->type)
  {
  case SERIAL_NOTIFY:
  case SERIAL_QUERY:
  case END_OF_DATA:
    bsnprintf(detail, sizeof(detail), "(session id: %u, serial number: %u)", header->reserved, ((struct pdu_end_of_data_v0 *) header)->sn);
    break;

  case CACHE_RESPONSE:
    bsnprintf(detail, sizeof(detail), "(session id: %u)", header->reserved);
    break;

  case IPV4_PREFIX:
  {
    const struct pdu_ipv4 *ipv4 = pdu;
    bsnprintf(detail, sizeof(detail), "(%I4/%u-%u AS%u)", ip4_from_u32(ipv4->prefix), ipv4->prefix_len, ipv4->max_prefix_len, ipv4->asn);
    break;
  }

  case IPV6_PREFIX:
  {
    const struct pdu_ipv6 *ipv6 = pdu;
    ip6_addr a = ip6_build(ipv6->prefix[0], ipv6->prefix[1], ipv6->prefix[2], ipv6->prefix[3]);
    bsnprintf(detail, sizeof(detail), "(%I6/%u-%u AS%u)", a, ipv6->prefix_len, ipv6->max_prefix_len, ipv6->asn);
    break;
  }

  case ROUTER_KEY:
  {
    const struct pdu_router_key *rk = pdu;
    bsnprintf(detail, sizeof(detail), "(AS%u %02x", rk->asn, rk->ski[0]);
    for (const u8 *x = &rk->ski[1]; x < &rk->ski[RPKI_SKI_SIZE]; x++)
      bsnprintf(detail+strlen(detail), sizeof(detail)-strlen(detail), ":%02x", *x);
    bsnprintf(detail+strlen(detail), sizeof(detail)-strlen(detail), ")");
    break;
  }

  default:
    *detail = '\0';
  }

  if (action == RPKI_RECV)
  {
    CACHE_TRACE(D_PACKETS, cache, "Received a %s packet %s", str_type, detail);
  }
  else
  {
    CACHE_TRACE(D_PACKETS, cache, "Sending a %s packet %s", str_type, detail);
  }

#if defined(LOCAL_DEBUG) || defined(GLOBAL_DEBUG)
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
#endif
}

static int
rpki_send_pdu(struct rpki_cache *cache, const void *pdu, const unsigned len)
{
  struct rpki_proto *p = cache->p;
  sock *sk = cache->tr_sock->sk;

  if (!sk)
  {
    RPKI_WARN(p, "Want send a %s packet, but the bird socket is NULL!", str_pdu_type[get_pdu_type(pdu)]);
    ASSERT(0);
    return RPKI_ERROR;
  }

  if (sk->fd < 0)
  {
    RPKI_WARN(p, "Want send a %s packet, but the bird socket FD is %d!", str_pdu_type[get_pdu_type(pdu)], sk->fd);
    ASSERT(0);
    return RPKI_ERROR;
  }

  if (cache->state == RPKI_CS_SHUTDOWN)
  {
    RPKI_WARN(p, "Want send a %s packet, but the protocol state is SHUTDOWN!", str_pdu_type[get_pdu_type(pdu)]);
    ASSERT(0);
    return RPKI_ERROR;
  }

  rpki_log_packet(cache, pdu, len, RPKI_SEND);

  byte pdu_converted[len];
  memcpy(pdu_converted, pdu, len);
  rpki_pdu_to_network_byte_order(pdu_converted);

  sk->tbuf = pdu_converted;
  if (!sk_send(sk, len))
  {
    DBG("Cannot send just the whole data. It will be sent using a call of tx_hook()");
  }

  return RPKI_SUCCESS;
}

/**
 * rpki_check_receive_packet - Make a basic validation of received RPKI PDU header
 * @cache: cache connection
 * @pdu: RPKI PDU
 * @len: length of @pdu
 *
 * It checks protocol version, PDU type and PDU size. If all good then
 * function returns %RPKI_SUCCESS otherwise sends Error PDU and returns %RPKI_ERROR
 */
static int
rpki_check_receive_packet(struct rpki_cache *cache, const void *pdu, const size_t len)
{
  struct rpki_proto *p = cache->p;
  int error = RPKI_SUCCESS;

  // header in hostbyte order, retain original received pdu, in case we need to detach it to an error pdu
  struct pdu_header header;
  memcpy(&header, pdu, sizeof(header));
  rpki_pdu_header_to_host_byte_order(&header);

  if (cache->state == RPKI_CS_SHUTDOWN)
  {
    RPKI_WARN(p, "Received %s packet, but cache->state == RPKI_CACHE_SHUTDOWN", str_pdu_type[header.type]);
    ASSERT(cache->state != RPKI_CS_SHUTDOWN);
    return RPKI_ERROR;
  }

  // Do not handle error PDUs here, leave this task to rtr_handle_error_pdu()
  if (header.ver != cache->version && header.type != ERROR)
  {
    // If this is the first PDU we have received -> Downgrade.
    if (cache->request_session_id && cache->last_update == 0
	&& header.ver >= RPKI_MIN_VERSION
	&& header.ver <= RPKI_MAX_VERSION
	&& header.ver < cache->version)
    {
      CACHE_TRACE(D_EVENTS, cache, "Downgrade session to %s from %u to %u version", rpki_get_cache_ident(cache), cache->version, header.ver);
      cache->version = header.ver;
    }
    else
    {
      // If this is not the first PDU we have received, something is wrong with
      // the server implementation -> Error
      error = UNSUPPORTED_PROTOCOL_VER;
      goto error;
    }
  }

  if ((header.type > 10) || (header.ver == RPKI_VERSION_0 && header.type == ROUTER_KEY))
  {
    error = UNSUPPORTED_PDU_TYPE;
    goto error;
  }

  if (header.len < sizeof(header))
  {
    error = CORRUPT_DATA;
    goto error;
  }
  else if (header.len > RPKI_PDU_MAX_LEN)
  {
    error = PDU_TOO_BIG;
    goto error;
  }

  if (header.type == IPV4_PREFIX || header.type == IPV6_PREFIX) {
    if (((struct pdu_ipv4 *) pdu)->zero != 0)
      CACHE_TRACE(D_PACKETS, cache, "Warning: Zero field of received Prefix PDU doesn't contain 0");
  }

  return RPKI_SUCCESS;

error:

  /* Send error msg to server, including unmodified pdu header (pdu variable instead header) */

  switch (error)
  {
  case CORRUPT_DATA:
  {
    const char *txt = "Corrupt data received, length value in PDU is too small";
    CACHE_TRACE(D_PACKETS, cache, "%s", txt);
    rpki_send_error_pdu(cache, pdu, sizeof(header), CORRUPT_DATA, txt, sizeof(txt));
    break;
  }

  case PDU_TOO_BIG:
  {
    char txt2[64];
    bsnprintf(txt2, sizeof(txt2),"PDU too big, max. PDU size is: %u bytes", RPKI_PDU_MAX_LEN);
    CACHE_TRACE(D_EVENTS, cache, "%s", txt2);
    rpki_send_error_pdu(cache, pdu, sizeof(header), CORRUPT_DATA, txt2, strlen(txt2)+1);
    break;
  }

  case UNSUPPORTED_PDU_TYPE:
    CACHE_DBG(cache, "Unsupported PDU type %zu received", header.type);
    rpki_send_error_pdu(cache, pdu, header.len, UNSUPPORTED_PDU_TYPE, NULL, 0);
    break;

  case UNSUPPORTED_PROTOCOL_VER:
    CACHE_TRACE(D_EVENTS, cache, "PDU with unsupported Protocol version received");
    rpki_send_error_pdu(cache, pdu, header.len, UNSUPPORTED_PROTOCOL_VER, NULL, 0);
    break;

  default:
    bug("Uncaught error");
  }

  return RPKI_ERROR;
}

static int
rpki_handle_error_pdu(struct rpki_cache *cache, const void *buf)
{
  const struct pdu_error *pdu = buf;

  const uint32_t len_err_txt = ntohl(*((uint32_t *) (pdu->rest + pdu->len_enc_pdu)));
  if (len_err_txt > 0)
  {
    if ((sizeof(pdu->ver) + sizeof(pdu->type) + sizeof(pdu->error_code) + sizeof(pdu->len) + sizeof(pdu->len_enc_pdu) + pdu->len_enc_pdu + 4 + len_err_txt) != pdu->len)
      CACHE_TRACE(D_PACKETS, cache, "Error: Length of error text contains an incorrect value");
    else
    {
      char txt[len_err_txt + 1];
      char *pdu_txt = (char *) pdu->rest + pdu->len_enc_pdu + 4;
      bsnprintf(txt, sizeof(txt), "%s", pdu_txt);
      CACHE_TRACE(D_PACKETS, cache, "Error PDU included the following error msg: '%s'", txt);
    }
  }

  switch (pdu->error_code)
  {
  case CORRUPT_DATA:
    CACHE_TRACE(D_PACKETS, cache, "Corrupt data received");
    rpki_cache_change_state(cache, RPKI_CS_ERROR_FATAL);
    break;

  case INTERNAL_ERROR:
    CACHE_TRACE(D_PACKETS, cache, "Internal error on server-side");
    rpki_cache_change_state(cache, RPKI_CS_ERROR_FATAL);
    break;

  case NO_DATA_AVAIL:
    CACHE_TRACE(D_PACKETS, cache, "No data available");
    rpki_cache_change_state(cache, RPKI_CS_ERROR_NO_DATA_AVAIL);
    break;

  case INVALID_REQUEST:
    CACHE_TRACE(D_PACKETS, cache, "Invalid request from client");
    rpki_cache_change_state(cache, RPKI_CS_ERROR_FATAL);
    break;

  case UNSUPPORTED_PROTOCOL_VER:
    CACHE_TRACE(D_PACKETS, cache, "Client uses unsupported protocol version");
    if (pdu->ver <= RPKI_MAX_VERSION &&
	pdu->ver >= RPKI_MIN_VERSION &&
	pdu->ver < cache->version)
    {
      CACHE_TRACE(D_EVENTS, cache, "Downgrading from protocol version %i to version %i", cache->version, pdu->ver);
      cache->version = pdu->ver;
      rpki_cache_change_state(cache, RPKI_CS_FAST_RECONNECT);
    }
    else
    {
      CACHE_TRACE(D_PACKETS, cache, "Got UNSUPPORTED_PROTOCOL_VER error PDU with invalid values, " \
		  "current version: %i, PDU version: %i", cache->version, pdu->ver);
      rpki_cache_change_state(cache, RPKI_CS_ERROR_FATAL);
    }
    break;

  case UNSUPPORTED_PDU_TYPE:
    CACHE_TRACE(D_PACKETS, cache, "Client set unsupported PDU type");
    rpki_cache_change_state(cache, RPKI_CS_ERROR_FATAL);
    break;

  default:
    CACHE_TRACE(D_PACKETS, cache, "error unknown, server sent unsupported error code %u", pdu->error_code);
    rpki_cache_change_state(cache, RPKI_CS_ERROR_FATAL);
    break;
  }

  return RPKI_SUCCESS;
}

static int
rpki_handle_cache_response_pdu(struct rpki_cache *cache, const struct pdu_cache_response *pdu)
{
  if (cache->request_session_id)
  {
    if (cache->last_update != 0)
    {
      /*
       * This point is before import new records from remote cache.
       * If this isn't the first sync, but we already received records,
       * delete old records and be ready for receive new records.
       */
      if (cache->roa4_channel)
	rt_refresh_begin(cache->roa4_channel->table, cache->roa4_channel);
      if (cache->roa6_channel)
	rt_refresh_begin(cache->roa6_channel->table, cache->roa6_channel);

      cache->refresh_channels = 1;
      cache->last_update = 0;
    }
    cache->session_id = pdu->session_id;
    cache->request_session_id = 0;
  }
  else
  {
    if (cache->session_id != pdu->session_id)
    {
      char txt[100];
      bsnprintf(txt, sizeof(txt), "Wrong session_id %u in Cache Response PDU", pdu->session_id);
      rpki_send_error_pdu(cache, NULL, 0, CORRUPT_DATA, txt, strlen(txt)+1);
      rpki_cache_change_state(cache, RPKI_CS_ERROR_FATAL);
      return RPKI_ERROR;
    }
  }
  return RPKI_SUCCESS;
}

static net_addr_union
rpki_prefix_pdu_2_net_addr(const void *pdu)
{
  net_addr_union n = {};
  const enum pdu_type type = get_pdu_type(pdu);

  if (type == IPV4_PREFIX)
  {
    const struct pdu_ipv4 *ipv4 = pdu;
    n.roa4.type = NET_ROA4;
    n.roa4.length = sizeof(net_addr_roa4);
    n.roa4.prefix = ip4_from_u32(ipv4->prefix);
    n.roa4.asn = ipv4->asn;
    n.roa4.pxlen = ipv4->prefix_len;
    n.roa4.max_pxlen = ipv4->max_prefix_len;
  }
  else if (type == IPV6_PREFIX)
  {
    const struct pdu_ipv6 *ipv6 = pdu;
    n.roa6.type = NET_ROA6;
    n.roa6.length = sizeof(net_addr_roa6);
    memcpy(&n.roa6.prefix, ipv6->prefix, sizeof(n.roa6.prefix));
    n.roa6.asn = ipv6->asn;
    n.roa6.pxlen = ipv6->prefix_len;
    n.roa6.max_pxlen = ipv6->max_prefix_len;
  }

  return n;
}

static int
rpki_handle_prefix_pdu(struct rpki_cache *cache, const void *pdu)
{
  struct channel *channel = NULL;

  const enum pdu_type type = get_pdu_type(pdu);
  ASSERT(type == IPV4_PREFIX || type == IPV6_PREFIX);

  if (type == IPV4_PREFIX)
    channel = cache->roa4_channel;
  if (type == IPV6_PREFIX)
    channel = cache->roa6_channel;

  net_addr_union addr = rpki_prefix_pdu_2_net_addr(pdu);

  if (!channel)
  {
    CACHE_TRACE(D_ROUTES, cache, "Skipping route %N, missing %s channel", &addr, (type == IPV4_PREFIX ? "roa4" : "roa6"), addr);
    return RPKI_ERROR;
  }

  switch (((struct pdu_ipv4 *) pdu)->flags)
  {
  case RPKI_ADD_FLAG:
    rpki_table_add_roa(cache, channel, &addr);
    break;

  case RPKI_DELETE_FLAG:
    rpki_table_remove_roa(cache, channel, &addr);
    break;

  default:
  {
    const char *txt = "Prefix PDU with invalid flags value received";
    size_t pdu_size = (type == IPV4_PREFIX ? sizeof(struct pdu_ipv4) : sizeof(struct pdu_ipv6));
    CACHE_DBG(cache, "%s", txt);
    rpki_send_error_pdu(cache, pdu, pdu_size, CORRUPT_DATA, txt, sizeof(txt));
    return RPKI_ERROR;
  }
  }

  return RPKI_SUCCESS;
}

static void
rpki_handle_router_key_pdu(struct rpki_cache *cache, const struct pdu_router_key *pdu)
{
  char file_name[4096]; /* PATH_MAX? */
  char ski_hex[41];
  const char *state_dir = config->rpki_state_dir;
  int i;
  int fd = -1;

  for (i = 0; i < 20; i++)
    bsnprintf(ski_hex + i*2, sizeof(ski_hex) - i*2, "%02X", pdu->ski[i]);

  /* Check buffer size */
  size_t req_size = strlen(state_dir) + 2*sizeof(pdu->ski) + 2 + strlen(RPKI_ROUTER_KEY_EXT);
  if (req_size >= sizeof(file_name))
  {
    CACHE_TRACE(D_EVENTS, cache, "Buffer too small for %s/%u.%s" RPKI_ROUTER_KEY_EXT, state_dir, pdu->asn, ski_hex);
    return;
  }

  bsnprintf(file_name, sizeof(file_name), "%s/%u.%s" RPKI_ROUTER_KEY_EXT, state_dir, pdu->asn, ski_hex);

  fd = open(file_name, O_WRONLY|O_CREAT, 0664);
  if (fd < 0)
  {
    CACHE_TRACE(D_EVENTS, cache, "Cannot open file %s for write router key", file_name);
    return;
  }

  if (write(fd, pdu->spki, RPKI_SPKI_SIZE) < 0)
    CACHE_TRACE(D_EVENTS, cache, "Cannot write into %s", file_name);
  else
    CACHE_TRACE(D_EVENTS, cache, "Wrote router key into file %s", file_name);

  close(fd);
}

static uint
rpki_check_interval(struct rpki_cache *cache, const char *(check_fn)(uint), uint interval)
{
  if (check_fn(interval))
  {
    RPKI_WARN(cache->p, "%s, received %u seconds", check_fn(interval), interval);
    return 0;
  }
  return 1;
}

static void
rpki_handle_end_of_data_pdu(struct rpki_cache *cache, const void *pdu)
{
  const struct pdu_end_of_data_v1 *eod_pdu = pdu;

  if (eod_pdu->ver == RPKI_VERSION_1)
  {
    if (rpki_check_interval(cache, rpki_check_expire_interval, eod_pdu->expire_interval))
      cache->expire_interval = eod_pdu->expire_interval;

    if (rpki_check_interval(cache, rpki_check_refresh_interval, eod_pdu->refresh_interval))
      cache->refresh_interval = eod_pdu->refresh_interval;

    if (rpki_check_interval(cache, rpki_check_retry_interval, eod_pdu->retry_interval))
      cache->retry_interval = eod_pdu->retry_interval;

    CACHE_TRACE(D_EVENTS, cache, "New interval values: "
	       "expire_interval: %us, "
	       "refresh_interval: %us, "
	       "retry_interval: %us",
	       cache->expire_interval, cache->refresh_interval, cache->retry_interval);
  }

  if (eod_pdu->session_id != cache->session_id)
  {
    char txt[67];
    bsnprintf(txt, sizeof(txt), "Received Session ID %u, but expected %u", eod_pdu->session_id, cache->session_id);
    CACHE_TRACE(D_EVENTS, cache, "%s", txt);
    rpki_send_error_pdu(cache, pdu, eod_pdu->len, CORRUPT_DATA, txt, strlen(txt) + 1);
    rpki_cache_change_state(cache, RPKI_CS_ERROR_FATAL);
  }

  if (cache->refresh_channels)
  {
    cache->refresh_channels = 0;
    if (cache->roa4_channel)
      rt_refresh_begin(cache->roa4_channel->table, cache->roa4_channel);
    if (cache->roa6_channel)
      rt_refresh_begin(cache->roa6_channel->table, cache->roa6_channel);
  }

  cache->last_update = now;
  cache->serial_number = eod_pdu->sn;
  rpki_cache_change_state(cache, RPKI_CS_ESTABLISHED);
  rpki_schedule_next_refresh(cache);
  rpki_schedule_next_expire_check(cache);
}

static void
rpki_rx_packet(struct rpki_cache *cache, void *pdu, uint len)
{
  struct rpki_proto *p = cache->p;
  enum pdu_type type = get_pdu_type(pdu);

  if (rpki_check_receive_packet(cache, pdu, len) == RPKI_ERROR)
  {
    rpki_cache_change_state(cache, RPKI_CS_ERROR_FATAL);
    return;
  }

  rpki_pdu_header_to_host_byte_order(pdu);
  rpki_pdu_body_to_host_byte_order(pdu);
  rpki_log_packet(cache, pdu, len, RPKI_RECV);

  switch (type)
  {
  case RESET_QUERY:
  case SERIAL_QUERY:
    RPKI_WARN(p, "Received a %s packet that is destined for cache server", str_pdu_type[type]);
    break;

  case SERIAL_NOTIFY:
    /* This is a signal to synchronize with the cache server just now */
    rpki_cache_change_state(cache, RPKI_CS_SYNC);
    break;

  case CACHE_RESPONSE:
    rpki_handle_cache_response_pdu(cache, pdu);
    break;

  case IPV4_PREFIX:
  case IPV6_PREFIX:
    rpki_handle_prefix_pdu(cache, pdu);
    break;

  case ROUTER_KEY:
    rpki_handle_router_key_pdu(cache, pdu);
    break;

  case END_OF_DATA:
    rpki_handle_end_of_data_pdu(cache, pdu);
    break;

  case CACHE_RESET:
    /* The cache may respond to a Serial Query informing the router that the
     * cache cannot provide an incremental update starting from the Serial
     * Number specified by the router.  The router must decide whether to
     * issue a Reset Query or switch to a different cache. */
    rpki_cache_change_state(cache, RPKI_CS_ERROR_NO_INCR_UPDATE_AVAIL);
    break;

  case ERROR:
    rpki_handle_error_pdu(cache, pdu);
    break;

  default:
    CACHE_TRACE(D_PACKETS, cache, "Received unsupported type of RPKI PDU: %u", type);
  };
}

static int
rpki_open_channel(struct channel *cs)
{
  if (cs)
    if (cs->channel_state != CS_FLUSHING)
      channel_open(cs);
    else
      return 0;

  return 1;
}

int
rpki_rx_hook(struct birdsock *sk, int size)
{
  struct rpki_cache *cache = sk->data;
  struct rpki_proto *p = cache->p;

  byte *pkt_start = sk->rbuf;
  byte *end = pkt_start + size;

  DBG("rx hook got %d bytes \n", size);

  if (!rpki_open_channel(cache->roa4_channel) || !rpki_open_channel(cache->roa6_channel))
  {
    DBG("Channels are busy, must wait \n");
    return 0; /* Channels are busy, must wait, don't purge sk->rbuf */
  }

  while (end >= pkt_start + RPKI_PDU_HEADER_LEN)
  {
    struct pdu_header header;
    memcpy(&header, pkt_start, sizeof(header));
    rpki_pdu_header_to_host_byte_order(&header);

    if (header.len < RPKI_PDU_HEADER_LEN || header.len > RPKI_PDU_MAX_LEN)
    {
      RPKI_WARN(p, "Received invalid packet length %u. Purge the whole receiving buffer.", header.len);
      return 1; /* Purge recv buffer */
    }

    if (end < pkt_start + header.len)
      break;

    rpki_rx_packet(cache, pkt_start, header.len);

    /* It is possible that bird socket was freed/closed */
    if (sk != cache->tr_sock->sk)
      return 0;

    pkt_start += header.len;
  }

  if (pkt_start != sk->rbuf)
  {
    CACHE_DBG(cache, "Move %u bytes of a memory at the start of buffer", end - pkt_start);
    memmove(sk->rbuf, pkt_start, end - pkt_start);
    sk->rpos = sk->rbuf + (end - pkt_start);
  }

  return 0; /* Not purge sk->rbuf */
}

void
rpki_err_hook(struct birdsock *sk, int error_num)
{
  struct rpki_cache *cache = sk->data;

  if (error_num && sk->err == NULL)
  {
    CACHE_TRACE(D_EVENTS, cache, "Lost connection: %M", error_num);
  }
  else
  {
    CACHE_TRACE(D_EVENTS, cache, "Lost connection: %s", sk->err);
  }

  rpki_cache_change_state(cache, RPKI_CS_ERROR_TRANSPORT);
}

static int
rpki_fire_tx(struct rpki_cache *cache)
{
  sock *sk = cache->tr_sock->sk;

  uint bytes_to_send = sk->tpos - sk->tbuf;
  DBG("Sending %u bytes", bytes_to_send);
  return sk_send(sk, bytes_to_send);
}

void
rpki_kick_tx(sock *sk)
{
  struct rpki_cache *cache = sk->data;

  while (rpki_fire_tx(cache) > 0)
    ;
}

void
rpki_tx_hook(sock *sk)
{
  struct rpki_cache *cache = sk->data;

  while (rpki_fire_tx(cache) > 0)
    ;
}

void
rpki_connected_hook(sock *sk)
{
  struct rpki_cache *cache = sk->data;

  CACHE_TRACE(D_EVENTS, cache, "Connected");

  sk->rx_hook = rpki_rx_hook;
  sk->tx_hook = rpki_tx_hook;

  rpki_cache_change_state(cache, RPKI_CS_SYNC);
}

int
rpki_send_error_pdu(struct rpki_cache *cache, const void *erroneous_pdu, const uint32_t pdu_len, const enum pdu_error_type error, const char *text, const uint32_t text_len)
{
  /* Don't send errors for erroneous error PDUs */
  if (pdu_len >= 2)
  {
    if (get_pdu_type(erroneous_pdu) == ERROR)
      return RPKI_SUCCESS;
  }

  uint msg_size = 16 + pdu_len + text_len;
  char msg[msg_size];
  struct pdu_header *header = (struct pdu_header *) msg;
  header->ver = cache->version;
  header->type = 10;
  header->reserved = error;
  header->len = msg_size;

  memcpy(msg+8, &pdu_len, sizeof(pdu_len));
  if (pdu_len > 0)
    memcpy(msg + 12, erroneous_pdu, pdu_len);
  *(msg + 12 + pdu_len) = htonl(text_len);
  if (text_len > 0)
    memcpy(msg+16+pdu_len, text, text_len);

  return rpki_send_pdu(cache, msg, msg_size);
}

int
rpki_send_serial_query(struct rpki_cache *cache)
{
  struct pdu_serial_query pdu = {
      .ver = cache->version,
      .type = SERIAL_QUERY,
      .session_id = cache->session_id,
      .len = sizeof(pdu),
      .sn = cache->serial_number
  };

  if (rpki_send_pdu(cache, &pdu, sizeof(pdu)) != RPKI_SUCCESS) {
    rpki_cache_change_state(cache, RPKI_CS_ERROR_TRANSPORT);
    return RPKI_ERROR;
  }
  return RPKI_SUCCESS;
}

int
rpki_send_reset_query(struct rpki_cache *cache)
{
  struct pdu_reset_query pdu = {
      .ver = cache->version,
      .type = RESET_QUERY,
      .len = 8,
  };

  if (rpki_send_pdu(cache, &pdu, sizeof(pdu)) != RPKI_SUCCESS) {
    rpki_cache_change_state(cache, RPKI_CS_ERROR_TRANSPORT);
    return RPKI_ERROR;
  }
  return RPKI_SUCCESS;
}
