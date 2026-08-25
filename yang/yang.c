/*
 *	BIRD -- YANG-CBOR / CORECONF api
 *
 *	(c) 2026       Maria Matejka <mq@jmq.cz>
 *	(c) 2026       CZ.NIC, z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "lib/tlists.h"
#include "conf/conf.h"
#include "yang/yang.h"
#include "yang/model-cli.h"
#include "yang/coreconf.h"

#include "yang/model.h"

static bool yang_default_endpoint(struct yang_session *se);

#define WELLKNOWN_CORE_DATASTORE "</c>;rt=core.c.ds"
#define WELLKNOWN_CORE_YANG_LIBRARY "</yl>;rt=core.c.yl"
#define WELLKNOWN_CORE_EVENT_STREAM "</s>;rt=core.c.ev"
#define WELLKNOWN_CORE_DATA_NODES ""

static const char wellknown_core_datastore[] = WELLKNOWN_CORE_DATASTORE;
static const char wellknown_core_yang_library[] = WELLKNOWN_CORE_YANG_LIBRARY;
static const char wellknown_core_event_stream[] = WELLKNOWN_CORE_EVENT_STREAM;
static const char wellknown_core_data_nodes[] = WELLKNOWN_CORE_DATA_NODES;

static const char wellknown_core_all[] = WELLKNOWN_CORE_DATASTORE "," WELLKNOWN_CORE_YANG_LIBRARY "," \
   WELLKNOWN_CORE_EVENT_STREAM "," WELLKNOWN_CORE_DATA_NODES;

struct core_rt_types {
   enum resource_type resource;
   const char name[13];
};

struct core_rt_types filters[] = {
   { .resource = CORECONF_DATASTORE,    .name = "rt=core.c.ds", },
   { .resource = CORECONF_YANG_LIB,     .name = "rt=core.c.yl", },
   { .resource = CORECONF_EVENT_STREAM, .name = "rt=core.c.ev", },
   { .resource = CORECONF_DATA_NODE,    .name = "rt=core.c.dn", },
   { .resource = UNKNOWN_RESOURCE, },
};

bool
yang_model_cli_endpoint_wellknown_core(struct yang_session *se)
{
  struct yang_socket *s = se->socket;
  SKIP_BACK_DECLARE(struct yang_api, api, listen, yang_socket_enlisted(s));

  switch (se->coap.parser.state) {
    case COAP_PS_MORE:
    case COAP_PS_HEADER:
      log(L_ERR "%s: Unexpected state in endpoint (TODO bad) 2", api->name);
      return false;

    case COAP_PS_ERROR:
      log(L_ERR "%s: CoAP error in endpoint (TODO bad)", api->name);
      return false;

    case COAP_PS_OPTION_PARTIAL:
    case COAP_PS_OPTION_COMPLETE:
      switch (se->coap.parser.option_type) {
	case COAP_OPT_URI_QUERY:
	  /* According to RFC 6690, Sec. 4, we are not required
	   * to support filtering at the well-known path. It's desirable for later implementation tho. */
	  log(L_INFO "URI Query (%u-%u/%u): %.*s",
	      se->coap.parser.option_chunk_offset,
	      se->coap.parser.option_chunk_offset + se->coap.parser.option_chunk_len,
	      se->coap.parser.option_len,
	      se->coap.parser.option_chunk_len, se->coap.parser.option_value);
      if (se->coap.parser.option_len != sizeof(filters[0].name) - 1)
      {
         log(L_INFO "query does not match (len)");
         se->core_report_all = true;
         break;
      }

      struct core_rt_types *filter = &filters[0];
      while (filter->resource != UNKNOWN_RESOURCE)
      {
         if (!strncmp(se->coap.parser.option_value, filter->name, sizeof(filters[0].name) - 1))
         {
            log(L_INFO "query match %u %s", filter->resource, filter->name);
            if (se->core_query == UNKNOWN_RESOURCE)
               se->core_query = filter->resource;
            else
               se->core_report_all = true;
            break;
         }
         filter++;
      }
      if (filter->resource == UNKNOWN_RESOURCE)
            log(L_INFO "query does not match");

	  break;
	default:
	  if (se->coap.parser.option_type & COAP_OPT_F_CRITICAL)
	  {
	    /* TODO: make this a macro or func */
	    log(L_INFO "Unhandled option %u, fail / TODO copy token", se->coap.parser.option_type);
	    if (!se->error_sent)
	    {
	      struct coap_tx_option *payload = COAP_TX_OPTION_PRINTF(
		  0, "Unhandled option %u", se->coap.parser.option_type);
         log(L_INFO "yang_model_cli_endpoint_wellknown_core COAP_TX_RESPONSE error");
	      coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_CERR_BAD_OPTION, payload));
	      se->error_sent = true;
	    }
	  }
      }
      //log(L_INFO "se->core_query reset 1 %u", se->coap.parser.state);
      // reset
      //se->core_query = UNKNOWN_RESOURCE;
      //se->core_report_all = false;
      return true;

    case COAP_PS_PAYLOAD_COMPLETE:
      if (se->coap.parser.payload_total_len != 0)
	log(L_WARN "%s: Received GET with a payload. Weird.", api->name);

      /* TODO: make this a macro or func? */
      se->endpoint = yang_default_endpoint;


      /* fall through */

    case COAP_PS_PAYLOAD_PARTIAL:
      if (!se->error_sent)
      {

   log(L_INFO "endpoint_wellknown_core");
   const char *links_ptr;
   switch (se->core_query)
   {
   case UNKNOWN_RESOURCE: links_ptr = wellknown_core_all; break;
   case CORECONF_DATASTORE: links_ptr = wellknown_core_datastore; break;
   case CORECONF_YANG_LIB: links_ptr = wellknown_core_yang_library; break;
   case CORECONF_EVENT_STREAM: links_ptr = wellknown_core_event_stream; break;
   case CORECONF_DATA_NODE:  links_ptr = wellknown_core_data_nodes; break;
   case CORE_WELL_KNOWN:
   case CORECONF_RPC_ACTION: bug("unreachable, invalid query %u", se->core_query);
   }


   log(L_INFO "parsed rt %u report_all %u: %s", se->core_query, se->core_report_all, links_ptr ? links_ptr : "");
	struct coap_tx_option
	  *content_format = COAP_TX_OPTION_INT(
	      COAP_OPT_CONTENT_FORMAT, (u8) COAP_CF_LINK_FORMAT),
	  *payload = COAP_TX_OPTION_PRINTF(0, links_ptr);

	coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_RESP_CONTENT,
	      content_format, payload));
      }

#if 0
      log(L_INFO "Payload (%u-%u/%u)", se->coap.parser.payload_chunk_offset,
	  se->coap.parser.payload_chunk_offset + se->coap.parser.payload_chunk_len,
	  se->coap.parser.payload_total_len);
#endif

      log(L_INFO "se->core_query reset 2");
      // reset
      se->core_query = UNKNOWN_RESOURCE;
      se->core_report_all = false;
      return true;

    default:
      bug("what the hell");

  }
}

static bool
yang_cbor_parser_error(struct yang_session *se, int pos, const char *reason)
{
  if (se->error_sent)
    return true;

  struct coap_tx_option *payload = COAP_TX_OPTION_PRINTF(
      0, "Parse error at position %u: %s", se->coap.parser.payload_chunk_offset + pos, reason);
   log(L_INFO "yang_cbor_parser_error COAP_TX_RESPONSE");
  coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_CERR_BAD_REQUEST, payload));
  se->error_sent = true;
  return true;
}

static bool
yang_push_sid(struct yang_session *se, u64 sid)
{
  u64 cur = se->sid_stack[se->sid_pos];

  /* Generate this by UYTC */
  switch (sid) {
    case 60001:
      /* Check parent SID */
      if (cur != 0)
	return false;

      break;

    default:
      /* Unexpected SID */
      return false;
  }

  se->sid_stack[se->sid_pos + 1] = se->sid_stack[se->sid_pos] + se->cbor->value;
  se->sid_pos++;

  return true;
}

static bool
yang_pop_sid(struct yang_session *se)
{
  ASSERT_DIE(se->sid_pos >= 0);

  u64 cur = se->sid_stack[se->sid_pos];

  /* Generate this by UYTC
   * Only block-like items */
  switch (cur) {
    case 0:
      /* Nothing to do */
      break;

    default:
      /* Unexpected SID */
      return false;
  }

  se->sid_pos--;
  return true;
}


static bool
yang_model_cli_cbor_c(struct yang_session *se)
{
  const char *payload = se->coap.parser.payload;
  uint len = se->coap.parser.payload_chunk_len;

  for (uint i=0; i<len; i++)
  {
    while (cbor_parse_block_end(se->cbor))
      if (!yang_pop_sid(se))
	return yang_cbor_parser_error(se, i, "End of block error"); /* TODO: make this nicer */

    ASSERT_DIE(se->sid_pos >= 0);

    switch (cbor_parse_byte(se->cbor, payload[i]))
    {
      case CPR_ERROR:
	return yang_cbor_parser_error(se, i, se->cbor->error);

      case CPR_MORE:
	continue;

      case CPR_MAJOR:
	switch (se->sid_state)
	{
	  case YANG_PS_RELATIVE_SID:
	    switch (se->cbor->type)
	    {
	      case CBOR_POSINT:
		if (se->sid_stack[se->sid_pos] + se->cbor->value < se->sid_stack[se->sid_pos])
		  return yang_cbor_parser_error(se, i, "SID overflow");

		if (!yang_push_sid(se, se->sid_stack[se->sid_pos] + se->cbor->value))
		  return yang_cbor_parser_error(se, i, "Unexpected SID");

		se->sid_state = YANG_PS_VALUE;
		continue;

	      case CBOR_NEGINT:
		if (se->sid_stack[se->sid_pos] - se->cbor->value > se->sid_stack[se->sid_pos])
		  return yang_cbor_parser_error(se, i, "SID underflow");

		if (!yang_push_sid(se, se->sid_stack[se->sid_pos] + se->cbor->value))
		  return yang_cbor_parser_error(se, i, "Unexpected SID");

		se->sid_state = YANG_PS_VALUE;
		continue;

	      case CBOR_TAG:
		if (se->cbor->value == CBOR_TAG_ABSOLUTE_SID)
		{
		  se->sid_state = YANG_PS_ABSOLUTE_SID;
		  continue;
		}

		/* fall through */

	      default:
		return yang_cbor_parser_error(se, i, "Wrong SID type");
	    }

	  case YANG_PS_ABSOLUTE_SID:
	    if (se->cbor->type != CBOR_POSINT)
	      return yang_cbor_parser_error(se, i, "Wrong type of absolute SID"); // TODO: (%u)", se->cbor->type);

	    if (!yang_push_sid(se, se->cbor->value))
	      return yang_cbor_parser_error(se, i, "Unexpected SID");

	    se->sid_state = YANG_PS_VALUE;
	    continue;

	    /* We kinda wanna generate this block by UYTC */
	  case YANG_PS_VALUE:
	    switch (se->sid_stack[se->sid_pos])
	    {
	      case 0:
		if (se->cbor->type != CBOR_MAP)
		  return yang_cbor_parser_error(se, i, "Wrong data for SID 0 / root");

		se->sid_state = YANG_PS_RELATIVE_SID;
		continue;

	      case 60001:
		if ((se->cbor->type != CBOR_SPECIAL) && (se->cbor->value != CBOR_SPECIAL_NULL))
		  return yang_cbor_parser_error(se, i, "Wrong data for SID 60001");

		se->sid_pos--;
		se->sid_state = YANG_PS_RELATIVE_SID;
		yang_model_cli_rpc_call_show_memory(se);
		continue;

	      default:
		return yang_cbor_parser_error(se, i, "Unexpected SID");
	    }
	}
	bug("this shall not happen");

      case CPR_STR_END:
	return yang_cbor_parser_error(se, i, "No strings expected");
    }
  }

  while (cbor_parse_block_end(se->cbor))
    if (!yang_pop_sid(se))
      return yang_cbor_parser_error(se, len, "End of block error"); /* TODO: make this nicer */

  if (se->sid_pos < 0)
    ASSERT_DIE(se->coap.parser.state == COAP_PS_PAYLOAD_COMPLETE);

  return true;
}

static bool
yang_model_cli_endpoint_c(struct yang_session *se)
{
  struct yang_socket *s = se->socket;
  SKIP_BACK_DECLARE(struct yang_api, api, listen, yang_socket_enlisted(s));

  switch (se->coap.parser.state) {
    case COAP_PS_EMPTY:
    case COAP_PS_MORE:
    case COAP_PS_HEADER:
      log(L_ERR "%s: Unexpected state in endpoint (TODO bad) 3", api->name);
      return false;

    case COAP_PS_ERROR:
      log(L_ERR "%s: CoAP error in endpoint (TODO bad)", api->name);
      return false;

    case COAP_PS_OPTION_PARTIAL:
    case COAP_PS_OPTION_COMPLETE:
      if (se->coap.parser.option_type & COAP_OPT_F_CRITICAL)
      {
	/* TODO: make this a macro or func */
	log(L_INFO "Unhandled option %u, fail / TODO copy token", se->coap.parser.option_type);
	if (!se->error_sent)
	{
	  struct coap_tx_option *payload = COAP_TX_OPTION_PRINTF(
	      0, "Unhandled option %u", se->coap.parser.option_type);
      log(L_INFO "yang_model_cli_endpoint_c COAP_TX_RESPONSE error");
	  coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_CERR_BAD_OPTION, payload));
	  se->error_sent = true;
	}
      }
      return true;

    case COAP_PS_PAYLOAD_PARTIAL:
    case COAP_PS_PAYLOAD_COMPLETE:
      if (se->error_sent)
	return true;

      if (se->coap.parser.code != COAP_REQ_POST)
      {
	struct coap_tx_option *payload = COAP_TX_OPTION_PRINTF(
	    0, "The CLI endpoint allows only POST/RPC calls");
   log(L_INFO "yang_model_cli_endpoint_c COAP_TX_RESOPNSE");
	coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_CERR_METHOD_NOT_ALLOWED, payload));
	se->error_sent = true;
	return true;
      }

      return yang_model_cli_cbor_c(se);
  }

  bug("this shall not happen");
}

static enum yang_proc_state
check_opt_accept(struct yang_session *se)
{
  if (se->coap.parser.state == COAP_PS_OPTION_PARTIAL)
    return YP_WAIT;

  u16 accept_cf;
  if (se->coap.parser.option_len == 0)
    accept_cf = 0;
  else if (se->coap.parser.option_len == 1)
    accept_cf = (u16) (u8) *se->coap.parser.option_value;
  else if (se->coap.parser.option_len == 2)
    accept_cf = get_u16(se->coap.parser.option_value);
  else
  {
    log(L_ERR "Invalid value for option Accept (option too long)");
    struct coap_tx_option *payload = COAP_TX_OPTION_PRINTF(0, "CoAP Accept Option must be shorted than 3 bytes.");
    coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_CERR_BAD_OPTION, payload));
    se->error_sent = true;
    return YP_ERR;
  }

  if (accept_cf == COAP_CF_NO_VALUE)
  {
    log(L_ERR "Invalid value for option Accept (implemetation defined opt. value)");
    coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_CERR_NOT_ACCEPTABLE));
    se->error_sent = true;
    return YP_ERR;
  }

  struct resource_info *info;
  for (info = &content_format_by_resource[0]; info->type != UNKNOWN_RESOURCE; info++)
  {
    if (info->type == se->resource_type && info->method == se->coap.parser.code)
      break;
  }

  log(L_TRACE "Checking match UNKNOWN_RESOURCE response_format %u accept %u",
      info->response_format, accept_cf);
  if (info->type != UNKNOWN_RESOURCE && info->response_format == accept_cf)
  {
    se->accept = accept_cf;
    return YP_OK;
  }

  struct coap_tx_option *payload;
  if (info->type == UNKNOWN_RESOURCE)
    payload = NULL;
  else if (se->coap.parser.code == COAP_REQ_POST)
  {
    ASSERT(content_format_by_resource[0].response_format == COAP_CF_NO_VALUE);
    ASSERT(content_format_by_resource[2].response_format == COAP_CF_YANG_INSTANCES);
    payload = COAP_TX_OPTION_PRINTF(0, "Response will be either empty (no Content-Format) or %u, got Accept %u",
				    COAP_CF_YANG_INSTANCES, accept_cf);
  }
  else if (info->response_format == COAP_CF_NO_VALUE)
    payload = COAP_TX_OPTION_PRINTF(0, "Response will have no payload and Content-Format, got Accept %u", accept_cf);
  else
    payload = COAP_TX_OPTION_PRINTF(0, "Response Content-Format is only %u, got Accept %u",
				    info->response_format, accept_cf);

  coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_CERR_NOT_ACCEPTABLE, payload));
  se->error_sent = true;
  return YP_ERR;
}

static enum yang_proc_state
check_opt_content_format(struct yang_session *se)
{
  if (se->coap.parser.state == COAP_PS_OPTION_PARTIAL)
    return YP_WAIT;

  u16 content_format;
  if (se->coap.parser.option_len == 0)
    content_format = 0;
  else if (se->coap.parser.option_len == 1)
    content_format = (u16) (u8) *se->coap.parser.option_value;
  else if (se->coap.parser.option_len == 2)
    content_format = get_u16(se->coap.parser.option_value);
  else
  {
    log(L_ERR "Invalid value for option Content-Format (option too long)");
    struct coap_tx_option *payload = COAP_TX_OPTION_PRINTF(0, "CoAP Content-Format Option must be shorted than 3 bytes.");
    coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_CERR_BAD_OPTION, payload));
    se->error_sent = true;
    return YP_ERR;
  }

  if (content_format == COAP_CF_NO_VALUE)
  {
    log(L_ERR "Invalid value for option Content-Format (implementation defined opt. value)");
    coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_CERR_UNSUPPORTED_CONTENT_FORMAT));
    se->error_sent = true;
    return YP_ERR;
  }

  struct resource_info *info;
  if (se->coap.parser.code != COAP_REQ_POST)
  {
    for (info = &content_format_by_resource[3]; info->type != UNKNOWN_RESOURCE; info++)
    {
      if (info->type == se->resource_type && info->method == se->coap.parser.code)
	break;
    }
  }
  else
  {
    info = &content_format_by_resource[0];
    for (info = &content_format_by_resource[0]; info->method == COAP_REQ_POST; info++)
    {
      if (info->type == se->resource_type && info->request_format == content_format)
	break;
    }

    if (info->method != COAP_REQ_POST)
    {
      info = &content_format_by_resource[11];
      ASSERT(info->type == UNKNOWN_RESOURCE);
    }
  }

  if (info->type != UNKNOWN_RESOURCE)
  {
    if (info->request_format == COAP_CF_NO_VALUE)
    {
      struct coap_tx_option *payload = COAP_TX_OPTION_PRINTF(0, "Expected no Content-Format and payload, got Content-Format %u", content_format);
      coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_CERR_UNSUPPORTED_CONTENT_FORMAT, payload));
      se->error_sent = true;
      return YP_ERR;
    }

    if (info->request_format != content_format)
    {
      struct coap_tx_option *payload = COAP_TX_OPTION_PRINTF(0, "Expected Content-Format %u, got %u",
							     info->request_format, content_format);
      coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_CERR_UNSUPPORTED_CONTENT_FORMAT, payload));
      se->error_sent = true;
      return YP_ERR;
    }
  }
  else if (se->coap.parser.code == COAP_REQ_POST)
  {
    ASSERT(content_format_by_resource[0].method == COAP_REQ_POST &&
	   content_format_by_resource[0].request_format == COAP_CF_YANG_CBOR);
    ASSERT(content_format_by_resource[1].method == COAP_REQ_POST &&
	   content_format_by_resource[1].request_format == COAP_CF_YANG_INSTANCES);
    // We ignore info at index [2]
    ASSERT(content_format_by_resource[3].method != COAP_REQ_POST);
    struct coap_tx_option *payload = COAP_TX_OPTION_PRINTF(0, "Expected Content-Format either %u or %u, got %u",
					      COAP_CF_YANG_CBOR, COAP_CF_YANG_INSTANCES, content_format);
    coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_CERR_UNSUPPORTED_CONTENT_FORMAT, payload));
    se->error_sent = true;
    return YP_ERR;
  }
  else
  {
    //struct coap_tx_option *payload = COAP_TX_OPTION_PRINTF("CoAP Content-Format");
    coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_CERR_UNSUPPORTED_CONTENT_FORMAT));
    se->error_sent = true;
    return YP_ERR;
  }

  se->cont_format = content_format;
  ASSERT(content_format_by_resource[2].type == CORECONF_RPC_ACTION &&
	 content_format_by_resource[2].method == COAP_REQ_POST &&
	 content_format_by_resource[2].request_format == COAP_CF_YANG_INSTANCES);
  if (se->resource_type == CORECONF_DATASTORE && se->coap.parser.code == COAP_REQ_POST &&
      se->cont_format == COAP_CF_YANG_INSTANCES)
    se->resource_type = CORECONF_RPC_ACTION;

  return YP_OK;
}

enum yang_proc_state
yang_common_coap_endpoint(struct yang_session *se)
{
  // content if this function is copied from yang_model_cli_emndpoint_c
  struct yang_socket *s = se->socket;
  SKIP_BACK_DECLARE(struct yang_api, api, listen, yang_socket_enlisted(s));

  switch (se->coap.parser.state) {
    case COAP_PS_HEADER:
      log(L_INFO "yang_common_coap_endpoint %u", se->coreconf_state);
      return YP_WAIT;

    case COAP_PS_EMPTY:
    case COAP_PS_MORE:
      log(L_ERR "%s: Unexpected state in endpoint (TODO bad) 1 %u (%u %u-%u %u)", api->name,
          se->coap.parser.state, COAP_PS_EMPTY, COAP_PSM_NONE, COAP_PS__MORE_MAX, COAP_PS_HEADER);
      return YP_ERR;

    case COAP_PS_ERROR:
      log(L_ERR "%s: CoAP error in endpoint (TODO bad)", api->name);
      return YP_ERR;

    case COAP_PS_OPTION_PARTIAL:
    case COAP_PS_OPTION_COMPLETE:
      if (se->coap.parser.option_type == COAP_OPT_CONTENT_FORMAT)
      {
	enum yang_proc_state yp = check_opt_content_format(se);
	if (yp == YP_ERR)
	  return YP_ERR;
	else
	  return YP_WAIT;
      }

      if (se->coap.parser.option_type == COAP_OPT_ACCEPT)
      {
	enum yang_proc_state yp = check_opt_accept(se);
	if (yp == YP_ERR)
	  return YP_ERR;
	else
	  return YP_WAIT;
      }

      return YP_OK;

#if 0
    // CoAP Option Accept
      if (se->coap.parser.option_type == COAP_OPT_ACCEPT &&
            se->coap.parser.state == COAP_PS_OPTION_PARTIAL)
         return YP_WAIT;

      if (se->coap.parser.option_type == COAP_OPT_ACCEPT &&
         (se->coap.parser.option_len == 1 || se->coap.parser.option_len == 2))
      {
         u16 accept = (se->coap.parser.option_len == 1) ? *(se->coap.parser.option_value)
            : get_u16(se->coap.parser.option_value);

         if (se->coap.parser.code == COAP_REQ_POST)
         {
            /* Checked later with Content-Format option. */
            se->accept = accept;
            return YP_WAIT;
         }

         struct resource_info *info = &content_format_by_resource[0];
         while (info->type != UNKNOWN_RESOURCE)
         {
            if (info->type == se->resource_type && info->method == se->coap.parser.code)
            {
               if (accept != info->response_format && info->response_format != COAP_CF_NO_VALUE)
               {
                  log(L_INFO "Invalid value %u for CoAP Accept Option, expected %u",
                      accept, info->response_format);
                  if (!se->error_sent) {
                     struct coap_tx_option *payload = COAP_TX_OPTION_PRINTF(
                           0, "Invalid value %u for CoAP Accept Option, expected %u",
                           accept, info->response_format);

                     log(L_INFO "yang_common_coap_endpoint COAP_TX_RESPONSE error 1");
                     coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_CERR_NOT_ACCEPTABLE, payload));
                     se->error_sent = true;
                  }
                  return YP_ERR;
               }
               else if (accept != info->response_format)
               {
                  log(L_INFO "Invalid value %u for CoAP Accept Option, expected no payload and no Content-Format",
                      accept);
                  if (!se->error_sent) {
                     struct coap_tx_option *payload = COAP_TX_OPTION_PRINTF(
                           0, "Invalid value %u for CoAP Accept Option, expected no payload and no Content-Format",
                           accept);

                     log(L_INFO "yang_common_coap_endpoint COAP_TX_RESPONSE error 2");
                     coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_CERR_NOT_ACCEPTABLE, payload));
                     se->error_sent = true;
                  }
                  return YP_ERR;
               }
            }
            info++;
         }

         /* Accept CoAP option is optional */
      }
#endif

#if 0
    // CoAP Option Content-Format
      if (se->coap.parser.option_type == COAP_OPT_CONTENT_FORMAT &&
            se->coap.parser.state == COAP_PS_OPTION_PARTIAL)
         return YP_WAIT;

      if (se->coap.parser.option_type == COAP_OPT_CONTENT_FORMAT &&
         (se->coap.parser.option_len == 1 || se->coap.parser.option_len == 2))
      {
         u16 content_format = (se->coap.parser.option_len == 1) ? *(se->coap.parser.option_value)
            : get_u16(se->coap.parser.option_value);

         if (se->coap.parser.code == COAP_REQ_POST)
         {
            bool content_accept_ok = false;
            struct resource_info *info = &content_format_by_resource[0];
            while (info->method == COAP_REQ_POST)
            {
               if (info->type == se->resource_type && info->request_format == content_format)
               {
                  if ((content_format == COAP_CF_NO_VALUE || content_format == info->request_format) && (se->accept == COAP_CF_NO_VALUE || se->accept == info->response_format))
                  {
		  log(L_TRACE "info rt %u rf %u", info->response_format, se->format);
                     content_accept_ok = true;
                     break;
                  }
               }

               info++;
            }

            if (!content_accept_ok)
            {
               ASSERT(content_format_by_resource[0].method == COAP_REQ_POST);
               ASSERT(content_format_by_resource[1].method == COAP_REQ_POST);
               ASSERT(content_format_by_resource[2].method == COAP_REQ_POST);
               ASSERT(content_format_by_resource[3].method != COAP_REQ_POST);
               /* CoAP Option Accept has higher priority? It is a Critical CoAP Option */
               if (se->accept != COAP_CF_NO_VALUE)
               {
                  log(L_INFO "Invalid value %u for CoAP Acccept Option, expected %u or nothing",
                      se->accept, content_format_by_resource[0].response_format, content_format_by_resource[1].response_format);
                  if (!se->error_sent)
                  {
                     struct coap_tx_option *payload = COAP_TX_OPTION_PRINTF(
                           0, "Invalid value %u for CoAP Acccept Option, expected %u or nothing",
                           se->accept, content_format_by_resource[0].response_format, content_format_by_resource[1].response_format);
                     log(L_INFO "yang_common_coap_endpoint COAP_TX_RESPONSE error 3");
                     coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_CERR_NOT_ACCEPTABLE, payload));
                     se->error_sent = true;
                  }
                  return YP_ERR;
               }

               log(L_INFO "Invalid value %u for CoAP Content-Format, expected %u or %u",
                  content_format, content_format_by_resource[0].request_format, content_format_by_resource[1].request_format);
               if (!se->error_sent)
               {
                  struct coap_tx_option *payload = COAP_TX_OPTION_PRINTF(
                        0, "Invalid value %u for CoAP Content-Format, expected %u or %u",
                        content_format, content_format_by_resource[0].request_format, content_format_by_resource[1].request_format);
                     log(L_INFO "yang_common_coap_endpoint COAP_TX_RESPONSE error 4");
                  coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_CERR_UNSUPPORTED_CONTENT_FORMAT, payload));
                  se->error_sent = true;
               }

               return YP_ERR;
            }

            return YP_WAIT;
         }

         bool format_ok = false;
         struct resource_info *info = &content_format_by_resource[0];
         while (info->type != UNKNOWN_RESOURCE)
         {
            if (info->type == se->resource_type && info->method == se->coap.parser.code)
            {
               if (content_format != info->request_format && info->request_format != COAP_CF_NO_VALUE)
               {
                  log(L_INFO "Invalid value %u for CoAP Content-Format Option, expected %u",
                      content_format, info->request_format);
                  if (!se->error_sent)
                  {
                     struct coap_tx_option *payload = COAP_TX_OPTION_PRINTF(
                           0, "Invalid value %u for CoAP Content-Format Option, expected %u",
                           content_format, info->request_format);

                     log(L_INFO "yang_common_coap_endpoint COAP_TX_RESPONSE error 5");
                     coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_CERR_UNSUPPORTED_CONTENT_FORMAT,
                                    payload));
                     se->error_sent = true;
                  }
                  return YP_ERR;
               }
               else if (content_format != info->request_format)
               {
                  log(L_INFO "Invalid value %u for CoAP Content-Format Option, expected no value and no payload",
                      content_format);
                  if (!se->error_sent)
                  {
                     struct coap_tx_option *payload = COAP_TX_OPTION_PRINTF(
                           0, "Invalid value %u for CoAP Content-Format Option, expected no value and no payload",
                        content_format);
                     log(L_INFO "yang_common_coap_endpoint COAP_TX_RESPONSE error 6");
                     coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_CERR_BAD_OPTION, payload));
                     se->error_sent = true;
                  }
                  return YP_ERR;
               }
               else
               {
                  format_ok = true;
                  break;
               }
            }
            info++;
         }

         if (!format_ok)
         {
            log(L_INFO "Invalid value %u for CoAP Content-Format Option, expected %u",
                content_format, info->request_format);
            if (!se->error_sent)
            {
               struct coap_tx_option *payload = COAP_TX_OPTION_PRINTF(
                     0, "Invalid value %u for CoAP Content-Format Option, expected %u",
                     content_format, info->request_format);

               log(L_INFO "yang_common_coap_endpoint COAP_TX_RESPONSE error 7");
               coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_CERR_UNSUPPORTED_CONTENT_FORMAT,
                              payload));
               se->error_sent = true;
            }
            return YP_ERR;
         }

         se->cont_format = content_format;
      }

      if (se->coap.parser.option_type & COAP_OPT_F_CRITICAL)
      {
	/* TODO: make this a macro or func */
	log(L_INFO "Unhandled option %u, fail / TODO copy token", se->coap.parser.option_type);
	if (!se->error_sent)
	{
	  struct coap_tx_option *payload = COAP_TX_OPTION_PRINTF(
	      0, "Unhandled option %u", se->coap.parser.option_type);
      log(L_INFO "yang_common_coap_endpoint COAP_TX_RESPONSE error 8");
	  coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_CERR_BAD_OPTION, payload));
	  se->error_sent = true;
	}
      }

      return YP_WAIT;
#endif

    case COAP_PS_PAYLOAD_PARTIAL:
    case COAP_PS_PAYLOAD_COMPLETE:
      // VV: Why should we continue processing when sending error?
      // Or more precisly we sent the error.
      if (se->error_sent)
         return YP_WAIT;

      // TODO controll missing Content-Format missing
      // TODO Implement propper Content-Format sensing from the payload for POST
      if (se->coap.parser.code == COAP_REQ_POST && se->cont_format == COAP_CF_NO_VALUE)
      {
         log(L_INFO "COAP_REQ_POST Missing crutial Content-Format CoAP option.");
         struct coap_tx_option *payload = COAP_TX_OPTION_PRINTF(
               0, "Missing Content-Format, expected %u or %u",
            content_format_by_resource[0].request_format, content_format_by_resource[1].request_format);
         // Is 4.00 Bad Request best option here? Wouldn't a 4.02 Bad Option be better?
         log(L_INFO "yang_common_coap_endpoint COAP_TX_RESPONSE error 9");
         coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_CERR_BAD_REQUEST, payload));
         se->error_sent = true;
         return YP_ERR;
      }

      return YP_OK;
  }

  bug("this shall not happen");
}

static const struct yang_url_node
yang_model_cli_wellknown_core = {
  .endpoint = yang_model_cli_endpoint_wellknown_core,
  .stem = "core",
  .resource_type = CORE_WELL_KNOWN,
  .children = {
    NULL
  },
},
yang_model_cli_datastore = {
  .endpoint = yang_model_cli_endpoint_c,
  .stem = "c2",
  .resource_type = CORECONF_DATASTORE,
  .children = {
    NULL
  },
},
yang_coreconf_datastore = {
   .endpoint = coreconf_datastore,
   .stem = "c",
   .resource_type = CORECONF_DATASTORE,
   .children = {
      NULL
   },
},
yang_model_cli_wellknown = {
  .stem = ".well-known",
  .resource_type = UNKNOWN_RESOURCE,
  .children = {
    &yang_model_cli_wellknown_core,
    NULL
  },
},
yang_model_cli_event_stream = {
   .endpoint = coreconf_event_stream,
   .stem = "s",
   .resource_type = CORECONF_EVENT_STREAM,
   .children = {
      NULL
   },
},
yang_model_constrained_library = {
   .endpoint = coreconf_yang_library,
   .stem = "yl",
   .resource_type = CORECONF_YANG_LIB,
   .children = {
      NULL
   },
},
yang_model_cli_root = {
  .endpoint = NULL,
  .stem = NULL,
  .resource_type = UNKNOWN_RESOURCE,
  .children = {
    &yang_coreconf_datastore, // the order matters!
    &yang_model_cli_datastore,
    &yang_model_cli_wellknown,
    &yang_model_cli_event_stream,
    &yang_model_constrained_library,
    NULL
  },
};

const struct yang_url_node *yang_url_tree[YANG_MODEL__MAX] = {
  NULL, &yang_model_cli_root,
};

static TLIST_LIST(yang_api) global_api_list;
pool *yang_pool;

bool
yang_socket_same(const struct yang_socket_params *a, const struct yang_socket_params *b)
{
  if (a->kind != b->kind)
    return false;

  if (a->port != b->port)
    return false;

  if (!ipa_equal(a->local_ip, b->local_ip))
    return false;

  return true;
}

static bool
yang_api_same(const struct yang_api_params *a, const struct yang_api_params *b)
{
  if (a->restricted != b->restricted)
    return false;

  return true;
}

static void
yang_session_rx_option(struct yang_session *se)
{
  if (se->coap.parser.option_type > COAP_OPT_URI_PATH)
  {
    /* This should have been already resolved by COAP_OPT_URI_PATH
     * and ending up here means wrong path */
    log(L_INFO "Error 4.04: Not Found (TODO)");
    return;
  }

  switch (se->coap.parser.option_type) {
    case COAP_OPT_URI_HOST:
      log(L_INFO "URI Host (%u-%u/%u): %.*s",
	  se->coap.parser.option_chunk_offset,
	  se->coap.parser.option_chunk_offset + se->coap.parser.option_chunk_len,
	  se->coap.parser.option_len,
	  se->coap.parser.option_chunk_len, se->coap.parser.option_value);
      return;

    case COAP_OPT_URI_PORT:
      log(L_INFO "URI Port");
      return;

    case COAP_OPT_URI_PATH:
      log(L_INFO "URI Path (%u-%u/%u): %.*s",
	  se->coap.parser.option_chunk_offset,
	  se->coap.parser.option_chunk_offset + se->coap.parser.option_chunk_len,
	  se->coap.parser.option_len,
	  se->coap.parser.option_chunk_len, se->coap.parser.option_value);

      ASSERT_DIE(se->url_pos == se->coap.parser.option_chunk_offset);

      while (*se->url)
	if (!strncmp(&(*se->url)->stem[se->url_pos], se->coap.parser.option_value, se->coap.parser.option_chunk_len))
	{
	  if (se->coap.parser.option_chunk_offset + se->coap.parser.option_chunk_len == se->coap.parser.option_len)
	  {
	    se->endpoint = ((*se->url)->endpoint) ?: yang_default_endpoint;
            se->resource_type = (*se->url)->resource_type;
	    se->url = (*se->url)->children;
	    return;
	  }
	  break;
	}
	else
	  se->url++;

      if (!*se->url)
	log(L_INFO "Error 4.04: Not Found (TODO)");

      return;

    default:
      if (se->coap.parser.option_type & COAP_OPT_F_CRITICAL)
      {
	log(L_INFO "Unhandled option %u, fail", se->coap.parser.option_type);
	if (!se->error_sent)
	{
	  struct coap_tx_option *payload = COAP_TX_OPTION_PRINTF(
	      0, "Unhandled option %u", se->coap.parser.option_type);
      log(L_INFO "yang_session_rx_option COAP_TX_RESPONSE");
	  coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_CERR_BAD_OPTION, payload));
	  se->error_sent = true;
	}
      }
      return;
  }
}

static bool
yang_default_endpoint(struct yang_session *se)
{
  enum coap_parse_state state = se->coap.parser.state;
  struct yang_socket *s = se->socket;
  SKIP_BACK_DECLARE(struct yang_api, api, listen, yang_socket_enlisted(s));

  log(L_TRACE "state is %d", state);
  switch (state) {
    case COAP_PS_MORE:
      return false;

    case COAP_PS_ERROR:
      log(L_ERR "%s: CoAP error, closing", api->name);
      se->sock->rx_hook = NULL;
      return false;

    case COAP_PS_HEADER:
      /* Reset all required data structures so that we can process the options */
      se->error_sent = false;
      se->url = &yang_url_tree[api->params.model]->children[0];
      se->url_pos = 0;

      cbor_parser_reset(se->cbor);

      return true;

    case COAP_PS_OPTION_PARTIAL:
    case COAP_PS_OPTION_COMPLETE:
      yang_session_rx_option(se);
      return true;

    case COAP_PS_PAYLOAD_PARTIAL:
    case COAP_PS_PAYLOAD_COMPLETE:
      /* If found, the endpoint function should not be this one */
      log(L_INFO "Error 4.04: Not Found (TODO)");
      return true;

    default:
      log(L_INFO "Dummy: Status %u", state);
      return false;
  }
}

static int
yang_session_rx(sock *sk, uint size)
{
  struct yang_session *se = sk->data;
  struct yang_socket *s = se->socket;
  SKIP_BACK_DECLARE(struct yang_api, api, listen, yang_socket_enlisted(s));

  log(L_TRACE "%s: RX data", api->name);

  /* Check the received data in */
  coap_tcp_rx(&se->coap, sk->rbuf, size);

  while (true)
  {
    log(L_TRACE "yang_session_rx: loop iter");
    /* Aggresively send data if possible */
    coap_tx_flush(&se->coap, sk);
    log(L_TRACE "yang_session_rx: flushed");

    /* Next parser step */
    if (!coap_tcp_parse(&se->coap))
    {
      log(L_TRACE "yang_session_rx: no parse step");
      return 1;
    }
    log(L_TRACE "yang_session_rx: process");

    /* It may be CoAP internal */
    if (coap_process(&se->coap))
    {
      log(L_TRACE "yang_session_rx: internal coap action");
      continue;
    }

    /* Or the current endpoint will take care */
    log(L_TRACE "yang_session_rx: endpoint info %p", se->endpoint);
    if (se->endpoint(se))
    {
      log(L_TRACE "yang_session_rx: endpoint not finished");
      continue;
    }

    log(L_TRACE "yang_session_rx: endpoint done, flushing");
    /* Send remaining data if possible */
    coap_tx_flush(&se->coap, sk);
    se->coreconf_state = CC_COAP_HEADER;
    return 1;
  }

   bug("yang_session_rx unreachable");
}

static void
yang_session_tx(sock *sk)
{
  struct yang_session *se = sk->data;

  coap_tx_written(&se->coap, sk);
  coap_tx_flush(&se->coap, sk);
}

static void
yang_session_err(sock *sk, int err)
{
  struct yang_session *se = sk->data;
  struct yang_socket *s = se->socket;
  SKIP_BACK_DECLARE(struct yang_api, api, listen, yang_socket_enlisted(s));

  if (err)
    log(L_INFO "%s: Connection lost (%M)", api->name, err);
  else
    log(L_INFO "%s: Connection closed", api->name);

  sk_close(sk);
  mb_free(se);
}

static int
yang_socket_accept(sock *sk, uint size UNUSED)
{
  struct yang_socket *s = sk->data;
  SKIP_BACK_DECLARE(struct yang_api, api, listen, yang_socket_enlisted(s));

  struct yang_session *se = mb_allocz(api->pool, sizeof *se);
  se->sock = sk;
  se->socket = s;
  se->endpoint = yang_default_endpoint;
  se->accept = COAP_CF_NO_VALUE;
  se->cont_format = COAP_CF_NO_VALUE;
  se->core_query = UNKNOWN_RESOURCE;
  se->core_report_all = false;
  se->coreconf_state = CC_COAP_HEADER;

  coap_session_init(&se->coap);
  se->cbor = cbor_parser_new(api->pool, 16);

  sk->rx_hook = yang_session_rx;
  sk->tx_hook = yang_session_tx;
  sk->err_hook = yang_session_err;
  sk->data = se;

  return 0;
}

static void
yang_listen_error(sock *sk, int err)
{
  struct yang_socket *s = sk->data;
  SKIP_BACK_DECLARE(struct yang_api, api, listen, yang_socket_enlisted(s));

  if (err == ECONNABORTED)
    log(L_WARN "%s: Incoming connection aborted", api->name);
  else
    log(L_ERR "%s: Error on listening socket: %M", err);
}

static void
yang_socket_olocked(void *_s)
{
  struct yang_socket *s = _s;
  SKIP_BACK_DECLARE(struct yang_api, api, listen, yang_socket_enlisted(s));

  s->sock = sock_new(api->pool);

  switch (s->params.kind)
  {
    case YANG_SOCKET_COAP_TCP:
      s->sock->pool = api->pool;
      s->sock->type = SK_TCP_PASSIVE;
      break;

    default:
      bug("Not implemented yet");
  }

  s->sock->saddr = s->params.local_ip;
  s->sock->sport = s->params.port;
  // We want SO_REUSEADDR (this make testing easier due to faster port reuse)
  s->sock->flags |= SKF_BIND;

  s->sock->rbsize = 16384;
  s->sock->tbsize = 16384;

  s->sock->rx_hook = yang_socket_accept;
  s->sock->err_hook = yang_listen_error;

  s->sock->data = s;

  sk_open(s->sock, &main_birdloop);

  int y = 1;
  if (setsockopt(s->sock->fd, SOL_SOCKET, SO_REUSEPORT, &y, sizeof(y)) < 0)
    bug("SO_REUSEPORT");
}

static void
yang_socket_new(struct yang_api *api, struct yang_socket_config *sc)
{
  struct yang_socket *s = mb_allocz(api->pool, sizeof *s);

  s->config = sc;
  sc->socket = s;
  yang_socket_add_tail(&api->listen, s);

  s->params = sc->params;

  s->olock = olock_new(api->pool);
  s->olock->addr = sc->params.local_ip;
  s->olock->port = sc->params.port;
  s->olock->event.hook = yang_socket_olocked;
  s->olock->event.data = s;
  s->olock->target = &global_event_list;

  switch (sc->params.kind)
  {
    case YANG_SOCKET_COAP_TCP:
      s->olock->type = OBJLOCK_TCP;
      break;

    case YANG_SOCKET_COAP_UDP:
      s->olock->type = OBJLOCK_UDP;
      break;

    default:
      bug("Strange API endpoint kind: %d", sc->params.kind);
  }

  olock_acquire(s->olock);
}

static void
yang_socket_delete(struct yang_socket *s)
{
  rfree(s->olock);
  rfree(s->sock);

#if 0
      switch (api->params.kind)
      {
	case YANG_SOCKET_COAP_TCP:
	  yang_socket_coap_tcp_delete(api);
	  break;

	case YANG_SOCKET_COAP_UDP:
	  yang_socket_coap_udp_delete(api);
	  break;

	default:
	  bug("Strange API endpoint kind: %d", api->params.kind);
      }
#endif
}

static void
yang_api_new(struct yang_api_config *ac)
{
  pool *p = rp_newf(yang_pool, yang_pool->domain, "YANG API %s", ac->name);
  struct yang_api *api = mb_allocz(p, sizeof *api);

  api->name = ac->name;
  api->pool = p;
  api->config = ac;
  api->params = ac->params;

  WALK_TLIST(yang_socket_config, sc, &ac->listen)
    yang_socket_new(api, sc);
}

static void
yang_api_delete(struct yang_api *api)
{
  WALK_TLIST_DELSAFE(yang_socket, s, &api->listen)
    yang_socket_delete(s);

  ASSERT_DIE(EMPTY_TLIST(yang_socket, &api->listen));

  api->config->api = NULL;

  rp_free(api->pool);
}

static void
yang_api_reconfigure(struct yang_api *api)
{
  /* Match sockets to new config */
  WALK_TLIST(yang_socket_config, sc, &api->config->listen)
  {
    /* Looking for the same socket */
    WALK_TLIST(yang_socket, s, &api->listen)
      if (yang_socket_same(&s->params, &sc->params))
	/* Found same */
      {
	ASSERT_DIE(yang_socket_config_enlisted(s->config) != &api->config->listen);
	/* Drop the old config pointer */
	s->config->socket = NULL;

	/* Set the new pointers */
	s->config = sc;
	sc->socket = s;

	break;
      }

    /* Not found */
    if (!sc->socket)
      yang_socket_new(api, sc);
  }

  /* Delete sockets not defined in new config */
  WALK_TLIST_DELSAFE(yang_socket, s, &api->listen)
    if (yang_socket_config_enlisted(s->config) != &api->config->listen)
      yang_socket_delete(s);

}

void
yang_commit(struct config *new, struct config *old)
{
  /* Match running APIs to new config */
  WALK_TLIST(yang_api_config, ac, &new->yang)
  {

    /* Is there an API with the same name?
     * Note: We expect the users to not have lots of API endpoints configured,
     * and therefore this is ok being O(N^2). */
    WALK_TLIST(yang_api, api, &global_api_list)
      if (!strcmp(api->name, ac->name))
      {
	ASSERT_DIE(api->config->global == old);
	ASSERT_DIE(api->config->api == api);

	if (yang_api_same(&api->params, &ac->params))
	  /* Found same, keep */
	{
	  /* Drop the old config pointer */
	  api->config->api = NULL;

	  /* Set the new pointers */
	  api->config = ac;
	  ac->api = api;

	  /* The name is shared with the symbol */
	  api->name = ac->name;

	  /* Reconfigure sockets */
	  yang_api_reconfigure(api);
	}

	/* Otherwise, we just pretend nothing was found */
	break;
      }

    /* Found same, done */
    if (ac->api)
      continue;

    /* Make new API endpoint */
    yang_api_new(ac);

    log(L_INFO "coreconf_yang_library %p", coreconf_yang_library);
    log(L_INFO "coreconf_datastore %p", coreconf_datastore);
    log(L_INFO "yang_model_cli_endpoint_c %p", yang_model_cli_endpoint_c);
    log(L_INFO "yang_default_endpoint %p", yang_default_endpoint);
  }

  /* Find unmatched endpoints and delete them */
  WALK_TLIST_DELSAFE(yang_api, api, &global_api_list)
    if (api->config->global != new)
    {
      api->config->api = NULL;
      yang_api_delete(api);
    }

  /* Consistency check of the old config */
  WALK_TLIST(yang_api_config, ac, &new->yang)
    ASSERT_DIE(!ac->api);
}

/**
 * yang_init - initialize needed YANG data structures on startup
 */
void
yang_init(void)
{
  yang_pool = rp_new(&root_pool, root_pool.domain, "YANG API toplevel");
}

