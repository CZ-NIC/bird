/*
*	BIRD -- CORECONF
*
*	(c) 2026       Vojtech Vilimek <vojtech.vilimek@nic.cz>
*	(c) 2026       CZ.NIC, z.s.p.o.
*
*	Can be freely distributed and used under the terms of the GNU GPL.
*/

#include "conf/conf.h"
#include "lib/cbor.h"
#include "lib/coap.h"
#include "yang/yang.h"
#include "yang/model.h"
#include "yang/coreconf.h"

const char *coreconf_state_names[] = {
"CC_COAP_HAEDER",
"CC_CHECK_HEADER",
"CC_YL_SEND",
"CC_CREATE_SUBSCRIPTION",
"CC_OP",
"CC_RPC_ACTION",
"CC_DONE",
"CC_ERROR",
};

struct resource_info content_format_by_resource[] = {
/* More work need to be done for POST */
{ CORECONF_DATASTORE,    COAP_REQ_POST,   COAP_CF_YANG_CBOR,        COAP_CF_NO_VALUE       },

/*
* The entries below are duplicated by design, usage of first case match is sufficient becuase 
* CORECONF never sees the pair (CORECONF_DATASTORE, COAP_REQ_POST). At least after parsing
* the whole CoAP request header.
*/
{ CORECONF_DATASTORE,    COAP_REQ_POST,   COAP_CF_YANG_INSTANCES,   COAP_CF_YANG_INSTANCES },
{ CORECONF_RPC_ACTION,   COAP_REQ_POST,   COAP_CF_YANG_INSTANCES,   COAP_CF_YANG_INSTANCES },

{ CORECONF_DATASTORE,    COAP_REQ_FETCH,  COAP_CF_YANG_IDENTIFIERS, COAP_CF_YANG_INSTANCES },
{ CORECONF_DATASTORE,    COAP_REQ_IPATCH, COAP_CF_YANG_INSTANCES,   COAP_CF_NO_VALUE       },
{ CORECONF_DATASTORE,    COAP_REQ_GET,    COAP_CF_NO_VALUE,         COAP_CF_YANG_CBOR      },
{ CORECONF_DATASTORE,    COAP_REQ_PUT,    COAP_CF_YANG_CBOR,        COAP_CF_NO_VALUE       },
{ CORECONF_DATASTORE,    COAP_REQ_DELETE, COAP_CF_NO_VALUE,         COAP_CF_NO_VALUE       },
{ CORECONF_YANG_LIB,     COAP_REQ_GET,    COAP_CF_NO_VALUE,         COAP_CF_YANG_CBOR      },
{ CORECONF_EVENT_STREAM, COAP_REQ_GET,    COAP_CF_NO_VALUE,         COAP_CF_YANG_INSTANCES },
{ CORECONF_EVENT_STREAM, COAP_REQ_FETCH,  COAP_CF_YANG_IDENTIFIERS, COAP_CF_YANG_INSTANCES },
{ UNKNOWN_RESOURCE, },
};


void
coreconf_datastore_fetch(void)
{

}

void
coreconf_datastore_ipatch(void)
{

}

void
coreconf_datastore_put(void)
{

}

void
coreconf_datastore_get(void)
{

}

enum yang_proc_state
rpc_show_status_in(struct yang_session *se, void **in_data)
{
if (!*in_data)
*in_data = mb_allocz(yang_pool, sizeof(struct rpc_show_status));

struct rpc_show_status *data_ptr = *in_data;

const char *payload = se->coap.parser.payload;
uint len = se->coap.parser.payload_chunk_len;
if (!len)
return YP_OK;

switch (data_ptr->state)
{
case STATUS_BEGIN:
switch (cbor_parse_byte(se->cbor, payload[0]))
{
case CPR_STR_BUF_END:
case CPR_STR_END:
case CPR_ERROR: return YP_ERR;
case CPR_MORE: return YP_WAIT;
case CPR_MAJOR:
switch (se->cbor->type)
{
case CBOR_MAP:
data_ptr->state = STATUS_CLOSE;
break;
default:
return YP_ERR;
}
}

len--;
payload++;
if (!len)
return YP_WAIT;

/* fall through */
case STATUS_CLOSE:
if (!cbor_parse_block_end(se->cbor))
return YP_ERR;
break;

default:
bug("unreachable %u", __LINE__);
}

mb_free(*in_data);
*in_data = NULL;

return YP_OK;
}

bool
rpc_show_status(void *in UNUSED, void **out)
{
*out = mb_allocz(yang_pool, sizeof(struct rpc_show_status_out));
struct rpc_show_status_out *status = *out;
char *buf = (char *) &status->data;
uint len = ARRAY_SIZE(status->data);

extern int shutting_down;
extern int configuring;

/* based on cmd_show_status() (file nest/cmds.c) */ 
rcu_read_lock();
struct global_runtime *gr = atomic_load_explicit(&global_runtime, memory_order_acquire);
struct timeformat *tf = &gr->tf_base;
byte tim[TM_DATETIME_BUFFER_SIZE];

uint written = bsnprintf(buf, len, "BIRD " BIRD_VERSION "\n");
buf += written;
len -= written;
written = bsnprintf(buf, len, "Router ID is %R\n", gr->router_id);
buf += written;
len -= written;
written = bsnprintf(buf, len, "Hostname is %s\n", gr->hostname);
buf += written;
len -= written;
tm_format_time(tim, tf, current_time());
written = bsnprintf(buf, len, "Current server time is %s\n", tim);
buf += written;
len -= written;
tm_format_time(tim, tf, boot_time);
written = bsnprintf(buf, len, "Last reboot on %s\n", tim);
buf += written;
len -= written;

// gr restart show status

if (shutting_down)
written = bsnprintf(buf, len, "Shutdown in progress\n");
else if (configuring)
written = bsnprintf(buf, len, "Reconfiguration in progress\n");
else
written = bsnprintf(buf, len, "Daemon is up and running\n");

rcu_read_unlock();

*out = buf;
return true; // ok
}

enum yang_proc_state
rpc_show_status_out(struct yang_session *se, void *out)
{
struct rpc_show_status_out *out_data = out;
switch (out_data->status.state)
{
case STATUS_BEGIN:
cbor_writer_init(&se->cbor_writer, /* max depth */ 32,
se->write_buffer, se->write_buffer_len);
out_data->status.state = STATUS_WRITER_READY;

/* fall through */
case STATUS_WRITER_READY:
if (!cbor_open_map(&se->cbor_writer))
return YP_ERR;
out_data->status.state = STATUS_MAP;

/* fall through */
case STATUS_MAP:
if (!cbor_put(&se->cbor_writer, CBOR_POSINT, 60030)) /* rpc cli-show-status absolute SID */
return YP_ERR;
out_data->status.state = STATUS_SID;

/* fall through */
case STATUS_SID:
if (!cbor_open_map(&se->cbor_writer))
return YP_ERR;
out_data->status.state = STATUS_MAP2;

/* fall through */
case STATUS_MAP2:
if (!cbor_put(&se->cbor_writer, CBOR_POSINT, 3)) /* leaf status absolute SID 60033 */
return YP_ERR;
out_data->status.state = STATUS_SID2;

/* fall through */
case STATUS_SID2:
if (!cbor_put_raw_bytes(&se->cbor_writer, CBOR_TEXT, out_data->data, strlen(out_data->data)))
return YP_ERR;
out_data->status.state = STATUS_CLOSE;

/* fall through */
case STATUS_CLOSE:
if (!cbor_close_map(&se->cbor_writer))
return YP_ERR;
out_data->status.state = STATUS_CLOSE2;

/* fall through */
case STATUS_CLOSE2:
if (!cbor_close_map(&se->cbor_writer))
return YP_ERR;
out_data->status.state = STATUS_DONE;

/* fall through */
case STATUS_DONE:
break;
}

return YP_OK;
}

enum yang_proc_state
rpc_load_config_in(struct yang_session *se, void **in_data)
{
if (!*in_data)
*in_data = mb_allocz(yang_pool, sizeof(struct rpc_load_config));

struct rpc_load_config *data_ptr = *in_data;

const char *payload = se->coap.parser.payload;
uint len  = se->coap.parser.payload_chunk_len;
if (!len)
return YP_OK;

switch (data_ptr->state)
{
case STATUS_BEGIN:
switch (cbor_parse_byte(se->cbor, payload[0]))
{
case CPR_STR_END:
case CPR_STR_BUF_END:
case CPR_ERROR: return YP_ERR;
case CPR_MORE: return YP_WAIT;
case CPR_MAJOR:
switch (se->cbor->type)
{
case CBOR_MAP:
data_ptr->state = STATUS_MAP;
break;
default:
return YP_ERR;
}
}

len--;
payload++;
if (!len)
return YP_WAIT;

/* fall through */
case STATUS_MAP:
u64 child_sid;
switch (cbor_parse_byte(se->cbor, payload[0]))
{
case CPR_STR_END:
case CPR_STR_BUF_END:
case CPR_ERROR: return YP_ERR;
case CPR_MORE: return YP_WAIT;
case CPR_MAJOR:
switch (se->cbor->type)
{
case CBOR_POSINT:
child_sid = /* parent */ 60025 + se->cbor->value;
break;
case CBOR_NEGINT:
bug("unexpected neg rel sid");
break;
default:
return YP_ERR;
}
}

switch (child_sid)
{
case 60027: // TODO
/* we will parse the child together with it's value here, inplace */
/* only for the sake of making things easier right now */
data_ptr->state = STATUS_SID;
break;
default:
bug("unexpected sid %u", child_sid);
break;
}

len--;
payload++;
if (!len)
return YP_WAIT;

/* fall through */
case STATUS_SID: /* we have parsed the identifing SID, now the value */
switch (cbor_parse_byte(se->cbor, payload[0]))
{
case CPR_STR_END:
case CPR_STR_BUF_END:
case CPR_ERROR: return YP_ERR;
case CPR_MORE: return YP_WAIT;
case CPR_MAJOR:
switch (se->cbor->type)
{
case CBOR_MAP:
data_ptr->state = STATUS_MAP2;
break;
default:
return YP_ERR;
}
}

len--;
payload++;
if (!len)
return YP_WAIT;

/* fall through */
case STATUS_MAP2:
switch (cbor_parse_byte(se->cbor, payload[0]))
{
case CPR_STR_END:
case CPR_STR_BUF_END:
case CPR_ERROR: return YP_ERR;
case CPR_MORE: return YP_WAIT;
case CPR_MAJOR:
switch (se->cbor->type)
{
case CBOR_POSINT:
child_sid = /* parent */ 60027 + se->cbor->value;
break;
case CBOR_NEGINT:
bug("unexpected neg rel sid");
break;
default:
return YP_ERR;
}
}

switch (child_sid)
{
case 60028:
data_ptr->state = STATUS_SID2;
break;
default:
return YP_ERR;
}

len--;
payload++;
if (!len)
return YP_WAIT;

se->cbor->target_buf = (char *) &data_ptr->filename;
se->cbor->target_len = sizeof(data_ptr->filename);

/* fall through */ 
case STATUS_SID2:
while (!cbor_parse_block_end(se->cbor))
{
switch (cbor_parse_byte(se->cbor, payload[0]))
{ 
case CPR_ERROR: return YP_ERR;
case CPR_MORE: return YP_WAIT;
case CPR_MAJOR:
if (se->cbor->type != CBOR_TEXT)
return YP_ERR;
break;
case CPR_STR_END:
data_ptr->state = STATUS_CLOSE;
break;
case CPR_STR_BUF_END:
bug("buffer too small");
}

len--;
payload++;
if (!len)
return YP_WAIT;
}

if (!se->cbor->target_len)
{
se->cbor->target_buf[se->cbor->target_len++] = '\0';
}
log(L_ERR "new config filename: %s", &data_ptr->filename);

/* fall through */
case STATUS_CLOSE:
switch (cbor_parse_byte(se->cbor, payload[0]))
{
case CPR_STR_BUF_END:
case CPR_STR_END:
case CPR_ERROR: return YP_ERR;
case CPR_MORE: return YP_WAIT;
case CPR_MAJOR:
data_ptr->state = STATUS_DONE;
}

/* fall through */
case STATUS_DONE:
break;

default:
bug("unreachable %u", __LINE__);
}

mb_free(*in_data);
*in_data = NULL;
return YP_OK;
}

enum yang_proc_state
rpc_load_config_out(struct yang_session *se, void *out)
{
struct rpc_load_config_out *out_data = out;

switch (out_data->state)
{
case STATUS_BEGIN: 
cbor_writer_init(&se->cbor_writer, /* max depth */ 32,
se->write_buffer, se->write_buffer_len);
out_data->state = STATUS_WRITER_READY;

/* fall through */
case STATUS_WRITER_READY:
if (!cbor_open_map(&se->cbor_writer))
return YP_ERR;
out_data->state = STATUS_MAP;

/* fall through */
case STATUS_MAP:
if (!cbor_put(&se->cbor_writer, CBOR_POSINT, 60027)) // TODO SID
return YP_ERR;
out_data->state = STATUS_SID;

/* fall through */
case STATUS_SID:
if (!cbor_open_map(&se->cbor_writer))
return YP_ERR;
out_data->state = STATUS_CLOSE;

/* fall through */
case STATUS_CLOSE:
if (!cbor_close_map(&se->cbor_writer))
return YP_ERR;
out_data->state = STATUS_CLOSE2;

/* fall through */
case STATUS_CLOSE2:
if (!cbor_close_map(&se->cbor_writer))
return YP_ERR;
out_data->state = STATUS_DONE;

/* fall through */
case STATUS_DONE:
break;

default:
bug("unreachable %u", __LINE__);
}

return YP_OK;
}

void cmd_reconfig(const char *name, int type, uint timeout);

bool
rpc_load_config(void *in UNUSED, void **out)
{
*out = mb_allocz(yang_pool, sizeof(struct rpc_load_config_out));
struct rpc_load_config *in_data = in;

cmd_reconfig(in_data->filename, RECONFIG_HARD, 10 /* sec */);  
return true; // ok
}

#if 0
enum yang_proc_state
uytc_rpc(struct yang_session *se)
{
if (!se->rpc)
{
struct uytc_rpc_data *data = mb_alloc(yang_pool, sizeof(*se->rpc));
data->state = RPC_BEGIN;
data->in_data = NULL;
data->out_data = NULL;
data->in_fn = NULL;
data->out_fn = NULL;
data->rpc = NULL;

se->rpc = data;
}

const char *payload = se->coap.parser.payload;
uint len = se->coap.parser.payload_chunk_len;
if (se->coap.parser.state == COAP_PS_PAYLOAD_COMPLETE &&
se->coap.parser.payload_total_len == 0)
{
struct coap_tx_option *cf = COAP_TX_OPTION_INT(COAP_OPT_CONTENT_FORMAT, (u16) COAP_CF_YANG_INSTANCES);
coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_RESP_CHANGED, cf));
return YP_OK;
}

/* things to think trough:
* - when and where to allocate the node status data?
* - how to manage cleanup during YP_ERR?
* - how to report errors, set status code and influence the error content/payload
*/
enum yang_proc_state yp;
switch (se->rpc->state)
{
case RPC_BEGIN:
switch (cbor_parse_byte(se->cbor, payload[0]))
{
case CPR_STR_END:
case CPR_STR_BUF_END:
case CPR_ERROR: return YP_ERR;
case CPR_MORE: return YP_WAIT;
case CPR_MAJOR:
switch (se->cbor->type)
{
case CBOR_MAP:
se->rpc->state = RPC_ID;
break;
default:
return YP_ERR;
}
}

len--;
payload++;
if (!len)
return YP_WAIT;
/* fall through */
case RPC_ID:
switch (cbor_parse_byte(se->cbor, payload[0]))
{
case CPR_STR_BUF_END:
case CPR_STR_END:
case CPR_ERROR: return YP_ERR;
case CPR_MORE: return YP_WAIT;
case CPR_MAJOR:; 
}

switch (se->cbor->type)
{
case CBOR_POSINT:
u64 sid = se->cbor->value;
switch (sid)
{
case 60001: /* rpc cli-show-memory */
// TODO move the alloc into the handling functions (maybe start vs. init)?
bug("not yet implemented");
break;
case 60025: /* rpc cli-load-config */
log(L_INFO "rpc cli-load-config");
se->rpc->in_fn = rpc_load_config_in;
se->rpc->rpc = rpc_load_config;
se->rpc->out_fn = rpc_load_config_out;
break;
case 60031: /* rpc cli-show-status */
log(L_INFO "rpc cli-show-status");
se->rpc->in_fn = rpc_show_status_in;
se->rpc->rpc = rpc_show_status;
se->rpc->out_fn =  rpc_show_status_out;
break;	
default:
return YP_ERR;
}
break;
case CBOR_NEGINT:
log(L_ERR "Negative int is not a valid SID.");
return YP_ERR;
case CBOR_TAG:
log(L_ERR "Identification using tags is not implemented");
return YP_ERR;
default:
log(L_ERR "Unexpected CBOR major type %u", se->cbor->type);
return YP_ERR;
}
se->rpc->state = RPC_PARSING;
/* fall through */
case RPC_PARSING:
yp = se->rpc->in_fn(se, &se->rpc->in_data);
switch (yp)
{
case YP_OK:
se->rpc->state = RPC_PROC;
break;
case YP_WAIT:
case YP_ERR:
return yp;
}

/* fall through */
case RPC_PROC:
if (!se->rpc->rpc(se->rpc->in_data, &se->rpc->out_data))
{
log(L_ERR "");
return YP_ERR;
}
se->rpc->state = RPC_GEN;

/* fall through */
case RPC_GEN:
yp = se->rpc->out_fn(se, se->rpc->out_data);
switch (yp)
{
case YP_OK:
se->rpc->state = RPC_DONE;
break;
case YP_WAIT:
case YP_ERR:
return yp;
}

/* fall through */
case RPC_DONE:
return YP_OK;

default:
bug("unreachable %u", __LINE__);
}
}
#endif

enum yang_proc_state uytc_rpc(struct yang_session *se);

bool
coreconf_rpc_action(struct yang_session *se)
{
log(L_INFO "YANG: coreconf_rpc_action");
enum yang_proc_state yp;
switch (se->coreconf_state) {
case CC_RPC_ACTION:
yp = yang_common_coap_endpoint(se);
switch (yp) {
case YP_ERR:
se->coreconf_state = CC_ERROR;
return false;
case YP_WAIT: return true;
case YP_OK:
se->coreconf_state = CC_RPC_ACTION_BODY;
}
se->coreconf_processing = true;
/* fall-through */
case CC_RPC_ACTION_BODY:
enum yang_proc_state yp;
yp = uytc_rpc(se);
if (yp == YP_WAIT)
return true;
/*
if (yp == YP_OK || yp == YP_ERR)
return false;
else
return true;
*/

/* fall-through */
case CC_DONE:
se->coreconf_processing = false;
switch (yp)
{
case YP_OK:
struct coap_tx_option *cf = COAP_TX_OPTION_INT(COAP_OPT_CONTENT_FORMAT, (u16) COAP_CF_YANG_INSTANCES);
log(L_INFO "coreconf_rpc_action COAP_TX_RESPONSE");
coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_RESP_CHANGED, cf));
break;
case YP_ERR:
log(L_INFO "coreconf_rpc_action COAP_TX_RESP ERROR");
struct coap_tx_option *debug = COAP_TX_OPTION_PRINTF(0, "rpc resulted in error (YP_ERR)");
coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_CERR_BAD_REQUEST, debug));
break;
case YP_WAIT:
bug("unreachable %u", __LINE__);
}
return false;
default:
se->coreconf_processing = false;
se->coreconf_state = CC_ERROR;
return false;
}

return false;
}

bool
coreconf_stream_subscribe(struct yang_session *se)
{
log(L_INFO "YANG: coreconf_stream_subscribe");
// TODO Observe option
enum yang_proc_state yp;
switch (se->coreconf_state) {
case CC_COAP_HEADER:
yp = yang_common_coap_endpoint(se);
switch (yp) {
case YP_ERR:
se->coreconf_state = CC_ERROR;
return false;
case YP_WAIT: return true;
case YP_OK:
se->coreconf_state = CC_CREATE_SUBSCRIPTION;
}
/* fall-through */
case CC_CREATE_SUBSCRIPTION:
// TODO this is incorrent, we just want success without data
// 2.05 Changed nor 2.01 Created does not sound right
log(L_INFO "coreconf_stream_subscribe COAP_TX_RESPONSE");
struct coap_tx_option *cf = COAP_TX_OPTION_INT(COAP_OPT_CONTENT_FORMAT, (u16) COAP_CF_YANG_INSTANCES);
coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_RESP_CONTENT, cf));
se->coreconf_state = CC_COAP_HEADER;
return false;
default:
se->coreconf_state = CC_ERROR;
return false;
}

return false;
}

bool
coreconf_stream_filtered(struct yang_session *se)
{
log(L_INFO "YANG: coreconf_stream_filtered");
// TODO Observe option
enum yang_proc_state yp;
switch (se->coreconf_state) {
case CC_COAP_HEADER:
yp = yang_common_coap_endpoint(se);
switch (yp) {
case YP_ERR:
se->coreconf_state = CC_ERROR;
return false; 
case YP_WAIT: return true;
case YP_OK:
se->coreconf_state = CC_CREATE_SUBSCRIPTION;
}
/* fall-through */
case CC_CREATE_SUBSCRIPTION:
// TODO this is incorrent, we just want success without data
// 2.05 Changed nor 2.01 Created does not sound right
log(L_INFO "coreconf_stream_filtered COAP_TX_RESPONSE");
coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_RESP_VALID));
se->coreconf_state = CC_COAP_HEADER;
return false;
default:
se->coreconf_state = CC_ERROR;
return false;
}

return false;
}

bool
coreconf_yang_library(struct yang_session *se)
{
log(L_INFO "YANG: coreconf_yang_library");
enum yang_proc_state yp;
switch (se->coreconf_state) {
case CC_COAP_HEADER:
log(L_TRACE "YANG: cc_yang_library COAP_HEADER");
yp = yang_common_coap_endpoint(se);
switch (yp) {
case YP_ERR:
se->coreconf_state = CC_ERROR;
return false;
case YP_WAIT: return true;
case YP_OK:
se->coreconf_state = CC_CHECK_HEADER;
}
/* fall-through */
case CC_CHECK_HEADER:
log(L_TRACE "YANG: cc_yang_library CHECK_HEADER");
if (se->coap.parser.code != COAP_REQ_GET)
{
struct coap_tx_option 
//*cf = get_response_content_format(se->resource_type, se->coap.parser.code),
*cf = COAP_TX_OPTION_INT(COAP_OPT_CONTENT_FORMAT, (u8) COAP_CF_LINK_FORMAT),
*payload = COAP_TX_OPTION_PRINTF(
0, "The YANG Library endpoint allows only GET request.");
log (L_INFO "coreconf_yang_library COAP_TX_RESONSE header error");
coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_CERR_METHOD_NOT_ALLOWED, cf, payload));
se->error_sent = true;
se->coreconf_state = CC_DONE;
return false;
}
se->coreconf_state = CC_YL_SEND; 
/* fall-through */
case CC_YL_SEND:
log(L_TRACE "YANG: cc_yang_library sending");
struct coap_tx_option 
//*content_format = get_response_content_format(se->resource_type, se->coap.parser.code),
*cf = COAP_TX_OPTION_INT(COAP_OPT_CONTENT_FORMAT, (u8) COAP_CF_LINK_FORMAT),
*payload = COAP_TX_OPTION_PRINTF(
0, "Constrained YANG Library goes here");

log(L_INFO "coreconf_yang_library COAP_TX_RESPONSE ok");
coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_RESP_CONTENT,
cf, payload));

se->coreconf_state = CC_DONE;
//se->coreconf_state = CC_COAP_HEADER;
return false;  

case CC_ERROR:
// TODO close the conn
return true;

default: // case CC_DONE:
}

log(L_INFO "YANG: coreconf_yang_library after switch, should not happen");
return false;
}

bool
coreconf_event_stream(struct yang_session *se)
{
log(L_INFO "YANG: coreconf_event_stream operation with CORECONF_EVENT_STREAM");
// TODO Observe option
enum yang_proc_state yp;
switch (se->coreconf_state) {
case CC_COAP_HEADER:
yp = yang_common_coap_endpoint(se);
switch (yp) {
case YP_ERR:
se->coreconf_state = CC_ERROR;
return false; 
case YP_WAIT: return true;
case YP_OK:
se->coreconf_state = CC_CREATE_SUBSCRIPTION;
}
/* fall-through */
case CC_CREATE_SUBSCRIPTION:
// TODO this is incorrent, we just want success without data
// 2.05 Changed nor 2.01 Created does not sound right
log(L_INFO "coreconf_event_stream COAP_TX_RESPONSE");
struct coap_tx_option *cf = COAP_TX_OPTION_INT(COAP_OPT_CONTENT_FORMAT, (u16) COAP_CF_YANG_INSTANCES);
coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_RESP_VALID, cf));
se->coreconf_state = CC_DONE;
return false;
default:
se->coreconf_state = CC_ERROR;
return YP_ERR;
}

return YP_ERR;
}

bool
coreconf_datastore(struct yang_session *se)
{
//log(L_INFO "YANG: coreconf_datastore operation with CORECONF_DATASTORE");
enum yang_proc_state yp;
switch (se->coreconf_state) {
case CC_COAP_HEADER:
yp = yang_common_coap_endpoint(se);
log(L_INFO "[DEBUG] coreconf_datastore common_coap_endpoint %u", yp);
switch (yp) {
case YP_ERR:
se->coreconf_state = CC_ERROR;
return false; 
case YP_WAIT: return true;
case YP_OK:
if (se->resource_type == CORECONF_DATASTORE)
se->coreconf_state = CC_OP;	
else
{
ASSERT(se->resource_type == CORECONF_RPC_ACTION);
se->endpoint = coreconf_rpc_action;
se->coreconf_state = CC_RPC_ACTION;
goto ds_rpc_action;
}
}
se->coreconf_processing = true;
/* fall-through */
case CC_OP:
// TODO this is incorrent, we just want success without data
// 2.05 Changed nor 2.01 Created does not sound right
//struct coap_tx_option *cf = get_response_content_format(se->resource_type, se->coap.parser.code);
//coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_RESP_VALID, cf));
log(L_INFO "[DEBUG] CC_OP", yp);

struct coap_tx_option *cf = NULL;
switch (se->coap.parser.code)
{
case COAP_REQ_FETCH: cf = COAP_TX_OPTION_INT(COAP_OPT_CONTENT_FORMAT, (u16) COAP_CF_YANG_INSTANCES); break;
case COAP_REQ_IPATCH: cf = NULL; break;
case COAP_REQ_GET: cf = COAP_TX_OPTION_INT(COAP_OPT_CONTENT_FORMAT, (u8) COAP_CF_YANG_CBOR); break;
case COAP_REQ_PUT: cf = NULL; break;
case COAP_REQ_POST: cf = NULL; break;
case COAP_REQ_DELETE: cf = NULL; break;

default: bug("unreachable %x %u", se->coap.parser.code, __LINE__);
}

coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_RESP_CHANGED, cf));
se->coreconf_state = CC_DONE;
return false;

default:
log(L_INFO "[DEBUG] default %u %s", se->coreconf_state, coreconf_state_names[se->coreconf_state]);
se->coreconf_state = CC_ERROR;
return false;

ds_rpc_action:
case CC_RPC_ACTION:
log(L_INFO "[DEBUG] CC_RPC_ACTION");
return coreconf_rpc_action(se); 
}

log(L_INFO "coreconf_datastore this shouldn't be reachable");
return false;
}

