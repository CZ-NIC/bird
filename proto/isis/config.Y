/*
 *	BIRD -- IS-IS Configuration
 *
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/isis/isis.h"

CF_DEFINES

#define ISIS_CFG ((struct isis_config *) this_proto)
#define ISIS_IFACE ((struct isis_iface_config *) this_ipatt)

static byte area_id_buffer[13];
static byte *area_id_bpos;

CF_DECLS

CF_KEYWORDS(AREA, BCAST, BROADCAST, BUFFER, CSNP, HELLO, HOLD, ID, INTERFACE, ISIS, LEVEL, LIFETIME,
	LSP, METRIC, MULT, PASSIVE, POINTOPOINT, PRIORITY, PSNP, PTP, RETRANSMIT, RX, SIZE, SYSTEM,
	TX, TYPE)


%type<i> isis_level

CF_GRAMMAR

CF_ADDTO(proto, isis_proto)

isis_proto_start: proto_start ISIS
{
  this_proto = proto_config_new(&proto_isis, sizeof(struct isis_config), $1);
  init_list(&ISIS_CFG->patt_list);
  ISIS_CFG->lsp_lifetime = ISIS_DEFAULT_LSP_LIFETIME;
  ISIS_CFG->rx_buffer_size = ISIS_DEFAULT_RX_BUFFER_SIZE;
  ISIS_CFG->tx_buffer_size = ISIS_DEFAULT_TX_BUFFER_SIZE;
};

isis_proto_item:
   proto_item
 | INTERFACE isis_iface
 | AREA ID isis_area_id
 | SYSTEM ID isis_system_id
 | LSP LIFETIME expr { ISIS_CFG->lsp_lifetime = $3; cf_range("LSP lifetime", $3, 300, 65535); }
 | RX BUFFER SIZE expr { ISIS_CFG->rx_buffer_size = $4; cf_range("RX buffer size", $4, 256, 65535); }
 | TX BUFFER SIZE expr { ISIS_CFG->tx_buffer_size = $4; cf_range("TX buffer size", $4, 256, 65535); }
 ;

isis_proto_finish:
{
  struct isis_config *cf = ISIS_CFG;

  if (! cf->areas[0])
    cf_error("Missing area ID");

  if (cf->rx_buffer_size < cf->tx_buffer_size)
    cf_error("RX buffer size must be greater than TX buffer size");
}

isis_proto_opts:
   /* empty */
 | isis_proto_opts isis_proto_item ';'
 ;

isis_proto:
   isis_proto_start proto_name '{' isis_proto_opts '}';


isis_iface_start:
{
  this_ipatt = cfg_allocz(sizeof(struct isis_iface_config));
  add_tail(&ISIS_CFG->patt_list, NODE this_ipatt);

  ISIS_IFACE->levels[ISIS_L1] = ISIS_DEFAULT_LEVEL_1;
  ISIS_IFACE->levels[ISIS_L2] = ISIS_DEFAULT_LEVEL_2;
  ISIS_IFACE->metric = ISIS_DEFAULT_METRIC;
  ISIS_IFACE->priority = ISIS_DEFAULT_PRIORITY;

  ISIS_IFACE->hello_int = ISIS_DEFAULT_HELLO_INT;
  ISIS_IFACE->hold_int  = ISIS_DEFAULT_HOLD_INT;
  ISIS_IFACE->hold_mult = ISIS_DEFAULT_HOLD_MULT;
  ISIS_IFACE->rxmt_int = ISIS_DEFAULT_RXMT_INT;
  ISIS_IFACE->csnp_int = ISIS_DEFAULT_CSNP_INT;
  ISIS_IFACE->psnp_int = ISIS_DEFAULT_PSNP_INT;
};

isis_level: expr { $$ = $1 - 1; if (($1 < 1) || ($1 > 2)) cf_error("Level must be 1 or 2"); }

isis_iface_item:
   LEVEL isis_level bool { ISIS_IFACE->levels[$2] = $3; }
 | LEVEL isis_level PASSIVE { ISIS_IFACE->levels[$2] = ISIS_LEVEL_PASSIVE; }
 | PASSIVE bool { ISIS_IFACE->passive = $2; }

 | TYPE BROADCAST { ISIS_IFACE->type = ISIS_IT_BCAST; }
 | TYPE BCAST { ISIS_IFACE->type = ISIS_IT_BCAST; }
 | TYPE POINTOPOINT { ISIS_IFACE->type = ISIS_IT_PTP; }
 | TYPE PTP { ISIS_IFACE->type = ISIS_IT_PTP; }

 | METRIC expr { ISIS_IFACE->metric = $2; cf_range("Metric", $2, 1, 63); }
 | PRIORITY expr { ISIS_IFACE->priority = $2; cf_range("Priority", $2, 1, 127); }

 | HELLO expr { ISIS_IFACE->hello_int = $2; cf_range("Hello interval", $2, 1, 65535); }
 | HOLD expr { ISIS_IFACE->hold_int = $2; cf_range("Hold interval", $2, 3, 65535); }
 | HOLD MULT expr { ISIS_IFACE->hold_mult = $3; cf_range("Hold multiplier", $3, 3, 255); }
 | RETRANSMIT expr { ISIS_IFACE->rxmt_int = $2; cf_range("Retransmit interval", $2, 3, 65535); }
 | CSNP expr { ISIS_IFACE->csnp_int = $2; cf_range("CSNP interval", $2, 1, 65535); }
 | PSNP expr { ISIS_IFACE->psnp_int = $2; cf_range("PSNP interval", $2, 1, 65535); }
 ;

isis_iface_finish:
{
  struct isis_iface_config *ic = ISIS_IFACE;

  if (! ic->hold_int)
  {
    u32 hold_int = ic->hold_mult * (u32) ic->hello_int;
    if (hold_int > 65535)
      cf_error("Hello interval times Hold multiplier greater than 65535");
    ic->hold_int = hold_int;
  }
};

isis_iface_opts:
   /* empty */
 | isis_iface_opts isis_iface_item ';'
 ;

isis_iface_opt_list:
   /* empty */
 | '{' isis_iface_opts '}'
 ;

isis_iface:
  isis_iface_start iface_patt_list isis_iface_opt_list isis_iface_finish;



isis_area_id_read:
   NUM 
   {
     check_u8($1);
     if ($1 == 0)
       cf_error("Area ID must not start with 0");
     area_id_bpos = area_id_buffer;
     *area_id_bpos++ = $1;
   }
 | isis_area_id_read '-' NUM
   { 
     check_u16($3);
     if ((area_id_bpos + 2 - area_id_buffer) > sizeof(area_id_buffer))
       cf_error("Area ID too long");
     put_u16(area_id_bpos, $3);
     area_id_bpos += 2;
   }
 ;

isis_area_id: isis_area_id_read
{
  struct isis_area_id *area_id;
  int i, blen;

  for (i = 0; i < ISIS_AREAS; i++)
    if (! ISIS_CFG->areas[i])
      goto found;

  cf_error("Too many areas");

found:
  blen = area_id_bpos - area_id_buffer;
  area_id = cfg_allocz(1 + blen);
  area_id->length = blen;
  memcpy(area_id->body, area_id_buffer, blen);
  ISIS_CFG->areas[i] = area_id;
}

isis_system_id: NUM '-' NUM '-' NUM
{
  check_u16($1); check_u16($3); check_u16($5);
  ISIS_CFG->system_id = (((u64) $1) << 48) | (((u64) $3) << 32) | (((u64) $5) << 16);
}

CF_CODE

CF_END
