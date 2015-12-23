/*
 *	BIRD -- The Resource Public Key Infrastructure (RPKI) to Router Protocol
 *
 *	(c) 2015 CZ.NIC
 *
 *	This file is part of RTRlib: http://rpki.realmv6.org/
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef RTR_PACKETS_H
#define RTR_PACKETS_H
#include <arpa/inet.h>
#include "rtr.h"

#define RPKI_RX_BUFFER_SIZE	65536
#define RPKI_TX_BUFFER_SIZE	65536
#define RPKI_PDU_HEADER_LEN 	8
#define RPKI_PDU_MAX_LEN	848  /* Error PDU size is the biggest (has encapsulate PDU inside):
				      * 	header(8) +
				      * 	len_of_encapsulated_pdu(4) +
				      * 	encapsulated_pdu_ipv6(32) +
				      * 	len_of_text(4) +
				      * 	utf-8 text(400*2) = 848
				      */
#define RPKI_RECV_TIMEOUT 	60
#define RPKI_SEND_TIMEOUT 	60

int rtr_sync(struct rpki_cache *cache);
int rtr_wait_for_sync(struct rpki_cache *cache);
int rtr_send_serial_query(struct rpki_cache *cache);
int rtr_send_reset_query(struct rpki_cache *cache);
int rpki_rx_hook(struct birdsock *sk, int size);
void rpki_connected_hook(sock *sk);
void rpki_err_hook(struct birdsock *sk, int size);
void pfx_table_src_remove(struct rpki_cache *cache);

#endif
