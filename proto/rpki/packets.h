/*
 *	BIRD -- The Resource Public Key Infrastructure (RPKI) to Router Protocol
 *
 *	(c) 2015 CZ.NIC
 *
 *	This file was a part of RTRlib: http://rpki.realmv6.org/
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_RPKI_PACKETS_H_
#define _BIRD_RPKI_PACKETS_H_

#include <arpa/inet.h>

#define RPKI_RX_BUFFER_SIZE	65536
#define RPKI_TX_BUFFER_SIZE	65536
#define RPKI_PDU_HEADER_LEN 	8

/* Error PDU size is the biggest (has encapsulate PDU inside):
 * 	Header size 8 Bytes +
 * 	Length of Encapsulated PDU 4 Bytes +
 * 	Encapsulated PDU IPv6 32 Bytes +
 * 	Length of Text 4 Bytes +
 * 	UTF-8 Text 400*2 Bytes
 * 	= 848 Bytes
 */
#define RPKI_PDU_MAX_LEN	848

int rpki_send_serial_query(struct rpki_cache *cache);
int rpki_send_reset_query(struct rpki_cache *cache);
int rpki_rx_hook(sock *sk, int size);
void rpki_connected_hook(sock *sk);
void rpki_err_hook(sock *sk, int size);
void rpki_table_remove_all(struct rpki_cache *cache);

#endif
