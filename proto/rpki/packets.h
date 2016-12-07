/*
 *	BIRD -- The Resource Public Key Infrastructure (RPKI) to Router Protocol
 *
 *	(c) 2015 CZ.NIC
 *	(c) 2015 Pavel Tvrdik <pawel.tvrdik@gmail.com>
 *
 *	This file was a part of RTRlib: http://rpki.realmv6.org/
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_RPKI_PACKETS_H_
#define _BIRD_RPKI_PACKETS_H_

#include <arpa/inet.h>

#define RPKI_PDU_HEADER_LEN 	8

/* A Error PDU size is the biggest (has encapsulate PDU inside):
 * 	   +8 bytes (Header size)
 * 	   +4 bytes (Length of Encapsulated PDU)
 * 	  +32 bytes (Encapsulated PDU IPv6 32)
 * 	   +4 bytes (Length of inserted text)
 * 	 +800 bytes (UTF-8 text 400*2 bytes)
 * 	------------
 * 	= 848 bytes (Maximal expected PDU size) */
#define RPKI_PDU_MAX_LEN	848

/* RX buffer size has a great impact to scheduler granularity */
#define RPKI_RX_BUFFER_SIZE	4096
#define RPKI_TX_BUFFER_SIZE	RPKI_PDU_MAX_LEN

/* Return values */
enum rpki_rtvals {
  RPKI_SUCCESS 			= 0,
  RPKI_ERROR 			= -1
};

int rpki_send_serial_query(struct rpki_cache *cache);
int rpki_send_reset_query(struct rpki_cache *cache);
int rpki_rx_hook(sock *sk, uint size);
void rpki_connected_hook(sock *sk);
void rpki_err_hook(sock *sk, int size);

#endif
