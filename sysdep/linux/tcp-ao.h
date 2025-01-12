/*
 *	BIRD Internet Routing Daemon -- Linux TCP-AO API
 *
 *	Based on Linux kernel header include/uapi/linux/tcp.h
 *
 *	Author:	Fred N. van Kempen <waltje@uWalt.NL.Mugnet.ORG>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_LINUX_TCP_AO_H_
#define _BIRD_LINUX_TCP_AO_H_

#ifndef TCP_AO_ADD_KEY
#define TCP_AO_ADD_KEY		38	/* Add/Set MKT */
#define TCP_AO_DEL_KEY		39	/* Delete MKT */
#define TCP_AO_INFO		40	/* Set/list TCP-AO per-socket options */
#define TCP_AO_GET_KEYS		41	/* List MKT(s) */
#define TCP_AO_REPAIR		42	/* Get/Set SNEs and ISNs */
#endif

#define TCP_AO_MAXKEYLEN_	80

struct tcp_ao_add_ext { /* setsockopt(TCP_AO_ADD_KEY) */
	struct sockaddr_storage addr;	/* peer's address for the key */
	char	alg_name[64];		/* crypto hash algorithm to use */
	s32	ifindex;		/* L3 dev index for VRF */
	u32     set_current	:1,	/* set key as Current_key at once */
		set_rnext	:1,	/* request it from peer with RNext_key */
		reserved	:30;	/* must be 0 */
	u16	reserved2;		/* padding, must be 0 */
	u8	prefix;			/* peer's address prefix */
	u8	sndid;			/* SendID for outgoing segments */
	u8	rcvid;			/* RecvID to match for incoming seg */
	u8	maclen;			/* length of authentication code (hash) */
	u8	keyflags;		/* see TCP_AO_KEYF_ */
	u8	keylen;			/* length of ::key */
	u8	key[TCP_AO_MAXKEYLEN_];
} __attribute__((aligned(8)));

struct tcp_ao_del_ext { /* setsockopt(TCP_AO_DEL_KEY) */
	struct sockaddr_storage addr;	/* peer's address for the key */
	s32	ifindex;		/* L3 dev index for VRF */
	u32     set_current	:1,	/* corresponding ::current_key */
		set_rnext	:1,	/* corresponding ::rnext */
		del_async	:1,	/* only valid for listen sockets */
		reserved	:29;	/* must be 0 */
	u16	reserved2;		/* padding, must be 0 */
	u8	prefix;			/* peer's address prefix */
	u8	sndid;			/* SendID for outgoing segments */
	u8	rcvid;			/* RecvID to match for incoming seg */
	u8	current_key;		/* KeyID to set as Current_key */
	u8	rnext;			/* KeyID to set as Rnext_key */
	u8	keyflags;		/* see TCP_AO_KEYF_ */
} __attribute__((aligned(8)));

struct tcp_ao_info_opt_ext { /* setsockopt(TCP_AO_INFO), getsockopt(TCP_AO_INFO) */
	/* Here 'in' is for setsockopt(), 'out' is for getsockopt() */
	u32     set_current	:1,	/* in/out: corresponding ::current_key */
		set_rnext	:1,	/* in/out: corresponding ::rnext */
		ao_required	:1,	/* in/out: don't accept non-AO connects */
		set_counters	:1,	/* in: set/clear ::pkt_* counters */
		accept_icmps	:1,	/* in/out: accept incoming ICMPs */
		reserved	:27;	/* must be 0 */
	u16	reserved2;		/* padding, must be 0 */
	u8	current_key;		/* in/out: KeyID of Current_key */
	u8	rnext;			/* in/out: keyid of RNext_key */
	u64	pkt_good;		/* in/out: verified segments */
	u64	pkt_bad;		/* in/out: failed verification */
	u64	pkt_key_not_found;	/* in/out: could not find a key to verify */
	u64	pkt_ao_required;	/* in/out: segments missing TCP-AO sign */
	u64	pkt_dropped_icmp;	/* in/out: ICMPs that were ignored */
} __attribute__((aligned(8)));

struct tcp_ao_getsockopt_ext { /* getsockopt(TCP_AO_GET_KEYS) */
	struct sockaddr_storage addr;	/* in/out: dump keys for peer
						 * with this address/prefix
						 */
	char	alg_name[64];		/* out: crypto hash algorithm */
	u8	key[TCP_AO_MAXKEYLEN_];
	u32	nkeys;			/* in: size of the userspace buffer
					 * @optval, measured in @optlen - the
					 * sizeof(struct tcp_ao_getsockopt)
					 * out: number of keys that matched
					 */
	u16     is_current	:1,	/* in: match and dump Current_key,
					 * out: the dumped key is Current_key
					 */

		is_rnext	:1,	/* in: match and dump RNext_key,
					 * out: the dumped key is RNext_key
					 */
		get_all		:1,	/* in: dump all keys */
		reserved	:13;	/* padding, must be 0 */
	u8	sndid;			/* in/out: dump keys with SendID */
	u8	rcvid;			/* in/out: dump keys with RecvID */
	u8	prefix;			/* in/out: dump keys with address/prefix */
	u8	maclen;			/* out: key's length of authentication
					 * code (hash)
					 */
	u8	keyflags;		/* in/out: see TCP_AO_KEYF_ */
	u8	keylen;			/* out: length of ::key */
	s32	ifindex;		/* in/out: L3 dev index for VRF */
	u64	pkt_good;		/* out: verified segments */
	u64	pkt_bad;		/* out: segments that failed verification */
} __attribute__((aligned(8)));

struct tcp_ao_repair_ext { /* {s,g}etsockopt(TCP_AO_REPAIR) */
	u32			snt_isn;  //should be __be32 alias fdt32_t - 32-bit, big-endian, unsigned integer
	u32			rcv_isn;  //should be __be32 alias fdt32_t - 32-bit, big-endian, unsigned integer
	u32			snd_sne;
	u32			rcv_sne;
} __attribute__((aligned(8)));

#endif
