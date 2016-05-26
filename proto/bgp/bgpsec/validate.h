/*
 *	bgpsec: validation functions
 *
 *
 *      Parsons, Inc.
 *      (c) 2013-2013
 *
 *	Code can be used under either license:
 *      - Freely distributed and used under the terms of the GNU GPLv2.
 *      - Freely distributed and used under a BSD license, See README.bgpsec.
 */

#ifndef _BIRD_VALIDATE_H_
#define _BIRD_VALIDATE_H_

#include <stdint.h>
#include <openssl/evp.h>

#include "nest/route.h"
#include "../bgp.h"

/* XXX: these need to be configurable in the bird config file instead */
#define DEFAULT_KEY_REPO_PATH	"/usr/share/bird/bgpsec-keys"
#define DEFAULT_PRIV_KEY_PATH	"/usr/share/bird/bgpsec-private-keys"
#define BGPSEC_MAX_SKI_COLLISIONS	3

/*
 * Structure to store keying data in. This used to be a union, but
 * since we should be using EVP_PKEY everywhere it's now just a wrapper.
 */
typedef struct {
   EVP_PKEY *pkey;
} bgpsec_key_data;

/* Generic error codes */
#define BGPSEC_SUCCESS 0
#define BGPSEC_FAILURE -1


/* These match the defined algorithm bytes from the protocol definition */

/* Algorithm #:         1
 * Digest algorithm:    SHA-256
 * Signature algorithm: ECDSA P-256
 */
/* XXX: IANA has yet to assign this number; 1 is a logical guess */
/* XXX: Definiton in draft-turner-sidr-bgpsec-algs-00.txt */
#define BGPSEC_ALGORITHM_SHA256_ECDSA_P_256 1

#define BGPSEC_DEFAULT_CURVE BGPSEC_ALGORITHM_SHA256_ECDSA_P_256

/*
 * Signs a blob of octets in 'octets' with the certificate found using
 * the 'subject_key_ident' using the algorithm indicated by
 * 'signature_algorithm'.  The resulting signature is placed in the
 * pre-allocated 'signature' block, whose pre-allocated length must be
 * stored in 'signature_len'.
 *
 * Internally this looks up the certificate and then calls
 * bgpsec_sign_data_with_key(), defined below.
 *
 * Returns: The length of the signature actually created, or -1 on error.
 */
int bgpsec_sign_data_with_ascii_ski(const struct bgp_config *conf,
                                    const byte *octets, const size_t octets_len,
                                    const char *ski, const size_t ski_len,
				    const int asn,
                                    const int signature_algorithm,
				    byte *signature, size_t signature_len);

int bgpsec_sign_data_with_bin_ski(const struct bgp_config *conf,
                                  const byte *octets, const size_t octets_len,
                                  const byte *ski, const size_t ski_len,
				  const int asn,
                                  const int signature_algorithm,
				  byte *signature, size_t signature_len);

/*
 * Signs a blob of octets in 'octets' with the private key 'key' using
 * the algorithm indicated by 'signature_algorithm'.  The resulting signature
 * is placed in the pre-allocated 'signature' block, who's
 * pre-allocated length bust be stored in 'signature_len'.
 *
 * Returns: The length of the signature actually created, or -1 on error.
 */
int bgpsec_sign_data_with_key(const struct bgp_config *conf,
			      const byte *octets, const size_t octets_len,
			      const bgpsec_key_data key,
			      const int signature_algorithm,
			      byte *signature, size_t signature_len);


#define BGPSEC_SIGNATURE_MATCH    0
#define BGPSEC_SIGNATURE_ERROR    1
/*
 * Validates a signature on a block and returns an error code if the
 * signature dosen't match.  The data to check the signature for
 * should be in 'octets' with length 'octets_len', and the public key
 * to check with should be in 'key' using algorithm
 * 'signature_algorithm'.  The signature from the bgp packet should
 * should be in 'signature' with length 'signature_len'.
 *
 * Returns:
 *   Success: BGPSEC_SIGNATURE_MATCH
 *   Failure: BGPSEC_SIGNATURE_ERROR
 */
int bgpsec_verify_signature_with_key(const struct bgp_config *conf,
				     const byte *octets, const size_t octets_len,
				     const bgpsec_key_data key,
				     const int signature_algorithm,
				     const byte *signature, const size_t signature_len);

/* verifies a signature when passed an ascii SKI */
int bgpsec_verify_signature_with_ascii_ski(const struct bgp_config *conf,
                                           const byte *octets, const size_t octets_len,
                                           const char *ski, const size_t ski_len,
					   const int asn,
                                           const int signature_algorithm,
                                           const byte *signature, const size_t signature_len);

/* verifies a signature when passed a binary SKI
   (internally, this is a wrapper around the above function and merely
   prints the binary to an hex-encoded ascii first) */
int bgpsec_verify_signature_with_bin_ski(const struct bgp_config *conf,
                                         const byte *octets, const size_t octets_len,
                                         const byte *ski, const size_t ski_len,
					 const int asn,
                                         const int signature_algorithm,
                                         const byte *signature, const size_t signature_len);


/*
 * Load private and public keys from files.
 *
 * Returns:
 *   Success: BGPSEC_SUCCESS
 *   Failure: BGPSEC_FAILURE
 */

int bgpsec_load_private_key(const struct bgp_config *conf,
			    const char *filename,
			    bgpsec_key_data *key_data);

int bgpsec_load_public_key(const struct bgp_config *conf,
			   const char *filename,
			   bgpsec_key_data *key_data);

/*
 * Calculate the SKI of a key.
 *
 * Returns:
 *   Success: length of calculated SKI
 *   Failure: BGPSEC_FAILURE
 */

int bgpsec_calculate_ski(const bgpsec_key_data key,
			 byte *ski, const size_t ski_len);

#endif
