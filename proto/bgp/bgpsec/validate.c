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

#include <stdio.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/ec.h>
#include <openssl/x509.h>
#include "validate.h"

static int
convert_ski_to_ascii(const byte *ski, const size_t ski_len,
		     char *ascii_ski, size_t ascii_ski_len) {

    int i;

    if (ski_len * 2 + 1 >= ascii_ski_len) {
        log(L_ERR "validate: buffer to small for SKI length: %d", ski_len);
	return BGPSEC_FAILURE;
    }

    memset(ascii_ski, 0, ascii_ski_len);

    for (i = 0; i < ski_len; i++)
      sprintf(ascii_ski + 2 * i, "%02X", ski[i]);

    return BGPSEC_SUCCESS;
}

static int
bgpsec_load_key_internal(const struct bgp_config *conf,
			 const char *filename,
			 bgpsec_key_data *key_data,
			 EVP_PKEY *(*d2i_bio_method)(BIO *, EVP_PKEY **)) {
    int ret = BGPSEC_FAILURE;
    BIO *bio = NULL;

    if ((bio = BIO_new_file(filename, "rb")) != NULL &&
	d2i_bio_method(bio, &key_data->pkey) != NULL &&
	EVP_PKEY_id(key_data->pkey) == EVP_PKEY_EC &&
	BIO_free(bio))
    {
	EC_KEY_set_asn1_flag(EVP_PKEY_get0(key_data->pkey), OPENSSL_EC_NAMED_CURVE);
        ret = BGPSEC_SUCCESS;
	bio = NULL;
    }

    BIO_free(bio);

    return ret;
}

int
bgpsec_load_private_key(const struct bgp_config *conf,
			const char *filename,
			bgpsec_key_data *key_data) {
    return bgpsec_load_key_internal(conf, filename, key_data, d2i_PrivateKey_bio);
}

int
bgpsec_load_public_key(const struct bgp_config *conf,
		       const char *filename,
		       bgpsec_key_data *key_data) {
    return bgpsec_load_key_internal(conf, filename, key_data, d2i_PUBKEY_bio);
}

/* Might need to call OpenSSL_add_all_digests() somewhere */

int bgpsec_sign_data_with_key(const struct bgp_config *conf,
			      const byte *octets, const size_t octets_len,
			      const bgpsec_key_data key,
			      const int signature_algorithm,
			      byte *signature, size_t signature_len) {

    EVP_PKEY_CTX *ctx = NULL;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    size_t md_len;
    size_t sig_len = signature_len;
    int result = -1;

    switch (signature_algorithm) {
    case BGPSEC_ALGORITHM_SHA256_ECDSA_P_256:

      if (EVP_Digest(octets, octets_len, md_value, (unsigned int *)&md_len,
		     EVP_sha256(), NULL) &&
	    (ctx = EVP_PKEY_CTX_new(key.pkey, NULL)) != NULL &&
	    EVP_PKEY_sign_init(ctx) > 0 &&
	    EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) > 0 &&
	    EVP_PKEY_sign(ctx, signature, &sig_len, md_value, md_len) > 0)
	{
	    result = sig_len;
	}
	else
	{
	  log(L_ERR "validate: Failed to create digest/sign");
          return BGPSEC_FAILURE;
	}

    default:
        break;
    }

    EVP_PKEY_CTX_free(ctx);
    return result;
}

int bgpsec_sign_data_with_ascii_ski(const struct bgp_config *conf,
                                    const byte *octets, const size_t octets_len,
                                    const char *ski, const size_t ski_len,
				    const int asn,
                                    const int signature_algorithm,
				    byte *signature, size_t signature_len) {
    const char *rootPath = (conf && conf->bgpsec_priv_key_path) ? conf->bgpsec_priv_key_path : DEFAULT_PRIV_KEY_PATH;
    bgpsec_key_data key = { NULL };
    char filename[MAXPATHLEN];

    if (snprintf(filename, sizeof(filename), "%s/%d.%s.key", rootPath, asn, ski) >= sizeof(filename) ||
	bgpsec_load_private_key(conf, filename, &key) != BGPSEC_SUCCESS)
    {
	return BGPSEC_FAILURE;
    }

    return bgpsec_sign_data_with_key(conf, octets, octets_len, key,
				     signature_algorithm, signature, signature_len);
}

int bgpsec_sign_data_with_bin_ski(const struct bgp_config *conf,
                                  const byte *octets, const size_t octets_len,
                                  const byte *ski, const size_t ski_len,
				  const int asn,
                                  const int signature_algorithm,
				  byte *signature, size_t signature_len) {
    char ascii_ski[MAXPATHLEN];

    if (convert_ski_to_ascii(ski, ski_len, ascii_ski, sizeof(ascii_ski)) == BGPSEC_FAILURE)
	return BGPSEC_FAILURE;

    return bgpsec_sign_data_with_ascii_ski(conf, octets, octets_len, ascii_ski, sizeof(ascii_ski),
					   asn, signature_algorithm, signature, signature_len);
}

int bgpsec_verify_signature_with_key(const struct bgp_config *conf,
				     const byte *octets, const size_t octets_len,
				     const bgpsec_key_data key,
				     const int signature_algorithm,
				     const byte *signature, const size_t signature_len) {
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    size_t md_len;
    int result = BGPSEC_SIGNATURE_ERROR;

    switch (signature_algorithm) {
    case BGPSEC_ALGORITHM_SHA256_ECDSA_P_256:

      if (EVP_Digest(octets, octets_len, md_value, (unsigned int *)&md_len,
		     EVP_sha256(), NULL) &&
	    (ctx = EVP_PKEY_CTX_new(key.pkey, NULL)) != NULL &&
	    EVP_PKEY_verify_init(ctx) > 0 &&
	    EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) > 0 &&
	    EVP_PKEY_verify(ctx, signature, signature_len, md_value, md_len) > 0)
	{
	    result = BGPSEC_SIGNATURE_MATCH;
	}

#if 0 && defined(LOG_OPENSSL_ERRORS) && defined(LOG_TO_STDERR)
	else
	    ERR_print_errors_fp(stderr);
#endif

    default:
      break;
    }

    EVP_PKEY_CTX_free(ctx);
    return result;
}

int bgpsec_verify_signature_with_ascii_ski(const struct bgp_config *conf,
                                           const byte *octets, const size_t octets_len,
                                           const char *ski, const size_t ski_len,
					   const int asn,
                                           const int signature_algorithm,
                                           const byte *signature, const size_t signature_len) {
    const char *rootPath = (conf && conf->bgpsec_key_repo_path) ? conf->bgpsec_key_repo_path : DEFAULT_KEY_REPO_PATH;
    bgpsec_key_data key = { NULL };
    char filename[MAXPATHLEN];
    int n;

    for (n = 0; n < BGPSEC_MAX_SKI_COLLISIONS; n++) {

	if (snprintf(filename, sizeof(filename), "%s/%d.%s.%d.key", rootPath, asn, ski, n) >= sizeof(filename))
	    break;

	if (bgpsec_load_public_key(conf, filename, &key) != BGPSEC_SUCCESS)
	    break;

	if (bgpsec_verify_signature_with_key(conf, octets, octets_len, key, signature_algorithm,
					     signature, signature_len) == BGPSEC_SIGNATURE_MATCH)
	    return BGPSEC_SIGNATURE_MATCH;

	EVP_PKEY_free(key.pkey);
	key.pkey = NULL;
    }

    return BGPSEC_SIGNATURE_ERROR;
}

int bgpsec_verify_signature_with_bin_ski(const struct bgp_config *conf,
                                         const byte *octets, const size_t octets_len,
                                         const byte *ski, const size_t ski_len,
					 const int asn,
                                         const int signature_algorithm,
                                         const byte *signature, const size_t signature_len) {
    char ascii_ski[MAXPATHLEN];

    if (convert_ski_to_ascii(ski, ski_len, ascii_ski, sizeof(ascii_ski)) == BGPSEC_FAILURE)
	return BGPSEC_SIGNATURE_ERROR;

    return bgpsec_verify_signature_with_ascii_ski(conf, octets, octets_len, ascii_ski, sizeof(ascii_ski),
						  asn, signature_algorithm, signature, signature_len);
}

int bgpsec_calculate_ski(const bgpsec_key_data key,
			 byte *ski, const size_t ski_len) {
    X509_PUBKEY *pubkey = NULL;
    byte digest[EVP_MAX_MD_SIZE];
    int result = BGPSEC_FAILURE;
    unsigned digest_len;

    if (X509_PUBKEY_set(&pubkey, key.pkey) &&
	EVP_Digest(pubkey->public_key->data, pubkey->public_key->length,
		   digest, &digest_len, EVP_sha1(), NULL) &&
	digest_len <= ski_len)
    {
	memcpy(ski, digest, digest_len);
	result = digest_len;
    }

    X509_PUBKEY_free(pubkey);
    return result;
}
