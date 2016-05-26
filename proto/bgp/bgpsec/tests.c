#include "validate.h"
#include <sys/param.h>
#include <openssl/ec.h>

#define HEADER(msg)       printf("--------------- " msg "\n");
#define HEADER1(msg, arg) printf("--------------- " msg "\n", arg);

#define RESULT(test, is_success) {                              \
        printf("%7.7s: ", ((is_success) ? "ok" : "not ok"));    \
        printf("%4d: ", __LINE__);                              \
        printf test;                                            \
        printf("\n");                                           \
        if (is_success) good++;                                 \
        else bad++;                                             \
    }

#define DIE(msg) do { fprintf(stderr, "CRITICAL FAIL: %s\n", msg); exit(1); } while(1);

#define DUMMYCERTFILE "router-key.15708"

#define TEST_KEY_REPO_PATH "/tmp/bgpsec-keys-testrepo"

int main(int argc, char **argv) {
    byte signature[1024];
    int  signature_len = sizeof(signature);
    char strBuffer[1024];
    bgpsec_key_data key_data;
    char ski[1024];
    char filePrefix[MAXPATHLEN];
    char fileName[MAXPATHLEN];
    int  signature_algorithms[] = { BGPSEC_ALGORITHM_SHA256_ECDSA_P_256, -1 };
    byte data_to_sign[] = { 1,2,3,4,5,6,7,8 };

    struct bgp_config bgpconfig;
    bgpconfig.bgpsec_key_repo_path = TEST_KEY_REPO_PATH;
    bgpconfig.bgpsec_save_binary_keys = 1;

    BIGNUM newbignum;
    EC_POINT *new_point;

    FILE *fp;

    printf("Testing:\n");

    int good = 0, bad = 0;

    /* test whether we can sign a block of text */
    int ret;
    int curveId;
    int bin_save;

    for(bin_save = 0; bin_save < 2; bin_save++) {
        HEADER1("starting test with binary_keys = %d", bin_save);

        int algorithm_count = 0;
        bgpconfig.bgpsec_save_binary_keys = bin_save;


        /* create a dummy certificate to use */
        system("../proto/bgp/bgpsec/gen-router-key -d " TEST_KEY_REPO_PATH " -c ../proto/bgp/bgpsec/router-key.cnf -p > ski.txt");
        fp = fopen("ski.txt", "r");
        if (NULL == fp)
            DIE("failed to open the ski.txt file that should have been created");
        ski[sizeof(ski)-1] = '\0';
        if (NULL == fgets(ski, sizeof(ski)-1, fp))
            DIE("Couldn't read the SKI from the ski.txt file");
        ski[strlen(ski)-1] = '\0'; /* chomp the LF off */
        fclose(fp);

        /* now define all the file names based on it the new cert */
        filePrefix[sizeof(filePrefix)-1] = '\0';
        snprintf(filePrefix, sizeof(filePrefix)-1, "%s/%s", TEST_KEY_REPO_PATH, ski);
        generate_ski_filename(filePrefix, sizeof(filePrefix), TEST_KEY_REPO_PATH,
                              ski, strlen(ski));

        while(signature_algorithms[algorithm_count] > 0) {
            HEADER1("-- starting test with sig alg = %d",
                    signature_algorithms[algorithm_count]);
            bgpsec_key_data key_data;
            curveId = signature_algorithms[algorithm_count];

            ret = bgpsec_load_key(&bgpconfig, filePrefix, &key_data,
                                  curveId, 1);
            RESULT(("cert sign: loaded the router key from tmp file: %s",
                    filePrefix),
                   ret == BGPSEC_SUCCESS);


            /* generate a signature using a certificate */
            signature_len =
                bgpsec_sign_data_with_key(&bgpconfig,
					  data_to_sign, sizeof(data_to_sign),
					  key_data,
					  signature_algorithms[algorithm_count],
					  signature, sizeof(signature));

            RESULT(("cert sign: algorithm %d, signature length (%d) is not negative",
                    signature_algorithms[algorithm_count], signature_len),
                   signature_len > -1);
            RESULT(("cert sign: algorithm %d, signature length (%d) has at least a byte", signature_algorithms[algorithm_count], signature_len), signature_len > 0);

            /* modify the private key so it can't be part of the verification */
            BN_init(&newbignum);
            EC_KEY_set_private_key(key_data.ecdsa_key, &newbignum);

            /* verify that the signature matches */
            ret = bgpsec_verify_signature_with_key(&bgpconfig, data_to_sign,
						   sizeof(data_to_sign),
						   key_data,
						   signature_algorithms[algorithm_count],
						   signature, signature_len);
            RESULT(("cert sign: verify signature result: %d (should be %d)",
                    ret, BGPSEC_SIGNATURE_MATCH),
                   ret == BGPSEC_SIGNATURE_MATCH);

            /* verify that the signature matches */
            ret = bgpsec_verify_signature_with_key(&bgpconfig, data_to_sign,
						   sizeof(data_to_sign),
						   key_data,
						   signature_algorithms[algorithm_count],
						   signature, signature_len);
            RESULT(("cert sign: verify signature result2: %d (should be %d)",
                    ret, BGPSEC_SIGNATURE_MATCH),
                   ret == BGPSEC_SIGNATURE_MATCH);

            /* modify the public key so it can't be part of the verification */
            /* (which should make the verification fail now) */
            new_point = EC_POINT_new(EC_GROUP_new_by_curve_name(curveId));
            EC_KEY_set_public_key(key_data.ecdsa_key, new_point);
            EC_POINT_free(new_point);

            /* verify that the signature no longer matches */
            ret = bgpsec_verify_signature_with_key(&bgpconfig,
						   data_to_sign,
						   sizeof(data_to_sign),
						   key_data,
						   signature_algorithms[algorithm_count],
						   signature, signature_len);
            RESULT(("cert sign: verify signature fail result: %d (should be %d)",
                    ret, BGPSEC_SIGNATURE_MISMATCH),
                   ret == BGPSEC_SIGNATURE_MISMATCH);

            /* completely get rid of the current key */
            EC_KEY_free(key_data.ecdsa_key);
            key_data.ecdsa_key = NULL;

            /* now reload the key from the files and use them to verify it */
            /* NOTE: this should reload the previously saved binary key */
            ret = bgpsec_load_key(&bgpconfig, filePrefix, &key_data, curveId, 1);
            RESULT(("cert sign: loading key function returned: %d (should be %d)",
                    ret, BGPSEC_SUCCESS), ret == BGPSEC_SUCCESS);

            /* verify that the signature matches again with the loaded key */
            ret = bgpsec_verify_signature_with_key(&bgpconfig,
						   data_to_sign,
						   sizeof(data_to_sign),
						   key_data,
						   signature_algorithms[algorithm_count],
						   signature, signature_len);
            RESULT(("cert sign: verify signature result of generated bin key: %d (should be %d)",
                    ret, BGPSEC_SIGNATURE_MATCH),
                   ret == BGPSEC_SIGNATURE_MATCH);


            /* Nuke the binary version of the key, and make sure the x.509
               gets reloaded again */
            snprintf(fileName, sizeof(fileName), "%s.bin_pub", filePrefix);
            unlink(fileName);

            ret = bgpsec_load_key(&bgpconfig, filePrefix, &key_data, curveId, 1);
            RESULT(("cert sign: loading key function returned: %d (should be %d)",
                    ret, BGPSEC_SUCCESS), ret == BGPSEC_SUCCESS);

            /* verify that the signature matches again with the loaded key */
            ret = bgpsec_verify_signature_with_key(&bgpconfig,
						   data_to_sign,
						   sizeof(data_to_sign),
						   key_data,
						   signature_algorithms[algorithm_count],
						   signature, signature_len);
            RESULT(("cert sign: verify signature result of non-bin: %d (should be %d)",
                    ret, BGPSEC_SIGNATURE_MATCH),
                   ret == BGPSEC_SIGNATURE_MATCH);



            /* completely get rid of the current key */
            EC_KEY_free(key_data.ecdsa_key);
            key_data.ecdsa_key = NULL;

            /* now reload just the public part of the key and test just it */
            ret = bgpsec_load_key(&bgpconfig, filePrefix, &key_data, curveId, 0);
            RESULT(("cert sign: loading public key function returned: %d (should be %d)",
                    ret, BGPSEC_SUCCESS), ret == BGPSEC_SUCCESS);

            /* verify that the signature matches again with the public key */
            ret = bgpsec_verify_signature_with_key(&bgpconfig,
						   data_to_sign,
						   sizeof(data_to_sign),
						   key_data,
						   signature_algorithms[algorithm_count],
						   signature, signature_len);
            RESULT(("cert sign: verify (pub) signature result: %d (should be %d)",
                    ret, BGPSEC_SIGNATURE_MATCH),
                   ret == BGPSEC_SIGNATURE_MATCH);

            /* generate a signature using a fingerprint */
            /* XXX: set test directory to search for matching ski->certs */
            signature_len =
                bgpsec_sign_data_with_ascii_ski(&bgpconfig,
                                                data_to_sign,
                                                sizeof(data_to_sign),
                                                ski, strlen(ski)+1,
                                                signature_algorithms[algorithm_count],
                                                signature, sizeof(signature));

            RESULT(("ski sign:  algorithm %d, signature length (%d) is not negative",
                    signature_algorithms[algorithm_count], signature_len),
                   signature_len > -1);
            RESULT(("ski sign:  algorithm %d, signature length (%d) has at least a byte", signature_algorithms[algorithm_count], signature_len), signature_len > 0);


            /* verify that the signature matches */
            ret = bgpsec_verify_signature_with_ascii_ski(&bgpconfig,
                                                         data_to_sign,
                                                         sizeof(data_to_sign),
                                                         ski, strlen(ski)+1,
                                                         signature_algorithms[algorithm_count],
                                                         signature, sizeof(signature));
            RESULT(("ski sign:  verify signature result: %d (should be %d)",
                    ret, BGPSEC_SIGNATURE_MATCH),
                   ret == BGPSEC_SIGNATURE_MATCH);

            if (bin_save) {
                /* Nuke the x.509 certificate version of the key, and make
                   sure the binary version can be loaded by itself. */
                snprintf(fileName, sizeof(fileName), "%s.pub", filePrefix);
                unlink(fileName);
                snprintf(fileName, sizeof(fileName), "%s.private", filePrefix);
                unlink(fileName);


                /* verify that the signature matches with an ski */
                ret = bgpsec_verify_signature_with_ascii_ski(&bgpconfig,
                                                             data_to_sign,
                                                             sizeof(data_to_sign),
                                                             ski, strlen(ski)+1,
                                                             signature_algorithms[algorithm_count],
                                                             signature, sizeof(signature));

                RESULT(("ski sign:  verify signature result of binary only: %d (should be %d)",
                        ret, BGPSEC_SIGNATURE_MATCH),
                       ret == BGPSEC_SIGNATURE_MATCH);


                /* verify that the signature matches with the key */

                ret = bgpsec_load_key(&bgpconfig, filePrefix, &key_data, curveId, 1);
                RESULT(("cert sign: loading binary-only key function returned: %d (should be %d)",
                        ret, BGPSEC_SUCCESS), ret == BGPSEC_SUCCESS);

                /* verify that the signature matches again with the loaded key */
                ret = bgpsec_verify_signature_with_key(&bgpconfig,
						       data_to_sign,
						       sizeof(data_to_sign),
						       key_data,
						       signature_algorithms[algorithm_count],
						       signature, signature_len);
                RESULT(("cert sign: verify signature result of binary-only: %d (should be %d)",
                        ret, BGPSEC_SIGNATURE_MATCH),
                       ret == BGPSEC_SIGNATURE_MATCH);
            }



            /* move on to the next algorithm */
            algorithm_count++;
        }

    }

    printf("\nResults:\n");
    printf("  Good: %d\n", good);
    printf("   Bad: %d\n", bad);

    return 0;
}
