/* Copyright 2013 Dirk-Willem van Gulik, WebWeaving, All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Simple utility that takes an existing S/MIME encrypted message; and adds
 * one or more recipients to it. It does so by requiring the use of one of
 * the existing recipients their (private) key as to decrypt the session
 * key. It will then encrypt these against the pup-keys of the new recipients
 * and add all this to the file.
 */
static char * _version = "1.02";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <sys/types.h>
#include <ctype.h>

#include <assert.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/safestack.h>
#include <openssl/rsa.h>

// Below 3 functions are from pkcs7/p7_lib.c in openssl
// as these are not exposed by normal API.
//
static int pkcs7_decrypt_rinfo(unsigned char **pek, size_t *peklen,
                               PKCS7_RECIP_INFO *ri, EVP_PKEY *pkey)
{
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *ek = NULL;
    size_t eklen = 0;
    
    int ret = -1;
    
    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx)
        return -1;
    
    if (EVP_PKEY_decrypt_init(pctx) <= 0)
        goto err;
    
    if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DECRYPT,
                          EVP_PKEY_CTRL_PKCS7_DECRYPT, 0, ri) <= 0)
    {
        PKCS7err(PKCS7_F_PKCS7_DECRYPT_RINFO, PKCS7_R_CTRL_ERROR);
        goto err;
    }
    
    // test the lenght - prior to really decrypting.
    //
    if (EVP_PKEY_decrypt(pctx, NULL, &eklen,
                         ri->enc_key->data, ri->enc_key->length) <= 0)
        goto err;
    
    ek = OPENSSL_malloc(eklen);
    
    if (ek == NULL)
    {
        PKCS7err(PKCS7_F_PKCS7_DECRYPT_RINFO, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (EVP_PKEY_decrypt(pctx, ek, &eklen,
                         ri->enc_key->data, ri->enc_key->length) <= 0)
    {
        ret = 0;
        PKCS7err(PKCS7_F_PKCS7_DECRYPT_RINFO, ERR_R_EVP_LIB);
        goto err;
    }
    
    ret = 1;
    
    if (*pek)
    {
        OPENSSL_cleanse(*pek, *peklen);
        OPENSSL_free(*pek);
    }
    
    *pek = ek;
    *peklen = eklen;
    
err:
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    if (!ret && ek)
        OPENSSL_free(ek);
    
    return ret;
}

static int pkcs7_encode_rinfo(PKCS7_RECIP_INFO *ri,
                              unsigned char *key, int keylen)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *ek = NULL;
    int ret = 0;
    size_t eklen;
    
    pkey = X509_get_pubkey(ri->cert);
    
    if (!pkey)
        return 0;
    
    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx)
        return 0;
    
    if (EVP_PKEY_encrypt_init(pctx) <= 0)
        goto err;
    
    if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_ENCRYPT,
                          EVP_PKEY_CTRL_PKCS7_ENCRYPT, 0, ri) <= 0)
    {
        PKCS7err(PKCS7_F_PKCS7_ENCODE_RINFO, PKCS7_R_CTRL_ERROR);
        goto err;
    }
    
    if (EVP_PKEY_encrypt(pctx, NULL, &eklen, key, keylen) <= 0)
        goto err;
    
    ek = OPENSSL_malloc(eklen);
    
    if (ek == NULL)
    {
        PKCS7err(PKCS7_F_PKCS7_ENCODE_RINFO, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    
    if (EVP_PKEY_encrypt(pctx, ek, &eklen, key, keylen) <= 0)
        goto err;
    
    ASN1_STRING_set0(ri->enc_key, ek, (int)eklen);
    ek = NULL;
    
    ret = 1;
    
err:
    if (pkey)
        EVP_PKEY_free(pkey);
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    if (ek)
        OPENSSL_free(ek);
    return ret;
    
}

static int pkcs7_cmp_ri(PKCS7_RECIP_INFO *ri, X509 *pcert)
{
    int ret;
    ret = X509_NAME_cmp(ri->issuer_and_serial->issuer,
                        pcert->cert_info->issuer);
    if (ret)
        return ret;
    return M_ASN1_INTEGER_cmp(pcert->cert_info->serialNumber,
                              ri->issuer_and_serial->serial);
}

char *ASN1_INTEGER_oneline(ASN1_INTEGER * ai, char * buff, size_t len) {
    BIGNUM * bn = ASN1_INTEGER_to_BN(ai, NULL);
    char * str = NULL;
    if (bn) str = BN_bn2hex(bn);
    strncpy(buff, str ? str : "<invalid-num>", len-1);
    OPENSSL_free(str);
    BN_free(bn);
    return buff;
}

void usage(char * progname) {
    char * p = rindex(progname,'/');
    if (p) progname = p+1;
    fprintf(stderr,"Syntax: %s [-v][-h] <-p key> <-P cert> <-c cert> [-o outfile] [in-file]\n"
            "\t-p privKey  private key of an already existing recipient.\n"
            "\t-P pubKey   public key of an already existing recipient (for stricter matching).\n"
            "\t-c pubKey   certificate(s) to add to the list of recipients. Can be repeated.\n"
            "\t-o file     output file with S/MIME message (default is stdout).\n"
            "\tfile        input S/MIME message in (default is stdin).\n"
            "\t-v          show verbose information about the process."
            "\t-h          This help message.\n"
            "\n"
            "All of the above certs and keys are assumed to be in PEM encoding. S/MIME as\n"
            "PEM or raw encoded PKCS#7 with(out) any headers or other sundry (i.e. the output of \n"
            "openssl -pk7out). This utility is version %s."
            "\n", progname, _version);
    exit(1);
}

int main(int argc, char ** argv) {
	int i, ch ,verbose =0;
    char * progname = argv[0];
    char buff[256],buff2[256];

    BIO *bio_err = BIO_new(BIO_s_file());
    if (bio_err)
        BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT);
    
	EVP_PKEY *pkey = NULL;
    STACK_OF(X509) *apcerts = sk_X509_new_null();
	X509 *pcert = NULL; // Optional - public key of pkey.
    
    BIO * in = BIO_new_fp(stdin, BIO_NOCLOSE);
	BIO * out = BIO_new_fp(stdout, BIO_NOCLOSE);
    
    while ((ch = getopt(argc, argv, "vP:p:c:o:")) != -1) {
        switch (ch) {
            case 'v':
                verbose += 1;
                break;
            case 'p':
            {
                if(pkey) usage(progname);
                BIO * keyfile = BIO_new_file(optarg, "r");
                if (!keyfile) {
                    BIO_printf(bio_err, "Cannot open key file for decryption: %s\n",
                               strerror(errno));
                    exit(1);
                }
                RSA *rsa = NULL;
                rsa = PEM_read_bio_RSAPrivateKey(keyfile, NULL,NULL,NULL);
                if (!rsa) {
                    BIO_printf(bio_err, "RSA key read error: %s\n",
                               ERR_reason_error_string(ERR_peek_error()));
                    exit(1);
                }
                if (!(pkey = EVP_PKEY_new()) || (EVP_PKEY_set1_RSA(pkey, rsa) != 1)) {
                    BIO_printf(bio_err, "RSA key parsing error: %s\n",
                               ERR_reason_error_string(ERR_peek_error()));
                    exit(1);
                }
                RSA_free(rsa);
                BIO_free(keyfile);
            };
                break;
            case 'P':
            {
                if(pcert)
                    usage(progname);
                BIO * certfile = BIO_new_file(optarg, "r");
                if (!certfile) {
                    BIO_printf(bio_err, "Cannot open certificate file for decryption: %s\n",
                               strerror(errno));
                    exit(1);
                }
                STACK_OF(X509_INFO) *xis = PEM_X509_INFO_read_bio(certfile, NULL, NULL, NULL);
                if (!xis) {
                    BIO_printf(bio_err, "Cannot parse certificate file to decrypt: %s\n",
                               ERR_reason_error_string(ERR_peek_error()));
                    exit(1);
                }
                BIO_free(certfile);
                for(i = 0; i < sk_X509_INFO_num(xis); i++) {
                    X509_INFO *xi = sk_X509_INFO_value (xis, i);
                    if (xi->x509) {
                        if (pcert) {
                            BIO_printf(bio_err, "More than one certificate to decrypt with. Aborted.\n");
                            exit(1);
                        }
                        pcert = xi->x509;
                        xi->x509 = NULL;
                    }
                }
                sk_X509_INFO_pop_free(xis, X509_INFO_free);
                // BIO_free(certfile); already freed in PEM_X509_INFO_read_bio.
                
                if (!pcert) {
                    BIO_printf(bio_err, "No (valid) certificate to decrypt with: %s\n",
                               ERR_reason_error_string(ERR_peek_error()));
                    exit(1);
                }
            };
                break;
            case 'o':
                if (!(out = BIO_new_file(optarg, "w"))) {
                    BIO_printf(bio_err, "Cannot open output file for writing: %s\n",
                               strerror(errno));
                    exit(1);
                }
                assert(out);
                break;
            case 'c':
            {
                BIO * certfile = BIO_new_file(optarg, "r");
                if (!certfile) {
                    BIO_printf(bio_err, "Cannot open certificate file to encrypt against for reading: %s\n",
                               ERR_reason_error_string(ERR_peek_error()));
                    exit(1);
                }
                STACK_OF(X509_INFO) *xis = PEM_X509_INFO_read_bio(certfile, NULL, NULL, NULL);
                if (!xis) {
                    BIO_printf(bio_err, "Cannot parse certificate file to encrypt against: %s\n",
                               ERR_reason_error_string(ERR_peek_error()));
                    exit(1);
                }
                BIO_free(certfile);
                for(i = 0; i < sk_X509_INFO_num(xis); i++) {
                    X509_INFO *xi = sk_X509_INFO_value (xis, i);
                    if (xi->x509) {
                        sk_X509_push(apcerts, xi->x509);
                        xi->x509 = NULL;
                        break;
                    }
                }
                sk_X509_INFO_pop_free(xis, X509_INFO_free);
                // BIO_free(certfile); already freed in PEM_X509_INFO_read_bio.

                if (!sk_X509_num(apcerts)) {
                    BIO_printf(bio_err, "No (valid) certificate to encrypt against: %s\n",
                               ERR_reason_error_string(ERR_peek_error()));
                    exit(1);
                }
            }
                break;
            case '?':
            default:
                usage(progname);
                break;
        }
    }
    argc -= optind;
    argv += optind;
    
    if (argc > 1) {
        usage(progname);
    } else
        if (argc == 1) {
            in = BIO_new_file(argv[0], "r");
        }
    
    if (!pkey || !sk_X509_num(apcerts))
        usage(progname);
    
	// Get down to work. Read in the file, find the entry
	// for my privkey decrypt, re-encrypt with pubkey
	// and add an entry for pubkeys x509's CN/Serial.
	//
	PKCS7 * p7 = PEM_read_bio_PKCS7(in, NULL, NULL, NULL);
	if (!p7) p7 = d2i_PKCS7_bio(in, NULL);
    
    if (!p7) {
        BIO_printf(bio_err, "Could not parse the PKCS#7 stream\n");
        exit(1);
    }
    
	i=OBJ_obj2nid(p7->type);
    if (i !=  NID_pkcs7_enveloped) {
        BIO_printf(bio_err, "Not a PKCS#7 envelope input\n");
        exit(1);
    }

    STACK_OF(PKCS7_RECIP_INFO) *rsk = p7->d.enveloped->recipientinfo;
    
	size_t eklen;
	unsigned char *ek = NULL;
	for (i=0; i<sk_PKCS7_RECIP_INFO_num(rsk); i++) {
		PKCS7_RECIP_INFO * r=sk_PKCS7_RECIP_INFO_value(rsk,i);
        if (verbose)
            BIO_printf(bio_err, "Recipient issuer: %s, serial %s",
                       X509_NAME_oneline(r->issuer_and_serial->issuer,buff,sizeof(buff)),
                       ASN1_INTEGER_oneline(r->issuer_and_serial->serial, buff2,sizeof(buff2))
                       );

		if (pcert) {
            if (!pkcs7_cmp_ri(r, pcert)) {
                if (ek) {
                    BIO_printf(bio_err, "\nMultiple entries match. Aborted.\n");
                    exit(1);
                }
                if (verbose)
                    BIO_printf(bio_err,"  (selected, CN/serial# match)");
                
               if (pkcs7_decrypt_rinfo(&ek, &eklen, r, pkey) != 1) {
                    BIO_printf(bio_err, "\nFailed to decrypt existing entry (wrong key?)\n");
                    exit(1);
                }
 			};
		} else {
			// not very subtle - simply try each entry - and see
			// if we can decrypt it. If so - take that on face
			// value.
            unsigned char * oek = ek;
			if (1 ==  pkcs7_decrypt_rinfo(&ek, &eklen, r, pkey)) {
                if (oek) {
                    BIO_printf(bio_err, "\nMultiple entries decrypt - supply a X509 certificate. Aborted.\n");
                    exit(1);
                }
                if (verbose)
                    BIO_printf(bio_err,"  (selected, decrypt succeeding)");            }
		};
        if (verbose)
            BIO_printf(bio_err,"\n");
	};
    if (!eklen || !ek) {
        BIO_printf(bio_err, "Could not decrypt any of the existing entries: %s\n",
                   ERR_reason_error_string(ERR_peek_error()));
        exit(1);
    }

    if (verbose)
        BIO_printf(bio_err, "Decrypted the %d bit key from selected entry.\n",(int)(8*eklen));


	// Create a new entry with this ek:eklen encrypted
	// by the new entries x509 pubkey.
	//
    for(int i = 0; i < sk_X509_num(apcerts); i++) {
        X509 * apcert = sk_X509_value(apcerts, i);
        
        PKCS7_RECIP_INFO * addRi = PKCS7_add_recipient(p7, apcert);
        if (!addRi) {
            BIO_printf(bio_err, "Could not add PKCS#7 receipient %s: %s\n",
                       X509_NAME_oneline(X509_get_subject_name(apcert),buff,sizeof(buff)),
                       ERR_reason_error_string(ERR_peek_error()));
            exit(1);
        }
        if(1 != pkcs7_encode_rinfo(addRi, ek, (int)eklen)) {
            BIO_printf(bio_err, "Could not encrypt for PKCS#7 receipient %s: %s\n",
                       X509_NAME_oneline(X509_get_subject_name(apcert),buff,sizeof(buff)),
                       ERR_reason_error_string(ERR_peek_error()));
            exit(1);
        }

        if (verbose)
            BIO_printf(bio_err, "Recipient issuer: %s, serial %s added.\n",
                       X509_NAME_oneline(addRi->issuer_and_serial->issuer,buff,sizeof(buff)),
                       ASN1_INTEGER_oneline(addRi->issuer_and_serial->serial, buff2,sizeof(buff2))
                       );
    };

    if (verbose)
        BIO_printf(bio_err, "Writing out the s/mime envelope.\n");

	OPENSSL_cleanse(ek, eklen);
	OPENSSL_free(ek);
    
	// write out the file
	if (1 != SMIME_write_PKCS7(out, p7, NULL, 0)) {
        BIO_printf(bio_err, "Could not complete writing file: %s\n",
                   ERR_reason_error_string(ERR_peek_error()));
        exit(1);
    }
    
	BIO_free_all(out);
    BIO_free_all(in);

	EVP_PKEY_free(pkey);
	sk_X509_free(apcerts);
    
	// PKCS7_RECIP_INFO_free(addRi) not needed - already done in below p7 free.
	PKCS7_free(p7);

	return 0;
}

