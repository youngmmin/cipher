/*******************************************************************
 *   File Type          :       external procedure definition
 *   Classes            :       PccCreateRsaKey
 *   Implementor        :       mwpark
 *   Create Date        :       2017. 06. 22
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PccCreateRsaKey.h"

#include "DgcDbProcess.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/x509.h"

PccCreateRsaKey::PccCreateRsaKey(const dgt_schar* name)
    : DgcExtProcedure(name) {}

PccCreateRsaKey::~PccCreateRsaKey() {}

DgcExtProcedure* PccCreateRsaKey::clone() {
    return new PccCreateRsaKey(procName());
}

dgt_sint32 PccCreateRsaKey::execute() throw(DgcExcept) {
    if (BindRows == 0 || BindRows->next() == 0 || ReturnRows == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "invalid parameter")),
                -1);
    }
    dgt_schar* pw = (dgt_schar*)BindRows->data();
    if (*pw == 0) {
        THROWnR(DgcLdbExcept(DGC_EC_LD_STMT_ERR,
                             new DgcError(SPOS, "null password not allowed")),
                -1);
    }

    dgt_sint32 ret = 0;
    RSA* r = NULL;
    BIGNUM* bne = NULL;
    BIO *bp_public = NULL, *bp_private = NULL;

    dgt_sint32 bits = 2048;
    unsigned long e = RSA_F4;

    // 1. generate rsa key
    bne = BN_new();
    ret = BN_set_word(bne, e);
    if (ret != 1) {
        goto free_all;
    }
    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if (ret != 1) {
        goto free_all;
    }

    // 2. save public key
    bp_public = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_RSA_PUBKEY(bp_public, r);
    if (ret != 1) {
        goto free_all;
    }
    dgt_schar public_buf[1024];
    memset(public_buf, 0, 1024);
    BIO_read(bp_public, public_buf, 1024);

    bp_private = BIO_new(BIO_s_mem());
    ret =
        PEM_write_bio_RSAPrivateKey(bp_private, r, EVP_aes_256_cbc(),
                                    (unsigned char*)pw, strlen(pw), NULL, NULL);
    dgt_schar private_buf[2048];
    memset(private_buf, 0, 2048);
    BIO_read(bp_private, private_buf, 2048);

    typedef struct {
        dgt_schar private_key[2048];
        dgt_schar public_key[1024];
    } return_type;
    return_type rtn_row;
    memset(&rtn_row, 0, sizeof(return_type));
    memcpy(rtn_row.private_key, private_buf, 2048);
    memcpy(rtn_row.public_key, public_buf, 1024);

    ReturnRows->reset();
    ReturnRows->add();
    ReturnRows->next();
    memcpy(ReturnRows->data(), &rtn_row, sizeof(return_type));
    ReturnRows->rewind();

free_all:
    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    RSA_free(r);
    BN_free(bne);

    return 0;
}
