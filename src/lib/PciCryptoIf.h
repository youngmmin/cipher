/*******************************************************************
 *   File Type          :       interface declaration
 *   Classes            :       PciCryptoIf
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 10. 10
 *   Description        :       petra cipher crypto module interface
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCI_CRYPTO_IF_H
#define PCI_CRYPTO_IF_H

#include "PciCipherFactory.h"

//
// cipher type
//
static const dgt_uint8	PCI_CIPHER_DFLT		=0;
static const dgt_uint8	PCI_CIPHER_AES		=1;
static const dgt_uint8	PCI_CIPHER_SEED		=2;
static const dgt_uint8	PCI_CIPHER_ARIA		=3;
static const dgt_uint8	PCI_CIPHER_SHA		=4;
static const dgt_uint8	PCI_CIPHER_TDES		=5;
static const dgt_uint8	PCI_CIPHER_RSA		=7;
static const dgt_uint8	PCI_CIPHER_DES		=8;
static const dgt_uint8	PCI_CIPHER_HMAC		=9;
static const dgt_uint8	PCI_CIPHER_HIGHT	=10;

// added by mwpark
// for nh requrement 
// get key interface
static const dgt_uint8	PCI_CIPHER_TRANSFER	=11;

//
// encryption mode
//
static const dgt_uint8	PCI_EMODE_DFLT		=0;
static const dgt_uint8	PCI_EMODE_ECB		=1;
static const dgt_uint8	PCI_EMODE_CBC		=2;
static const dgt_uint8	PCI_EMODE_CFB		=3;
static const dgt_uint8	PCI_EMODE_OFB		=4;
static const dgt_uint8	PCI_EMODE_CBC0		=5;


//
// initial vector type
//
static const dgt_uint8	PCI_IVT_NO		=0; // no iv
static const dgt_uint8	PCI_IVT_RANDOM		=2; // random iv
static const dgt_uint8	PCI_IVT_PIV1		=3; // predefined iv1
static const dgt_uint8	PCI_IVT_PIV2		=4; // predefined iv2
static const dgt_uint8	PCI_IVT_PIV3		=5; // predefined iv3
static const dgt_uint8	PCI_IVT_PIV4		=6; // predefined iv4
static const dgt_uint8	PCI_IVT_PIV5		=7; // predefined iv5

static const dgt_uint8	PCI_MAX_IV_LENGTH	=64; // max initial vector length


//
// source type 
//
static const dgt_uint8	PCI_SRC_TYPE_OTHERS	=0;
static const dgt_uint8	PCI_SRC_TYPE_VARCHAR	=1;
static const dgt_uint8	PCI_SRC_TYPE_NUM	=2;
static const dgt_uint8	PCI_SRC_TYPE_DATE	=3;
static const dgt_uint8	PCI_SRC_TYPE_RAW	=4;
static const dgt_uint8	PCI_SRC_TYPE_CHAR	=5;

//
// padding mode
//
static const dgt_uint8  PCI_PAD_ZERO		=1;
static const dgt_uint8  PCI_PAD_PKCS		=2;


//
// encode_type
//
static const dgt_uint8  PCI_B64_OLD            =1;
static const dgt_uint8  PCI_B64_NEW            =2;
static const dgt_uint8  PCI_B16_HEXA            =5;


//
// error code
//
static const dgt_sint32	PCI_ERR_UNSUPPORTED_KEY_SIZE	= 	-30101;
static const dgt_sint32	PCI_ERR_UNSUPPORTED_ENC_MODE	= 	-30102;
static const dgt_sint32	PCI_ERR_UNSUPPORTED_CIPHER_TYPE	= 	-30103;
static const dgt_sint32	PCI_ERR_ENC_DATA_TOO_SHORT	= 	-30104;
static const dgt_sint32	PCI_ERR_OUT_BUFFER_TOO_SHORT	= 	-30105;
static const dgt_sint32	PCI_ERR_UNSUPPORTED_DIGEST_LEN	= 	-30106;
static const dgt_sint32	PCI_ERR_INVALID_ENC_DATA_LEN	=	-30107;
static const dgt_sint32	PCI_ERR_B64_FORMAT_ERROR	=	-30108;
static const dgt_sint32	PCI_ERR_ARIA_KEY_MAKING_ERROR	=	-30109;
static const dgt_sint32	PCI_ERR_INVALID_ENC_START_POS	=	-30110;
static const dgt_sint32	PCI_ERR_INVALID_PARAM_VALUE	=	-30111;
static const dgt_sint32	PCI_ERR_EVP_FAILED		=	-30112;
static const dgt_sint32	PCI_ERR_SFC_FAILED		=	-30113;
static const dgt_sint32	PCI_ERR_INVALID_IV_TYPE		=	-30114;
static const dgt_sint32	PCI_ERR_ALREADY_ENCRYPTED	=	-30115;
static const dgt_sint32	PCI_ERR_INVALID_TRAILER		=	-30116;
static const dgt_sint32	PCI_ERR_CIPHER_INITIALIZATION	=	-30117;


//
// petra cipher context type
//
static const dgt_sint32	PCI_ERR_MSG_LEN		=256;
static const dgt_sint32	PCI_OPH_BUFFER_LEN	=100;

class PCI_Context {
  public:
	const dgt_uint8*	key;
	dgt_uint32		enc_length;
	dgt_uint16		key_size;
	dgt_uint8		cipher_type;
	dgt_uint8		enc_mode;
	dgt_uint8		iv_type;
	dgt_uint8		n2n_flag;
	dgt_uint8		b64_txt_enc_flag;
	dgt_uint8		enc_start_pos;
	dgt_uint8		remains;
	dgt_uint8		double_enc_check;
	dgt_sint32		err_code;
	dgt_schar		err_msg[PCI_ERR_MSG_LEN];
	dgt_uint8		oph_buffer[PCI_OPH_BUFFER_LEN];
	dgt_sint8		coupon_type;
	dgt_uint8		dynamic_start_pos_flag;
	dgt_uint8		trailer_flag;
	dgt_uint8		pad_type;   // 0,1 : zero 2 : pkcs#5,7 3: pkcs #5,7 + user defined trailer
	PciCipherFactory	factory;
	PciCipher*		cipher;
	dgt_uint8		next_hash[64];
	dgt_sint8		oph_key_flag;
	dgt_uint8		u_trailer_size; // user defined trailer size
	dgt_schar		u_trailer_char[7]; // user defined trailer
	dgt_sint8		crc32_trailer_flag; // crc32 trailer flag
};


dgt_sint32 PCI_initContext(
	PCI_Context*		ctx,
	const dgt_uint8*	key,
	dgt_uint16		key_size,
	dgt_uint8		cipher_type,
	dgt_uint8		enc_mode,
	dgt_uint8		iv_type=0,
	dgt_uint8		n2n_flag=0,
	dgt_uint8		b64_txt_enc_flag=0,
	dgt_uint8		enc_start_pos=1,
	dgt_uint32		enc_length=0,
	dgt_uint8		oph_flag=0,
	dgt_uint8		u_trailer_size=0,
	const dgt_schar*	u_trailer_char=0);


// added by mwpark for changing key periodically
dgt_sint32 PCI_changeContext(
        PCI_Context*            ctx,
        const dgt_uint8*        key);



dgt_uint32 PCI_encryptLength(
	PCI_Context*		ctx,
	dgt_sint32		src_len,
	dgt_sint32*		out_enc_len=0);


dgt_sint32 PCI_encrypt(
	PCI_Context*		ctx,
	dgt_uint8*		src,
	dgt_sint32		src_len,
	dgt_uint8*		dst,
	dgt_uint32*		dst_len,
	dgt_uint8		oph_pos=0);
	

dgt_sint32 PCI_decrypt(
	PCI_Context*		ctx,
	dgt_uint8*		src,
	dgt_sint32		src_len,
	dgt_uint8*		dst,
	dgt_uint32*		dst_len);


#if 0
static const dgt_uint16 PCI_OPHUEK_MAX_ROUND	=5;
static const dgt_uint16 PCI_OPHUEK_MAX_HASH	=10;
#else
static const dgt_uint16 PCI_OPHUEK_MAX_ROUND	=1;
static const dgt_uint16 PCI_OPHUEK_MAX_HASH	=1;
#endif
static const dgt_uint32 PCI_OPHUEK_MIN_NUM_HASH	=44;


dgt_uint32 PCI_ophuekLength(dgt_sint32 src_len, dgt_uint8 src_type, dgt_sint32 b64_flag=0);


dgt_sint32 PCI_OPHUEK(
	PCI_Context*		ctx,
	dgt_uint8*		src,
	dgt_sint32		src_len,
	dgt_uint8*		dst,
	dgt_uint32*		dst_len,
	dgt_sint64		enc_col_id,
	dgt_uint8		src_type,
	dgt_sint32		src_enc_flag=1,
	dgt_sint32		b64_flag=0);

dgt_sint32 PCI_Coupon(
        PCI_Context*            ctx,
        dgt_uint8*              src,
        dgt_sint32              src_len,
        dgt_uint8*              dst,
        dgt_uint32*             dst_len);


dgt_sint32 PCI_getErrCode(PCI_Context* ctx);


dgt_schar* PCI_getErrMsg(PCI_Context* ctx);

dgt_sint32 PCI_checkCRC32(dgt_uint8* src, dgt_sint32 src_len);



#endif
