/*******************************************************************
 *   File Type          :       interface class implementation
 *   Classes            :       PciCryptoIf
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 10. 11
 *   Description        :       petra cipher crypto interface
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "DgcBase64.h"
#include "PciCryptoIf.h"
#include "PciSha2.h"
#include "PciAriaCipher.h"
#include "PciAesCipher.h"
#include "PciSeedCipher.h"
#include "Pci3DesCipher.h"
#include "PciHmac.h"
#include "PciHmacCipher.h"
#include "PciHightCipher.h"
#include "PciLeaCipher.h"

#define PCC_TEMP_LEN 32

static dgt_sint32	PCC_ENC_TRAILER_LENGTH=4;
#define PCC_IV_TYPE(_tlr_)	(((_tlr_[0] & 0x03) << 1) + ((_tlr_[1] & 0x80) >> 7))		// initial vector type
#define PCC_REMAINS(_tlr_)	(_tlr_[1] & 0x3f)			// effective bytes in the last block
#define PCC_OPH_POS(_tlr_)	(_tlr_[2])				// ophuek end position

static const dgt_uint8  PCI_INBS[32]= // Instead of Null Block SEED
{132, 87, 63,  2,123,  9, 78,123, 94,123,
  89, 74, 51,239, 78, 41,237, 89,  5,  3,
  45, 71, 34, 85,234, 97,197, 82, 31, 49,
  23, 12
};

static inline dgt_uint8* PCI_INB()
{
	static dgt_uint8* wjdwogns=0;
	if (!wjdwogns) {
		wjdwogns=new dgt_uint8[32];
		memcpy(wjdwogns,PCI_INBS,32);
		for(dgt_uint8 i=0; i<32; i++)
			if (wjdwogns[i] < 100) wjdwogns[i] += wjdwogns[i] & 0xc8 % 15;
			else wjdwogns[i] -= wjdwogns[i] & 0xd9 % 8;
	}
	return wjdwogns;
}

static const dgt_uint8  PCI_PIVS[74]= // Predefined Initial Vector seed
{123,  8, 94, 71,230,  9, 12, 70, 95, 71,
  84, 84,  3, 78,  5, 63,  4, 83,123, 95,
  47, 56, 91, 34,123, 46, 73,214, 38, 24,
   1,239, 76,237,  8, 39, 81, 80,238, 90,
  81,  3,123, 89, 74,  1,239, 81,230, 67,
  51,236, 51, 59,238, 74, 61, 92, 37, 84,
 125,180, 36,237,0,0,0,0,0,0,0,0,0,0
};

static inline dgt_uint8* PCI_PIV(dgt_uint8 iv_type)
{
	static dgt_uint8* wjsdmswjd=0;
	if (!wjsdmswjd) {
		wjsdmswjd=new dgt_uint8[74];
		memcpy(wjsdmswjd,PCI_PIVS,74);
		for(dgt_uint8 i=0; i<74; i++)
			if (wjsdmswjd[i] < 100) wjsdmswjd[i] += wjsdmswjd[i] & 0xaf % 17;
			else wjsdmswjd[i] -= wjsdmswjd[i] & 0xba % 21;
	}
	return (wjsdmswjd + iv_type);
}

static dgt_void PCI_printContext(PCI_Context* ctx)
{
	printf("	key pointer => [%p]\n",ctx->key);
	printf("	encrypt length => [%u]\n",ctx->enc_length);
	printf("	key size => [%u]\n",ctx->key_size);
	printf("	key => [");
	if (ctx->key_size && ctx->key) for (dgt_uint16 i=0; i<ctx->key_size/8; i++) printf("%02x",*(ctx->key+i));
	printf("]\n");
	printf("	cipyer type => [%u]\n",ctx->cipher_type);
	printf("	encrypt mode => [%u]\n",ctx->enc_mode);
	printf("	initial vector type => [%u]\n",ctx->iv_type);
	printf("	base64 encoding flag => [%u]\n",ctx->b64_txt_enc_flag);
	printf("	remains => [%u]\n",ctx->remains);
	printf("	encrypt start position => [%u]\n",ctx->enc_start_pos);
	printf("	block size => [%u]\n",ctx->cipher->blockSize());
	printf("	cipher pointer => [%p]\n",ctx->cipher);
	printf("	error code => [%d]\n",ctx->err_code);
	printf("	error message => [%s]\n",ctx->err_msg);
}


static dgt_void PCI_resetError(PCI_Context* ctx)
{
	ctx->err_code=0;
	memset(ctx->err_msg,0,PCI_ERR_MSG_LEN);
}


dgt_sint32 PCI_initContext(
        PCI_Context*            ctx,
        const dgt_uint8*        key,
        dgt_uint16              key_size,
        dgt_uint8               cipher_type,
        dgt_uint8               enc_mode,
        dgt_uint8               iv_type,
        dgt_uint8               n2n_flag,
        dgt_uint8               b64_txt_enc_flag,
        dgt_uint8               enc_start_pos,
	dgt_uint32		enc_length,
	dgt_uint8		oph_flag,
	dgt_uint8		u_trailer_size,
	const dgt_schar*	u_trailer_char)
{
#ifdef PCI_TEST
printf("PCI_initContext-INPUT::\n");
printf("	ctx => [%p]\n",ctx);
printf("	key pointer => [%p]\n",key);
printf("	encrypt length => [%u]\n",enc_length);
printf("	key size => [%u]\n",key_size);
printf("	key => [");
if (key_size && key) for (dgt_uint16 i=0; i<key_size/8; i++) printf("%02x",*(key+i));
printf("]\n");
printf("	cipyer type => [%u]\n",cipher_type);
printf("	encrypt mode => [%u]\n",enc_mode);
printf("	initial vector type => [%u]\n",iv_type);
printf("	base64 encoding flag => [%u]\n",b64_txt_enc_flag);
printf("	encrypt start position => [%u]\n",enc_start_pos);
#endif

	memset(ctx,0,sizeof(PCI_Context));
	ctx->key = key;
	ctx->key_size = key_size;
	ctx->cipher_type = cipher_type;
	ctx->enc_mode = enc_mode;
	ctx->iv_type = iv_type;
	ctx->n2n_flag = n2n_flag;
	if (ctx->cipher_type == PCI_CIPHER_SHA || ctx->cipher_type == PCI_CIPHER_HMAC) {
		if ((ctx->b64_txt_enc_flag=b64_txt_enc_flag) < PCI_B64_NEW) {
			ctx->enc_mode=PCI_EMODE_CBC;
		} else if (ctx->enc_mode != PCI_EMODE_ECB) {
			ctx->enc_mode=PCI_EMODE_CBC;
		}
	}
	if ((ctx->b64_txt_enc_flag=b64_txt_enc_flag) < PCI_B64_NEW &&
	     ctx->cipher_type == PCI_CIPHER_ARIA && ctx->enc_mode != PCI_EMODE_ECB) {
		//
		// for supporting old type aria cipher
		//
		ctx->enc_mode=PCI_EMODE_CBC0;
	}
	ctx->pad_type = b64_txt_enc_flag; // 0,1 : zero , 2,3,4,5,6: pkcs #5,#7 
	if (ctx->pad_type >= PCI_PAD_PKCS) ctx->pad_type = PCI_PAD_PKCS;
	if (oph_flag || ctx->pad_type <= PCI_PAD_ZERO) {
		//
		// b64_txt_enc_flag : 0,1 = zero padding needs trailer(old version compatible)
		// oph_flag : 1 = opheuk needs trailer
		//
		ctx->trailer_flag = 1;
	}
	if (ctx->trailer_flag == 0 && n2n_flag == 0) {
		//
		// null encryption needs trailer
		//
		//ctx->n2n_flag = 1;
		ctx->trailer_flag = 1;
	}
	ctx->enc_start_pos = enc_start_pos;
	ctx->enc_length = enc_length;
	if (enc_start_pos == 0 && enc_length > 0) {
		//
		// zero start position means partial encryption from the end
		//
		ctx->dynamic_start_pos_flag = 1;
	}
	if (ctx->trailer_flag == 0 && ctx->b64_txt_enc_flag == 3 && u_trailer_size && u_trailer_char) {
		ctx->u_trailer_size = u_trailer_size;
		memset(ctx->u_trailer_char,0,7);
		memcpy(ctx->u_trailer_char,u_trailer_char,u_trailer_size);
	}
	if (ctx->b64_txt_enc_flag == 4) {
		//
		// for nh requirement
		// b64_txt_enc_flag == 4 : pkcs#7 padding and no b64_ext_enc_flag
		//
		ctx->b64_txt_enc_flag = 0;
	}
	if (ctx->b64_txt_enc_flag == 5) {
		//
		// for nh requirement
		// b64_txt_enc_flag == 5 : pkcs#7 padding and hexa encoding
		//
		ctx->b64_txt_enc_flag = 5;
	}
	if (ctx->trailer_flag == 0 && ctx->b64_txt_enc_flag == 7) {
		//
		// for ibk requriement
		// b64_txt_enc_flag == 7 : crc32 for checking double encryption 
		ctx->crc32_trailer_flag = 1;
		ctx->b64_txt_enc_flag = 2;
	}
	PCI_resetError(ctx);
	if (ctx->cipher_type == PCI_CIPHER_SEED && (ctx->key_size != 128 && ctx->key_size != 256)) {
		sprintf(ctx->err_msg,"unsupported key size[%d]",ctx->key_size);
		return ctx->err_code=PCI_ERR_UNSUPPORTED_KEY_SIZE;
	}
	if (ctx->cipher_type == PCI_CIPHER_SHA &&
	    ctx->key_size != 256 && ctx->key_size != 384 && ctx->key_size != 512) { // unsupported digest length
		sprintf(ctx->err_msg,"unsupported digest length[%d]",ctx->key_size);
		return ctx->err_code=PCI_ERR_UNSUPPORTED_DIGEST_LEN;
	}
	if (ctx->cipher_type == PCI_CIPHER_HMAC &&
	    ctx->key_size != 160 && ctx->key_size != 256) { // unsupported digest length
		sprintf(ctx->err_msg,"unsupported hmac digest length[%d]",ctx->key_size);
		return ctx->err_code=PCI_ERR_UNSUPPORTED_DIGEST_LEN;
	}
	if ((ctx->cipher=ctx->factory.getCipher(ctx->cipher_type,ctx->key_size)) == 0 && ctx->cipher_type != PCI_CIPHER_TRANSFER) {
		sprintf(ctx->err_msg,"unsupported cipher type[%d]",ctx->cipher_type);
		return ctx->err_code = PCI_ERR_UNSUPPORTED_CIPHER_TYPE;
	}
	dgt_sint32 rtn;
	if (ctx->cipher_type != PCI_CIPHER_TRANSFER) {
		if ((rtn=ctx->cipher->initialize(ctx->key,ctx->key_size,ctx->enc_mode,ctx->pad_type))) {
			sprintf(ctx->err_msg,"cipher[%u] initialization failed[%d]",ctx->cipher_type,rtn);
			return ctx->err_code=PCI_ERR_CIPHER_INITIALIZATION;
		}
	}


#ifdef PCI_TEST
printf("PCI_initContext-OUTPUT::\n");
PCI_printContext(ctx);
#endif
	return 0;
}

// added by mwpark for changing key periodically
dgt_sint32 PCI_changeContext(
        PCI_Context*            ctx,
        const dgt_uint8*        key)
{
        dgt_sint32 rtn;
	if ((rtn=ctx->cipher->initialize(key,ctx->key_size,ctx->enc_mode,ctx->pad_type))) {
		sprintf(ctx->err_msg,"cipher[%u] initialization failed[%d]",ctx->cipher_type,rtn);
		return ctx->err_code=PCI_ERR_CIPHER_INITIALIZATION;
	}
	return 0;
}



dgt_uint32 PCI_encryptLength(
        PCI_Context*    ctx,
	dgt_sint32	src_len,
	dgt_sint32*	out_enc_len)
{
	//
	// added by mwpark
	// in case of minus length null data 
	//
	if (src_len < 0) src_len=0;
	dgt_uint32	output_len = 0; // case0 => null to null
	dgt_sint32	enc_len = 0;
	if (src_len || !ctx->n2n_flag) {
		//
		// only in case of not-null, null but null-2-null flag off,
		// which means null is to be replaced with a block-sized special pattern.
		//
		if (src_len && ctx->enc_start_pos > src_len) {
			// case1 => out-of-bound starting position => no encryption
			output_len = src_len;
		} else {
			dgt_uint8 ab = ctx->dynamic_start_pos_flag ? 0 : 1;
			if (src_len == 0) {
				enc_len = 0;
			} else {
				enc_len = ctx->enc_length; // the amount to be encrypted
				if (enc_len == 0 || enc_len > (src_len - ctx->enc_start_pos + ab)) {
					//
					// case2 => whole back part encryption
					//
					// enc_len could not be the same as "ctx->enc_length" 
					// even if the latter is greater than zero
					// because it couldn't goes over the end of "target source".
					//
					enc_len = src_len - ctx->enc_start_pos + ab;
				}
			}
			if (ctx->cipher_type == PCI_CIPHER_SHA || ctx->cipher_type == PCI_CIPHER_HMAC) {
				//
				// the result length of hash is always the digest length
				// regardless of the amount of encryption target
				//
				output_len = (dgt_uint32)(ctx->key_size/8);
			} else {
				if (src_len == 0) {
					//
					// case3 => null encryption
 					// null would be replaced with a block-sized pattern later.
 					//
					output_len = ctx->cipher->blockSize();
				} else {
					// case4 => front or middle encryption
					if (ctx->enc_mode == PCI_EMODE_CFB || ctx->enc_mode == PCI_EMODE_OFB) {
						// CBF & OFB need no padding
						output_len = enc_len;
					} else {
						output_len = (dgt_uint32)ceil((double)enc_len/ctx->cipher->blockSize())*ctx->cipher->blockSize();
					} 
				}
				if (enc_len && (enc_len % ctx->cipher->blockSize()) == 0 &&
				    ctx->pad_type == PCI_PAD_PKCS && 
				    ctx->enc_mode != PCI_EMODE_CFB && ctx->enc_mode != PCI_EMODE_OFB) {
					//
					// in pkcs7 padding scheme 
					// if src_len is multiple of block size, add a full padding block
					//
					output_len += ctx->cipher->blockSize();
				}
				if (ctx->iv_type == PCI_IVT_RANDOM && ctx->enc_mode != PCI_EMODE_ECB) {
					// random initial vector which should be attached at the end
					// output_len += ctx->cipher->blockSize();
					 output_len += 16;
				}
			}
			if (ctx->b64_txt_enc_flag == PCI_B64_OLD) {
				// old style base64 encoding
				output_len = DgcBase64::encodeLength(output_len);
			} else if (ctx->b64_txt_enc_flag >= PCI_B64_NEW && ctx->b64_txt_enc_flag < PCI_B16_HEXA) {
				// new style base64 encoding
				output_len = DgcBase64::encodeLength2(output_len);
			} else if (ctx->b64_txt_enc_flag == PCI_B16_HEXA) {
				// hexa encoding
				output_len = output_len * 2;
			}
			//
			// now add the lengths of leading & tailing non-enrypted part
			//
			output_len += (src_len - enc_len);
			//
			// now add the length of an encrypted tailer except for hash
			//
			if ((ctx->cipher_type != PCI_CIPHER_SHA && ctx->cipher_type != PCI_CIPHER_HMAC) && ctx->trailer_flag) output_len += PCC_ENC_TRAILER_LENGTH;
		}
		if (ctx->u_trailer_size) {
			output_len += ctx->u_trailer_size;
		}
		if (ctx->crc32_trailer_flag) {
			output_len += 4;
		}
	}
	if (out_enc_len) {
		*out_enc_len = enc_len;
	}
	return output_len;
}


static inline dgt_sint32 PCI_isEncrypted(
        PCI_Context*    ctx,
	dgt_uint8*      src,
	dgt_sint32	src_len)
{
	//
	// added by mwpark
	// in case of minus length null data 
	//
	if (src_len < 0) src_len=0;
	if (ctx->trailer_flag) {
		//
		// impossible to ensure that src is encrypted without a trailer 
		//
		dgt_uint8 trailer[3] = {0,0,0};
		dgt_uint8* b64_tailer = 0;
		dgt_sint32 null_len = ctx->cipher->blockSize();
	        dgt_sint32 min_len = ctx->cipher->blockSize();
	        if (ctx->enc_mode == PCI_EMODE_CFB || ctx->enc_mode == PCI_EMODE_OFB) min_len = 0;
        	if (ctx->enc_mode != PCI_EMODE_ECB && ctx->iv_type == PCI_IVT_RANDOM) {
	                min_len += ctx->cipher->blockSize();
	        }
        	if (ctx->b64_txt_enc_flag == PCI_B64_OLD) {
	                min_len = DgcBase64::encodeLength(min_len);
	        } else if (ctx->b64_txt_enc_flag >= PCI_B64_NEW) {
        	        min_len = DgcBase64::encodeLength2(min_len);
	        }
        	if (ctx->trailer_flag) {
	                min_len += PCC_ENC_TRAILER_LENGTH;
	        }
        	if (ctx->u_trailer_size) {
	                min_len += ctx->u_trailer_size;
	        }
		if (ctx->crc32_trailer_flag) {
	                min_len += 4;
		}
		//
	        // check the length of source
        	//
	        if (min_len > src_len) {
			return 0;
	        }
		if (ctx->enc_mode != PCI_EMODE_ECB && ctx->iv_type == PCI_IVT_RANDOM) null_len += ctx->cipher->blockSize();
		if (ctx->b64_txt_enc_flag == PCI_B64_OLD) null_len = DgcBase64::encodeLength(null_len);
		else if (ctx->b64_txt_enc_flag >= PCI_B64_NEW) null_len = DgcBase64::encodeLength2(null_len);
		null_len += PCC_ENC_TRAILER_LENGTH;
		b64_tailer = src + src_len - PCC_ENC_TRAILER_LENGTH;
		if (ctx->b64_txt_enc_flag >= PCI_B64_NEW) {
			DgcBase64::decode2((dgt_schar*)b64_tailer, PCC_ENC_TRAILER_LENGTH, trailer, 3);
		} else {
			DgcBase64::decode((dgt_schar*)b64_tailer, PCC_ENC_TRAILER_LENGTH, trailer, 3);
		}
		if (ctx->pad_type != PCI_PAD_PKCS && (ctx->remains=PCC_REMAINS(trailer)) > ctx->cipher->blockSize()) return 0;
		if (src_len == null_len && ctx->remains == 0) return 1; // encrypted null
		if (PCC_IV_TYPE(trailer) > PCI_IVT_PIV5) return 0;
		dgt_uint8 ab = ctx->dynamic_start_pos_flag ? 0 : 1;
		dgt_sint32 enc_perfect_len = ctx->enc_start_pos+ctx->enc_length-(ctx->dynamic_start_pos_flag?0:1);
		dgt_sint32 enc_len = 0;
		dgt_sint32 output_len = PCI_encryptLength(ctx,enc_perfect_len,&enc_len);
		if (src_len >= output_len) return 1;
	}
	return 0;
}


#include "DgcCRC32.h"

dgt_void PCI_Crc32(
	dgt_uint8* src,
	dgt_sint32 src_len,
	dgt_uint8* dst,
	dgt_uint32* dst_len)
{
	//
	// added by mwpark
	// in case of minus length null data 
	//
	if (src_len < 0) src_len=0;
	dgt_uint32 str_crc = DgcCRC32::initCRC();
#ifndef WIN32
	DgcCRC32::calCRC(&str_crc,(const dgt_uint8*)src,src_len);
#else
	DgcCRC32::calCRC(&str_crc,(dgt_uint8*)src,src_len);
#endif
	str_crc = DgcCRC32::resultCRC(str_crc);
	dgt_uint8	tmp[5];
	memset(tmp,0,5);
	mcp4(tmp,(dgt_uint8*)&str_crc);
	DgcBase64::encode2(tmp, 3, (dgt_schar*)dst, 4);
	*dst_len=4;
}

dgt_sint32 PCI_checkCRC32(
	dgt_uint8* src,
	dgt_sint32 src_len)
{
	//
	// added by mwpark
	// in case of minus length null data 
	//
	if (src_len < 0) src_len=0;
	dgt_sint32 i=0;
	dgt_sint32 is_match=1;
	dgt_uint8  tmp[5];
	memset(tmp,0,5);
	dgt_uint32 tmp_len=4;
	PCI_Crc32(src, src_len-4, tmp, &tmp_len);
	dgt_uint8 org_str[5];
	memset(org_str,0,5);
	memcpy(org_str,src+src_len-4,4);
	if (!strncmp((dgt_schar*)org_str, (dgt_schar*)tmp, 4)) {
		is_match=1;
	} else {
		is_match=0;
	}
	return is_match;
}


dgt_sint32 PCI_encrypt(
        PCI_Context*    ctx,
	dgt_uint8*      src,
	dgt_sint32      src_len,
	dgt_uint8*      dst,
	dgt_uint32*     dst_len,
	dgt_uint8	oph_pos)
{
#ifdef PCI_TEST
printf("PCI_encrypt-INPUT::\n");
PCI_printContext(ctx);
printf("	input pointer => [%p]\n",src);
printf("	input length => [%u]\n",src_len);
printf("	input => [");
if (src_len && src) for (dgt_sint32 i=0; i<src_len; i++) printf("%02x",*(src+i));
printf("]\n");
printf("	output pointer => [%p]\n",dst);
printf("	output length => [%u]\n",*dst_len);
#endif
	PCI_resetError(ctx);
	//
	// added by mwpark
	// in case of minus length null data 
	//
	if (src_len < 0) src_len=0;

	//
	// check output buffer correctness
	//
	if (ctx == 0 || dst_len == 0 || (ctx->n2n_flag == 0 && dst == 0)) {
		sprintf(ctx->err_msg,"invalid parameter value:: ctx[%p] src[%p] src_len[%d] dst[%p] dst_len[%p:%u] start_pos[%d]",
			ctx, src, src_len, dst, dst_len, (dst_len ? *dst_len:0), ctx->enc_start_pos);
	}
	//
	// check output buffer length
	//
	dgt_sint32	enc_len = 0; // the amount to be encrypted
	dgt_uint32	output_len = PCI_encryptLength(ctx, src_len, &enc_len);
	if (output_len == 0) {
		//
		// case0 => null to null
		//
		*dst_len = 0;
		return 0;
	}
	if (*dst_len < output_len) { // destination buffer too short
		sprintf(ctx->err_msg,"out buffer[%d] too short for %d bytes\n src_len [%d]", *dst_len, output_len, src_len);
		return ctx->err_code=PCI_ERR_OUT_BUFFER_TOO_SHORT;
	}
	// 
	// adjust the start position in case of partial encryption from the end
	//
	dgt_uint8 enc_start_pos = ctx->enc_start_pos;
	if (ctx->dynamic_start_pos_flag) {
		if (src_len <= (dgt_sint32)ctx->enc_length) enc_start_pos = 1;
		else enc_start_pos = src_len-ctx->enc_length + 1;
	}
	//
	// check no encryption
	//
	if (src_len && enc_start_pos > src_len) {
		//
		// case1 => no encryption
		//
		// when source length less than encrypt start position,
		// return source data without encryption in case of not-null.
		//
		memcpy(dst, src, src_len);
		*dst_len = src_len;
		return 0;
	}
	dgt_uint8* dst_org = dst; // only for test
	//
	// copy the leading unencrypted part to the output buffer before encryption
	//
	if (src_len && enc_start_pos > 1) {
		memcpy(dst, src, (enc_start_pos - 1));
		dst += (enc_start_pos - 1);
		*dst_len -= (enc_start_pos - 1);
	}
	//
	// set the pointer where the data starts to be encrypted
	//
	dgt_uint8* enc_ptr = src + enc_start_pos - 1;
	if (src_len == 0) {
		//
		// encrypted target is replaced with the null pattern
		//
		enc_ptr = PCI_INB();
		if (ctx->pad_type < PCI_PAD_PKCS) enc_len=ctx->cipher->blockSize();
	} else {
#if 1 // add by chchung, 2011.11.30, add double encryption check 
		if (ctx->double_enc_check && ctx->trailer_flag && (ctx->cipher_type != PCI_CIPHER_SHA && ctx->cipher_type != PCI_CIPHER_HMAC)) {
			if (PCI_isEncrypted(ctx, src, src_len)) {
				*dst_len=src_len;
				sprintf(ctx->err_msg,"source[%d] already encrypted", src_len);
				return ctx->err_code=PCI_ERR_ALREADY_ENCRYPTED;
			}
                } else if (ctx->double_enc_check && ctx->u_trailer_size && ctx->u_trailer_char && src_len > 23) {
                        dgt_sint32 i=0;
                        dgt_sint32 is_match=1;
			
                        for (i=0; i<ctx->u_trailer_size; i++) {
                                if (ctx->u_trailer_char[i] != src[src_len-ctx->u_trailer_size+i]) {
                                        is_match=0;
                                }
                        }
                        if (is_match) {
				*dst_len=src_len;
                        	sprintf(ctx->err_msg,"source[%d] already encrypted", src_len);
                                return ctx->err_code=PCI_ERR_ALREADY_ENCRYPTED;
                        }
		} else if (ctx->double_enc_check && ctx->crc32_trailer_flag && src_len > 23 &&(ctx->cipher_type != PCI_CIPHER_SHA && ctx->cipher_type != PCI_CIPHER_HMAC)) {
			dgt_sint32 is_match=PCI_checkCRC32(src, src_len);
                        if (is_match) {
                                dgt_sint32 rtn=0;
                                dgt_uint8*  dt=new dgt_uint8[src_len];
                                memset(dt,0,src_len);
                                dgt_uint32 dt_len=src_len;
                                if ((rtn=PCI_decrypt(ctx, src, src_len, dt, &dt_len)) < 0) {
					delete dt;
                                        ctx->err_code=0;
                                        memset(ctx->err_msg,0,PCI_ERR_MSG_LEN);
                                } else {
					*dst_len=src_len;
					delete dt;
                                        sprintf(ctx->err_msg,"source[%d] already encrypted", src_len);
                                        return ctx->err_code=PCI_ERR_ALREADY_ENCRYPTED;
                                }
                        }
		} else if (ctx->double_enc_check && ctx->trailer_flag == 0 && (ctx->cipher_type != PCI_CIPHER_SHA && ctx->cipher_type != PCI_CIPHER_HMAC)) {
			dgt_sint32 rtn=0;
			dgt_uint8*  dt=new dgt_uint8[src_len];
			memset(dt,0,src_len);
			dgt_uint32 dt_len=src_len;
			if ((rtn=PCI_decrypt(ctx, src, src_len, dt, &dt_len)) < 0) {
				delete dt;
				ctx->err_code=0;
				memset(ctx->err_msg,0,PCI_ERR_MSG_LEN);
			} else {
				*dst_len=src_len;
				delete dt;
				sprintf(ctx->err_msg,"source[%d] already encrypted", src_len);
                                return ctx->err_code=PCI_ERR_ALREADY_ENCRYPTED;
			}
		}
#endif
	}
	//
	// encryption begins.
	//
	dgt_sint32	rtn = 0;
	dgt_sint32	b64_enc_len;
	if (ctx->cipher_type == PCI_CIPHER_SHA) {
		if (ctx->iv_type >= PCI_IVT_PIV1 && ctx->iv_type <= PCI_IVT_PIV5) { // fixed iv
			ctx->cipher->setIV(PCI_PIV(ctx->iv_type));
		}
		dgt_uint8 hash_val[128] = {0,}; // temporary buffer for the last block
		dgt_uint32 hash_len = 128;
		if (src_len == 0) enc_len = 32; // in case of null, the 32 bit null pattern is replaced
		if ((rtn=ctx->cipher->encrypt(enc_ptr,enc_len,hash_val,&hash_len)) < 0) {
			sprintf(ctx->err_msg,"encrypt[SHA] failed due to error");
			return ctx->err_code=rtn;
		}
		if (ctx->b64_txt_enc_flag == PCI_B64_OLD) {
			b64_enc_len = DgcBase64::encode(hash_val, hash_len, (dgt_schar*)dst, *dst_len);
			dst += b64_enc_len;
			*dst_len -= b64_enc_len;
		} else if (ctx->b64_txt_enc_flag >= PCI_B64_NEW && ctx->b64_txt_enc_flag < PCI_B16_HEXA) {
			b64_enc_len = DgcBase64::encode2(hash_val, hash_len, (dgt_schar*)dst, *dst_len);
			dst += b64_enc_len;
			*dst_len -= b64_enc_len;
		} else if (ctx->b64_txt_enc_flag == PCI_B16_HEXA) {
			b64_enc_len = DgcBase16::encode(hash_val, hash_len, (dgt_schar*)dst, *dst_len);
			dst += b64_enc_len;
			*dst_len -= b64_enc_len;
		} else {
			memcpy(dst,hash_val,hash_len);
			dst += hash_len;
			*dst_len -= hash_len;
		}
	} else {
		//
		// block cipher encryption
		//
		// prepare initial vector
		//
		dgt_uint8  iv_buffer[PCI_MAX_IV_LENGTH];
		if (ctx->iv_type && ctx->enc_mode != PCI_EMODE_ECB) {
			if (ctx->iv_type == PCI_IVT_RANDOM) { // random iv
				RAND_pseudo_bytes(iv_buffer, PCI_MAX_IV_LENGTH);
				ctx->cipher->setIV(iv_buffer);
			} else if (ctx->iv_type <= PCI_IVT_PIV5) { // fixed iv
				ctx->cipher->setIV(PCI_PIV(ctx->iv_type));
			}
		}
#if 0		
//		2015.10.05 modified by mwpark
		if (src_len == 0) {
			// in case of null, encrypt length is the size of one block
			enc_len = ctx->cipher->blockSize();
		}
#endif
		dgt_uint32 encrypted_len = *dst_len;
		if ((rtn=ctx->cipher->encrypt(enc_ptr, enc_len, dst, &encrypted_len)) < 0) {
			sprintf(ctx->err_msg,"encrypt failed due to error");
			return ctx->err_code=rtn;
		}
		dst += encrypted_len;
		*dst_len -= encrypted_len;
		//
		// add initial vector at the end of encrypted data
		//
		if (ctx->iv_type == PCI_IVT_RANDOM && ctx->enc_mode != PCI_EMODE_ECB) {
			//
			// random initial vector is added in encrypted form
			//
			PCI_Context	iv_ctx;
			PCI_initContext(&iv_ctx, ctx->key, 128, PCI_CIPHER_AES, 0, PCI_IVT_NO, 1, 0, 1,0,0);
			//dgt_uint32	tmp_len = ctx->cipher->blockSize()*2;
			dgt_uint32	tmp_len = iv_ctx.cipher->blockSize()*2;
			dgt_uint8	tmp_iv[PCC_TEMP_LEN];
			iv_ctx.b64_txt_enc_flag = 0;
			iv_ctx.enc_start_pos = 1;
			if ((rtn=PCI_encrypt(&iv_ctx, iv_buffer, iv_ctx.cipher->blockSize(), tmp_iv, &tmp_len)) < 0) {
				ctx->err_code = iv_ctx.err_code;
				memcpy(ctx->err_msg, iv_ctx.err_msg, PCI_ERR_MSG_LEN);
				return rtn;
			}
			memcpy(dst, tmp_iv, iv_ctx.cipher->blockSize());
			dst += iv_ctx.cipher->blockSize();
			*dst_len -= iv_ctx.cipher->blockSize();
			encrypted_len += iv_ctx.cipher->blockSize();
		}
		//
		// base64 encoding for encrypted part
		//
		if (ctx->b64_txt_enc_flag) {
			dgt_schar	fixed_buf[256];
			dgt_schar*	encoding_buf = fixed_buf;
			if (ctx->b64_txt_enc_flag == PCI_B64_OLD) {
				b64_enc_len = DgcBase64::encodeLength(encrypted_len);
				if (b64_enc_len > 256) encoding_buf = new dgt_schar[b64_enc_len];
				DgcBase64::encode((dst - encrypted_len), encrypted_len, encoding_buf, b64_enc_len);
				memcpy((dst - encrypted_len), encoding_buf, b64_enc_len);
				dst += (b64_enc_len - encrypted_len);
			} else if (ctx->b64_txt_enc_flag >= PCI_B64_NEW && ctx->b64_txt_enc_flag < PCI_B16_HEXA) {
				b64_enc_len = DgcBase64::encodeLength2(encrypted_len);
				if (b64_enc_len > 256) encoding_buf = new dgt_schar[b64_enc_len];
				DgcBase64::encode2((dst - encrypted_len), encrypted_len, encoding_buf, b64_enc_len);
				memcpy((dst - encrypted_len), encoding_buf, b64_enc_len);
				dst += (b64_enc_len - encrypted_len);
			} else {
				// hexa encoding
				b64_enc_len = encrypted_len * 2;
				if (b64_enc_len > 256) encoding_buf = new dgt_schar[b64_enc_len];
				DgcBase16::encode((dst - encrypted_len), encrypted_len, encoding_buf, b64_enc_len);
				memcpy((dst - encrypted_len), encoding_buf, b64_enc_len);
				dst += (b64_enc_len - encrypted_len);
			}
			if (encoding_buf != fixed_buf) delete encoding_buf;
		}
		//
		// making a trailer 
		//
		if (ctx->trailer_flag) {
			dgt_uint8 remains = (dgt_uint8)(enc_len % ctx->cipher->blockSize());
			if (enc_ptr == PCI_INB()) remains = 0;
			dgt_uint8 trailer[3]={0,0,0};
			if (ctx->iv_type <= PCI_IVT_PIV5 && ctx->cipher->iv()) {
				trailer[0] = ctx->iv_type >> 1;
				trailer[1] = ctx->iv_type << 7;
			}
			if (oph_pos) trailer[2] = oph_pos;
			if (remains) trailer[1] += remains;
			else if (src_len && enc_len >= ctx->cipher->blockSize()) trailer[1] += ctx->cipher->blockSize();
			DgcBase64::encode(trailer, 3, (dgt_schar*)dst, PCC_ENC_TRAILER_LENGTH);
			dst += PCC_ENC_TRAILER_LENGTH;
		}
	}
	//
	// add the trailing non-encrypted part right after 
	//
	if (src_len && ctx->enc_length) {
		dgt_sint32 tail_len = src_len - (enc_start_pos + ctx->enc_length - 1);
		if (tail_len > 0) memcpy(dst, src + src_len - tail_len, tail_len);
	}
	
	if (ctx->u_trailer_size) {
		memcpy(dst, ctx->u_trailer_char, ctx->u_trailer_size); 
	}

	if (ctx->crc32_trailer_flag) {
		dgt_uint8  tmp[5];
		memset(tmp,0,5);
		dgt_uint32 tmp_len=5;
		PCI_Crc32(dst_org, output_len-4, tmp, &tmp_len);
		memcpy(dst, tmp, 4);
	}
	*dst_len = output_len;

#ifdef PCI_TEST
printf("PCI_encrypt-OUTPUT::\n");
printf("	output length => [%u]\n",*dst_len);
printf("	output => [");
if (*dst_len && dst_org) for (dgt_uint32 i=0; i<*dst_len; i++) printf("%02x",*(dst_org+i));
printf("]\n");
#endif
	return 0;
}


static inline dgt_sint32 PCI_encryptCheck(
        PCI_Context*    ctx,
	dgt_uint8*      src,
	dgt_sint32      src_len,
	dgt_sint32*	encrypted_len,	// 0 => null, -1 => not encrypted, >1 => encrypted length
	dgt_sint8	set_err_msg_flag=1)
{
	//
	// added by mwpark
	// in case of minus length null data 
	//
	if (src_len < 0) src_len=0;
	//
	// condition "src_len > 0" is always guareented
	// because the callers of this function have checked it already.
	//
	// 1. compute the lengths of min and null
	//
	dgt_sint32 min_len = ctx->cipher->blockSize();
	dgt_sint32 null_len = ctx->cipher->blockSize();
	if (ctx->enc_mode == PCI_EMODE_CFB || ctx->enc_mode == PCI_EMODE_OFB) min_len = 0;
	if (ctx->enc_mode != PCI_EMODE_ECB && ctx->iv_type == PCI_IVT_RANDOM) {
		min_len += ctx->cipher->blockSize();
		null_len += ctx->cipher->blockSize();
	}
	if (ctx->b64_txt_enc_flag == PCI_B64_OLD) {
		min_len = DgcBase64::encodeLength(min_len);
		null_len = DgcBase64::encodeLength(null_len);
	} else if (ctx->b64_txt_enc_flag >= PCI_B64_NEW && ctx->b64_txt_enc_flag < PCI_B16_HEXA) {
		min_len = DgcBase64::encodeLength2(min_len);
		null_len = DgcBase64::encodeLength2(null_len);
	} else if (ctx->b64_txt_enc_flag == PCI_B16_HEXA) {
		// hexa encoding
		min_len = min_len * 2;
		null_len = null_len * 2;
	}
	if (ctx->trailer_flag) {
		min_len += PCC_ENC_TRAILER_LENGTH;
		null_len += PCC_ENC_TRAILER_LENGTH;
	}
	if (ctx->u_trailer_size) {
		min_len += ctx->u_trailer_size;
		null_len += ctx->u_trailer_size;
	}
	if (ctx->crc32_trailer_flag) {
		min_len += 4;
		null_len += 4;
	}
	//
	// 2. check null
	//
	if (ctx->n2n_flag == 0 && src_len == null_len) {
		if (ctx->trailer_flag) {
			dgt_uint8 trailer[3] = {0,0,0};
			dgt_uint8* b64_tailer = 0;
			b64_tailer = src + src_len - PCC_ENC_TRAILER_LENGTH;
			if (ctx->b64_txt_enc_flag >= PCI_B64_NEW) {
				DgcBase64::decode2((dgt_schar*)b64_tailer, PCC_ENC_TRAILER_LENGTH, trailer, 3);
			} else {
				DgcBase64::decode((dgt_schar*)b64_tailer, PCC_ENC_TRAILER_LENGTH, trailer, 3);
			}
			if (PCC_REMAINS(trailer) == 0) {
				*encrypted_len = 0;
				return 0;
			}
		}
	}
	//
	// 3. check no encryption
	//
	if (ctx->enc_start_pos > src_len) { // not encrypted or null
		*encrypted_len = -1; // not encrypted
		return 0;
	}
	//
	// 4. check the length of source
	//
	if (min_len > src_len) {
		if (set_err_msg_flag) {
			sprintf(ctx->err_msg,"src[%.*s] invalid decrypt source length[%d:%d], it must be >= min_len[%d]", 
				src_len < 120 ? src_len : 120, (dgt_schar*)src, src_len,*encrypted_len,min_len);
		}
		return ctx->err_code=PCI_ERR_INVALID_ENC_DATA_LEN;
	}
	dgt_uint8 ab = ctx->dynamic_start_pos_flag ? 0 : 1;
	dgt_sint32 enc_len = 0;
	dgt_sint32 output_len;
	if (ctx->enc_length) {
		dgt_uint8 enc_start_pos = ctx->enc_start_pos;
		dgt_uint32 enc_length = ctx->enc_length;
		ctx->enc_start_pos = 1;
		ctx->enc_length = 0;
		ctx->dynamic_start_pos_flag = 0;
		output_len = PCI_encryptLength(ctx,enc_length,&enc_len);
		ctx->enc_start_pos = enc_start_pos;
		ctx->enc_length = enc_length;
		if (ab == 0) ctx->dynamic_start_pos_flag = 1;
	} else {
		output_len = src_len - ctx->enc_start_pos + ab;
	}
	if (src_len >= output_len) {
		*encrypted_len = output_len;
		if (ctx->trailer_flag) *encrypted_len -= PCC_ENC_TRAILER_LENGTH;
		if (ctx->u_trailer_size) *encrypted_len -= ctx->u_trailer_size;
		if (ctx->crc32_trailer_flag) *encrypted_len -= 4;
		if (enc_len && ctx->b64_txt_enc_flag == PCI_B64_OLD && (src_len-output_len) <= 1) {
			//
			// in case of encrypting target length <= encrypting request length and old base64 encoding,
			// output_len could be incorrect by one.
			// this incorrectness can be found and adjusted by counting and comparing the number of pads.
			//
			dgt_sint32 num_pads = 0;
			dgt_schar* cp = (dgt_schar*)src + src_len - 1 - (ctx->trailer_flag ? PCC_ENC_TRAILER_LENGTH : 0);
			while (*cp == '=' && cp != (dgt_schar*)src) {
				num_pads++;
				cp--;
			}
			dgt_sint32 tmp_pads = (enc_len % 3);
			if (tmp_pads) tmp_pads = 3 - tmp_pads;
			if (tmp_pads < num_pads) *encrypted_len += 1;
			else if (tmp_pads > num_pads) *encrypted_len -= 1;
		}
	} else {
		//
		// insufficient encryption:
		// the requested length(enc_length) is bigger than the possible length(src_len - enc_start_pos + ab)
		//
		*encrypted_len = src_len - ctx->enc_start_pos + ab;
		if (ctx->trailer_flag) *encrypted_len -= PCC_ENC_TRAILER_LENGTH;
		if (ctx->u_trailer_size) *encrypted_len -= ctx->u_trailer_size;
		if (ctx->crc32_trailer_flag) *encrypted_len -= 4;
		if (*encrypted_len < 0) {
			if (set_err_msg_flag) sprintf(ctx->err_msg, "src[%.*s] not enough decrypt source length[%d]", 
								src_len < 130 ? src_len : 130, (dgt_schar*)src, src_len);
			return ctx->err_code=PCI_ERR_INVALID_ENC_DATA_LEN;
		}
	}
	//
	// 5. check trailer
	//
	if (ctx->trailer_flag) {
		dgt_uint8 trailer[3] = {0,0,0};
		dgt_uint8* b64_tailer = 0;
		if (ab) b64_tailer = src + ctx->enc_start_pos - ab + *encrypted_len;
		else b64_tailer = src + src_len - PCC_ENC_TRAILER_LENGTH;
		if (ctx->b64_txt_enc_flag >= PCI_B64_NEW) {
			DgcBase64::decode2((dgt_schar*)b64_tailer, PCC_ENC_TRAILER_LENGTH, trailer, 3);
		} else {
			DgcBase64::decode((dgt_schar*)b64_tailer, PCC_ENC_TRAILER_LENGTH, trailer, 3);
		}
		if ((ctx->remains=PCC_REMAINS(trailer)) > ctx->cipher->blockSize()) {
			if (set_err_msg_flag) {
				sprintf(ctx->err_msg, "src[%.*s][%.*s] too big remains[%d]",
					src_len < 130 ? src_len : 130,(dgt_schar*)src, 4, b64_tailer, ctx->remains);
			}
			return ctx->err_code=PCI_ERR_INVALID_TRAILER;
		}
		dgt_uint8 iv_type;
		if ((iv_type=PCC_IV_TYPE(trailer)) > PCI_IVT_PIV5) {
			if (set_err_msg_flag) {
				sprintf(ctx->err_msg, "src[%.*s][%.*s] invalid iv type[%d]",
					src_len < 130 ? src_len : 130,(dgt_schar*)src, 4, b64_tailer, iv_type);
			}
			return ctx->err_code=PCI_ERR_INVALID_TRAILER;
		}
	}
	//
	// 6. check crc32 trailer 
	//
	if (ctx->crc32_trailer_flag) {
		dgt_sint32 is_match=PCI_checkCRC32(src, src_len);
		if (is_match == 0) {
			if (set_err_msg_flag) {
                                sprintf(ctx->err_msg, "invalid crc32 trailer");
                        }
			return ctx->err_code=PCI_ERR_B64_FORMAT_ERROR;
		}
	}
	//
	// 7. check u_trailer trailer
	// 
	if (ctx->u_trailer_size && ctx->u_trailer_char) {
		dgt_sint32 i=0;
                dgt_sint32 is_match=1;
                for (i=0; i<ctx->u_trailer_size; i++) {
                	if (ctx->u_trailer_char[i] != src[src_len-ctx->u_trailer_size+i]) {
                        	is_match=0;
                        }
                }
                if (is_match == 0) {
			if (set_err_msg_flag) {
                                sprintf(ctx->err_msg, "invalid u_trailer");
                        }
			return ctx->err_code=PCI_ERR_B64_FORMAT_ERROR;
                }
	}
	return 0;
}


dgt_sint32 PCI_decrypt(
        PCI_Context*    ctx,
	dgt_uint8*      src,
	dgt_sint32      src_len,
	dgt_uint8*      dst,
	dgt_uint32*     dst_len)
{
#ifdef PCI_TEST
printf("PCI_decrypt-INPUT::\n");
PCI_printContext(ctx);
printf("	input pointer => [%p]\n",src);
printf("	input length => [%u]\n",src_len);
printf("	input => [");
if (src_len && src) for (dgt_sint32 i=0; i<src_len; i++) printf("%02x",*(src+i));
printf("]\n");
printf("	output pointer => [%p]\n",dst);
printf("	output length => [%u]\n",*dst_len);
#endif

	PCI_resetError(ctx);
	//
	// added by mwpark
	// in case of minus length null data 
	//
	if (src_len < 0) src_len=0;
	//
	// check null and return null
	//
	if (ctx && src_len == 0) {
		*dst_len = 0;
		return 0;
	}
	//
	// check other parameters
	//
	if (ctx == 0 || src == 0 || dst_len == 0 || (ctx->n2n_flag == 0 && dst == 0) ||
	    ctx->cipher_type == PCI_CIPHER_SHA || ctx->cipher_type == PCI_CIPHER_HMAC || ctx->cipher->blockSize() == 0) {
		sprintf(ctx->err_msg,"invalid parameter value:: ctx[%p] src[%p] dst[%p] dst_len[%p:%u] ctype[%d] bs[%d] start_pos[%d]",
			ctx, src, dst, dst_len, (dst_len ? *dst_len:0), ctx->cipher_type, ctx->cipher->blockSize(), ctx->enc_start_pos);
		return ctx->err_code=PCI_ERR_INVALID_PARAM_VALUE;
	}
	//
	// check the encrypted data
	//
	dgt_sint32	rtn = 0;
	dgt_sint32	encrypted_len = 0;
	if ((rtn=PCI_encryptCheck(ctx, src, src_len, &encrypted_len,1)) < 0) return rtn;
	if (encrypted_len == 0) { // case3 => src is null
		*dst_len = 0;
		return 0;
	} else if (encrypted_len == -1) { // not encrypted
		if (*dst_len < (dgt_uint32)src_len) {
			sprintf(ctx->err_msg,"src[%.*s] out buffer[%d] too short for %d bytes", 
						src_len < 130 ? src_len : 130, (dgt_schar*)src, *dst_len, src_len);
			return ctx->err_code=PCI_ERR_OUT_BUFFER_TOO_SHORT;
		}
		memset(dst, 0, src_len+1);
		memcpy(dst, src, src_len);
		*dst_len = src_len;
		return 0;
	}
        //
        // adjust the start position for partial encryption from the end
        //
        dgt_uint8 enc_start_pos = ctx->enc_start_pos;
        if (ctx->dynamic_start_pos_flag) {
		enc_start_pos = src_len - encrypted_len + 1;
		if (ctx->trailer_flag) enc_start_pos -= PCC_ENC_TRAILER_LENGTH;
		if (ctx->u_trailer_size) enc_start_pos -= ctx->u_trailer_size;
        }
	//
	// compute tail length. from here it's not null
	//
	dgt_uint8*	dst_org = dst; 
	dgt_uint8*	enc_ptr = src + enc_start_pos - 1;	// the pointer where the encrypted data starts
	dgt_uint32 	tail_len = src_len - (enc_start_pos - 1) - encrypted_len;
	if (ctx->trailer_flag) tail_len -= PCC_ENC_TRAILER_LENGTH;
	if (ctx->u_trailer_size) tail_len -= ctx->u_trailer_size;
	if (ctx->crc32_trailer_flag) tail_len -= 4;


	//
	// decode the base64 format
	//
	dgt_uint8	fixed_buf[256];
	dgt_uint8*	decoding_buf = fixed_buf;
	dgt_sint32	decode_len = 0;
	if (ctx->b64_txt_enc_flag == PCI_B64_OLD) {
		if (encrypted_len > 256) decoding_buf = new dgt_uint8[encrypted_len];
		if ((decode_len=DgcBase64::decode((dgt_schar*)enc_ptr, encrypted_len, decoding_buf, encrypted_len)) <= 0) {
			sprintf(ctx->err_msg,"src[%.*s] base64 format error[%d]src_len[%d:%d]" , src_len < 130 ? src_len : 130, (dgt_schar*)enc_ptr, decode_len,src_len,encrypted_len);
			if (decoding_buf != fixed_buf) delete decoding_buf;
			return ctx->err_code=PCI_ERR_B64_FORMAT_ERROR;
		}
		encrypted_len = decode_len;
		//
		// "src" can't be reused for encrypted binary data
		// because the contents in src might be preserved in some environments.
		// the "enc_ptr" must be deleted before returning.
		//
		enc_ptr = decoding_buf;
	} else if (ctx->b64_txt_enc_flag >= PCI_B64_NEW && ctx->b64_txt_enc_flag < PCI_B16_HEXA) {
		if (encrypted_len > 256) decoding_buf = new dgt_uint8[encrypted_len];
                if ((decode_len=DgcBase64::decode2((dgt_schar*)enc_ptr, encrypted_len, decoding_buf, encrypted_len)) <= 0) {
                        sprintf(ctx->err_msg,"src[%.*s] base64 format error[%d]src_len[%d:%d]" , src_len < 130 ? src_len : 130, (dgt_schar*)enc_ptr, decode_len,src_len,encrypted_len);
			if (decoding_buf != fixed_buf) delete decoding_buf;
                        return ctx->err_code=PCI_ERR_B64_FORMAT_ERROR;
                }
		encrypted_len = decode_len;
                enc_ptr = decoding_buf;
	} else if (ctx->b64_txt_enc_flag == PCI_B16_HEXA) {
		// hexa encoding
		if (encrypted_len > 256) decoding_buf = new dgt_uint8[encrypted_len];
                if ((decode_len=DgcBase16::decode((dgt_schar*)enc_ptr, encrypted_len, decoding_buf, encrypted_len)) <= 0) {
                        sprintf(ctx->err_msg,"src[%.*s] base16 format error[%d]src_len[%d:%d]" , src_len < 130 ? src_len : 130, (dgt_schar*)enc_ptr, decode_len,src_len,encrypted_len);
                        if (decoding_buf != fixed_buf) delete decoding_buf;
                        return ctx->err_code=PCI_ERR_B64_FORMAT_ERROR;
                }
                encrypted_len = decode_len;
                enc_ptr = decoding_buf;
	}
	//
	// set initial vector
	//
	dgt_uint8 random_iv[PCI_MAX_IV_LENGTH];
	if (ctx->iv_type && ctx->enc_mode != PCI_EMODE_ECB) {
		//
		// the last one block before the trailer is initial vector
		//
		if (ctx->iv_type == PCI_IVT_RANDOM && ctx->enc_mode != PCI_EMODE_ECB) {
			PCI_Context	iv_ctx;
			PCI_initContext(&iv_ctx, ctx->key, 128, PCI_CIPHER_AES, 0, PCI_IVT_NO, 1, 0, 1);
			//dgt_sint32	enc_iv_len = ctx->cipher->blockSize();
			dgt_sint32	enc_iv_len = iv_ctx.cipher->blockSize();
			dgt_uint8	enc_iv[PCI_MAX_IV_LENGTH];
			dgt_uint32	tmp_len = PCI_MAX_IV_LENGTH;
			iv_ctx.iv_type = PCI_IVT_NO;
			iv_ctx.b64_txt_enc_flag = 0;
			iv_ctx.enc_start_pos = 1;
			memcpy(enc_iv, enc_ptr + encrypted_len - iv_ctx.cipher->blockSize(), iv_ctx.cipher->blockSize());
			if (iv_ctx.trailer_flag) {
				// add trailer
				dgt_uint8 trailer[3];
				trailer[0] = 0;
				trailer[1] = iv_ctx.cipher->blockSize();
				trailer[2] = 0;
				DgcBase64::encode(trailer,3,(dgt_schar*)(enc_iv+enc_iv_len),PCC_ENC_TRAILER_LENGTH);
				enc_iv_len += PCC_ENC_TRAILER_LENGTH;
			}
			if ((rtn=PCI_decrypt(&iv_ctx, enc_iv, enc_iv_len, random_iv, &tmp_len)) < 0) {
				ctx->err_code=iv_ctx.err_code;
				memcpy(ctx->err_msg, iv_ctx.err_msg, PCI_ERR_MSG_LEN);
				if (decoding_buf != fixed_buf) delete decoding_buf;
				return rtn;
			}
			ctx->cipher->setIV(random_iv);
			encrypted_len -= iv_ctx.cipher->blockSize();
		} else if (ctx->iv_type <= PCI_IVT_PIV5 && ctx->enc_mode != PCI_EMODE_ECB) { // fixed iv
			ctx->cipher->setIV(PCI_PIV(ctx->iv_type));
		}
	}
	//
	// compute the length of output
	//
        dgt_uint32 output_len = enc_start_pos - 1 + encrypted_len + tail_len;
	if (*dst_len < output_len) {
		//
		// destination buffer too short
		//
		if (decoding_buf != fixed_buf) delete decoding_buf;
		sprintf(ctx->err_msg,"src[%.*s] out buffer[%d] too short for %d bytes", 
					src_len < 130 ? src_len : 130, (dgt_schar*)src, *dst_len, output_len);
		if (decoding_buf != fixed_buf) delete decoding_buf;
		return ctx->err_code=PCI_ERR_OUT_BUFFER_TOO_SHORT;
	}
	//
	// copy the unencrypted part to the destination buffer before decryption
	//
	if (enc_start_pos > 1) {
		memcpy(dst, src, (enc_start_pos - 1));
		dst += (enc_start_pos - 1);
		*dst_len -= (enc_start_pos - 1);
	}
	//
	//
	dgt_uint32 dec_len = *dst_len;
	if ((rtn=((PciBlockCipher*)ctx->cipher)->decrypt(enc_ptr, encrypted_len, dst, &dec_len)) < 0) {
		sprintf(ctx->err_msg,"decrypt failed[invalid pkcs7 padding data]");
		return ctx->err_code=rtn;
	}
	dst += dec_len;
	output_len = enc_start_pos - 1 + dec_len + tail_len;
	if (ctx->enc_mode != PCI_EMODE_CFB && ctx->enc_mode != PCI_EMODE_OFB) {
		if (ctx->remains && output_len >= ctx->cipher->blockSize()) {
//
// bug fix : 2019.08.30 by mwpark
// case of null to null off
// miscalculate output_len
//
			if (output_len % ctx->cipher->blockSize() == 0) {
				output_len -= ctx->cipher->blockSize();
				output_len += ctx->remains;
			} else {
//
//  bug fix : 2022.07.22  by dhkim
//  add a condition that runs 
//	unconditionally if it is an A condition old-base64(ctx->b64_txt_enc_flag <= 1)
//
				if(ctx->b64_txt_enc_flag <= 1) {
					output_len -= ctx->cipher->blockSize();
					output_len += ctx->remains;
				}
			}
		}
	}
	*dst_len = output_len;

	//
	// add tail to decrypted data at the end
	//
	if (tail_len) memcpy((dst_org + output_len - tail_len), (src + src_len - tail_len), tail_len);
	if (decoding_buf != fixed_buf) delete decoding_buf;

#ifdef PCI_TEST
printf("PCI_decrypt-OUTPUT::\n");
printf("	output length => [%u]\n",*dst_len);
printf("	output => [");
if (*dst_len && dst_org) for (dgt_uint32 i=0; i<*dst_len; i++) printf("%02x",*(dst_org+i));
printf("]\n");
#endif
	return 0;
}


dgt_uint32 PCI_ophuekLength(
	dgt_sint32	src_len,
	dgt_uint8	src_type,
	dgt_sint32	b64_flag)
{
	dgt_sint32	rtn = src_len + (src_len/8);
	if ((src_len%8) != 0) rtn++;
	if (src_type == PCI_SRC_TYPE_NUM) rtn = PCI_OPHUEK_MIN_NUM_HASH;
	if (b64_flag) return DgcBase64::encodeLength(rtn,1);
	return rtn;
}


#include "PciShaCipher.h"

dgt_sint32 PCI_OPHUEK(
        PCI_Context*            ctx,
        dgt_uint8*              src,	 // encrypted data
        dgt_sint32              src_len, // encrypted data length
        dgt_uint8*              dst,
        dgt_uint32*             dst_len,
	dgt_sint64		enc_col_id,
        dgt_uint8               src_type,
	dgt_sint32		src_enc_flag,
	dgt_sint32		b64_flag)
{
#ifdef PCI_TEST
printf("PCI_OPHUEK-INPUT::\n");
PCI_printContext(ctx);
printf("	input pointer => [%p]\n",src);
printf("	input length => [%u]\n",src_len);
printf("	input => [");
if (src_len && src) for (dgt_sint32 i=0; i<src_len; i++) printf("%02x",*(src+i));
printf("]\n");
printf("	output pointer => [%p]\n",dst);
printf("	output length => [%u]\n",*dst_len);
#endif

	dgt_uint8*	od = new dgt_uint8[(*dst_len+3)*2]; // allocate enough space for base64 encoded hash
	dgt_uint32	od_len = src_len; // orignal data length
	dgt_sint32	rtn = 0;
	if (src_enc_flag) {
		//
		// decrypt first
		//
		if ((rtn=PCI_decrypt(ctx, src, src_len, od, &od_len)) < 0) {
			delete od;
			return rtn;
		}
		*dst_len=od_len+1;
		src_len=od_len;
	} else {
		memcpy(od, src, src_len);
	}
	if (*dst_len < od_len+PCI_OPHUEK_MAX_ROUND) {
		delete od;
		sprintf(ctx->err_msg,"out buffer[%d] too short for src[%d] bytes", *dst_len, od_len+PCI_OPHUEK_MAX_ROUND);
		return ctx->err_code=PCI_ERR_OUT_BUFFER_TOO_SHORT;
	}
	memset(dst, 0, *dst_len);

#ifdef PCI_TEST
printf("PCI_OPHUEK-INPUT::\n");
printf("	od pointer => [%p]\n",od);
printf("	od length => [%u]\n",od_len);
printf("	od => [");
for (dgt_sint32 i=0; i<od_len; i++) printf("%02x",*(od+i));
printf("]\n");
#endif

	//
	// assign the decrypted original data to destination buffer from right to left
	//
	dgt_uint8	sign_byte=0;	// sign byte holder in case of number being modified by sign
	dgt_uint32	idx=0;		// the number of bytes being involved in making OPHUEK
	dgt_uint32	fcount=0;	// the offset of decimal pointer from left
	dgt_uint8	cbyte;		// from right to left
	dgt_uint32	non_zero_sum=0;
	if (src_type == PCI_SRC_TYPE_NUM) {
		dgt_uint8*	cp=od;
		//
		// cut off leading & tailing zero
		//
		for(;*cp == 48 || *cp == 43;) { cp++; od_len--; } // cut off leading zero, plus sign
		//
		// convert decimal char into hex number from right to left
		//
		for(dgt_uint32 i=1; i <= od_len; i++) {
			cbyte = *(cp + od_len - i);
			if (cbyte >= 48 && cbyte <= 57) { // number character
				cbyte -= 48;
				non_zero_sum += cbyte;
				if (idx%2) *(dst + *dst_len - idx/2 - 1) += cbyte << 4;
				else *(dst + *dst_len - idx/2 - 1) = cbyte;
			} else if (cbyte == 46) { // decimal point
				fcount = idx/2;
				if (idx%2 == 0) continue;
				else {
					fcount++;
					for(dgt_sint32 k=fcount; k > 0; k--) {
						dgt_uint8*	cp = dst + *dst_len - k;
						*cp = *cp<<4;
						if (k > 1) *cp += *(cp+1)>>4;
					}
				}
			} else if (cbyte == 45) { // sign '-'
				if (non_zero_sum > 0) sign_byte = cbyte; // for guaranteeing the same hash value for -0.0, -0, -0000.00 etc.
				break;
			}
			idx++;
		}
		//
		// move left so as to position decimal pointer at the center, 19
		//
		if (non_zero_sum == 0) {
			od_len=19;
		} else {
			dgt_uint32	move_left_chars = 19 - fcount;
			for(dgt_uint32 i=1; i < *dst_len; i++) {
				if ((i + move_left_chars) < *dst_len) *(dst + i) = *(dst + i +  move_left_chars);
				else *(dst + i) = 0;
			}
			od_len = idx/2 + 1 + move_left_chars;
			if (idx%2 == 0) od_len--;
		}
	} else {
		memcpy(dst + PCI_OPHUEK_MAX_ROUND, od, od_len);
		od_len = *dst_len - PCI_OPHUEK_MAX_ROUND;
	}

#if 0
printf("idx[%d] fcount[%d] sign[%d] od_len[%d] *dst_len[%d] dst[", idx, fcount, sign_byte, od_len, *dst_len);
for(dgt_uint32 i=0; i<*dst_len; i++) printf("%02x",*(dst+i));
printf("]\n");
#endif

	//
	// obtain the first hash
	//
	if (ctx->oph_key_flag == 0) {
                dgt_uint8       hash_src[128];
                memset(hash_src,0,128);
                memset(ctx->next_hash,0,64);
                PCI_Context     key_hash_ctx;   // context for SHA hashing
                if ((rtn=PCI_initContext(&key_hash_ctx, ctx->key, 256, PCI_CIPHER_SHA, 0, PCI_IVT_PIV1, 0, 0, 1)) < 0) {
                        delete od;
                        return rtn;
                }
                dgt_uint32      hash_len=32;
                memcpy(hash_src, ctx->key, ctx->key_size/8);
                memcpy(hash_src + (ctx->key_size/8), &enc_col_id, sizeof(enc_col_id));
                if ((rtn=PCI_encrypt(&key_hash_ctx, hash_src, (ctx->key_size/8), ctx->next_hash, &hash_len)) < 0) {
                        delete od;
                        return rtn;
                }
                ctx->oph_key_flag = 1;
        }
	
	//
	// build OPHUEK by applying key driven hash to original data while preserving its order by PCI_OPHUEK_MAX_HASH times
	//
	//
	// for supportion variable length ophuek data
	//
	dgt_uint32	allo_size = src_len + (src_len/8); 
	if ((src_len%8) != 0) allo_size++;
	dgt_uint8*	allo_buf=new dgt_uint8[allo_size];
	memset(allo_buf, 0, allo_size);

	dgt_uint16	hash_byte=0;	// temporary hash result holder
	dgt_uint8	carry=0;	// carry
	for(dgt_uint16 k=0; k<PCI_OPHUEK_MAX_ROUND; k++) {
		dgt_uint8	round_flag=0;
		for(dgt_uint16 i=0; i<PCI_OPHUEK_MAX_HASH; i++) {
			//
			// obtain next hash based on the previous hash
			//
#if 0 // for performance
			if ((rtn=PCI_encrypt(&key_hash_ctx, prev_hash, 32, next_hash, &hash_len)) < 0) {
				delete od;
				return rtn;
			}
#endif
			for(idx=1; idx <= od_len; idx++) {
				cbyte = *(dst + idx);
				if ((hash_byte = cbyte + *(ctx->next_hash+(idx % 8))) > 255) {
					cbyte = hash_byte % 256;
					carry = 1;
				} else {
					cbyte = (dgt_uint8)hash_byte;
					carry = 0;
				}
				// 
				// carry position
				//
				dgt_sint32 cpos=idx % 8;
				//
				// variable length ophuek buffer postion
				//
				dgt_sint32 bufpos=idx  + ((idx) / 8) -1;

				if (cpos == 7) {
                                        allo_buf[bufpos] += (cbyte >> cpos);
                                        allo_buf[bufpos+1] += (cbyte << (8-cpos));
				} else if (cpos == 0) {
					allo_buf[bufpos-1] += (carry >> 7);
                                        allo_buf[bufpos] += cbyte;
				} else {
					allo_buf[bufpos] += (carry << (8-cpos));
                                        allo_buf[bufpos] += (cbyte >> cpos);
                                        allo_buf[bufpos+1] += (cbyte << (8-cpos));
				}
			}
#if 0
			if (carry) {
				//
				// there's a last carry
				//
				//*(dst + *dst_len - idx++) += carry;
				dgt_sint32 bufpos=allo_size - idx - (idx / 8);
				allo_buf[buffpos] += carry;
				round_flag = 1;
			}
#endif


#if 0
			memcpy(prev_hash, next_hash, 32);
#endif
		}
		if (round_flag) od_len++;
	}

#if 0
printf("idx[%d] fcount[%d] sign[%d] od_len[%d] dst[", idx, fcount, sign_byte, od_len);
for(dgt_uint32 i=0; i<*dst_len; i++) printf("%02x",*(dst+i));
printf("]\n");
#endif

	if (src_type == PCI_SRC_TYPE_NUM) {
		if (sign_byte == 45) for(dgt_uint32 i=1; i <= od_len; i++) *(dst + *dst_len - i) = 255 - *(dst + *dst_len - i);
		else *dst |= 0x80;
	}

#ifdef PCI_TEST
printf("PCI_OPHUEK-OUTPUT::\n");
printf("	output length => [%u]\n",*dst_len);
printf("	output => [");
for (dgt_uint32 i=0; i<*dst_len; i++) printf("%02x",*(dst+i));
printf("][%d]\n",*dst_len);
#endif

	if (b64_flag) {
		//dgt_sint32	enc_len = DgcBase64::encode(dst, *dst_len, (dgt_schar*)od, (*dst_len+3)*2, 1);
		dgt_sint32	enc_len = DgcBase64::encode(allo_buf, allo_size, (dgt_schar*)od, (*dst_len+3)*2, 1);
		if (enc_len < 0) {
			delete od;
			delete allo_buf;
			sprintf(ctx->err_msg,"out buffer[%d] too short for src[%d] bytes", *dst_len, od_len+PCI_OPHUEK_MAX_ROUND);
			return ctx->err_code=PCI_ERR_OUT_BUFFER_TOO_SHORT;
		}
		memcpy(dst, od, enc_len);
		*dst_len = enc_len;
	}
	delete od;
	delete allo_buf;
	return 0;
}

dgt_sint32 PCI_Coupon(
        PCI_Context*    ctx,
	dgt_uint8*      src,
	dgt_sint32      src_len,
	dgt_uint8*      dst,
	dgt_uint32*     dst_len)
{
#ifdef PCI_TEST
printf("PCI_encrypt-INPUT::\n");
PCI_printContext(ctx);
printf("	input pointer => [%p]\n",src);
printf("	input length => [%u]\n",src_len);
printf("	input => [");
if (src_len && src) for (dgt_sint32 i=0; i<src_len; i++) printf("%02x",*(src+i));
printf("]\n");
printf("	output pointer => [%p]\n",dst);
printf("	output length => [%u]\n",*dst_len);
#endif

	PCI_resetError(ctx);
	//
	// if src is null return null (because not possible to issue null coupon)
	//
	if (src_len == 0) {
		*dst_len = 0;
		return 0;
	}
	//
	// check output buffer correctness
	//
	if (ctx == 0 || dst_len == 0 || (ctx->n2n_flag == 0 && dst == 0) || ctx->enc_start_pos == 0) {
		sprintf(ctx->err_msg,"invalid parameter value:: ctx[%p] src[%p] src_len[%d] dst[%p] dst_len[%p:%u] start_pos[%d]",
			ctx, src, src_len, dst, dst_len, (dst_len ? *dst_len:0), ctx->enc_start_pos);
	}
	dgt_sint32	enc_len = 0; // the amount to be encrypted
	if (src_len == 0) {
        	enc_len = 0;
	} else {
        	enc_len = ctx->enc_length; // the amount to be encrypted
		if (enc_len == 0 || enc_len > (src_len - ctx->enc_start_pos + 1)) {
			//
			// case2 => whole back part encryption
			//
			// enc_len could not be the same as "ctx->enc_length" even if the latter is greater than zero
			// because it couldn't goes over the end of "target source".
			//
			enc_len = src_len - ctx->enc_start_pos + 1; // the maximum length being able to be encrypted from "enc_start_pos".
		}
	}

	dgt_uint32	output_len = src_len;
	if (output_len == 0) {
		//
		// case0 => null to null
		//
		*dst_len = 0;
		return 0;
	}
	//
	// check output buffer length
	//
	if (*dst_len < output_len) { // destination buffer too short
		sprintf(ctx->err_msg,"out buffer[%d] too short for %d bytes\n src_len [%d]", *dst_len, output_len, src_len);
		return ctx->err_code=PCI_ERR_OUT_BUFFER_TOO_SHORT;
	}
	//
	// when source length less than encrypt start position,
	// return source data without encryption in case of not-null.
	//
	if (src_len && ctx->enc_start_pos > src_len) {
		//
		// case1 => no encryption
		//
		memcpy(dst, src, src_len);
		*dst_len = src_len;
		return 0;
	}
	//
	// copy the src to dst
	//
        if (src_len && ctx->enc_start_pos > 1) {
                memcpy(dst, src, src_len);
                dst += (ctx->enc_start_pos - 1);
                *dst_len -= (ctx->enc_start_pos - 1);
        }
	//
	// issue coupon begins.
	//
        //dgt_time        ct=dgtime(&ct);
	dgt_schar	rand_seed[256];
	memset(rand_seed,0,256);
        //sprintf((dgt_schar*)rand_seed,"%s%d", ctx->key, ct);
        sprintf((dgt_schar*)rand_seed,"%s", ctx->key);
        RAND_seed((dgt_schar*)rand_seed, strlen((dgt_schar*)rand_seed));
        dgt_uint8       rand_bytes[1024+1];
	memset(rand_bytes,0,1024+1);
        RAND_bytes(rand_bytes, enc_len);
	dgt_uint32 	tmp_len = DgcBase64::encodeLength(enc_len);
	dgt_schar	tmp_bytes[1024+1];
	memset(tmp_bytes,0,1024+1);
	DgcBase64::encode(rand_bytes, enc_len, tmp_bytes, tmp_len);
	memcpy(dst,tmp_bytes,enc_len);
	*dst_len=src_len;
	return 0;
}

dgt_sint32 PCI_getErrCode(PCI_Context* ctx)
{
	return ctx->err_code;
}


dgt_schar* PCI_getErrMsg(PCI_Context* ctx)
{
	return ctx->err_msg;
}
