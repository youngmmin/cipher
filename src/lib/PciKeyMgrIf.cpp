/*******************************************************************
 *   File Type          :       interface class implementation
 *   Classes            :       DgcKeyMgrIf
 *   Implementor        :       Jaehun
 *   Create Date        :       2011. 10. 11
 *   Description        :       Key Managing Module interface
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#include "PciKeyMgrIf.h"
#include "PciCryptoIf.h"
#ifndef WIN32 
#include "DgcPwChecker.h"
#endif


static const dgt_sint32 PCC_MASTER_KEY_LENGTH   = 32;
static const dgt_sint32 PCC_MASTER_HASH_SIZE    = 256;


static dgt_schar	PCI_KmgrErrMsg[PCI_ERR_MSG_LEN*2];


class PciKeyHolder {
 private:
	dgt_uint8	Ekmk[PCC_MASTER_KEY_LENGTH];
	dgt_uint8	Mk[PCC_MASTER_KEY_LENGTH];
	dgt_uint8	Eks[PCC_MAX_KEY_SET_LENGTH];
 public:
	PciKeyHolder() {};
	~PciKeyHolder() {};
	inline dgt_uint8* eKMK() { return Ekmk; };
	inline dgt_uint8* mK() { return Mk; };
	inline dgt_uint8* eKS() { return Eks; };
};


class PciKeyStash {
 private:
	PCT_KEY_STASH*	KeyStash;
	dgt_uint8	EncKey[PCC_MASTER_KEY_LENGTH+1];
	PCI_Context	EncContext;
	PCI_Context	HashContext;
 public:
	PciKeyStash(PCT_KEY_STASH* key_stash) {
		KeyStash=key_stash;
		dgt_schar	key_seed[PCC_MASTER_KEY_LENGTH+1]=
		{ 23, 84,239, 42,  3, 59,  5,232, 50, 89,
		  34,202, 95,  7, 93,123, 98,  7,122,  9,
		  23,173,  4,  6, 99, 82,  7, 69, 38,204,
		 101, 82, 76};
		memcpy(EncKey, key_seed, PCC_MASTER_KEY_LENGTH+1);
		for(dgt_sint32 i=0; i<PCC_MASTER_KEY_LENGTH; i++) if (i%2) EncKey[i] |= EncKey[i+1]; else EncKey[i] &= EncKey[i+1];
		PCI_initContext(&EncContext, EncKey, PCC_MASTER_HASH_SIZE, PCI_CIPHER_AES, PCI_EMODE_CBC, PCI_IVT_PIV1, 0, 0, 1);
		PCI_initContext(&HashContext, 0, PCC_MASTER_HASH_SIZE, PCI_CIPHER_SHA, 0, PCI_IVT_PIV1, 0, 0, 1);
	};
	~PciKeyStash() {};

	inline PCT_KEY_STASH* keyStash() { return KeyStash; };

	inline dgt_sint32 openKeySet(dgt_uint8* eks)
	{
		if (eks == 0) {
			sprintf(PCI_KmgrErrMsg, "openKeySet failed due to null EKS");
			return PCC_ERR_KMGR_INVALID_INPUT_PARAM;
		}
		if (KeyStash->open_status) {
			sprintf(PCI_KmgrErrMsg,"openKeySet failed because the key set already opened");
			return PCC_ERR_KMGR_KEY_OPENED;
		}
		//
		// encrypt EKS and save it into the key stash
		//
		dgt_sint32	rtn=0;
		dgt_uint32	tmp_len=PCC_MAX_EKEY_SET_LENGTH;
        	if ((rtn=PCI_encrypt(&EncContext, eks, PCC_MAX_KEY_SET_LENGTH, KeyStash->key_set, &tmp_len)) < 0) {
			sprintf(PCI_KmgrErrMsg,"openKeySet failed due to %s",PCI_getErrMsg(&EncContext));
			return rtn;
		}
		//
		// save the signature of the EKS for integrity checking
		//
		tmp_len=PCC_KEY_SET_SIG_LENGTH;
        	if ((rtn=PCI_encrypt(&HashContext, eks, PCC_MAX_KEY_SET_LENGTH, KeyStash->key_set_signature, &tmp_len)) < 0) {
			sprintf(PCI_KmgrErrMsg,"openKeySet failed due to %s",PCI_getErrMsg(&HashContext));
			return rtn;
		}
		KeyStash->open_status = 1;
		return 0;
	};

	inline dgt_sint32 getKey(dgt_uint32 key_idx,dgt_uint32 key_len,dgt_uint8* key_buffer)
	{
		if (KeyStash->open_status == 0) {
			sprintf(PCI_KmgrErrMsg,"getKey failed because the key set not opened");
			return PCC_ERR_KMGR_KEY_NOT_OPEN;
		}
		if (key_buffer == 0) {
			sprintf(PCI_KmgrErrMsg, "getKey failed due to invalid input parameter");
			return PCC_ERR_KMGR_INVALID_INPUT_PARAM;
		}
		if ((key_idx + key_len) >  (dgt_uint32)PCC_MAX_KEY_SET_LENGTH) {
			sprintf(PCI_KmgrErrMsg,"getKey failed due to the requested key[%d] out of the range[%d]",
				key_idx+key_len,PCC_MAX_KEY_SET_LENGTH);
			return PCC_ERR_KMGR_KEY_OVERFLOW;
		}
		//
		// decrypt EKS
		//
		dgt_sint32	rtn=0;
		dgt_uint8	eks_buf[PCC_MAX_KEY_SET_LENGTH];
		dgt_uint32	tmp_len=PCC_MAX_KEY_SET_LENGTH;
        	if ((rtn=PCI_decrypt(&EncContext, KeyStash->key_set, PCC_MAX_EKEY_SET_LENGTH, eks_buf, &tmp_len)) < 0) {
			sprintf(PCI_KmgrErrMsg,"getKey failed due to %s", PCI_getErrMsg(&EncContext));
			return rtn;
		}
		//
		// check the integrity of EKS
		//
		dgt_uint8	eks_sign_buf[PCC_KEY_SET_SIG_LENGTH];
		tmp_len=PCC_KEY_SET_SIG_LENGTH;
        	if ((rtn=PCI_encrypt(&HashContext, eks_buf, PCC_MAX_KEY_SET_LENGTH, eks_sign_buf, &tmp_len)) < 0) {
			sprintf(PCI_KmgrErrMsg,"getKey failed due to %s",PCI_getErrMsg(&HashContext));
			return rtn;
		}
		if (memcmp(eks_sign_buf, KeyStash->key_set_signature, PCC_KEY_SET_SIG_LENGTH)) {
			sprintf(PCI_KmgrErrMsg, "getKey failed due to corrupted key stash[%s][%s]",eks_sign_buf,KeyStash->key_set_signature);
			return PCC_ERR_KMGR_CORRUPTED_KEY_STASH;
		}
		memcpy(key_buffer, eks_buf + key_idx, key_len);
		return 0;
	};

	inline dgt_void closeKeySet() { KeyStash->open_status = 0; };

	inline dgt_uint32 dump(dgt_uint8* dbuf)
	{
		memcpy(dbuf,KeyStash,sizeof(PCT_KEY_STASH));
		memcpy(dbuf+sizeof(PCT_KEY_STASH),&EncKey,sizeof(EncKey));
		return sizeof(PCT_KEY_STASH) + sizeof(EncKey);
	};
};


static PciKeyStash*	PCI_KeyStash=0;

//
// PBKDF2(Password Based Key Derivation Function)
// NIST Special Publication 800-132 PBKDB2 implementation
//
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
static const dgt_uint32	PCI_PBKDF2_HASH_SIZE=32;
static const dgt_uint32	PCI_PBKDF2_ITERATION=3000;

dgt_sint32 PCI_PBKDF2(
	const dgt_schar* pw,
	const dgt_uint8* salt,
	dgt_uint32 salt_len,
	dgt_uint8* mk,
	dgt_uint32* mk_len)
{
#ifdef PCI_TEST
printf("PCI_PBKDF2-INPUT::\n");
printf("        pw pointer => [%p]\n",pw);
printf("        password   => [%s]\n",pw);
printf("        salt pointer => [%p]\n",salt);
printf("        salt_len => [%u]\n",salt_len);
if (salt && salt_len) {
	printf("        salt => [");
	for(dgt_uint32 i=0; i<salt_len; i++) printf("%02x",*(salt+i));
	printf("]\n");
}
printf("        mk pointer => [%p]\n",mk);
printf("        mk_len pointer => [%p]\n",mk_len);
printf("        mk_len => [%u]\n",*mk_len);
#endif

	dgt_uint32	pw_len=0;
	if (pw  == 0 || (pw_len=strlen(pw)) == 0 || salt == 0 || salt_len == 0 || mk == 0 || mk_len == 0 || *mk_len == 0) {
		sprintf(PCI_KmgrErrMsg, "PCI_PBKDF2 failed due to invalid input parameter[%p:%u:%p:%u:%p:%p:%u",pw,pw_len,salt,salt_len,mk,mk_len,*mk_len);
		return PCC_ERR_KMGR_INVALID_INPUT_PARAM;
	}
	dgt_uint32	n_hash=(dgt_uint32)ceil(*mk_len/(PCI_PBKDF2_HASH_SIZE*1.0));	// the number of hash result for mk
	dgt_uint8	tmp_hash[PCI_PBKDF2_HASH_SIZE]={0,};	// temporary hash value
	dgt_uint32	tmp_len=PCI_PBKDF2_HASH_SIZE;	// the length of temporary hash value
	HMAC_CTX	ctx;	// HMAC context
	//
	// make the first salt
	//
	if (salt_len < PCI_PBKDF2_HASH_SIZE-sizeof(dgt_uint32)) memcpy(tmp_hash, salt, salt_len);
	else memcpy(tmp_hash, salt, PCI_PBKDF2_HASH_SIZE-sizeof(dgt_uint32));
	//
	// initialize HMAC context
	//
	HMAC_Init(&ctx, pw, pw_len, EVP_sha256());
	for(dgt_uint32 i=0; i<n_hash; i++) {	// for the number of hashes
		dgt_uint32	c_pos=PCI_PBKDF2_HASH_SIZE*i;
		if (i == n_hash-1) memset(mk+c_pos, 0, *mk_len%PCI_PBKDF2_HASH_SIZE);
		else memset(mk+c_pos, 0, PCI_PBKDF2_HASH_SIZE);
		memcpy(tmp_hash+PCI_PBKDF2_HASH_SIZE-sizeof(dgt_uint32), &i, sizeof(dgt_uint32)); // strength the salt with index value
		for(dgt_uint32 j=1; j<=PCI_PBKDF2_ITERATION; j++) {	// for the defined iteration count
			//
			// calculate a HMAC with passwod & the i-th salt
			//
			HMAC_Update(&ctx, tmp_hash, PCI_PBKDF2_HASH_SIZE);
		}
		HMAC_Final(&ctx, tmp_hash, &tmp_len);
		//
		// build the i-th part of master key with the HMAC
		//
		for(dgt_uint8 k=0; k<PCI_PBKDF2_HASH_SIZE; k++) {
			if ((c_pos+k) < *mk_len) *(mk+c_pos+k) ^= *(tmp_hash+k);
			else break;
		}
		HMAC_cleanup(&ctx);
		HMAC_Init(&ctx, tmp_hash, PCI_PBKDF2_HASH_SIZE, EVP_sha256());
	}
	HMAC_cleanup(&ctx);

#ifdef PCI_TEST
printf("PCI_PBKDF2-OUTPUT::\n");
printf("        mk_len => [%u]\n",*mk_len);
printf("        mk => [");
for(dgt_uint32 i=0; i<*mk_len; i++) printf("%02x",*(mk+i));
printf("]\n");
#endif

	return 0;
}


//
// generate EKMK - Encryption Key for Master Key
//

static dgt_sint32 PCI_generateEKMK(
	const dgt_schar* pw,
	dgt_uint8* ekmk_buf,
	dgt_uint32* ekmk_buf_len,
	dgt_sint32  hsm_mode=0,
	const dgt_schar* hsm_password=0)
{
	if (pw == 0) {
		sprintf(PCI_KmgrErrMsg, "PCI_generateEKMK failed due to invalid input parameter");
		return PCC_ERR_KMGR_INVALID_INPUT_PARAM;
	}
	if (hsm_mode) {
		sprintf(PCI_KmgrErrMsg, "As of June 27, 2023, we no longer support HSM.\n");
		return PCC_ERR_NOT_SUPPORT_HSM;
	} else {
		dgt_sint32	rtn=0;
		PCI_Context	ctx;
		if ((rtn=PCI_initContext(&ctx, 0, PCC_MASTER_HASH_SIZE, PCI_CIPHER_SHA, 0, PCI_IVT_PIV1, 0, 0, 1)) < 0) {
			sprintf(PCI_KmgrErrMsg,"PCI_generateEKMK failed due to %s", PCI_getErrMsg(&ctx));
			return rtn;	// 32 bytes key
		}
		if ((rtn=PCI_encrypt(&ctx, (dgt_uint8*)pw, strlen(pw), ekmk_buf, ekmk_buf_len)) < 0) {
			sprintf(PCI_KmgrErrMsg,"PCI_generateEKMK failed due to %s", PCI_getErrMsg(&ctx));
			return rtn;
		}
	}
	return 0;
}


//
// check key
//
static dgt_sint32 PCI_checkKey(
	const dgt_schar* pw,
	dgt_schar* smk,
	dgt_uint32 smk_len,
	dgt_schar* seks,
	dgt_uint32 seks_len,
	dgt_schar* sks,
	dgt_uint32 sks_len,
	PciKeyHolder& key_holder,
	dgt_sint32 hsm_mode=0,
	const dgt_schar* hsm_password=0)
{
	//
	// check input parameters
	//
	if (pw == 0 || smk == 0 || smk_len == 0 || seks == 0 || seks_len == 0 || sks == 0 || sks_len == 0) {
		sprintf(PCI_KmgrErrMsg, "PCI_checkKey failed due to invalid input parameter");
		return PCC_ERR_KMGR_INVALID_INPUT_PARAM;
	}
	//
	// generate EKMK - Encryption Key for Master Key
	//
	dgt_sint32	rtn=0;
	dgt_uint32	dst_len=PCC_MASTER_KEY_LENGTH;
	dgt_uint8*	EKMK=key_holder.eKMK();
	dgt_uint8*	MK=key_holder.mK();
	dgt_uint8*	EKS=key_holder.eKS();
	if ((rtn=PCI_generateEKMK(pw, EKMK, &dst_len, hsm_mode, hsm_password)) < 0) return rtn;

	//
	// decrypt master key
	//
	dgt_uint8	tmp_sks[128];
	dgt_uint32	tmp_len=128;
	PCI_Context	ctx;

	if (hsm_mode) {
		sprintf(PCI_KmgrErrMsg, "As of June 27, 2023, we no longer support HSM.\n");
		return PCC_ERR_NOT_SUPPORT_HSM;
	} else {
		if ((rtn=PCI_initContext(&ctx, EKMK, PCC_MASTER_HASH_SIZE, PCI_CIPHER_AES, PCI_EMODE_CBC, PCI_IVT_PIV1, 0, 1, 1)) < 0) goto PCI_ERR_RETURN1;
		dst_len=PCC_MASTER_KEY_LENGTH;
		if ((rtn=PCI_decrypt(&ctx, (dgt_uint8*)smk, smk_len, MK, &dst_len)) < 0) goto PCI_ERR_RETURN1;
	}

	//
	// decrypt encryption key set
	//
	if ((rtn=PCI_initContext(&ctx, MK, PCC_MASTER_HASH_SIZE, PCI_CIPHER_AES, PCI_EMODE_CBC, PCI_IVT_PIV1, 0, 1, 1)) < 0) goto PCI_ERR_RETURN1;
	dst_len=PCC_MAX_KEY_SET_LENGTH;
        if ((rtn=PCI_decrypt(&ctx, (dgt_uint8*)seks, seks_len, (dgt_uint8*)EKS, &dst_len)) < 0) goto PCI_ERR_RETURN1;

	//
	// generate SKS - Saved Key Signature and check old password
	//
	if ((rtn=PCI_initContext(&ctx, 0, PCC_MASTER_HASH_SIZE, PCI_CIPHER_SHA, 0, PCI_IVT_PIV1, 0, 1, 1)) < 0) goto PCI_ERR_RETURN1;
        if ((rtn=PCI_encrypt(&ctx, (dgt_uint8*)EKS, PCC_MAX_KEY_SET_LENGTH, tmp_sks, &tmp_len)) < 0) goto PCI_ERR_RETURN1;
	if (tmp_len != sks_len || memcmp(sks, tmp_sks, sks_len)) {
		sprintf(PCI_KmgrErrMsg, "PCI_checkKey failed due to wrong password");
		return PCC_ERR_KMGR_WRONG_PASSWORD;
	}

PCI_ERR_RETURN1:
	if (rtn) sprintf(PCI_KmgrErrMsg,"PCI_checkKey failed due to %s", PCI_getErrMsg(&ctx));
	return rtn;
}


#include <openssl/evp.h>
#include <openssl/rand.h>


#ifndef WIN32
dgt_sint32 PCI_createKey(
	const dgt_schar* pw,
	dgt_void* thread_ptr,
	dgt_schar* smk,
	dgt_uint32* smk_len,
	dgt_schar* seks,
	dgt_uint32* seks_len,
	dgt_schar* sks,
	dgt_uint32* sks_len,
	dgt_sint32  hsm_mode,
	const dgt_schar* hsm_password)
{
#ifdef PCI_TEST
printf("PCI_createKey-INPUT::\n");
printf("        pw pointer => [%p]\n",pw);
printf("        password   => [%s]\n",pw);
printf("        thread pointer => [%p]\n",thread_ptr);
printf("        smk pointer => [%p]\n",smk);
printf("        smk_len pointer => [%p]\n",smk_len);
printf("        smk_len => [%u]\n",*smk_len);
printf("        seks pointer => [%p]\n",seks);
printf("        seks_len pointer => [%p]\n",smk_len);
printf("        seks_len => [%u]\n",*seks_len);
printf("        sks pointer => [%p]\n",sks);
printf("        sks_len pointer => [%p]\n",sks_len);
printf("        sks_len => [%u]\n",*sks_len);
#endif

	//
	// check input parameters
	//
	if (pw == 0 ||
	    smk == 0 || smk_len == 0 || *smk_len == 0 ||
	    seks == 0 || seks_len == 0 || *seks_len == 0 ||
	    sks == 0 || sks_len == 0 || *sks_len == 0) {
		sprintf(PCI_KmgrErrMsg, "PCI_createKey failed due to invalid input parameter");
		return PCC_ERR_KMGR_INVALID_INPUT_PARAM;
	}

	//
	// check password strength
	//
	dgt_sint32	rtn=0;
	if ((rtn=DgcPwChecker::checkStrength(pw,strlen(pw))) < 0) {
		sprintf(PCI_KmgrErrMsg,"PCI_createKey failed due to %s", EXCEPT->getErr()->message());
		delete EXCEPTnC;
		return  PCC_ERR_KMGR_WEAK_PASSWORD; 
        }
	PciKeyHolder	key_holder;
	dgt_uint8*	EKMK=key_holder.eKMK();
	dgt_uint8*	MK=key_holder.mK();
	dgt_uint8*	EKS=key_holder.eKS();
	//
	// generate EKMK - Encryption Key for Master Key
	//
	dgt_uint32	dst_len=PCC_MASTER_KEY_LENGTH;
	if ((rtn=PCI_generateEKMK(pw, EKMK, &dst_len, hsm_mode, hsm_password))) return rtn;

	//
	// generate MK- Master Key
	//
	PCI_Context	ctx;
	dgt_time	ct=dgtime(&ct);
	sprintf((dgt_schar*)EKS,"%s%d%p", pw, ct, thread_ptr);
	RAND_seed((dgt_schar*)EKS, strlen((dgt_schar*)EKS));
	dgt_uint8	rand_bytes[EVP_MAX_KEY_LENGTH+1];
	RAND_bytes(rand_bytes, EVP_MAX_KEY_LENGTH);
	dst_len = PCC_MASTER_KEY_LENGTH;
	if ((rtn=PCI_PBKDF2(pw, rand_bytes, EVP_MAX_KEY_LENGTH, MK, &dst_len))) return rtn;

	//
	// generate EKS - Encryption Key Set
	//
	RAND_bytes(rand_bytes, EVP_MAX_KEY_LENGTH);
	dst_len = PCC_MAX_KEY_SET_LENGTH;
	if ((rtn=PCI_PBKDF2(pw, rand_bytes, EVP_MAX_KEY_LENGTH, EKS, &dst_len))) return rtn;
	//
	// generate SKS - Saved Key Signature
	//
	if ((rtn=PCI_initContext(&ctx, 0, PCC_MASTER_HASH_SIZE, PCI_CIPHER_SHA, 0, PCI_IVT_PIV1, 0, 1, 1)) < 0) goto PCI_ERR_RETURN2;
        if ((rtn=PCI_encrypt(&ctx, EKS, PCC_MAX_KEY_SET_LENGTH, (dgt_uint8*)sks, sks_len)) < 0) goto PCI_ERR_RETURN2;
	//
	// generate SEKS - Saved Encryption Key Set
	//
	if ((rtn=PCI_initContext(&ctx, MK, PCC_MASTER_HASH_SIZE, PCI_CIPHER_AES, PCI_EMODE_CBC, PCI_IVT_PIV1, 0, 1, 1)) < 0) goto PCI_ERR_RETURN2;
        if ((rtn=PCI_encrypt(&ctx, EKS, PCC_MAX_KEY_SET_LENGTH, (dgt_uint8*)seks, seks_len)) < 0) goto PCI_ERR_RETURN2;
	//
	// generate SMK - Saved Master Key
	//
	if (hsm_mode) {
		sprintf(PCI_KmgrErrMsg, "As of June 27, 2023, we no longer support HSM.\n");
		return PCC_ERR_NOT_SUPPORT_HSM;
	} else {
		if ((rtn=PCI_initContext(&ctx, EKMK, PCC_MASTER_HASH_SIZE, PCI_CIPHER_AES, PCI_EMODE_CBC, PCI_IVT_PIV1, 0, 1, 1)) < 0) goto PCI_ERR_RETURN2;
        	if ((rtn=PCI_encrypt(&ctx, MK, PCC_MASTER_KEY_LENGTH, (dgt_uint8*)smk, smk_len)) < 0) goto PCI_ERR_RETURN2;
	}


PCI_ERR_RETURN2:
	if (rtn) sprintf(PCI_KmgrErrMsg,"PCI_createKey failed due to %s", PCI_getErrMsg(&ctx));

#ifdef PCI_TEST
printf("PCI_createKey-OUTPUT::\n");
printf("        smk_len => [%u]\n",*smk_len);
printf("        smk => [");
for(dgt_uint32 i=0; i<*smk_len; i++) printf("%02x",*(smk+i));
printf("]\n");
printf("        seks_len => [%u]\n",*seks_len);
printf("        seks => [");
for(dgt_uint32 i=0; i<*seks_len; i++) printf("%02x",*(seks+i));
printf("]\n");
printf("        sks_len => [%u]\n",*sks_len);
printf("        sks => [");
for(dgt_uint32 i=0; i<*sks_len; i++) printf("%02x",*(sks+i));
printf("]\n");
#endif

	return rtn;
}
#endif
	

dgt_sint32 PCI_checkPassword(
	const dgt_schar* pw,
	dgt_schar* smk,
	dgt_uint32 smk_len,
	dgt_schar* seks,
	dgt_uint32 seks_len,
	dgt_schar* sks,
	dgt_uint32 sks_len,
	dgt_sint32 hsm_mode,
	const dgt_schar* hsm_password)
{
#ifdef PCI_TEST
printf("PCI_checkPassword-INPUT::\n");
printf("        password   => [%s]\n",pw);
printf("        smk => [%s]\n",smk);
printf("        smk_len => [%u]\n",smk_len);
printf("        seks => [%s]\n",seks);
printf("        seks_len => [%u]\n",seks_len);
printf("        sks => [%s]\n",sks);
printf("        sks_len => [%u]\n",sks_len);
#endif

	dgt_sint32	rtn=0;
	PciKeyHolder	key_holder;
	rtn=PCI_checkKey(pw,smk,smk_len,seks,seks_len,sks,sks_len,key_holder, hsm_mode, hsm_password);

#ifdef PCI_TEST
printf("PCI_checkPassword-OUTPUT::\n");
printf("        rtn => [%d]\n",rtn);
#endif

	return rtn;
}


#ifndef WIN32
dgt_sint32 PCI_changePassword(
	const dgt_schar* old_pw,
	const dgt_schar* new_pw,
	dgt_schar* smk,
	dgt_uint32 smk_len,
	dgt_schar* seks,
	dgt_uint32 seks_len,
	dgt_schar* sks,
	dgt_uint32 sks_len,
	dgt_sint32 hsm_mode,
	const dgt_schar* hsm_password)
{
#ifdef PCI_TEST
printf("PCI_changePassword-INPUT::\n");
printf("        old password   => [%s]\n",old_pw);
printf("        new password   => [%s]\n",new_pw);
printf("        smk => [%s]\n",smk);
printf("        smk_len => [%u]\n",smk_len);
printf("        seks => [%s]\n",seks);
printf("        seks_len => [%u]\n",seks_len);
printf("        sks => [%s]\n",sks);
printf("        sks_len => [%u]\n",sks_len);
#endif

	dgt_sint32	rtn=0;
	PciKeyHolder	key_holder;
	if ((rtn=PCI_checkKey(old_pw, smk, smk_len, seks, seks_len, sks, sks_len, key_holder,hsm_mode,hsm_password)) < 0) return rtn;
	//
	// generate EKMK for the new password
	//
	if ((rtn=DgcPwChecker::checkStrength(new_pw,strlen(new_pw))) < 0) {
		sprintf(PCI_KmgrErrMsg,"PCI_changePassword failed due to %s", EXCEPT->getErr()->message());
		delete EXCEPTnC;
		return  PCC_ERR_KMGR_WEAK_PASSWORD; 
        }
	dgt_uint32	dst_len = PCC_MASTER_KEY_LENGTH;
	if ((rtn=PCI_generateEKMK(new_pw, key_holder.eKMK(), &dst_len, hsm_mode, hsm_password)) < 0) return rtn;
	//
	// generate SMK - Saved Master Key
	//
	PCI_Context	ctx;
	if (hsm_mode) {
		sprintf(PCI_KmgrErrMsg, "As of June 27, 2023, we no longer support HSM.\n");
		return PCC_ERR_NOT_SUPPORT_HSM;
	} else {
		if ((rtn=PCI_initContext(&ctx, key_holder.eKMK(), PCC_MASTER_HASH_SIZE, PCI_CIPHER_AES, PCI_EMODE_CBC, PCI_IVT_PIV1, 0, 1, 1)) < 0) goto PCI_ERR_RETURN3;
        	if ((rtn=PCI_encrypt(&ctx, key_holder.mK(), PCC_MASTER_KEY_LENGTH, (dgt_uint8*)smk, &smk_len)) < 0) goto PCI_ERR_RETURN3;
	}

PCI_ERR_RETURN3:
	if (rtn) sprintf(PCI_KmgrErrMsg,"PCI_changePassword failed due to %s", PCI_getErrMsg(&ctx));

#ifdef PCI_TEST
printf("PCI_changePassword-OUTPUT::\n");
printf("        smk => [%s]\n",smk);
#endif

	return rtn;
}
#endif


dgt_sint32 PCI_setKeyStash(PCT_KEY_STASH* key_stash)
{
#ifdef PCI_TEST
printf("PCI_setKeyStash-INPUT::\n");
printf("        key_stash pointer  => [%p]\n",key_stash);
printf("        open_status => [%d]\n",key_stash->open_status);
printf("        key_signature => [");
for(dgt_uint32 i=0; i<PCC_KEY_SET_SIG_LENGTH; i++) printf("%02x",*(key_stash->key_set_signature+i));
printf("]\n");
printf("        key_set => [");
for(dgt_uint32 i=0; i<PCC_MAX_EKEY_SET_LENGTH; i++) printf("%02x",*(key_stash->key_set+i));
printf("]\n");
#endif

	if (key_stash == 0) {
		sprintf(PCI_KmgrErrMsg, "PCI_setKeyStash failed due to invalid input parameter");
		return PCC_ERR_KMGR_INVALID_INPUT_PARAM;
	}
	if (PCI_KeyStash) {
		sprintf(PCI_KmgrErrMsg, "PCI_setKeyStash failed because the key stash's already set");
		return PCC_ERR_KMGR_KEY_STASH_SET_ALREADY;
	}
	PCI_KeyStash = new PciKeyStash(key_stash);
	return 0;
}


dgt_sint32 PCI_getKeyStash(PCT_KEY_STASH** key_stash)
{
	if (PCI_KeyStash == 0 || PCI_KeyStash->keyStash() == 0) {
		sprintf(PCI_KmgrErrMsg,"PCI_openKey failed due to no key stash, call PCI_setKeyStash first");
		return PCC_ERR_KMGR_NO_KEY_STASH;
	}
	*key_stash = PCI_KeyStash->keyStash();
	return 0;
}


dgt_sint32 PCI_openKey(
	const dgt_schar* pw,
	dgt_schar* smk,
	dgt_uint32 smk_len,
	dgt_schar* seks,
	dgt_uint32 seks_len,
	dgt_schar* sks,
	dgt_uint32 sks_len,
	dgt_sint32 hsm_mode,
	const dgt_schar* hsm_password)
{
#ifdef PCI_TEST
printf("PCI_openKey-INPUT::\n");
printf("        password   => [%s]\n",pw);
printf("        smk => [%s]\n",smk);
printf("        smk_len => [%u]\n",smk_len);
printf("        seks => [%s]\n",seks);
printf("        seks_len => [%u]\n",seks_len);
printf("        sks => [%s]\n",sks);
printf("        sks_len => [%u]\n",sks_len);
#endif

	if (PCI_KeyStash == 0) {
		sprintf(PCI_KmgrErrMsg,"PCI_openKey failed due to no key stash, call PCI_setKeyStash first");
		return PCC_ERR_KMGR_NO_KEY_STASH;
	}
	dgt_sint32	rtn=0;
	PciKeyHolder	key_holder;
	if ((rtn=PCI_checkKey(pw, smk, smk_len, seks, seks_len, sks, sks_len, key_holder, hsm_mode, hsm_password)) < 0) return rtn;
	rtn=PCI_KeyStash->openKeySet(key_holder.eKS());

#ifdef PCI_TEST
printf("PCI_openKey-OUTPUT::\n");
printf("        open_status => [%d]\n",PCI_KeyStash->keyStash()->open_status);
printf("        key_signature => [");
for(dgt_uint32 i=0; i<PCC_KEY_SET_SIG_LENGTH; i++) printf("%02x",*(PCI_KeyStash->keyStash()->key_set_signature+i));
printf("]\n");
printf("        key_set => [");
for(dgt_uint32 i=0; i<PCC_MAX_EKEY_SET_LENGTH; i++) printf("%02x",*(PCI_KeyStash->keyStash()->key_set+i));
printf("]\n");
#endif

	return rtn;
}


dgt_sint32 PCI_closeKey(
	const dgt_schar* pw,
	dgt_schar* smk,
	dgt_uint32 smk_len,
	dgt_schar* seks,
	dgt_uint32 seks_len,
	dgt_schar* sks,
	dgt_uint32 sks_len,
	dgt_sint32 hsm_mode,
	const dgt_schar* hsm_password)
{
#ifdef PCI_TEST
printf("PCI_closeKey-INPUT::\n");
printf("        password   => [%s]\n",pw);
printf("        smk => [%s]\n",smk);
printf("        smk_len => [%u]\n",smk_len);
printf("        seks => [%s]\n",seks);
printf("        seks_len => [%u]\n",seks_len);
printf("        sks => [%s]\n",sks);
printf("        sks_len => [%u]\n",sks_len);
#endif

	if (PCI_KeyStash == 0) {
		sprintf(PCI_KmgrErrMsg,"PCI_closeKey failed due to no key stash, call PCI_setKeyStash first");
		return PCC_ERR_KMGR_NO_KEY_STASH;
	}
	dgt_sint32	rtn=0;
	PciKeyHolder	key_holder;
	if ((rtn=PCI_checkKey(pw, smk, smk_len, seks,seks_len, sks, sks_len, key_holder, hsm_mode, hsm_password)) < 0) return rtn;
	PCI_KeyStash->closeKeySet();

#ifdef PCI_TEST
printf("PCI_closeKey-OUTPUT::\n");
printf("        open_status => [%d]\n",PCI_KeyStash->keyStash()->open_status);
#endif

	return 0;
}


dgt_sint32 PCI_getEncryptKey(
	dgt_uint32 key_idx,
	dgt_uint32 key_len,	// length in bites
	dgt_uint8* key_buffer)
{
#ifdef PCI_TEST
printf("PCI_getEncryptKey-INPUT::\n");
printf("        key_idx   => [%u]\n",key_idx);
printf("        key_len   => [%u]\n",key_len);
printf("        key_buffer pointer => [%p]\n",key_buffer);
#endif

	if (key_len == 0 || key_buffer == 0) {
		sprintf(PCI_KmgrErrMsg, "PCI_getEncryptKey failed due to invalid input parameter");
		return PCC_ERR_KMGR_INVALID_INPUT_PARAM;
	}
	if (PCI_KeyStash == 0) {
		sprintf(PCI_KmgrErrMsg,"PCI_getEncryptKey failed due to no key stash, call PCI_setKeyStash first");
		return PCC_ERR_KMGR_NO_KEY_STASH;
	}
	dgt_sint32 rtn=PCI_KeyStash->getKey(key_idx, key_len, key_buffer);

#ifdef PCI_TEST
printf("PCI_getEncryptKey-OUTPUT::\n");
printf("        key_buffer => [");
for(dgt_uint32 i=0; i<key_len; i++) printf("%02x",*(key_buffer+i));
printf("]\n");
#endif

	return rtn;
}


const dgt_schar* PCI_getKmgrErrMsg()
{
	return PCI_KmgrErrMsg;
}


#if 0
dgt_uint32 PCI_dumpKeyStash(dgt_uint8* dbuf)
{
	return PCI_KeyStash->dump(dbuf);
}
#endif
