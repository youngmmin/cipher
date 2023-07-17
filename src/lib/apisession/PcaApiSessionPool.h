/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcaApiSessionPool
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 4. 1
 *   Description        :       petra cipher API session pool
 *   Modification history
 *   date                    modification
 *   18.06.19 by shson		 added logUserFileRequest method
--------------------------------------------------------------------

********************************************************************/
#ifndef PCA_API_SESSION_POOL_H
#define PCA_API_SESSION_POOL_H

#include "PcaSessionPool.h"

#include "PccSearchEngineFactory.h"


static const dgt_sint32 PSP_HS_LENGTH = 256;		// api session hash string length


class PcaApiSession : public PcaHashNode {
  private :
	static const dgt_sint32 PSP_ERR_LOCK_FAIL = -30309;	// error code for spin locking failure 

	dgt_slock	FuncLatch;	// spin lock for concurrency control over crypt function
	dgt_schar	HashString[PSP_HS_LENGTH];
	PcaSession*	ClientSession;
	dgt_sint32	SharedFlag;
  protected :
  public :
	static inline dgt_sint32 computeHashValue(const char* client_ip,const char* user_id,const char* client_program, const dgt_schar* client_mac, const dgt_schar* db_user, const dgt_schar* os_user, dgt_uint8 access_protocol, dgt_schar* hash_string)
	{
		dgt_sint32	hash_val = 0;
		sprintf(hash_string,"[%s]^[%s]^[%s]^[%s]^[%s]^[%s]^[%d]",client_ip?client_ip:"", user_id?user_id:"", client_program?client_program:"", client_mac?client_mac:"", db_user?db_user:"", os_user?os_user:"",access_protocol?access_protocol:0);
		for(dgt_sint32 i=0; i<PSP_HS_LENGTH && hash_string[i]; i++) hash_val += hash_string[i]*(i+1);
		return hash_val;
	}

	PcaApiSession(const dgt_schar* client_ip,const char* user_id,const char* client_program, const dgt_schar* client_mac, const dgt_schar* db_user, const dgt_schar* os_user, dgt_uint8 access_protocol, PcaSession* pca_session, dgt_sint32 shared_flag=0) : ClientSession(pca_session), SharedFlag(shared_flag)
	{
		DgcSpinLock::unlock(&FuncLatch);
		memset(HashString,0,PSP_HS_LENGTH);
		computeHashValue(client_ip,user_id,client_program,client_mac,db_user,os_user,access_protocol,HashString);
		ClientSession->setParentLink((dgt_void*)this);
	}

	virtual ~PcaApiSession() {}

	inline dgt_sint32 sid() { return ClientSession->sid(); }
	inline dgt_schar* hashString() { return HashString; }
	inline dgt_sint32 sharedFlag() { return SharedFlag; }

	inline dgt_void setCharSet(const dgt_schar* char_set=0)
	{
		return ClientSession->setCharSet(char_set);
	}

	inline dgt_uint8* inBuffer(dgt_sint32 len=0)
	{
		return ClientSession->inBuffer(len);
	}

	inline dgt_sint64 getEncColID(const dgt_schar* enc_col_name)
	{
		return ClientSession->getEncColID(enc_col_name);
	}

	inline dgt_uint8 hasEncryptPriv(dgt_sint64 enc_col_id)
	{
		return ClientSession->hasEncryptPriv(enc_col_id);
	}

	inline dgt_uint8 hasDecryptPriv(dgt_sint64 enc_col_id)
	{
		return ClientSession->hasDecryptPriv(enc_col_id);
	}

#if 1 // added by shson 2017.6.5 for automatic calculation of the read buffer size in decrypting
	inline dgt_sint32 encryptLength(const dgt_schar* enc_col_name,dgt_sint32 src_len)
	{   
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->encryptLength(enc_col_name,src_len);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	}

	// added by jhpark 2017.07.20
	inline dgt_sint32 encryptLengthWithVirtualKey(
			dgt_sint64 virtual_key_id,
			dgt_sint32 src_len,
			dgt_uint8	crypt_type,
			dgt_uint8	target_type,
			dgt_schar*	name1=0,
			dgt_schar*	name2=0,
			dgt_schar*	name3=0,
			dgt_schar*	name4=0,
			dgt_schar*	name5=0,
			dgt_schar*	name6=0,
			dgt_schar*	name7=0,
			dgt_schar*	name8=0,
			dgt_schar*	name9=0,
			dgt_schar*	name10=0)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}

		PcaPrivilege*	priv = ClientSession->getVKeyPrivilege(virtual_key_id,crypt_type,target_type,
												name1, name2, name3, name4, name5, name6, name7, name8, name9, name10);
		dgt_sint32 rtn = 0;
		if (priv && priv->encColID()) {
			rtn = ClientSession->encryptLength(priv->encColID(),src_len);
		} else {
			rtn = ClientSession->getErrCode();
		}

		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	}
#endif

#if 1 // added by mwpark 2017.06.26 for file encrypt/decrypt logging and massive data control
	inline dgt_sint32 isEncryptAudit(const dgt_schar* enc_col_name)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_uint8 rtn = ClientSession->isEncryptAudit(enc_col_name);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	}

	inline dgt_sint32 isDecryptAudit(const dgt_schar* enc_col_name)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_uint8 rtn = ClientSession->isDecryptAudit(enc_col_name);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	}

	inline dgt_sint64 maskingDecCount(const dgt_schar* enc_col_name)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint64 rtn = ClientSession->maskingDecCount(enc_col_name);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	}
#endif

	inline dgt_sint32 encrypt(
                dgt_sint64      enc_col_id,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8*      dst,
                dgt_uint32*     dst_len)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->encrypt(enc_col_id,src,src_len,dst,dst_len);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};

	inline dgt_sint32 encrypt(
                dgt_sint64      enc_col_id,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8*      dst,
                dgt_uint32*     dst_len,
                int             sql_type)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->encrypt(enc_col_id,src,src_len,dst,dst_len,sql_type);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};

	inline dgt_sint32 encrypt(
                dgt_sint64      enc_col_id,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8**     dst,
                dgt_uint32*     dst_len)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->encrypt(enc_col_id,src,src_len,dst,dst_len);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};

	inline dgt_sint32 encrypt(
                dgt_sint64      enc_col_id,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8**     dst,
                dgt_uint32*     dst_len,
		int             sql_type)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->encrypt(enc_col_id,src,src_len,dst,dst_len,sql_type);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};

	inline dgt_sint32 encrypt(
                const dgt_schar*      enc_col_name,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8*      dst,
                dgt_uint32*     dst_len)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->encrypt(enc_col_name,src,src_len,dst,dst_len);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};

	inline dgt_sint32 encrypt(
                const dgt_schar*      enc_col_name,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8*      dst,
                dgt_uint32*     dst_len,
                dgt_schar* header_flag)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->encrypt(enc_col_name,src,src_len,dst,dst_len,header_flag);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};

	inline dgt_sint32 encrypt(
                const dgt_schar*      enc_col_name,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8*      dst,
                dgt_uint32*     dst_len,
                int             sql_type,
		dgt_uint8*	set_key=0,
		dgt_uint8*	set_iv=0)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->encrypt(enc_col_name,src,src_len,dst,dst_len,sql_type,set_key,set_iv);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};

	inline dgt_sint32 encrypt(
                const dgt_schar*      enc_col_name,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8**     dst,
                dgt_uint32*     dst_len)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->encrypt(enc_col_name,src,src_len,dst,dst_len);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};

	inline dgt_sint32 encrypt(
                const dgt_schar*      enc_col_name,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8**     dst,
                dgt_uint32*     dst_len,
                int             sql_type)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->encrypt(enc_col_name,src,src_len,dst,dst_len,sql_type);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};

        inline dgt_sint32 crypt_test(
                dgt_sint64      enc_col_id,
                dgt_uint8*      str,
                dgt_sint32      ksv_num)
        {
                if (DgcSpinLock::lock(&FuncLatch)) {
                        PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
                        return PSP_ERR_LOCK_FAIL;
                }
                dgt_sint32 rtn = ClientSession->crypt_test(enc_col_id,str,ksv_num);
                DgcSpinLock::unlock(&FuncLatch);
                return rtn;
        };

        inline dgt_sint32 crypt_test(
                const dgt_schar*      enc_col_name,
                dgt_uint8*      str,
                dgt_sint32      ksv_num)
        {

                if (DgcSpinLock::lock(&FuncLatch)) {
                        PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
                        return PSP_ERR_LOCK_FAIL;
                }
                dgt_sint32 rtn = ClientSession->crypt_test(enc_col_name,str,ksv_num);
                DgcSpinLock::unlock(&FuncLatch);
                return rtn;
        };

	inline dgt_sint32 PtMonCipherApiCall(
		dgt_sint64	enc_col_id,
		const dgt_schar*	str,
		dgt_sint32*	key_stat)
	{
                if (DgcSpinLock::lock(&FuncLatch)) {
                        PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
                        return PSP_ERR_LOCK_FAIL;
                }
		for(dgt_sint32 i=0; i<3; i++) key_stat[i] = ClientSession->crypt_test(enc_col_id, (dgt_uint8*)str, i);

                DgcSpinLock::unlock(&FuncLatch);
                return 0;

	};	
	
	inline dgt_sint32 PtMonCipherApiCall(
		const dgt_schar*	enc_col_name,
		const dgt_schar*	str,
		dgt_sint32*	key_stat)
	{
                if (DgcSpinLock::lock(&FuncLatch)) {
                        PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
                        return PSP_ERR_LOCK_FAIL;
                }
		for(dgt_sint32 i=0; i<3; i++) key_stat[i] = ClientSession->crypt_test(enc_col_name, (dgt_uint8*)str, i);

                DgcSpinLock::unlock(&FuncLatch);
                return 0;

	};	

	inline dgt_sint32 decrypt(
                dgt_sint64      enc_col_id,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8*      dst,
                dgt_uint32*     dst_len)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->decrypt(enc_col_id,src,src_len,dst,dst_len);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};

	inline dgt_sint32 decrypt(
                dgt_sint64      enc_col_id,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8*      dst,
                dgt_uint32*     dst_len,
                int             sql_type)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->decrypt(enc_col_id,src,src_len,dst,dst_len,sql_type);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};

	inline dgt_sint32 decrypt(
                dgt_sint64      enc_col_id,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8**     dst,
                dgt_uint32*     dst_len)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->decrypt(enc_col_id,src,src_len,dst,dst_len);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};

	inline dgt_sint32 decrypt(
                dgt_sint64      enc_col_id,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8**     dst,
                dgt_uint32*     dst_len,
                int             sql_type)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->decrypt(enc_col_id,src,src_len,dst,dst_len,sql_type);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};

	inline dgt_sint32 decrypt(
                const dgt_schar*      enc_col_name,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8*      dst,
                dgt_uint32*     dst_len)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->decrypt(enc_col_name,src,src_len,dst,dst_len);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};

	inline dgt_sint32 decrypt(
                const dgt_schar*      enc_col_name,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8*      dst,
                dgt_uint32*     dst_len,
                dgt_schar* header_flag)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->decrypt(enc_col_name,src,src_len,dst,dst_len,header_flag);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};

	inline dgt_sint32 decrypt(
                const dgt_schar*      enc_col_name,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8*      dst,
                dgt_uint32*     dst_len,
                int             sql_type,
		dgt_uint8*	set_key=0,
		dgt_uint8*	set_iv=0)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->decrypt(enc_col_name,src,src_len,dst,dst_len,sql_type,set_key,set_iv);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};

	inline dgt_sint32 decrypt(
                const dgt_schar*      enc_col_name,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8**     dst,
                dgt_uint32*     dst_len)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->decrypt(enc_col_name,src,src_len,dst,dst_len);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};

	inline dgt_sint32 decrypt(
                const dgt_schar*      enc_col_name,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8**     dst,
                dgt_uint32*     dst_len,
                int             sql_type)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->decrypt(enc_col_name,src,src_len,dst,dst_len,sql_type);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};

	inline dgt_sint32 decrypt_vkey(
				dgt_sint64		virtual_key_id,
				dgt_uint8*		src,
				dgt_sint32		src_len,
				dgt_uint8*		dst,
				dgt_uint32*		dst_len,
				dgt_uint8		target_type,
				dgt_schar*	name1=0,
				dgt_schar*	name2=0,
				dgt_schar*	name3=0,
				dgt_schar*	name4=0,
				dgt_schar*	name5=0,
				dgt_schar*	name6=0,
				dgt_schar*	name7=0,
				dgt_schar*	name8=0,
				dgt_schar*	name9=0,
				dgt_schar*	name10=0)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->decrypt_vkey(
				virtual_key_id, src, src_len, dst, dst_len,
				target_type, name1, name2, name3, name4, name5, name6, name7, name8, name9, name10);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};

	inline dgt_sint32 decrypt_vkey(
				dgt_sint64		virtual_key_id,
				dgt_uint8*		src,
				dgt_sint32		src_len,
				dgt_uint8**		dst,
				dgt_uint32*		dst_len,
				dgt_uint8		target_type,
				dgt_schar*	name1=0,
				dgt_schar*	name2=0,
				dgt_schar*	name3=0,
				dgt_schar*	name4=0,
				dgt_schar*	name5=0,
				dgt_schar*	name6=0,
				dgt_schar*	name7=0,
				dgt_schar*	name8=0,
				dgt_schar*	name9=0,
				dgt_schar*	name10=0)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->decrypt_vkey(
				virtual_key_id, src, src_len, dst, dst_len,
				target_type, name1, name2, name3, name4, name5, name6, name7, name8, name9, name10);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};

	inline dgt_sint32 OPHUEK(
                dgt_sint64      enc_col_id,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8*      dst,
                dgt_uint32*     dst_len,
		dgt_sint32	src_enc_flag)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->OPHUEK(enc_col_id,src,src_len,dst,dst_len,src_enc_flag);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};

	inline dgt_sint32 OPHUEK(
                dgt_sint64      enc_col_id,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8**     dst,
                dgt_uint32*     dst_len,
		dgt_sint32	src_enc_flag)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->OPHUEK(enc_col_id,src,src_len,dst,dst_len,src_enc_flag);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};
	
	inline dgt_sint32 OPHUEK(
                const dgt_schar*      enc_col_name,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8*      dst,
                dgt_uint32*     dst_len,
		dgt_sint32	src_enc_flag)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->OPHUEK(enc_col_name,src,src_len,dst,dst_len,src_enc_flag);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};

	inline dgt_sint32 OPHUEK(
                const dgt_schar*      enc_col_name,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8**     dst,
                dgt_uint32*     dst_len,
		dgt_sint32	src_enc_flag)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->OPHUEK(enc_col_name,src,src_len,dst,dst_len,src_enc_flag);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};
	
	inline dgt_sint32 encryptCpn(
                dgt_sint64      enc_col_id,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8*      coupon,
                dgt_uint32*     coupon_len)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->encryptCpn(enc_col_id,src,src_len,coupon,coupon_len);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};

	inline dgt_sint32 encryptCpn(
                dgt_sint64      enc_col_id,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8**     coupon,
                dgt_uint32*     coupon_len)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->encryptCpn(enc_col_id,src,src_len,coupon,coupon_len);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};

	inline dgt_sint32 encryptCpn(
                const dgt_schar*      enc_col_name,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8*      coupon,
                dgt_uint32*     coupon_len)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->encryptCpn(enc_col_name,src,src_len,coupon,coupon_len);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};

	inline dgt_sint32 encryptCpn(
                const dgt_schar*      enc_col_name,
                dgt_uint8*      src,
                dgt_sint32      src_len,
                dgt_uint8**     coupon,
                dgt_uint32*     coupon_len)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->encryptCpn(enc_col_name,src,src_len,coupon,coupon_len);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};

	inline dgt_sint32 decryptCpn(
                dgt_sint64      enc_col_id,
                dgt_uint8*      coupon,
                dgt_sint32      coupon_len,
                dgt_uint8*      dst,
                dgt_uint32*     dst_len)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->decryptCpn(enc_col_id,coupon,coupon_len,dst,dst_len);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};
	
	inline dgt_sint32 decryptCpn(
                dgt_sint64      enc_col_id,
                dgt_uint8*      coupon,
                dgt_sint32      coupon_len,
                dgt_uint8**     dst,
                dgt_uint32*     dst_len)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->decryptCpn(enc_col_id,coupon,coupon_len,dst,dst_len);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};
	
	inline dgt_sint32 decryptCpn(
                const dgt_schar*      enc_col_name,
                dgt_uint8*      coupon,
                dgt_sint32      coupon_len,
                dgt_uint8*      dst,
                dgt_uint32*     dst_len)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->decryptCpn(enc_col_name,coupon,coupon_len,dst,dst_len);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};
	
	inline dgt_sint32 decryptCpn(
                const dgt_schar*      enc_col_name,
                dgt_uint8*      coupon,
                dgt_sint32      coupon_len,
                dgt_uint8**     dst,
                dgt_uint32*     dst_len)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->decryptCpn(enc_col_name,coupon,coupon_len,dst,dst_len);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	};

	inline dgt_void setSqlHash(dgt_schar* sql_hash,dgt_sint32 sql_type)
	{
		 ClientSession->setSqlHash(sql_hash,sql_type);
	};

	inline dgt_void logCurrRequest(dgt_schar* sql_hash=0,dgt_sint32 sql_type=0,dgt_schar* user_id=0)
	{
		ClientSession->logCurrRequest(sql_hash,sql_type,user_id);
	};

	inline dgt_sint32 getErrCode() { return ClientSession->getErrCode(); };
        inline dgt_sint32 getNewSqlFlag() { return ClientSession->getNewSqlFlag(); };

        inline dgt_sint32 getKey(
                const dgt_schar*      enc_col_name,
                dgt_uint8*      key_buffer,
                dgt_sint32*     key_size)
        {
                if (DgcSpinLock::lock(&FuncLatch)) {
                        PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
                        return PSP_ERR_LOCK_FAIL;
                }
                dgt_sint32 rtn = ClientSession->getKey(enc_col_name,key_buffer,key_size);
                DgcSpinLock::unlock(&FuncLatch);
                return rtn;
        };

        inline dgt_sint64 getKeyId(
                const dgt_schar*      enc_col_name)
        {
                if (DgcSpinLock::lock(&FuncLatch)) {
                        PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
                        return PSP_ERR_LOCK_FAIL;
                }
                dgt_sint64 key_id = ClientSession->getKeyId(enc_col_name);
                DgcSpinLock::unlock(&FuncLatch);
                return key_id;
        };

	inline dgt_sint32 putExtKey(
                const dgt_schar*      key_name,
                const dgt_schar*      key,
                dgt_uint16     format_no)
        {
                if (DgcSpinLock::lock(&FuncLatch)) {
                        PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
                        return PSP_ERR_LOCK_FAIL;
                }
                dgt_sint32 rtn = ClientSession->putExtKey(key_name,key,format_no);
                DgcSpinLock::unlock(&FuncLatch);
                return rtn;
        };

	inline dgt_void logFileRequest(pc_type_file_request_in* log_request)
	{
		ClientSession->logFileRequest(log_request);
	};

	inline dgt_void logUserFileRequest(pc_type_user_file_request_in* log_request)
	{
		ClientSession->logUserFileRequest(log_request);
	};

	inline dgt_void logDetectFileRequest(pc_type_detect_file_request_in* log_request, DgcMemRows* log_data)
        {
                ClientSession->logDetectFileRequest(log_request, log_data);
        };

	inline dgt_void getDetectFileRequest(DgcMemRows* get_request)
        {
                ClientSession->getDetectFileRequest(get_request);
        };
	
	inline dgt_sint32 getKeyInfo(const dgt_schar* enc_col_name,const dgt_schar* passwd,dgt_schar* key_info_buf,dgt_uint32* buf_len)
	{
                if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->getKeyInfo(enc_col_name,passwd,key_info_buf,buf_len);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	}

	inline dgt_sint32 getZoneParam(dgt_sint64 zone_id, dgt_schar** param)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->getZoneParam(zone_id,param);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	}

	inline dgt_sint32 getZoneParam(dgt_schar* zone_name, dgt_schar** param)
	{
		if (DgcSpinLock::lock(&FuncLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
			return PSP_ERR_LOCK_FAIL;
		}
		dgt_sint32 rtn = ClientSession->getZoneParam(zone_name,param);
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	}

	inline dgt_sint32 getRegEngine(dgt_sint64 reg_engine_id, PccRegExprSearchEngine** param)
        {
                if (DgcSpinLock::lock(&FuncLatch)) {
                        PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
                        return PSP_ERR_LOCK_FAIL;
                }
                dgt_sint32 rtn = ClientSession->getRegEngine(reg_engine_id,param);
                DgcSpinLock::unlock(&FuncLatch);
                return rtn;
        }

	inline dgt_sint32 getRegEngine(dgt_schar* reg_name, PccRegExprSearchEngine** param)
        {
                if (DgcSpinLock::lock(&FuncLatch)) {
                        PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
                        return PSP_ERR_LOCK_FAIL;
                }
                dgt_sint32 rtn = ClientSession->getRegEngine(reg_name,param);
                DgcSpinLock::unlock(&FuncLatch);
                return rtn;
        }

	inline dgt_sint32 getCryptParam(dgt_schar* crypt_param_name, dgt_schar** param)
	{
                if (DgcSpinLock::lock(&FuncLatch)) {
                        PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
                        return PSP_ERR_LOCK_FAIL;
		}
                dgt_sint32 rtn = ClientSession->getCryptParam(crypt_param_name,param);
                DgcSpinLock::unlock(&FuncLatch);
                return rtn;
	}

	inline PcaKeySvrSessionPool* keySvrSessionPool() { 
                if (DgcSpinLock::lock(&FuncLatch)) {
                        PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
                        return 0;
                }
		PcaKeySvrSessionPool* rtn=ClientSession->keySvrSessionPool();
		DgcSpinLock::unlock(&FuncLatch);
		return rtn;
	}

        inline dgt_uint32 getFileHeaderFlag() { return ClientSession->getFileHeaderFlag(); }
        inline dgt_uint32 getFileRealBytes() { return ClientSession->getFileRealBytes(); }
        inline dgt_schar* getFileKeyName() { return ClientSession->getFileKeyName(); }
        inline dgt_schar* getFileName() { return ClientSession->getFileName(); }
        inline dgt_uint32 getFileFlags() { return ClientSession->getFileFlags(); }
        inline dgt_sint32 getFileMode() { return ClientSession->getFileMode(); }
        inline dgt_void setFileHeaderFlag() { ClientSession->setFileHeaderFlag(); }
        inline dgt_void setFileRealBytes(dgt_uint32 real_bytes) { ClientSession->setFileRealBytes(real_bytes); }
        inline dgt_void setFileOpen(const dgt_schar* key_name=0, const dgt_schar* file_name=0, dgt_uint32 flags=0, dgt_uint32 mode=0)
        {
		ClientSession->setFileOpen(key_name, file_name, flags, mode);
        }

        inline dgt_sint32 getRsaKey(dgt_schar* key_name, dgt_schar** key_string)
        {
                if (DgcSpinLock::lock(&FuncLatch)) {
                        PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
                        return PSP_ERR_LOCK_FAIL;
                }
                dgt_sint32 rtn = ClientSession->getRsaKey(key_name, key_string);
                DgcSpinLock::unlock(&FuncLatch);
                return rtn;
        }

};


class PcaApiSessionPool : public DgcObject {
  private:
	static const dgt_sint32	PSP_MAX_SESSIONS = 10000;	// size of session hash table
	static const dgt_sint32 PSP_ERR_LOCK_FAIL = -30309;	// error code for spin locking failure 

#ifdef hpux11
	static PcaApiSessionPool*	ApiSessionPool;
#else
	static PcaApiSessionPool	ApiSessionPool;
#endif

	dgt_slock		PoolLatch;	// spin lock for concurrency control over ApiSessions
	PcaApiSession*		ApiSessions[PSP_MAX_SESSIONS]; // api session pool
	PcaApiSession**		ApiSharedSessions; // shared api session pool
	dgt_sint32		NumSharedSession; // the number of shared api session pool
	dgt_sint32		LastAssignedIdx; // the index in the shared api session pool that was fetched latest.
	dgt_sint32*		SharedFreePool; // shared free session pool
	dgt_sint32		FreePoolSize; // the number of free session in free pool

	inline dgt_sint32 findSharedSession(dgt_uint8 no_lock=0)
	{
		if (no_lock ==0) {
			if (DgcSpinLock::lock(&PoolLatch)) {
				PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
				return PSP_ERR_LOCK_FAIL;
			}
		}
		if (NumSharedSession == 0) {
			//
			// not initialized shared session pool, initialize shared session pool
			//
			if ((NumSharedSession=PcaSessionPool::numSharedSession()) > 0) {
				ApiSharedSessions = new PcaApiSession*[NumSharedSession];	// create a shared session pool
				SharedFreePool = new dgt_sint32[NumSharedSession];
				for(dgt_sint32 i=0; i<NumSharedSession; i++) {
					ApiSharedSessions[i] = 0;
					SharedFreePool[i] = -1;
					//
					// open a client session
					//
					PcaSession*	pca_session = PcaSessionPool::openSession(0); // open a shared client session
					if (pca_session) {
						if (pca_session->openSession() >= 0) { // open a shared user session
							ApiSharedSessions[i] = new PcaApiSession("", "", "", "", "", "",0,pca_session,1); // register with the api session pool
							SharedFreePool[FreePoolSize++] = pca_session->sid();
						} else {
							//
							// failed to open a user session, remove it from the client session pool
							//
							PcaSessionPool::closeSession(pca_session->sid());
						}
					}
				}
				LastAssignedIdx = -1;
			}
		}
		dgt_sint32	sid = -1;
		if (FreePoolSize > 0) {
			sid = SharedFreePool[--FreePoolSize];
		} else {
			//
			// forward search
			//
			for(dgt_sint32 i=LastAssignedIdx+1; i<NumSharedSession; i++) {
				if (ApiSharedSessions[i]) {
					sid = ApiSharedSessions[LastAssignedIdx=i]->sid();
					break;
				}
			}
			if (sid < 0) {
				//
				// not found and then backward search
				//
				for(dgt_sint32 i=0; i<=LastAssignedIdx; i++) {
					if (ApiSharedSessions[i]) {
						sid = ApiSharedSessions[LastAssignedIdx=i]->sid();
						break;
					}
				}
			}
		}
		if (no_lock == 0) DgcSpinLock::unlock(&PoolLatch);
		return sid;
	};

	inline dgt_void returnSharedSession(dgt_sint32 sid)
	{
		if (DgcSpinLock::lock(&PoolLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
		} else {
			dgt_sint32	rtn_sid = -1;
			for(dgt_sint32 i=0; i<NumSharedSession; i++) {
				if (ApiSharedSessions[i] && ApiSharedSessions[i]->sid() == sid) {
					rtn_sid = sid;
					break;
				}
			}
			if (rtn_sid >= 0 && FreePoolSize < NumSharedSession) SharedFreePool[FreePoolSize++] = rtn_sid;
			DgcSpinLock::unlock(&PoolLatch);
		}
	};

	inline dgt_sint32 findApiSession(const dgt_schar* client_ip,const dgt_schar* user_id,const dgt_schar* client_program, const dgt_schar* client_mac, const dgt_schar* db_user, const dgt_schar* os_user, dgt_uint8 access_protocol, dgt_uint8 no_lock=0)
	{
		dgt_sint32	sid;
		if ((!client_ip || *client_ip == 0) && (!user_id || *user_id == 0) && (!client_program || *client_program == 0) && (!client_mac || *client_mac == 0) && (!db_user || *db_user == 0) && (!os_user || *os_user == 0) && !access_protocol) {
			//
			// a shared session asked
			//
			if ((sid=findSharedSession(no_lock)) > 0) return sid;
			//
			// in case that a client asks a shared session but fails to get one due to problem,
			// the library would better try to create an personal session,
			// which is the reason why an error is not returned at this point.
			//
		}
		dgt_schar	hash_string[PSP_HS_LENGTH];
		memset(hash_string,0,PSP_HS_LENGTH);
		dgt_sint32	hval = PcaApiSession::computeHashValue(client_ip,user_id,client_program,client_mac,db_user,os_user,access_protocol,hash_string) % PSP_MAX_SESSIONS;
		if (DgcSpinLock::lock(&PoolLatch)) {
			PcaKeySvrSessionPool::logging(sid=PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
		} else {
			PcaApiSession*	api_session = ApiSessions[hval];
			while(api_session) {
				//
				// search the api session pool first with ip, uid, program
				//
				if (strncmp(api_session->hashString(), hash_string, PSP_HS_LENGTH) == 0) break;
				api_session = (PcaApiSession*)api_session->next();
			}
			DgcSpinLock::unlock(&PoolLatch);
			if (!api_session) {
				//
				// not found in the api session pool and then open a client session first
				//
				PcaSession*	pca_session = PcaSessionPool::openSession(0);
				if (pca_session) {
					sid = pca_session->sid();
					//
					// open a user session in key server
					//
					dgt_sint32	rtn = 0;
					if ((rtn=pca_session->openSession(0,"","",client_ip,db_user,os_user,client_program,access_protocol,user_id,client_mac)) >= 0) {
						if (DgcSpinLock::lock(&PoolLatch)) {
							PcaSessionPool::closeSession(sid);
							PcaKeySvrSessionPool::logging(sid=PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
						} else {
							//
							// register with the api session pool
							//
							api_session = new PcaApiSession(client_ip, user_id, client_program,client_mac,db_user,os_user,access_protocol, pca_session);
							if (ApiSessions[hval]) api_session->setNext(ApiSessions[hval]); // set it as the first node
							ApiSessions[hval] = api_session;
							DgcSpinLock::unlock(&PoolLatch);
						}
					} else {
						PcaSessionPool::closeSession(sid);
						sid = rtn;
					}
				} else sid = PSP_ERR_LOCK_FAIL;
			} else sid = api_session->sid();
		}
		return sid;
	};

	inline dgt_void removeApiSession(const dgt_schar* client_ip,const dgt_schar* user_id,const dgt_schar* client_program, const dgt_schar* client_mac, const dgt_schar* db_user, const dgt_schar* os_user, dgt_uint8 access_protocol)
	{
		dgt_schar	hash_string[PSP_HS_LENGTH];
		dgt_sint32	hval = PcaApiSession::computeHashValue(client_ip,user_id,client_program,client_mac,db_user,os_user,access_protocol,hash_string) % PSP_MAX_SESSIONS;
		if (DgcSpinLock::lock(&PoolLatch)) {
			PcaKeySvrSessionPool::logging(PSP_ERR_LOCK_FAIL,"locking the api session pool failed");
		} else {
			PcaApiSession*     prev = 0;
	                PcaApiSession*     curr = ApiSessions[hval];
			dgt_sint32	sid = -1;
			while(curr) {
				if (strncmp(curr->hashString(), hash_string, PSP_HS_LENGTH) == 0) {
					//
					// found and remove a api session
					//
					if (prev) prev->setNext(curr->next());
					else ApiSessions[hval] = (PcaApiSession*)curr->next();
					curr->setNext();
					sid = curr->sid();
					delete curr;
					break;
				}
				prev = curr;
				curr = (PcaApiSession*)curr->next();
			}
			DgcSpinLock::unlock(&PoolLatch);
			//
			// close a client session
			//
			if (sid >= 0) PcaSessionPool::closeSession(sid);
		}
	};
  protected:
  public:
	PcaApiSessionPool();
	virtual ~PcaApiSessionPool();

	static inline dgt_sint32 initialize(dgt_schar* info_file_path=0,const dgt_schar* credentials_pw=0)
        {
                return PcaSessionPool::initialize(info_file_path,credentials_pw);
        };

	static inline dgt_sint32 getApiSession(const dgt_schar* client_ip, const dgt_schar* user_id, const dgt_schar* client_program, const dgt_schar* client_mac, const dgt_schar* db_user, const dgt_schar* os_user, dgt_uint8 access_protocol, dgt_uint8 no_lock=0)
	{
#ifdef hpux11
		if (ApiSessionPool == 0) ApiSessionPool = new PcaApiSessionPool();
		return ApiSessionPool->findApiSession(client_ip, user_id, client_program,client_mac,db_user,os_user,access_protocol,no_lock);
#else
		return ApiSessionPool.findApiSession(client_ip, user_id, client_program,client_mac,db_user,os_user,access_protocol,no_lock);
#endif
	};

	static inline dgt_void returnApiSession(dgt_sint32 sid)
	{
#ifdef hpux11
		if (ApiSessionPool == 0) ApiSessionPool = new PcaApiSessionPool();
		return ApiSessionPool->returnSharedSession(sid);
#else
		return ApiSessionPool.returnSharedSession(sid);
#endif
	};

	static inline PcaApiSession* getApiSession(dgt_sint32 sid)
	{
		PcaSession*	pca_session = PcaSessionPool::getSession(sid);
		if (pca_session) return (PcaApiSession*)pca_session->parentLink();
		return 0;
	};

	static inline void closeApiSession(const dgt_schar* client_ip, const dgt_schar* user_id, const dgt_schar* client_program, const dgt_schar* client_mac, const dgt_schar* db_user, const dgt_schar* os_user, dgt_uint8 access_protocol)
	{
#ifdef hpux11
		if (ApiSessionPool == 0) ApiSessionPool = new PcaApiSessionPool();
		ApiSessionPool->removeApiSession(client_ip, user_id, client_program, client_mac, db_user, os_user, access_protocol);
#else
		ApiSessionPool.removeApiSession(client_ip, user_id, client_program, client_mac,db_user,os_user,access_protocol);
#endif
	};

	static dgt_sint32 putKeyInfo(const dgt_schar* key_info_buffer,dgt_uint32 buffer_len,const dgt_schar* passwd)
	{
		return PcaSessionPool::putKeyInfo(key_info_buffer,buffer_len,passwd);
	}

// added by chchung 2017.10.17 for altibase rdbms
	static inline PcaNamePool* namePool()
	{
		return PcaSessionPool::namePool();
	};

};


#endif
