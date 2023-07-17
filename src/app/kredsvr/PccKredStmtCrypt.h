/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccKredStmtCrypt
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 4. 30
 *   Description        :       KRED statement
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef DGC_KRED_STMT_CRYPT_H
#define DGC_KRED_STMT_CRYPT_H


#include "PccKredStmt.h"
#include "PciCryptoIf.h"
#include "PccTableTypes.h"

typedef struct {
        dgt_sint64      key_id;
        dgt_sint64      last_update;         /* sync watch */
        dgt_sint64      coupon_id;           /* coupon ID from PCT_ENC_COUPON */
        dgt_uint32      enc_length;          /* encryption length */
        dgt_uint16      key_no;              /* Key no in key set ranging from 0 to 1792 */
        dgt_uint16      key_size;            /* Key Size in bits, 128, 192, 256, 384(sha only), 512(sha only)  */
        dgt_uint8       cipher_type ;        /* 0:default, 1:'AES', 2:'SEED', 3:'ARIA', 3:'SHA' */
        dgt_uint8       enc_mode;            /* Encrypt Mode, 0:ECB, 1:CBC, 2:CFB, 3:OFB */
        dgt_uint8       iv_type;             /* initial vector type, 0:no iv, 1:random iv, 2:random within predefined iv, 3-7:predefined iv */
        dgt_uint8       n2n_flag;            /* null to null flag */
        dgt_uint8       b64_txt_enc_flag;    /* base64 text encoding flag */
        dgt_uint8       enc_start_pos;       /* encryption start position */
        dgt_schar       key_name[33];
        dgt_schar       mask_char[33];       /* mask character string for selecting with no privilige */
        dgt_schar       char_set[33];        /* character set from PT_CHAR_SET_LIST */
	dgt_uint32	expire_date;
        dgt_uint8       expire_action; 
        dgt_schar       reserved[33];       /* reserved */
        dgt_sint8       coupon_type;       /* coupon_type */
        dgt_sint32      data_length;       /* data_length */
} pct_type_key_coupon;


class PccKredStmtCrypt : public PccKredStmt {
  private:
	dgt_uint32		NumRtnRows;	// the number of return rows
	PCI_Context		Context;	// crypto context
	dgt_sint32		MsgType;	// crypt message type
	dgt_sint64		EncColID;	// encryption column ID
	dgt_uint8		Key[64];	// key
	pct_type_key_coupon	KeyRow;		// key row
	dgt_uint8*		SrcData;	// source data buffer
	dgt_sint32		SrcLen;		// source data buffer length
	dgt_uint8*		DstData;	// destination data buffer
	dgt_uint32		DstLen;		// destination data buffer length
	dgt_uint32		RtnLen;		// return data length
	DgcSqlStmt*		SqlStmt;	// sql statement to fetch key row
	dgt_uint8		RtnRowData[PCI_CRYPT_COL_LEN];

  protected:
  public:
	PccKredStmtCrypt(DgcPhyDatabase* pdb,DgcSession* session,DgcSqlTerm* stmt_term);
	virtual ~PccKredStmtCrypt();

	virtual dgt_sint32	execute(DgcMemRows* mrows=0,dgt_sint8 delete_flag=1) throw(DgcLdbExcept,DgcPdbExcept);
	virtual dgt_uint8*      fetch() throw(DgcLdbExcept,DgcPdbExcept);

};


#endif
