/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcbCipherColumn
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCB_CIPHER_COLUMN_H
#define PCB_CIPHER_COLUMN_H


#include "PcbDataChunk.h"
#include "DgcExcept.h"
#include "PccTableTypes.h"
#include "PciCryptoIf.h"
#include "PciCipherColumn.h"


class PcbCipherColumn : public PciCipherColumn {
  private:
	dgt_sint64		EncColumnID;
	pct_type_enc_column	EncColumn;
	pct_type_encrypt_key	EncKey;
	dgt_uint8		Key[64];
	PCI_Context		CipherContext;
	dgt_uint16		IdxColumnOrder;
	dgt_uint8		DomainIndexFlag;
  protected:
  public:
	static const dgt_sint8	PCB_COL_TYPE_2CHR=0;
	static const dgt_sint8	PCB_COL_TYPE_CHR=1;
	static const dgt_sint8	PCB_COL_TYPE_NUM=2;
	static const dgt_sint8	PCB_COL_TYPE_DATE=3;
	static const dgt_sint8	PCB_COL_TYPE_BIN=4;

        PcbCipherColumn(dgt_sint64 enc_col_id);
        virtual ~PcbCipherColumn();
        inline dgt_void setIdxColumnOrder(dgt_uint16 idx_column_order) { IdxColumnOrder=idx_column_order; };
        inline dgt_uint16 getIdxColumnOrder() { return IdxColumnOrder; };

	inline dgt_sint64 encColumnID() { return EncColumnID; };
	inline const dgt_schar* columnName() { return EncColumn.column_name; };
	inline const dgt_schar* encColName() { return EncColumn.renamed_col_name; };
	inline const dgt_schar* indexColName() { return EncColumn.index_col_name; };
	inline dgt_uint8 isTextEncoded() { return EncKey.b64_txt_enc_flag; };

	inline const pct_type_enc_column* getEncColumn() { return &EncColumn; };
	inline const pct_type_encrypt_key* getEncKey() { return &EncKey; };
	inline const PCI_Context* getCipherContext() { return &CipherContext; };

	dgt_sint32 initialize() throw(DgcExcept);
	dgt_sint32 initializeIndexColumns(const pct_type_enc_column*	enc_column,const pct_type_encrypt_key* enc_key,const PCI_Context* cipher_context ) throw(DgcExcept);
	dgt_uint8  colType();

	virtual dgt_uint32 encryptLength(dgt_sint32 src_len);
	virtual dgt_sint32 encrypt(PcbDataColumn* data_column) throw(DgcExcept);
	virtual dgt_sint32 decrypt(PcbDataColumn* data_column,dgt_uint8 verify_flag=0) throw(DgcExcept);

	dgt_uint32 ophuekLength(dgt_sint32 src_length, dgt_uint8 src_type);
	dgt_sint32 ophuek(PcbDataColumn* index_data_column, PcbDataColumn* data_column) throw(DgcExcept);

};


#endif
