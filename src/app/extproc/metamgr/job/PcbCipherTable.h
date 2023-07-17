/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PcbCipherTable
 *   Implementor        :       Jaehun
 *   Create Date        :       2012. 1. 26
 *   Description        :
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCB_CIPHER_TABLE_H
#define PCB_CIPHER_TABLE_H


#include "DgcLinkInfo.h"
#include "PcbCipherColumn.h"
#include "PcTableType.h"
//#include "Petra4TableType.h"

static const dgt_uint8	PCB_DECRYPT_FLAG_ENCRYPT=0;
static const dgt_uint8	PCB_DECRYPT_FLAG_DECRYPT=1;
static const dgt_uint8	PCB_DECRYPT_FLAG_NULLUPDATE=2;
static const dgt_uint8	PCB_DECRYPT_FLAG_VERIFICATION=10;

class PcbCipherTable : public DgcObject {
  private:
	static const dgt_uint16	PCB_MAX_CIPHER_COLUMNS=100;

	dgt_sint64		EncTableID;		// encryption table id
	dgt_uint8		DecryptFlag;		// decrypt flag 0:encrypt / 1:decrypt / 2:null update
	pct_type_enc_table	EncTable;		// encrypt table row
	pct_type_enc_schema	EncSchema;		// encrypt schema row
	pct_type_db_agent 		DbAgent;
	pt_type_database	EncDatabase;		// encrypt database row
	DgcLinkInfo		SchemaLinkInfo;		// link info for schema link
	pt_database_link_info*	LinkInfo;		// link info structure
	dgt_uint16		NumColumns;		// the number of encrypted columns
	dgt_uint16		NumIndexes;		// the number of encrypted index columns
	PcbCipherColumn*	CipherColumns[PCB_MAX_CIPHER_COLUMNS]; // cipher columns
	dgt_schar*		QueryText;
  protected:
  public:
        PcbCipherTable(dgt_sint64 enc_table_id,dgt_uint8 decrypt_flag=0);
        virtual ~PcbCipherTable();

    	static inline dgt_uint32 maxColumns() { return PCB_MAX_CIPHER_COLUMNS; };

    	inline dgt_uint8 getDecryptFlag() { return DecryptFlag; };
    	inline pt_database_link_info* linkInfo() { return LinkInfo; };
    	inline dgt_uint16 numColumns() { return NumColumns; };
    	inline dgt_uint16 numIndexes() { return NumIndexes; };
    	inline PcbCipherColumn* cipherColumn(dgt_uint16 idx) { if (idx < (NumColumns+NumIndexes)) return CipherColumns[idx]; else return 0; };
    	inline const dgt_uint8 encType() { return EncTable.enc_type; };
    	inline const dgt_schar* encTabName() { return EncTable.renamed_tab_name; };
    	inline const dgt_schar* tableName() { return EncTable.table_name; };
    	inline const dgt_schar* schemaName() { return EncSchema.schema_name; };
    	inline const dgt_uint8 dbmsType() { return EncDatabase.db_type; };
    	inline const dgt_sint64 encTabId() { return EncTable.enc_tab_id; };
    	inline pct_type_db_agent* getDbAgent() {return &DbAgent; };

	//
	// get encryption table info, schema table, schema link info, create PcbCipherColumns
	//
	dgt_sint32	initialize() throw(DgcExcept);
	dgt_sint32	encrypt(PcbDataChunk* data_chunk) throw(DgcExcept);
	dgt_sint32	decrypt(PcbDataChunk* data_chunk) throw(DgcExcept);
};


#endif
