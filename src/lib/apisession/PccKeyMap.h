#ifndef PCC_KEY_MAP_H
#define PCC_KEY_MAP_H

#include "DgcWorker.h"

class PccKeyMap : public DgcObject {
  private :
	static const dgt_sint32 MAX_COLS = 2048;
	const dgt_schar*	KeyMap[MAX_COLS];
	dgt_sint64		VirtualKeyMap[MAX_COLS];
	dgt_uint16		OutColLengths[MAX_COLS];
	dgt_uint8		KeyType;

	const dgt_schar*		InputFileNamePtr;	// for virtual key priv
	dgt_schar		HostName[65];
	dgt_schar		OsUser[65];
  protected :
  public :
	PccKeyMap();
	virtual ~PccKeyMap();
	inline dgt_uint8 keyType() { return KeyType; };
	inline const dgt_schar* inputFileNamePtr() { return InputFileNamePtr; };
	inline const dgt_schar* hostName() { return HostName; };
	inline const dgt_schar* osUser() { return OsUser; };

	dgt_sint32 maxCols() { return MAX_COLS; }
	dgt_uint16 outColLength(dgt_uint16 col_no) { if (col_no && col_no < MAX_COLS) return OutColLengths[col_no-1]; return 0; }

	dgt_void addKeyMap(const dgt_schar* enc_name,dgt_schar* col_string);
	dgt_void addVirtualKeyMap(dgt_sint64 vkey_id,dgt_schar* col_string);
	dgt_sint32 addOutColLengths(dgt_schar* length_string);
	const dgt_schar* encName(dgt_uint16 col_no);
	dgt_sint64 virtualKeyID(dgt_uint16 col_no);
	dgt_void setVKeyTargetEnv(const dgt_schar* target_file);
};

#endif
