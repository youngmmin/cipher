/*******************************************************************
 *   File Type          :       class declaration
 *   Classes            :       PccSearchEngineFactory
 *   Implementor        :       jaehun
 *   Create Date        :
 *   Description        :       consolidate manager
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#ifndef PCC_SEARCH_ENGINE_FACTORY_H
#define PCC_SEARCH_ENGINE_FACTORY_H

#include "DgcBgmrList.h"
#include "PccCryptBuffer.h"
#include "PccKeyMap.h"
#include "PccRegExprList.h"

static const dgt_sint32 PPE_TAG_LEN = 9;
static const dgt_schar* PPE_TAG_REG_EXPR = "<P[0-9]{2}:[0-9]{3}>";

class PccPttnSearchEngine : public DgcObject {
   private:
   protected:
    static const dgt_sint32 MAX_ENC_COLS = 100;
    dgt_sint32 MaxPatternLen;
    dgt_sint32 MaxLineLen;

    dgt_sint32 getLineHandoverSize(PccCryptBuffer* crypt_buf);

   public:
    PccPttnSearchEngine(dgt_sint32 max_pattern_len, dgt_sint32 max_line_len);
    virtual ~PccPttnSearchEngine();

    dgt_sint32 maxPatternLen() { return MaxPatternLen; }
    dgt_sint32 maxLineLen() { return MaxLineLen; }
    dgt_sint32 maxHandoverSize() {
        return MaxLineLen ? MaxLineLen : (MaxPatternLen * 2 - 1);
    }
    virtual dgt_sint32 needHandover() { return 1; }

    virtual dgt_sint32 getHandoverSize(PccCryptBuffer* crypt_buf) = 0;
    virtual dgt_sint32 patternSearch(PccCryptBuffer* crypt_buf) = 0;
};

class PccNoSearchEngine : public PccPttnSearchEngine {
   private:
   protected:
   public:
    PccNoSearchEngine() : PccPttnSearchEngine(0, 0) {}
    virtual ~PccNoSearchEngine() {}
    virtual dgt_sint32 needHandover() { return 0; }
    virtual dgt_sint32 getHandoverSize(PccCryptBuffer* crypt_buf) { return 0; }
    virtual dgt_sint32 patternSearch(PccCryptBuffer* crypt_buf) { return 0; }
};

class PccRegExprSearchEngine : public PccPttnSearchEngine {
   private:
    static const dgt_sint32 NUM_PTTN = 1;
    dgt_schar* ErrBuffer;
#ifndef WIN32
    regmatch_t PttnMatch[NUM_PTTN];
#endif
   protected:
    PccRegExprList* ExprList[MAX_ENC_COLS];
    virtual dgt_sint32 pttnSearch(dgt_schar* buf, PccSortedSegList* seg_list,
                                  dgt_uint32 buf_size, dgt_uint64 seq_no = 0);

   public:
    PccRegExprSearchEngine(dgt_sint32 max_pattern_len, dgt_sint32 max_line_len);
    virtual ~PccRegExprSearchEngine();

    dgt_sint32 addRegExpr(dgt_sint32 col_no, const dgt_schar* reg_expr,
                          dgt_schar* err_string);

    virtual dgt_sint32 getHandoverSize(PccCryptBuffer* crypt_buf);
    virtual dgt_sint32 patternSearch(PccCryptBuffer* crypt_buf);
};

class PccFormatSearchEngine : public PccPttnSearchEngine {
   private:
    static const dgt_sint32 MAX_DELIMITERS = 30;

   protected:
    dgt_uint16 CryptCols[MAX_ENC_COLS];
    dgt_uint16 NumCryptCols;
    dgt_uint8 RowDelimiterLen;
    dgt_uint8 ContinueDelimiterLen;
    dgt_uint8 IBK_flag;  // added 2017.08.14 by shson - exist history with IBK
                         // bank, check with shson
    dgt_uint32 MultiRecordLength;  // added 2017.09.12 by shson - for
                                   // milti_record_length
    dgt_uint32 HeaderLine;  // added 2017.09.12 by shson - for skip header_line
    dgt_uint32 TailLine;    // added 2017.09.12 by shson - for skip tail_line
    dgt_uint32
        HeaderSkipSize;  // added 2017.10.11 by shson - for skip header_size
    dgt_uint32 TailSkipSize;  // added 2017.10.11 by shson - for skip tail_size
    dgt_uint8 RowDelimiters[MAX_DELIMITERS];
    dgt_uint8 CRRowDelimiters[MAX_DELIMITERS];
    dgt_uint8 ContinueDelimiters[MAX_DELIMITERS];
    dgt_uint8 CRContinueDelimiters[MAX_DELIMITERS];

   public:
    PccFormatSearchEngine(dgt_sint32 max_pattern_len, dgt_sint32 max_line_len);
    virtual ~PccFormatSearchEngine();
    inline dgt_uint8 continueDelimiterLen() { return ContinueDelimiterLen; }
    inline dgt_uint8 setHeaderLine(dgt_uint32 header_line) {
        return HeaderLine = header_line;
    }
    inline dgt_uint8 setTailLine(dgt_uint32 tail_line) {
        return TailLine = tail_line;
    }
    inline dgt_uint8 setHeaderSkipSize(dgt_uint32 header_skip_size) {
        return HeaderSkipSize = header_skip_size;
    }
    inline dgt_uint8 setTailSkipSize(dgt_uint32 tail_skip_size) {
        return TailSkipSize = tail_skip_size;
    }
    inline dgt_uint8 rowDelimiterLen() { return RowDelimiterLen; }

    dgt_uint8 isRowDelimiter(dgt_uint8* cv);
    dgt_uint8 isIncludeContinueDelimiter(dgt_uint8* cv, dgt_sint32 col_len);
    dgt_sint32 addCryptColNo(dgt_uint16 col_no);
    dgt_void addRowDelimiters(const dgt_schar* row_delimiters);
    dgt_void addContinueDelimiters(const dgt_schar* continue_delimiters);
    dgt_sint32 addCryptColNos(dgt_schar* col_no_string);
    dgt_sint32 addMultiLecordLength(dgt_schar* record_length);
    dgt_sint32 getSkipSize(PccCryptBuffer* crypt_buf, dgt_sint32 start_flag);

    virtual dgt_sint32 getHandoverSize(PccCryptBuffer* crypt_buf);
};

class PccDelimiterSearchEngine : public PccFormatSearchEngine {
   private:
    static const dgt_sint32 MAX_DELIMITERS = 30;
    dgt_sint32 NumColDelimiter;
    dgt_uint8 Delimiters[MAX_DELIMITERS + 1];
    inline dgt_uint8 isDelimiter(dgt_uint8* cv) {
        dgt_schar* cp;
        cp = (dgt_schar*)cv;
        if (strncmp((dgt_schar*)Delimiters, cp,
                    strlen((dgt_schar*)Delimiters)) == 0) {
            NumColDelimiter++;
            return 1;
        }
        return 0;
    };
    inline dgt_sint32 isCryptCol(dgt_uint16 col_no) {
        for (dgt_uint16 i = 0; i < NumCryptCols; i++)
            if (CryptCols[i] == col_no) return 1;
        return 0;
    };

   protected:
   public:
    PccDelimiterSearchEngine(dgt_sint32 max_pattern_len,
                             dgt_sint32 max_line_len);
    virtual ~PccDelimiterSearchEngine();

    dgt_void addDelimiters(const dgt_schar* delimiters);
    virtual dgt_sint32 patternSearch(PccCryptBuffer* crypt_buf);
};

class PccFixedSearchEngine : public PccFormatSearchEngine {
   private:
    static const dgt_sint32 MAX_COLS = 2048;
    dgt_uint16 ColOffsets[MAX_COLS + 1];
    dgt_uint16 NumCols;
    dgt_sint32 LeadSpaceTrimFlag;
    dgt_sint32 TailSpaceTrimFlag;

   protected:
   public:
    PccFixedSearchEngine(dgt_sint32 max_pattern_len, dgt_sint32 max_line_len);
    virtual ~PccFixedSearchEngine();
    inline dgt_void setLeadSpaceTrim(dgt_sint32 flag) {
        LeadSpaceTrimFlag = flag;
    }
    inline dgt_void setTailSpaceTrim(dgt_sint32 flag) {
        TailSpaceTrimFlag = flag;
    }
    inline dgt_sint32 paramCheck(dgt_schar* err_string) {
        if (MaxLineLen == 0 && ColOffsets[NumCols])
            MaxLineLen = ColOffsets[NumCols] + rowDelimiterLen() * 3;
        if (MaxLineLen == 0) {
            sprintf(err_string, "max_line_len not defined");
            return -1;
        }
        return 0;
    }

    dgt_sint32 addColOffsets(dgt_schar* offset_string);
    dgt_sint32 addColLengths(dgt_schar* length_string);
    virtual dgt_sint32 patternSearch(PccCryptBuffer* crypt_buf);
};

class PccSearchEngineFactory : public DgcObject {
   private:
    static const dgt_sint32 MAX_ENGINES = 2048;
    static const dgt_sint32 MAX_REG_EXPR = 200;

    PccKeyMap& KeyMap;
    dgt_sint32 CryptMode;
    dgt_sint32 DetectMode;
    dgt_sint32 MaxLineLen;
    dgt_sint32 MaxPatternLen;
    dgt_sint64 MaxDetection;
    dgt_sint32 EngineType;
    dgt_sint32 NumEngine;
    dgt_sint32 NumRegExpr;
    dgt_slock FactoryLock;
#if 0
	struct {
		dgt_uint16	col_no;
		dgt_schar*	expr_string;
	} RegExprs[MAX_REG_EXPR];
#else
    typedef struct {
        dgt_uint16 col_no;
        dgt_schar* expr_string;
    } psef_type_expr;

    psef_type_expr RegExprs[MAX_REG_EXPR];
#endif
    PccPttnSearchEngine* Engines[MAX_ENGINES];

   protected:
   public:
    static const dgt_sint32 FORMAT_DECRYPTOR = 1;
    static const dgt_sint32 FORMAT_ENCRYPTOR = 2;
    static const dgt_sint32 PATTERN_DECRYPTOR = 3;
    static const dgt_sint32 PATTERN_ENCRYPTOR = 4;
    static const dgt_sint32 WHOLE_DECRYPTOR = 5;
    static const dgt_sint32 WHOLE_ENCRYPTOR = 6;
    static const dgt_sint32 WHOLE_MIGRATOR = 7;

    PccSearchEngineFactory(PccKeyMap& key_map, const dgt_schar* crypt_mode = 0);
    virtual ~PccSearchEngineFactory();

    inline dgt_sint32 cryptMode() { return CryptMode; };
    inline dgt_sint32 detectMode() { return DetectMode; };
    inline dgt_sint32 maxLineLen() { return MaxLineLen; };
    inline dgt_sint32 maxPatternLen() { return MaxPatternLen; };
    inline dgt_sint64 maxDetection() { return MaxDetection; };
    inline dgt_sint32 engineType() { return EngineType; };
    inline dgt_sint32 numEngine() { return NumEngine; };
    inline dgt_sint32 numRegExpr() { return NumRegExpr; };
    psef_type_expr* regExpr(dgt_sint32 idx) { return &RegExprs[idx]; };

    dgt_void setCryptMode(const dgt_schar* crypt_mode);
    dgt_void setDetectMode(dgt_sint32 detect_mode) {
        DetectMode = detect_mode;
    };
    dgt_void setMaxDetection(dgt_sint64 max_detection) {
        MaxDetection = max_detection;
    };
    dgt_sint32 initDelimiter(DgcBgrammer* dg, dgt_schar* err_string);
    dgt_sint32 initFixed(DgcBgrammer* dg, dgt_schar* err_string);
    dgt_sint32 initRegular(DgcBgrammer* dg, dgt_schar* err_string);

    PccPttnSearchEngine* getEngine();
};

#endif
