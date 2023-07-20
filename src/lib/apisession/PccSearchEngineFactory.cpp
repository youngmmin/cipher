/*******************************************************************
 *   File Type          :       class definition
 *   Classes            :       PccSearchEngineFactory
 *   Implementor        :       jaehun
 *   Create Date        :
 *   Description        :       consolidate manager
 *   Modification history
 *   date                    modification
--------------------------------------------------------------------

********************************************************************/
#if 0
#define DEBUG
#endif

#include "PccSearchEngineFactory.h"

// pttn search engine
PccPttnSearchEngine::PccPttnSearchEngine(dgt_sint32 max_pattern_len,
                                         dgt_sint32 max_line_len)
    : MaxPatternLen(max_pattern_len), MaxLineLen(max_line_len) {}

PccPttnSearchEngine::~PccPttnSearchEngine() {}

dgt_sint32 PccPttnSearchEngine::getLineHandoverSize(PccCryptBuffer* crypt_buf) {
    dgt_sint32 handover_size = 0;
    for (dgt_sint32 i = 1; i < crypt_buf->SrcLength; i++) {
        if (*(crypt_buf->SrcDataPtr + crypt_buf->SrcLength - i) == '\n') {
            handover_size = i - 1;
            break;
        }
    }
    return handover_size;
}

// reg_expr search engine
PccRegExprSearchEngine::PccRegExprSearchEngine(dgt_sint32 max_pattern_len,
                                               dgt_sint32 max_line_len)
    : PccPttnSearchEngine(max_pattern_len, max_line_len) {
    ErrBuffer = new dgt_schar[MAX_ERR_STRING];
    for (dgt_sint32 i = 0; i < MAX_ENC_COLS; i++) ExprList[i] = 0;
}

PccRegExprSearchEngine::~PccRegExprSearchEngine() {
    if (ErrBuffer) delete ErrBuffer;
    for (dgt_sint32 i = 0; i < MAX_ENC_COLS; i++) delete ExprList[i];
}

dgt_sint32 PccRegExprSearchEngine::pttnSearch(dgt_schar* buf,
                                              PccSortedSegList* seg_list,
                                              dgt_uint32 buf_size,
                                              dgt_uint64 seq_no) {
    exp_type* preg;
    dgt_sint32 num_pttn = 0;
    dgt_sint32 pttn_len = 0;
    dgt_uint32 buf_offset = 0;
    dgt_schar* working_buf = buf;

    while (1) {
        for (dgt_uint16 col_no = 0; col_no < MAX_ENC_COLS; col_no++) {
            dgt_sint32 expr_no = -1;
            if (ExprList[col_no]) {
                ExprList[col_no]->rewind();
                while ((preg = ExprList[col_no]
                                   ->nextPttn())) {  // each regular expression
                    expr_no++;
                    dgt_schar* str = working_buf;  // search target string
                    dgt_sint32 str_os =
                        buf_offset;  // search target string offset
// printf("str [%s], str_os [%d] strlen(str)
// [%d]\n",str,str_os,(dgt_sint32)strlen(str));
#ifndef WIN32
                    for (; str;) {
                        int errcode;
                        if ((errcode = regexec(&preg->reg, str, NUM_PTTN,
                                               PttnMatch, 0))) {
                            if (errcode != REG_NOMATCH) {
                                memset(ErrBuffer, 0, MAX_ERR_STRING);
                                regerror(errcode, &preg->reg, ErrBuffer,
                                         MAX_ERR_STRING - 1);
                                DgcWorker::PLOG.tprintf(
                                    0, "regexec failed:[%s]\n", ErrBuffer);
                            }
                            str = 0;
                        } else {
                            dgt_sint32 i;
                            for (i = 0; i < NUM_PTTN; i++) {
                                if (PttnMatch[i].rm_so >= 0) {
                                    // found a pattern text segment
                                    seg_list->add(new PccSegment(
                                        PttnMatch[i].rm_so + str_os,
                                        PttnMatch[i].rm_eo + str_os,
                                        PccSegment::SEG_T_PTTN, col_no + 1,
                                        expr_no, (dgt_schar*)preg->exp));
                                    num_pttn++;
                                    pttn_len =
                                        PttnMatch[i].rm_eo - PttnMatch[i].rm_so;
                                }
                            }
                            str = str + PttnMatch[NUM_PTTN - 1].rm_eo;
                            str_os += PttnMatch[NUM_PTTN - 1].rm_eo;
                        }
                    }
#else  // WIN32 else
#ifdef KERNEL_MODE
                    // not using in kernel mode
#else  // KERNEL_MODE else
                    try {
                        std::tr1::smatch m;
                        std::string tmp_str(str);
                        std::tr1::regex pattern(preg->exp);
                        while (std::tr1::regex_search(tmp_str, m, pattern)) {
                            // found a pattern text segment
                            std::string tmp = m[0];
                            seg_list->add(new PccSegment(
                                m.position() + str_os,
                                m.position() + tmp.length() + str_os,
                                PccSegment::SEG_T_PTTN, col_no + 1));
                            num_pttn++;
                            tmp_str = m.suffix();
                            str = str + m.position() + tmp.length();
                            str_os += m.position() + tmp.length();
                        }
                    } catch (const std::tr1::regex_error& rerr) {
                        DgcWorker::PLOG.tprintf(0, "std::tr1::regex_error\n");
                        str = 0;
                    }
#endif  // KERNEL_MODE end
#endif  // WIN32 end
                }  // while
            }      // if
        }          // for
        buf_offset += strlen(working_buf) + 1;
        if (buf_size <= buf_offset)
            break;
        else
            working_buf = buf + buf_offset;
    }  // while(1)
    return num_pttn;
}

dgt_sint32 PccRegExprSearchEngine::addRegExpr(dgt_sint32 col_no,
                                              const dgt_schar* reg_expr,
                                              dgt_schar* err_string) {
    if (col_no >= MAX_ENC_COLS)
        return 0;  // column number out of MAX_ENC_COLS, which case is
                   // automatically discarded
    if (ExprList[col_no - 1] == 0) ExprList[col_no - 1] = new PccRegExprList();
    return ExprList[col_no - 1]->compileStr(reg_expr, err_string);
}

dgt_sint32 PccRegExprSearchEngine::getHandoverSize(PccCryptBuffer* crypt_buf) {
    //	if (MaxLineLen && crypt_buf->SrcLength >= MaxLineLen) return
    //getLineHandoverSize(crypt_buf);
    dgt_sint32 handover_size = 0;
    handover_size = getLineHandoverSize(crypt_buf);
    if (handover_size) return handover_size;

    if (MaxPatternLen && crypt_buf->SrcLength >= MaxPatternLen) {
        //
        // "MaxLineLen > 0" or "MaxPatternLen == 0" means there's no split
        // pattern
        //
        if (crypt_buf->SegList == 0)
            crypt_buf->SegList = new PccSortedSegList();
        //
        // split pattern search
        //
        dgt_sint32 split_pttn_area_offset =
            (crypt_buf->SrcLength - (MaxPatternLen * 2 - 1));
        dgt_schar* split_pttn_area =
            (dgt_schar*)crypt_buf->SrcDataPtr + split_pttn_area_offset;
        if (pttnSearch(split_pttn_area, crypt_buf->SegList,
                       crypt_buf->SrcLength - split_pttn_area_offset,
                       crypt_buf->SeqNo)) {
            //
            // there could be multiple patterns in the split pattern area
            //
            PccSegment* seg;
            dgt_sint32 handover_offset = 0;
            crypt_buf->FirstSplitPttnOffset = crypt_buf->SrcLength;
            crypt_buf->SegList->rewind();
            while ((seg = crypt_buf->SegList->next())) {
                seg->adjustsOffset(split_pttn_area_offset);
                seg->adjusteOffset(split_pttn_area_offset);
                if (crypt_buf->FirstSplitPttnOffset > seg->sOffset())
                    crypt_buf->FirstSplitPttnOffset = seg->sOffset();
                if (handover_offset < seg->eOffset())
                    handover_offset = seg->eOffset();
            }
            handover_size = crypt_buf->SrcLength - handover_offset;
            crypt_buf->FirstSplitPttnChar =
                *(crypt_buf->SrcDataPtr + crypt_buf->FirstSplitPttnOffset);
            *(crypt_buf->SrcDataPtr + crypt_buf->FirstSplitPttnOffset) =
                0;  // from prevent double pattern search
        } else {
            // not found
            handover_size = MaxPatternLen - 1;
        }
    }
    return handover_size;
}

dgt_sint32 PccRegExprSearchEngine::patternSearch(PccCryptBuffer* crypt_buf) {
    if (crypt_buf->SegList == 0) crypt_buf->SegList = new PccSortedSegList();

    dgt_sint32 num_pttn =
        pttnSearch((dgt_schar*)crypt_buf->SrcDataPtr, crypt_buf->SegList,
                   crypt_buf->SrcLength, crypt_buf->SeqNo);
    crypt_buf->SegList->complete(crypt_buf->SrcLength);
    if (crypt_buf->FirstSplitPttnChar)
        *(crypt_buf->SrcDataPtr + crypt_buf->FirstSplitPttnOffset) =
            crypt_buf->FirstSplitPttnChar;
    return num_pttn;
}

// format search engine
PccFormatSearchEngine::PccFormatSearchEngine(dgt_sint32 max_pattern_len,
                                             dgt_sint32 max_line_len)
    : PccPttnSearchEngine(max_pattern_len, max_line_len),
      NumCryptCols(0),
      RowDelimiterLen(0),
      ContinueDelimiterLen(0),
      IBK_flag(0),
      MultiRecordLength(0),
      HeaderLine(0),
      TailLine(0),
      HeaderSkipSize(0),
      TailSkipSize(0) {}

PccFormatSearchEngine::~PccFormatSearchEngine() {}

dgt_uint8 PccFormatSearchEngine::isRowDelimiter(dgt_uint8* cv) {
    dgt_schar* cp;
    cp = (dgt_schar*)cv;
#if 0
	if (strlen(cp) < RowDelimiterLen)
		return 1;
#endif
    if (strncmp((dgt_schar*)RowDelimiters, cp,
                strlen((dgt_schar*)RowDelimiters)) == 0) {
        IBK_flag = 1;
        return 1;
    }
    //*************************important***************************************
    //*************************important***************************************
    // added 2017.08.14 by shson - exist history with IBK bank, check with shson
    if (IBK_flag == 0) {
        if (strncmp((dgt_schar*)CRRowDelimiters, cp,
                    strlen((dgt_schar*)CRRowDelimiters)) == 0) {
            memcpy(RowDelimiters, CRRowDelimiters, sizeof(RowDelimiters));
            RowDelimiterLen = strlen((dgt_schar*)CRRowDelimiters);
            memcpy(ContinueDelimiters, CRContinueDelimiters,
                   sizeof(ContinueDelimiters));
            ContinueDelimiterLen = strlen((dgt_schar*)CRContinueDelimiters);
            IBK_flag = 1;
            return 1;
        }
    }

    // dgt_uint8* cp;
    // for(dgt_sint32 i=0; i<MAX_DELIMITERS && (cp=*(Delimiters+i)); i++) if (cp
    // == cv) return 1;
    return 0;
}

dgt_uint8 PccFormatSearchEngine::isIncludeContinueDelimiter(
    dgt_uint8* cv, dgt_sint32 col_len) {
    if (strlen((dgt_schar*)ContinueDelimiters) == 0) return 0;
    dgt_schar* cp;
    cp = (dgt_schar*)cv;
    // printf("cv [%s] return
    // [%d]\n",cp,strncmp((dgt_schar*)ContinueDelimiters,cp,strlen((dgt_schar*)ContinueDelimiters)));
    if (strncmp((dgt_schar*)ContinueDelimiters, cp,
                strlen((dgt_schar*)ContinueDelimiters)) == 0) {
        IBK_flag = 1;
        return 1;  //[continue delimiter]column
    }
    if (strncmp((dgt_schar*)ContinueDelimiters,
                cp + col_len - strlen((dgt_schar*)ContinueDelimiters),
                strlen((dgt_schar*)ContinueDelimiters)) == 0) {
        IBK_flag = 1;
        return 2;  //[continue delimiter]column
    }
#if 0
	//*************************important***************************************
	//*************************important***************************************
//added 2017.08.14 by shson - exist history with IBK bank, check with shson
	if (IBK_flag == 0) {
		if (strncmp((dgt_schar*)CRContinueDelimiters,cp,strlen((dgt_schar*)CRContinueDelimiters)) == 0 ||
				strncmp((dgt_schar*)CRContinueDelimiters,cp +col_len-strlen((dgt_schar*)CRContinueDelimiters),strlen((dgt_schar*)CRContinueDelimiters)) == 0) {
			printf("CrContinueDelimiters in \n");
			memcpy(RowDelimiters, CRRowDelimiters, sizeof(RowDelimiters));
			RowDelimiterLen = strlen((dgt_schar*)CRRowDelimiters);
			memcpy(ContinueDelimiters, CRContinueDelimiters, sizeof(ContinueDelimiters));
			ContinueDelimiterLen = strlen((dgt_schar*)CRContinueDelimiters);
			IBK_flag = 1;
			if (strncmp((dgt_schar*)CRContinueDelimiters,cp,strlen((dgt_schar*)CRContinueDelimiters)) == 0)
				return 1;
			else return 2;
		}
	}
#endif
    // dgt_uint8* cp;
    // for(dgt_sint32 i=0; i<MAX_DELIMITERS && (cp=*(Delimiters+i)); i++) if (cp
    // == cv) return 1;
    return 0;
}
dgt_sint32 PccFormatSearchEngine::addCryptColNo(dgt_uint16 col_no) {
    if (col_no && NumCryptCols < MAX_ENC_COLS)
        CryptCols[NumCryptCols++] = col_no;
    return NumCryptCols;
}

dgt_void PccFormatSearchEngine::addRowDelimiters(
    const dgt_schar* row_delimiters) {
    memset(RowDelimiters, 0, MAX_DELIMITERS);
    memset(CRRowDelimiters, 0, MAX_DELIMITERS);
    // added by shson 2017.08.01 for IBK - delimiter + line feed format apply
    dgt_schar tmp_delimiter[MAX_DELIMITERS];
    memset(tmp_delimiter, 0, MAX_DELIMITERS);
    memcpy(tmp_delimiter, row_delimiters, strlen(row_delimiters));
    for (dgt_sint32 i = 0; tmp_delimiter[i] != 0x00; i++) {
        if (tmp_delimiter[i] == '\\') {  // convert escape character
            if (tmp_delimiter[i + 1] == 'n') {
                tmp_delimiter[i] = '\n';
            } else if (tmp_delimiter[i + 1] == 'r') {
                tmp_delimiter[i] = '\r';
            }
            for (dgt_sint32 idx = i + 1; idx < MAX_DELIMITERS - 2;
                 idx++)  // pull up tmp_delimiter
            {
                tmp_delimiter[idx] = tmp_delimiter[idx + 1];
            }
        }  // if (tmp_delimiter[i] == '\\' ) end
    }      // for(dgt_sint32 i = 0 ; tmp_delimiter[i] != 0x00 ; i++) end
    memcpy(RowDelimiters, tmp_delimiter, MAX_DELIMITERS);
    RowDelimiterLen = strlen((dgt_schar*)RowDelimiters);
    //*************************important***************************************
    // added 2017.08.14 by shson - exist history with IBK bank, check with shson
    if (RowDelimiters[RowDelimiterLen - 1] == '\n') {
        memcpy(CRRowDelimiters, RowDelimiters, RowDelimiterLen);
        CRRowDelimiters[RowDelimiterLen - 1] = '\r';
        CRRowDelimiters[RowDelimiterLen] = '\n';
    } else
        IBK_flag = 1;
}

dgt_void PccFormatSearchEngine::addContinueDelimiters(
    const dgt_schar* continue_delimiters) {
#ifndef WIN32
    if (continue_delimiters == nul) return;
#else
    if (continue_delimiters == NULL) return;
#endif
    memset(ContinueDelimiters, 0, MAX_DELIMITERS);
    memset(CRContinueDelimiters, 0, MAX_DELIMITERS);
    // added by shson 2017.08.01 for IBK - delimiter + line feed format apply
    dgt_schar tmp_delimiter[MAX_DELIMITERS];
    memset(tmp_delimiter, 0, MAX_DELIMITERS);
    memcpy(tmp_delimiter, continue_delimiters, strlen(continue_delimiters));
    for (dgt_sint32 i = 0; tmp_delimiter[i] != 0x00; i++) {
        if (tmp_delimiter[i] == '\\') {  // convert escape character
            if (tmp_delimiter[i + 1] == 'n') {
                tmp_delimiter[i] = '\n';
            } else if (tmp_delimiter[i + 1] == 'r') {
                tmp_delimiter[i] = '\r';
            }
            for (dgt_sint32 idx = i + 1; idx < MAX_DELIMITERS - 2;
                 idx++)  // pull up tmp_delimiter
            {
                tmp_delimiter[idx] = tmp_delimiter[idx + 1];
            }
        }  // if (tmp_delimiter[i] == '\\' ) end
    }      // for(dgt_sint32 i = 0 ; tmp_delimiter[i] != 0x00 ; i++) end
    memcpy(ContinueDelimiters, tmp_delimiter, MAX_DELIMITERS);
    ContinueDelimiterLen = strlen((dgt_schar*)ContinueDelimiters);
    //*************************important***************************************
    // added 2017.08.14 by shson - exist history with IBK bank, check with shson
    if (ContinueDelimiters[ContinueDelimiterLen - 1] == '\n') {
        memcpy(CRContinueDelimiters, ContinueDelimiters, ContinueDelimiterLen);
        CRContinueDelimiters[ContinueDelimiterLen - 1] = '\r';
        CRContinueDelimiters[ContinueDelimiterLen] = '\n';
    }
#if 0
#ifndef WIN32
	if (continue_delimiters == nul)
#else
	if (continue_delimiters == NULL)
#endif
		return;
	memset(ContinueDelimiters,0,MAX_DELIMITERS);
	// added by shson 2017.08.01 for IBK - delimiter + line feed format apply
	for(dgt_sint32 i = 0 ; *(continue_delimiters+i) != 0x00 ; i++)
	{
		if (strcmp(continue_delimiters+i, "\\n") == 0 ) {
			strncpy((dgt_schar*)ContinueDelimiters,continue_delimiters,strlen(continue_delimiters)-2);
			strcat((dgt_schar*)ContinueDelimiters,"\n");
			ContinueDelimiterLen = strlen((dgt_schar*)ContinueDelimiters);
			return;
		}
	} //for end
	strncpy((dgt_schar*)ContinueDelimiters,continue_delimiters,MAX_DELIMITERS);
	ContinueDelimiterLen = strlen((dgt_schar*)ContinueDelimiters);
#endif
}

dgt_sint32 PccFormatSearchEngine::addCryptColNos(dgt_schar* col_no_string) {
    dgt_schar* last;
#ifndef WIN32
    dgt_schar* cp = strtok_r(col_no_string, " \f\n", &last);
#else
    dgt_schar* cp = strtok_s(col_no_string, " \f\n", &last);
#endif
    do {
        dgt_sint32 col_no = strtol(cp, 0, 10);
        if (col_no && NumCryptCols < MAX_ENC_COLS)
            CryptCols[NumCryptCols++] = col_no;
#ifndef WIN32
    } while ((cp = strtok_r(0, " \f\n", &last)));
#else
    } while ((cp = strtok_s(0, " \f\n", &last)));
#endif
    return NumCryptCols;
}

dgt_sint32 PccFormatSearchEngine::addMultiLecordLength(
    dgt_schar* record_length) {
    MultiRecordLength = strtol(record_length, 0, 10);
    return 0;
}

dgt_sint32 PccFormatSearchEngine::getSkipSize(PccCryptBuffer* crypt_buf,
                                              dgt_sint32 start_flag) {
    // start flag is 1, means front search to buffer head,
    // 0 is started back search to buffer tail
    dgt_uint32 skip_size = 0;
    dgt_uint32 numDelimiter = 0;
    if (start_flag == 0) {   // when last_buffer
        if (TailSkipSize) {  // when exist tail_skip_size parameter
            return TailSkipSize;
        }
        for (dgt_uint32 i = 1 /*null size*/;
             i <= (dgt_uint32)crypt_buf->SrcLength;
             i++) {  // when exist header_line parameter
            if (isRowDelimiter(crypt_buf->SrcDataPtr + crypt_buf->SrcLength -
                               i) == 1) {
                numDelimiter++;
                if (numDelimiter - 1 == TailLine) {
                    skip_size = i - rowDelimiterLen();
                    break;
                }  // if (numDelimiter -1 == TailLine) end
            }      // if (isRowDelimiter(crypt_buf->SrcDataPtr +
               // crypt_buf->SrcLength - i) end
        }  // for(dgt_sint32 i = skip_size + 1/*null size*/; i <=
           // crypt_buf->SrcLength; i++) end
    } else {                   // when first buffer
        if (HeaderSkipSize) {  // when exist header_skip_size parameter
            return HeaderSkipSize;
        }
        for (dgt_uint32 i = 0; i < (dgt_uint32)crypt_buf->SrcLength;
             i++) {  // when exist header_line parameter
            if (isRowDelimiter(crypt_buf->SrcDataPtr + i) == 1) {
                numDelimiter++;
                if (numDelimiter == HeaderLine) {
                    skip_size = i + rowDelimiterLen();
                    break;
                }  // if (numDelimiter == TailLine) end
            }      // if (isRowDelimiter(crypt_buf->SrcDataPtr + i) end
        }          // for(dgt_uint32 i = 0; i < crypt_buf->SrcLength; i++) end
    }              // else end
    return skip_size;
}

dgt_sint32 PccFormatSearchEngine::getHandoverSize(PccCryptBuffer* crypt_buf) {
    dgt_sint32 handover_size = 0;
    dgt_uint32 header_skip_size = 0;
    if (MultiRecordLength) {  // 2017.09.12 by shson for MultiRecordLength
        if (crypt_buf->SeqNo == 0 && (HeaderLine || HeaderSkipSize))
            header_skip_size = getSkipSize(crypt_buf, 1);
        handover_size =
            (crypt_buf->SrcLength - header_skip_size) % MultiRecordLength;
        return handover_size;
    }
    if (crypt_buf->LastFlag == 0) {
        for (dgt_sint32 i = 1; i <= crypt_buf->SrcLength; i++) {
            if (isRowDelimiter(crypt_buf->SrcDataPtr + crypt_buf->SrcLength -
                               i) == 1) {
                handover_size = i - rowDelimiterLen();
                break;
            }
        }  // for end
        return handover_size;
    }  // if end
    return 0;
#if 0
	if (MaxLineLen && crypt_buf->SrcLength >= MaxLineLen) return getLineHandoverSize(crypt_buf);
	return 0;
#endif
}

// delimiter search engine
PccDelimiterSearchEngine::PccDelimiterSearchEngine(dgt_sint32 max_pattern_len,
                                                   dgt_sint32 max_line_len)
    : PccFormatSearchEngine(max_pattern_len, max_line_len) {
    NumColDelimiter = 0;
    memset(Delimiters, 0, MAX_DELIMITERS);
}

PccDelimiterSearchEngine::~PccDelimiterSearchEngine() {}

dgt_void PccDelimiterSearchEngine::addDelimiters(const dgt_schar* delimiters) {
    memset(Delimiters, 0, MAX_DELIMITERS);
    strncpy((dgt_schar*)Delimiters, delimiters, MAX_DELIMITERS);
}

dgt_sint32 PccDelimiterSearchEngine::patternSearch(PccCryptBuffer* crypt_buf) {
    dgt_sint32 num_pttn = 0;          // # of found patterns
    dgt_uint16 col_no = 1;            // column number of a line
    dgt_sint32 col_len = 0;           // column length
    dgt_uint32 header_skip_size = 0;  //
    dgt_uint32 tail_skip_size = 0;    //
    dgt_sint32 col_offset = 0;
    crypt_buf->SegList = new PccSortedSegList();
    if (crypt_buf->SeqNo == 0 && (HeaderLine || HeaderSkipSize)) {
        // header skip
        header_skip_size = getSkipSize(crypt_buf, 1);
    }
    if (crypt_buf->LastFlag == 1 && (TailLine || TailSkipSize)) {
        // tail skip
        tail_skip_size = getSkipSize(crypt_buf, 0);
    }
    if ((header_skip_size + tail_skip_size) >=
        (dgt_uint32)crypt_buf->SrcLength) {  // for ibk, whole file is skiped
        crypt_buf->SegList->complete(crypt_buf->SrcLength);
        return 0;
    }
    for (dgt_sint32 col_offset = header_skip_size;
         col_offset < crypt_buf->SrcLength - (dgt_sint32)tail_skip_size;
         col_offset++) {
        dgt_uint8* cv = crypt_buf->SrcDataPtr + col_offset;
        if (isDelimiter(cv) || isRowDelimiter(cv)) {  // end of a column or line
            if (col_len && isCryptCol(col_no)) {
                dgt_uint8 except_flag =
                    0;  // 1: exist except string to front 2: exist except
                        // string to back 0: not dxist except string
                except_flag = isIncludeContinueDelimiter(cv - col_len, col_len);
                if (except_flag == 1)
                    crypt_buf->SegList->add(new PccSegment(
                        col_offset - col_len + continueDelimiterLen(),
                        col_offset, PccSegment::SEG_T_PTTN, col_no));
                else if (except_flag == 2)
                    crypt_buf->SegList->add(
                        new PccSegment(col_offset - col_len,
                                       col_offset - continueDelimiterLen(),
                                       PccSegment::SEG_T_PTTN, col_no));
                else
                    crypt_buf->SegList->add(
                        new PccSegment(col_offset - col_len, col_offset,
                                       PccSegment::SEG_T_PTTN, col_no));
                num_pttn++;
            }
            if (isRowDelimiter(cv)) {
                col_no = 1;  // end of line
                col_offset += rowDelimiterLen() - 1;
            } else {
                col_no++;  // end of column
                col_offset += strlen((dgt_schar*)Delimiters) - 1;
            }
            col_len = 0;
        } else {
            col_len++;
        }
    }
    crypt_buf->SegList->complete(crypt_buf->SrcLength);
    return NumColDelimiter == 0 ? PFC_SE_ERR_CODE_DILIMETER_NOT_FOUND
                                : num_pttn;
}

// fixed search engine
PccFixedSearchEngine::PccFixedSearchEngine(dgt_sint32 max_pattern_len,
                                           dgt_sint32 max_line_len)
    : PccFormatSearchEngine(max_pattern_len, max_line_len),
      NumCols(1),
      LeadSpaceTrimFlag(0),
      TailSpaceTrimFlag(0) {
    memset(&ColOffsets[0], 0, sizeof(ColOffsets));
}

PccFixedSearchEngine::~PccFixedSearchEngine() {}

dgt_sint32 PccFixedSearchEngine::addColOffsets(dgt_schar* offset_string) {
    dgt_schar* last;
#ifndef WIN32
    dgt_schar* cp = strtok_r(offset_string, " ,\f\n", &last);
#else
    dgt_schar* cp = strtok_s(offset_string, " ,\f\n", &last);
#endif
    do {
        dgt_uint16 col_offset = strtol(cp, 0, 10);
        if (col_offset && NumCols < MAX_COLS) {
            ColOffsets[NumCols++] = col_offset;
        }
#ifndef WIN32
    } while ((cp = strtok_r(0, " ,\f\n", &last)));
#else
    } while ((cp = strtok_s(0, " ,\f\n", &last)));
#endif
    return NumCols;
}

dgt_sint32 PccFixedSearchEngine::addColLengths(dgt_schar* length_string) {
    dgt_uint16 curr_offset = 0;
    dgt_schar* last;
#ifndef WIN32
    dgt_schar* cp = strtok_r(length_string, " ,\f\n", &last);
#else
    dgt_schar* cp = strtok_s(length_string, " ,\f\n", &last);
#endif
    do {
        dgt_uint16 col_length = strtol(cp, 0, 10);
        if (col_length && NumCols < MAX_COLS) {
            curr_offset += col_length;
            ColOffsets[NumCols++] = curr_offset;
        }
#ifndef WIN32
    } while ((cp = strtok_r(0, " ,\f\n", &last)));
#else
    } while ((cp = strtok_s(0, " ,\f\n", &last)));
#endif
    if (NumCols) NumCols--;
    return NumCols;
}

dgt_sint32 PccFixedSearchEngine::patternSearch(PccCryptBuffer* crypt_buf) {
    dgt_sint32 num_pttn = 0;  // # of found patterns
    dgt_sint32 line_offset = 0;
    if (crypt_buf->SegList == 0) crypt_buf->SegList = new PccSortedSegList();
    dgt_uint32 header_skip_size = 0;  //
    dgt_uint32 tail_skip_size = 0;    //
#if 1
    if (crypt_buf->SeqNo == 0 && (HeaderLine || HeaderSkipSize)) {
        // header_line skip
        header_skip_size = getSkipSize(crypt_buf, 1);
        line_offset = header_skip_size;
    }
    if (crypt_buf->LastFlag == 1 && (TailLine || TailSkipSize)) {
        // tail_line skip
        tail_skip_size = getSkipSize(crypt_buf, 0);
    }
    if ((header_skip_size + tail_skip_size) >=
        (dgt_uint32)crypt_buf->SrcLength) {
        crypt_buf->SegList->complete(crypt_buf->SrcLength);
        return 0;
    }
#endif
    do {
        dgt_uint16 col_soffset = 0;
        dgt_uint16 col_eoffset = 0;
        for (dgt_uint16 i = 0; i < NumCryptCols; i++) {
            col_soffset = 0;
            col_eoffset = 0;
            dgt_sint32 lsc = 0;  // lead space counter
            dgt_sint32 tsc = 0;  // tail space counter
            if (CryptCols[i] &&
                CryptCols[i] <= NumCols) {  // valid column number
                col_soffset = ColOffsets[CryptCols[i] - 1];
                if (CryptCols[i] == NumCols) {
                    // the last column is crypted column
                    if (ColOffsets[NumCols]) {
                        col_eoffset = ColOffsets[NumCols];
                    } else {
                        col_eoffset = ColOffsets[CryptCols[i] - 1];
                        while (*(crypt_buf->SrcDataPtr + line_offset +
                                 (++col_eoffset)) != '\n')
                            ;  // row end
                    }
                } else {
                    col_eoffset = ColOffsets[CryptCols[i]];
                }

                if (LeadSpaceTrimFlag) {  // leading space trimming
                    while (*(crypt_buf->SrcDataPtr + line_offset + col_soffset +
                             lsc) == ' ' &&
                           (lsc < col_eoffset - col_soffset))
                        lsc++;
                    if (lsc &&
                        (lsc < col_eoffset -
                                   col_soffset)) {  // add a passing segment for
                                                    // discarding leading space
                        crypt_buf->SegList->add(
                            new PccSegment(line_offset + col_soffset,
                                           line_offset + col_soffset + lsc,
                                           PccSegment::SEG_T_PASS));
                    }
                }
                if (TailSpaceTrimFlag) {  // tailing space trimming
                    while (*(crypt_buf->SrcDataPtr + line_offset + col_eoffset -
                             1 - tsc) == ' ' &&
                           (tsc < col_eoffset - col_soffset))
                        tsc++;
                    if (tsc &&
                        (tsc < col_eoffset -
                                   col_soffset)) {  // add a passing segment for
                                                    // discarding leading space
                        crypt_buf->SegList->add(new PccSegment(
                            line_offset + col_eoffset - tsc,
                            line_offset + col_eoffset, PccSegment::SEG_T_PASS));
                    }
                }

                if ((lsc == col_eoffset - col_soffset) ||
                    (tsc ==
                     col_eoffset - col_soffset)) {  // this case is only filled
                                                    // ' '(space) in segment
                    crypt_buf->SegList->add(new PccSegment(
                        line_offset + col_soffset, line_offset + col_eoffset,
                        PccSegment::SEG_T_PTTN_NULL, CryptCols[i]));
                } else {
                    crypt_buf->SegList->add(
                        new PccSegment(line_offset + col_soffset + lsc,
                                       line_offset + col_eoffset - tsc,
                                       PccSegment::SEG_T_PTTN, CryptCols[i]));
                }
            }  // if (CryptCols[i] && CryptCols[i] <= NumCols) end
        }      // for(dgt_uint16 i=0; i<NumCryptCols; i++) end
        line_offset += col_eoffset;
        if (MultiRecordLength == 0) {  // common case
            while ((line_offset < crypt_buf->SrcLength) &&
                   isRowDelimiter(crypt_buf->SrcDataPtr + line_offset++) != 1)
                ;  // move to the end of line
            if ((line_offset < crypt_buf->SrcLength))
                line_offset +=
                    rowDelimiterLen() -
                    1;  // move offset so rowDelimiterLen, -1 is added because
                        // of first line_offset++ to upline
        } else {  // MultiRecordLength encrypt case
            if (MultiRecordLength == header_skip_size) header_skip_size = 0;
            while ((line_offset % MultiRecordLength) != header_skip_size)
                line_offset++;  // move to the end of line
            if ((dgt_uint32)(crypt_buf->SrcLength - line_offset -
                             tail_skip_size) < MultiRecordLength)
                break;
        }
    } while (line_offset <
             crypt_buf->SrcLength - 1 - (dgt_sint32)tail_skip_size);
    crypt_buf->SegList->complete(crypt_buf->SrcLength);
    return num_pttn;
}

// factory
PccSearchEngineFactory::PccSearchEngineFactory(PccKeyMap& key_map,
                                               const dgt_schar* crypt_mode)
    : KeyMap(key_map),
      CryptMode(1),
      DetectMode(1),
      MaxLineLen(0),
      MaxPatternLen(0),
      MaxDetection(10),
      EngineType(WHOLE_ENCRYPTOR),
      NumEngine(0),
      NumRegExpr(0) {
    DgcSpinLock::unlock(&FactoryLock);
    setCryptMode(crypt_mode);
}

PccSearchEngineFactory::~PccSearchEngineFactory() {
    for (dgt_sint32 i = 0; i < NumEngine; i++) delete Engines[i];
}

dgt_void PccSearchEngineFactory::setCryptMode(const dgt_schar* crypt_mode) {
    if (crypt_mode && strlen(crypt_mode) &&
        strncasecmp(crypt_mode, "decrypt", 7) == 0) {  // when decrypt mode
        CryptMode = 0;
        // 17.06.23 shson modify for bug fix
        // after fist read searchengine parameter, read mode parameter
        // EngineType be modifed define WHOLE_ENCRYPTOR or WHOLE_DECRYPTOR
        // so add if clause of under line
        if (EngineType == WHOLE_ENCRYPTOR) EngineType = WHOLE_DECRYPTOR;

    } else if (crypt_mode && strlen(crypt_mode) &&
               strncasecmp(crypt_mode, "encrypt", 7) ==
                   0) {  // when encrypt mode
        CryptMode = 1;
    } else if (crypt_mode && strlen(crypt_mode) &&
               strncasecmp(crypt_mode, "migration", 9) ==
                   0) {  // when migration mode
        CryptMode = 3;
        EngineType = WHOLE_MIGRATOR;
    }
}

dgt_sint32 PccSearchEngineFactory::initDelimiter(DgcBgrammer* dg,
                                                 dgt_schar* err_string) {
    if (EngineType >= WHOLE_DECRYPTOR) {  // no engine defined yet
        dgt_schar* val = 0;
        dgt_sint32 max_line_len = 0;
        dgt_sint32 max_pattern_len = 0;
        if ((val = dg->getValue("delimiter.max_line_len")))
            max_line_len = strtol(val, 0, 10);
        if ((val = dg->getValue("delimiter.max_pattern_len")))
            max_pattern_len = strtol(val, 0, 10);
        if (CryptMode)
            EngineType = FORMAT_ENCRYPTOR;
        else
            EngineType = FORMAT_DECRYPTOR;
        //		if (max_line_len && max_pattern_len &&
        //(val=dg->getValue("delimiter.chars")) && strlen(val)) {
        if ((val = dg->getValue("delimiter.chars")) && strlen(val)) {
            MaxLineLen = max_line_len;
            MaxPatternLen = max_pattern_len;
            PccDelimiterSearchEngine* tmp =
                new PccDelimiterSearchEngine(MaxPatternLen, MaxLineLen);
            tmp->addDelimiters(val);
            // row delimiter set
            if ((val = dg->getValue("delimiter.row_delimiter")) && strlen(val))
                tmp->addRowDelimiters(val);
            else
                tmp->addRowDelimiters("\n");
            // except string set
            if ((val = dg->getValue("delimiter.continue_delimiter")) &&
                strlen(val))
                tmp->addContinueDelimiters(val);
            else
#ifndef WIN32
                tmp->addContinueDelimiters(nul);
#else
                tmp->addContinueDelimiters(NULL);
#endif

            if ((val = dg->getValue("delimiter.header_line")))
                tmp->setHeaderLine(strtol(val, 0, 10));
            if ((val = dg->getValue("delimiter.tail_line")))
                tmp->setTailLine(strtol(val, 0, 10));

            for (dgt_uint16 i = 1; i < KeyMap.maxCols(); i++) {
                if (KeyMap.keyType() == USE_KEY_TYPE_VIRTUAL_KEY) {
                    if (KeyMap.virtualKeyID(i)) tmp->addCryptColNo(i);
                } else {
                    if (strlen(KeyMap.encName(i))) tmp->addCryptColNo(i);
                }
            }
            Engines[NumEngine++] = tmp;
        } else {
#if 0
			if (max_line_len == 0) sprintf(err_string,"delimiter.max_line_len not defined or zero");
			else if (max_pattern_len == 0) sprintf(err_string,"delimiter.max_pattern_len not defined or zero");
			else sprintf(err_string,"delimiter.chars not defined");
#endif
            sprintf(err_string, "delimiter.chars not defined");
            return -1;
        }
    }
    return 0;
}

dgt_sint32 PccSearchEngineFactory::initFixed(DgcBgrammer* dg,
                                             dgt_schar* err_string) {
    if (EngineType >= WHOLE_DECRYPTOR) {  // no engine defined yet
        dgt_schar* val = 0;
        dgt_sint32 num = 0;
        if ((val = dg->getValue("fixed.max_line_len")) &&
            (num = strtol(val, 0, 10)))
            MaxLineLen = num;
        if ((val = dg->getValue("fixed.max_pattern_len")) &&
            (num = strtol(val, 0, 10)))
            MaxPatternLen = num;
        PccFixedSearchEngine* engine =
            new PccFixedSearchEngine(MaxPatternLen, MaxLineLen);
        if ((val = dg->getValue("fixed.col_offsets")) && strlen(val))
            engine->addColOffsets(val);
        if ((val = dg->getValue("fixed.col_lengths")) && strlen(val))
            engine->addColLengths(val);
        if ((val = dg->getValue("fixed.lead_space_trim")) &&
            strcasecmp(val, "yes") == 0)
            engine->setLeadSpaceTrim(1);
        if ((val = dg->getValue("fixed.tail_space_trim")) &&
            strcasecmp(val, "yes") == 0)
            engine->setTailSpaceTrim(1);

        // added row_delimiter and continue_delimiter by shson 2017.07.25 for
        // IBK bank row delimiter set
        if ((val = dg->getValue("fixed.row_delimiter")) && strlen(val))
            engine->addRowDelimiters(val);
        else
            engine->addRowDelimiters("\n");
        // except string set
        if ((val = dg->getValue("fixed.continue_delimiter")) && strlen(val))
            engine->addContinueDelimiters(val);
        else
#ifndef WIN32
            engine->addContinueDelimiters(nul);
#else
            engine->addContinueDelimiters(NULL);
#endif
        if ((val = dg->getValue("fixed.multi_record_length")) && strlen(val))
            engine->addMultiLecordLength(val);

        if ((val = dg->getValue("fixed.header_line")))
            engine->setHeaderLine(strtol(val, 0, 10));
        if ((val = dg->getValue("fixed.tail_line")))
            engine->setTailLine(strtol(val, 0, 10));
        if ((val = dg->getValue("fixed.header_skip_size")))
            engine->setHeaderSkipSize(strtol(val, 0, 10));
        if ((val = dg->getValue("fixed.tail_skip_size")))
            engine->setTailSkipSize(strtol(val, 0, 10));

        for (dgt_uint16 i = 1; i < KeyMap.maxCols(); i++) {
            if (KeyMap.keyType() == USE_KEY_TYPE_VIRTUAL_KEY) {
                if (KeyMap.virtualKeyID(i)) engine->addCryptColNo(i);
            } else {
                if (strlen(KeyMap.encName(i))) engine->addCryptColNo(i);
            }
        }
        if ((num = engine->paramCheck(err_string))) {
            delete engine;
            return num;
        }
        if ((val = dg->getValue("fixed.out_col_lengths")) && strlen(val))
            KeyMap.addOutColLengths(val);
        Engines[NumEngine++] = engine;
        if (CryptMode)
            EngineType = FORMAT_ENCRYPTOR;
        else
            EngineType = FORMAT_DECRYPTOR;
    }
    return 0;
}

dgt_sint32 PccSearchEngineFactory::initRegular(DgcBgrammer* dg,
                                               dgt_schar* err_string) {
    if (EngineType >= WHOLE_DECRYPTOR) {  // no engine defined yet
        dgt_schar* val = 0;
        dgt_sint32 max_line_len = 0;
        dgt_sint32 max_pattern_len = 0;
        EngineType = PATTERN_ENCRYPTOR;
        if ((val = dg->getValue("regular.max_pattern_len")))
            max_pattern_len = strtol(val, 0, 10);
        if (max_pattern_len == 0) {
#if 0
			sprintf(err_string,"regular.max_pattern_len not defined or zero");
			return -1;
#endif
            // modify by shson 18.01.11
            // no exist max_pattern_len don't error
            // default max_pattern_len is 30
            max_pattern_len = 30;
        }
        if ((val = dg->getValue("regular.max_line_len")))
            max_line_len = strtol(val, 0, 10);

        if (CryptMode) {
            dgt_sint32 rtn = 0;
            dgt_schar expr_string[32];
            dgt_sint32 col_no;
            for (col_no = 1;; col_no++) {
                dgt_sint32 expr_no;
                for (expr_no = 1;; expr_no++) {
                    sprintf(expr_string, "regular.%d.%d", col_no, expr_no);
                    if ((val = dg->getValue(expr_string))) {
                        RegExprs[NumRegExpr].col_no = col_no;
                        RegExprs[NumRegExpr++].expr_string = val;
                    } else
                        break;
                }
                if (expr_no == 1) break;
            }
            if (col_no == 1) {
                // no expression
                sprintf(err_string, "no regular expression defined");
                return -1;
            }
            MaxLineLen = max_line_len;
            MaxPatternLen = max_pattern_len;
        } else {
            EngineType = PATTERN_DECRYPTOR;
            MaxLineLen = max_line_len;
            MaxPatternLen = max_pattern_len;
        }
    }
    return 0;
}

PccPttnSearchEngine* PccSearchEngineFactory::getEngine() {
    PccPttnSearchEngine* engine = 0;
    for (;;) {
        dgt_schar err_string[513] = {
            0,
        };
        if (DgcSpinLock::lock(&FactoryLock) == 0) {
            if (EngineType == PATTERN_ENCRYPTOR) {
                //
                // reglar expression search engine can't be shared because it
                // needs state variables each thread's PccCipher is need it
                //
                PccRegExprSearchEngine* tmp =
                    new PccRegExprSearchEngine(MaxPatternLen, MaxLineLen);
                for (dgt_sint32 i = 0; i < NumRegExpr; i++) {
                    if (tmp->addRegExpr(RegExprs[i].col_no,
                                        RegExprs[i].expr_string,
                                        err_string) < 0) {
                        DgcWorker::PLOG.tprintf(0, "addRegExpr failed:%s\n",
                                                err_string);
                    }
                }
                engine = tmp;
                Engines[NumEngine++] = engine;
            } else if (EngineType == PATTERN_DECRYPTOR) {
                // tag regular expression can't be shared
                // each thread's PccCipher is need it
                PccRegExprSearchEngine* tmp =
                    new PccRegExprSearchEngine(MaxPatternLen, MaxLineLen);
                if (tmp->addRegExpr(1, PPE_TAG_REG_EXPR, err_string) < 0) {
                    DgcWorker::PLOG.tprintf(0, "addRegExpr failed:%s\n",
                                            err_string);
                }
                engine = tmp;
                Engines[NumEngine++] = engine;
            } else {
                // no engine defined yet, which is considered as no search
                // engine
                if (NumEngine == 0) {
                    engine = new PccNoSearchEngine();
                    Engines[NumEngine++] = engine;
                }
            }
#if 0
			// no engine defined yet, which is considered as no search engine
pr_debug("EngineType[%d] NumEngine[%d]\n",EngineType,NumEngine);
			if (NumEngine == 0) engine = new PccNoSearchEngine();
			if (engine) Engines[NumEngine++] = engine;
#endif
            DgcSpinLock::unlock(&FactoryLock);
            break;
        }
    }
    return engine ? engine : Engines[0];  // engine shoulde be only one in any
                                          // case except reg_expr case
}
