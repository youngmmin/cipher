import java.sql.*;
import oracle.jdbc.driver.*;

public class PcaOracle {

  private static native int INIT(
    byte[] conf_file_path,
    byte[] credentials_password
  );

  private static native int OPN(
    int db_sid,
    byte[] instance_id,
    byte[] db_name,
    byte[] client_ip,
    byte[] db_user,
    byte[] os_user,
    byte[] client_program,
    int protocol,
    byte[] user_id,
    byte[] client_mac
  ); // open user session

  private static native void CLS(int db_sid); // close API session

  private static native void CCS(int db_sid, byte[] char_set_bytes); // set session character set

  private static native byte[] ENC(int db_sid, int enc_col_id, byte[] src); // encrypt

  private static native byte[] ENC_C(int db_sid, int enc_col_id, byte[] src); // encrypt for initial encryption

  private static native byte[] ENC_NM(
    int db_sid,
    byte[] enc_col_name,
    byte[] src
  ); // encrypt

  private static native byte[] DEC(int db_sid, int enc_col_id, byte[] src); // decrypt

  private static native byte[] DEC_NM(
    int db_sid,
    byte[] enc_col_name,
    byte[] src
  ); // decrypt

  private static native byte[] OPHUEK(
    int db_sid,
    int enc_col_id,
    byte[] src,
    int src_enc_flag
  ); // get indexing hash

  private static native byte[] OPHUEK_NM(
    int db_sid,
    byte[] enc_col_name,
    byte[] src,
    int src_enc_flag
  ); // get indexing hash

  private static native byte[] ENC_CPN(int db_sid, int enc_col_id, byte[] src); // encrypt coupon

  private static native byte[] ENC_CPN_NM(
    int db_sid,
    byte[] enc_col_name,
    byte[] src
  ); // encrypt coupon

  private static native byte[] DEC_CPN(int db_sid, int enc_col_id, byte[] src); // decrypt coupon

  private static native byte[] DEC_CPN_NM(
    int db_sid,
    byte[] enc_col_name,
    byte[] src
  ); // decrypt coupon

  private static native int SSHT(int db_sid, int sql_hash, int sql_type); // set sql int hash

  private static native int SSHT64(int db_sid, byte[] sql_hash, int sql_type); // set sql byte array hash

  private static native int LCR(int db_sid, int sql_hash, int sql_type); // log current request with integer hash

  private static native int LCR64(int db_sid, byte[] sql_hash, int sql_type); // log current request with byte array hash

  private static native int ECODE(int db_sid); // get error code

  private static native int GNSF(int db_sid); // get new sql flag

  private static native void LOGGING(int ecode, byte[] msg); // logging message

  private static int SID = -1;
  private static Connection DefaultConn = null;
  private static PreparedStatement GetSqlHashStmt = null;

  private static void openSession() {
    try {
      String query =
        "select (select instance_name from v$instance) instance_id, upper(nvl(sys_context('userenv','db_name'),'NULL')) db_name,TO_NUMBER(SUBSTR(DBMS_SESSION.UNIQUE_SESSION_ID,1,4),'XXXX') sid,  NVL(SYS_CONTEXT('userenv','ip_address'),'127.0.0.1') ip_address, upper(nvl(SYS_CONTEXT('userenv','session_user'),'NULL')) db_user, DECODE(UPPER(SYS_CONTEXT('userenv','network_protocol')),'BEQ',1,'IPC',2,'TCP',3,1) protocol, upper(nvl(SYS_CONTEXT('userenv','host'),'NULL')) os_user, (select upper(nvl(program,'NULL')) from v$session where sid =TO_NUMBER(SUBSTR(DBMS_SESSION.UNIQUE_SESSION_ID,1,4),'XXXX')) module from dual";
      if (DefaultConn == null) DefaultConn =
        new OracleDriver().defaultConnection();
      Statement stmt = DefaultConn.createStatement();
      ResultSet rs = stmt.executeQuery(query);
      byte[] v_instance_id;
      byte[] v_db_name;
      byte[] v_ip_address;
      byte[] v_db_user;
      byte v_protocol = 0;
      byte[] v_os_user;
      byte[] v_module;
      rs.next();
      v_instance_id = rs.getString("instance_id").getBytes();
      v_db_name = rs.getString("db_name").getBytes();
      SID = rs.getInt("sid");
      v_ip_address = rs.getString("ip_address").getBytes();
      v_db_user = rs.getString("db_user").getBytes();
      v_protocol = rs.getByte("protocol");
      v_os_user = rs.getString("os_user").getBytes();
      v_module = rs.getString("module").getBytes();
      OPN(
        SID,
        v_instance_id,
        v_db_name,
        v_ip_address,
        v_db_user,
        v_os_user,
        v_module,
        v_protocol,
        "".getBytes(),
        "".getBytes()
      );
      rs.close();
      stmt.close();
    } catch (Exception e) {
      String msg = e.toString();
      LOGGING(-31111, msg.getBytes());
      //			StackTraceElement[]	elements = e.getStackTrace();
      //			for(int i=0; i<elements.length; i++) {
      //				LOGGING(-31111, (elements[i].getClassName()+":"+elements[i].getMethodName()+":"+elements[i].getLineNumber()+":"+elements[i].toString()).getBytes());
      //			}
      int[] arg = new int[1];
      arg[3] = 1;
    }
  }

  private static void setSqlHashType() {
    try {
      if (DefaultConn == null) DefaultConn =
        new OracleDriver().defaultConnection();
      if (GetSqlHashStmt == null) GetSqlHashStmt =
        DefaultConn.prepareStatement(
          "select sql_hash_value, command from v$session where sid= ?"
        );
      GetSqlHashStmt.setInt(1, SID);
      ResultSet rs = GetSqlHashStmt.executeQuery();
      rs.next();
      String sql_hash = rs.getString("sql_hash_value");
      int sql_type = rs.getInt("command");
      //
      // 6: UPDATE ->2
      // 2: INSERT ->1
      // 7: DELETE ->3
      // 3: SELECT ->4
      //  : OTHRES ->5
      if (sql_type == 3) {
        sql_type = 4;
      } else if (sql_type == 6) {
        sql_type = 2;
      } else if (sql_type == 2) {
        sql_type = 1;
      } else if (sql_type == 7) {
        sql_type = 3;
      } else {
        sql_type = 5;
      }
      SSHT64(SID, sql_hash.getBytes(), sql_type);
      rs.close();
    } catch (Exception e) {
      String msg = e.toString();
      LOGGING(-31112, msg.getBytes());
      SSHT64(SID, "".getBytes(), 4);
      /* commented by mwpark 
			int[] arg = new int[1];
			arg[3]=1;
*/
    }
  }

  public static void setCharSet(byte[] char_set_bytes) {
    if (char_set_bytes == null) char_set_bytes = "".getBytes();
    CCS(SID, char_set_bytes);
  }

  public static byte[] EXT_ENC_BB(byte[] data, int enc_col_id) {
    if (data == null) data = "".getBytes();
    byte[] ret = ENC(SID, enc_col_id, data);
    if (ret == null) {
      int ErrCode = ECODE(SID);
      if (ErrCode != 0) {
        int[] arg = new int[1];
        arg[3] = 1;
      }
    }
    if (GNSF(SID) != 0) setSqlHashType();
    return ret;
  }

  public static byte[] EXT_ENC_BB_C(byte[] data, int enc_col_id) {
    if (data == null) data = "".getBytes();
    byte[] ret = ENC_C(SID, enc_col_id, data);
    if (ret == null) {
      int ErrCode = ECODE(SID);
      if (ErrCode != 0) {
        int[] arg = new int[1];
        arg[3] = 1;
      }
    }
    return ret;
  }

  public static byte[] EXT_ENC_BB(byte[] data, String ecn) {
    if (ecn == null) ecn = new String("");
    if (data == null) data = "".getBytes();
    byte[] ret = ENC_NM(SID, ecn.getBytes(), data);
    if (ret == null) {
      int ErrCode = ECODE(SID);
      if (ErrCode != 0) {
        int[] arg = new int[1];
        arg[3] = 1;
      }
    }
    if (GNSF(SID) != 0) setSqlHashType();
    return ret;
  }

  public static byte[] EXT_ENC_BB(byte[] data) {
    if (data == null) data = "".getBytes();
    byte[] ret = ENC_NM(SID, "".getBytes(), data);
    if (ret == null) {
      int ErrCode = ECODE(SID);
      if (ErrCode != 0) {
        int[] arg = new int[1];
        arg[3] = 1;
      }
    }
    if (GNSF(SID) != 0) setSqlHashType();
    return ret;
  }

  public static byte[] EXT_ENC_HASH(byte[] data) {
    return EXT_ENC_BB(data, DefaultHashColName);
  }

  public static byte[] EXT_DEC_BB(byte[] data, int enc_col_id) {
    if (data == null) data = "".getBytes();
    byte[] ret = DEC(SID, enc_col_id, data);
    if (ret == null) {
      int ErrCode = ECODE(SID);
      if (ErrCode != 0) {
        int[] arg = new int[1];
        arg[3] = 1;
      }
    }
    if (GNSF(SID) != 0) setSqlHashType();
    return ret;
  }

  public static byte[] EXT_DEC_BB(byte[] data, String ecn) {
    if (ecn == null) ecn = new String("");
    if (data == null) data = "".getBytes();
    byte[] ret = DEC_NM(SID, ecn.getBytes(), data);
    if (ret == null) {
      int ErrCode = ECODE(SID);
      if (ErrCode != 0) {
        int[] arg = new int[1];
        arg[3] = 1;
      }
    }
    if (GNSF(SID) != 0) setSqlHashType();
    return ret;
  }

  public static byte[] EXT_DEC_BB(byte[] data) {
    if (data == null) data = "".getBytes();
    byte[] ret = DEC_NM(SID, "".getBytes(), data);
    if (ret == null) {
      int ErrCode = ECODE(SID);
      if (ErrCode != 0) {
        int[] arg = new int[1];
        arg[3] = 1;
      }
    }
    if (GNSF(SID) != 0) setSqlHashType();
    return ret;
  }

  public static byte[] EXT_OPHUEK(
    byte[] data,
    int enc_col_id,
    int src_enc_flag
  ) {
    if (data == null) data = "".getBytes();
    byte[] ret = OPHUEK(SID, enc_col_id, data, src_enc_flag);
    if (ret == null) {
      int ErrCode = ECODE(SID);
      if (ErrCode != 0) {
        int[] arg = new int[1];
        arg[3] = 1;
      }
    }
    return ret;
  }

  public static byte[] EXT_OPHUEK(byte[] data, String ecn, int src_enc_flag) {
    if (ecn == null) ecn = new String("");
    if (data == null) data = "".getBytes();
    byte[] ret = OPHUEK_NM(SID, ecn.getBytes(), data, src_enc_flag);
    if (ret == null) {
      int ErrCode = ECODE(SID);
      if (ErrCode != 0) {
        int[] arg = new int[1];
        arg[3] = 1;
      }
    }
    return ret;
  }

  public static byte[] EXT_ENC_CPN(byte[] data, int enc_col_id) {
    if (data == null) data = "".getBytes();
    byte[] ret = ENC_CPN(SID, enc_col_id, data);
    if (ret == null) {
      int ErrCode = ECODE(SID);
      if (ErrCode != 0) {
        int[] arg = new int[1];
        arg[3] = 1;
      }
    }
    if (GNSF(SID) != 0) setSqlHashType();
    return ret;
  }

  public static byte[] EXT_ENC_CPN(byte[] data, String ecn) {
    if (ecn == null) ecn = new String("");
    if (data == null) data = "".getBytes();
    byte[] ret = ENC_CPN_NM(SID, ecn.getBytes(), data);
    if (ret == null) {
      int ErrCode = ECODE(SID);
      if (ErrCode != 0) {
        int[] arg = new int[1];
        arg[3] = 1;
      }
    }
    if (GNSF(SID) != 0) setSqlHashType();
    return ret;
  }

  public static byte[] EXT_DEC_CPN(byte[] data, int enc_col_id) {
    if (data == null) data = "".getBytes();
    byte[] ret = DEC_CPN(SID, enc_col_id, data);
    if (ret == null) {
      int ErrCode = ECODE(SID);
      if (ErrCode != 0) {
        int[] arg = new int[1];
        arg[3] = 1;
      }
    }
    if (GNSF(SID) != 0) setSqlHashType();
    return ret;
  }

  public static byte[] EXT_DEC_CPN(byte[] data, String ecn) {
    if (ecn == null) ecn = new String("");
    if (data == null) data = "".getBytes();
    byte[] ret = DEC_CPN_NM(SID, ecn.getBytes(), data);
    if (ret == null) {
      int ErrCode = ECODE(SID);
      if (ErrCode != 0) {
        int[] arg = new int[1];
        arg[3] = 1;
      }
    }
    if (GNSF(SID) != 0) setSqlHashType();
    return ret;
  }

  public static byte[] EXT_LCR(byte[] tabName, byte[] colName) {
    LCR64(SID, "".getBytes(), 0);
    return null;
  }

  private static int lobChunkSize = 2097152; // 2Mega

  public static oracle.sql.CLOB EXT_ENC_CLOB(
    oracle.sql.BLOB data,
    int enc_col_id
  ) {
    oracle.sql.CLOB tempClob = null;
    try {
      if (data == null) {
        byte[] ret = ENC(SID, enc_col_id, "".getBytes());
        if (ret == null) {
          int ErrCode = ECODE(SID);
          if (ErrCode != 0) {
            int[] arg = new int[1];
            arg[3] = 1;
          } else {
            return null;
          }
        }
        String ret_string = new String(ret);
        tempClob =
          oracle.sql.CLOB.createTemporary(
            DefaultConn,
            true,
            oracle.sql.CLOB.DURATION_SESSION
          );
        tempClob.open(oracle.sql.CLOB.MODE_READWRITE);
        tempClob.setString(1, ret_string);
        tempClob.close();
      } else if (data.length() < lobChunkSize) {
        //				byte[] buffer = data.getBytes(1,(int)data.getLength());
        byte[] buffer = data.getBytes(1, (int) data.length());
        byte[] ret = ENC(SID, enc_col_id, buffer);
        if (ret == null) {
          int ErrCode = ECODE(SID);
          if (ErrCode != 0) {
            int[] arg = new int[1];
            arg[3] = 1;
          } else {
            return null;
          }
        }
        String ret_string = new String(ret);
        tempClob =
          oracle.sql.CLOB.createTemporary(
            DefaultConn,
            true,
            oracle.sql.CLOB.DURATION_SESSION
          );
        tempClob.open(oracle.sql.CLOB.MODE_READWRITE);
        tempClob.setString(1, ret_string);
        tempClob.close();
      } else {
        long clobLength = data.length();
        int chunkSize = lobChunkSize;
        tempClob =
          oracle.sql.CLOB.createTemporary(
            DefaultConn,
            true,
            oracle.sql.CLOB.DURATION_SESSION
          );
        tempClob.open(oracle.sql.CLOB.MODE_READWRITE);
        long clobPosition = 1;
        for (long position = 1; position <= clobLength; position += chunkSize) {
          byte[] buffer = data.getBytes(position, chunkSize);
          byte[] ret = ENC(SID, enc_col_id, buffer);
          if (ret == null) {
            int ErrCode = ECODE(SID);
            if (ErrCode != 0) {
              int[] arg = new int[1];
              arg[3] = 1;
            } else {
              return null;
            }
          }
          String ret_string = new String(ret);
          tempClob.setString(clobPosition, ret_string);
          clobPosition += ret.length;
        }
        tempClob.close();
      }
    } catch (Exception e) {
      LOGGING(-31113, e.toString().getBytes());
      int[] arg = new int[1];
      arg[3] = 1;
    }
    return tempClob;
  }

  public static oracle.sql.CLOB EXT_DEC_CLOB(
    oracle.sql.CLOB data,
    int enc_col_id
  ) {
    oracle.sql.CLOB tempClob = null;
    try {
      if (data == null) {
        return null;
      } else if (data.length() < lobChunkSize) {
        String data_string = data.getSubString(1, (int) data.length());
        byte[] src = data_string.getBytes();
        byte[] ret = DEC(SID, enc_col_id, src);
        if (ret == null) {
          int ErrCode = ECODE(SID);
          if (ErrCode != 0) {
            int[] arg = new int[1];
            arg[3] = 1;
          } else {
            return null;
          }
        }
        tempClob =
          oracle.sql.CLOB.createTemporary(
            DefaultConn,
            true,
            oracle.sql.CLOB.DURATION_SESSION
          );
        tempClob.open(oracle.sql.CLOB.MODE_READWRITE);
        String ret_string = new String(ret);
        tempClob.setString(1, ret_string);
        tempClob.close();
      } else {
        long clobLength = data.length();
        //
        // information <int chunkSize =  ((int)Math.ceil((double)lobChunkSize/16)*16) + 4 ;>
        //
        int chunkSize = 2796209;
        long clobPosition = 1;
        tempClob =
          oracle.sql.CLOB.createTemporary(
            DefaultConn,
            true,
            oracle.sql.CLOB.DURATION_SESSION
          );
        tempClob.open(oracle.sql.CLOB.MODE_READWRITE);
        for (long position = 1; position <= clobLength; position += chunkSize) {
          String data_string = data.getSubString(position, chunkSize);
          byte[] src = data_string.getBytes();
          byte[] ret = DEC(SID, enc_col_id, src);
          if (ret == null) {
            int ErrCode = ECODE(SID);
            if (ErrCode != 0) {
              int[] arg = new int[1];
              arg[3] = 1;
            } else {
              return null;
            }
          }
          String ret_string = new String(ret);
          tempClob.setString(clobPosition, ret_string);
          clobPosition += ret.length;
        }
        tempClob.close();
      }
    } catch (Exception e) {
      LOGGING(-31114, e.toString().getBytes());
      int[] arg = new int[1];
      arg[3] = 1;
    }
    return tempClob;
  }

  public static oracle.sql.BLOB EXT_ENC_BLOB(
    oracle.sql.BLOB data,
    int enc_col_id
  ) {
    oracle.sql.BLOB tempBlob = null;
    try {
      if (data == null) {
        byte[] src = "".getBytes();
        byte[] ret = ENC(SID, enc_col_id, src);
        if (ret == null) {
          int ErrCode = ECODE(SID);
          if (ErrCode != 0) {
            int[] arg = new int[1];
            arg[3] = 1;
          } else {
            return null;
          }
        }
        tempBlob =
          oracle.sql.BLOB.createTemporary(
            DefaultConn,
            true,
            oracle.sql.CLOB.DURATION_SESSION
          );
        tempBlob.open(oracle.sql.BLOB.MODE_READWRITE);
        //tempBlob.setBytes(1,ret,0,ret.length);
        tempBlob.putBytes(1, ret, ret.length);
        tempBlob.close();
      } else if (data.length() < lobChunkSize) {
        byte[] src = data.getBytes(1, (int) data.length());
        byte[] ret = ENC(SID, enc_col_id, src);
        if (ret == null) {
          int ErrCode = ECODE(SID);
          if (ErrCode != 0) {
            int[] arg = new int[1];
            arg[3] = 1;
          } else {
            return null;
          }
        }
        tempBlob =
          oracle.sql.BLOB.createTemporary(
            DefaultConn,
            true,
            oracle.sql.CLOB.DURATION_SESSION
          );
        tempBlob.open(oracle.sql.BLOB.MODE_READWRITE);
        //tempBlob.setBytes(1,ret,0,ret.length);
        tempBlob.putBytes(1, ret, ret.length);
        tempBlob.close();
      } else {
        long blobLength = data.length();
        int chunkSize = lobChunkSize;
        tempBlob =
          oracle.sql.BLOB.createTemporary(
            DefaultConn,
            true,
            oracle.sql.CLOB.DURATION_SESSION
          );
        tempBlob.open(oracle.sql.BLOB.MODE_READWRITE);
        long blobPosition = 1;
        for (long position = 1; position <= blobLength; position += chunkSize) {
          byte[] src = data.getBytes(position, chunkSize);
          byte[] ret = ENC(SID, enc_col_id, src);
          if (ret == null) {
            int ErrCode = ECODE(SID);
            if (ErrCode != 0) {
              int[] arg = new int[1];
              arg[3] = 1;
            } else {
              return null;
            }
          }
          //tempBlob.setBytes(blobPosition,ret,0,ret.length);
          tempBlob.putBytes(blobPosition, ret, ret.length);
          blobPosition += ret.length;
        }
        tempBlob.close();
      }
    } catch (Exception e) {
      LOGGING(-31115, e.toString().getBytes());
      int[] arg = new int[1];
      arg[3] = 1;
    }
    return tempBlob;
  }

  public static oracle.sql.BLOB EXT_DEC_BLOB(
    oracle.sql.BLOB data,
    int enc_col_id
  ) {
    oracle.sql.BLOB tempBlob = null;
    try {
      if (data == null) {
        return null;
      } else if (data.length() < lobChunkSize) {
        byte[] src = data.getBytes(1, (int) data.length());
        byte[] ret = DEC(SID, enc_col_id, src);
        if (ret == null) {
          int ErrCode = ECODE(SID);
          if (ErrCode != 0) {
            int[] arg = new int[1];
            arg[3] = 1;
          } else {
            return null;
          }
        }
        tempBlob =
          oracle.sql.BLOB.createTemporary(
            DefaultConn,
            true,
            oracle.sql.CLOB.DURATION_SESSION
          );
        tempBlob.open(oracle.sql.BLOB.MODE_READWRITE);
        //tempBlob.setBytes(1,ret,0,ret.length);
        tempBlob.putBytes(1, ret, ret.length);
        tempBlob.close();
      } else {
        long blobLength = data.length();
        //int chunkSize = ((int)Math.ceil((double)lobChunkSize/16)*16) + 4 ;
        int chunkSize = 2097156;
        tempBlob =
          oracle.sql.BLOB.createTemporary(
            DefaultConn,
            true,
            oracle.sql.CLOB.DURATION_SESSION
          );
        tempBlob.open(oracle.sql.BLOB.MODE_READWRITE);
        long blobPosition = 1;
        for (long position = 1; position <= blobLength; position += chunkSize) {
          byte[] src = data.getBytes(position, chunkSize);
          byte[] ret = DEC(SID, enc_col_id, src);
          if (ret == null) {
            int ErrCode = ECODE(SID);
            if (ErrCode != 0) {
              int[] arg = new int[1];
              arg[3] = 1;
            } else {
              return null;
            }
          }
          //tempBlob.setBytes(blobPosition,ret,0,ret.length);
          tempBlob.putBytes(blobPosition, ret, ret.length);
          blobPosition += ret.length;
        }
        tempBlob.close();
      }
    } catch (Exception e) {
      LOGGING(-31116, e.toString().getBytes());
      int[] arg = new int[1];
      arg[3] = 1;
    }
    return tempBlob;
  }

  public static oracle.sql.CLOB EXT_ENC_CLOB(oracle.sql.BLOB data, String ecn) {
    oracle.sql.CLOB tempClob = null;
    try {
      if (data == null) {
        byte[] ret = ENC_NM(SID, ecn.getBytes(), "".getBytes());
        if (ret == null) {
          int ErrCode = ECODE(SID);
          if (ErrCode != 0) {
            int[] arg = new int[1];
            arg[3] = 1;
          } else {
            return null;
          }
        }
        String ret_string = new String(ret);
        tempClob =
          oracle.sql.CLOB.createTemporary(
            DefaultConn,
            true,
            oracle.sql.CLOB.DURATION_SESSION
          );
        tempClob.open(oracle.sql.CLOB.MODE_READWRITE);
        tempClob.setString(1, ret_string);
        tempClob.close();
      } else if (data.length() < lobChunkSize) {
        //				byte[] buffer = data.getBytes(1,(int)data.getLength());
        byte[] buffer = data.getBytes(1, (int) data.length());
        byte[] ret = ENC_NM(SID, ecn.getBytes(), buffer);
        if (ret == null) {
          int ErrCode = ECODE(SID);
          if (ErrCode != 0) {
            int[] arg = new int[1];
            arg[3] = 1;
          } else {
            return null;
          }
        }
        String ret_string = new String(ret);
        tempClob =
          oracle.sql.CLOB.createTemporary(
            DefaultConn,
            true,
            oracle.sql.CLOB.DURATION_SESSION
          );
        tempClob.open(oracle.sql.CLOB.MODE_READWRITE);
        tempClob.setString(1, ret_string);
        tempClob.close();
      } else {
        long clobLength = data.length();
        int chunkSize = lobChunkSize;
        tempClob =
          oracle.sql.CLOB.createTemporary(
            DefaultConn,
            true,
            oracle.sql.CLOB.DURATION_SESSION
          );
        tempClob.open(oracle.sql.CLOB.MODE_READWRITE);
        long clobPosition = 1;
        for (long position = 1; position <= clobLength; position += chunkSize) {
          byte[] buffer = data.getBytes(position, chunkSize);
          byte[] ret = ENC_NM(SID, ecn.getBytes(), buffer);
          if (ret == null) {
            int ErrCode = ECODE(SID);
            if (ErrCode != 0) {
              int[] arg = new int[1];
              arg[3] = 1;
            } else {
              return null;
            }
          }
          String ret_string = new String(ret);
          tempClob.setString(clobPosition, ret_string);
          clobPosition += ret.length;
        }
        tempClob.close();
      }
    } catch (Exception e) {
      LOGGING(-31113, e.toString().getBytes());
      int[] arg = new int[1];
      arg[3] = 1;
    }
    return tempClob;
  }

  public static oracle.sql.CLOB EXT_DEC_CLOB(oracle.sql.CLOB data, String ecn) {
    oracle.sql.CLOB tempClob = null;
    try {
      if (data == null) {
        return null;
      } else if (data.length() < lobChunkSize) {
        String data_string = data.getSubString(1, (int) data.length());
        byte[] src = data_string.getBytes();
        byte[] ret = DEC_NM(SID, ecn.getBytes(), src);
        if (ret == null) {
          int ErrCode = ECODE(SID);
          if (ErrCode != 0) {
            int[] arg = new int[1];
            arg[3] = 1;
          } else {
            return null;
          }
        }
        tempClob =
          oracle.sql.CLOB.createTemporary(
            DefaultConn,
            true,
            oracle.sql.CLOB.DURATION_SESSION
          );
        tempClob.open(oracle.sql.CLOB.MODE_READWRITE);
        String ret_string = new String(ret);
        tempClob.setString(1, ret_string);
        tempClob.close();
      } else {
        long clobLength = data.length();
        //
        // information <int chunkSize =  ((int)Math.ceil((double)lobChunkSize/16)*16) + 4 ;>
        //
        int chunkSize = 2796209;
        long clobPosition = 1;
        tempClob =
          oracle.sql.CLOB.createTemporary(
            DefaultConn,
            true,
            oracle.sql.CLOB.DURATION_SESSION
          );
        tempClob.open(oracle.sql.CLOB.MODE_READWRITE);
        for (long position = 1; position <= clobLength; position += chunkSize) {
          String data_string = data.getSubString(position, chunkSize);
          byte[] src = data_string.getBytes();
          byte[] ret = DEC_NM(SID, ecn.getBytes(), src);
          if (ret == null) {
            int ErrCode = ECODE(SID);
            if (ErrCode != 0) {
              int[] arg = new int[1];
              arg[3] = 1;
            } else {
              return null;
            }
          }
          String ret_string = new String(ret);
          tempClob.setString(clobPosition, ret_string);
          clobPosition += ret.length;
        }
        tempClob.close();
      }
    } catch (Exception e) {
      LOGGING(-31114, e.toString().getBytes());
      int[] arg = new int[1];
      arg[3] = 1;
    }
    return tempClob;
  }

  public static oracle.sql.BLOB EXT_ENC_BLOB(oracle.sql.BLOB data, String ecn) {
    oracle.sql.BLOB tempBlob = null;
    try {
      if (data == null) {
        byte[] src = "".getBytes();
        byte[] ret = ENC_NM(SID, ecn.getBytes(), src);
        if (ret == null) {
          int ErrCode = ECODE(SID);
          if (ErrCode != 0) {
            int[] arg = new int[1];
            arg[3] = 1;
          } else {
            return null;
          }
        }
        tempBlob =
          oracle.sql.BLOB.createTemporary(
            DefaultConn,
            true,
            oracle.sql.CLOB.DURATION_SESSION
          );
        tempBlob.open(oracle.sql.BLOB.MODE_READWRITE);
        //tempBlob.setBytes(1,ret,0,ret.length);
        tempBlob.putBytes(1, ret, ret.length);
        tempBlob.close();
      } else if (data.length() < lobChunkSize) {
        byte[] src = data.getBytes(1, (int) data.length());
        byte[] ret = ENC_NM(SID, ecn.getBytes(), src);
        if (ret == null) {
          int ErrCode = ECODE(SID);
          if (ErrCode != 0) {
            int[] arg = new int[1];
            arg[3] = 1;
          } else {
            return null;
          }
        }
        tempBlob =
          oracle.sql.BLOB.createTemporary(
            DefaultConn,
            true,
            oracle.sql.CLOB.DURATION_SESSION
          );
        tempBlob.open(oracle.sql.BLOB.MODE_READWRITE);
        //tempBlob.setBytes(1,ret,0,ret.length);
        tempBlob.putBytes(1, ret, ret.length);
        tempBlob.close();
      } else {
        long blobLength = data.length();
        int chunkSize = lobChunkSize;
        tempBlob =
          oracle.sql.BLOB.createTemporary(
            DefaultConn,
            true,
            oracle.sql.CLOB.DURATION_SESSION
          );
        tempBlob.open(oracle.sql.BLOB.MODE_READWRITE);
        long blobPosition = 1;
        for (long position = 1; position <= blobLength; position += chunkSize) {
          byte[] src = data.getBytes(position, chunkSize);
          byte[] ret = ENC_NM(SID, ecn.getBytes(), src);
          if (ret == null) {
            int ErrCode = ECODE(SID);
            if (ErrCode != 0) {
              int[] arg = new int[1];
              arg[3] = 1;
            } else {
              return null;
            }
          }
          //tempBlob.setBytes(blobPosition,ret,0,ret.length);
          tempBlob.putBytes(blobPosition, ret, ret.length);
          blobPosition += ret.length;
        }
        tempBlob.close();
      }
    } catch (Exception e) {
      LOGGING(-31115, e.toString().getBytes());
      int[] arg = new int[1];
      arg[3] = 1;
    }
    return tempBlob;
  }

  public static oracle.sql.BLOB EXT_DEC_BLOB(oracle.sql.BLOB data, String ecn) {
    oracle.sql.BLOB tempBlob = null;
    try {
      if (data == null) {
        return null;
      } else if (data.length() < lobChunkSize) {
        byte[] src = data.getBytes(1, (int) data.length());
        byte[] ret = DEC_NM(SID, ecn.getBytes(), src);
        if (ret == null) {
          int ErrCode = ECODE(SID);
          if (ErrCode != 0) {
            int[] arg = new int[1];
            arg[3] = 1;
          } else {
            return null;
          }
        }
        tempBlob =
          oracle.sql.BLOB.createTemporary(
            DefaultConn,
            true,
            oracle.sql.CLOB.DURATION_SESSION
          );
        tempBlob.open(oracle.sql.BLOB.MODE_READWRITE);
        //tempBlob.setBytes(1,ret,0,ret.length);
        tempBlob.putBytes(1, ret, ret.length);
        tempBlob.close();
      } else {
        long blobLength = data.length();
        //int chunkSize = ((int)Math.ceil((double)lobChunkSize/16)*16) + 4 ;
        int chunkSize = 2097156;
        tempBlob =
          oracle.sql.BLOB.createTemporary(
            DefaultConn,
            true,
            oracle.sql.CLOB.DURATION_SESSION
          );
        tempBlob.open(oracle.sql.BLOB.MODE_READWRITE);
        long blobPosition = 1;
        for (long position = 1; position <= blobLength; position += chunkSize) {
          byte[] src = data.getBytes(position, chunkSize);
          byte[] ret = DEC_NM(SID, ecn.getBytes(), src);
          if (ret == null) {
            int ErrCode = ECODE(SID);
            if (ErrCode != 0) {
              int[] arg = new int[1];
              arg[3] = 1;
            } else {
              return null;
            }
          }
          //tempBlob.setBytes(blobPosition,ret,0,ret.length);
          tempBlob.putBytes(blobPosition, ret, ret.length);
          blobPosition += ret.length;
        }
        tempBlob.close();
      }
    } catch (Exception e) {
      LOGGING(-31116, e.toString().getBytes());
      int[] arg = new int[1];
      arg[3] = 1;
    }
    return tempBlob;
  }

  private static String DefaultHashColName = new String(
    "__default__hash__column__"
  );

  static {
    System.loadLibrary("PcaOracle");
    openSession();
  }
}
