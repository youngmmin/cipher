package sinsiway;

import java.util.*;

public class PcaSession extends Object {

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

  private static native byte[] ENC(int db_sid, int enc_col_id, byte[] src); // encrypt

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

  private static native int ECODE(int db_sid); // get error code

  private static native int CRYPTFILE(
    int db_sid,
    byte[] param_string,
    byte[] intput_file_path,
    byte[] output_file_path
  );

  private static native int ISENCRYPTED(byte[] file_name); //check encrypted

  private static native int NSS(); // the number of shared session

  private static native int MAXPS(); // the maximum number of private session

  public static int numSharedSession() {
    return NSS();
  }

  public static int maxPrivateSession() {
    return MAXPS();
  }

  public static String genHashKey(
    String client_ip,
    String user_id,
    String client_program
  ) {
    return new String(
      "ci=" + client_ip + "ui=" + user_id + "cp=" + client_program
    );
  }

  public static void initialize(
    String conf_file_path,
    String credentials_password
  ) throws PcaException {
    byte[] cfp;
    if (conf_file_path != null) cfp = conf_file_path.getBytes(); else cfp =
      "".getBytes();
    byte[] cp = "".getBytes();
    if (credentials_password != null) cp =
      credentials_password.getBytes(); else cp = "".getBytes();
    int rtn = INIT(cfp, cp);
    if (rtn != 0) {
      throw new PcaException("initialize failed. error code[" + rtn + "]", rtn);
    }
  }

  public PcaSession(String client_ip, String user_id, String client_program)
    throws PcaException {
    if (client_ip == null) client_ip = new String("");
    if (user_id == null) user_id = new String("");
    if (client_program == null) client_program = new String("");
    HashKey = genHashKey(client_ip, user_id, client_program);

    if (
      (
        SID =
          OPN(
            0,
            "".getBytes(),
            "".getBytes(),
            client_ip.getBytes(),
            "".getBytes(),
            user_id.getBytes(),
            client_program.getBytes(),
            0,
            user_id.getBytes(),
            "".getBytes()
          )
      ) <
      0
    ) {
      throw new PcaException(
        "session open failed. error code[" + SID + "]",
        SID
      );
    }
  }

  public PcaSession() throws PcaException {
    if (
      (
        SID =
          OPN(
            0,
            "".getBytes(),
            "".getBytes(),
            "127.0.0.1".getBytes(),
            "".getBytes(),
            "".getBytes(),
            "".getBytes(),
            0,
            "".getBytes(),
            "".getBytes()
          )
      ) <
      0
    ) {
      throw new PcaException(
        "session open failed. error code[" + SID + "]",
        SID
      );
    }
  }

  public void closeSession() {
    synchronized (this) {
      if (SID >= 0) {
        CLS(SID);
        SID = -1;
      }
    }
  }

  public byte[] encrypt(int eci, byte[] src) throws PcaException {
    if (src == null) src = "".getBytes();
    byte[] encrypted_data;
    synchronized (this) {
      encrypted_data = ENC(SID, eci, src);
    }
    if (encrypted_data == null) {
      int ErrCode = ECODE(SID);
      if (ErrCode != 0) {
        throw new PcaException(
          "encryption failed, error code[" + ErrCode + "]",
          ErrCode
        );
      }
    }
    return encrypted_data;
  }

  public String encrypt(int eci, String src) throws PcaException {
    byte[] src_bytes = null;
    if (src != null) src_bytes = src.getBytes();
    byte[] encrypted_data = encrypt(eci, src_bytes);
    if (encrypted_data == null) return null;
    return new String(encrypted_data);
  }

  public byte[] encrypt(String ecn, byte[] src) throws PcaException {
    if (ecn == null) ecn = new String("");
    if (src == null) src = "".getBytes();
    byte[] encrypted_data;
    synchronized (this) {
      encrypted_data = ENC_NM(SID, ecn.getBytes(), src);
    }
    if (encrypted_data == null) {
      int ErrCode = ECODE(SID);
      if (ErrCode != 0) {
        throw new PcaException(
          "encryption failed, error code[" + ErrCode + "]",
          ErrCode
        );
      }
    }
    return encrypted_data;
  }

  public String encrypt(String ecn, String src) throws PcaException {
    byte[] src_bytes = null;
    if (src != null) src_bytes = src.getBytes();
    byte[] encrypted_data = encrypt(ecn, src_bytes);
    if (encrypted_data == null) return null;
    return new String(encrypted_data);
  }

  public byte[] decrypt(int eci, byte[] src) throws PcaException {
    if (src == null) src = "".getBytes();
    byte[] decrypted_data;
    synchronized (this) {
      decrypted_data = DEC(SID, eci, src);
    }
    if (decrypted_data == null) {
      int ErrCode = ECODE(SID);
      if (ErrCode != 0) {
        throw new PcaException(
          "decryption failed, error code[" + ErrCode + "]",
          ErrCode
        );
      }
    }
    return decrypted_data;
  }

  public String decrypt(int eci, String src) throws PcaException {
    byte[] src_bytes = null;
    if (src != null) src_bytes = src.getBytes();
    byte[] decrypted_data = decrypt(eci, src_bytes);
    if (decrypted_data == null) return null;
    return new String(decrypted_data);
  }

  public byte[] decrypt(String ecn, byte[] src) throws PcaException {
    if (ecn == null) ecn = new String("");
    if (src == null) src = "".getBytes();
    byte[] decrypted_data;
    synchronized (this) {
      decrypted_data = DEC_NM(SID, ecn.getBytes(), src);
    }
    if (decrypted_data == null) {
      int ErrCode = ECODE(SID);
      if (ErrCode != 0) {
        throw new PcaException(
          "decryption failed, error code[" + ErrCode + "]",
          ErrCode
        );
      }
    }
    return decrypted_data;
  }

  public String decrypt(String ecn, String src) throws PcaException {
    byte[] src_bytes = null;
    if (src != null) src_bytes = src.getBytes();
    byte[] decrypted_data = decrypt(ecn, src_bytes);
    if (decrypted_data == null) return null;
    return new String(decrypted_data);
  }

  public void cryptFile(String param_file_path) throws PcaException {
    int ret = 0;
    synchronized (this) {
      ret =
        CRYPTFILE(
          SID,
          param_file_path.getBytes(),
          "".getBytes(),
          "".getBytes()
        );
    }
    if (ret < 0) {
      int ErrCode = ECODE(SID);
      throw new PcaException("file encrypt/decrypt failed[" + ret + "]", ret);
    }
  }

  public void cryptFile(
    String param_string,
    String input_file_path,
    String output_file_path
  ) throws PcaException {
    int ret = 0;
    if (input_file_path == null) input_file_path = new String("");
    if (output_file_path == null) output_file_path = new String("");
    synchronized (this) {
      ret =
        CRYPTFILE(
          SID,
          param_string.getBytes(),
          input_file_path.getBytes(),
          output_file_path.getBytes()
        );
    }
    if (ret < 0) {
      int ErrCode = ECODE(SID);
      throw new PcaException("file encrypt/decrypt failed[" + ret + "]", ret);
    }
  }

  public int isEncrypted(String file_name) throws PcaException {
    int ret = 0;
    synchronized (this) {
      ret = ISENCRYPTED(file_name.getBytes());
    }
    return ret;
  }

  public String hashKey() {
    return HashKey;
  }

  public int sid() {
    return SID;
  }

  protected void finalize() throws Throwable {
    super.finalize();
  }

  private String HashKey; // hash key
  private int SID; // client Session ID
}
