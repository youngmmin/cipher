package sinsiway;

import java.util.*;

public class PcaException extends Exception {

  private final int ERR_CODE;

  PcaException(String msg, int errcode) {
    super(msg);
    ERR_CODE = errcode;
  }

  PcaException(String msg) {
    this(msg, 100);
  }

  public int getErrCode() {
    return ERR_CODE;
  }
}
