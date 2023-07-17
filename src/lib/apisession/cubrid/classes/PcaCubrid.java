import sinsiway.*;

public class PcaCubrid
{
  public static String encrypt(String paramString, int paramInt)
    throws sinsiway.PcaException
  {
    sinsiway.PcaSession localPcaSession = sinsiway.PcaSessionPool.getSession();
    String str = localPcaSession.encrypt(paramInt, paramString);
    return str;
  }

  public static String encrypt(String paramString1, String paramString2) throws sinsiway.PcaException
  {
    sinsiway.PcaSession localPcaSession = sinsiway.PcaSessionPool.getSession();
    String str = localPcaSession.encrypt(paramString2, paramString1);
    return str;
  }

  public static String decrypt(String paramString, int paramInt) throws sinsiway.PcaException
  {
    sinsiway.PcaSession localPcaSession = sinsiway.PcaSessionPool.getSession();
    String str = localPcaSession.decrypt(paramInt, paramString);
    return str;
  }

  public static String decrypt(String paramString1, String paramString2) throws sinsiway.PcaException
  {
    sinsiway.PcaSession localPcaSession = sinsiway.PcaSessionPool.getSession();
    String str = localPcaSession.decrypt(paramString2, paramString1);
    return str;
  }
}