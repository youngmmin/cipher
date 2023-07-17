package sinsiway;

import java.util.*;

public class PcaSessionPool extends Object {

  public static void initialize(
    String conf_file_path,
    String credentials_password
  ) throws PcaException {
    sinsiway.PcaSession.initialize(conf_file_path, credentials_password);
  }

  public static sinsiway.PcaSession getSession() throws PcaException {
    int idx = -1;
    sinsiway.PcaSession session = null;
    synchronized (SharedSessionPool) {
      if (NumSharedSession == 0) {
        //
        // initialize shared session pool
        //
        if ((NumSharedSession = sinsiway.PcaSession.numSharedSession()) > 0) {
          int i;
          for (i = 0; i < NumSharedSession; i++) {
            session = new sinsiway.PcaSession("", "", "");
            SharedSessionPool.addElement(session);
            SharedFreePool.push(session);
          }
        }
        LastFetchedSharedSessionIdx = -1;
      }
      if (
        SharedFreePool.empty() ||
        (session = (sinsiway.PcaSession) SharedFreePool.pop()) == null
      ) {
        if (LastFetchedSharedSessionIdx < (NumSharedSession - 1)) {
          idx = ++LastFetchedSharedSessionIdx;
        } else if (NumSharedSession > 0) {
          idx = LastFetchedSharedSessionIdx = 0;
        }
      }
    }
    if (idx >= 0) {
      //
      // run out of free shared session,
      // user didn't return sessions after using them
      //
      session = (sinsiway.PcaSession) SharedSessionPool.elementAt(idx);
    }
    if (session == null) {
      //
      // shared session is not defined in petra_cipher_api.conf,
      // a pesonal session returning would be better.
      //
      session = getSession("", "", "");
    }
    return session;
  }

  public static sinsiway.PcaSession getEncSession() throws PcaException {
    int idx = -1;
    sinsiway.PcaSession session = null;
    synchronized (SharedSessionPool) {
      if (NumSharedSession == 0) {
        //
        // initialize shared session pool
        //
        if ((NumSharedSession = sinsiway.PcaSession.numSharedSession()) > 0) {
          int i;
          for (i = 0; i < NumSharedSession; i++) {
            session = new sinsiway.PcaSession();
            SharedSessionPool.addElement(session);
            SharedFreePool.push(session);
          }
        }
        LastFetchedSharedSessionIdx = -1;
      }
      if (
        SharedFreePool.empty() ||
        (session = (sinsiway.PcaSession) SharedFreePool.pop()) == null
      ) {
        if (LastFetchedSharedSessionIdx < (NumSharedSession - 1)) {
          idx = ++LastFetchedSharedSessionIdx;
        } else if (NumSharedSession > 0) {
          idx = LastFetchedSharedSessionIdx = 0;
        }
      }
    }
    if (idx >= 0) {
      //
      // run out of free shared session,
      // user didn't return sessions after using them
      //
      session = (sinsiway.PcaSession) SharedSessionPool.elementAt(idx);
    }
    if (session == null) {
      //
      // shared session is not defined in petra_cipher_api.conf,
      // a pesonal session returning would be better.
      //
      session = getSession("", "", "");
    }
    return session;
  }

  public static sinsiway.PcaSession getSession(
    String client_ip,
    String user_id,
    String client_program
  ) throws PcaException {
    String hash_key = sinsiway.PcaSession.genHashKey(
      client_ip,
      user_id,
      client_program
    );
    sinsiway.PcaSession session;
    synchronized (SessionPool) {
      if (SessionPool.size() >= PcaSession.maxPrivateSession()) {
        //
        // reach the maximum number of private sessions
        //
        int target = (int) (SessionPool.size() * 0.1);
        while (target > 0) {
          session = (sinsiway.PcaSession) SessionLRU.elementAt(0);
          SessionLRU.removeElementAt(0);
          SessionPool.remove(session.hashKey());
          session.closeSession();
          target--;
        }
      }
      if ((session = (sinsiway.PcaSession) SessionPool.get(hash_key)) == null) {
        session = new sinsiway.PcaSession(client_ip, user_id, client_program);
        SessionPool.put(hash_key, session);
      } else {
        SessionLRU.removeElement(session);
      }
      SessionLRU.addElement(session);
    }
    return session;
  }

  private static Hashtable SessionPool = new Hashtable(4096);
  private static Vector SessionLRU = new Vector();
  private static int NumSharedSession = 0;
  private static int LastFetchedSharedSessionIdx;
  private static Vector SharedSessionPool = new Vector();
  private static Stack SharedFreePool = new Stack();

  static {
    System.loadLibrary("pcjapi");
  }
}
