package cn.com.infosec.XMLTest;

import java.security.KeyPair;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.apache.xml.security.Init;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import cn.com.infosec.xml.verify.XMLVerify;


/**
 * @author Gsealy
 * 
 */
public class ConcurrentTestUtil {

  private static KeyPair kp;

  private static Document SIGNED_XMLDOC;

  private static int count = 0;

  static {
    init();
  }

  /**
   * concurrent TPS test
   *
   * @param concurrentThreads concurrent thread number (simulation visual users)
   * @param times total process number
   * @param task
   * @param requestHandler result handler
   * @param executeTimeoutMillis timeout time
   * @throws InterruptedException
   * @throws ExecutionException
   */
  public static <T> void concurrentTest(long concurrentThreads, int times, final Callable<T> task,
      RequestHandler<T> requestHandler, long executeTimeoutMillis)
      throws InterruptedException, ExecutionException {

    ExecutorService executor = Executors.newFixedThreadPool((int) concurrentThreads);
    List<Future<T>> results = new ArrayList<Future<T>>(times);

    long startTimeMillis = System.currentTimeMillis();
    for (int i = 0; i < times; i++) {
      results.add(executor.submit(task));
    }
    executor.shutdown();

    boolean executeCompleteWithinTimeout =
        executor.awaitTermination(executeTimeoutMillis, TimeUnit.SECONDS);
    if (!executeCompleteWithinTimeout) {
      System.out.println("Execute tasks out of timeout [" + executeTimeoutMillis + "ms]");

      /*
       * cancel all task
       */
      for (Future<T> r : results) {
        r.cancel(true);
      }
    } else {
      long totalCostTimeMillis = System.currentTimeMillis() - startTimeMillis;

      // close thread pool, handle result
      for (Future<T> r : results) {
        if (requestHandler != null) {
          requestHandler.handle(r.get());
        }
      }

      System.out.println("concurrent threads: " + concurrentThreads + ", times: " + times);
      System.out.println("total cost time(ms): " + totalCostTimeMillis + "ms, avg time(ms): "
          + ((double) totalCostTimeMillis / times));
      System.out
          .println("tps: " + (int) (times * 1000) / totalCostTimeMillis + ", errors: " + count);
      System.out.println();
    }
  }

  public static void main(String[] args) throws InterruptedException, ExecutionException {
    ConcurrentTestUtil.concurrentTest(64, 900000, new Callable<Boolean>() {
      @Override
      public Boolean call() throws Exception {
        return genEnveloped();
      }
    }, new RequestHandler<Boolean>() {
      @Override
      public void handle(Boolean result) {
        if (!result) {
          count++;
        }
      }
    }, 6000);
  }

  public interface RequestHandler<T> {
    public void handle(T result);
  }

  public static boolean genEnveloped() throws Exception {
    try {
      XMLVerify xmlVerify = new XMLVerify(SIGNED_XMLDOC, kp.getPublic());
      return xmlVerify.vaildate();
    } catch (Exception e) {
      e.printStackTrace();
    }
    return false;

  }

  public static void init() {
    Security.insertProviderAt(new BouncyCastleProvider(), 0);
    Security.insertProviderAt(new XMLDSigRI(), 1);
    Init.init();
    Constants.SM2KeyPair();
    Constants.CreatePlainDocument();
    Constants.CreateSignedDocument();
    kp = Constants.kp;
    SIGNED_XMLDOC = Constants.SIGNED_XMLDOC;
  }
}

