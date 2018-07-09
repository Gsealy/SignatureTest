package cn.com.infosec.XMLTest;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.xml.security.utils.XMLUtils;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public class Constants {

  private Constants() {}

  public static KeyPair kp;

  public static Document SIGNED_XMLDOC = null;

  public static Document XMLDOC = null;

  public static final String PrivKey = "-----BEGIN EC PRIVATE KEY-----\r\n"
      + "MHcCAQEEIHnCKKyGWdiPX6CFHT48td9QqcGqkRme0vtGzTJJnTOHoAoGCCqBHM9V\r\n"
      + "AYItoUQDQgAEiovb69QXCQpYhgS52z+X0FfE9gc7sSIljilZCVlfHnmuJ4pimMhp\r\n"
      + "4M0MHwbT0gkhR+AlGgxCT1+CCz1bOwCQoQ==\r\n" + "-----END EC PRIVATE KEY-----";

  public static final String RSAPrivKey = "-----BEGIN RSA PRIVATE KEY-----\r\n"
      + "MIIEpQIBAAKCAQEA514eEQai25rJJax1JmnsLMrK6e3PJTdkgWuUB6gEvS4L/2Q6\r\n"
      + "nwHmgSpKMjD8PM1nW45pJZNyRTIaML2+Kq7168IpvrXxbcDyQOKKRyGre+qQk7J+\r\n"
      + "F9Q/HGYVWf4fADALbjg6wWGw1eYbkVNnn2ZsQSEFFc2Nb43WnyyCZPZzRzRLKSZV\r\n"
      + "Kj93UJL3pqOJDV+9guHIszGFXNTSQfO0zh/1mrAi9JqKl5mschgJydahuXd2YkgG\r\n"
      + "8x+88QkuXnLHbaIQKJHh6wMdIH81ukEMhsOt4ill5LRc3pvbXySQ1C41tZgjh2Lx\r\n"
      + "8DgZLPVQj/Z1o05DKk7XMP9gWGPGI6ABEPt1nwIDAQABAoIBAQDX7tomz8e9J3gl\r\n"
      + "xg/MGz2GDHpW21DiDhGqTCnq/1/04/3kjLm9XzuvPzXiJB+164pUQ9RUcolKlVkm\r\n"
      + "NmA+W+4+64akbBB4e4RdFFEz0/PFAgWPIx5VxQxlx8yTof1y4mQ4qRgFFdTBvTHr\r\n"
      + "bykd9qyAGH4zfBVNkNZG1naYHf826ovu97YCMLtiUhR42sfb5pzDE1soMlafh0KC\r\n"
      + "0GukF93xcYOkOtupzvbV5M+GGgKlLKi3jMdQrfPgh1rALeqCv7VcTNByaicDwe5B\r\n"
      + "vWLcn9Dxim3KUIiWLamLG6Uxmj8HrqeUuI3zdEV08oRxm001jPmjM/JDJex2qnhi\r\n"
      + "k3lzJr0hAoGBAPngZucFTgeEG86rtVzjJb7XmCJ218h22Fnb0jdy8ow9R3HCxC1R\r\n"
      + "2SjCO8sa1TBICCAJaUvZhuMKzxs8dj+evnl/TMb22GTzqXSDQkvT5SXWeKzVUYJy\r\n"
      + "NE83T9NbponZLchkjVrQ3a5JLMbS4jyBdJBOHDOyMNJD1RlRxFso/jtPAoGBAO0J\r\n"
      + "mZYBqDcE8x60j2dZC/CoXaRc0IqNgeE41A298CqdtiaotG8Kd6XoShSf+T/Kel/o\r\n"
      + "8BR01E1tSetj4Ouz15A7fpnnhTByeeB0vmutK4tq6BgnSaDTP0F8HaYF7o7xwhS0\r\n"
      + "7vwJX+4Z5YDpO1pukFYQnQI2+NiNhzmP4DF8l0yxAoGAZO9hgcZhy6Vwuh4gR6I1\r\n"
      + "uA5MlPdemMpxAHNMSjuzgDSsrGZZalkamF1FW/i9zx/5sD88+nenBgVyvXTB61cL\r\n"
      + "Z/alI+XIaZcHh1oSKKEyegNVgbM1lrTdLnaQVzc5YYuJ892yP9IJCgLjBHlhC8Hb\r\n"
      + "PQNgXv2GvRjLdsvRvmUjtP8CgYEA5HgcUTnHqUBcFXxzvGlX2N5vY70SRHmgdjUQ\r\n"
      + "Ly6kDm904k45m827BW6f+ME4vQOscEVVImJ5PyfX18qtQIJXg+3UWQOOnOO6FV5x\r\n"
      + "K9f94KNqkd1MWndCwRugeCW/iof7SXob31Ip5JWRYG9thfyLomjg7QGPWSsQ66qB\r\n"
      + "rTEppAECgYEAnRt7Js1wsCiDBpWfCQtY+SQOQ6yInUwpWd6KlR9E3XDyfX5DxT2J\r\n"
      + "2VSgo10yKJivgVG+a6IZqb+HfU9sYZIlp0SoYs7kktmKehP4MBXHuJ5i7DSmN8Bo\r\n"
      + "46oV1WwkQh2W+UUM3nu6p0nQew4R0G+OYQPo/ja5fuIk6MVq5mcWMWM=\r\n"
      + "-----END RSA PRIVATE KEY-----";

  public static final String plain = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
      + "<PurchaseOrder xmlns=\"urn:example:po\" Id=\"test\">\r\n" + "  <Items Id=\"test2\">\r\n"
      + "    <Item Code=\"001-001-001\" Quantity=\"1\">\r\n" + "      spade\r\n" + "    </Item>\r\n"
      + "    <Item Code=\"001-001-002\" Quantity=\"1\">\r\n" + "      shovel\r\n"
      + "    </Item>\r\n" + "  </Items>\r\n" + "  <ShippingAddress Id=\"test3\">\r\n"
      + "    Dig PLC, 1 First Ave, Dublin 1, Ireland\r\n" + "  </ShippingAddress>\r\n"
      + "  <PaymentInfo>\r\n" + "    <BillingAddress>\r\n"
      + "      Dig PLC, 1 First Ave, Dublin 1, Ireland\r\n" + "    </BillingAddress>\r\n"
      + "    <CreditCard Type=\"Amex\">\r\n" + "      <Name>Foo B Baz</Name>\r\n"
      + "      <Number>1234 567890 12345</Number>\r\n"
      + "      <Expires Month=\"1\" Year=\"2005\" />\r\n" + "    </CreditCard>\r\n"
      + "  </PaymentInfo>\r\n" + "</PurchaseOrder>";

  public static final String x509area = "-----BEGIN CERTIFICATE-----\r\n"
      + "MIIBEDCBtqADAgECAgYBY2z9zC4wCgYIKoEcz1UBg3UwDzENMAsGA1UEAwwEdGVz\r\n"
      + "dDAeFw0xODA1MTcwNzI2MDJaFw0yMTEwMDIwNzI2MDJaMA8xDTALBgNVBAMMBHRl\r\n"
      + "c3QwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAASKi9vr1BcJCliGBLnbP5fQV8T2\r\n"
      + "BzuxIiWOKVkJWV8eea4nimKYyGngzQwfBtPSCSFH4CUaDEJPX4ILPVs7AJChMAoG\r\n"
      + "CCqBHM9VAYN1A0kAMEYCIQCFf+xhzTFLi7Y3KkOCnRL6PawDDJuW4jBrTw1jWcic\r\n"
      + "FAIhAPFGsZ2Q4MoMtJGpI16KF3zNYxKZ6b5K+olTGy4fDujH\r\n" + "-----END CERTIFICATE-----\r\n"
      + "";

  public static final String validtext = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
      + "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"123\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2006/12/xml-c14n11\"></CanonicalizationMethod><SignatureMethod Algorithm=\"http://www.w3.org/2018/02/xmlgmdsig#ecsm2-sm3\"></SignatureMethod><Reference URI=\"http://127.0.0.1:5499/static/plaintext.xml\"><DigestMethod Algorithm=\"http://www.w3.org/2018/02/xmlgmdsig#sm3\"></DigestMethod><DigestValue>vBV30lPu+tguUpCfYr4rThfmejBAH6kskli8zgnWo7w=</DigestValue></Reference></SignedInfo><SignatureValue>pKLSa6p5CDqPFUejOpjXLGKWCPJY/+HcqSRyRqIr0R6GhmA8W/Onnh+UNsENfGVLS9vKKR3xpw0h\r\n"
      + "weq01dWtLQ==</SignatureValue><KeyInfo><KeyValue><ECKeyValue><NamedCurve xmlns=\"http://www.w3.org/2009/xmldsig11#\" URI=\"urn:oid:1.2.156.10197.1.301\"></NamedCurve><PublicKey>BIqL2+vUFwkKWIYEuds/l9BXxPYHO7EiJY4pWQlZXx55rieKYpjIaeDNDB8G09IJIUfgJRoMQk9f\r\n"
      + "ggs9WzsAkKE=</PublicKey></ECKeyValue></KeyValue></KeyInfo></Signature>";

  public static final String validtext_2 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
      + "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"123\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2006/12/xml-c14n11\"></CanonicalizationMethod><SignatureMethod Algorithm=\"http://www.w3.org/2018/02/xmlgmdsig#ecsm2-sm3\"></SignatureMethod><Reference URI=\"#_b7c8d910-c6f5-4d62-959a-bb81fd6a8b24\"><DigestMethod Algorithm=\"http://www.w3.org/2018/02/xmlgmdsig#sm3\"></DigestMethod><DigestValue>yt9KmtfYmGYEtZ4QaAh907C0rfgnC4U35HpYIMPlGp0=</DigestValue></Reference></SignedInfo><SignatureValue>DkrCGzUBiAIgrePKxX1UR8tDTpgYvKr36KTHrblz5YZfzUYQJZIhU5amt6hOl3lkZbEwf9aM3UlV\r\n"
      + "ShYVw+lXNw==</SignatureValue><KeyInfo><KeyValue><ECKeyValue><NamedCurve xmlns=\"http://www.w3.org/2009/xmldsig11#\" URI=\"urn:oid:1.2.156.10197.1.301\"></NamedCurve><PublicKey>BIqL2+vUFwkKWIYEuds/l9BXxPYHO7EiJY4pWQlZXx55rieKYpjIaeDNDB8G09IJIUfgJRoMQk9f\r\n"
      + "ggs9WzsAkKE=</PublicKey></ECKeyValue></KeyValue></KeyInfo><Object Id=\"_b7c8d910-c6f5-4d62-959a-bb81fd6a8b24\"><PurchaseOrder xmlns=\"urn:example:po\" Id=\"test\">\r\n"
      + "  <Items Id=\"test2\">\r\n" + "    <Item Code=\"001-001-001\" Quantity=\"1\">\r\n"
      + "      spade\r\n" + "    </Item>\r\n" + "    <Item Code=\"001-001-002\" Quantity=\"1\">\r\n"
      + "      shovel\r\n" + "    </Item>\r\n" + "  </Items>\r\n"
      + "  <ShippingAddress Id=\"test3\">\r\n" + "    Dig PLC, 1 First Ave, Dublin 1, Ireland\r\n"
      + "  </ShippingAddress>\r\n" + "  <PaymentInfo>\r\n" + "    <BillingAddress>\r\n"
      + "      Dig PLC, 1 First Ave, Dublin 1, Ireland\r\n" + "    </BillingAddress>\r\n"
      + "    <CreditCard Type=\"Amex\">\r\n" + "      <Name>Foo B Baz</Name>\r\n"
      + "      <Number>1234 567890 12345</Number>\r\n"
      + "      <Expires Month=\"1\" Year=\"2005\"></Expires>\r\n" + "    </CreditCard>\r\n"
      + "  </PaymentInfo>\r\n" + "</PurchaseOrder></Object></Signature>";

  public static final String RSAValidText = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
      + "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"123\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2006/12/xml-c14n11\"></CanonicalizationMethod><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"></SignatureMethod><Reference URI=\"http://localhost:5499/static/plaintext.xml\"><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></DigestMethod><DigestValue>FXB0npb6BJqCbISyTk7W+D3skcbnQixpECqF1PxtzQU=</DigestValue></Reference></SignedInfo><SignatureValue>lFuvNEhYSqaXyhFxb73F72I2D7iKyLgNHh7saS4qCmeWBtoHmj6Eillf6b3OlY7Ztx+iJrNnuHln\r\n"
      + "GqDRwyn5U/beG0Phi+kQydQrInKoOAO2y+JDRFZu8X1WTDqtg5dtg93d5s1x+slu1l0i6lNM9EuC\r\n"
      + "gvzJtCjcyypq72S78nKs+uXVS9gvUV4eb4hGTp4bfcnUxCxTHOrEkqY/ONf5xk3XSiANIlb2C0eM\r\n"
      + "zAinUqkxBbUDXeDJkio6B6FRPltJsG+4BCeGJ5fzYRMmODf5d+7pGvkfLwmlkqxpOYtc80wOe34v\r\n"
      + "Lq4Iduiot8hFFIhCVS9I5CsCkbv3fts5P4cJYw==</SignatureValue><KeyInfo><KeyValue><RSAKeyValue><Modulus>514eEQai25rJJax1JmnsLMrK6e3PJTdkgWuUB6gEvS4L/2Q6nwHmgSpKMjD8PM1nW45pJZNyRTIa\r\n"
      + "ML2+Kq7168IpvrXxbcDyQOKKRyGre+qQk7J+F9Q/HGYVWf4fADALbjg6wWGw1eYbkVNnn2ZsQSEF\r\n"
      + "Fc2Nb43WnyyCZPZzRzRLKSZVKj93UJL3pqOJDV+9guHIszGFXNTSQfO0zh/1mrAi9JqKl5mschgJ\r\n"
      + "ydahuXd2YkgG8x+88QkuXnLHbaIQKJHh6wMdIH81ukEMhsOt4ill5LRc3pvbXySQ1C41tZgjh2Lx\r\n"
      + "8DgZLPVQj/Z1o05DKk7XMP9gWGPGI6ABEPt1nw==</Modulus><Exponent>1+7aJs/HvSd4JcYPzBs9hgx6VttQ4g4Rqkwp6v9f9OP95Iy5vV87rz814iQfteuKVEPUVHKJSpVZ\r\n"
      + "JjZgPlvuPuuGpGwQeHuEXRRRM9PzxQIFjyMeVcUMZcfMk6H9cuJkOKkYBRXUwb0x628pHfasgBh+\r\n"
      + "M3wVTZDWRtZ2mB3/NuqL7ve2AjC7YlIUeNrH2+acwxNbKDJWn4dCgtBrpBfd8XGDpDrbqc721eTP\r\n"
      + "hhoCpSyot4zHUK3z4IdawC3qgr+1XEzQcmonA8HuQb1i3J/Q8YptylCIli2pixulMZo/B66nlLiN\r\n"
      + "83RFdPKEcZtNNYz5ozPyQyXsdqp4YpN5cya9IQ==</Exponent></RSAKeyValue></KeyValue></KeyInfo></Signature>\r\n"
      + "";

  public static void SM2KeyPair() {
    InputStream stream = new ByteArrayInputStream(PrivKey.getBytes(StandardCharsets.UTF_8));
    PEMParser pr = new PEMParser(new InputStreamReader(stream));
    Object o = null;
    try {
      o = pr.readObject();
      pr.close();
      JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
      kp = converter.getKeyPair((PEMKeyPair) o);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  public static void RSAKeyPair() {
    InputStream stream = new ByteArrayInputStream(RSAPrivKey.getBytes(StandardCharsets.UTF_8));
    PEMParser pr = new PEMParser(new InputStreamReader(stream));
    Object o = null;
    try {
      o = pr.readObject();
      pr.close();
      JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
      kp = converter.getKeyPair((PEMKeyPair) o);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  public static void CreatePlainDocument() {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    try {
      XMLDOC = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(plain.getBytes()));
      XMLUtils.outputDOM(XMLDOC, System.out);
    } catch (SAXException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    } catch (ParserConfigurationException e) {
      e.printStackTrace();
    }
  }

  public static void CreateSignedDocument() {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    try {
      SIGNED_XMLDOC =
          dbf.newDocumentBuilder().parse(new ByteArrayInputStream(validtext_2.getBytes()));
      XMLUtils.outputDOM(SIGNED_XMLDOC, System.out);
    } catch (SAXException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    } catch (ParserConfigurationException e) {
      e.printStackTrace();
    }
  }

}
