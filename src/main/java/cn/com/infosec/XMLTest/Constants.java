package cn.com.infosec.XMLTest;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public class Constants {

  private Constants() {}

  public static KeyPair kp;

  public static Document XMLDOC;

  public static Document SIGNED_XMLDOC;

  public static final String PrivKey = "-----BEGIN EC PRIVATE KEY-----\r\n"
      + "MHcCAQEEIHnCKKyGWdiPX6CFHT48td9QqcGqkRme0vtGzTJJnTOHoAoGCCqBHM9V\r\n"
      + "AYItoUQDQgAEiovb69QXCQpYhgS52z+X0FfE9gc7sSIljilZCVlfHnmuJ4pimMhp\r\n"
      + "4M0MHwbT0gkhR+AlGgxCT1+CCz1bOwCQoQ==\r\n" + "-----END EC PRIVATE KEY-----";

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

  public static void CreatePlainDocument() {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    try {
      XMLDOC = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(plain.getBytes()));
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
    } catch (SAXException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    } catch (ParserConfigurationException e) {
      e.printStackTrace();
    }
  }

}
