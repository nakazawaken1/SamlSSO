import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map.Entry;
import java.util.Scanner;
import java.util.UUID;
import java.util.logging.Logger;

import javax.xml.XMLConstants;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class Main {
	static final Logger logger = Logger.getLogger(Main.class.getCanonicalName());

	static final int port = Integer.parseInt(System.getProperty("port", "8880"));
	static final String sp = System.getProperty("sp");
	static final String spUrl = System.getProperty("sp_url");
	static final Path certPath = Paths.get(System.getProperty("cert_path"));
	static final String password = System.getProperty("password");

	public static void main(String... unused) throws Exception {
		logger.info("web server is started. port = " + port);
		try (ServerSocket serverSocket = new ServerSocket()) {
			serverSocket.setReuseAddress(true);
			serverSocket.bind(new InetSocketAddress(port));
			for (boolean running = true; running;) {
				try (Socket socket = serverSocket.accept();
						InputStream in = socket.getInputStream();
						Scanner scanner = new Scanner(in);
						OutputStream out = socket.getOutputStream()) {
					String[] items = scanner.nextLine().split("[\\s?]+");
					logger.info(Arrays.toString(items));
					StringBuilder body = new StringBuilder();
					switch (items[1]) {
					case "/quit":
						body.append("shutdown server");
						running = false;
						break;
					default:
						if (items.length <= 3) {
							break;
						}
						String loginId = items[2];
						if (loginId.isEmpty()) {
							break;
						}
						String idp = "http://127.0.0.1:" + port;
						String xml = buildXml(loginId, idp, sp, spUrl);
						String samlResponse = sign(xml, certPath, password);
						body.append("<body onload=\"document.forms[0].submit()\"><form method=\"post\" action=\"")
								.append(spUrl).append("\"><input type=\"hidden\" name=\"SAMLResponse\" value=\"")
								.append(encodeBase64(samlResponse)).append("\"/></form></body>");
						break;
					}
					if (body.length() <= 0) {
						body.append(Arrays.toString(items));
					}
					byte[] bodyBytes = body.toString().getBytes(StandardCharsets.UTF_8);
					List<String> headers = Arrays.asList("HTTP/1.0 200 OK", "Connection: close",
							"Date: " + ZonedDateTime.now().format(DateTimeFormatter.RFC_1123_DATE_TIME),
							"Content-Type: text/html; charset=UTF-8", "Content-Length: " + bodyBytes.length);
					logger.info(headers.toString() + body);
					out.write((String.join("\r\n", headers) + "\r\n\r\n").getBytes());
					out.write(bodyBytes);
				}
			}
		}
		logger.info("web server is stoped.");
	}

	static Entry<PrivateKey, Certificate> loadCert(Path certPath, String password) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {
		char[] passwordArray = password.toCharArray();
		KeyStore store = KeyStore.getInstance("PKCS12");
		try (InputStream in = Files.newInputStream(certPath)) {
			store.load(in, passwordArray);
		}
		String alias = store.aliases().nextElement();
		PrivateKey privateKey = (PrivateKey) store.getKey(alias, passwordArray);
		Certificate certificate = store.getCertificate(alias);
		return new SimpleImmutableEntry<>(privateKey, certificate);
	}

	static String sign(String xml, Path certPath, String password)
			throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException,
			UnrecoverableKeyException, XPathExpressionException, ParserConfigurationException, SAXException,
			InvalidAlgorithmParameterException, MarshalException, XMLSignatureException, TransformerException {
		Document dom = xmlFromString(xml);
		Element target = (Element) dom.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion")
				.item(0);
		String id = target.getAttribute("ID");
		target.setIdAttribute("ID", true);
		XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
		DigestMethod digest = factory.newDigestMethod(DigestMethod.SHA1, null);
		List<Transform> transforms = Arrays.asList(
				factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null),
				factory.newTransform(CanonicalizationMethod.EXCLUSIVE, (TransformParameterSpec) null));
		Reference reference = factory.newReference("#" + id, digest, transforms, null, null);
		SignedInfo signedInfo = factory.newSignedInfo(
				factory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
				factory.newSignatureMethod(SignatureMethod.RSA_SHA1, null), Arrays.asList(reference));
		KeyInfoFactory keyFactory = factory.getKeyInfoFactory();
		Entry<PrivateKey, Certificate> pair = loadCert(certPath, password);
		KeyInfo keyInfo = keyFactory.newKeyInfo(Arrays.asList(keyFactory.newX509Data(Arrays.asList(pair.getValue()))));
		factory.newXMLSignature(signedInfo, keyInfo).sign(new DOMSignContext(pair.getKey(), target));
		return xmlToString(dom);
	}

	static String buildXml(String loginId, String idp, String sp, String spUrl) {
		try (Scanner xmlScanner = new Scanner(ClassLoader.getSystemResourceAsStream("response.xml"))) {
			xmlScanner.useDelimiter("\\Z");
			return String.format(xmlScanner.next(), //
					"i" + UUID.randomUUID(), // 1
					ZonedDateTime.now().format(DateTimeFormatter.ISO_INSTANT), // 2
					spUrl, // 3
					idp, // 4
					"i" + UUID.randomUUID(), // 5
					sp, // 6
					loginId, // 7
					ZonedDateTime.now().plusMinutes(10).format(DateTimeFormatter.ISO_INSTANT));// 8
		}
	}

	static Document xmlFromString(String xml)
			throws ParserConfigurationException, SAXException, IOException, XPathExpressionException {
		if (xml.contains("<!ENTITY")) {
			throw new SAXException("Detected use of ENTITY in XML, disabled to prevent XXE/XEE attacks");
		}
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		factory.setExpandEntityReferences(false);
		factory.setAttribute("http://java.sun.com/xml/jaxp/properties/schemaLanguage",
				XMLConstants.W3C_XML_SCHEMA_NS_URI);
		try {
			factory.setAttribute("http://xml.org/sax/features/external-general-entities", Boolean.FALSE);
		} catch (Throwable e) {
		}
		try {
			factory.setAttribute("http://xml.org/sax/features/external-parameter-entities", Boolean.FALSE);
		} catch (Throwable e) {
		}
		try {
			factory.setAttribute("http://apache.org/xml/features/disallow-doctype-decl", Boolean.TRUE);
		} catch (Throwable e) {
		}
		try {
			factory.setAttribute("http://javax.xml.XMLConstants/feature/secure-processing", Boolean.TRUE);
		} catch (Throwable e) {
		}
		try {
			factory.setAttribute("http://apache.org/xml/features/nonvalidating/load-external-dtd", Boolean.FALSE);
		} catch (Throwable e) {
		}
		try {
			factory.setAttribute("http://apache.org/xml/features/nonvalidating/load-dtd-grammar", Boolean.FALSE);
		} catch (Throwable e) {
		}
		try {
			factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		} catch (Throwable e) {
		}
		Document dom = factory.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
		XPathExpression expression = XPathFactory.newInstance().newXPath().compile("//*[@ID]");
		NodeList nodeList = (NodeList) expression.evaluate(dom, XPathConstants.NODESET);
		for (int i = 0; i < nodeList.getLength(); i++) {
			Element element = (Element) nodeList.item(i);
			Attr attr = (Attr) element.getAttributes().getNamedItem("ID");
			element.setIdAttributeNode(attr, true);
		}
		return dom;
	}

	static String xmlToString(Document dom) throws TransformerException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		TransformerFactory.newInstance().newTransformer().transform(new DOMSource(dom), new StreamResult(out));
		return new String(out.toByteArray(), StandardCharsets.UTF_8);
	}

	static String encodeBase64(String input) {
		return new String(Base64.getEncoder().encode(input.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
	}
}
