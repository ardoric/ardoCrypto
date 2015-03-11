package ardo.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

public class CryptoBackend {
	
	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}
	
	private static final byte[] fixedSalt = 
			DatatypeConverter.parseBase64Binary("rgbah+AZtko0FlU0W6BCaaAuvKKlF2dAFHjrEVZTF+8RKQPOyn/RO9D8LOCLlAOxgoPad0HcQS5IAWYIq5RsMmihILUdWHe3Gr7YZJUNGtzPqZZI+VtmTS4Hvb+LHbahD5dhWey1moFlYmrxpjkisI1OPkS/1EnWaiaUf/9iVEw=");
	private static final int iterationCount = 37649;
	// wonder if this reseeds itself or if I need to be careful about it.
	private static final SecureRandom rng = new SecureRandom();
	
	
	public synchronized static byte[] getRandomBytes(int count) {
		byte[] res = new byte[count];
		rng.nextBytes(res);
		return res;
	}
	
	public static byte[] deriveKey(String password) throws Exception {	
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		KeySpec spec = new PBEKeySpec(password.toCharArray(), fixedSalt, iterationCount, 256);
		return factory.generateSecret(spec).getEncoded();
	}
	
	
	public static String encrypt(byte[] keyBytes, String plaintext) throws Exception {
		SecretKey key = new SecretKeySpec(keyBytes, "AES");

		Cipher encrypter = getCipher();
		Mac mac = Mac.getInstance("HMACSHA256");

		byte[] iv = getRandomBytes(encrypter.getBlockSize());
		encrypter.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
		mac.init(key);
		
		// encrypt then mac
		
		ByteArrayOutputStream ostream = new ByteArrayOutputStream();
		ostream.write(iv);
		byte[] cipherBytes = encrypter.doFinal(plaintext.getBytes("UTF-8"));
		ostream.write(cipherBytes);
		
		mac.update(iv);
		byte[] macBytes = mac.doFinal(cipherBytes);
		ostream.write(macBytes);
		ostream.close();
		
		
		return DatatypeConverter.printBase64Binary(ostream.toByteArray());
	}
	
	public static String decrypt(byte[] keyBytes, String cipherText) throws Exception {
		SecretKey key = new SecretKeySpec(keyBytes, "AES");

		Cipher decrypter = getCipher();
		Mac mac = Mac.getInstance("HMACSHA256");

		byte[] cipherBytes = DatatypeConverter.parseBase64Binary(cipherText);
		
		if (cipherBytes.length < mac.getMacLength() + decrypter.getBlockSize())
			throw new Exception("Ciphertext Length too short");
		
		DataInputStream istream = new DataInputStream(new ByteArrayInputStream(cipherBytes));
		byte [] iv = new byte[decrypter.getBlockSize()];
		byte [] macBytes = new byte[mac.getMacLength()];
		byte [] cBytes = new byte[cipherBytes.length - iv.length - macBytes.length];
		

		istream.read(iv);
		istream.read(cBytes);
		istream.read(macBytes);
		
		istream.close();
		
		mac.init(key);
		
		mac.update(iv);
		byte[] mBytes = mac.doFinal(cBytes);
		
		if (!equalBytes(macBytes, mBytes))
			throw new Exception("Decryption Failed");

		decrypter.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
		return new String(decrypter.doFinal(cBytes), "UTF-8");
	}	
	
	public static String det_encrypt(byte[] keyBytes, String plaintext) throws Exception {
		SecretKey key = new SecretKeySpec(keyBytes, "AES");

		Cipher encrypter = getCipher();
		Mac mac = Mac.getInstance("HMACSHA256");

		byte[] plainBytes = plaintext.getBytes("UTF-8"); 
		byte[] iv = new byte[encrypter.getBlockSize()];

		mac.init(key);		
		System.arraycopy(mac.doFinal(plainBytes), 0, iv, 0, iv.length);
		
		encrypter.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
				
		ByteArrayOutputStream ostream = new ByteArrayOutputStream();
		ostream.write(iv);
		ostream.write(encrypter.doFinal(plainBytes));
		ostream.close();
		
		return DatatypeConverter.printBase64Binary(ostream.toByteArray());
	}
	
	public static String det_decrypt(byte[] keyBytes, String cipherText) throws Exception {
		SecretKey key = new SecretKeySpec(keyBytes, "AES");

		Mac mac = Mac.getInstance("HMACSHA256");
		Cipher decrypter = getCipher();
		
		byte[] cipherBytes = DatatypeConverter.parseBase64Binary(cipherText);
		DataInputStream istream = new DataInputStream(new ByteArrayInputStream(cipherBytes));
		
		
		byte [] iv = new byte[decrypter.getBlockSize()];
		byte [] cBytes = new byte[cipherBytes.length - iv.length];
		

		istream.read(iv);
		istream.read(cBytes);

		decrypter.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
		
		byte[] plainBytes = decrypter.doFinal(cBytes);
		
		mac.init(key);

		byte[] macIV = new byte[iv.length];		
		System.arraycopy(mac.doFinal(plainBytes), 0, macIV, 0, iv.length);
		
		if (!equalBytes(iv, macIV))
			throw new Exception("Decryption Failed");
		
		return new String(plainBytes, "UTF-8");
	}
	
	public static byte[] hash(String input, String algorithm) throws Exception {
		return MessageDigest.getInstance(algorithm).digest(input.getBytes("UTF-8"));
	}
		
	private static Cipher getCipher() throws Exception {
		return Cipher.getInstance("AES/CBC/PKCS7Padding");
		// return Cipher.getInstance("AES/CTR/NoPadding");
	}
	
	private static boolean equalBytes(byte[] b1, byte[] b2) { 
		// engineered to always take the same ammount of time (for equal length arrays)
		int minLen = (b1.length > b2.length)? b2.length : b1.length;
		boolean res = b1.length == b2.length;
		for (int i = 0; i < minLen; i++) {
			res = res && (b1[i] == b2[i]);
		}
		return res;
	}
	
	public static String doMac(byte[] key, String input) throws Exception {
		Mac mac = Mac.getInstance("HMACSHA256");
		mac.init(new SecretKeySpec(key, "AES"));
		
		return DatatypeConverter.printBase64Binary(mac.doFinal(input.getBytes("UTF-8")));
	}
	
	private static void generateSalt() {
		for (int i = 0; i < 20; i++) {
			System.out.println(DatatypeConverter.printBase64Binary(getRandomBytes(128)));
		}		
	}
	
	public static String hashPassword(String password) throws Exception {
		byte[] salt = getRandomBytes(24);
		MessageDigest hash = MessageDigest.getInstance("SHA-512");
		
		hash.update(salt);
		hash.update(password.getBytes("UTF-8"));
		
		byte[] hashBytes = hash.digest();
		
		return DatatypeConverter.printBase64Binary(salt) + ":" + DatatypeConverter.printBase64Binary(hashBytes);
	}
	
	public static boolean comparePassword(String password, String hash) throws Exception {
		String[] split = hash.split(":");
		byte[] salt = DatatypeConverter.parseBase64Binary(split[0]);
		byte[] originalHash = DatatypeConverter.parseBase64Binary(split[1]);
		
		MessageDigest digest = MessageDigest.getInstance("SHA-512");
		digest.update(salt);
		digest.update(password.getBytes("UTF-8"));
		
		byte[] calculatedHash = digest.digest();
		
		return slowEquals(originalHash, calculatedHash);
	}
	
    /** 
     * Compares two byte arrays in length-constant time. This comparison method
     * is used so that password hashes cannot be extracted from an on-line 
     * system using a timing attack and then attacked off-line.
     * 
     * @param   a       the first byte array
     * @param   b       the second byte array 
     * @return          true if both byte arrays are the same, false if not
     * 
     * taken from https://crackstation.net/hashing-security.htm#javasourcecode
     */
    private static boolean slowEquals(byte[] a, byte[] b)
    {
        int diff = a.length ^ b.length;
        for(int i = 0; i < a.length && i < b.length; i++)
            diff |= a[i] ^ b[i];
        return diff == 0;
    }
    
    
    public static String rsa_generateKey(int bits) throws Exception
    {
    	KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    	keyGen.initialize(bits);
    	
        return keyPairToXML(keyGen.genKeyPair());
    }

    public static String rsa_getPublicKey(String privateKey) throws Exception
    {
        DocumentBuilder docBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        
        Document pubDoc = docBuilder.newDocument();
        Document privDoc = docBuilder.parse(new InputSource(new StringReader(privateKey)));
        
        Element pubRoot = pubDoc.createElement("RSAKeyValue");
        pubDoc.appendChild(pubRoot);
        
        Element privRoot = (Element)privDoc.getElementsByTagName("RSAKeyValue").item(0);
        pubRoot.appendChild(pubDoc.importNode(privRoot.getElementsByTagName("Modulus").item(0).cloneNode(true), true));
        pubRoot.appendChild(pubDoc.importNode(privRoot.getElementsByTagName("Exponent").item(0).cloneNode(true), true));
        
    	return docToXML(pubDoc);
    }

    public static String rsa_encrypt(String publicKey, String plaintext) throws Exception
    {
        Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding");
        
        KeyFactory keyfact = KeyFactory.getInstance("RSA");
        PublicKey key = keyfact.generatePublic(getPublicSpecFromXML(publicKey));
        
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
    	return DatatypeConverter.printBase64Binary(cipher.doFinal( plaintext.getBytes("UTF-8") ));
    }

    public static String rsa_decrypt(String privateKey, String ciphertext) throws Exception
    {
        Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding");
        
        KeyFactory keyfact = KeyFactory.getInstance("RSA");
        PrivateKey key = keyfact.generatePrivate(getPrivateSpecFromXML(privateKey));
        
        cipher.init(Cipher.DECRYPT_MODE, key);
        
    	return new String(cipher.doFinal(DatatypeConverter.parseBase64Binary(ciphertext)), "UTF-8");
    }
    
    
    private static String keyPairToXML(KeyPair keyPair) throws Exception {
    	
        
        DocumentBuilder docBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        
        Document doc = docBuilder.newDocument();
        Element root = doc.createElement("RSAKeyValue");
        doc.appendChild(root);

        RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        
        addElement(root, doc.createElement("Modulus"),  privKey.getModulus());
        addElement(root, doc.createElement("Exponent"), privKey.getPublicExponent());
        addElement(root, doc.createElement("P"),  privKey.getPrimeP());
        addElement(root, doc.createElement("Q"),  privKey.getPrimeQ());
        addElement(root, doc.createElement("DP"), privKey.getPrimeExponentP());
        addElement(root, doc.createElement("DQ"), privKey.getPrimeExponentQ());
        addElement(root, doc.createElement("InverseQ"), privKey.getCrtCoefficient());
        addElement(root, doc.createElement("D"),  privKey.getPrivateExponent());
        
        
        return docToXML(doc);
    }
    
    private static void addElement(Element root, Element newElement, BigInteger value) {
    	String text = DatatypeConverter.printBase64Binary(toIntegerBytes(value));
    	newElement.setTextContent(text);
    	root.appendChild(newElement);
    }

	
    private static String docToXML(Document doc) throws Exception {
    	  Transformer transformer = TransformerFactory.newInstance().newTransformer();
    	  transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
    	  StreamResult result = new StreamResult(new StringWriter());
    	  DOMSource source = new DOMSource(doc);
    	  transformer.transform(source, result);
    	  return result.getWriter().toString();
    }
    
    private static RSAPrivateCrtKeySpec getPrivateSpecFromXML(String privateKey) throws Exception {
        DocumentBuilder docBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Element privKey = (Element)docBuilder.parse(new InputSource(new StringReader(privateKey))).getFirstChild();

    	RSAPrivateCrtKeySpec spec = 
    			new RSAPrivateCrtKeySpec(
    					getKeyComponent(privKey, "Modulus"), 
    					getKeyComponent(privKey, "Exponent"), 
    					getKeyComponent(privKey, "D"), 
    					getKeyComponent(privKey, "P"), 
    					getKeyComponent(privKey, "Q"), 
    					getKeyComponent(privKey, "DP"), 
    					getKeyComponent(privKey, "DQ"), 
    					getKeyComponent(privKey, "InverseQ"));
    	return spec;
    }
    
    private static RSAPublicKeySpec getPublicSpecFromXML(String publicKey) throws Exception {
        DocumentBuilder docBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Element privKey = (Element)docBuilder.parse(new InputSource(new StringReader(publicKey))).getFirstChild();

        RSAPublicKeySpec spec = 
    			new RSAPublicKeySpec(
    					getKeyComponent(privKey, "Modulus"), 
    					getKeyComponent(privKey, "Exponent")); 
    	return spec;    	
    }
    
    private static BigInteger getKeyComponent(Element root, String component) {
    	return new BigInteger(1, DatatypeConverter.parseBase64Binary(root.getElementsByTagName(component).item(0).getTextContent()));
    }
    
    	
    /**
     * 
     * Taken from apache commons. 
     * http://commons.apache.org/proper/commons-codec/apidocs/src-html/org/apache/commons/codec/binary/Base64.html
     * 
     * Returns a byte-array representation of a <code>BigInteger</code> without sign bit.
     *
     * @param bigInt
     *            <code>BigInteger</code> to be converted
     * @return a byte array representation of the BigInteger parameter
     */
    private static byte[] toIntegerBytes(final BigInteger bigInt) {
    	int bitlen = bigInt.bitLength();
    	// round bitlen
    	bitlen = ((bitlen + 7) >> 3) << 3;
    	final byte[] bigBytes = bigInt.toByteArray();

    	if (((bigInt.bitLength() % 8) != 0) && (((bigInt.bitLength() / 8) + 1) == (bitlen / 8))) {
    		return bigBytes;
    	}
    	// set up params for copying everything but sign bit
    	int startSrc = 0;
    	int len = bigBytes.length;

    	// if bigInt is exactly byte-aligned, just skip signbit in copy
    	if ((bigInt.bitLength() % 8) == 0) {
    		startSrc = 1;
    		len--;
    	}
    	final int startDst = bitlen / 8 - len; // to pad w/ nulls as per spec
    	final byte[] resizedBytes = new byte[bitlen / 8];
    	System.arraycopy(bigBytes, startSrc, resizedBytes, startDst, len);
    	return resizedBytes;
    }

}
