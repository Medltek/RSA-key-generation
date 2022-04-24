package rsa;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.io.*;
import java.security.*;
import java.security.spec.*;

import javax.crypto.Cipher;

public class ToRun {

	static String plainText = "Testovaci token";
	static String publicKeyEncoded = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtJNu6qOiYMaRyIlFBHBkv5vVgBwX12oOHfBtUWXAvOtfb3WVJbVStMRJASEMh+fJOxR7TOKvIECQynaPpvXdQMFkNXFSKX0hRB96oTJBeeJrqHlM+07yO8R4ab00LaRAX84eP4S3gz1e44+QSQzgAxg3DlC29XTx2H/3Xl6CfpVPtRZKk2NrfkdJTK+Lrpw//eG7HSK0rPaUVqTjtdA2ElLQ76BsbG+oWhR0/3nBhefGEeLxVkWNANKoIRjbioFts/svFRIeDzUPbuMcKAdmxSjhZMTxvjVini7jg7VAoIGONJTh6DXHIH4EUF6dBq+CP+oPPeda/Fapv07IpaJ2yT46fwZaonYwWdRTSM2pyKxBhPugkL/2anlsX/2l3Noc8KARid0/McuXNnJgNJOJrt2s7SLlO/E8Ftr/q8d3+sCaJFvjbS1LRxneShKVTluZKVOFWWuzAA8Qd1rHukCABLSXTdBmPqCH1Kicbv43NkrSYZuaRyTwxNp27dEXSm+8CDLKXxY8wsnZmm7sm+sSJDdYSU1QQ9KtIHnbmOADT7Z4pA45IiK+CakYYwZSxunCSd+NL1O50RlYlExsdTkdUMe62x1i3R9Re00S+G+LdbFe2bR1cNfqTWiNJDNj4Zzx82tTS5/I7IORybPfl9/Rp0U2xE93ISUt2PNzd60oXRMCAwEAAQ==";
	static String privateKeyEncoded = "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";
	
	public static void main(String[] args) throws Exception {
		
		
		// Get an instance of the RSA key generator
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(4096);

        // Generate the KeyPair
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Get the public and private key
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        System.out.println(publicKey);
        System.out.println(privateKey);
        
        SaveKeyPair("C:\\Users\\dan0125\\eclipse-workspace\\rsa", keyPair);
        
        //trying to save public key to string
     	X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
     	byte[] bytesOfPublicKey = x509EncodedKeySpec.getEncoded();
     	System.out.println("bytesOfPublicKey " +bytesOfPublicKey.length);
     	System.out.println("x509EncodedKeySpec PUBLIC KEY: " +x509EncodedKeySpec);
        
     	//Encoding BASE64
     	String encodedPublicKey = Base64.getEncoder().encodeToString(bytesOfPublicKey);
     	System.out.println("encoded Base64 PUBLIC KEY : " + encodedPublicKey);
        //Decoding BASE64 back to byte array
     	byte[] decodedPublicKey = Base64.getDecoder().decode(encodedPublicKey);
     	System.out.println("decoded byte array length: " + decodedPublicKey.length);
     	
     	//Read back public Key
     	KeyFactory keyFactory = KeyFactory.getInstance("RSA");	
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
				decodedPublicKey);
		PublicKey publicKey2 = keyFactory.generatePublic(publicKeySpec);
		RSAPublicKeySpec publicKeySpec2 = keyFactory.getKeySpec(publicKey2, RSAPublicKeySpec.class);
        
		
		//trying to save private key to string
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
				privateKey.getEncoded());
		
		byte[] bytesOfPrivateKey = pkcs8EncodedKeySpec.getEncoded();
     	System.out.println(bytesOfPrivateKey.length);
		
     	//Encoding BASE64
     	String encodedPrivateKey = Base64.getEncoder().encodeToString(bytesOfPrivateKey);
     	System.out.println("encoded string: " + encodedPrivateKey);
        //Decoding BASE64 back to byte array
     	byte[] decodedPrivateKey = Base64.getDecoder().decode(encodedPrivateKey);
     	System.out.println("decoded byte array length: " + decodedPrivateKey.length);
		
     	//Read back the Private key
     	PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
     			decodedPrivateKey);
		PrivateKey privateKey2 = keyFactory.generatePrivate(privateKeySpec);
		RSAPrivateKeySpec privateKeySpec2 = keyFactory.getKeySpec(privateKey2, RSAPrivateKeySpec.class);
		
        // Saving the Key to the file
        System.out.println("Saving the keyFiles");
        saveKeyToFile("public.xml", publicKeySpec2.getModulus(), publicKeySpec2.getPublicExponent());
        saveKeyToFile("private.xml", privateKeySpec2.getModulus(), privateKeySpec2.getPrivateExponent());
        
        saveKeyToFile("public.key", publicKeySpec2.getModulus(), publicKeySpec2.getPublicExponent());
        saveKeyToFile("private.key", privateKeySpec2.getModulus(), privateKeySpec2.getPrivateExponent());

        //System.out.println("Public key data " + publicKeySpec2.getModulus(), publicKeySpec2.getPublicExponent());
        //System.out.println("Private key data " + privateKeySpec2.getModulus(), privateKeySpec2.getPrivateExponent());
        
        System.out.println("Original Text  : " + plainText);

        // Encryption
        byte[] cipherTextArray = encrypt(plainText, "D:\\sts-3.8.3.RELEASE\\Workspace\\Encryption\\public.key");
        System.out.println("CipherTextArray(before encoding to String) size : " + cipherTextArray.length);
        String encryptedText = Base64.getEncoder().encodeToString(cipherTextArray);
        System.out.println("Encrypted text : " + encryptedText);
        byte[] textBytes = Base64.getDecoder().decode(encryptedText);
        System.out.println("Encrypted text bytes count: " + textBytes.length);
        // Decryption
        String decryptedText = decrypt(cipherTextArray, "D:\\sts-3.8.3.RELEASE\\Workspace\\Encryption\\private.key");
        System.out.println("Decrypted text : " + decryptedText);
        
        //System.out.println(readKeyFromFile("private.key"));
        

    }

    public static void saveKeyToFile(String fileName, BigInteger modulus, BigInteger exponent) throws IOException
    {
        ObjectOutputStream ObjOutputStream = new ObjectOutputStream(
                new BufferedOutputStream(new FileOutputStream(fileName)));
        try
        {
            ObjOutputStream.writeObject(modulus);
            ObjOutputStream.writeObject(exponent);
        } catch (Exception e)
        {
            e.printStackTrace();
        } finally
        {
            ObjOutputStream.close();
        }
    }

    public static Key readKeyFromFile(String keyFileName) throws IOException
    {
        Key key = null;
        InputStream inputStream = new FileInputStream(keyFileName);
        ObjectInputStream objectInputStream = new ObjectInputStream(new BufferedInputStream(inputStream));
        try
        {
            BigInteger modulus = (BigInteger) objectInputStream.readObject();
            BigInteger exponent = (BigInteger) objectInputStream.readObject();
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            if (keyFileName.startsWith("public"))
                key = keyFactory.generatePublic(new RSAPublicKeySpec(modulus, exponent));
            else
                key = keyFactory.generatePrivate(new RSAPrivateKeySpec(modulus, exponent));

        } catch (Exception e)
        {
            e.printStackTrace();
        } finally
        {
            objectInputStream.close();
        }
        return key;
    }

    public static byte[] encrypt(String plainText, String fileName) throws Exception
    {
        Key publicKey = readKeyFromFile("public.key");
        
        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");

        // Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Perform Encryption
        byte[] cipherText = cipher.doFinal(plainText.getBytes());

        return cipherText;
    }

    public static String decrypt(byte[] cipherTextArray, String fileName) throws Exception
    {
        Key privateKey = readKeyFromFile("private.key");
        System.out.println("PRIVATE KEY USED FOR DECRYPT : " + privateKey);
        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");

        // Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        
        
        // Perform Decryption
        byte[] decryptedTextArray = cipher.doFinal(cipherTextArray);

        return new String(decryptedTextArray);
    }
	
    public static void SaveKeyPair(String path, KeyPair keyPair) throws IOException {
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
 
		// Store Public Key.
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
				publicKey.getEncoded());
		FileOutputStream fos = new FileOutputStream(path + "/public2.key");
		fos.write(x509EncodedKeySpec.getEncoded());
		fos.close();
 
		// Store Private Key.
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
				privateKey.getEncoded());
		fos = new FileOutputStream(path + "/private2.key");
		fos.write(pkcs8EncodedKeySpec.getEncoded());
		System.out.println("PKCS8 encoded key: " + pkcs8EncodedKeySpec.getEncoded());
		fos.close();
	}
 
	public KeyPair LoadKeyPair(String path, String algorithm)
			throws IOException, NoSuchAlgorithmException,
			InvalidKeySpecException {
		// Read Public Key.
		File filePublicKey = new File(path + "/public.key");
		FileInputStream fis = new FileInputStream(path + "/public.key");
		byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
		fis.read(encodedPublicKey);
		fis.close();
 
		// Read Private Key.
		File filePrivateKey = new File(path + "/private.key");
		fis = new FileInputStream(path + "/private.key");
		byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
		fis.read(encodedPrivateKey);
		fis.close();
 
		// Generate KeyPair.
		KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
				encodedPublicKey);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
 
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
				encodedPrivateKey);
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
 
		return new KeyPair(publicKey, privateKey);
	}
	
	
}
