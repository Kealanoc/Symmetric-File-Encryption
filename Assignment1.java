/* sources used to help throughout this assignment:
    https://www.geeksforgeeks.org/biginteger-testbit-method-in-java/
    https://www.geeksforgeeks.org/modular-exponentiation-power-in-modular-arithmetic/
    https://stackoverflow.com/questions/18142745/how-do-i-generate-a-salt-in-java-for-salted-hash
    https://howtodoinjava.com/java/java-security/aes-256-encryption-decryption/
    https://www.geeksforgeeks.org/java-program-to-convert-byte-array-to-hex-string/
    https://stackoverflow.com/questions/19623367/rsa-encryption-decryption-using-java
    https://www.baeldung.com/sha-256-hashing-java
*/

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import java.util.Random;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Assignment1 implements Assignment1Interface
{    

    private final static Logger logger = Logger.getLogger(Assignment1.class.getName());
    
    private static byte[] generateSalt()
    {   
        // generate 16 bytes == 128 bit salt
        byte [] byteVal = new byte[16];
        /** secure random is used instead of the default random as it generates with 128 bits as opposed to the default randoms 48 bits
         This ensures that our random number generater is more cryptographically secure */
         Random rng = new SecureRandom();
         // converts our secure random number to 16 byte form
         rng.nextBytes(byteVal);
         return byteVal;
    }
    
    private static byte[] EncryptPassword(String password) throws UnsupportedEncodingException
    {
        byte[] BytePass = password.getBytes("UTF-8");
        return BytePass;
    }
    
    private static byte[] generateIV()
    {
        // similar process to generating the salt
        byte [] IVbytes = new byte[16];
        Random rnd = new SecureRandom();
        rnd.nextBytes(IVbytes);
        
        return IVbytes;
    }
    
    // generateKey returns a key as an array of bytes and is generated from the password and salt inputs.
	public byte[] generateKey(byte[] password, byte[] salt)
    {
        byte [] key = new byte[password.length + salt.length];
        System.arraycopy(password, 0, key, 0, password.length);
        System.arraycopy(salt, 0, key, password.length, salt.length);
        
        //loop to hash 200 times https://www.baeldung.com/sha-256-hashing-java
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (int i = 0; i < 200; i++) 
            {
                key = digest.digest(key);
            }
        } catch (NoSuchAlgorithmException e) {
            logger.info("Invalid hash");
        }
        return key;
    }
	
    // Method encryptAES returns the AES encryption of the given plaintext as an array of bytes using the given iv and key   
	public byte[] encryptAES(byte[] plaintext, byte[] iv, byte[] key)
    {
        try 
        {
            IvParameterSpec IV = new IvParameterSpec(iv);
            SecretKeySpec AESkey = new SecretKeySpec(key, "AES");
            Cipher encryption = Cipher.getInstance("AES/CBC/NoPadding");
            encryption.init(Cipher.ENCRYPT_MODE, AESkey, IV);
            
            // padding
            int padding = 16 - (plaintext.length % 16);
            byte[] paddedFile = new byte[plaintext.length + padding];
		    System.arraycopy(plaintext, 0, paddedFile, 0, plaintext.length);		
            
            // set leftmost bit to 1, followed by zeros
		    paddedFile[plaintext.length] = (byte) 128;
		    for (int i = plaintext.length + 1; i < paddedFile.length; i++) 
            {
                paddedFile[i] = (byte) 0;
		    }
            
            byte[] cipherBytes = encryption.doFinal(paddedFile);
            
            return cipherBytes;
        }
        catch(Exception e)
        {
            logger.info("Error file encryption failed");
            System.out.println(e);
            return plaintext;
        }
    }
	
    // Similar to above but decrypts the cipher, dont believe this is acutally needed but used mainly for testing
    
    public byte[] decryptAES(byte[] ciphertext, byte[] iv, byte[] key) 
    {
        try 
        {
            IvParameterSpec IV = new IvParameterSpec(iv);
            SecretKeySpec AESkey = new SecretKeySpec(key, "AES");
            Cipher decryptor = Cipher.getInstance("AES/CBC/NoPadding");
            decryptor.init(Cipher.DECRYPT_MODE, AESkey, IV);
            
            byte[] plaintextBytes = decryptor.doFinal(ciphertext);
            
            return plaintextBytes;
        }
        catch(Exception e)
        {
            logger.info("Error file decryption failed");
            System.out.println(e);
            return ciphertext;
        }
    }
    
    private static String toHex(byte[] byteArray)
    {
        String hex = "";
        for (byte i : byteArray) {
            hex += String.format("%02X", i);
        }
        return hex;
    }	
    
    //returns the encryption of the given plaintext
    
    public byte[] encryptRSA(byte[] plaintext, BigInteger exponent, BigInteger modulus) 
    {
        byte[] RSA = null;
        BigInteger base = new BigInteger(plaintext);
        BigInteger modExp = modExp(base, exponent, modulus);
        RSA = modExp.toByteArray();
        return RSA;
    }
    
    public BigInteger modExp(BigInteger base, BigInteger exponent, BigInteger modulus) 
    {
        BigInteger y = new BigInteger("1");
        while(exponent.compareTo(BigInteger.ZERO) > 0) 
        {
            // The method returns true if and only if the designated bit is set else it will return false.
            if(exponent.testBit(0)) y = (y.multiply(base).mod(modulus));
            exponent = exponent.shiftRight(1);
            // p^e(mod N)
            base = (base.multiply(base).mod(modulus));
        }
        return y.mod(modulus);
    }

    
    private static final BigInteger publicMod = new BigInteger("c406136c12640a665900a9df4df63a84fc855927b729a3a106fb3f379e8e4190ebba442f67b93402e535b18a5777e6490e67dbee954bb02175e43b6481e7563d3f9ff338f07950d1553ee6c343d3f8148f71b4d2df8da7efb39f846ac07c865201fbb35ea4d71dc5f858d9d41aaa856d50dc2d2732582f80e7d38c32aba87ba9", 16);
    public static void main(String[] args) throws GeneralSecurityException, IOException 
    {
        // Initialise inputs, create password, generate salt and IV, encrypt password.
        Assignment1 cipher = new Assignment1();
        String file = args[0];
        BigInteger exponent = new BigInteger("65537");
        String password = "z{t<eQ`H`6Y@rz(S";
        byte[] IV = generateIV();
        byte[] SecretPassword = EncryptPassword(password);
        byte[] salt = generateSalt();
        
        //generate encryption key with length 256 bits
        byte [] encryptionKey = cipher.generateKey(SecretPassword, salt);
        
        try 
        {
            Path filePath = Paths.get(System.getProperty("user.dir") + "/" + file);
            byte[] fileBytes = Files.readAllBytes(filePath);
            byte[] encryptedText = cipher.encryptAES(fileBytes, IV, encryptionKey);
            byte [] decryptedText = cipher.decryptAES(encryptedText, IV, encryptionKey);
            String decryptedCipherText = toHex(decryptedText);
            String cipherText = toHex(encryptedText);
            
            BufferedWriter PasswordOut = new BufferedWriter(new FileWriter ("Password.txt"));
            byte[] RSA = cipher.encryptRSA(SecretPassword,exponent,publicMod);
            String RSAhex = toHex(RSA);
            PasswordOut.write(RSAhex);
            PasswordOut.close();
            
            BufferedWriter IVOut = new BufferedWriter(new FileWriter ("IV.txt"));
            IVOut.write(toHex(IV));
            IVOut.close();
            
            BufferedWriter SaltOut = new BufferedWriter(new FileWriter ("Salt.txt"));
            SaltOut.write(toHex(salt));
            SaltOut.close();
            
            System.out.println(cipherText);            
            
        } catch (Exception e) {
            logger.info("Error with reading file");
        }
        
        
    }
    
}