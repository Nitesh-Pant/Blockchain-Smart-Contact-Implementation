import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import java.util.ArrayList;
import java.util.Arrays;
import java.lang.reflect.Array;


public class ScannerExample 
{
    public static void main(String args[]) throws Exception, FileNotFoundException 
    {
        File text = new File("D:/College/Projects/output.txt");
        Scanner scnr = new Scanner(text);
        while(scnr.hasNextLine())
        {
            String plainText = scnr.nextLine();
            System.out.println(plainText);
        
        SecretKey secKey = getSecretEncryptionKey();
        byte[] cipherText = encryptText(plainText, secKey);
        String decryptedText = decryptText(cipherText, secKey);
        
        System.out.println("*******\nOriginal Text:" + plainText);
        System.out.println("\nAES Key (Hex Form):"+bytesToHex(secKey.getEncoded()));
        System.out.println("\nEncrypted Text (Hex Form):"+bytesToHex(cipherText));
        System.out.println("\nDescrypted Text:"+decryptedText);
        String plainTextt[]={""};
        Block genesisBlock = new Block(/*previousHash: */0, plainTextt);

        String[] block2Transactions = {"Nitesh sent 100 bitcoins to Google\n\t\t\tGoogle sent 10 bitcoin to KFC"};
        Block block2 = new Block(genesisBlock.getBlockHash(), block2Transactions);
      
        System.out.println("Hash of genesis block:\t" + genesisBlock.getBlockHash());
        System.out.println("Previous hash:\t\t" + "0");
        System.out.println("List of transactions:\t" +plainText +"\n\n");

        System.out.println("Hash of block 2:\t" + block2.getBlockHash());
        System.out.println("Previous hash:\t\t" + genesisBlock.getBlockHash()) ;
        System.out.println("List of transactions:\t" +Arrays.toString(block2Transactions) +"\n\n");
        }
    }
    /**
     * gets the AES encryption key. In your actual programs, this should be safely
     * stored.
     * @return
     * @throws Exception 
     */
    public static SecretKey getSecretEncryptionKey() throws Exception{
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128); // The AES key size in number of bits
        SecretKey secKey = generator.generateKey();
        return secKey;
    }
    
    /**
     * Encrypts plainText in AES using the secret key
     * @param plainText
     * @param secKey
     * @return
     * @throws Exception 
     */
    public static byte[] encryptText(String plainText,SecretKey secKey) throws Exception{
    // AES defaults to AES/ECB/PKCS5Padding in Java 7
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, secKey);
        byte[] byteCipherText = aesCipher.doFinal(plainText.getBytes());
        return byteCipherText;
    }
    
    /**
     * Decrypts encrypted byte array using the key used for encryption.
     * @param byteCipherText
     * @param secKey
     * @return
     * @throws Exception 
     */
    public static String decryptText(byte[] byteCipherText, SecretKey secKey) throws Exception {
    // AES defaults to AES/ECB/PKCS5Padding in Java 7
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, secKey);
        byte[] bytePlainText = aesCipher.doFinal(byteCipherText);
        return new String(bytePlainText);
    }
    
    /**
     * Convert a binary byte array into readable hex form
     * @param hash
     * @return 
     */
    private static String  bytesToHex(byte[] hash) {
        return DatatypeConverter.printHexBinary(hash);

        
    }      
}