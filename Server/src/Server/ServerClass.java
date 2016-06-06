package Server;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import sun.security.pkcs.PKCS7;

public class ServerClass extends Thread {

    Socket socket = null;
    BufferedReader bin = null;
    File keyFile = new File("D:\\key.txt");
    SecretKey key = null;
    String serverHashValue = null;

    public ServerClass(Socket socket) {
        this.socket = socket;
        //key = generateKey();
    }

    @Override
    public void run() {
        try {
            key = generateKey();
            writeKey(key, keyFile);
            bin = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String msg = bin.readLine();
            //System.out.println("Msg recieved from client: " + txt);
            
            /////////////////////////////////////////
            String hashValue = msg.substring(msg.length() - 32, msg.length());
            msg = msg.substring(0, msg.length() - 32);

            String tempMsg = msg;
            System.out.println("Message from the client : " + msg);

            String decryptedByteData = decrypt(key, msg);
            //String decryptedData = decryptedByteData.toString();
            System.out.println("Message from client:" + decryptedByteData);
            System.out.println("Hash from client:" + hashValue.length());

            //generate hash value of the user message.......
            try {
                MessageDigest md = MessageDigest.getInstance("MD5");
                md.update(decryptedByteData.getBytes());
                byte[] digest = md.digest();
                StringBuffer hexString = new StringBuffer();

                for (int i = 0; i < digest.length; i++) {
                    decryptedByteData = Integer.toHexString(0xFF & digest[i]);
                    if (decryptedByteData.length() < 2) {
                        decryptedByteData = "0" + decryptedByteData;
                    }

                    hexString.append(decryptedByteData);
                }

                serverHashValue = hexString.toString();
            } catch (Throwable e) {
                System.out.println("Error " + e.getMessage());
                e.printStackTrace();
            }
            System.out.println("hash in cal in server: " +
                    serverHashValue.length());
            if(serverHashValue.equals(hashValue)){
                System.out.println("message integrity is okey!");
            } else {
                System.out.println("message integrity failed !");
            }
        } catch (Exception ex) {
            Logger.getLogger(ServerClass.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        // generate DES secret key........
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        keyGen.init(56);
        return keyGen.generateKey();
    } 

    /** Save the specified TripleDES SecretKey to the specified file */
    public static void writeKey(SecretKey key, File f) throws  IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // Convert the secret key to an array of bytes like this
        SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("DES");
        //DESedeKeySpec keyspec = (DESedeKeySpec)
        //keyfactory.getKeySpec(key,DESedeKeySpec.class);
        DESKeySpec keyspec = (DESKeySpec) keyfactory.getKeySpec(key, DESKeySpec.class);
        byte[] rawkey = keyspec.getKey();

        // Write the raw key to the file
        FileOutputStream out = new FileOutputStream(f);
        out.write(rawkey);
        out.close();
    }

    /** Read a TripleDES secret key from the specified file */
    public static SecretKey readKey(File f) throws IOException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        // Read the raw bytes from the keyfile
        DataInputStream in = new DataInputStream(new FileInputStream(f));
        byte[] rawkey = new byte[(int) f.length()];
        in.readFully(rawkey);
        in.close();

        // Convert the raw bytes to a secret key like this
        DESedeKeySpec keyspec = new DESedeKeySpec(rawkey);
        SecretKeyFactory keyfactory =
                SecretKeyFactory.getInstance("DESede");
        SecretKey key = keyfactory.generateSecret(keyspec);
        return key;
    }

    //decrypt user data .........
    public static String decrypt(SecretKey key, String userMsg)
            throws NoSuchAlgorithmException, InvalidKeyException, IOException,
            IllegalBlockSizeException, NoSuchPaddingException,
            BadPaddingException {

        //decode the encoded text.......
        byte [] Base64Decode = new
                sun.misc.BASE64Decoder().decodeBuffer(userMsg);

        //String objBase64Decode=new String(Base64Decode, "UTF8");
        System.out.println("Decoded Message:" + Base64Decode);

        // get a DES cipher
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        //decryption initialization
        cipher.init(Cipher.DECRYPT_MODE, key);
        //decrypt the decoded text
        byte[] decryptedText = cipher.doFinal(Base64Decode);

        //unicode transform........
        String retrievedMessage=new String(decryptedText, "UTF8");
        System.out.println("Retrieved Message:" +
                retrievedMessage);
        return retrievedMessage;
    }
}
