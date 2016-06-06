package client;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import sun.security.pkcs.*;

public class NewJFrame extends javax.swing.JFrame {

    /** Creates new form NewJFrame */
    PrintWriter in = null;
    Socket socket = null;

    public NewJFrame() {
        initComponents();
        txtMsg.setVisible(false);
        btnSent.setVisible(false);
    }

    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        btnLogin = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        txtMsg = new javax.swing.JTextField();
        btnSent = new javax.swing.JButton();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        txtPassword = new javax.swing.JTextField();
        txtLogin = new javax.swing.JTextField();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        btnLogin.setText("Login");
        btnLogin.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnLoginActionPerformed(evt);
            }
        });

        btnSent.setText("Sent");
        btnSent.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnSentActionPerformed(evt);
            }
        });

        jLabel2.setText("Login");

        jLabel3.setText("Password");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel3)
                            .addComponent(jLabel2))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(txtLogin)
                            .addComponent(txtPassword, javax.swing.GroupLayout.DEFAULT_SIZE, 123, Short.MAX_VALUE)
                            .addComponent(btnLogin)))
                    .addComponent(txtMsg, javax.swing.GroupLayout.PREFERRED_SIZE, 309, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel1, javax.swing.GroupLayout.DEFAULT_SIZE, 380, Short.MAX_VALUE)
                    .addComponent(btnSent))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(20, 20, 20)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel2)
                    .addComponent(txtLogin, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(30, 30, 30)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3)
                    .addComponent(txtPassword, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(btnLogin)
                .addGap(18, 18, 18)
                .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 18, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(txtMsg, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(btnSent)
                .addContainerGap(61, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void btnLoginActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnLoginActionPerformed
        try {
            if(txtLogin.getText().equalsIgnoreCase("user") &&
                    txtPassword.getText().equalsIgnoreCase("user")) {
                txtMsg.setVisible(true);
                btnSent.setVisible(true);
                socket = new Socket("localhost", 4141);
                jLabel1.setText("Client is connected........");
                //btnLogin.setEnabled(false);

                txtLogin.setVisible(false);
                txtPassword.setVisible(false);
                jLabel2.setVisible(false);
                jLabel3.setVisible(false);
                btnLogin.setVisible(false);
            } else {
                
            }
        } catch(Exception ex) {
            System.err.println(ex.getLocalizedMessage());
        }
    }//GEN-LAST:event_btnLoginActionPerformed

    private void btnSentActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnSentActionPerformed
        try {
            File keyFile = new File("C:\\Ahad/key.txt");
            in = new PrintWriter(socket.getOutputStream());
            
            String hashValue = txtMsg.getText(); 
            java.net.Socket sock = null;
            // Socket object for communicating 
            java.io.PrintWriter     pw   = null;                              
            // socket output to server 
            java.io.BufferedReader  br   = null;
            String encryptedData = null;
            // socket input from server 
            
            //generate hash value of the user message....... 
            try{ 
                MessageDigest md = MessageDigest.getInstance("MD5"); 
                md.update(hashValue.getBytes()); 
                byte[] digest = md.digest(); 
                StringBuffer hexString = new StringBuffer(); 
                
                for (int i = 0; i < digest.length; i++) { 
                    hashValue = Integer.toHexString(0xFF & digest[i]); 
                    if (hashValue.length() < 2) {                   
                        hashValue = "0" + hashValue; 
                    } 
                    
                    hexString.append(hashValue); 
                } 
                
                hashValue = hexString.toString(); 
            }catch (Throwable e) { 
                System.out.println("Error " + e.getMessage()); 
                e.printStackTrace(); 
            } 
            
            SecretKey key = null; 
            try { 
                key = readKey(keyFile);
            } catch (Exception e1) { 
                e1.printStackTrace(); 
            } 
            
            //encrypt data...... 
            try { 
                encryptedData = encrypt(key, txtMsg.getText());
            } catch (Exception e1) {
                e1.printStackTrace(); 
            } 
            
            String transmittedData = encryptedData + hashValue;
            
            in.println(transmittedData);
            in.flush();
        } catch (IOException ex) {
            Logger.getLogger(NewJFrame.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_btnSentActionPerformed

    /**
    * @param args the command line arguments
    */
    public static void main(String args[]) {
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new NewJFrame().setVisible(true);
            }
        });
    }
    
    /** Read a TripleDES secret key from the specified file */
    public static SecretKey readKey(File f) throws IOException,
            NoSuchAlgorithmException, InvalidKeyException,
            InvalidKeySpecException {
        // Read the raw bytes from the keyfile
        DataInputStream in = new DataInputStream(new FileInputStream(f));
        byte[] rawkey = new byte[(int) f.length()];
        in.readFully(rawkey);
        in.close();

        // Convert the raw bytes to a secret key like this
        //DESedeKeySpec keyspec = new DESedeKeySpec(rawkey);
        DESKeySpec keyspec = new DESKeySpec(rawkey);
        SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("DES");
        SecretKey key = keyfactory.generateSecret(keyspec);
        return key;
    }

     public static String encrypt(SecretKey key, String msg)
             throws NoSuchAlgorithmException, InvalidKeyException,
             NoSuchPaddingException, IOException, IllegalBlockSizeException,
             BadPaddingException {
         Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

         cipher.init(Cipher.ENCRYPT_MODE, key);
         byte[] unicodeTransformedUserText= msg.getBytes("UTF8");
         byte[] cipherText =
                 cipher.doFinal(unicodeTransformedUserText);
         System.out.println("Encrypted Message:" + cipherText);
         String Base64Encode = new
                 sun.misc.BASE64Encoder().encode(cipherText);
         System.out.println("Encoded Message:" + Base64Encode);
         return Base64Encode;
     }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnLogin;
    private javax.swing.JButton btnSent;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JTextField txtLogin;
    private javax.swing.JTextField txtMsg;
    private javax.swing.JTextField txtPassword;
    // End of variables declaration//GEN-END:variables

}
