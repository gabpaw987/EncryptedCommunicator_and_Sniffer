/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package encryptioncommunicator;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 * In dieser Klasse werden asymetrische und symetrische Verschluesselungen
 * bearbeitet.</br> - generieren von Keys - entschluesseln von Nachrichten und
 * Keys </br> - verschluesseln von Nachrichten und Keys
 *
 * @author Josef Sochovsky
 * @version 1.0
 */
public class CryptographicMethods {

    /**
     * Diese Methode generiert einen synchronen Secretkey ("AES")
     *
     * @return ein AES Secretkey
     */
    public SecretKey generateSynchronousKey() {
        SecretKey key = null;
        try {
            // Keygenerator wird instnziert
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            SecureRandom random = new SecureRandom();
            keygen.init(random);
            // generiert den Key
            key = keygen.generateKey();
            System.out.println("Secretkey wurde generiert");
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
        return key;
    }

    /**
     * Diese Methode generiert ein asynchronen Keypair ("RSA")
     *
     * @return ein RSA KeyPair
     */
    public KeyPair generateAsynchronousKeys() {
        KeyPair keyPair = null;
        try {
            // Keygenerator wird instnziert
            KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = new SecureRandom();
            keygen.initialize(2048, random);
            // keypair wird generiert
            keyPair = keygen.generateKeyPair();
            System.out.println("Public-Private-Keypair wurde generiert");
        } catch (NoSuchAlgorithmException ex) {
            return null;
        }
        return keyPair;
    }

    /**
     * Diese Methode verschluesselt asynchron mut einem publicKey einen </br>
     * secretkey
     *
     * @param sk der zu verschluesselnde Secretkey
     * @param publicKey der PublicKey der verschluesselt
     * @return der verschluesselte Secretkey
     */
    public byte[] encryptAsynchronous(SecretKey sk, PublicKey publicKey) {
        byte[] encryptedMessageBytes = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            // WRAP bedeutet das ein anderer Key verschluesselt wurd
            cipher.init(Cipher.WRAP_MODE, publicKey);
            // cerschluesseln des Secretkeys
            encryptedMessageBytes = cipher.wrap(sk);
            System.out.println("SecretKey wurde verschluesselt");
        } catch (IllegalBlockSizeException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException ex) {
            System.err.println("Fehler bei asynchroner Verschluesselung" + ex.getMessage());
            return null;
        }
        return encryptedMessageBytes;
    }

    /**
     * Asynchrone Entschluesselung eines Keys
     *
     * @param encryptedText verschluesselter Key
     * @param privateKey privateKey mit dem entschluesselt werden kann
     * @return ein SecretKey der vorher verschluesselt war
     */
    public SecretKey decryptAsynchronous(byte[] encryptedText, PrivateKey privateKey) {
        SecretKey decryptedMessageBytes = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            //unwrap bedeutet das vorher ein Schluessel in dem Text verschluesselt wurde
            cipher.init(Cipher.UNWRAP_MODE, privateKey);
            byte[] messageBytes = encryptedText;
            // entschluesseln des Schluessels
            decryptedMessageBytes = (SecretKey) cipher.unwrap(messageBytes, "AES", Cipher.SECRET_KEY);
            System.out.println("Secretkey wurde entschluesselt");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException ex) {
            System.err.println("Fehler bei asynchroner Entschluesselung" + ex.getMessage());
        }
        return decryptedMessageBytes;
    }

    /**
     * Synchrone Verschluesselung. Hier wird ein String mit einem SecretKey
     * </br> verschluesselt
     *
     * @param plainText der Text der verschluesselt werden soll
     * @param key der Key mit dem verschluesselt werden soll
     * @return ein Bytearray, das nun verschluesselt ist
     */
    public byte[] encryptSynchronous(String plainText, SecretKey key) {
        byte[] encryptedMessageBytes = null;
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] messageBytes = plainText.getBytes();
            // doFinal loest das verschluesseln aus
            encryptedMessageBytes = cipher.doFinal(messageBytes);
            System.out.println("Nachricht wurde verschluesselt");
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException ex) {
            System.err.println("Fehler bei synchroner Verschluesselung" + ex.getMessage());
        }
        return encryptedMessageBytes;
    }

    /**
     * Synchrone Entschluesselung. Hier wird ein Bytearray mit einem SecretKey
     * </br> entschluesselt
     *
     * @param encryptedText der verschluesselte Text
     * @param key der Key mit dem entschluesselt werden soll
     * @return die urspruengliche Nachricht in einem Bytearray
     */
    public byte[] decryptSynchronous(byte[] encryptedText, SecretKey key) {
        byte[] decryptedMessageBytes = null;
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] messageBytes = encryptedText;
            decryptedMessageBytes = cipher.doFinal(messageBytes);
            System.out.println("Nachricht wurde entschluesselt");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException ex) {
            System.err.println("Fehler bei synchroner Verschluesselung" + ex.getMessage());
        }
        return decryptedMessageBytes;
    }
}
