/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package encryptioncommunicator;

import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import static org.junit.Assert.*;
import org.junit.Test;

/**
 *
 * @author Josefs
 */
public class CryptographicMethodsTest {

    /**
     * Ueberpruefen ob Keypaare generiert werden koennen.
     */
    @Test
    public void testGenerateAsynchronousKeys() {
        System.out.println("generateAsynchronousKeys");
        CryptographicMethods instance = new CryptographicMethods();
        KeyPair kp = instance.generateAsynchronousKeys();
        Key privateKey = kp.getPrivate();
        Key publicKey = kp.getPublic();
        if ((!(privateKey instanceof PrivateKey) && privateKey == null) || (!(publicKey instanceof PublicKey) && publicKey == null)) {
            fail("Es wurden keine Keys erstellt!");
        }
    }

    /**
     * In diesem Testfall wird ueberprueft ob man einen Key verschluesseln kann.
     */
    @Test
    public void testEncryptAsynchronous() {
        System.out.println("encryptAysnchronous");
        Key publicKey = new CryptographicMethods().generateAsynchronousKeys().getPublic();
        CryptographicMethods instance = new CryptographicMethods();
        SecretKey sk = instance.generateSynchronousKey();
        byte[] encryptedText = instance.encryptAsynchronous(sk, (PublicKey) publicKey);
        assertNotSame(sk.getEncoded(), encryptedText);
    }

    /**
     * In diesem Testfall wird ueberprueft ob man einen Key den man
     * verschluesselt </br> hat auch wieder richtig entschluesseln kann.
     */
    @Test
    public void testDecryptAsynchronous() {
        System.out.println("decryptAsynchronous");
        KeyPair keys = new CryptographicMethods().generateAsynchronousKeys();
        Key publicKey = keys.getPublic();
        Key privateKey = keys.getPrivate();
        CryptographicMethods instance = new CryptographicMethods();
        SecretKey sk = instance.generateSynchronousKey();
        byte[] encryptedText = instance.encryptAsynchronous(sk, (PublicKey) publicKey);
        SecretKey test = instance.decryptAsynchronous(encryptedText, (PrivateKey) privateKey);
        assertEquals(sk, test);
    }

    /**
     * Ueberpruefen ob ein SecretKey erstellt werden kann.
     */
    @Test
    public void testGenerateSynchronousKey() {
        System.out.println("generateSynchronousKeys");
        CryptographicMethods instance = new CryptographicMethods();
        SecretKey sk = instance.generateSynchronousKey();
        if (!(sk instanceof SecretKey) && sk == null) {
            fail("Es wurde kein Key erstellt!");
        }
    }

    /**
     * Vergleicht einen unverschluesselten Text mit einem verschluesselten
     */
    @Test
    public void testEncryptSynchronous() {
        System.out.println("encryptSynchronous");
        String plainText = "Hallo";
        SecretKey key = new CryptographicMethods().generateSynchronousKey();
        CryptographicMethods instance = new CryptographicMethods();
        byte[] result = instance.encryptSynchronous(plainText, key);
        assertNotSame(plainText, new String(result));
    }

    /**
     * Dieser Testfall testet das Entschluesseln von synchron-verschluesselten
     * </br> Nachrichten. Dies wird mittels Vergleich plain text und ver- und
     * dann ent- schluesselten Nachrichten gemacht.
     */
    @Test
    public void testDecryptSynchronous() {
        System.out.println("decryptSynchronous");
        String plainText = "Hallo";
        SecretKey key = new CryptographicMethods().generateSynchronousKey();
        CryptographicMethods instance = new CryptographicMethods();
        byte[] encrypted = instance.encryptSynchronous(plainText, key);
        byte[] result = instance.decryptSynchronous(encrypted, key);
        assertEquals(plainText, new String(result).trim());
    }
}
