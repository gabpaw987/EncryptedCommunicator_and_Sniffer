/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package encryptionsniffer;

import javax.crypto.Cipher;

/**
 * In der Klasse wird ein File ausgelesen, dieses File enthaellt einen
 * verschluesselten </br> Text. DIeser Text soll mittels Bruteforce
 * entschluesselt werden.
 *
 * @author Josef Sochovsky
 * @version 1.0
 */
public class BruteForce implements Runnable {

    private byte[] content = null;
    private int keylength = 0;
    private String keytype = null;

    public BruteForce(byte[] content, int keyLength, String keytype) {
        this.content = content;
        this.keylength = keyLength;
        this.keytype = keytype;
    }

    @Override
    public void run() {
        byte[] nachricht = content;

        System.out.println(nachricht.length);
        ATMKey atm = new ATMKey(16, keytype);
        while (true) {
            try {
                Cipher cipher = Cipher.getInstance(keytype);
                cipher.init(Cipher.DECRYPT_MODE, atm.getKey());
                nachricht = cipher.doFinal(nachricht);
                System.out.println("Nachricht wurde entschluesselt");
                break;
            } catch (Exception ex) {
                atm.incrementKey();
                if (atm.getRound() % 100000 == 0) {
                    System.out.println("Runde: " + atm.getRound() + ex.getMessage());
                }
            }
        }
        System.out.println(new String(nachricht));
    }
}
