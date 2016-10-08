/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package encryptionsniffer;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Diese Klasse spiegelt momentanen Schluessel wieder, mit dem probiert wird
 * </br> den verschluesselten Text auszulesen
 *
 * @author Josef Sochovsky
 * @version 1.0
 */
public class ATMKey {
    // in diesem Array steht der Inhalt des Keys als Bytearray

    private byte[] key;
    // in diesem String ist gespeichert welcher Verschluesselungsalgohrithmus angewendet worden ist
    private String cryptType;
    // speichert in welcher row zuletzt geaendert wurde
    private int row;
    // gibt an wie oft geaendert wurde.
    private int round;

    /**
     * In dem Konstruktor wird die gewuenschte Laenge des Schluessels angegeben,
     * </br> zusaetzlich wird auch noch der Typ des zu errechnenden Schluessels
     * eingegeben. </br>
     *
     * @param length die Laenge des gewuenschten Schluessels
     * @param cryptType die Art der Verschluesselung
     */
    public ATMKey(int length, String cryptType) {
        this.key = new byte[length];
        this.cryptType = cryptType;
        row = 0;
        for (int i = 0; i < key.length; i++) {
            key[i] = 00000001;
        }
    }

    /**
     * In dieser Methode wird aus dem CharArray ein Secretkey generiert. </br>
     * Dieser wird dann auch sofort zurueckgegeben.
     *
     * @return
     */
    public SecretKey getKey() {
        return (SecretKey) new SecretKeySpec(key, 0, key.length, cryptType);
    }

    /**
     * Erhoeht den momentanen Key
     */
    public void incrementKey() {
        //erste Ueberpruefung ob die Reihe schon voll ist
        if (key[row] == 11111111) {
            row++;
        } else if (row > key.length) {
            row = 0;
        }
        // wenn sie nach der 1ten Ueberpruefung noch immmer voll ist, war sie es schon vorher
        // --> sie wird zurueckgesetzt.
        if (key[row] == 11111111) {
            key[row] = 0;
        }

        key[row]++;
        round++;
    }

    public int getRound() {
        return round;
    }
}
