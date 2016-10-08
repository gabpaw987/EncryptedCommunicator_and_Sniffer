/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package encryptioncommunicator;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.SecretKey;

/**
 * Diese Klasse ist der Client der Applikation, hier koennen Nachrichten
 * empfangen werden, </br> ausserdem wird in diesem Teil der Applikation ein
 * Secretkey generiert </br> mit dem der Nachrichtenverkehr moeglich </br>
 * gemacht wird. Beendet und verarbeitet wird alles beim Server </br>
 *
 *
 * @author Josef Sochovsky
 * @version 1.0
 */
public class Client {

    public static void main(String[] args) {
        // Client wird gestartet
        System.out.println("Client");
        //erzeugen eines Readers der fuer das Einlesen der Nutzerdaten zustaendig ist
        BufferedReader bufferRead = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("Adresse eingeben");
        String address = "";
        // einlesen der Adresse oder hostnames des Servers
        try {
            address = bufferRead.readLine();
        } catch (IOException ex) {
            System.err.println("Nichts eingelesen!");
        }
        //einlesen des Ports vom Server
        System.out.println("Port eingeben");
        String port = null;
        try {
            port = bufferRead.readLine();
        } catch (IOException ex) {
            System.err.println("Nichts eingelesen!" + ex.getMessage());
        }
        //erzeugen der Verbindung
        Socket socket = null;
        if (Integer.parseInt(port) > 0 && Integer.parseInt(port) < 65536) {
            try {
                socket = new Socket(InetAddress.getByName(address), Integer.parseInt(port));
            } catch (IOException ex) {
                System.err.println("Konnte Socket nicht erstellen " + ex.getMessage());
                return;
            }
        }
        OutputStream os = null;
        InputStream is = null;
        try {
            os = socket.getOutputStream();
            is = socket.getInputStream();
        } catch (IOException ex) {
            System.err.println("Konnte die Streams nicht erzeugen" + ex.getMessage());
            return;
        }
        System.out.println("Verbindung wurde aufgebaut");

        // erzeugen eines Objekts zur Verschluesselung und Entschluesselung
        CryptographicMethods cm = new CryptographicMethods();
        // generieren des Secretkeys (Sessionkey)
        SecretKey sk = cm.generateSynchronousKey();
        System.out.println("Länge: " + sk.getEncoded().length);
        // empfangen des Publickeys
        byte[] publicKey = new byte[294];
        try {
            is.read(publicKey);
        } catch (IOException ex) {
            System.err.println("Fehler bei austausch der Keys" + ex.getMessage());
        }
        System.out.println("Publickey wurde empfangen");
        PublicKey pk = null;
        try {
            try {
                pk = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKey));
            } catch (InvalidKeySpecException ex) {
                System.err.println("Konnte das encoding nicht veraendern" + ex.getMessage());
            }
        } catch (NoSuchAlgorithmException ex) {
            //nicht moeglich weil hardgecoded
            System.err.println("");
        }
        try {
            os.write(cm.encryptAsynchronous(sk, pk));
            os.flush();
        } catch (IOException ex) {
            System.err.println("Konnte nicht schreiben" + ex.getMessage());
        }
        System.out.println("Secretkey wurde versandt");
        while (true) {
            // die decision wird vom server immer vor dem erhalten einer Nachricht verschickt
            // "1" steht fuer verschluesseln
            // "0" steht fuer Plaintext-Ausgabe
            // "2" steht fuer Beenden
            // wenn zu lange Zeit nichts vom Stream gelesen werden konnte
            // wird "3" selbst hineingeschrieben dies fuehrt zu einer Ausgabe im 
            // Client
            byte[] decision = new byte[1];
            try {
                is.read(decision);
            } catch (IOException ex) {
                decision = "3".getBytes();
            }
            if (Integer.parseInt(new String(decision)) == 1) {
                System.out.println("Empfange verschluesselt Nachricht: ");
                //System.out.println(new String(sk.getEncoded()));
                byte[] byteMessage = new byte[272];
                try {
                    is.read(byteMessage);
                } catch (IOException ex) {
                    System.err.println("Konnte vom Stream nicht lesen" + ex.getMessage());
                }
                //entschluesselt die Nachricht und gibt sie aus
                byte[] decryptedMessage = cm.decryptSynchronous(byteMessage, sk);
                System.out.println(new String(decryptedMessage).trim());
            } else if (Integer.parseInt(new String(decision)) == 0) {
                System.out.println("Empfange Plaintext:");
                byte[] byteMessage = new byte[256];
                try {
                    is.read(byteMessage);
                } catch (IOException ex) {
                    System.err.println("Konnte nicht vom Stream lesen" + ex.getMessage());
                }
                // ausgabe des Plaintexts
                System.out.println(new String(byteMessage));
            } else if (Integer.parseInt(new String(decision)) == 2) {
                System.out.println("System wird beendet");
                break;
            } else if (Integer.parseInt(new String(decision)) == 3) {
                System.out.println("Es wurde nicht gesendet");
            }
        }
        try {
            is.close();
            os.close();
            socket.close();
        } catch (IOException ex) {
            System.err.println("Die Sockets und Streams konnten nicht geschlossen werden" + ex.getMessage());
        }

    }
}
