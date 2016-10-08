package encryptioncommunicator;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;

/**
 * Diese Klasse ist der Server der Applikation, hier koennen Nachrichten
 * verschickt werden, </br> ausserdem wird in diesem Teil der Applikation ein
 * Public/Private Keypair generiert </br> mit dem der Schluesselaustausch
 * moeglich </br> gemacht wird. Der Nutzer kann entscheiden ob er Plain oder
 * Crypto <br/> Text verschicken moechte
 *
 *
 * @author Josef Sochovsky
 * @version 1.0
 */
public class Server {

    public static void main(String[] args) {
        //Start des Servers
        System.out.println("Server");
        //erzeugen eines Readers der fuer das Einlesen der Nutzerdaten zustaendig ist
        BufferedReader bufferRead = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("Port eingeben");
        String port = "";
        //einlesen des Ports
        try {
            port = bufferRead.readLine();
        } catch (IOException ex) {
            System.err.println("Port konnte nicht eingelesen werden " + ex.getMessage());
        }
        ServerSocket serverSocket = null;
        try {
            if (Integer.parseInt(port) > 0 && Integer.parseInt(port) < 65536) {
                try {
                    serverSocket = new ServerSocket(Integer.parseInt(port), 20, Inet4Address.getLocalHost());
                } catch (UnknownHostException ex) {
                    System.err.println("Localhost konnte nicht festgestellt werden: " + ex.getMessage());
                } catch (IOException ex) {
                    System.err.println("Konnte Socket nicht erzeugen " + ex.getMessage());
                }

            } else {
                System.out.println("Porteingabe war unzulaessig (1-65536)");
                return;
            }
        } catch (NumberFormatException ex) {
            System.err.println("Port ist nicht richtig eingegeben worden " + ex.getMessage());
            return;
        }
        // ausgeben des Hosts damit der Verbindungsaufbau erleichtert wird.
        System.out.println(serverSocket.getInetAddress());
        Socket socket = null;
        OutputStream os = null;
        InputStream is = null;
        try {
            socket = serverSocket.accept();
            os = socket.getOutputStream();
            is = socket.getInputStream();
        } catch (IOException ex) {
            System.err.println("Konnte Socket nicht erzeugen " + ex.getMessage());
        }
        System.out.println("Verbindung wurde aufgebaut");
        // erzeugen eines Objekts zur Verschluesselung und Entschluesselung
        CryptographicMethods cm = new CryptographicMethods();

        // generieren von Public- und Privatekey
        KeyPair kp = cm.generateAsynchronousKeys();
        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();

        // verschicken des PublicKeys
        try {
            os.write(publicKey.getEncoded());
            os.flush();
        } catch (IOException ex) {
            System.err.println("Konnte nicht an Client schreiben " + ex.getMessage());
        }
        System.out.println("PublicKey wurde versendet...");

        // der Secretkey wird empfangen

        byte[] test = new byte[256];
        try {
            is.read(test);
        } catch (IOException ex) {
            System.err.println("Konnte nicht vom Client lesen " + ex.getMessage());
        }
        System.out.println("Secretkey wurde empfangen");
        // byte secretKey
        SecretKey sk = cm.decryptAsynchronous(test, privateKey);
        System.out.println("Kommunikation kann nun verschluesselt und entschluesselt durchgefuehrt werden");

        while (true) {
            // user hat 3 Mglks
            System.out.println("crypt oder plain oder close");
            String decision = "";
            // einlesen der Entscheidung des Benutzers
            try {
                decision = bufferRead.readLine();
            } catch (IOException ex) {
                System.err.println("Konnte keine Zeile einlesen " + ex.getMessage());
            }
            if (decision.equalsIgnoreCase("crypt")) {
                try {
                    os.write("1".getBytes());
                } catch (IOException ex) {
                    System.err.println("Konnte keine Zeile einlesen " + ex.getMessage());
                }
                System.out.println("Nachricht (max 256 Bytes): ");
                String message = "";
                try {
                    message = bufferRead.readLine();
                } catch (IOException ex) {
                    System.err.println("Konnte keine Zeile einlesen " + ex.getMessage());
                }
                // auffuellen der Nachricht
                for (int i = message.length(); i < 256; i++) {
                    message += " ";
                }
                // Verschicken der Nachricht wenn sie verschluesselt wurde
                try {
                    os.write(cm.encryptSynchronous(message, sk));
                } catch (IOException ex) {
                    System.err.println("Konnte den Geheimtext nicht verschicken " + ex.getMessage());
                }
                System.out.println("Nachricht wurde verschickt");

            } else if (decision.equalsIgnoreCase("plain")) {
                try {
                    os.write("0".getBytes());
                    System.out.println("Nachricht: ");
                    String message = bufferRead.readLine() + " ";
                    os.write(message.getBytes());
                } catch (IOException ex) {
                    System.err.println("Konnte den Plaintext nicht verschicken " + ex.getMessage());
                }
                System.out.println("Nachricht wurde verschickt");

            } else if (decision.equalsIgnoreCase("close")) {
                try {
                    os.write("2".getBytes());
                } catch (IOException ex) {
                    System.err.println("Konnte den Client und Server nicht schliessen " + ex.getMessage());
                }
                System.out.println("System wird beendet");
                break;
            }
        }

        try {
            is.close();
            os.close();
            serverSocket.close();
            socket.close();
        } catch (IOException ex) {
            System.err.println("Streams und Sockets konnten nicht geschlossen werden " + ex.getMessage());
        }

    }
}