
package encryptionsniffer;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import net.sourceforge.jpcap.capture.PacketCapture;

/**
 * Class which can start the sniffer.
 * It asks for all the required parameters of the package capturing process and
 * starts it. If necessary it also shows the available device IDs.
 * 
 * @author Gabriel Pawlowsky
 * @version 2013-01-24
 */
public class StartSniffer {    
    
    /**
     * main-Method
     * 
     * @param args the device-ID of the interface on which the sniffer shall listen
     */
    public static void main(String[] args) {
        try {
            //if the device-ID was supplied properly start the caputing process
            if (args.length == 1) {
                BufferedReader bufferRead = new BufferedReader(new InputStreamReader(System.in));
                System.out.println("On which host-address do you want to listen?");
                String hostToListen = bufferRead.readLine();
                System.out.println("And on which Port?");
                int portToListen = Integer.parseInt(bufferRead.readLine());
                EncryptionSniffer sniffer = new EncryptionSniffer(args[0], hostToListen, portToListen);
            //if not, show all the available device IDs
            } else {
                System.out.println("Usage: java Sniffer [device name]");
                System.out.println("Available network devices on your machine:");
                String[] devs = PacketCapture.lookupDevices();
                for (int i = 0; i < devs.length; i++) {
                    System.out.println("\t" + devs[i]);
                }
            }
        } catch (Exception e) {
            System.err.println("An error occured!");
        }
    }
}
