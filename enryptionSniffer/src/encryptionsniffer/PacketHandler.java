
package encryptionsniffer;

// $Id: Sniffer.java,v 1.1 2002/02/18 21:49:49 pcharles Exp $
/**
 * *************************************************************************
 * Copyright (C) 2001, Rex Tsai <chihchun@kalug.linux.org.tw> * Distributed
 * under the Mozilla Public License * http://www.mozilla.org/NPL/MPL-1.1.txt *
 **************************************************************************
 */

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.net.Inet4Address;
import net.sourceforge.jpcap.capture.PacketListener;
import net.sourceforge.jpcap.net.Packet;
import net.sourceforge.jpcap.net.TCPPacket;

/**
 * jpcap Tutorial - Sniffer example
 * I changed it so it only listens to one port and the communication with one
 * host, so that it doesn´t show all the other unnecessary traffic on the interface.
 * Also it saves encrypted messages to a file for further bruteforce treatment.
 *
 * @author Rex Tsai & Gabriel Pawlowsky
 * @version $Revision: 1.2 $
 * @lastModifiedBy $Author: Gabriel Pawlowsky $
 * @lastModifiedAt $Date: 2013/01/24 12:37:00 $
 */
public class PacketHandler implements PacketListener {

    //host address on which the sniffer should listen
    private String hostToListen;
    //port on which the sniffer should listen
    private int portToListen;
    //Indicates if the next incoming message will be an encrypted text.
    private boolean saveNextMessage;

    public PacketHandler(String hostToListen, int portToListen) {
        this.hostToListen = hostToListen;
        this.portToListen = portToListen;
        this.saveNextMessage = false;
    }

    @Override
    public void packetArrived(Packet packet) {
        try {
            // only handle TCP packets
            if (packet instanceof TCPPacket) {
                TCPPacket tcpPacket = (TCPPacket) packet;
                //Only listen to packets that are specified as insteresting by the
                //user
                if ((tcpPacket.getSourceAddress().equals(hostToListen) && tcpPacket.getDestinationAddress().equals(Inet4Address.getLocalHost().toString().split("/")[1])
                        || tcpPacket.getDestinationAddress().equals(this.hostToListen) && tcpPacket.getSourceAddress().equals(Inet4Address.getLocalHost().toString().split("/")[1]))
                        && (tcpPacket.getDestinationPort() == this.portToListen || tcpPacket.getSourcePort() == this.portToListen)
                        && (new String(tcpPacket.getTCPData())).trim().length() != 0) {

                    byte[] data = tcpPacket.getTCPData();

                    //Show the necessary information about the packages in the console
                    System.out.println(tcpPacket.getSourceAddress() + ":" + tcpPacket.getSourcePort() + " -> " + tcpPacket.getDestinationAddress()
                            + ":" + tcpPacket.getDestinationPort() + ": " + new String(data, "ISO-8859-1"));

                    //if a 1 gets sent over the interface, this indicates a following
                    //encrypted text which means that the next message has to be saved
                    //for bruteforce treatment. Therefore a boolean flag is used
                    if (!(new String(tcpPacket.getTCPData())).equals("1")) {
                        if (this.saveNextMessage) {
                            BufferedWriter writer = null;
                            try {
                                //Write the encrypted text to a new file
                                writer = new BufferedWriter(new FileWriter("encryptedMessages" + "-" + System.currentTimeMillis() + ".txt"));
                                writer.write(new String(tcpPacket.getTCPData()));
                                System.out.println("An encrypted key was detected!\nIt was saved to encryptedMessages.txt for further treatment.");
                                /* uncomment this if the bruteforcer is working
                                //start a brute forcing process
                                BruteForce b = new BruteForce(tcpPacket.getTCPData(), 16, "AES");
                                new Thread(b).start();
                                System.out.println("Also a brute force operation was started in a thread to find out the text!");*/
                            } catch (IOException e) {
                            } finally {
                                try {
                                    if (writer != null) {
                                        writer.close();
                                    }
                                } catch (IOException e) {
                                }
                            }
                            this.saveNextMessage = false;
                        }
                    } else {
                        //indicate that the next message will be encrypted
                        this.saveNextMessage = true;
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
