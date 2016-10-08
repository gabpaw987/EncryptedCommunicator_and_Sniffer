package encryptionsniffer;

// $Id: Sniffer.java,v 1.1 2002/02/18 21:49:49 pcharles Exp $
/**
 * *************************************************************************
 * Copyright (C) 2001, Rex Tsai <chihchun@kalug.linux.org.tw> * Distributed
 * under the Mozilla Public License * http://www.mozilla.org/NPL/MPL-1.1.txt *
 **************************************************************************
 */
import net.sourceforge.jpcap.capture.*;

/**
 * jpcap Tutorial - Sniffer example
 *
 * @author Rex Tsai
 * @version $Revision: 1.1 $
 * @lastModifiedBy $Author: pcharles $
 * @lastModifiedAt $Date: 2002/02/18 21:49:49 $
 */
public class EncryptionSniffer {

    private static final int INFINITE = -1;
    private static final int PACKET_COUNT = INFINITE;

    /**
     * This construktor is starting the package capturing process on the specified 
     * interface, host and port.
     * 
     * @param device the device-id of the interface on which the sniffer shall listen
     * @param hostToListen host address on which the sniffer shall listen
     * @param portToListen port of the host on which the sniffer shall listen
     * @throws Exception Exceptions that can occur within the package caputring process
     */
    public EncryptionSniffer(String device, String hostToListen, int portToListen) throws Exception {
        // Initialize jpcap
        PacketCapture pcap = new PacketCapture();
        System.out.println("Using device '" + device + "'");
        pcap.open(device, true);
        pcap.addPacketListener(new PacketHandler(hostToListen, portToListen));

        System.out.println("Capturing packets...");
        pcap.capture(PACKET_COUNT);
    }
}