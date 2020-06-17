package PacketSniffer;

import java.util.ArrayList;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;

public class SMTP extends TCP {
    /*A subtype of TCP packet that uses JPCAP
      for using underlaying TCP Packets.
    */
    
    @Override
    public Boolean CheckPacketType(Packet p) {
        if(p instanceof TCPPacket &&
          (((TCPPacket)p).src_port == 25
          || ((TCPPacket)p).dst_port == 25))
            return true;	
        else 
            return false;
    }
}
