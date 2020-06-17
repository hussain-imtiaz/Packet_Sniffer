package PacketSniffer;
import java.util.ArrayList;
import java.util.Arrays;
import jpcap.packet.Packet;

public class PacketChecker {
    /*Used for filtering and
      identifying purposes*/
    
    ArrayList<PacketStructure> packetTypes;
    ArrayList<PacketStructure> analyzedPkt;
    
    PacketChecker() {
        packetTypes = new ArrayList<>(Arrays.asList(new TCP(), new UDP(), new FTP(), new DNS(),
                          new HTTP(), new ICMP(), new IPv4())); 
    }
    public PacketStructure checkPacket(Packet checkPacket) {
        PacketStructure packet = null;
        for(int i = 0; i < packetTypes.size(); i++) {
            if(packetTypes.get(i).CheckPacketType(checkPacket)) {
                String type = packetTypes.get(i).GetProtocolLabel();
                System.out.println(type);
                
                if(type == "DNS") {
                    packet = new DNS();
                    packet.SetProperties(checkPacket);
                }
                else if(type == "FTP") {
                    packet = new FTP();
                    packet.SetProperties(checkPacket);
                }
                else if(type == "HTTP") {
                    packet = new HTTP();
                    packet.SetProperties(checkPacket);
                }
                else if(type == "ICMP") {
                    packet = new ICMP();
                    packet.SetProperties(checkPacket);
                }
                else if(type == "SMTP") {
                    packet = new SMTP();
                    packet.SetProperties(checkPacket);
                }
                else if(type == "TCP") {
                    packet = new TCP();
                    packet.SetProperties(checkPacket);
                }
                else if(type == "UDP") {
                    packet = new UDP();
                    packet.SetProperties(checkPacket);
                }
            }
        }
        return packet;
    }
}
