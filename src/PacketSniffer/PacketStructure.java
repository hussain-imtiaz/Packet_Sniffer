package PacketSniffer;
import java.util.ArrayList;
import jpcap.packet.Packet;

public abstract class PacketStructure {
    
    /*This is the abstract class from
      which every packet is inherited
      from. These are the basic properties
      every packet(from JPCAP) should have.
      DNS, FTP, HTTP, ICMP, SMTPP, TCP, UDP
    */
    
    public int osiLevel;   //Level identifier in OSI model
    public abstract Boolean CheckPacketType(Packet packet);   //Get instance of
    
    //Getters
    public abstract Object GetProperty(String name);
    public abstract Object[] GetProperties();
    public abstract ArrayList<String> GetPropertiesLabels();
    public abstract String GetProtocolLabel();
    public abstract String GetSrcAdrs();
    public abstract String GetDestAdrs();
    public byte[] GetPacketData(Packet packet) {
        return packet.data;
    }
    public byte[] GetPacketHeader(Packet packet) {
        return packet.header;
    }
    
    //Setter
    public abstract void SetProperties(Packet p);
  
}
