package PacketSniffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;

public class UDP extends PacketStructure {
    /*A type of packet that uses JPCAP
      for using underlaying UDP Packets.
    */
    
    Hashtable properties;
    private ArrayList<String> propertyLabels;
    
    UDP() {
        properties=new Hashtable();
        propertyLabels = new ArrayList<>( 
        Arrays.asList("Source Port", "Destination Port", "Source Address", "Destination Address",
                      "Length", "TTL"));
    }
    @Override
    public Boolean CheckPacketType(Packet packet) {
        return (packet instanceof UDPPacket);
    }
    @Override
    public Object GetProperty(String label) {
        return properties.get(label);
    }
    @Override
    public Object[] GetProperties() {
        Object[] property = new Object[propertyLabels.size()];
        for(int i = 0; i < propertyLabels.size(); i++) {
            property[i] = properties.get(propertyLabels.get(i));
        }
        return property;
    }
    @Override
    public ArrayList<String> GetPropertiesLabels(){
        return propertyLabels;
    }
    @Override
    public String GetProtocolLabel() {
        return "UDP";
    }
    @Override
    public String GetSrcAdrs() {
        return properties.get("Source Address").toString();
    }
    @Override
    public String GetDestAdrs() {
        return properties.get("Destination Address").toString();
    }
    @Override
    public void SetProperties(Packet packet) {
        UDPPacket udp = (UDPPacket) packet;
        properties.put(propertyLabels.get(0), udp.src_port);
        properties.put(propertyLabels.get(1), udp.dst_port);
        properties.put(propertyLabels.get(2), udp.src_ip);
        properties.put(propertyLabels.get(3), udp.dst_ip);
        properties.put(propertyLabels.get(4), udp.length);
        properties.put(propertyLabels.get(5), udp.hop_limit);
    }
}
