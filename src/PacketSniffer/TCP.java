package PacketSniffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;

public class TCP extends PacketStructure {
    /*A type of packet that uses JPCAP
      for using underlaying TCP Packets.
    */
    
    Hashtable properties;
    private ArrayList<String> propertyLabels;
    private int OSI_Transport_Level = 1;
    
    TCP() {
        super.osiLevel = OSI_Transport_Level;
        properties=new Hashtable();
        propertyLabels = new ArrayList<>( 
        Arrays.asList("Source Port", "Destination Port", "Source Address", "Destination Address",
                      "Sequence Number", "ACK Number", "ACK", "Window Size", "FIN", "SIN",
                      "RST", "PSH"));    
    }
    @Override
    public Boolean CheckPacketType(Packet packet) {
        return (packet instanceof TCPPacket);
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
        return "TCP";
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
        properties.clear();
        TCPPacket tcp =(TCPPacket) packet;
        properties.put(propertyLabels.get(0), tcp.src_port);
        properties.put(propertyLabels.get(1), tcp.dst_port);
        properties.put(propertyLabels.get(2), tcp.src_ip);
        properties.put(propertyLabels.get(3), tcp.dst_ip);
        properties.put(propertyLabels.get(4), tcp.sequence);
        properties.put(propertyLabels.get(5), tcp.ack_num);
        properties.put(propertyLabels.get(6), tcp.ack);
        properties.put(propertyLabels.get(7), tcp.window);
        properties.put(propertyLabels.get(8), tcp.fin);
        properties.put(propertyLabels.get(9), tcp.syn);
        properties.put(propertyLabels.get(10), tcp.rst);
        properties.put(propertyLabels.get(11), tcp.psh);
    }
}
