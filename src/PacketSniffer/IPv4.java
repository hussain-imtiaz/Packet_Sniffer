package PacketSniffer;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;

public class IPv4 extends PacketStructure {
    /*A type of packet that uses JPCAP
      for using underlaying IP Packets.
    */
    
    Hashtable properties = new Hashtable();
    private final ArrayList<String> propertyLabels = new ArrayList<>( 
            Arrays.asList("Version", "TOS: Priority", "TOS: Throughput", "TOS: Reliability",
		"Length", "Identification", "Fragment: Don't Fragment", "Fragment: More Fragment",
		"Fragment Offset", "Time To Live", "Protocol", "Source IP", "Destination IP"));

//,
//"Source Host Name",
//"Destination Host Name"));
//	public String[] getValueNames(){
//		return propertyLabels;
//	}
    
    @Override
    public Boolean CheckPacketType(Packet p) {
        if(p instanceof IPPacket &&
          ((IPPacket)p).version == 4 &&
           p instanceof TCPPacket) 
            return true;	
        else 
            return false;
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
    public ArrayList<String> GetPropertiesLabels() {
        return propertyLabels;
    }
    @Override
    public String GetProtocolLabel() {
        return "IPv4";
    }
    @Override
    public String GetSrcAdrs() {
        return properties.get("Source IP").toString();
    }
    @Override
    public String GetDestAdrs() {
        return properties.get("Destination IP").toString();
    }
    @Override
    public void SetProperties(Packet packet) {
        IPPacket ip = (IPPacket) packet;
        properties.put(propertyLabels.get(0), new Integer(4));
        properties.put(propertyLabels.get(1), new Integer(ip.priority));
        properties.put(propertyLabels.get(2), new Boolean(ip.t_flag));
        properties.put(propertyLabels.get(3), new Boolean(ip.r_flag));
	properties.put(propertyLabels.get(4), new Integer(ip.length));
	properties.put(propertyLabels.get(5), new Integer(ip.ident));
	properties.put(propertyLabels.get(6), new Boolean(ip.dont_frag));
	properties.put(propertyLabels.get(7), new Boolean(ip.more_frag));
	properties.put(propertyLabels.get(8), new Integer(ip.offset));
	properties.put(propertyLabels.get(9), new Integer(ip.hop_limit));
	properties.put(propertyLabels.get(10), new Integer(ip.protocol));
	properties.put(propertyLabels.get(11), ip.src_ip.getHostAddress());
	properties.put(propertyLabels.get(12), ip.dst_ip.getHostAddress());
    }
}
