package PacketSniffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import jpcap.packet.ICMPPacket;
import jpcap.packet.Packet;

public class ICMP extends PacketStructure {
    /*A type of packet that uses JPCAP
      for using underlaying ICMP Packets.
    */
    
    Hashtable properties;
    private final ArrayList<String> propertyLabels = new ArrayList<>( 
            Arrays.asList("Type", "Code", "ID", "Sequence", "Redirect Address",
                          "Address Mask", "Original Timestamp", "Receive Timestamp",
                          "Transmission Timestamp", "Source Address", "Destination Address"));
    private final ArrayList<String> typeLabels = new ArrayList<>( 
            Arrays.asList("Echo Reply(0)", "Unknown(1)", "Unknown(2)", "Destination Unreachable(3)", "Source Quench(4)",
		"Redirect(5)", "Unknown(6)", "Unknown(7)", "Echo(8)", "Unknown(9)", "Unknown(10)", "Time Exceeded(11)",
		"Parameter Problem(12)", "Timestamp(13)", "Timestamp Reply(14)", "Unknown(15)", "Unknown(16)",
		"Address Mask Request(17)", "Address Mask Reply(18)"));
    
    ICMP(){
        properties = new Hashtable();
    }
    @Override
    public Boolean CheckPacketType(Packet p) {
        return (p instanceof ICMPPacket);
    }
    @Override
    public Object GetProperty(String label) {
        return properties.get(label);
    }
    @Override
    public Object[] GetProperties() {
        Object[] property = new Object[properties.size()];
        for(int i = 0; i < properties.size(); i++) {
            property[i] = properties.get(propertyLabels.get(i));
        }
        return property;
    }
    @Override
    public ArrayList<String> GetPropertiesLabels(){
        ArrayList<String> valuesName=new ArrayList<>();
        for(int i = 0; i < propertyLabels.size(); i++) {
            valuesName.add(propertyLabels.get(i));
        }
        return valuesName;
    }

    @Override
    public String GetProtocolLabel() {
        return "ICMP";
    }
    @Override
    public String GetSrcAdrs() {
        return properties.get("Source Address").toString();
    }
    @Override
    public String GetDestAdrs() {
        return properties.get("Destination Mask").toString();
    }
    @Override
    public void SetProperties(Packet packet) {
        properties.clear();
        ICMPPacket icmp = (ICMPPacket) packet;
        properties.put(propertyLabels.get(9), icmp.src_ip);
        properties.put(propertyLabels.get(10), icmp.dst_ip);
        if(icmp.type >= typeLabels.size()){
            properties.put(propertyLabels.get(0), String.valueOf(icmp.type));
        }
        else
        {
            properties.put(propertyLabels.get(0), typeLabels.get(icmp.type));
        }
        properties.put(propertyLabels.get(1), new Integer(icmp.code));
        if(icmp.type == 0 || icmp.type == 8 
           || (icmp.type >= 13 && icmp.type <= 18)) {
            properties.put(propertyLabels.get(2), new Integer(icmp.id));
            properties.put(propertyLabels.get(3), new Integer(icmp.seq));
        }
        if(icmp.type == 5)
            properties.put(propertyLabels.get(4), icmp.redir_ip);
        if(icmp.type == 17 || icmp.type == 18)
            properties.put(propertyLabels.get(5),(icmp.subnetmask >> 12)+ "." +
                          ((icmp.subnetmask >> 8)&0xff) + "." +
                          ((icmp.subnetmask >> 4)&0xff) + "." +
                          (icmp.subnetmask&0xff) + ".");
        if(icmp.type == 13 || icmp.type == 14){
            properties.put(propertyLabels.get(6), new Long(icmp.orig_timestamp));
            properties.put(propertyLabels.get(7), new Long(icmp.recv_timestamp));
            properties.put(propertyLabels.get(8), new Long(icmp.trans_timestamp));
	}
    }   
}
