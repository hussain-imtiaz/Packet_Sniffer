package PacketSniffer;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.logging.Level;
import java.util.logging.Logger;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;

public class HTTP extends PacketStructure {
    /*A type of packet that uses JPCAP
      for taking input for filtering
      the header of incoming packets.
    */
    
    Hashtable properties;
    private ArrayList<String> propertyLabels;
    private int OSI_App_Level = 1;
    
    HTTP() {
        super.osiLevel = OSI_App_Level;
        properties = new Hashtable();
        propertyLabels = new ArrayList<>( 
        Arrays.asList("Source Port", "Destination Port", "Source Address", "Destination Address",
                           "Sequence Number", "ACK Number", "ACK", "Window Size", "FIN", "SIN",
                           "RST", "PSH", "Method", "Header")); 
    }
    @Override
    public Boolean CheckPacketType(Packet packet) {
        if(packet instanceof TCPPacket &&
          (((TCPPacket) packet).src_port == 80 || 
          ((TCPPacket) packet).dst_port == 80)) {
            return true;
        }
        return false;
    }
    @Override
    public Object GetProperty(String label) {
        return properties.get(label);
    }
    @Override
    public Object[] GetProperties() {
        Object[] property = new Object[propertyLabels.size()];
        for(int i = 0;i < propertyLabels.size(); i++) {
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
        return "HTTP";
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
        TCPPacket tcp = (TCPPacket) packet;
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
        
        /*Taking input from user for
          filtering the packet header
          information*/
        String type="";
        ArrayList<Object> packetHead = new ArrayList<>();
        BufferedReader input = new BufferedReader(new StringReader(new String(packet.data)));
        try {
            String temp;
            type = input.readLine();
            if(type == null || type.indexOf("HTTP") == -1) {
                type = "No HTTP Header";
                return;
            }
            while((temp = input.readLine()).length() > 0) {
                packetHead.add(temp);
            }
        }
        catch (IOException exception) {
           //If any issue input taking input
        }
    }
}
