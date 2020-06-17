package PacketSniffer;
import java.awt.Color;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Scanner;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.sourceforge.jpcap.capture.CaptureDeviceNotFoundException;
import net.sourceforge.jpcap.capture.CaptureDeviceOpenException;
import net.sourceforge.jpcap.capture.PacketCapture;
import net.sourceforge.jpcap.capture.RawPacketListener;
import jpcap.NetworkInterface;
import jpcap.JpcapCaptor;
import jpcap.JpcapWriter;
import jpcap.PacketReceiver;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import static java.awt.Frame.NORMAL;
import java.awt.event.ActionEvent;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPopupMenu;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import sun.rmi.runtime.Log;

public class Sniffer extends javax.swing.JFrame {

    Sniffer() {
        initComponents();
        filterOptions.setEnabled(true);
        captureButton.setEnabled(true);
        stopButton.setEnabled(true);
        saveButton.setEnabled(true);
        loadButton.setEnabled(true);
    }
    
    //Globals
    public static int captureBound = 500;
    Thread captureThread;
    String threadLabel;
    List<PacketStructure> packets;
    public static int interfaceIndex=0;
    public static JpcapCaptor captor;
    public static boolean captureState = true;
    
    private void initComponents() {
        
        getContentPane().setBackground(Color.BLACK);

        toolBar = new javax.swing.JToolBar();
        listButton = new java.awt.Button();
        filterOptions = new java.awt.Button();
        captureButton = new java.awt.Button();
        stopButton = new JButton("Stop");
        saveButton = new java.awt.Button();
        loadButton = new java.awt.Button();
        
        packetTable = new javax.swing.JTable(){
            @Override
            public boolean isCellEditable(int row, int column){
                return false;
            }
        };
        packetTable.setForeground(Color.WHITE);
        packetTable.setBackground(Color.DARK_GRAY);
        packetTable.setGridColor(Color.white);
        packetTable.setFillsViewportHeight(true);
        JTableHeader header = packetTable.getTableHeader();
        header.setBackground(Color.black);
        header.setForeground(Color.white);
        tableScroll = new javax.swing.JScrollPane();

        infoLabel = new javax.swing.JLabel();
        infoLabel.setForeground(Color.white);
        infoTextArea = new javax.swing.JTextArea();
        infoTextArea.setBackground(Color.DARK_GRAY);
        infoTextArea.setForeground(Color.WHITE);
        infoScroll = new javax.swing.JScrollPane();
 
        hexLabel = new javax.swing.JLabel();
        hexLabel.setForeground(Color.white);
        hexTextArea = new javax.swing.JTextArea();
        hexTextArea.setBackground(Color.DARK_GRAY);
        hexTextArea.setForeground(Color.WHITE);
        hexScroll = new javax.swing.JScrollPane();
        
        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Packet Sniffer");
        setName("Packet Sniffer");
        toolBar.setRollover(true);

        listButton.setActionCommand("List Interfaces");
        listButton.setBackground(new java.awt.Color(0, 0, 102));
        listButton.setFont(new java.awt.Font("Dialog", 1, 12)); // NOI18N
        listButton.setForeground(new java.awt.Color(255, 255, 255));
        listButton.setLabel("List Interfaces");
        listButton.setPreferredSize(new java.awt.Dimension(90, 26));
        toolBar.add(listButton);

        //filterOptions.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "---", "TCP", "UDP", "ICMP" }));
        filterOptions.setPreferredSize(new java.awt.Dimension(320, 24));
        filterOptions.setBackground(Color.yellow);
        filterOptions.setLabel("Filter");
        filterOptions.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) {
            
            }
        });
        toolBar.add(filterOptions);

        captureButton.setBackground(new java.awt.Color(0, 204, 0));
        captureButton.setFont(new java.awt.Font("Dialog", 1, 12)); // NOI18N
        captureButton.setLabel("Capture");
        captureButton.setPreferredSize(new java.awt.Dimension(83, 24));
        toolBar.add(captureButton);

        stopButton.setBackground(new java.awt.Color(255, 0, 51));
        stopButton.setFont(new java.awt.Font("Dialog", 1, 12)); // NOI18N
        stopButton.setLabel("Stop");
        stopButton.setPreferredSize(new java.awt.Dimension(83, 24));
        stopButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                
            }
        });
        toolBar.add(stopButton);

        saveButton.setLabel("Save");
        saveButton.setPreferredSize(new java.awt.Dimension(83, 24));
        saveButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                
            }
        });
        toolBar.add(saveButton);
        
        loadButton.setLabel("Load");
        loadButton.setPreferredSize(new java.awt.Dimension(83, 24));
        loadButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                
            }
        });
        toolBar.add(loadButton);


        packetTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "No.", "Length", "Source", "Destination", "Protocol"
            }
        ) {
            Class[] types = new Class [] {
                java.lang.Integer.class, java.lang.Object.class, java.lang.Object.class, java.lang.Object.class, java.lang.String.class
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }
          }
        );
        packetTable.setRowHeight(20);
        packetTable.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                
            }
        });
        tableScroll.setViewportView(packetTable);

        infoTextArea.setEditable(false);
        infoTextArea.setColumns(20);
        infoTextArea.setRows(5);
        infoScroll.setViewportView(infoTextArea);

        hexScroll.setHorizontalScrollBarPolicy(javax.swing.ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

        hexTextArea.setEditable(false);
        hexTextArea.setColumns(20);
        hexTextArea.setRows(5);
        hexScroll.setViewportView(hexTextArea);

        infoLabel.setText("Packet info:");

        hexLabel.setText("Hex view:");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(tableScroll)
            .addComponent(toolBar, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addComponent(infoScroll)
            .addComponent(hexScroll)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(infoLabel)
                    .addComponent(hexLabel))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(toolBar, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(tableScroll, javax.swing.GroupLayout.PREFERRED_SIZE, 312, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(infoLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 9, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(infoScroll, javax.swing.GroupLayout.PREFERRED_SIZE, 140, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(hexLabel)
                .addGap(1, 1, 1)
                .addComponent(hexScroll, javax.swing.GroupLayout.PREFERRED_SIZE, 108, javax.swing.GroupLayout.PREFERRED_SIZE))
        );

        pack();
    }
    
    public static void main (String[] args) throws 
                             IOException, CaptureDeviceNotFoundException, CaptureDeviceOpenException {

        System.out.println(System.getProperty("java.library.path"));

        //Initialise UI and make it visible
        Sniffer UI = new Sniffer();
        UI.setVisible(true);
        final NetworkInterface[] inputInterfaces;
        final PacketChecker checker = new PacketChecker();
        final ArrayList<PacketStructure> checked = new ArrayList<>();
        final ArrayList<Packet> savedPackets = new ArrayList<>();
        final Hashtable hash = new Hashtable();
        
        //Print input interfaces List
        inputInterfaces = JpcapCaptor.getDeviceList();
        for(int i = 0; i < inputInterfaces.length; i++) { 
            System.out.println(inputInterfaces[i].description);
        }
        
        stopButton.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                //Setting the interface to default
                System.out.println(interfaceIndex);
                try {
                    captor = JpcapCaptor.openDevice(inputInterfaces[interfaceIndex], 65536, true, 1000);
                } catch (IOException ex) {
                    Logger.getLogger(Sniffer.class.getName()).log(Level.SEVERE, null, ex);
                }
                captureButton.enable();
                captureState = false;
                System.out.println(interfaceIndex);
            }
        });

        //Event of pressing List Button
        listButton.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                JFrame popup = new JFrame();
                javax.swing.JTable interfaceList = new javax.swing.JTable();
                String interfaces = new String();
                for(int i=0; i < inputInterfaces.length; i++) {
                    interfaces += i + "->" + inputInterfaces[i].description + "\n";
                }
                String inputIndex = JOptionPane.showInputDialog(popup,"Choose Interface from below \n"+interfaces);
                try {
                    interfaceIndex = Integer.parseInt(inputIndex);
                    System.out.println(interfaceIndex);
                    DefaultTableModel model = (DefaultTableModel) packetTable.getModel();
                    model.setRowCount(0);
                }
                catch(Exception e) {
                    JOptionPane.showMessageDialog(popup, "Wrong Interface Index");
                }
            }
        });
        System.out.println(interfaceIndex);
        captor = JpcapCaptor.openDevice(inputInterfaces[interfaceIndex], 65536, true, 1000);
           
        //Event of capture button pressed
        captureButton.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                captureState = true;
                new Thread(new Runnable(){
                    int index = 0;
                    
                    @Override
                    public void run() {
                        DefaultTableModel model = (DefaultTableModel) packetTable.getModel();
                        model.setRowCount(0);
                        captureButton.disable();
                        while(!stopButton.getModel().isPressed() && captureState == true) {
                            SwingUtilities.invokeLater(new Runnable() {
                                Packet packet = captor.getPacket();
                                
                                @Override
                                public void run() {
                                    if(packet != null) {
                                        savedPackets.add(packet);

                                        IPv4 tempIP = new IPv4();
                                        ArrayList<PacketStructure> packetTemp = new ArrayList<>();

                                        packetTemp.add(checker.checkPacket(packet));
                                        if(tempIP.CheckPacketType(packet)){
                                            tempIP.SetProperties(packet);
                                            hash.put(index, tempIP);
                                        }
                                        checked.add(packetTemp.get(0));

                                        Vector tableRow = new Vector();
                                        tableRow.add(index);
                                        tableRow.add(packet.len);
                                        tableRow.add(packetTemp.get(0).GetSrcAdrs());
                                        tableRow.add(packetTemp.get(0).GetDestAdrs());
                                        tableRow.add(packetTemp.get(0).GetProtocolLabel());

                                        DefaultTableModel model=(DefaultTableModel) packetTable.getModel();
                                        model.addRow(tableRow);

                                        packetTemp.clear();
                                        index++;
                                    }
                                }
                            });
                            try {
                                    java.lang.Thread.sleep(200);
                            } catch(Exception e){}
                        }
                    }
                }).start();
            }
        });
        
        //Event for updating packet table values
        packetTable.getSelectionModel().addListSelectionListener(new ListSelectionListener(){
            
            @Override
            public void valueChanged(ListSelectionEvent e) {
                infoTextArea.selectAll();
                hexTextArea.selectAll();
                infoTextArea.replaceSelection("");
                hexTextArea.replaceSelection("");

                if (captureState == false)
                    return;
                //Packet Info
                PacketStructure packet = checked.get((int) packetTable.getValueAt(packetTable.getSelectedRow(),
                                                      NORMAL));
                Object[] properties = packet.GetProperties();
                ArrayList<String> propertyLabels = packet.GetPropertiesLabels();
                for(int i = 0; i < properties.length; i++) {
                    infoTextArea.append(propertyLabels.get(i) + ":  " + properties[i].toString() + "\n");
                }
                int key = (int)packetTable.getValueAt(packetTable.getSelectedRow(), NORMAL);
                Packet selectedPacket = savedPackets.get(key);
                if(hash.containsKey(key)) {
                    infoTextArea.append("\n IPv4 Information: \n");
                    for(int i = 0; i < properties.length; i++) {
                        infoTextArea.append(propertyLabels.get(i)+":  "+properties[i].toString()+"\n");
                    }
                }
                
                //Hex Data
                byte[] data = checked.get(0).GetPacketData(selectedPacket);
                BigInteger storeData = new BigInteger(1,data);
                StringBuilder hexString = new StringBuilder();
                for(byte b:data) {
                    hexString.append(String.format("%02x",b));
                }
                hexTextArea.append(storeData.toString(16));    
            }
        });
        
        //Event for when saved button is pressed
        saveButton.addActionListener(new java.awt.event.ActionListener() {
            
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    JFrame popup = new JFrame();
                    Object result = JOptionPane.showInputDialog(popup, "Enter FileName");
                    JpcapWriter writer = JpcapWriter.openDumpFile(captor, result.toString());

                    for(int i = 0; i < savedPackets.size(); i++) {
                        Packet packet = savedPackets.get(i);
                        writer.writePacket(packet);
                    }
                    JOptionPane.showMessageDialog(null, "Data Saved Successfully");
                } catch (IOException ex) {
                    JOptionPane.showMessageDialog(null, "Data Save Failed");
                    Logger.getLogger(Sniffer.class.getName()).log(Level.SEVERE, null, ex);
                }
                captureState = false;
            }
        });

        //Event for when load button is pressed
        loadButton.addActionListener(new java.awt.event.ActionListener() {
            
            @Override
            public void actionPerformed(ActionEvent e) { 
                captureState = false;
                String CaptureData = "";
                DefaultTableModel model = (DefaultTableModel) packetTable.getModel();
                model.setRowCount(0);
                try {
                    int noOfPackets = 0;
                    JFileChooser chooser = new JFileChooser();
                    chooser.showOpenDialog(null);
                    File f = chooser.getSelectedFile();

                    captor = JpcapCaptor.openFile(f.toString());
                    int index = 0;
             
                    while(true) {
                        //read a packet from the opened file
                        Packet packet = captor.getPacket();
                        //if some error occurred or EOF has reached, break the loop
                        if(packet == null || packet == Packet.EOF)
                            break;
                        else {
                            savedPackets.add(packet);
                            
                            IPv4 tempIP = new IPv4();
                            ArrayList<PacketStructure> packetTemp = new ArrayList<>();
                            
                            packetTemp.add(checker.checkPacket(packet));
                            if(tempIP.CheckPacketType(packet)){
                                tempIP.SetProperties(packet);
                                hash.put(index, tempIP);
                            }
                            checked.add(packetTemp.get(0));
                            
                            Vector tableRow = new Vector();
                            tableRow.add(index);
                            tableRow.add(packet.len);
                            if (packet.len <= 0)
                                break;
                            tableRow.add(packetTemp.get(0).GetSrcAdrs());
                            tableRow.add(packetTemp.get(0).GetDestAdrs());
                            tableRow.add(packetTemp.get(0).GetProtocolLabel());
                            
                            model = (DefaultTableModel) packetTable.getModel();
                            model.addRow(tableRow);
                            
                            packetTemp.clear();
                            index++;
                        }    
                    }
                    captor = JpcapCaptor.openFile(f.toString());
                    captureButton.disable();
                    JOptionPane.showMessageDialog(null, "Data Loaded Successfully");
                    
                } catch (IOException ex) {
                    JOptionPane.showMessageDialog(null, "File Access Error, could not access data.");
                    Logger.getLogger(Sniffer.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
       });
        
        
        filterOptions.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                JFrame popup = new JFrame();
                String filter = new String();
                String inputFilter = JOptionPane.showInputDialog(popup,"Enter Filter Below \n" + filter);
                try {
                    captor.setFilter(inputFilter, true);
                    int index = 0;
                    DefaultTableModel model = (DefaultTableModel) packetTable.getModel();
                    model.setRowCount(0);
                    while(true) {
                        //read a packet from the opened file
                        Packet packet = captor.getPacket();
                        //if some error occurred or EOF has reached, break the loop
                        if(packet == null || packet == Packet.EOF)
                            break;
                        else {
                            savedPackets.add(packet);
                            
                            IPv4 tempIP = new IPv4();
                            ArrayList<PacketStructure> packetTemp = new ArrayList<>();
                            
                            packetTemp.add(checker.checkPacket(packet));
                            if(tempIP.CheckPacketType(packet)){
                                tempIP.SetProperties(packet);
                                hash.put(index, tempIP);
                            }
                            checked.add(packetTemp.get(0));
                            
                            Vector tableRow = new Vector();
                            tableRow.add(index);
                            tableRow.add(packet.len);
                            if (packet.len <= 0)
                                break;
                            tableRow.add(packetTemp.get(0).GetSrcAdrs());
                            tableRow.add(packetTemp.get(0).GetDestAdrs());
                            tableRow.add(packetTemp.get(0).GetProtocolLabel());
                            
                            model = (DefaultTableModel) packetTable.getModel();
                            model.addRow(tableRow);
                            
                            packetTemp.clear();
                            index++;
                        }    
                    }
                } catch (IOException ex) {
                    Logger.getLogger(Sniffer.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    public static java.awt.Button captureButton;
    public static java.awt.Button filterOptions;

    public static JButton stopButton;
    private javax.swing.JLabel infoLabel;
    private javax.swing.JLabel hexLabel;
    private javax.swing.JScrollPane infoScroll;
    private javax.swing.JScrollPane hexScroll;
    private javax.swing.JScrollPane tableScroll;
    public static javax.swing.JTable packetTable;
    public static javax.swing.JTextArea infoTextArea;
    public static javax.swing.JTextArea hexTextArea;

    private javax.swing.JToolBar toolBar;
    public static java.awt.Button listButton;
    public static java.awt.Button saveButton;
    public static java.awt.Button loadButton;

}


       


