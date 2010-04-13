package jpcap;

/** This class is used to capture packets.<P>
 *
 * Sample program<BR>
 * <PRE>
 * import jpcap.*;
 *
 * class Tcpdump implements JpcapHandler
 * {
 *   public void handlePacket(Packet packet){
 *     System.out.println(packet);
 *   }
 *
 *   public static void main(String[] args) throws java.io.IOException{
 *     Jpcap jpcap=Jpcap.openDevice(args[0],1000,true,20);
 *     jpcap.processPacket(-1,new Tcpdump());
 *   }
 * }
 * </PRE>
 */
public class Jpcap {
    /** Number of received packets
     * @see #updateStat()
     */
    public int received_packets;
    
    /** Number of dropped packets
     * @see #updateStat()
     */
    public int dropped_packets;
    
    private static final int MAX_NUMBER_OF_INSTANCE=10;
    private static boolean[] instanciatedFlag=new boolean[MAX_NUMBER_OF_INSTANCE];
    int ID;
    
    private native String nativeOpenLive(String device,int snaplen,
    int promisc,int to_ms);
    private native String nativeOpenOffline(String filename);
    
    private Jpcap() throws java.io.IOException{
        //find unused ID
        ID=-1;
        for(int i=0;i<MAX_NUMBER_OF_INSTANCE;i++)
            if(!instanciatedFlag[i]){
                ID=i;
                instanciatedFlag[i]=true;
                break;
            }
        
        if(ID==-1) throw new java.io.IOException("Unable to open a device: "+MAX_NUMBER_OF_INSTANCE+" devices are already opened.");
    }
    
    /** Initializes the network interface, and returns an instance of this class.
     * @return an instance of this class Jpcap.
     * @param device Name of the network interface
     * @param snaplen Max number of bytes captured at once
     * @param promisc If true, the inferface becomes promiscuous mode
     * @param to_ms Timeout of {@link #processPacket(int,JpcapHandler) processPacket()}
     * @exception java.io.IOException Raised when the specified interface cannot be opened
     */
    public static Jpcap openDevice(String device,int snaplen,boolean promisc,int to_ms)
    throws java.io.IOException{
        Jpcap jpcap=new Jpcap();
        String ret=jpcap.nativeOpenLive(device,snaplen,(promisc?1:0),to_ms);
        
        if(ret!=null) //error
            throw new java.io.IOException(ret);
        
        return jpcap;
    }
    
    /** Opens a dump file created by tcpdump or Ethereal, and returns an instance of
     * this class.
     * @param filename File name of the dump file
     * @exception java.io.IOException If the file cannot be opened
     * @return an instance of this class Jpcap
     */
    public static Jpcap openFile(String filename) throws java.io.IOException{
        Jpcap jpcap=new Jpcap();
        String ret=jpcap.nativeOpenOffline(filename);
        
        if(ret!=null) //error
            throw new java.io.IOException(ret);
        
        return jpcap;
    }
    
    /** Returns the names of the interfaces that can be used for capturing.
     * @return List of the interface names
     */
    public static native String lookupDevice();
    
    /** Returns the names of the interfaces that can be used for capturing.
     * @return List of the interface names
     */
    public static native String[] getDeviceList();
    
    /** Returns the descriptions of the interfaces (For Windows only)<P>
     *
     * On Windows, the interface name is represented as a difficult string
     * (e.g. \Device\Packet_{6E05D...}) This method returns the description
     * of each interface that is easier to understand (e.g. 3com EtherLinkII).
     * @return Descriptions of the interfaces
     */
    public static native String[] getDeviceDescription();
    
    /** Returns a captured packet.
     * @return a captured packet
     */
    public native Packet getPacket();
    
    /** Captures the specified number of packets consecutively.
     * @param count Number of packets to be captured<BR>
     * You can specify -1 to capture packets parmanently until timeour, EOF or an error occurs.
     * @param handler an instnace of JpcapHandler that analyzes the captured packets
     * @return Number of captured packets
     */
    public native int processPacket(int count,JpcapHandler handler);
    
    /** Captures the specified number of packets consecutively.<P>
     *
     * Unlike processPacket(), this method ignores the timeout.
     * @param count Number of packets to be captured<BR>
     * You can specify -1 to capture packets parmanently until EOF or an error occurs.
     * @param handler an instnace of JpcapHandler that analyzes the captured packets
     * @return Number of captured packets
     */
    public native int loopPacket(int count,JpcapHandler handler);
    
    /** Sets a filter. This filter is same as tcpdump.
     * @param condition a string representation of the filter
     * @param optimize If true, the filter is optimized
     */
    public native void setFilter(String condition,boolean optimize);
    
    /** Updates {@link #received_packets received_packets} and {@link #dropped_packets
     * dropped_packets}.
     */
    public native void updateStat();
    
    /** Returns an error message
     * @return error message
     */
    public native String getErrorMessage();
    
    /** Closes the opened interface of dump file. */
    public native void close();
    
    static{
        System.loadLibrary("jpcap");
    }
}
