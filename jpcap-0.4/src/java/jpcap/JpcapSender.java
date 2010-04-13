package jpcap;

/** This class is used to send a packet. */
public class JpcapSender
{
	private static final int MAX_NUMBER_OF_INSTANCE=10;
	private static boolean[] instanciatedFlag=new boolean[MAX_NUMBER_OF_INSTANCE];
	private int ID;

	private JpcapSender() throws java.io.IOException{
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
	
	
        /** Initializes a network interface for sending a packet,
         * and returns an instance of this class.
         * @param device Interface for sending a packet
         * @throws IOException Raised when initialization of the interface failed
         * @return intstance of this class (JpcapSender)
         */        
	public static JpcapSender openDevice(String device) throws java.io.IOException{
		JpcapSender sender=new JpcapSender();
		sender.openRawSocket(device);
		
		return sender;
	}

	/**
	* IPパケット送信用のソケットを初期化する
	*
	*/
	private native void openRawSocket(String device);

	/** Sends a packet.<P>
         * On UNIX, only IP packet is supported.
         * For ICMP, only echo packet is supported (to prohibit DOS attack). <P>
         * ON WINDOWS, you may be able to send non-IP packet, too. However, on Windows,
         * you must also set the Datalink layer header (e.g. Ethernet header).
         * @param packet Packet to be sent
         */
	public native void sendPacket(IPPacket packet);
	
        /** Closes the interface. */        
	public native void close();
}
