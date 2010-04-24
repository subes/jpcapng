package jpcap;

import java.io.IOException;

import jpcap.packet.Packet;

/** This class is used to send a packet. */
public class JpcapSender extends JpcapInstance {
	private native String nativeOpenDevice(String device);
	private native void nativeSendPacket(Packet packet);
	private native void nativeCloseDevice();
	
	private JpcapSender() throws java.io.IOException {
		if (reserveID() < 0)
			throw new java.io.IOException("Unable to open a device: "
					+ MAX_NUMBER_OF_INSTANCE + " devices are already opened.");
	}
	
	JpcapSender(int ID){
		this.ID=ID;
	}

	/**
	 * Initializes a network interface for sending a packet, and returns an
	 * instance of this class.
	 * 
	 * @param device
	 *            Interface for sending a packet
	 * @throws IOException
	 *             Raised when initialization of the interface failed
	 * @return intstance of this class (JpcapSender)
	 */
	public static JpcapSender openDevice(NetworkInterface device) throws java.io.IOException {
		JpcapSender sender = new JpcapSender();
		String ret=sender.nativeOpenDevice(device.name);

		if(ret==null)
			return sender;
		else
			throw new java.io.IOException(ret);
	}

	/** Closes the interface. */
	public void close() {
		nativeCloseDevice();
		unreserveID();
	}

	/**
	 * Sends a packet.
	 * <P>
	 * If this JpcapSender instance was created by openDevice(), you need to set
	 * the Datalink layer's header (e.g., Ethernet header) of the packet. <P>
	 * 
	 * @param packet Packet to be sent
	 */
	public void sendPacket(Packet packet) throws IOException{
		nativeSendPacket(packet);
	}
}
