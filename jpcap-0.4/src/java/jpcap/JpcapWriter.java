package jpcap;

/** This class is used to save the captured packets into a file. */
public class JpcapWriter
{
	private native String nativeOpenDumpFile(String filename,int ID);
	
	/** Opens a file to save the captured packets.
         * @param jpcap instance of Jpcap that was used to capture (load) packets
         * @param filename filename
         * @throws IOException If the file cannot be opened
         */
	public JpcapWriter(Jpcap jpcap,String filename)
			throws java.io.IOException{
		String ret=nativeOpenDumpFile(filename,jpcap.ID);
		
		if(ret!=null){ //error
			throw new java.io.IOException(ret);
		}
	}
	
	/** Closes the opened file. */
	public native void closeDumpFile();
	
	/** Saves a packet into the file.
         * @param packet Packet to be saved
         */
	public native void writeDumpFile(Packet packet);
	
  static{
    System.loadLibrary("jpcap");
  }
}
