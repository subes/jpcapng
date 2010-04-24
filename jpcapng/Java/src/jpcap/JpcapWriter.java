package jpcap;

import java.io.IOException;

import jpcap.packet.Packet;

/** This class is used to save the captured packets into a file. */
public class JpcapWriter {

    private JpcapWriter(JpcapCaptor jpcap, String filename) throws IOException {
        String ret = nativeOpenDumpFile(filename, jpcap.ID);
        if (ret != null) { // error
            throw new IOException(ret);
        }
    }

    private native String nativeOpenDumpFile(String filename, int ID);

    /**
     * Opens a file to save the captured packets.
     * 
     * @param jpcap
     *            instance of JpcapCaptor that was used to capture (load)
     *            packets
     * @param filename
     *            filename
     * @throws IOException
     *             If the file cannot be opened
     */
    public static JpcapWriter openDumpFile(JpcapCaptor jpcap, String filename) throws IOException {
        return new JpcapWriter(jpcap, filename);
    }

    /** Closes the opened file. */
    public native void close();

    /**
     * Saves a packet into the file.
     * 
     * @param packet
     *            Packet to be saved
     */
    public native void writePacket(Packet packet);

}
