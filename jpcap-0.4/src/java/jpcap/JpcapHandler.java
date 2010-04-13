package jpcap;

/** This interface is used to define a method to analyze the captured packets,
 * which is used in Jpcap.handlePacket() or Jpcap.processPacket()
 * @see Jpcap#processPacket(int,JpcapHandler)
 * @see Jpcap#loopPacket(int,JpcapHandler)
 */
public interface JpcapHandler
{
    /** Analyzes a packet.<BR>
     * <BR>
     * This method is called everytime a packet is captured.
     * @param p A packet to be analyzed
     */
  public void handlePacket(Packet p);
}
