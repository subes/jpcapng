package jpcap.packet;

/** This class represents TCP packet. */
public class TCPPacket extends IPPacket {
  private static final long serialVersionUID = -8856988406589484129L;

  /** Source port number */
  public int src_port;
  /** Destination port number */
  public int dst_port;
  /** Sequence number */
  public long sequence;
  /** ACK number */
  public long ack_num;
  /** URG flag */
  public boolean urg;
  /** ACK flag */
  public boolean ack;
  /** PSH flag */
  public boolean psh;
  /** RST flag */
  public boolean rst;
  /** SYN flag */
  public boolean syn;
  /** FIN flag */
  public boolean fin;

  // !!!!! Manu modif
  /** Data offset (header length+RFU bits) */
  public byte dataOffset;
  // !!!!! end

  // added by Damien Daspit 5/7/01
  /** RSV1 flag */
  public boolean rsv1;
  /** RSV2 flag */
  public boolean rsv2;
  // *****************************

  /** Window size */
  public int window;

  /** 
   * TCP checksum, if null checksum will be computed automatically, 
   * otherwise the specified value at index 0 will be included into TCP segment
   */
  public short[] tcpChecksum;

  /** Urgent pointer */
  public short urgent_pointer;

  /** TCP option */
  public byte[] tcpOptions;

  /** Creates a TCP packet.
   * @param rsv1 RSV1 flag
   * @param rsv2 RSV2 flag
   * @param src_port Source port number
   * @param dst_port Destination port number
   * @param sequence sequence number
   * @param ack_num ACK number
   * @param urg URG flag
   * @param ack ACK flag
   * @param psh PSH flag
   * @param rst RST flag
   * @param syn SYN flag
   * @param fin FIN flag
   * @param window window size
   * @param urgent urgent pointer
   */
  public TCPPacket(int src_port, int dst_port, long sequence, long ack_num,
      boolean urg, boolean ack, boolean psh, boolean rst, boolean syn,
      boolean fin, boolean rsv1, boolean rsv2, int window, int urgent) {
    this.src_port = src_port;
    this.dst_port = dst_port;
    this.sequence = sequence;
    this.ack_num = ack_num;
    this.urg = urg;
    this.ack = ack;
    this.psh = psh;
    this.rst = rst;
    this.syn = syn;
    this.fin = fin;
    // added by Damien Daspit 5/7/01
    this.rsv1 = rsv1;
    this.rsv2 = rsv2;
    // *****************************
    this.window = window;
    urgent_pointer = (short)urgent;
    
    //tcpChecksum = new short[1];
  }

  void setValue(int src, int dst, long seq, long ack_num, boolean urg,
      boolean ack, boolean psh, boolean rst, boolean syn, boolean fin,
      byte dataOffset, boolean rsv1, boolean rsv2, int win, short tcpChksum,
      short urp) {
    src_port = src;
    dst_port = dst;
    sequence = seq;
    this.ack_num = ack_num;
    this.urg = urg;
    this.ack = ack;
    this.psh = psh;
    this.rst = rst;
    this.syn = syn;
    this.fin = fin;

    // !!!!! Manu modif
    // header length
    this.dataOffset = dataOffset;
    // !!!!! end

    // added by Damien Daspit 5/7/01

    this.rsv1 = rsv1;
    this.rsv2 = rsv2;
    // *****************************
    window = win;

    // !!!!!!!! added by Manu Bachimon
    if(tcpChecksum == null);
      tcpChecksum = new short[1];
    tcpChecksum[0] = tcpChksum;
    // !!!!!!!! End of modifications
    urgent_pointer = urp;
  }

  public void setTcpOptions(byte[] tcpOptions) {
    byte nbOfPaddingByte = 0;

    if (tcpOptions == null) {
      System.out.println("ERROR : tcpOptions[] is NULL");
      return;
    }
    // adding padding bytes if necessary
    nbOfPaddingByte = (byte)(tcpOptions.length % 4);
    if(nbOfPaddingByte != 0) {
      nbOfPaddingByte = (byte) (4 - nbOfPaddingByte);
    }
   
    this.tcpOptions = new byte[(tcpOptions.length + nbOfPaddingByte)];
    for (byte i = 0; i < tcpOptions.length; i++)
      this.tcpOptions[i] = tcpOptions[i];
  }

  public byte[] getTcpOptions() {
    return this.tcpOptions;
  }

  public short[] getTcpChecksum() {
    return this.tcpChecksum;
  }

  public int getTcpOptionsLength() {
    return this.tcpOptions.length;
  }

  /** Returns a string representation of this packet<BR>
   *
   * <BR>
   * Format: src_port > dst_port seq(sequence) win(window) [ack ack_num] [S][F][P]
   * @return a string representation of this packet
   */
  public String toString() {
    return super.toString() + " TCP " + src_port + " > " + dst_port + " seq("
        + sequence + ") win(" + window + ")" + (ack ? " ack " + ack_num : "")
        + " " + (syn ? " S" : "") + (fin ? " F" : "") + (psh ? " P" : "")
        + (rst ? " R" : "") + (urg ? " U" : "");
  }
}
