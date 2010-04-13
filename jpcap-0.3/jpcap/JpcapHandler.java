package jpcap;

/**
* JpcapのhandlePacket()でパケットを解析するメソッドを定義するためのインターフェースです
*
* @see Jpcap#processPacket(int,JpcapHandler)
*/
public interface JpcapHandler
{
  /**
  * パケットを解析するメソッド<BR>
  * <BR>
  * パケットを受信する度に呼び出されます
  */
  public void handlePacket(Packet p);
}
