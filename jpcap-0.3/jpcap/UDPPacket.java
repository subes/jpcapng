package jpcap;

/**
* UDPパケットを表現するクラスです
*/
public class UDPPacket extends IPPacket
{
	/**
	 * 送信元ポート
	 */
	public int src_port;
	/**
	 * 送信先ポート
	 */
	public int dst_port;
	/**
	 * パケット長
	 */
	public int length;
	
	/**
	 * UDPパケットのオブジェクトを生成します
	 *
	 * @param src_port 送信元ポート番号
	 * @param dst_port 送信先ポート番号
	 **/
	public UDPPacket(int src_port,int dst_port){
		this.src_port=src_port;
		this.dst_port=dst_port;
	}

	void setValue(int src,int dst,int len){
		src_port=src;dst_port=dst;
		length=len;
	}
	
	/**
	 * このパケットの内容を文字列で表現します<BR>
	 *
	 * <BR>
	 * 形式: src_port > dst_port
	 */
	public String toString(){
		return super.toString()+" UDP "+src_port+" > "+dst_port;
	}
}
