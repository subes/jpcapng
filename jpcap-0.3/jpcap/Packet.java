package jpcap;

/**
* {@link Jpcap Jpcap}によってキャプチャされる全てのパケットデータの親クラスです。
*/
public class Packet
{
	/**
	 * キャプチャされた時刻のタイムスタンプ（秒）
	 */
	public long sec;
	
	/**
	 * キャプチャされた時刻のタイムスタンプ（マイクロ秒）
	 **/
	public long usec;
	
	/**
	 * キャプチャされた長さ
	 **/
	public int caplen;
	
	/**
	* このパケットの長さ
	**/
	public int len;
	
	/**
	 * データリンク層ヘッダ
	 **/
	public DatalinkPacket datalink;

	/**
	* ヘッダ部のデータ
	**/
	public byte[] header;

	/**
	 * パケットのデータ (ヘッダ部を除いたもの)
	 **/
	public byte[] data;

	void setPacketValue(long sec,long usec,int caplen,int len){
		this.sec=sec;this.usec=usec;
		this.caplen=caplen;
		this.len=len;
	}

	void setDatalinkPacket(DatalinkPacket p){
		datalink=p;
	}
	
	void setPacketData(byte[] data){
		this.data=data;
	}
	
	void setPacketHeader(byte[] header){
		this.header=header;
	}
	
	/**
	 * このパケットの内容を文字列で表現します<BR>
	 * 形式: sec:usec
	 */
	public String toString(){
		return sec+":"+usec;
	}
}
