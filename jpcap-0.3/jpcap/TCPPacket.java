package jpcap;

/**
* TCPパケットを表現するクラスです
*/
public class TCPPacket extends IPPacket
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
	 * シーケンス番号
	 */
	public long sequence;
	/**
	 * ACK番号
	 */
	public long ack_num;
	/**
	 * URGフラグ: 緊急データ（優先送信要求）
	 */
	public boolean urg;
	/**
	 * ACKフラグ: ACK番号フィールド有効
	 */
	public boolean ack;
	/**
	 * PSHフラグ: PUSH（強制送信）要求
	 */
	public boolean psh;
	/**
	 * RSTフラグ: 強制切断要求
	 */
	public boolean rst;
	/**
	 * SYNフラグ: シーケンス番号の同期要求
	 */
	public boolean syn;
	/**
	 * FINフラグ: 送信終了要求
	 */
	public boolean fin;
	/**
	 * ウィンドウ（受信バッファ残りバイト数）
	 */
	public int window;
	/**
	 * 緊急ポインタ
	 */
	public short urgent_pointer;

	/**
	* TCPオプション
	**/
	public byte[] option;

	/**
	 * TCPパケットのオブジェクトを生成します
	 *
	 * @param src_port 送信元ポート番号
	 * @param dst_port 送信先ポート番号
	 * @param sequence シーケンス番号
	 * @param ack_num ACK番号
	 * @param urg URGフラグ: 緊急データ（優先送信要求）
	 * @param ack ACKフラグ: ACK番号フィールド有効
	 * @param psh PSHフラグ: PUSH（強制送信）要求
	 * @param rst RSTフラグ: 強制切断要求
	 * @param syn SYNフラグ: シーケンス番号の同期要求
	 * @param fin FINフラグ: 送信終了要求
	 * @param window ウィンドウサイズ
	 * @param urgent 緊急ポインタ
	 */
	public TCPPacket(int src_port,int dst_port,long sequence,long ack_num,
					 boolean urg,boolean ack,boolean psh,boolean rst,
					 boolean syn,boolean fin,int window,int urgent){
		this.src_port=src_port;this.dst_port=dst_port;
		this.sequence=this.sequence;
		this.ack_num=ack_num;
		this.urg=urg;this.ack=ack;this.psh=psh;this.rst=rst;
		this.syn=syn;this.fin=fin;
		this.window=window;
		urgent_pointer=(short)urgent;
	}

	void setValue(int src,int dst,long seq,long ack_num,boolean urg,boolean ack,
	      boolean psh,boolean rst,boolean syn,boolean fin,int win,short urp){
    src_port=src;dst_port=dst;
    sequence=seq;
    this.ack_num=ack_num;
    this.urg=urg;this.ack=ack;this.psh=psh;this.rst=rst;this.syn=syn;this.fin=fin;
    window=win;
	urgent_pointer=urp;
  }
  
  void setOption(byte[] option){
		this.option=option;
	}

  /**
  * このパケットの内容を文字列で表現します<BR>
  *
  * <BR>
  * 形式: src_port > dst_port seq(sequence) win(window) [ack ack_num] [S][F][P]
  */
	public String toString(){
		return super.toString()+" TCP "+
			src_port+" > "+dst_port+" seq("+sequence+
			") win("+window+")"+(ack?" ack "+ack_num:"")+" "+
			(syn?" S":"")+(fin?" F":"")+(psh?" P":"")+
			(rst?" R":"")+(urg?" U":"");
	}
}
