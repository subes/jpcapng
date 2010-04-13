package jpcap;

/**
* IPv6のオプションヘッダを表現するクラスです。
*/
public class IPv6Option{

	/**
	 * 中継点オプション
	 **/
	public static final byte HOP_BY_HOP_OPTION=0;
	/**
	 * 経路制御オプション
	 **/
	public static final byte ROUTING_OPTION=43;
	/**
	 * 断片オプション
	 **/
	public static final byte FRAGMENT_OPTION=44;
	/**
	 * セキュリティペイロード
	 **/
	public static final byte ESP_OPTION=50;
	/**
	 * 認証オプション
	 **/
	public static final byte AH_OPTION=51;
	/**
	 * 次ヘッダ無し
	 **/
	public static final byte NONE_OPTION=59;
	/**
	 * 終点オプション
	 **/
	public static final byte DESTINATION_OPTION=60;

	/**
	 * 拡張オプションタイプ
	 **/
	public byte type;
	/**
	 * 次ヘッダ
	 **/
	public byte next_header;
	/**
	 * 拡張ヘッダ長
	 **/
	public byte hlen;

	/**
	* オプション
	*/
	public byte[] option;

	/**
	* ルーティングタイプ（経路制御オプション）
	*/
	public byte routing_type;
	/**
	* ホップ残数（経路制御オプション）
	*/
	public byte hop_left;
	/**
	* 経路アドレス（経路制御オプション）
	*/
	public IPAddress[] addrs;

	/**
	* オフセット（フラグメントオプション）
	*/
	public short offset;
	/**
	* 後続フラグ（フラグメントオプション）
	*/
	public boolean m_flag;
	/**
	* Identification（フラグメントオプション）
	*/
	public int identification;

	/**
	* SPI（AHオプション用）
	*/
	public int spi;
	/**
	* シーケンス番号（AHオプション用）
	*/
	public int sequence;

	void setValue(byte type,byte next,byte hlen){
		this.type=type;
		this.next_header=next;
		this.hlen=hlen;
	}

	void setOptionData(byte[] option){
		this.option=option;
	}

	void setRoutingOption(byte type,byte left,String[] addrs){
		this.routing_type=type;
		this.hop_left=left;
		this.addrs=new IPAddress[addrs.length];
		for(int i=0;i<addrs.length;i++){
			try{
				this.addrs[i]=new IPAddress(addrs[i]);
			}catch(java.net.UnknownHostException e){}
		}
	}

	void setFragmentOption(short offset,boolean m,int ident){
		this.offset=offset;
		this.m_flag=m;
		this.identification=ident;
	}

	void setAHOption(int spi,int seq){
		this.spi=spi;
		this.sequence=seq;
	}
}
