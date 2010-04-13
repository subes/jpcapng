package jpcap;

/**
 * ARP/RARPパケットを表現するクラスです。
 **/
public class ARPPacket extends Packet
{
	/**
	 * ハードウェアタイプ
	 **/
	public short hardtype;
	/**
	 * ハードウェアタイプ:イーサネット
	 **/
	public static final short HARDTYPE_ETHER=1;
	/**
	 * ハードウェアタイプ:トークンリング
	 **/
	public static final short HARDTYPE_IEEE802=6;
	/**
	 * ハードウェアタイプ:フレームリレー
	 **/
	public static final short HARDTYPE_FRAMERELAY=15;

	/**
	 * プロトコルタイプ
	 **/
	public short prototype;
	/**
	* プロトコルタイプ: IP
	**/
	public static final short PROTOTYPE_IP=2048;

	/**
	 * ハードウエアアドレス長
	 **/
	public short hlen;

	/**
	 * プロトコルアドレス長
	 **/
	public short plen;

	/**
	 * オペレーション
	 **/
	public short operation;
	/**
	 * ARPリクエスト
	 **/
	public static final short ARP_REQUEST=1;
	/**
	 * ARPリプライ
	 **/
	public static final short ARP_REPLY=2;
	/**
	 * Reverse ARPリクエスト
	 **/
	public static final short RARP_REQUEST=3;
	/**
	 * Reverse ARPリプライ
	 **/
	public static final short RARP_REPLY=4;
	/**
	 * Identify peer request
	 **/
	public static final short INV_REQUEST=8;
	/**
	 * Identify peer response
	 **/
	public static final short INV_REPLY=9;


	/**
	 * 送信者ハードウェアアドレス
	 **/
	public byte[] sender_hardaddr;
	/**
	 * 送信者プロトコルアドレス
	 **/
	public byte[] sender_protoaddr;
	/**
	 * ターゲットハードウェアアドレス
	 **/
	public byte[] target_hardaddr;
	/**
	 * ターゲットプロトコルアドレス
	 **/
	public byte[] target_protoaddr;

	void setValue(short hardtype,short prototype,short hlen,short plen,
			 short operation,byte[] sha,byte[] spa,byte[] tha,byte[] tpa){
		this.hardtype=hardtype;
		this.prototype=prototype;
		this.hlen=hlen;this.plen=plen;
		this.operation=operation;
		sender_hardaddr=sha;
		sender_protoaddr=spa;
		target_hardaddr=tha;
		target_protoaddr=tpa;
	}

	/**
	* 送信元MACアドレスをStringで返す
	**/
	public Object getSenderHardwareAddress(){
		switch(hardtype){
			case HARDTYPE_ETHER:
				char[] adr=new char[17];

				for(int i=0;i<5;i++){
					adr[i*3]=hexUpperChar(sender_hardaddr[i]);
					adr[i*3+1]=hexLowerChar(sender_hardaddr[i]);
					adr[i*3+2]=':';
				}
				adr[15]=hexUpperChar(sender_hardaddr[5]);
				adr[16]=hexLowerChar(sender_hardaddr[5]);

				return new String(adr);
			default:
				return "Unknown Protocol";
		}
	}

	/**
	* 送信先MACアドレスをStringで返す
	**/
	public Object getTargetHardwareAddress(){
		switch(hardtype){
			case HARDTYPE_ETHER:
				char[] adr=new char[17];

				for(int i=0;i<5;i++){
					adr[i*3]=hexUpperChar(target_hardaddr[i]);
					adr[i*3+1]=hexLowerChar(target_hardaddr[i]);
					adr[i*3+2]=':';
				}
				adr[15]=hexUpperChar(target_hardaddr[5]);
				adr[16]=hexLowerChar(target_hardaddr[5]);

				return new String(adr);
			default:
				return "Unknown Protocol";
		}
	}

	/**
	* 送信元プロトコルアドレスを返す
	**/
	public Object getSenderProtocolAddress(){
		switch(prototype){
			case PROTOTYPE_IP:
				return new IPAddress(sender_protoaddr);
			default:
				return "Unknown Protocol";
		}
	}
	
	/**
	* 送信先プロトコルアドレスを返す
	**/
	public Object getTargetProtocolAddress(){
		switch(prototype){
			case PROTOTYPE_IP:
				return new IPAddress(target_protoaddr);
			default:
				return "Unknown Protocol";
		}
	}

	/**
	 * このパケットの内容を文字列で表現する<BR>
	 *
	 * <BR>
	 * 形式: ARP(hardtype:prototype) 
	 **/
	public String toString(){
		StringBuffer buf=new StringBuffer();
		
		switch(operation){
			case ARP_REQUEST: buf.append("ARP REQUEST ");break;
			case ARP_REPLY: buf.append("ARP REPLY ");break;
			case RARP_REQUEST: buf.append("RARP REQUEST ");break;
			case RARP_REPLY: buf.append("RARP REPLY ");break;
			case INV_REQUEST: buf.append("IDENTIFY REQUEST ");break;
			case INV_REPLY: buf.append("IDENTIFY REPLY ");break;
			default: buf.append("UNKNOWN ");break;
		}
		
		return buf.toString()+getSenderHardwareAddress()+"("+getSenderProtocolAddress()+") -> "+
		       getTargetHardwareAddress()+"("+getTargetProtocolAddress()+")";
	}

	private char hexUpperChar(byte b){
		b=(byte)((b>>4)&0xf);
		if(b==0) return '0';
		else if(b<10) return (char)('0'+b);
		else return (char)('a'+b-10);
	}

	private char hexLowerChar(byte b){
		b=(byte)(b&0xf);
		if(b==0) return '0';
		else if(b<10) return (char)('0'+b);
		else return (char)('a'+b-10);
	}
}
