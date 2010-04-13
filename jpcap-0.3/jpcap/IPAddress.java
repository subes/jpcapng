package jpcap;

import java.net.*;
import java.util.Hashtable;

/**
 * IPアドレスを表現するためのクラスです。<P>
 * IPv4/v6どちらのアドレスも表現できます。アドレスとドメイン名の変換なども行います。
 **/
public class IPAddress
{
	//be careful! network byte order!!
	private byte[] addr;
	private int ver;

	private native String gethostnamenative(byte[] addr) throws UnknownHostException;
	private native String gethostname6native(byte[] addr);
	private native byte[] getaddr6native(String host)
		 throws UnknownHostException;

	private static boolean isConvertAddress=false;

	private static Hashtable domainNames=new Hashtable();

	/**
	 * バージョンとアドレスまたはドメイン名を指定してアドレスを作成します。<P>
	 *
	 * @param version このアドレスのIPバージョン
	 * @param address IPアドレスまたはドメイン名
	 * @exception java.net.UnknownHostException アドレスが不当な場合
	 **/
	 public IPAddress(int version, String address) throws UnknownHostException{
		this.ver=version;
		
		if(ver==4){
			this.addr=InetAddress.getByName(address).getAddress();
		}else if(ver==6){
			this.addr=getaddr6native(address);
		}
	}
	
	/**
	 * アドレスまたはドメイン名を指定してIPv4アドレスを作成します。
	 *
	 * @param address IPアドレスまたはドメイン名
	 * @exception java.net.UnknownHostException アドレスが不当な場合
	 **/
	public IPAddress(String address) throws UnknownHostException{
		this(4,address);
	}

	/**
	* バージョンとバイト列を指定してアドレスを作成します。<BR>
	* アドレスの妥当性はチェックしません。
	*/
	public IPAddress(int version,byte[] address){
		this.addr=address;
		this.ver=version;
	}

	/**
	* バイト列を指定してアドレスを作成します。<BR>
	* アドレスの妥当性はチェックしません。
	*/
	public IPAddress(byte[] address){
		this.addr=address;
		this.ver=4;
	}


	/**
	 * このIPアドレスをバイト列で返します。
	 **/
	public byte[] getAddress(){
		return addr;
	}

	/**
	 * IPアドレス文字列"%d.%d.%d.%d"または"%x:%x::%x:%x"を返します
	 **/
	public String getHostAddress(){
		if(ver==4)
			return (int)(addr[0]&0x00ff)+"."+
				(int)(addr[1]&0x00ff)+"."+
				(int)(addr[2]&0x00ff)+"."+
				(int)(addr[3]&0x00ff);
		else
			return toHex(addr[0])+
				toHex(addr[1])+":"+
				toHex(addr[2])+
				toHex(addr[3])+":"+
				toHex(addr[4])+
				toHex(addr[5])+":"+
				toHex(addr[6])+
				toHex(addr[7])+":"+
				toHex(addr[8])+
				toHex(addr[9])+":"+
				toHex(addr[10])+
				toHex(addr[11])+":"+
				toHex(addr[12])+
				toHex(addr[13])+":"+
				toHex(addr[14])+
				toHex(addr[15]);
	}

	private String toHex(byte b){
		String s=Integer.toHexString(b&0x00ff);
		if(s.length()==1) return "0"+s;
		else return s;
	}

	/**
	 * ドメイン名を返します。
	 **/
	public String getHostName() throws UnknownHostException{
		if(domainNames.containsKey(this)){
			Object name=domainNames.get(this);
			
			if(name instanceof UnknownHostException)
				throw (UnknownHostException)name;
			else return (String)name;
		}
		
		String dname;
		if(ver==4)
			try{
				dname=gethostnamenative(addr);
			}catch(UnknownHostException e){
				domainNames.put(this,e);
				throw e;
			}
		else if(ver==6){
			dname=gethostname6native(addr);
			if(dname==null){
				domainNames.put(this,new UnknownHostException(getHostAddress()));
				throw new UnknownHostException(getHostAddress());
			}
		}else
			return null;

		domainNames.put(this,dname);
		return dname;
	}

	/**
	 * java.net.InetAddressを返します。(バージョンが4の場合のみ)
	 * バージョンが6の場合はnullを返します。
	 **/
	public InetAddress getInetAddress() throws UnknownHostException{
		if(ver==4) return InetAddress.getByName(gethostnamenative(addr));
		else return null;
	}

	/**
	 * このオブジェクトと指定されたオブジェクトを比較します。
	 **/
	public boolean equals(Object p){
		if(!(p instanceof IPAddress)) return false;
		IPAddress ip=(IPAddress)p;

		if(ver!=ip.ver || addr.length!=ip.addr.length) return false;

		for(int i=0;i<addr.length;i++)
			if(addr[i]!=ip.addr[i]) return false;

		return true;
	}

	/**
	* toString()メソッドでアドレスとドメイン名のどちらを返すか
	* 指定します。
	* @param isDomainName Trueならばドメイン名を,Falseならばアドレスを返します
	**/
	public static void setAddressConvert(boolean isDomainName){
		isConvertAddress=isDomainName;
	}

	/**
	* IPアドレス文字列("%d.%d.%d.%d" または"%x:%x::%x:%x" )または
	* ドメイン名を返します
	*/
	public String toString(){
		if(isConvertAddress){
			try{
				return getHostName();
			}catch(UnknownHostException e){
				return getHostAddress();
			}
		}else return getHostAddress();
	}
	
	public int hashCode(){
		int code=ver;
		
		for(int i=0;i<addr.length;i++){
			code+=addr[i]<<(8*(i%4));
		}
		
		return code;
	}
}
