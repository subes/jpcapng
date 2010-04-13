package jpcap;

import java.net.*;
import java.util.Hashtable;

/**
 * IP�A�h���X��\�����邽�߂̃N���X�ł��B<P>
 * IPv4/v6�ǂ���̃A�h���X���\���ł��܂��B�A�h���X�ƃh���C�����̕ϊ��Ȃǂ��s���܂��B
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
	 * �o�[�W�����ƃA�h���X�܂��̓h���C�������w�肵�ăA�h���X���쐬���܂��B<P>
	 *
	 * @param version ���̃A�h���X��IP�o�[�W����
	 * @param address IP�A�h���X�܂��̓h���C����
	 * @exception java.net.UnknownHostException �A�h���X���s���ȏꍇ
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
	 * �A�h���X�܂��̓h���C�������w�肵��IPv4�A�h���X���쐬���܂��B
	 *
	 * @param address IP�A�h���X�܂��̓h���C����
	 * @exception java.net.UnknownHostException �A�h���X���s���ȏꍇ
	 **/
	public IPAddress(String address) throws UnknownHostException{
		this(4,address);
	}

	/**
	* �o�[�W�����ƃo�C�g����w�肵�ăA�h���X���쐬���܂��B<BR>
	* �A�h���X�̑Ó����̓`�F�b�N���܂���B
	*/
	public IPAddress(int version,byte[] address){
		this.addr=address;
		this.ver=version;
	}

	/**
	* �o�C�g����w�肵�ăA�h���X���쐬���܂��B<BR>
	* �A�h���X�̑Ó����̓`�F�b�N���܂���B
	*/
	public IPAddress(byte[] address){
		this.addr=address;
		this.ver=4;
	}


	/**
	 * ����IP�A�h���X���o�C�g��ŕԂ��܂��B
	 **/
	public byte[] getAddress(){
		return addr;
	}

	/**
	 * IP�A�h���X������"%d.%d.%d.%d"�܂���"%x:%x::%x:%x"��Ԃ��܂�
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
	 * �h���C������Ԃ��܂��B
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
	 * java.net.InetAddress��Ԃ��܂��B(�o�[�W������4�̏ꍇ�̂�)
	 * �o�[�W������6�̏ꍇ��null��Ԃ��܂��B
	 **/
	public InetAddress getInetAddress() throws UnknownHostException{
		if(ver==4) return InetAddress.getByName(gethostnamenative(addr));
		else return null;
	}

	/**
	 * ���̃I�u�W�F�N�g�Ǝw�肳�ꂽ�I�u�W�F�N�g���r���܂��B
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
	* toString()���\�b�h�ŃA�h���X�ƃh���C�����̂ǂ����Ԃ���
	* �w�肵�܂��B
	* @param isDomainName True�Ȃ�΃h���C������,False�Ȃ�΃A�h���X��Ԃ��܂�
	**/
	public static void setAddressConvert(boolean isDomainName){
		isConvertAddress=isDomainName;
	}

	/**
	* IP�A�h���X������("%d.%d.%d.%d" �܂���"%x:%x::%x:%x" )�܂���
	* �h���C������Ԃ��܂�
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
