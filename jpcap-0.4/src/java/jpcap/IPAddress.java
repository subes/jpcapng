package jpcap;

import java.net.*;
import java.util.Hashtable;

/** This class represents an IP address.<P>
 * This class represents both IPv4 and IPv6 address.
 * This class also contains methods to convert an IP address to a domain name, and
 * vise vesa.
 */
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

	/** Creates an IP address of the specified IP address or domain name in the
         * specified version.<P>
         * @param version IP version
         * @param address IP address or domain name
         * @exception java.net.UnknownHostException Raised when the specified address was illegal
         */
	 public IPAddress(int version, String address) throws UnknownHostException{
		this.ver=version;
		
		if(ver==4){
			this.addr=InetAddress.getByName(address).getAddress();
		}else if(ver==6){
			this.addr=getaddr6native(address);
		}
	}
	
	/** Creates an IPv4 address of the specified IP address or domain name.
         * @param address IP address or domain name
         * @exception java.net.UnknownHostException Raised when the specified address was illegal
         */
	public IPAddress(String address) throws UnknownHostException{
		this(4,address);
	}

	/** Creates an IP address represented by the byte array in the specified version.<BR>
         * This method does not check whether the address is valid or not.
         * @param version IP version
         * @param address Byte array representing an IP address
         */
	public IPAddress(int version,byte[] address){
		this.addr=address;
		this.ver=version;
	}

	/** Creates an IPv4 address represented by the byte array.<BR>
         * This method does not check whether the address is valid or not.
         * @param address Byte array representing an IP address
         */
	public IPAddress(byte[] address){
		this.addr=address;
		this.ver=4;
	}


	/** Returns this IP address as a byte array
         * @return Byte array representation of this address
         */
	public byte[] getAddress(){
		return addr;
	}

	/** Returns this IP address as a string. ("%d.%d.%d.%d" or "%x:%x::%x:%x")
         * @return String representation of this address
         */
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

	/** Returns the domain name of this address.
         * @throws UnknownHostException Raised when the domain name cannot be found
         * @return Domain name of this address
         */
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

	/** Returns an instance of java.net.InetAddress. (Only if the IP version is 4.
         * Returns null if the version is 6.)
         * @throws UnknownHostException Raised when the address cannot be converted into java.net.InetAddress
         * @return an instance of java.net.InetAddress.
         * Null if the version is 6.
         */
	public InetAddress getInetAddress() throws UnknownHostException{
		if(ver==4) return InetAddress.getByName(gethostnamenative(addr));
		else return null;
	}

	/** Indicates whether some other object is "equal to" this one.
         * @param p the reference object with which to compare
         * @return true if this object is the same as the obj argument; false otherwise
         */
	public boolean equals(Object p){
		if(!(p instanceof IPAddress)) return false;
		IPAddress ip=(IPAddress)p;

		if(ver!=ip.ver || addr.length!=ip.addr.length) return false;

		for(int i=0;i<addr.length;i++)
			if(addr[i]!=ip.addr[i]) return false;

		return true;
	}

	/** Specifies which representation (domain name or IP address
         * ("%d.%d.%d.%d" or "%x:%x::%x:%x")) is used in toString().
         * @param isDomainName If true, domain name is used. If false, IP address is used
         */
	public static void setAddressConvert(boolean isDomainName){
		isConvertAddress=isDomainName;
	}

	/** Returns a string representation (either as a domain name
         * as an IP address) of this IP address.
         * @return a string representation of this IP address
         * @see setAddressConvert()
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
	
        /** Returns the hash code of this address.
         * @return hash code of this address
         */        
	public int hashCode(){
		int code=ver;
		
		for(int i=0;i<addr.length;i++){
			code+=addr[i]<<(8*(i%4));
		}
		
		return code;
	}
}
