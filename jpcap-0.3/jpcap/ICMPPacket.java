package jpcap;

/**
* ICMP�p�P�b�g��\������N���X�ł�
*/
public class ICMPPacket extends IPPacket
{
	/**
	* echo reply
	*/
	public static final short ICMP_ECHOREPLY = 0;
	/**
	* dest unreachable
	*/
	public static final short ICMP_UNREACH   = 3;
	  /**
	  * dest unreachable code: bad net
	  */
	  public static final short ICMP_UNREACH_NET = 0;
	  /**
	  * dest unreachable code: bad host
	  */
	  public static final short ICMP_UNREACH_HOST = 1;
	  /**
	  * dest unreachable code: bad protocol
	  */
	  public static final short ICMP_UNREACH_PROTOCOL = 2;
  	  /**
  	  * dest unreachable code: bad port
  	  */
	  public static final short ICMP_UNREACH_PORT = 3;
	  /**
	  * dest unreachable code: IP_DF caused drop
	  */
	  public static final short ICMP_UNREACH_NEEDFRAG = 4;
	  /**
	  * dest unreachable code: src route failed
	  */
	  public static final short ICMP_UNREACH_SRCFAIL = 5;
	  /**
	  * dest unreachable code: unknown net
	  */
	  public static final short ICMP_UNREACH_NET_UNKNOWN = 6;
	  /**
	  * dest unreachable code: unknown host
	  */
	  public static final short ICMP_UNREACH_HOST_UNKNOWN = 7;
	  /**
	  * dest unreachable code: src host isolated
	  */
	  public static final short ICMP_UNREACH_ISOLATED = 8;
	  /**
	  * dest unreachable code: prohibited access
	  */
	  public static final short ICMP_UNREACH_NET_PROHIB = 9;
	  /**
	  * dest unreachable code: ditto
	  */
	  public static final short ICMP_UNREACH_HOST_PROHIB = 10;
	  /**
	  * dest unreachable code: bad tos for net
	  */
	  public static final short ICMP_UNREACH_TOSNET = 11;
	  /**
	  * dest unreachable code: bad tos for host
	  */
	  public static final short ICMP_UNREACH_TOSHOST = 12;
	  /**
	  * dest unreachable code: admin prohib
	  */
	  public static final short ICMP_UNREACH_FILTER_PROHIB = 13;
	  /**
	  * dest unreachable code: host prec vio.
	  */
	  public static final short ICMP_UNREACH_HOST_PRECEDENCE = 14;
	  /**
	  * dest unreachable code: prec cutoff
	  */
	  public static final short ICMP_UNREACH_PRECEDENCE_CUTOFF = 15;
	/**
	* packet lost, slow down
	*/
	public static final short ICMP_SOURCEQUENCH	= 4;
	/**
	* redirect
	*/
	public static final short ICMP_REDIRECT = 5;
	  /**
	  * redirect code: for network
	  */
	  public static final short ICMP_REDIRECT_NET = 0;
	  /**
	  * redirect code: for host
	  */
	  public static final short ICMP_REDIRECT_HOST = 1;
	  /**
	  * redirect code: for tos and net
	  */
	  public static final short ICMP_REDIRECT_TOSNET = 2;
	  /**
	  * redirect code: for tos and host
	  */
	  public static final short ICMP_REDIRECT_TOSHOST = 3;
	/**
	* echo request
	*/
	public static final short ICMP_ECHO = 8;
	/**
	* router advertisement
	*/
	public static final short ICMP_ROUTERADVERT	= 9;
	/**
	* router solicitation
	*/
	public static final short ICMP_ROUTERSOLICIT = 10;
	/**
	* time exceeded
	*/
	public static final short ICMP_TIMXCEED = 11;
	  /**
	  * time exceeded code: ttl==0 in transit
	  */
	  public static final short ICMP_TIMXCEED_INTRANS = 0;
	  /**
	  * time exceeded code: ttl==0 in reass
	  */
	  public static final short ICMP_TIMXCEED_REASS	= 1;
	/**
	* ip header bad
	*/
	public static final short ICMP_PARAMPROB = 12;
	  /**
	  * ip header bad code: error at param ptr
	  */
	  public static final short ICMP_PARAMPROB_ERRATPTR = 0;
	  /**
	  * ip header bad code: req. opt. absent
	  */
	  public static final short ICMP_PARAMPROB_OPTABSENT = 1;
	  /**
	  * ip header bad code: bad length
	  */
	  public static final short ICMP_PARAMPROB_LENGTH = 2;
	/**
	* timestamp request
	*/
	public static final short ICMP_TSTAMP = 13;
	/**
	* timestamp reply
	*/
	public static final short ICMP_TSTAMPREPLY = 14;
	/**
	* information request
	*/
	public static final short ICMP_IREQ = 15;
	/**
	* information reply
	*/
	public static final short ICMP_IREQREPLY = 16;
	/**
	* address mask request
	*/
	public static final short ICMP_MASKREQ = 17;
	/**
	* address mask reply
	*/
	public static final short ICMP_MASKREPLY = 18;

	/**
	 * ICMP�^�C�v
	 */
	public byte type;
	/**
	 * ICMP�R�[�h
	 */
	public byte code;
	/**
	 * �`�F�b�N�T��
	 */
	public short checksum;
	
	/**
	* ID
	*/
	public int id;
	/**
	* �V�[�P���X�ԍ�
	*/
	public int seq;

	/**
	* �A�h���X�}�X�N
	*/
	public int subnetmask;
	
	/**
	* �^�C���X�^���v���N�G�X�g
	*/
	public long orig_timestamp,recv_timestamp,trans_timestamp;
	
	/**
	* MTU
	*/
	public short mtu;
	/**
	* �ԐM���ꂽIP�w�b�_
	*/
	public IPPacket ippacket;
	
	/**
	* ���_�C���N�g��A�h���X
	*/
	public IPAddress redir_ip;
	
	/**
	* �A�h���X�L����
	*/
	public byte addr_num;
	/**
	* �G���g���[�T�C�Y
	*/
	public byte addr_entry_size;
	/**
	* �A�h���X��������
	*/
	public short alive_time;
	/**
	* �L�����ꂽ�A�h���X
	*/
	public IPAddress[] router_ip;
	/**
	* �v���t�@�����X
	*/
	public int[] preference;
	
	void setValue(byte type,byte code,short checksum,short id,short seq){
		this.type=type;this.code=code;
		this.checksum=checksum;
		this.id=id;this.seq=seq;
	}
	
	void setID(int id,int seq){
		this.id=id;
		this.seq=seq;
	}

	void setTimestampValue(long orig,long recv,long trans){
		this.orig_timestamp=orig;
		this.recv_timestamp=recv;
		this.trans_timestamp=trans;
	}

	void setRedirectIP(byte[] ip){
		redir_ip=new IPAddress(ip);
	}

	void setRouterAdValue(byte addr_num,byte entry_size,short alive_time,
						  String[] addr,int[] pref){
		this.addr_num=addr_num;
		this.addr_entry_size=entry_size;
		this.alive_time=alive_time;

		for(int i=0;i<addr_num;i++){
			try{
				router_ip[i]=new IPAddress(addr[i]);
			}catch(java.net.UnknownHostException e){}
			preference[i]=pref[i];
		}
	}

	/**
	* ���̃p�P�b�g�̓��e�𕶎���ŕ\�����܂�<BR>
	* <BR>
	* �`���Ftype(type) code(code)
	*/
	public String toString(){
		return super.toString()+"type("+type+") code("+code+")";
	}
}
