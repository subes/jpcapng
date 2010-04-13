package jpcap;

/**
* IPv6�̃I�v�V�����w�b�_��\������N���X�ł��B
*/
public class IPv6Option{

	/**
	 * ���p�_�I�v�V����
	 **/
	public static final byte HOP_BY_HOP_OPTION=0;
	/**
	 * �o�H����I�v�V����
	 **/
	public static final byte ROUTING_OPTION=43;
	/**
	 * �f�ЃI�v�V����
	 **/
	public static final byte FRAGMENT_OPTION=44;
	/**
	 * �Z�L�����e�B�y�C���[�h
	 **/
	public static final byte ESP_OPTION=50;
	/**
	 * �F�؃I�v�V����
	 **/
	public static final byte AH_OPTION=51;
	/**
	 * ���w�b�_����
	 **/
	public static final byte NONE_OPTION=59;
	/**
	 * �I�_�I�v�V����
	 **/
	public static final byte DESTINATION_OPTION=60;

	/**
	 * �g���I�v�V�����^�C�v
	 **/
	public byte type;
	/**
	 * ���w�b�_
	 **/
	public byte next_header;
	/**
	 * �g���w�b�_��
	 **/
	public byte hlen;

	/**
	* �I�v�V����
	*/
	public byte[] option;

	/**
	* ���[�e�B���O�^�C�v�i�o�H����I�v�V�����j
	*/
	public byte routing_type;
	/**
	* �z�b�v�c���i�o�H����I�v�V�����j
	*/
	public byte hop_left;
	/**
	* �o�H�A�h���X�i�o�H����I�v�V�����j
	*/
	public IPAddress[] addrs;

	/**
	* �I�t�Z�b�g�i�t���O�����g�I�v�V�����j
	*/
	public short offset;
	/**
	* �㑱�t���O�i�t���O�����g�I�v�V�����j
	*/
	public boolean m_flag;
	/**
	* Identification�i�t���O�����g�I�v�V�����j
	*/
	public int identification;

	/**
	* SPI�iAH�I�v�V�����p�j
	*/
	public int spi;
	/**
	* �V�[�P���X�ԍ��iAH�I�v�V�����p�j
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
