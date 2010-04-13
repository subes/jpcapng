package jpcap;

/**
 * ARP/RARP�p�P�b�g��\������N���X�ł��B
 **/
public class ARPPacket extends Packet
{
	/**
	 * �n�[�h�E�F�A�^�C�v
	 **/
	public short hardtype;
	/**
	 * �n�[�h�E�F�A�^�C�v:�C�[�T�l�b�g
	 **/
	public static final short HARDTYPE_ETHER=1;
	/**
	 * �n�[�h�E�F�A�^�C�v:�g�[�N�������O
	 **/
	public static final short HARDTYPE_IEEE802=6;
	/**
	 * �n�[�h�E�F�A�^�C�v:�t���[�������[
	 **/
	public static final short HARDTYPE_FRAMERELAY=15;

	/**
	 * �v���g�R���^�C�v
	 **/
	public short prototype;
	/**
	* �v���g�R���^�C�v: IP
	**/
	public static final short PROTOTYPE_IP=2048;

	/**
	 * �n�[�h�E�G�A�A�h���X��
	 **/
	public short hlen;

	/**
	 * �v���g�R���A�h���X��
	 **/
	public short plen;

	/**
	 * �I�y���[�V����
	 **/
	public short operation;
	/**
	 * ARP���N�G�X�g
	 **/
	public static final short ARP_REQUEST=1;
	/**
	 * ARP���v���C
	 **/
	public static final short ARP_REPLY=2;
	/**
	 * Reverse ARP���N�G�X�g
	 **/
	public static final short RARP_REQUEST=3;
	/**
	 * Reverse ARP���v���C
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
	 * ���M�҃n�[�h�E�F�A�A�h���X
	 **/
	public byte[] sender_hardaddr;
	/**
	 * ���M�҃v���g�R���A�h���X
	 **/
	public byte[] sender_protoaddr;
	/**
	 * �^�[�Q�b�g�n�[�h�E�F�A�A�h���X
	 **/
	public byte[] target_hardaddr;
	/**
	 * �^�[�Q�b�g�v���g�R���A�h���X
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
	* ���M��MAC�A�h���X��String�ŕԂ�
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
	* ���M��MAC�A�h���X��String�ŕԂ�
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
	* ���M���v���g�R���A�h���X��Ԃ�
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
	* ���M��v���g�R���A�h���X��Ԃ�
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
	 * ���̃p�P�b�g�̓��e�𕶎���ŕ\������<BR>
	 *
	 * <BR>
	 * �`��: ARP(hardtype:prototype) 
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
