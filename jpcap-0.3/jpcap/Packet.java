package jpcap;

/**
* {@link Jpcap Jpcap}�ɂ���ăL���v�`�������S�Ẵp�P�b�g�f�[�^�̐e�N���X�ł��B
*/
public class Packet
{
	/**
	 * �L���v�`�����ꂽ�����̃^�C���X�^���v�i�b�j
	 */
	public long sec;
	
	/**
	 * �L���v�`�����ꂽ�����̃^�C���X�^���v�i�}�C�N���b�j
	 **/
	public long usec;
	
	/**
	 * �L���v�`�����ꂽ����
	 **/
	public int caplen;
	
	/**
	* ���̃p�P�b�g�̒���
	**/
	public int len;
	
	/**
	 * �f�[�^�����N�w�w�b�_
	 **/
	public DatalinkPacket datalink;

	/**
	* �w�b�_���̃f�[�^
	**/
	public byte[] header;

	/**
	 * �p�P�b�g�̃f�[�^ (�w�b�_��������������)
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
	 * ���̃p�P�b�g�̓��e�𕶎���ŕ\�����܂�<BR>
	 * �`��: sec:usec
	 */
	public String toString(){
		return sec+":"+usec;
	}
}
