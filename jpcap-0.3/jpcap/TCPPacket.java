package jpcap;

/**
* TCP�p�P�b�g��\������N���X�ł�
*/
public class TCPPacket extends IPPacket
{
	/**
	 * ���M���|�[�g
	 */
	public int src_port;
	/**
	 * ���M��|�[�g
	 */
	public int dst_port;
	/**
	 * �V�[�P���X�ԍ�
	 */
	public long sequence;
	/**
	 * ACK�ԍ�
	 */
	public long ack_num;
	/**
	 * URG�t���O: �ً}�f�[�^�i�D�摗�M�v���j
	 */
	public boolean urg;
	/**
	 * ACK�t���O: ACK�ԍ��t�B�[���h�L��
	 */
	public boolean ack;
	/**
	 * PSH�t���O: PUSH�i�������M�j�v��
	 */
	public boolean psh;
	/**
	 * RST�t���O: �����ؒf�v��
	 */
	public boolean rst;
	/**
	 * SYN�t���O: �V�[�P���X�ԍ��̓����v��
	 */
	public boolean syn;
	/**
	 * FIN�t���O: ���M�I���v��
	 */
	public boolean fin;
	/**
	 * �E�B���h�E�i��M�o�b�t�@�c��o�C�g���j
	 */
	public int window;
	/**
	 * �ً}�|�C���^
	 */
	public short urgent_pointer;

	/**
	* TCP�I�v�V����
	**/
	public byte[] option;

	/**
	 * TCP�p�P�b�g�̃I�u�W�F�N�g�𐶐����܂�
	 *
	 * @param src_port ���M���|�[�g�ԍ�
	 * @param dst_port ���M��|�[�g�ԍ�
	 * @param sequence �V�[�P���X�ԍ�
	 * @param ack_num ACK�ԍ�
	 * @param urg URG�t���O: �ً}�f�[�^�i�D�摗�M�v���j
	 * @param ack ACK�t���O: ACK�ԍ��t�B�[���h�L��
	 * @param psh PSH�t���O: PUSH�i�������M�j�v��
	 * @param rst RST�t���O: �����ؒf�v��
	 * @param syn SYN�t���O: �V�[�P���X�ԍ��̓����v��
	 * @param fin FIN�t���O: ���M�I���v��
	 * @param window �E�B���h�E�T�C�Y
	 * @param urgent �ً}�|�C���^
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
  * ���̃p�P�b�g�̓��e�𕶎���ŕ\�����܂�<BR>
  *
  * <BR>
  * �`��: src_port > dst_port seq(sequence) win(window) [ack ack_num] [S][F][P]
  */
	public String toString(){
		return super.toString()+" TCP "+
			src_port+" > "+dst_port+" seq("+sequence+
			") win("+window+")"+(ack?" ack "+ack_num:"")+" "+
			(syn?" S":"")+(fin?" F":"")+(psh?" P":"")+
			(rst?" R":"")+(urg?" U":"");
	}
}
