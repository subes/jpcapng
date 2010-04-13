package jpcap;

/**
* UDP�p�P�b�g��\������N���X�ł�
*/
public class UDPPacket extends IPPacket
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
	 * �p�P�b�g��
	 */
	public int length;
	
	/**
	 * UDP�p�P�b�g�̃I�u�W�F�N�g�𐶐����܂�
	 *
	 * @param src_port ���M���|�[�g�ԍ�
	 * @param dst_port ���M��|�[�g�ԍ�
	 **/
	public UDPPacket(int src_port,int dst_port){
		this.src_port=src_port;
		this.dst_port=dst_port;
	}

	void setValue(int src,int dst,int len){
		src_port=src;dst_port=dst;
		length=len;
	}
	
	/**
	 * ���̃p�P�b�g�̓��e�𕶎���ŕ\�����܂�<BR>
	 *
	 * <BR>
	 * �`��: src_port > dst_port
	 */
	public String toString(){
		return super.toString()+" UDP "+src_port+" > "+dst_port;
	}
}
