package jpcap;

/**
* Jpcap��handlePacket()�Ńp�P�b�g����͂��郁�\�b�h���`���邽�߂̃C���^�[�t�F�[�X�ł�
*
* @see Jpcap#processPacket(int,JpcapHandler)
*/
public interface JpcapHandler
{
  /**
  * �p�P�b�g����͂��郁�\�b�h<BR>
  * <BR>
  * �p�P�b�g����M����x�ɌĂяo����܂�
  */
  public void handlePacket(Packet p);
}
