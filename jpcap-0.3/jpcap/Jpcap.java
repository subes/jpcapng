package jpcap;

/**
* Java/Pcap��{�N���X<P>
* �p�P�b�g�̃L���v�`�������O�͂��̃N���X�̃C���X�^���X��ʂ��čs���B<P>
*
* �g�p���@�F<P>
* ���ϐ�CLASSPATH��/usr/local/java/jre/lib/jpcap.jar��ǉ�����B<BR>
* �i��Fsetenv CLASSPATH .:/usr/local/java/jre/lib/jpcap.jar�j<P>
*
* �ȒP�ȃp�P�b�g�L���v�`���v���O�����itcpdump���C�N�j<BR>
* <PRE>
* import jpcap.*;
* 
* class Tcpdump implements JpcapHandler
* {
*   public void handlePacket(Packet packet){
*     System.out.println(packet);
*   }
* 
*   public static void main(String[] args) throws java.io.IOException{
*     Jpcap jpcap=new Jpcap(args[0],1000,true,20);
*     jpcap.processPacket(-1,new Tcpdump());
*   }
* }
* </PRE>
*/
public class Jpcap
{
  /**
  * ��M�����p�P�b�g��
  *
  * @see #updateStat()
  */
  public int received_packets;
  /**
  * ��M�ł��Ȃ������p�P�b�g��
  *
  * @see #updateStat()
  */
  public int dropped_packets;

  private native String nativeOpenLive(String device,int snaplen,
				     int promisc,int to_ms);
  private native String nativeOpenOffline(String filename);

  /**
   * �L���v�`���\�ȃf�o�C�X�𔭌�����
   *
   * @return ���������f�o�C�X��
   **/  
  public static native String lookupDevice();

	/**
	 * �L���v�`���\�ȃf�o�C�X�̃��X�g��Ԃ�
	 *
	 * @return ���������f�o�C�X�̃��X�g
	 **/
	public static native String[] getDeviceList();

	/**
	 * getDeviceList()�ŏ��������f�o�C�X�̐�����Ԃ�(MS Windows�̂�)<P>
	 * 
	 * Windows�ł̓f�o�C�X�������Ȕԍ��ƕ�����Ƃ��Ĉ����Ă��܂��B
	 * (��F\Device\Packet_{6E05D...}�j���̃��\�b�h�́A�e�f�o�C�X��
	 * �΂�����킩��₷�������i��F3com EtherLinkII)��Ԃ��܂��B
	 *
	 * @return �e�f�o�C�X�̐���
	 **/
  public static native String[] getDeviceDescription();

  /**
  * �p�P�b�g���P��������
  */
  public native Packet getPacket();

  /**
  * �p�P�b�g��A�����ď�������<P>
  *
  * �w�肵�����̃p�P�b�g���������܂��B�w�萔�p�P�b�g���������I��邩
  * �^�C���A�E�g�ɂȂ�ƏI�����܂��B���ۂɏ��������p�P�b�g����
  * �Ԃ��܂��B
  *
  * @param	count	��������p�P�b�g��<BR>
  *			-1�̏ꍇ�̓G���[���������邩EOF�܂ŏ�����������
  * @param	handler	���������p�P�b�g����͂��邽�߂�JpcapHandler�N���X
  * @return	�L���v�`�������p�P�b�g��
  */
  public native int processPacket(int count,JpcapHandler handler);

  /**
  * �p�P�b�g��A�����ď�������<P>
  *
  * �w�肵�����̃p�P�b�g���������܂��BprocessPacket()�Ƃ͈قȂ�A
  * �^�C���A�E�g�𖳎����Ďw�肵���p�P�b�g������������܂�
  * �L���v�`���𑱂��܂��B�^�C���A�E�g�𗘗p����������
  * processPacket���g�p���ĉ������B
  *
  * @param	count	��������p�P�b�g��<BR>
  *			-1�̏ꍇ�̓G���[���������邩EOF�܂ŏ�����������
  * @param	handler	���������p�P�b�g����͂��邽�߂�JpcapHandler�N���X
  * @return	�L���v�`�������p�P�b�g��
  */
  public native int loopPacket(int count,JpcapHandler handler);

  /**
  * �t�B���^��ݒ肷��
  *
  * @param	condition	�t�B���^�ɃZ�b�g���镶����
  * @param	optimize	true�̏ꍇ�͍œK�����s��
  */
  public native void setFilter(String condition,boolean optimize);

  /**
  * {@link #received_packets received_packets} �� {@link #dropped_packets dropped_packets}���X�V����
  */
  public native void updateStat();

  /**
  * IP�p�P�b�g���M�p�̃\�P�b�g������������
  *
  */
  public native void openRawSocket();

  /**
  * IP�p�P�b�g���P���M����B<P>
  * ���݂�TCP/UDP/ICMP over IPv4�̂݃T�|�[�g���Ă��܂��B<BR>
  * ICMP�̓G�R�[�p�P�b�g�̂ݑ��M���܂��B
  *
  * @param  packet   ���M����IP�p�P�b�g
  */
  public native void sendPacket(IPPacket packet);

  /**
  * �G���[���b�Z�[�W��Ԃ�
  **/
  public native String getErrorMessage();
  
  /**
  * �I�[�v�����Ă���C���^�[�t�F�[�X�܂��̓_���v�t�@�C�������
  */
  public native void close();

  /**
  * ���C�u�L���v�`�������O�p�Ƀl�b�g���[�N�C���^�[�t�F�[�X����������Jpcap�̃C���X�^���X���쐬����
  *
  * @param	device	�L���v�`������l�b�g���[�N�f�o�C�X�� (��Fhme0,eth0)
  * @param	snaplen �P�x�ɃL���v�`������ő�o�C�g��
  * @param	promisc	�w�肵���C���^�[�t�F�[�X���v���~�V���X���[�h�ɂ���
  * @param	to_ms	{@link #processPacket(int,JpcapHandler) processPacket()}�𒆒f����܂ł̃^�C���A�E�g����
  * @exception java.io.IOException �L���v�`���f�o�C�X���J���Ȃ����ꍇ
  */
  public Jpcap(String device,int snaplen,boolean promisc,int to_ms)
      throws java.io.IOException{
    String ret=nativeOpenLive(device,snaplen,(promisc?1:0),to_ms);

    if(ret!=null){ //error
      throw new java.io.IOException(ret);
    }
  }

  /**
  * tcpdump�Ń_���v�����t�@�C�����J��Jpcap�̃C���X�^���X���쐬����
  *
  * @param	filename	�_���v�t�@�C���̃t�@�C����
  * @exception java.io.IOException �t�@�C�����J���Ȃ������ꍇ
  *
  */
  public Jpcap(String filename) throws java.io.IOException{
    String ret=nativeOpenOffline(filename);

    if(ret!=null){ //error
      throw new java.io.IOException(ret);
    }
  }

	/**
	* �L���v�`������ێ�����ׂ̃N���X�BJpcapWriter���g�p����ۂɕK�v�B
	**/
	public class JpcapInfo{
		int linktype,thiszone,snaplen;
		
		JpcapInfo(int linktype,int thiszone,int snaplen){
			this.linktype=linktype;this.thiszone=thiszone;this.snaplen=snaplen;
		}
	}
	
	private JpcapInfo info;
	
	void setInfo(int linktype,int thiszone,int snaplen){
		info=new JpcapInfo(linktype,thiszone,snaplen);
	}
	
	/**
	* ����Jpcap�C���X�^���X��Jpcap.JpcapInfo��Ԃ�
	**/
	public JpcapInfo getJpcapInfo(){
		return info;
	}

  static{
    System.loadLibrary("jpcap");
  }
}
