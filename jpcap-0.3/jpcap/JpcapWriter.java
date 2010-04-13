package jpcap;

public class JpcapWriter
{
	private native String nativeOpenDumpFile(String filename,int linktype,int thiszone,
		int snaplen);
	
	/**
	* �L���v�`�������p�P�b�g���t�@�C���ɕۑ�����ׂ�JpcapWriter�C���X�^���X���쐬����
	*
	* @param info Jpcap#getInfo()�ŏ�������JpcapInfo
	* @param filename �_���v�t�@�C����
	**/
	public JpcapWriter(Jpcap.JpcapInfo info,String filename)
			throws java.io.IOException{
		String ret=nativeOpenDumpFile(filename,info.linktype,info.thiszone,info.snaplen);
		
		if(ret!=null){ //error
			throw new java.io.IOException(ret);
		}
	}
	
	/**
	* �J���Ă���_���v�t�@�C�������
	**/
	public native void closeDumpFile();
	
	/**
	* �_���v�t�@�C���Ƀp�P�b�g���������o��
	**/
	public native void writeDumpFile(Packet packet);
	
  static{
    System.loadLibrary("jpcap");
  }
}
