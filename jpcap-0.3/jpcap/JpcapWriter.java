package jpcap;

public class JpcapWriter
{
	private native String nativeOpenDumpFile(String filename,int linktype,int thiszone,
		int snaplen);
	
	/**
	* キャプチャしたパケットをファイルに保存する為のJpcapWriterインスタンスを作成する
	*
	* @param info Jpcap#getInfo()で所得したJpcapInfo
	* @param filename ダンプファイル名
	**/
	public JpcapWriter(Jpcap.JpcapInfo info,String filename)
			throws java.io.IOException{
		String ret=nativeOpenDumpFile(filename,info.linktype,info.thiszone,info.snaplen);
		
		if(ret!=null){ //error
			throw new java.io.IOException(ret);
		}
	}
	
	/**
	* 開いているダンプファイルを閉じる
	**/
	public native void closeDumpFile();
	
	/**
	* ダンプファイルにパケット情報を書き出す
	**/
	public native void writeDumpFile(Packet packet);
	
  static{
    System.loadLibrary("jpcap");
  }
}
