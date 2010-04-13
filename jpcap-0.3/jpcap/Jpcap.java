package jpcap;

/**
* Java/Pcap基本クラス<P>
* パケットのキャプチャリングはこのクラスのインスタンスを通して行う。<P>
*
* 使用方法：<P>
* 環境変数CLASSPATHに/usr/local/java/jre/lib/jpcap.jarを追加する。<BR>
* （例：setenv CLASSPATH .:/usr/local/java/jre/lib/jpcap.jar）<P>
*
* 簡単なパケットキャプチャプログラム（tcpdumpライク）<BR>
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
  * 受信したパケット数
  *
  * @see #updateStat()
  */
  public int received_packets;
  /**
  * 受信できなかったパケット数
  *
  * @see #updateStat()
  */
  public int dropped_packets;

  private native String nativeOpenLive(String device,int snaplen,
				     int promisc,int to_ms);
  private native String nativeOpenOffline(String filename);

  /**
   * キャプチャ可能なデバイスを発見する
   *
   * @return 発見したデバイス名
   **/  
  public static native String lookupDevice();

	/**
	 * キャプチャ可能なデバイスのリストを返す
	 *
	 * @return 発見したデバイスのリスト
	 **/
	public static native String[] getDeviceList();

	/**
	 * getDeviceList()で所得したデバイスの説明を返す(MS Windowsのみ)<P>
	 * 
	 * Windowsではデバイス名を難解な番号と文字列として扱われています。
	 * (例：\Device\Packet_{6E05D...}）このメソッドは、各デバイスに
	 * 対するよりわかりやすい説明（例：3com EtherLinkII)を返します。
	 *
	 * @return 各デバイスの説明
	 **/
  public static native String[] getDeviceDescription();

  /**
  * パケットを１つ所得する
  */
  public native Packet getPacket();

  /**
  * パケットを連続して所得する<P>
  *
  * 指定した数のパケットを所得します。指定数パケットを所得し終わるか
  * タイムアウトになると終了します。実際に所得したパケット数を
  * 返します。
  *
  * @param	count	所得するパケット数<BR>
  *			-1の場合はエラーが発生するかEOFまで所得し続ける
  * @param	handler	所得したパケットを解析するためのJpcapHandlerクラス
  * @return	キャプチャしたパケット数
  */
  public native int processPacket(int count,JpcapHandler handler);

  /**
  * パケットを連続して所得する<P>
  *
  * 指定した数のパケットを所得します。processPacket()とは異なり、
  * タイムアウトを無視して指定したパケット数を所得するまで
  * キャプチャを続けます。タイムアウトを利用したい時は
  * processPacketを使用して下さい。
  *
  * @param	count	所得するパケット数<BR>
  *			-1の場合はエラーが発生するかEOFまで所得し続ける
  * @param	handler	所得したパケットを解析するためのJpcapHandlerクラス
  * @return	キャプチャしたパケット数
  */
  public native int loopPacket(int count,JpcapHandler handler);

  /**
  * フィルタを設定する
  *
  * @param	condition	フィルタにセットする文字列
  * @param	optimize	trueの場合は最適化を行う
  */
  public native void setFilter(String condition,boolean optimize);

  /**
  * {@link #received_packets received_packets} と {@link #dropped_packets dropped_packets}を更新する
  */
  public native void updateStat();

  /**
  * IPパケット送信用のソケットを初期化する
  *
  */
  public native void openRawSocket();

  /**
  * IPパケットを１つ送信する。<P>
  * 現在はTCP/UDP/ICMP over IPv4のみサポートしています。<BR>
  * ICMPはエコーパケットのみ送信します。
  *
  * @param  packet   送信するIPパケット
  */
  public native void sendPacket(IPPacket packet);

  /**
  * エラーメッセージを返す
  **/
  public native String getErrorMessage();
  
  /**
  * オープンしているインターフェースまたはダンプファイルを閉じる
  */
  public native void close();

  /**
  * ライブキャプチャリング用にネットワークインターフェースを初期化しJpcapのインスタンスを作成する
  *
  * @param	device	キャプチャするネットワークデバイス名 (例：hme0,eth0)
  * @param	snaplen １度にキャプチャする最大バイト数
  * @param	promisc	指定したインターフェースをプロミシャスモードにする
  * @param	to_ms	{@link #processPacket(int,JpcapHandler) processPacket()}を中断するまでのタイムアウト時間
  * @exception java.io.IOException キャプチャデバイスを開けなった場合
  */
  public Jpcap(String device,int snaplen,boolean promisc,int to_ms)
      throws java.io.IOException{
    String ret=nativeOpenLive(device,snaplen,(promisc?1:0),to_ms);

    if(ret!=null){ //error
      throw new java.io.IOException(ret);
    }
  }

  /**
  * tcpdumpでダンプしたファイルを開きJpcapのインスタンスを作成する
  *
  * @param	filename	ダンプファイルのファイル名
  * @exception java.io.IOException ファイルが開けなかった場合
  *
  */
  public Jpcap(String filename) throws java.io.IOException{
    String ret=nativeOpenOffline(filename);

    if(ret!=null){ //error
      throw new java.io.IOException(ret);
    }
  }

	/**
	* キャプチャ情報を保持する為のクラス。JpcapWriterを使用する際に必要。
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
	* このJpcapインスタンスのJpcap.JpcapInfoを返す
	**/
	public JpcapInfo getJpcapInfo(){
		return info;
	}

  static{
    System.loadLibrary("jpcap");
  }
}
