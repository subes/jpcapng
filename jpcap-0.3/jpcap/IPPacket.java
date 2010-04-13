package jpcap;

/**
 * IPパケットを表現するクラスです。<P>
 * v4/v6の両方を取り扱うことが出来ます。
 */
public class IPPacket extends Packet
{
        /**
         * IPのバージョン (v4/v6)
         */
        public byte version;
        /**
         * このパケットの優先度(クラス) (v4/v6)
         */
        public byte priority;
        /**
         * IPフラグビット [D]elay 極力遅延させない (v4)
         */
        public boolean d_flag;
        /**
         * IPフラグビット[T]hrough 高スループット要求 (v4)
         */
        public boolean t_flag;
        /**
         * IPフラグビット[R]eliability 高信頼性要求 (v4)
         */
        public boolean r_flag;
        /**
         * パケット長 (v4/v6)
         */
        public short length;
        /**
         * 予約フラグメントフラグ (v4)
         */
        public boolean rsv_frag;
        /**
         * フラグメント禁止フラグ (v4)
         */
        public boolean dont_frag;
        /**
         * フラグメント後続ありのフラグ (v4)
         */
        public boolean more_frag;
        /**
         * フラグメントオフセット (v4)
         */
        public short offset;
        /**
         * ホップ限界値 (旧Time To Live) (v4/v6)
         */
        public short hop_limit;
        /**
         * 下位レイヤプロトコル (v4/v6)
         */
        public short protocol;
        /**
         * IDENTIFICATION (v4)
         */
        public int ident;
        /**
         * フローラベル (v6)
         */
        public int flow_label;

        /**
         * 送信元IPアドレス
         */
        public IPAddress src_ip;
        /**
         * 送信先IPアドレス
         */
        public IPAddress dst_ip;

        /**
         * オプションヘッダ (v6)
         **/
        public java.util.Vector options=null;

        /**
         * IPv4としてパケットのパラメータを設定します
         *
         * @param priority 優先度
         * @param d_flag,t_flag,r_flag Delay, Through, Realiabilityフラグ
         * @param rsv_frag 予約フラグメントフラグ
         * @param dont_frag フラグメント禁止フラグ
         * @param more_frag 後続フラグメントフラグ
         * @param offset オフセット
         * @param ident 識別子
         * @param ttl Time To Live
         * @param protocol プロトコル番号 (上位レイヤプロトコル(eg. TCPPacket)を継承している場合はこの値
は無視されます。)
         * @param src 送信元IPアドレス
         * @param dst 送信先IPアドレス
         **/
        public void setIPv4Parameter(int priority,
                                         boolean d_flag,boolean t_flag,boolean r_flag,
                                         boolean rsv_frag,boolean dont_frag,boolean more_frag,
                                         int offset,int ident,int ttl,
                                         int protocol,IPAddress src,IPAddress dst){
                this.version=4;
                this.priority=(byte)priority;
                this.d_flag=d_flag;this.t_flag=t_flag;this.r_flag=r_flag;
                this.rsv_frag=rsv_frag;this.dont_frag=dont_frag;
                this.more_frag=more_frag;
                offset=(short)offset;
                this.ident=ident;
                this.hop_limit=(short)ttl;
                this.protocol=(short)protocol;
                this.src_ip=src;
                this.dst_ip=dst;
        }

        /**
         * IPv6としてパケットのパラメータを設定します
         *
         * @param class クラス
         * @param flow_label フローラベル
         * @param nxt_hdr 次ヘッダ
         * @param hop_limit 限界ホップ数
         * @param src 送信元アドレス
         * @param dst 送信先アドレス
         **/
        public void setIPv6Parameter(int cls,int flowlabel,int nxt_hdr,
                                         int hop_limit,IPAddress src,IPAddress dst){
                this.version=6;
                this.priority=(byte)cls;
                this.flow_label=flowlabel;
                this.protocol=(short)nxt_hdr;
                this.hop_limit=(short)hop_limit;
                this.src_ip=src;
                this.dst_ip=dst;
        }

        void setIPv4Value(byte ver,byte pri,boolean d,boolean t,boolean r,
                                          boolean rf,boolean df,boolean mf,short offset,
                                          short len,short ident,short ttl,short proto,
                                          byte[] src_ip,byte[] dst_ip){

                this.version=ver;
                this.priority=pri;
                d_flag=d;t_flag=t;r_flag=r;
                rsv_frag=rf;dont_frag=df;more_frag=mf;
                this.offset=offset;
                this.length=len;
                this.ident=ident;
                this.hop_limit=ttl;
                this.protocol=proto;
                this.src_ip=new IPAddress(4,src_ip);
                this.dst_ip=new IPAddress(4,dst_ip);
        }

        void setIPv6Value(byte ver,byte v6class,int flow,
                                          short payload,byte nxt,short hlim,
                                          byte[] src,byte[] dst){
                this.version=ver;
                this.priority=v6class;
                this.flow_label=flow;
                this.length=payload;
                this.protocol=nxt;
                this.hop_limit=hlim;
                this.src_ip=new IPAddress(6,src);
                this.dst_ip=new IPAddress(6,dst);
        }

        void addOptionHeader(IPv6Option header){
                if(options==null)
                        options=new java.util.Vector();

                options.addElement(header);
        }

        byte[] getSourceAddress(){
                return src_ip.getAddress();
        }

        byte[] getDestinationAddress(){
                return dst_ip.getAddress();
        }

        /**
         * このパケットの内容を文字列で表現する<P>
         * 形式(IPv4): src_ip->dst_ip protocol(protocol) priority(priority)
         * [D][T][R] hop(hop_limit) [RF/][DF/][MF] offset(offset) ident(ident)<P>
         * 形式(IPv6): src_ip->dst_ip protocol(protocol) priority(priority)
         * flowlabel(flow_label) hop(hop_limit)
         */
        public String toString(){
                if(version==4){
                        return super.toString()+" "+src_ip+"->"+
                                dst_ip+" protocol("+protocol+
                                ") priority("+priority+") "+(d_flag?"D":"")+(t_flag?"T":"")+
                                (r_flag?"R":"")+" hop("+hop_limit+") "+(rsv_frag?"RF/":"")+
                                (dont_frag?"DF/":"")+(more_frag?"MF":"")+" offset("+offset+
                                ") ident("+ident+")";
                }else{
                        return super.toString()+" "+src_ip+"->"+
                                dst_ip+" protocol("+protocol+") priority("+priority+
                                ") flowlabel("+flow_label+") hop("+hop_limit+")";;
                }
        }
}
