package jpcap;

/**
 * IP�p�P�b�g��\������N���X�ł��B<P>
 * v4/v6�̗�������舵�����Ƃ��o���܂��B
 */
public class IPPacket extends Packet
{
        /**
         * IP�̃o�[�W���� (v4/v6)
         */
        public byte version;
        /**
         * ���̃p�P�b�g�̗D��x(�N���X) (v4/v6)
         */
        public byte priority;
        /**
         * IP�t���O�r�b�g [D]elay �ɗ͒x�������Ȃ� (v4)
         */
        public boolean d_flag;
        /**
         * IP�t���O�r�b�g[T]hrough ���X���[�v�b�g�v�� (v4)
         */
        public boolean t_flag;
        /**
         * IP�t���O�r�b�g[R]eliability ���M�����v�� (v4)
         */
        public boolean r_flag;
        /**
         * �p�P�b�g�� (v4/v6)
         */
        public short length;
        /**
         * �\��t���O�����g�t���O (v4)
         */
        public boolean rsv_frag;
        /**
         * �t���O�����g�֎~�t���O (v4)
         */
        public boolean dont_frag;
        /**
         * �t���O�����g�㑱����̃t���O (v4)
         */
        public boolean more_frag;
        /**
         * �t���O�����g�I�t�Z�b�g (v4)
         */
        public short offset;
        /**
         * �z�b�v���E�l (��Time To Live) (v4/v6)
         */
        public short hop_limit;
        /**
         * ���ʃ��C���v���g�R�� (v4/v6)
         */
        public short protocol;
        /**
         * IDENTIFICATION (v4)
         */
        public int ident;
        /**
         * �t���[���x�� (v6)
         */
        public int flow_label;

        /**
         * ���M��IP�A�h���X
         */
        public IPAddress src_ip;
        /**
         * ���M��IP�A�h���X
         */
        public IPAddress dst_ip;

        /**
         * �I�v�V�����w�b�_ (v6)
         **/
        public java.util.Vector options=null;

        /**
         * IPv4�Ƃ��ăp�P�b�g�̃p�����[�^��ݒ肵�܂�
         *
         * @param priority �D��x
         * @param d_flag,t_flag,r_flag Delay, Through, Realiability�t���O
         * @param rsv_frag �\��t���O�����g�t���O
         * @param dont_frag �t���O�����g�֎~�t���O
         * @param more_frag �㑱�t���O�����g�t���O
         * @param offset �I�t�Z�b�g
         * @param ident ���ʎq
         * @param ttl Time To Live
         * @param protocol �v���g�R���ԍ� (��ʃ��C���v���g�R��(eg. TCPPacket)���p�����Ă���ꍇ�͂��̒l
�͖�������܂��B)
         * @param src ���M��IP�A�h���X
         * @param dst ���M��IP�A�h���X
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
         * IPv6�Ƃ��ăp�P�b�g�̃p�����[�^��ݒ肵�܂�
         *
         * @param class �N���X
         * @param flow_label �t���[���x��
         * @param nxt_hdr ���w�b�_
         * @param hop_limit ���E�z�b�v��
         * @param src ���M���A�h���X
         * @param dst ���M��A�h���X
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
         * ���̃p�P�b�g�̓��e�𕶎���ŕ\������<P>
         * �`��(IPv4): src_ip->dst_ip protocol(protocol) priority(priority)
         * [D][T][R] hop(hop_limit) [RF/][DF/][MF] offset(offset) ident(ident)<P>
         * �`��(IPv6): src_ip->dst_ip protocol(protocol) priority(priority)
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
