package jpcap;

/** This class represents an IP packet.<P>
 * Both IPv4 and IPv6 are supported.
 */
public class IPPacket extends Packet
{
        /** IP version (v4/v6) */
        public byte version;
        /** Priority (class) (v4/v6) */
        public byte priority;
        /** IP flag bit: [D]elay (v4) */
        public boolean d_flag;
        /** IP flag bit: [T]hrough (v4) */
        public boolean t_flag;
        /** IP flag bit: [R]eliability (v4) */
        public boolean r_flag;

        // added by Damien Daspit 5/7/01
        /** Type of Service (TOS) (v4/v6) */        
        public byte rsv_tos;
        // *****************************

        /** Packet length (v4/v6) */
        public short length;
        /** Fragmentation reservation flag (v4) */
        public boolean rsv_frag;
        /** Don't fragment flag (v4) */
        public boolean dont_frag;
        /** More fragment flag (v4) */
        public boolean more_frag;
        /** Fragment offset (v4) */
        public short offset;
        /** Hop Limit, Time To Live (TTL) (v4/v6) */
        public short hop_limit;
        /** Protocol (v4/v6) */
        public short protocol;
        /** IDENTIFICATION (v4) */
        public int ident;
        /** Flow label (v6) */
        public int flow_label;

        /** Source IP address */
        public IPAddress src_ip;
        /** Destination IP address */
        public IPAddress dst_ip;

		/** Option in IPv4 header (v4) */
		public byte[] option;

        /** Option headers in IPv6Option (v6) */
        public java.util.Vector options=null;

        /** Sets the IPv4 parameters
         * @param d_flag IP flag bit: [D]elay
         * @param t_flag IP flag bit: [T]hrough
         * @param r_flag IP flag bit: [R]eliability
         * @param rsv_tos Type of Service (TOS)
         * @param priority Priority
         * @param rsv_frag Fragmentation Reservation flag
         * @param dont_frag Don't fragment flag
         * @param more_frag More fragment flag
         * @param offset Offset
         * @param ident Identifier
         * @param ttl Time To Live
         * @param protocol Protocol <BR>
         * This value is ignored when this packets
         * inherits a higher layer protocol(e.g. TCPPacket)
         * @param src Source IP address
         * @param dst Destination IP address
         */
        public void setIPv4Parameter(int priority,
                                         boolean d_flag,boolean t_flag,boolean r_flag, int rsv_tos,
                                         boolean rsv_frag,boolean dont_frag,boolean more_frag,
                                         int offset,int ident,int ttl,
                                         int protocol,IPAddress src,IPAddress dst){
                this.version=4;
                this.priority=(byte)priority;
                this.d_flag=d_flag;this.t_flag=t_flag;this.r_flag=r_flag;
                // added by Damien Daspit 5/7/01
                this.rsv_tos=(byte)rsv_tos;
                // *****************************
                this.rsv_frag=rsv_frag;this.dont_frag=dont_frag;
                this.more_frag=more_frag;
                offset=(short)offset;
                this.ident=ident;
                this.hop_limit=(short)ttl;
                this.protocol=(short)protocol;
                this.src_ip=src;
                this.dst_ip=dst;
        }

        /** Sets the IPv6 parameters
         * @param cls class
         * @param flowlabel flow label
         * @param nxt_hdr next header
         * @param hop_limit hop limit
         * @param src source address
         * @param dst destination address
         */
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


        void setIPv4Value(byte ver,byte pri,boolean d,boolean t,boolean r,byte rsv_tos,
                                          boolean rf,boolean df,boolean mf,short offset,
                                          short len,short ident,short ttl,short proto,
                                          byte[] src_ip,byte[] dst_ip){

                this.version=ver;
                this.priority=pri;
                d_flag=d;t_flag=t;r_flag=r;
                // added by Damien Daspit 5/7/01
                this.rsv_tos=rsv_tos;
                // *****************************
                rsv_frag=rf;dont_frag=df;more_frag=mf;
                this.offset=offset;
                this.length=len;
                this.ident=ident;
                this.hop_limit=ttl;
                this.protocol=proto;
                this.src_ip=new IPAddress(4,src_ip);
                this.dst_ip=new IPAddress(4,dst_ip);
        }

		void setOption(byte[] option){
			this.option=option;
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

        /** Returns a string represenation of this packet.<P>
         * Format(IPv4): src_ip->dst_ip protocol(protocol) priority(priority)
         * [D][T][R] hop(hop_limit) [RF/][DF/][MF] offset(offset) ident(ident)<P>
         *
         * Format(IPv6): src_ip->dst_ip protocol(protocol) priority(priority)
         * flowlabel(flow_label) hop(hop_limit)
         * @return a string represenation of this packet
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
                                ") flowlabel("+flow_label+") hop("+hop_limit+")";
                }
        }
}
