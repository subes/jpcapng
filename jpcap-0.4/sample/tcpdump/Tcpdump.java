import jpcap.*;

class Tcpdump implements JpcapHandler
{
   public void handlePacket(Packet packet){
     System.out.println(packet);
   }
 
   public static void main(String[] args) throws java.io.IOException{
     String[] lists=Jpcap.getDeviceDescription();
     System.out.println("Start capturing on "+lists[0]);

     Jpcap jpcap=Jpcap.openDevice(Jpcap.getDeviceList()[0],1000,false,20);
     jpcap.loopPacket(-1,new Tcpdump());
   }
}
