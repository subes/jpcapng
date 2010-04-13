import jpcap.*;

class Tcpdump implements JpcapHandler
{
  public void handlePacket(Packet packet){
    System.out.println(packet);
  }

  public static void main(String[] args) throws java.io.IOException{
    Jpcap jpcap=null;
    
	IPAddress.setAddressConvert(true);
	String[] devices=Jpcap.getDeviceList();
	for(int i=0;i<devices.length;i++)
		System.out.println(devices[i]);

	if(args.length==1){
	  jpcap=new Jpcap(args[0],1500,true,200);
	}else if(args.length==2 && args[0].equals("-f")){
	  jpcap=new Jpcap(args[1]);
	}else{
	  System.out.println("Usage: java Tcpdump [device name] | -f [dumpfile]");
	  System.exit(0);
	}
	
	jpcap.loopPacket(-1,new Tcpdump());
  }
}
