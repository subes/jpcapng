import jpcap.*;

class Ping
{
	public static void main(String[] args) throws java.io.IOException{
		System.out.println(Jpcap.getDeviceList()[1]);
		JpcapSender sender=JpcapSender.openDevice(Jpcap.getDeviceList()[1]);

		UDPPacket p=new UDPPacket(12345,54321);
		p.setIPv4Parameter(0,false,false,false,0,false,false,false,0,1010101,100,0,
			new IPAddress("bassoon.goto.info.waseda.ac.jp"),new IPAddress("oboe.goto.info.waseda.ac.jp"));
		p.data="data".getBytes();

		for(int i=0;i<10;i++)
			sender.sendPacket(p);
	}
}