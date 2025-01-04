using System.Net;
using System.Net.Sockets;
using PacketDotNet;
using SharpPcap;
var ver = Pcap.SharpPcapVersion;
Console.WriteLine("PacketDotNet example using SharpPcap {0}", ver);

// Retrieve all capture devices
CaptureDeviceList  devices = CaptureDeviceList.Instance;

// If no devices were found print an error
if(devices.Count < 1)
{
  Console.WriteLine("No devices were found on this machine");
  return;
}

foreach(ICaptureDevice device in devices)
{
  Console.WriteLine("{0}\n", device.ToString());
  if(device.ToString().Contains(" Wi-Fi"))
  {
    // Register our handler function to the
    // 'packet arrival' event
    device.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival);
    // Open the device for capturing
    int readTimeoutMilliseconds = 1000;
    device.Open(DeviceModes.Promiscuous, readTimeoutMilliseconds);
    // tcpdump filter to capture only TCP/IP packets
    string filter = "ip and tcp";
    device.Filter = filter;
    // Start the capturing process
    device.StartCapture();
    // Wait for 'Enter' from the user.
    Console.ReadLine();
    // Stop the capturing process
    device.StopCapture();
    // Close the pcap device
    device.Close();
    // Print out the device statistics
    Console.WriteLine(device.Statistics.ToString());
    break;
  }
}

Console.Write("Hit 'Enter' to exit...");
Console.ReadLine();

static void device_OnPacketArrival(object sender, PacketCapture e)
{
  RawCapture rawPacket = e.GetPacket();
  LinkLayers layer = rawPacket.LinkLayerType;
  DateTime time = rawPacket.Timeval.Date;
  int len = rawPacket.Data.Length;
  
  
  if (layer == LinkLayers.Ethernet)
  {
    var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
    var ethernetPacket = (EthernetPacket)packet;

    var tcpPacket = packet.Extract<TcpPacket>();
    if (tcpPacket != null)
    {
      var ipPacket = (IPPacket)tcpPacket.ParentPacket;
      IPAddress sourceIp = ipPacket.SourceAddress;
      IPAddress destinationIp = ipPacket.DestinationAddress;

      int sourcePort = tcpPacket.SourcePort;
      int destinationPort = tcpPacket.DestinationPort;

      IPAddress hostIp = IPAddress.None;
      IPHostEntry hostEntry = Dns.GetHostEntry(Dns.GetHostName());
      foreach(IPAddress ip in hostEntry.AddressList)
      {
        if(ip.AddressFamily == AddressFamily.InterNetwork)
        {
          hostIp = ip;
        }
      }

      if(!destinationIp.Equals(hostIp))
      {
        Console.WriteLine("{0}:{1}:{2},{3} Len={4} {5}:{6} -> {7}:{8}",
                      time.Hour, time.Minute, time.Second, time.Millisecond, len,
                      sourceIp, sourcePort, destinationIp, destinationPort);
      }
    }
  }
}