using System.Collections.Generic;
using NdisApiDotNet;
using NdisApiDotNetPacketDotNet.Extensions;
using PacketDotNet;
using System;
using System.Net;
using System.Text;
using System.Threading;
using System.Timers;
namespace IDS
{
    /// <summary>
    /// After analyzing the SYN-attacks, it was revealed that the number of requests would exceed 500. 
    /// To detect the SYN-attack, it was decided to use a timer and estimate the number of packets in 1 second.
    /// This program will close connection when attack detect.
    /// </summary>
    public class IDS
    {
        int ksyn = 0;
        public int seconds = 1000;
        public int amount = 500;
        public void SYNFloodDetector(NdisApi filter, WaitHandle[] waitHandles, IReadOnlyList<NetworkAdapter> networkAdapters, IReadOnlyList<ManualResetEvent> waitHandlesManualResetEvents)
        {
            var ndisApiHelper = new NdisApiHelper();
            var ethRequest = ndisApiHelper.CreateEthRequest();
            System.Timers.Timer aTimer = new System.Timers.Timer(); //Timer method
            aTimer.Elapsed += new ElapsedEventHandler(Status); //Call status method when timer reloading
            aTimer.Interval = seconds;//1000 ms is 1 sec
            aTimer.Enabled = true;
            int n = 1;

            while (true)
            {
                var handle = WaitHandle.WaitAny(waitHandles);
                ethRequest.AdapterHandle = networkAdapters[handle].Handle;
                while (filter.ReadPacket(ref ethRequest) && n == 1)
                {
                    var packet = ethRequest.Packet;
                    var ethPacket = packet.GetEthernetPacket(ndisApiHelper);
                    if (ethPacket.PayloadPacket is IPv4Packet iPv4Packet)
                    {
                        if (iPv4Packet.PayloadPacket is TcpPacket tcpPacket)
                        {
                            if ((tcpPacket.DestinationPort == 80) || (tcpPacket.SourcePort == 80))
                            {
                                // Receive TCP packet. Perception the HHTP markers.
                                string httpPacket = Encoding.UTF8.GetString(tcpPacket.PayloadData);
                                if ((httpPacket != "") && (httpPacket != "\0"))
                                {
                                    string[] headersHttp = httpPacket.Split(new string[1] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
                                    string context = "search";
                                    if (headersHttp[0].IndexOf(context) > -1)
                                    {
                                        Console.WriteLine($"\r\n{iPv4Packet.SourceAddress}:{tcpPacket.SourcePort} -> {iPv4Packet.DestinationAddress}:{tcpPacket.DestinationPort} | HTTP: {context}");
                                    }
                                }
                            }
                            {
                                ksyn += 1;
                                Console.WriteLine($"\r\n{iPv4Packet.SourceAddress}:{tcpPacket.SourcePort} -> {iPv4Packet.DestinationAddress}:{tcpPacket.DestinationPort} | Flag: SYN");
                                // amount is the number of packets that will be recognized as an attack.
                                if (ksyn > amount)
                                {
                                    Console.WriteLine($"{ksyn} packets");
                                    Console.WriteLine("SYN-flood attack detected");
                                    n = 0;
                                    aTimer.Enabled = false;
                                }
                            }
                        }
                    }
                    filter.SendPacket(ref ethRequest);
                }
                waitHandlesManualResetEvents[handle].Reset();
            }
        }

        
        
       public void Status(object source, ElapsedEventArgs e)
        {
            Console.WriteLine($"{ksyn} packets");
            ksyn = 0;
        }



    }
}
