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
    public class IDS
    {
        int ksyn = 0;
        public void SYNFloodDetector(NdisApi filter, WaitHandle[] waitHandles, IReadOnlyList<NetworkAdapter> networkAdapters, IReadOnlyList<ManualResetEvent> waitHandlesManualResetEvents)
        {
            var ndisApiHelper = new NdisApiHelper();
            var ethRequest = ndisApiHelper.CreateEthRequest();
            System.Timers.Timer aTimer = new System.Timers.Timer(); //Создаем таймер
            aTimer.Elapsed += new ElapsedEventHandler(OnTimedEvent); //добавляем событие под конец таймера
            aTimer.Interval = 1000;//1 sec
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
                            // Протокол HTTP
                            if ((tcpPacket.DestinationPort == 80)
                            || (tcpPacket.SourcePort == 80))
                            {
                                // Считывание данных TCP пакета. Получение HTTP пакета
                                string httpPacket = Encoding.UTF8.GetString(tcpPacket.PayloadData);
                                if ((httpPacket != "") && (httpPacket != "\0"))
                                {
                                    string[] headersHttp = httpPacket.Split(new string[1] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
                                    string context = "search";
                                    // Поиск слова в строке url
                                    if (headersHttp[0].IndexOf(context) > -1)
                                    {
                                        Console.WriteLine($"\r\n{iPv4Packet.SourceAddress}:{tcpPacket.SourcePort} -> {iPv4Packet.DestinationAddress}:{tcpPacket.DestinationPort} | HTTP: {context}");
                                    }
                                }
                            }
                            // Обнаружение флага SYN в TCP пакете
                            //string hostName = Dns.GetHostName();
                            // string myIP = "192.168.31.173";//Dns.GetHostByName(hostName).AddressList[0].ToString();
                            //IPAddress address = IPAddress.Parse(myIP);
                            //Console.WriteLine($"\r\naddress: {address}");
                            //Console.WriteLine($"\r\niPv4Packet: {iPv4Packet.DestinationAddress}");
                            if (tcpPacket.Syn) //&& iPv4Packet.DestinationAddress == address)
                            {
                                ksyn += 1;
                                Console.WriteLine($"\r\n{iPv4Packet.SourceAddress}:{tcpPacket.SourcePort} -> {iPv4Packet.DestinationAddress}:{tcpPacket.DestinationPort} | Флаг: SYN");
                                if (ksyn > 500)
                                {
                                    Console.WriteLine($"{ksyn} пакетов");
                                    Console.WriteLine("ПИЗДЕЦ ХУЙНЯ АЛЕ");
                                    n = 0;
                                    aTimer.Enabled = false;
                                }
                                //if (tcpPacket.Ack == true)
                                //{
                                //    Console.WriteLine($"\r\nAck присутствует");
                                //}
                            }
                        }
                    }
                    //Отправка пакетов дальше
                    filter.SendPacket(ref ethRequest);
                }
                waitHandlesManualResetEvents[handle].Reset();
            }
        }
        public void OnTimedEvent(object source, ElapsedEventArgs e)
        {
            Console.WriteLine($"{ksyn} пакетов");
            ksyn = 0;
            Console.WriteLine("Таймер закончился! Перезапускаем...");
        }
    }
}
//перед началом цикла у нас запускается таймер