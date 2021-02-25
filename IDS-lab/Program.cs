using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using NdisApiDotNet;
using NdisApiDotNetPacketDotNet.Extensions;
using PacketDotNet;

namespace IDS
{
    public class Program
    {
        [STAThread]
        public static void Main()
        {
            var filter = NdisApi.Open();
            if (!filter.IsValid)
                throw new ApplicationException("Network adapter didn't match");
            Console.WriteLine($"Adapter version: {filter.GetVersion()}");
            // Create connection
            var waitHandlesCollection = new List<ManualResetEvent>();
            // Creating adapter list
            var tcpAdapters = new List<NetworkAdapter>();
            foreach (var networkAdapter in filter.GetNetworkAdapters())
            {
                if (networkAdapter.IsValid)
                {
                    var success = filter.SetAdapterMode(networkAdapter,
                    NdisApiDotNet.Native.NdisApi.MSTCP_FLAGS.MSTCP_FLAG_TUNNEL |
                    NdisApiDotNet.Native.NdisApi.MSTCP_FLAGS.MSTCP_FLAG_LOOPBACK_FILTER |
                    NdisApiDotNet.Native.NdisApi.MSTCP_FLAGS.MSTCP_FLAG_LOOPBACK_BLOCK);
                    var manualResetEvent = new ManualResetEvent(false);
                    success &= filter.SetPacketEvent(networkAdapter, manualResetEvent.SafeWaitHandle);
                    if (success)
                    {
                        Console.WriteLine($"Adapter {networkAdapter.FriendlyName} : is successfully added ");
                        // Adapters to list
                        waitHandlesCollection.Add(manualResetEvent);
                        tcpAdapters.Add(networkAdapter);
                    }
                }
            }
            var waitHandlesManualResetEvents = waitHandlesCollection.Cast<ManualResetEvent>().ToArray();
            var waitHandles = waitHandlesCollection.Cast<WaitHandle>().ToArray();
            // Packet analysis
            Console.Write("Press ENTER to start");
            ConsoleKeyInfo keyInfo = Console.ReadKey();
            if (keyInfo.Key == ConsoleKey.Enter)
            {
                IDS ids = new IDS();
                Console.Write("Choose the mode:");
                Console.WriteLine("\n1. Default mode. Packet limited at 500 per 1 second" +
                                  "\n2. Custom mode.");
                var mode = int.Parse(Console.ReadLine());

                if (mode == 1)
                {

                   ids.seconds = 1000;
                   ids.amount = 500;
                    var t1 = Task.Factory.StartNew(() => ids.SYNFloodDetector(filter, waitHandles, tcpAdapters.ToArray(), waitHandlesManualResetEvents));
                    Task.WaitAll(t1);
                    Console.Read();
                }
                if (mode == 2)
                {
                    Console.WriteLine("Enter the number of milliseconds (period) to analyze");
                    ids.seconds = int.Parse(Console.ReadLine());
                    Console.WriteLine("Enter the limit of packets per period");
                    ids.amount = int.Parse(Console.ReadLine());
                    var t1 = Task.Factory.StartNew(() => ids.SYNFloodDetector(filter, waitHandles, tcpAdapters.ToArray(), waitHandlesManualResetEvents));
                    Task.WaitAll(t1);
                    Console.Read();

                }
            }


        }
    }
}