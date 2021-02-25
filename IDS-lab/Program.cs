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
    class Program
    {
        [STAThread]
        static void Main()
        {
            var filter = NdisApi.Open();
            if (!filter.IsValid)
                throw new ApplicationException("Network adapter didnt match");
            Console.WriteLine($"Adapter version: {filter.GetVersion()}");
            // Create conncetion
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
                        Console.WriteLine($"Adapter {networkAdapter.FriendlyName} : is succesfully addded ");
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
            IDS ids = new IDS();
            if (keyInfo.Key == ConsoleKey.Enter)
            {
                var t1 = Task.Factory.StartNew(() => ids.SYNFloodDetector(filter, waitHandles, tcpAdapters.ToArray(), waitHandlesManualResetEvents));
                Task.WaitAll(t1);
                Console.Read();

            }
        }


    }
}
