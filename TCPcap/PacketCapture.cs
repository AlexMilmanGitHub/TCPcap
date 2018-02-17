using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TCPcap
{
    public class PacketPayloadStatistics
    {
        public ulong Occurrences { get; set; }

        public DateTime Timestamp { get; }

        public PacketPayloadStatistics()
        {
            Occurrences = 1;

            Timestamp = DateTime.Now;
        }

        public PacketPayloadStatistics(ulong i_occurrences, DateTime i_timestamp)
        {
            Occurrences = i_occurrences;

            Timestamp = i_timestamp;
        }

        public void IncreaseOccurrence()
        {
            Occurrences += 1;
        }
    }

    class PacketCapture
    {
        const int DICTIONARY_SIZE_LIMIT = Int16.MaxValue;
        const ushort BATCH_SIZE = 800;
        private static ulong _totalNumberOfPackets = 0;
        private static Dictionary<byte[], PacketPayloadStatistics> _packetDictionary = new Dictionary<byte[], PacketPayloadStatistics>();
        private static object _dictionaryLock = new object();
        private static string _totalPayload;
        private static int _numOfOccurences = 0;
        public PacketCapture()
        {
            LoadDictionary();

            Thread mainThread = new Thread(new ThreadStart(initPcap));

            Thread calcStatsThread = new Thread(new ThreadStart(CalcStats));

            mainThread.Start();

            calcStatsThread.Start();

        }

        private void LoadDictionary()
        {
            try
            {   // Open the text file using a stream reader.

                if (File.Exists("DictionaryBackup.txt"))
                {
                    using (StreamReader sr = new StreamReader("DictionaryBackup.txt"))
                    {
                        // Read the stream to a string, and write the string to the console.
                        String line = sr.ReadToEnd();

                        List<string> strList = line.Split('[').ToList();

                        foreach(string listEntry in strList)
                        {
                            if(listEntry != String.Empty)
                            {
                                string[] str = listEntry.Split(',');

                                string[] byteArray = str[0].Split(' ');

                                List<byte> byteKeyArray = new List<byte>();
                                foreach (string singleByte in byteArray)
                                {
                                    if(singleByte != String.Empty)
                                    {
                                        byteKeyArray.Add(Convert.ToByte(singleByte));
                                    }
                                }

                                long occurences;

                                bool occurencesSuccess = Int64.TryParse(str[1], out occurences);

                                DateTime timestamp = Convert.ToDateTime(str[2].Replace("]", ""));

                                lock (_dictionaryLock)
                                {
                                    _packetDictionary.Add(byteKeyArray.ToArray(), new PacketPayloadStatistics((ulong)occurences, timestamp));
                                }
                            }
                        }
                    }
                }
                else
                {

                }
            }
            catch (Exception e)
            {
                Console.WriteLine("The file could not be read:");
                Console.WriteLine(e.Message);
            }
        }

        private void initPcap()
        {
            try
            {
                // Retrieve the device list from the local machine
                IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;

                if (allDevices.Count == 0)
                {
                    Console.WriteLine("No interfaces found! Make sure WinPcap is installed.");
                    return;
                }

                // Print the list
                for (int i = 0; i != allDevices.Count; ++i)
                {
                    LivePacketDevice device = allDevices[i];
                    Console.Write((i + 1) + ". " + device.Name);
                    if (device.Description != null)
                        Console.WriteLine(" (" + device.Description + ")");
                    else
                        Console.WriteLine(" (No description available)");
                }

                //int deviceIndex = 0;
                //do
                //{
                //    Console.WriteLine("Enter the interface number (1-" + allDevices.Count + "):");
                //    string deviceIndexString = Console.ReadLine();
                //    if (!int.TryParse(deviceIndexString, out deviceIndex) ||
                //        deviceIndex < 1 || deviceIndex > allDevices.Count)
                //    {
                //        deviceIndex = 0;
                //    }
                //} while (deviceIndex == 0);

                // Take the selected adapter
                PacketDevice selectedDevice = allDevices[2];

                // Open the device
                using (PacketCommunicator communicator =
                    selectedDevice.Open(65536,                                  // portion of the packet to capture
                                                                                // 65536 guarantees that the whole packet will be captured on all the link layers
                                        PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                        1000))                                  // read timeout
                {
                    // Check the link layer. We support only Ethernet for simplicity.
                    if (communicator.DataLink.Kind != DataLinkKind.Ethernet)
                    {
                        Console.WriteLine("This program works only on Ethernet networks.");
                        return;
                    }

                    // Compile the filter
                    using (BerkeleyPacketFilter filter = communicator.CreateFilter("ip and udp"))
                    {
                        // Set the filter
                        communicator.SetFilter(filter);
                    }

                    // Compile the filter
                    using (BerkeleyPacketFilter filter = communicator.CreateFilter("ip and tcp"))
                    {
                        // Set the filter
                        communicator.SetFilter(filter);
                    }

                    Console.WriteLine("Listening on " + selectedDevice.Description + "...");

                    // start the capture
                    communicator.ReceivePackets(0, PacketHandler);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }

        // Callback function invoked by libpcap for every incoming packet
        private static void PacketHandler(Packet packet)
        {
            // print timestamp and length of the packet
            Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length);

            _totalNumberOfPackets++;

            if (packet.Ethernet.Payload.Length > BATCH_SIZE)
            {
                if (packet.Ethernet.IpV4.IsValid == true)
                {
                    if(packet.Ethernet.IpV4.Tcp.IsValid == true)
                    {
                        handlePayload(packet.Ethernet.IpV4.Tcp.Payload.ToArray());
                    }
                    else if(packet.Ethernet.IpV4.Udp.IsValid == true)
                    {
                        handlePayload(packet.Ethernet.IpV4.Udp.Payload.ToArray());
                    }
                }
                else if(packet.Ethernet.IpV6.IsValid == true)
                {
                    if (packet.Ethernet.IpV6.Tcp.IsValid == true)
                    {
                        handlePayload(packet.Ethernet.IpV6.Tcp.Payload.ToArray());
                    }
                    else if (packet.Ethernet.IpV6.Udp.IsValid == true)
                    {
                        handlePayload(packet.Ethernet.IpV6.Udp.Payload.ToArray());
                    }
                }
            }

            IpV4Datagram ip = packet.Ethernet.IpV4;
            UdpDatagram udp = ip.Udp;

            // print ip addresses and udp ports
            Console.WriteLine(ip.Source + ":" + udp.SourcePort + " -> " + ip.Destination + ":" + udp.DestinationPort);
        }

        private static void handlePayload(byte [] payload)
        {
            int counter = 0;

            byte[] tempArr = new byte[BATCH_SIZE];

            string bArrAsStr = BitConverter.ToString(payload);

            _totalPayload += " ";

            _totalPayload += bArrAsStr;

            string str = PatternRecognition.LongestRepeatedSubstring(_totalPayload, out _numOfOccurences);

            var lenCommon = str.Length;
            var len = _totalPayload.Length;

            string copy = _totalPayload;

            copy.Replace(str, "1234");

            var copyLen = copy.Length;
            //var str = Encoding.UTF8.GetString(payload);

            //var str2 = Encoding.Default.GetString(payload);

            //var str3 = Encoding.ASCII.GetString(payload);

            //var index = str.IndexOf("111111111111111111111111111111");

            //if(index >= 0)
            //{
            //    Console.WriteLine("30 1's!!!");
            //}

            foreach (byte singleByte in payload)
            {
                if(counter >= BATCH_SIZE)
                {
                    counter = 0;

                    handleBatch(tempArr.Take(BATCH_SIZE).ToArray());
                }

                tempArr[counter] = singleByte;

                counter++;
            }
        }

        private static void handleBatch(byte[] payloadBatch)
        {
            lock (_dictionaryLock)
            {
                if (_packetDictionary.ContainsKey(payloadBatch) == true)
                {
                    _packetDictionary[payloadBatch].IncreaseOccurrence();
                }
                else if (_packetDictionary.Count >= DICTIONARY_SIZE_LIMIT)
                {
                    handleDictionaryOversize(payloadBatch);
                    ulong maxOccurrences = _packetDictionary.Values.Max(x => x.Occurrences);
                }
                else // Otherwise just add to the Dictionary
                {
                    _packetDictionary.Add(payloadBatch, new PacketPayloadStatistics());
                }
            }
        }

        private static void handleDictionaryOversize(byte[] payload)
        {
            try
            {
                ulong minOccurrences = _packetDictionary.Values.Min(x=> x.Occurrences);

                DateTime oldest = _packetDictionary.Values.Min(x=> x.Timestamp);

                KeyValuePair<byte[], PacketPayloadStatistics> minEntry = _packetDictionary.Where(pair => pair.Value.Occurrences == minOccurrences && pair.Value.Timestamp == oldest).FirstOrDefault();

                _packetDictionary.Remove(minEntry.Key);

                _packetDictionary.Add(payload, new PacketPayloadStatistics());
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }

        private static void CalcStats()
        {
            while (true)
            {
                using (StreamWriter file = new StreamWriter("DictionaryBackup.txt"))
                {
                    lock (_dictionaryLock)
                    {
                        foreach (var entry in _packetDictionary)
                        {
                            file.Write("[{0},{1},{2}]", ByteArrayToString(entry.Key), entry.Value.Occurrences, entry.Value.Timestamp);
                        }
                    }
                }


                if (_packetDictionary.Count > 0)
                {
                    lock (_dictionaryLock)
                    {
                        ulong max = _packetDictionary.Values.Max(x => x.Occurrences);
                    }
                }
                System.Threading.Thread.Sleep(60000);
            }
        }

        public static string ByteArrayToString(byte [] byteArray)
        {
            string resStr = String.Empty;

            foreach(byte b in byteArray)
            {
                resStr += String.Format(" {0}",b);
            }

            return resStr;
        }
    }
}
