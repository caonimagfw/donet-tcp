using System;
using System.IO;
using System.Text;
using System.Threading;

namespace TLS_Handshake_Proxy { 
  class Program {
    public static void Main(string[] args) {
      if(args.Length < 1 || (args[0] != "client" && args[0] != "keygen")) {
        System.Console.WriteLine("Usage: proxy <server|client|keygen> [options...]");
        return;
      }

      switch(args[0]) {
        case "client": 
          if(args.Length < 4) {
            Console.WriteLine("Usage: proxy client <keyPath> <port> <remoteHost> <remotePort>");
            return;
          }
          break;
      }

      if(args[0] == "keygen") {
        Random r = new Random();
        byte[] randomNums = new byte[16];
        r.NextBytes(randomNums);

        System.Console.WriteLine(BitConverter.ToString(randomNums).Replace("-", String.Empty));
        return;
      }


      var exitEvent = new ManualResetEvent(false);

      Console.CancelKeyPress += (sender, eventArgs) => {
        eventArgs.Cancel = true;
        exitEvent.Set();
      };

      StreamReader reader = new StreamReader(args[1]);
      byte[] key = Encoding.UTF8.GetBytes(reader.ReadToEnd());
      
      var Client = new TLSHandshakeClient(Int16.Parse(args[4]), args[3], Int16.Parse(args[2]), key);
      System.Console.WriteLine("Listening on port " + args[2]);
      Client.start();
    }
  }
}