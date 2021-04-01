using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TLS_Handshake_Proxy {
  public class TLSHandshakeServer {
    private TcpListener tcpListener;
    private byte[] key;
    bool isRunning = false;

    public TLSHandshakeServer(int port, byte[] key) {
      tcpListener = new TcpListener(IPAddress.Any, port);
      this.key = key;
    }

    public async void start() {
      AsyncEchoServer().Wait();
    }

    public void stop() { 
      isRunning = false;
      tcpListener.Stop();
    }
    
    async Task AsyncEchoServer() {
      tcpListener.Start();
      isRunning = true;
      while(isRunning) { 
        TcpClient tc = await tcpListener.AcceptTcpClientAsync().ConfigureAwait(false);
        AsyncTcpProcess(tc);
        // Task.Factory.StartNew(AsyncTcpProcess, tc);
      }
    }
    async void AsyncTcpProcess(object o) {
      TcpClient tc = (TcpClient) o;
      NetworkStream stream = tc.GetStream();
      byte[] encryptedInput, decryptedOutput, encryptedOutput;
      byte[] data;
      int numBytesRead = 0;
      byte[] outBuf = new byte[1024];

      using(var ms = new MemoryStream()) {
        while (stream.DataAvailable && (numBytesRead = stream.Read(outBuf, 0, outBuf.Length)) > 0) {
          ms.Write(outBuf, 0, numBytesRead);
        }
        encryptedInput = ms.ToArray();
      }
      System.Console.WriteLine(Encoding.UTF8.GetString(encryptedInput));
      string[] split = Encoding.UTF8.GetString(encryptedInput).Split('|');
      if(split.Length < 2) {
        stream.Write(new byte[]{00}, 0, 1);
        stream.Close();
        return;
      }
      string ipAddr = split[0];
      int port = Int32.Parse(split[1]);
      data = SecurityModule.AESDecrypt256(Convert.FromBase64String(split[2]), key);

      System.Console.WriteLine(BitConverter.ToString(data).Replace('-', ' '));
      System.Console.WriteLine($"Opening socket to {ipAddr}:{port}");
      TcpClient proxy = new TcpClient();
      proxy.Connect(ipAddr, port);
      System.Console.WriteLine($"Socket opened to {ipAddr}:{port} - status: {proxy.Connected}");
      System.Console.WriteLine($"Sending {data.Length} bytes");
      NetworkStream proxyStream = proxy.GetStream();
      proxyStream.Write(data, 0, data.Length);
      System.Console.WriteLine($"Sent {data.Length} bytes");

      int nBytes = 0;
      using(var ms = new MemoryStream()) {
        try {
          while ((numBytesRead = proxyStream.Read(outBuf, 0, outBuf.Length)) > 0) {
            ms.Write(outBuf, 0, numBytesRead);
            nBytes += numBytesRead;
          }
        } catch(IOException e) {
          System.Console.WriteLine("Stream closed");
        }
        decryptedOutput = ms.ToArray();
      }
      System.Console.WriteLine($"Received {nBytes} bytes from remote");
      System.Console.WriteLine(BitConverter.ToString(decryptedOutput).Replace("-", " "));

      encryptedOutput = SecurityModule.AESEncrypt256(decryptedOutput, key);
      stream.Write(encryptedOutput, 0, encryptedOutput.Length);
      System.Console.WriteLine($"Sent {encryptedOutput.Length} bytes to proxy client");
      stream.Flush();
      stream.Close();
    }
  }
}

