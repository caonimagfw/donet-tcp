using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace TLS_Handshake_Proxy {
  struct addr_type {
    public long ip;
    public int port;
  }

  struct FormattedAddrType {
    public string ip;
    public int port;
  }

  class InsufficientPrivilegeException : Exception {

  }

  class TLSHandshakeClient {
    private TcpListener tcpListener;
    private String remoteIpAddr;
    private int remotePort;
    private byte[] key;
    bool isRunning = false;

    [DllImport("./liboriginaddr.so")]
    public static extern addr_type get_original_addr(int fd);
    [DllImport("./liboriginaddr.so")]
    public static extern addr_type get_peer_name(int fd);
    public TLSHandshakeClient(int remotePort, String remoteIpAddr, int port, byte[] key) {
      tcpListener = new TcpListener(IPAddress.Any, port);
      this.remotePort = remotePort;
      this.remoteIpAddr = remoteIpAddr;
      this.key = key;
    }
    public void start() {
      tcpListener.Start();
      isRunning = true;

      while(isRunning) { 
        TcpClient tc = tcpListener.AcceptTcpClient();
        AsyncTcpProcess(tc);
        Task.Factory.StartNew(AsyncTcpProcess, tc);
      }
    }

    public void stop() { 
      isRunning = false;
      tcpListener.Stop();
    }

    async void AsyncTcpProcess(object o) {
      TcpClient tc = (TcpClient) o;
      NetworkStream stream = tc.GetStream();
      byte[] outBuf = new byte[1024];
      int numBytesRead = 0;
      string ipAddr;
      int port;
      byte[] buff;

      System.Console.WriteLine("Socket connection established");
      int fd = (int) tc.Client.Handle;
      
      if(RuntimeInformation.IsOSPlatform(OSPlatform.OSX)) {
        addr_type peerAddr = get_peer_name(fd);
        if(peerAddr.port == -1) {
          throw new Exception();
        }
        string ip = TLSHandshakeClient.ParseIP(peerAddr.ip);
        var originalAddr = TLSHandshakeClient.GetOriginalAddrMach(ip, peerAddr.port);
        ipAddr = originalAddr.ip;
        port = originalAddr.port;
      } else if(RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) {
        addr_type originalAddr = get_original_addr(fd);
      
        if(originalAddr.port == -1) {
          throw new Exception();
        }
        ipAddr = TLSHandshakeClient.ParseIP(originalAddr.ip);
        port = originalAddr.port;
      } else {
        System.Console.WriteLine("OS Not supported!");
        return;
      }

      int nBytes = 0;
      using(var ms = new MemoryStream()) {
        while(stream.DataAvailable && (numBytesRead = stream.Read(outBuf, 0, outBuf.Length)) > 0) {
          ms.Write(outBuf, 0, outBuf.Length); 
          nBytes += numBytesRead;
          System.Console.WriteLine(numBytesRead);
        }
        buff = ms.ToArray();
      }
      System.Console.WriteLine(BitConverter.ToString(buff).Replace("-", " "));

      if(nBytes <= 0) return;
      
      if(buff[0] == 0x16) { // TLS Handshake packet
        System.Console.WriteLine("Handshake");
        var rand = new Random();
        byte[] iv = new byte[16];
        rand.NextBytes(iv);
        byte[] encryptedData = SecurityModule.AESDecrypt256(buff, this.key, iv);
        string bodyString = $"{ipAddr}|{port}|{Convert.ToBase64String(encryptedData)}";
        byte[] encryptedInput, decryptedInput;
        encryptedInput = await PostData($"http://{remoteIpAddr}:{remotePort}/tls", bodyString); 

        System.Console.WriteLine($"Received {encryptedInput.Length} bytes");

        decryptedInput = SecurityModule.AESDecrypt256(encryptedInput, key, iv);
        stream.Write(decryptedInput, 0, decryptedInput.Length);
      } else { // IDK just bypass it
        System.Console.WriteLine($"Normal Packet: Initiating connection to {ipAddr}:{port}");
        TcpClient bypass = new TcpClient(ipAddr, port);
        NetworkStream bypassStream = bypass.GetStream();

        System.Console.WriteLine($"Writing {nBytes} bytes to stream");
        bypassStream.Write(buff, 0, nBytes);
        
        while (bypassStream.DataAvailable && (numBytesRead = bypassStream.Read(outBuf, 0, outBuf.Length)) > 0) {
          stream.Write(outBuf, 0, numBytesRead);
          System.Console.WriteLine(bypassStream.DataAvailable);
          
        }
        System.Console.WriteLine("Normal Stream Closed");
      }
      stream.Flush();
      stream.Close();
      tc.Close();
    }

    private static FormattedAddrType GetOriginalAddrMach(string ip, int port) {
      var psi = new ProcessStartInfo {
        FileName = "/bin/bash",
        UseShellExecute = false,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        Arguments = $"-c \"sudo -n /sbin/pfctl -s state\""
      };
      var p = Process.Start(psi);
      if(p == null) {
        return new FormattedAddrType {
          port = -1
        };
      }
      string stdout = p.StandardOutput.ReadToEnd();
      string stderr = p.StandardError.ReadToEnd();
      p.WaitForExit();

      if(stderr.Contains("a password is required") || stdout.Contains("a password is required")) {
        throw new InsufficientPrivilegeException();
      }

      string spec = $"{ip}:{port}";
      foreach (var item in stdout.Split("\n")) {
        if(item.Contains("ESTABLISHED:ESTABLISHED") && item.Contains(spec)) {
          string[] s = item.Split(" ");
          if(s.Length > 4) {
            string[] ss = s[4].Split(":");
            if(ss.Length == 2) {
              return new FormattedAddrType {
                ip = ss[0],
                port = Int32.Parse(ss[1])
              };
            }
          }
        }
      }
      return new FormattedAddrType {
        port = -1
      };
    }
    
    private static string ParseIP(long rawIp) {
      byte[] ipClasses = new byte[4];
      long ipLong = IPAddress.HostToNetworkOrder(rawIp & 0xFFFFFFFF) >> 32;
      foreach(int i in new int[]{ 0, 1, 2, 3 }) {
        ipClasses[i] = (byte)(ipLong >> (3-i)*8);
      }
      
      return String.Join('.', ipClasses);
    }

    static async Task<byte[]> PostData(string url, string body) {
      using(HttpClient client = new HttpClient()) {
        var response = await client.PostAsync(url, new StringContent(body));
        response.EnsureSuccessStatusCode();

        string content = await response.Content.ReadAsStringAsync();
        return Convert.FromBase64String(content);
      }
    }
  }
}