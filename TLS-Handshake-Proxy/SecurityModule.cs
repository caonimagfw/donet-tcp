using System.IO;
using System.Security.Cryptography;

namespace TLS_Handshake_Proxy {
  class SecurityModule {
    public static byte[] AESEncrypt256(byte[] Input, byte[] key, byte[] iv) {
      RijndaelManaged aes = new RijndaelManaged();
      aes.KeySize = 256;
      aes.BlockSize = 128;
      aes.Mode = CipherMode.CBC;
      aes.Padding = PaddingMode.PKCS7;
      aes.Key = key;
      aes.IV = iv;

      var encrypt = aes.CreateEncryptor(aes.Key, aes.IV);
      byte[] xBuff = null;
      using (var ms = new MemoryStream()) {
        using (var cs = new CryptoStream(ms, encrypt, CryptoStreamMode.Write)) {
          cs.Write(Input, 0, Input.Length);
        }
        xBuff = ms.ToArray();
      }

      return xBuff;
    }


    //AES_256 복호화
    public static byte[] AESDecrypt256(byte[] Input, byte[] key, byte[] iv) {
      RijndaelManaged aes = new RijndaelManaged();
      aes.KeySize = 256;
      aes.BlockSize = 128;
      aes.Mode = CipherMode.CBC;
      aes.Padding = PaddingMode.PKCS7;
      aes.Key = key;
      aes.IV = iv;

      var decrypt = aes.CreateDecryptor();
      byte[] xBuff = null;
      using (var ms = new MemoryStream()) {
        using (var cs = new CryptoStream(ms, decrypt, CryptoStreamMode.Write)) {
          cs.Write(Input, 0, Input.Length);
        }

        xBuff = ms.ToArray();
      }

      return xBuff;
    }
  }
}