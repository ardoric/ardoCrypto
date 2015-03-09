using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace ardo.Crypto
{
    class CryptoBackend
    {
        private static byte[] fixedSalt = Convert.FromBase64String("rgbah+AZtko0FlU0W6BCaaAuvKKlF2dAFHjrEVZTF+8RKQPOyn/RO9D8LOCLlAOxgoPad0HcQS5IAWYIq5RsMmihILUdWHe3Gr7YZJUNGtzPqZZI+VtmTS4Hvb+LHbahD5dhWey1moFlYmrxpjkisI1OPkS/1EnWaiaUf/9iVEw=");
        private static int iterationCount = 37649;
        static private RNGCryptoServiceProvider rnd = new RNGCryptoServiceProvider();

        public static byte[] hash(String input, String algorithm)
        {
            using (HashAlgorithm hash = HashAlgorithm.Create(algorithm))
            {
                return hash.ComputeHash(Encoding.UTF8.GetBytes(input));
            }
        }

        public static byte[] deriveKey(String password)
        {
            Rfc2898DeriveBytes deriver = new Rfc2898DeriveBytes(password, fixedSalt)
            {
                IterationCount = iterationCount
            };

            return deriver.GetBytes(32);
        }

        private static byte[] getRandomBytes(int count)
        {
            byte[] res = new byte[count];
            rnd.GetBytes(res);
            return res;
        }

        private static Aes getCipher()
        {
            return new AesManaged()
            {
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            };
        }

        public static String encrypt(byte[] keyBytes, String plaintext)
        {
            using (Aes crypto = getCipher())
            {
                crypto.Key = keyBytes;
                crypto.IV = getRandomBytes(crypto.BlockSize / 8);

                byte[] plainBytes = Encoding.UTF8.GetBytes(plaintext);
                MemoryStream ms = new MemoryStream();
                ms.Write(crypto.IV, 0, crypto.IV.Length);
                using (CryptoStream cs = new CryptoStream(ms, crypto.CreateEncryptor(crypto.Key, crypto.IV), CryptoStreamMode.Write))
                    cs.Write(plainBytes, 0, plainBytes.Length);
                ms.Close();
                var cipherBytes = ms.ToArray();

                HMACSHA256 mac = new HMACSHA256();
                mac.Key = keyBytes;

                var macBytes = mac.ComputeHash(cipherBytes);

                MemoryStream resStream = new MemoryStream();
                resStream.Write(cipherBytes, 0, cipherBytes.Length);
                resStream.Write(macBytes, 0, macBytes.Length);
                return Convert.ToBase64String(resStream.ToArray());

            }
        }

        public static String decrypt(byte[] keyBytes, String ciphertext)
        {
            using (Aes crypto = getCipher())
            {
                HMAC mac = new HMACSHA256();
                mac.Key = keyBytes;

                byte[] allBytes = Convert.FromBase64String(ciphertext);

                byte[] iv = new byte[crypto.BlockSize / 8];
                byte[] macBytes = new byte[mac.HashSize / 8];
                byte[] cipherBytes = new byte[allBytes.Length - iv.Length - macBytes.Length];

                using (MemoryStream ms = new MemoryStream(allBytes, /*writable*/false))
                {
                    ms.Read(iv, 0, iv.Length);
                    ms.Read(cipherBytes, 0, cipherBytes.Length);
                    ms.Read(macBytes, 0, macBytes.Length);
                }

                crypto.Key = keyBytes;
                crypto.IV = iv;

                byte[] maccable = new byte[iv.Length + cipherBytes.Length];
                iv.CopyTo(maccable, 0);
                cipherBytes.CopyTo(maccable, iv.Length);

                byte[] mBytes = mac.ComputeHash(new MemoryStream(maccable, /*writable*/false));

                if (!equalBytes(mBytes, macBytes))
                    throw new Exception("Decryption Failed");

                MemoryStream output = new MemoryStream();
                using (CryptoStream cs = new CryptoStream(output, crypto.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(cipherBytes, 0, cipherBytes.Length);
                }
                output.Close();
                return Encoding.UTF8.GetString(output.ToArray());
            }
        }

        public static String det_encrypt(byte[] keyBytes, String plaintext)
        {
            using (Aes crypto = getCipher())
            {
                HMAC mac = new HMACSHA256();
                mac.Key = keyBytes;

                crypto.Key = keyBytes;
                byte[] iv = new byte[crypto.BlockSize / 8];
                byte[] plainBytes = Encoding.UTF8.GetBytes(plaintext);

                byte[] macBytes = mac.ComputeHash(plainBytes);
                for (int i = 0; i < iv.Length; i++)
                {
                    iv[i] = macBytes[i];
                }

                crypto.IV = iv;

                using (MemoryStream ms = new MemoryStream())
                {
                    ms.Write(crypto.IV, 0, crypto.IV.Length);
                    using (CryptoStream cs = new CryptoStream(ms, crypto.CreateEncryptor(crypto.Key, crypto.IV), CryptoStreamMode.Write))
                        cs.Write(plainBytes, 0, plainBytes.Length);

                    return Convert.ToBase64String(ms.ToArray());
                }

            }
        }

        public static String det_decrypt(byte[] keyBytes, String ciphertext)
        {
            using (Aes crypto = getCipher())
            {
                HMAC mac = new HMACSHA256();
                mac.Key = keyBytes;

                byte[] allBytes = Convert.FromBase64String(ciphertext);

                byte[] iv = new byte[crypto.BlockSize / 8];
                byte[] cipherBytes = new byte[allBytes.Length - iv.Length];

                using (MemoryStream ms = new MemoryStream(allBytes, /*writable*/false))
                {
                    ms.Read(iv, 0, iv.Length);
                    ms.Read(cipherBytes, 0, cipherBytes.Length);
                }

                crypto.Key = keyBytes;
                crypto.IV = iv;

                MemoryStream output = new MemoryStream();
                using (CryptoStream cs = new CryptoStream(output, crypto.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(cipherBytes, 0, cipherBytes.Length);
                }
                output.Close();
                byte[] plainBytes = output.ToArray();

                byte[] macBytes = mac.ComputeHash(plainBytes);
                byte[] mBytes = new byte[iv.Length];

                for (int i = 0; i < mBytes.Length; i++)
                    mBytes[i] = macBytes[i];

                if (!equalBytes(mBytes, iv))
                    throw new Exception("Decryption Failed");

                return Encoding.UTF8.GetString(plainBytes);
            }
        }

        public static string doMac(byte[] key, string input)
        {
            HMAC mac = new HMACSHA256();
            mac.Key = key;

            return Convert.ToBase64String(mac.ComputeHash(Encoding.UTF8.GetBytes(input)));
        }


        private static bool equalBytes(byte[] b1, byte[] b2)
        {
            int minLen = (b1.Length > b2.Length) ? b2.Length : b1.Length;
            bool res = b1.Length == b2.Length;
            for (int i = 0; i < minLen; i++)
            {
                res = res && (b1[i] == b2[i]);
            }
            return res;
        }

        public static String hashPassword(String password)
        {
            using (SHA512 sha512 = new SHA512Managed())
            {
                MemoryStream ms = new MemoryStream();
                byte[] salt = getRandomBytes(24);
                byte[] data = Encoding.UTF8.GetBytes(password);
                ms.Write(salt, 0, salt.Length);
                ms.Write(data, 0, data.Length);
                ms.Close();
                return Convert.ToBase64String(salt) + ":" + Convert.ToBase64String(sha512.ComputeHash(ms.ToArray()));
            }
        }

        public static bool comparePassword(String hash, String password)
        {
            String[] split = hash.Split(':');
            byte[] salt = Convert.FromBase64String(split[0]);
            byte[] providedHash = Convert.FromBase64String(split[1]);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            MemoryStream ms = new MemoryStream();
            ms.Write(salt, 0, salt.Length);
            ms.Write(passwordBytes, 0, passwordBytes.Length);
            ms.Close();

            using (SHA512 sha = new SHA512Managed()) {
                return equalBytes(sha.ComputeHash(ms.ToArray()), providedHash);
            }
        }

        // RSA 

        public static string rsa_generateKey(int bits)
        {
            return (new RSACryptoServiceProvider(bits)).ToXmlString(true);
        }

        public static string rsa_getPublicKey(string privateKey)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(privateKey);
            return rsa.ToXmlString(false);
        }

        public static string rsa_encrypt(string publicKey, string plaintext)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(publicKey);
            return Convert.ToBase64String(rsa.Encrypt(Encoding.UTF8.GetBytes(plaintext), true));
        }

        public static string rsa_decrypt(string privateKey, string ciphertext)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(privateKey);
            return Encoding.UTF8.GetString(rsa.Decrypt(Convert.FromBase64String(ciphertext), true));
        }

    }
}
