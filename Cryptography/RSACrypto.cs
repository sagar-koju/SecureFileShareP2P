using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System;
using System.Numerics;


namespace SecureFileShareP2P.Cryptography
{
    public static class RSACrypto
    {
        // Encrypt with public key (n, e)
        public static string Encrypt(string plaintext, BigInteger n, BigInteger e)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(plaintext);
            BigInteger m = new BigInteger(bytes);
            BigInteger c = BigInteger.ModPow(m, e, n);
            return Convert.ToBase64String(c.ToByteArray());
        }

        //Decrypt with private key(n, d)
        public static string Decrypt(string ciphertext, BigInteger n, BigInteger d)
        {
            byte[] bytes = Convert.FromBase64String(ciphertext);
            BigInteger c = new BigInteger(bytes);
            BigInteger m = BigInteger.ModPow(c, d, n);
            return Encoding.UTF8.GetString(m.ToByteArray());
        }

    }
}