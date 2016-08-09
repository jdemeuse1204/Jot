using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Jot.Console
{
    class Program
    {
        private static class UrlEncode
        {
            #region Url Encoding

            // From https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-08#appendix-C
            public static string Base64UrlEncode(byte[] payload)
            {
                var s = Convert.ToBase64String(payload); // Regular base64 encoder
                s = s.Split('=')[0]; // Remove any trailing '='s
                s = s.Replace('+', '-'); // 62nd char of encoding
                s = s.Replace('/', '_'); // 63rd char of encoding
                return s;
            }

            public static byte[] Base64UrlDecode(string payload)
            {
                var s = payload;
                s = s.Replace('-', '+'); // 62nd char of encoding
                s = s.Replace('_', '/'); // 63rd char of encoding
                switch (s.Length % 4) // Pad with trailing '='s
                {
                    case 0:
                        break; // No pad chars in this case
                    case 2:
                        s += "==";
                        break; // Two pad chars
                    case 3:
                        s += "=";
                        break; // One pad char
                    default:
                        throw new System.Exception("Illegal base64url string!");
                }

                return Convert.FromBase64String(s); // Standard base64 decoder
            }

            #endregion
        }

        static void Main(string[] args)
        {
            
            using (var sha = new HMACSHA256(Encoding.UTF8.GetBytes("TEST")))
            {
                var result = UrlEncode.Base64UrlEncode(sha.ComputeHash(Encoding.UTF8.GetBytes("WIN")));
            }

            using (var sha2 = new HMACSHA256(Encoding.UTF8.GetBytes("TEST")))
            {
                var result2 = UrlEncode.Base64UrlEncode(sha2.ComputeHash(Encoding.UTF8.GetBytes("WIN")));
            }

            var provider = new JwtTokenProvider();

            var token = provider.Create();

            var encoded = provider.Encode(token);

            var decoded = provider.Decode(encoded);

            if (provider.Validate(encoded) == TokenValidationResult.Passed)
            {

            }

            // Setup

            // Creating a Token

                // Setting claims


            // Encoding a Token

            // Decoding a Token

            // Checking token Validity


            // 
        }
    }
}
