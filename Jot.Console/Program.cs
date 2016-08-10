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
        static void Main(string[] args)
        {

            var userId = Guid.NewGuid();
            var provider = new JwtTokenProvider();

            provider.OnGetGhostClaims += () => new Dictionary<string, object> {{"cid", userId } };

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
