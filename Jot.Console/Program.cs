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
            var jot = new Jot(30, HashAlgorithm.HS512);

            jot.OnGetGhostClaims += () => new Dictionary<string, object> {{"cid", userId } };

            var token = jot.Create();

            var encoded = jot.Encode(token);

            var decoded = jot.Decode(encoded);

            if (jot.Validate(encoded) == TokenValidationResult.Passed)
            {

            }
        }
    }
}
