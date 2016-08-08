using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Jot.Console
{
    class Program
    {
        static void Main(string[] args)
        {
            var provider = new JwtTokenProvider();

            var token = provider.Create();

            var encoded = provider.Encode(token);

            //var decoded = provider.Decode(encoded);

            if (provider.Validate(encoded) == TokenValidationResult.Passed)
            {

            }
        }
    }
}
