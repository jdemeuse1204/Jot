﻿using System;
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
            var jot = new JotProvider(30, HashAlgorithm.HS512);

            var token = jot.Create();

            //token.SetGhostClaim("cid", userId);

            var encoded = jot.Encode(token);

            var decoded = jot.Decode(encoded);

            if (jot.Validate(encoded) == TokenValidationResult.Passed)
            {

            }
        }
    }
}
