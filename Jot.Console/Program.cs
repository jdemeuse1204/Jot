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
            var jot = new JotProvider();

            var token = jot.Create();

            var x = jot.Encode(token);
        }
    }
}
