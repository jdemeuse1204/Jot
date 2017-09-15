using System;

namespace Jot.Attributes
{
    [AttributeUsage(AttributeTargets.Class, AllowMultiple = false)]
    public class TokenTimeout : Attribute
    {
        public int Timeout { get; }

        public TokenTimeout(int tokenTimeoutInMinuites)
        {
            Timeout = tokenTimeoutInMinuites;
        }
    }
}
