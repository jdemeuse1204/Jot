using System;

namespace Jot.Attributes
{
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    public class VerifyClaim : Attribute
    {
        public string ClaimKey { get; }
        public int Order { get; }

        public VerifyClaim(string claimKey, int order = -1)
        {
            ClaimKey = claimKey;
            Order = order;
        }
    }
}
