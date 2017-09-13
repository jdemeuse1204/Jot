using System;

namespace Jot.Attributes
{
    [AttributeUsage(AttributeTargets.Parameter, AllowMultiple = false)]
    public class InjectAdditionalClaim : Attribute
    {
        public string Key { get; }

        public InjectAdditionalClaim(string claimKey)
        {
            Key = claimKey;
        }
    }
}
