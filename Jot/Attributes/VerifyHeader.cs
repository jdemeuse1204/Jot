using System;

namespace Jot.Attributes
{
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    public class VerifyHeader : Attribute, IVerifiable
    {
        public string Key { get; }

        public VerifyHeader(string claimKey)
        {
            Key = claimKey;
        }
    }
}
