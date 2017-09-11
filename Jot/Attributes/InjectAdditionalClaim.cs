using System;

namespace Jot.Attributes
{
    [AttributeUsage(AttributeTargets.Parameter, AllowMultiple = false)]
    public class InjectAdditionalClaim : Attribute
    {
        public string Key { get; }

        public bool IsRequired { get; }

        public InjectAdditionalClaim(string claimKey, bool isRequired = false)
        {
            Key = claimKey;
            IsRequired = isRequired;
        }
    }
}
