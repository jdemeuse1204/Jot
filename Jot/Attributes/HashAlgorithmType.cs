using System;

namespace Jot.Attributes
{
    [AttributeUsage(AttributeTargets.Class, AllowMultiple = false)]
    public class HashAlgorithmType : Attribute
    {
        public HashAlgorithm HashAlgorithm { get; }

        public HashAlgorithmType(HashAlgorithm hashAlgorithm)
        {
            HashAlgorithm = hashAlgorithm;
        }
    }
}
