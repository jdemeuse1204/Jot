﻿using System;

namespace Jot.Attributes
{
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    public class VerifyClaim : Attribute, IVerifiable
    {
        public string Key { get; }
        
        public VerifyClaim(string claimKey)
        {
            Key = claimKey;
        }
    }
}
