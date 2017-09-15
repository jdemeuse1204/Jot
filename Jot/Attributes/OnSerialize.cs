using System;

namespace Jot.Attributes
{
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    public class OnSerialize : Attribute
    {
    }
}
