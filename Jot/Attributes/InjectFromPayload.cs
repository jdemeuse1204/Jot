using System;

namespace Jot.Attributes
{
    [AttributeUsage(AttributeTargets.Parameter, AllowMultiple = false)]
    public class InjectFromPayload : Attribute
    {
        public string PropertyName { get; }

        public InjectFromPayload(string propertyName)
        {
            PropertyName = propertyName;
        }
    }
}
