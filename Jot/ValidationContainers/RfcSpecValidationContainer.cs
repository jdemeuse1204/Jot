using Jot.Time;
using System;

namespace Jot.ValidationContainers
{
    public class RfcSpecValidationContainer : ValidationContainerBase, IValidationContainer
    {
        public Func<IJotToken, bool> OnTokenValidate { get; set; }

        public RfcSpecValidationContainer() : base(new UnixTimeProvider())
        {
        }

        public void Build()
        {
            AddDefaultNbfVerification(true);

            AddDefaultIatVerification(true);

            AddDefaultExpVerification(true);
        }
    }
}
