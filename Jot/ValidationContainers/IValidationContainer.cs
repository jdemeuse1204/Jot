using System;
using System.Collections.Generic;

namespace Jot.ValidationContainers
{
    public interface IValidationContainer
    {
        void Build();
        bool AnyChecks();
        bool AnyOptionalChecks();
        Dictionary<string, Func<object, TokenValidationResult>> GetClaimVerifications();
        Dictionary<string, Func<object, TokenValidationResult>> GetClaimOptionalVerifications();
        TokenValidationResult GetTokenResultFromKey(string claimKey);
        Func<IJotToken, TokenValidationResult> GetOnValidate();
    }
}
