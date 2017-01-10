/*
 * Jot v1.0
 * License: The MIT License (MIT)
 * Code: https://github.com/jdemeuse1204/Jot
 * Email: james.demeuse@gmail.com
 * Copyright (c) 2016 James Demeuse
 */

using System.Collections.Generic;

namespace Jot
{
    public class JotValidationContainer
    {
        public JotValidationContainer()
        {
            _customChecks = new Dictionary<string, object>();
            _skipClaimVerifications = new List<string>();
        }

        private readonly Dictionary<string, object> _customChecks;

        private readonly List<string> _skipClaimVerifications;

        public bool AnyCustomChecks()
        {
            return _customChecks != null && _customChecks.Count > 0;
        }

        public bool AnySkipClaimVerificaitons()
        {
            return _skipClaimVerifications != null && _skipClaimVerifications.Count > 0;
        }

        public void SkipClaimVerification(string claimKey)
        {
            _skipClaimVerifications.Add(claimKey);
        }

        public void AddCustomClaimVerification(string claimKey, object expectedValue)
        {
            _customChecks.Add(claimKey, expectedValue);
        }

        public Dictionary<string, object> GetCustomClaimVerifications()
        {
            return _customChecks;
        }

        public IEnumerable<string> GetSkipClaimVerificaitons()
        {
            return _skipClaimVerifications;
        }
    }
}
