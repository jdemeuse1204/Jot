/*
 * Jot v1.0
 * License: The MIT License (MIT)
 * Code: https://github.com/jdemeuse1204/Jot
 * Email: james.demeuse@gmail.com
 * Copyright (c) 2016 James Demeuse
 */

using System.Collections;
using System.Collections.Generic;

namespace Jot
{
    public class JwtValidationContainer : IEnumerable<KeyValuePair<string, object>>
    {
        public JwtValidationContainer()
        {
            CheckNfb = true;
            _customChecks = new Dictionary<string, object>();
        }

        public bool CheckNfb { get; set; }

        private readonly Dictionary<string, object> _customChecks;

        public bool Any()
        {
            return _customChecks != null && _customChecks.Count > 0;
        }

        public void AddCustomCheck(string claimKey, object expectedValue)
        {
            _customChecks.Add(claimKey, expectedValue);
        }

        public IEnumerator<KeyValuePair<string, object>> GetEnumerator()
        {
            foreach (var claim in _customChecks) yield return claim;
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }
}
