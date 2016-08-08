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
    public sealed class JwtClaimPayload : IEnumerable<KeyValuePair<string, object>>
    {
        public JwtClaimPayload()
        {
            _claims = new Dictionary<string, object>();
        }

        private readonly Dictionary<string, object> _claims;

        public void Add(string key, object value)
        {
            _claims.Add(key, value);
        }

        public object Get(string key)
        {
            return _claims[key];
        }

        public IEnumerator<KeyValuePair<string, object>> GetEnumerator()
        {
            foreach (var claim in _claims) yield return claim;
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }
}
