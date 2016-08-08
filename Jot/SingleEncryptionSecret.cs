/*
 * Jot v1.0
 * License: The MIT License (MIT)
 * Code: https://github.com/jdemeuse1204/Jot
 * Email: james.demeuse@gmail.com
 * Copyright (c) 2016 James Demeuse
 */

namespace Jot
{
    public class SingleEncryptionSecret : IEncryptionSecret
    {
        public SingleEncryptionSecret(string secret)
        {
            Secret = secret;
        }

        public string Secret { get; private set; }
    }
}
