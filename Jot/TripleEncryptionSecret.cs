/*
 * Jot v1.0
 * License: The MIT License (MIT)
 * Code: https://github.com/jdemeuse1204/Jot
 * Email: james.demeuse@gmail.com
 * Copyright (c) 2016 James Demeuse
 */

namespace Jot
{
    public sealed class TripleEncryptionSecret : SingleEncryptionSecret
    {
        public TripleEncryptionSecret(string secretOne, string secretTwo, string secretThree) : base(secretOne)
        {
            SecretTwo = secretTwo;
            SecretThree = secretThree;
        }

        public string SecretTwo { get; set; }

        public string SecretThree { get; set; }
    }
}
