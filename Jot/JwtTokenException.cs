/*
 * Jot v1.0
 * License: The MIT License (MIT)
 * Code: https://github.com/jdemeuse1204/Jot
 * Email: james.demeuse@gmail.com
 * Copyright (c) 2016 James Demeuse
 */

using System;

namespace Jot
{
    public class JwtTokenException: Exception
    {
        public JwtTokenException(string message) 
            : base(message)
        {
        }
    }
}
