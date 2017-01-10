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
    public class JotException: Exception
    {
        public JotException(string message) 
            : base(message)
        {
        }
    }
}
