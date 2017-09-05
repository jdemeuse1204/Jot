/*
 * Jot v1.1
 * License: The MIT License (MIT)
 * Code: https://github.com/jdemeuse1204/Jot
 * Email: james.demeuse@gmail.com
 * Copyright (c) 2016 James Demeuse
 */

using Jot.Time;
using System;

namespace Jot.ValidationContainers
{
    public class JotDefaultValidationContainer : ValidationContainerBase, IValidationContainer
    {
        public Func<IJotToken, bool> OnTokenValidate { get; set; }

        public JotDefaultValidationContainer() : base(new UnixTimeProvider())
        {
        }

        public void Build()
        {
            AddDefaultNbfVerification(false);

            AddDefaultIatVerification(false);

            AddDefaultExpVerification(false);
        }
    }
}
