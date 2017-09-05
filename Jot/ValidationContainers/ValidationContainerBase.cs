/*
 * Jot v1.1
 * License: The MIT License (MIT)
 * Code: https://github.com/jdemeuse1204/Jot
 * Email: james.demeuse@gmail.com
 * Copyright (c) 2016 James Demeuse
 */

using Jot.Time;
using System;
using System.Collections.Generic;

namespace Jot.ValidationContainers
{
    public class ValidationContainerBase
    {
        public ValidationContainerBase(IUnixTimeProvider unixTimeProvider)
        {
            _checks = new Dictionary<string, Func<object, TokenValidationResult>>();
            UnixTimeProvider = unixTimeProvider;
        }

        protected readonly IUnixTimeProvider UnixTimeProvider;
        private readonly Dictionary<string, Func<object, TokenValidationResult>> _optionalChecks;
        private readonly Dictionary<string, Func<object, TokenValidationResult>> _checks;
        protected Func<IJotToken, TokenValidationResult> OnValidate { get; set; }

        public bool AnyChecks()
        {
            return _checks != null && _checks.Count > 0;
        }

        public bool AnyOptionalChecks()
        {
            return _optionalChecks != null && _optionalChecks.Count > 0;
        }

        public void Add(string claimKey, object expectedValue)
        {
            _checks.Add(claimKey, (data) =>
            {
                return data != null && data.Equals(expectedValue) ? TokenValidationResult.Passed : GetTokenResultFromKey(claimKey);
            });
        }

        public void Add(string claimKey, Func<object, TokenValidationResult> function)
        {
            _checks.Add(claimKey, function);
        }

        public void AddOptional(string claimKey, object expectedValue)
        {
            _optionalChecks.Add(claimKey, (data) =>
            {
                return data != null && data.Equals(expectedValue) ? TokenValidationResult.Passed : GetTokenResultFromKey(claimKey);
            });
        }

        public void AddOptional(string claimKey, Func<object, TokenValidationResult> function)
        {
            _optionalChecks.Add(claimKey, function);
        }

        public void AddDefaultNbfVerification(bool isOptional = false)
        {
            Func<object, TokenValidationResult> func = (claimValue) =>
            {
                if (claimValue == null) { return TokenValidationResult.NotBeforeFailed; }

                double parsedValue;

                if (!double.TryParse(claimValue.ToString(), out parsedValue)) { return TokenValidationResult.NotBeforeFailed; }

                return parsedValue <= UnixTimeProvider.GetUnixTimestamp() ? TokenValidationResult.Passed : TokenValidationResult.NotBeforeFailed;
            };

            if (isOptional)
            {
                AddOptional(JotDefaultClaims.NBF, func);
                return;
            }

            Add(JotDefaultClaims.NBF, func);
        }

        public void AddDefaultExpVerification(bool isOptional = false)
        {
            Func<object, TokenValidationResult> func = (claimValue) =>
            {
                if (claimValue == null) { return TokenValidationResult.TokenExpired; }

                double parsedValue;

                if (!double.TryParse(claimValue.ToString(), out parsedValue)) { return TokenValidationResult.TokenExpired; }

                return UnixTimeProvider.GetUnixTimestamp() < parsedValue ? TokenValidationResult.Passed : TokenValidationResult.TokenExpired;
            };

            if (isOptional)
            {
                AddOptional(JotDefaultClaims.EXP, func);
                return;
            }

            Add(JotDefaultClaims.EXP, func);
        }

        public void AddDefaultIatVerification(bool isOptional = false)
        {
            Func<object, TokenValidationResult> func = (claimValue) =>
            {
                if (claimValue == null) { return TokenValidationResult.CreatedTimeCheckFailed; }

                double parsedValue;

                return double.TryParse(claimValue.ToString(), out parsedValue) ? TokenValidationResult.Passed : TokenValidationResult.CreatedTimeCheckFailed;
            };

            if (isOptional)
            {
                AddOptional(JotDefaultClaims.IAT, func);
                return;
            }

            Add(JotDefaultClaims.IAT, func);
        }

        public Dictionary<string, Func<object, TokenValidationResult>> GetClaimVerifications()
        {
            return _checks;
        }

        public Dictionary<string, Func<object, TokenValidationResult>> GetClaimOptionalVerifications()
        {
            return _optionalChecks;
        }

        public Func<IJotToken, TokenValidationResult> GetOnValidate()
        {
            return OnValidate;
        }

        public TokenValidationResult GetTokenResultFromKey(string claimKey)
        {
            switch (claimKey)
            {
                case "iat":
                    return TokenValidationResult.CreatedTimeCheckFailed;
                case "nbf":
                    return TokenValidationResult.NotBeforeFailed;
                case "jti":
                    return TokenValidationResult.JtiValidateFailed;
                case "exp":
                    return TokenValidationResult.TokenExpired;
                default:
                    return TokenValidationResult.CustomCheckFailed;
            }
        }
    }
}
