/*
 * Jot v1.0
 * License: The MIT License (MIT)
 * Code: https://github.com/jdemeuse1204/Jot
 * Email: james.demeuse@gmail.com
 * Copyright (c) 2016 James Demeuse
 */

using System;
using System.Configuration;

namespace Jot
{
    public sealed class JotAuthConfigurationSection : ConfigurationSection
    {
        public const string SectionName = "Jot";

        private const string _tokenSectionName = "Token";

        private const string _encryptionSectionName = "Encryption";

        [ConfigurationProperty(_tokenSectionName)]
        public TokenConfigurationElement Token
        {
            get
            {
                return (TokenConfigurationElement)base[_tokenSectionName];
            }
        }

        [ConfigurationProperty(_encryptionSectionName, IsRequired = false)]
        public EncryptionConfigurationElement Encryption
        {
            get
            {
                return (EncryptionConfigurationElement)base[_encryptionSectionName];
            }
        }

        #region Methods
        public string GetEncryptionSecret()
        {
            return Encryption.Secret;
        }

        public HashAlgorithm GetHashAlgorithm()
        {
            return (HashAlgorithm)Enum.Parse(typeof(HashAlgorithm), Encryption.Type);
        }

        public int GetTimeOut()
        {
            return Convert.ToInt32(Token.TimeOut);
        }

        public bool UseGhostClaims()
        {
            return Encryption.UseGhostClaims.HasValue && Encryption.UseGhostClaims.Value;
        }

        public bool AnonymousAlgorithmInHeader()
        {
            return Token.AnonymousAlgorithmInHeader.HasValue && Token.AnonymousAlgorithmInHeader.Value;
        }

        public void CheckConfigurationIsValid()
        {
            // check token
            if (string.IsNullOrEmpty(Token.TimeOut)) throw new JotException("Config error.  Token TimeOut is blank or missing");

            int value;

            if (!int.TryParse(Token.TimeOut, out value)) throw new JotException("Config error.  Token TimeOut is not an integer");

            // check encryption service

            if (!Encryption.ElementInformation.IsPresent) throw new JotException("Config error.  Encryption missing.");

            if (Encryption.Secret.Length < 12) throw new JotException("Config error.  Secret length must be at least 12 characters");

            if (string.IsNullOrEmpty(Encryption.Type)) throw new JotException("Config error.  Encryption type is not set.");
        }
        #endregion
    }

    public sealed class TokenConfigurationElement : ConfigurationElement
    {

        [ConfigurationProperty("timeOut", IsRequired = true)]
        public string TimeOut
        {
            get
            {
                return base["timeOut"] as string;
            }
        }

        [ConfigurationProperty("anonymousAlgorithmInHeader", IsRequired = false)]
        public bool? AnonymousAlgorithmInHeader
        {
            get
            {
                return base["anonymousAlgorithmInHeader"] as bool?;
            }
        }
    }

    public sealed class EncryptionConfigurationElement : ConfigurationElement
    {
        [ConfigurationProperty("useGhostClaims", IsRequired = false)]
        public bool? UseGhostClaims
        {
            get
            {
                return base["useGhostClaims"] as bool?;
            }
        }

        [ConfigurationProperty("type", IsRequired = true)]
        public string Type
        {
            get
            {
                return base["type"] as string;
            }
        }

        [ConfigurationProperty("secret", IsRequired = true)]
        public string Secret
        {
            get
            {
                return base["secret"] as string;
            }
        }
    }
}
