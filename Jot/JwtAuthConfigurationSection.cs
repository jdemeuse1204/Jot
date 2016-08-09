/*
 * Jot v1.0
 * License: The MIT License (MIT)
 * Code: https://github.com/jdemeuse1204/Jot
 * Email: james.demeuse@gmail.com
 * Copyright (c) 2016 James Demeuse
 */

using System.Configuration;

namespace Jot
{
    public sealed class JwtAuthConfigurationSection : ConfigurationSection
    {
        public const string SectionName = "Jot";

        private const string _tokenSectionName = "Token";

        private const string _singleEncryptionSectionName = "SingleEncryption";

        private const string _tripleEncryptionSectionName = "TripleEncryption";

        [ConfigurationProperty(_tokenSectionName)]
        public TokenConfigurationElement Token
        {
            get
            {
                return (TokenConfigurationElement)base[_tokenSectionName];
            }
        }

        [ConfigurationProperty(_singleEncryptionSectionName, IsRequired = false)]
        public SingleEncryptionConfigurationElement SingleEncryption
        {
            get
            {
                return (SingleEncryptionConfigurationElement)base[_singleEncryptionSectionName];
            }
        }

        [ConfigurationProperty(_tripleEncryptionSectionName, IsRequired = false)]
        public TripleEncryptionConfigurationElement TripleEncryption
        {
            get
            {
                return (TripleEncryptionConfigurationElement)base[_tripleEncryptionSectionName];
            }
        }
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
    }

    public sealed class SingleEncryptionConfigurationElement : ConfigurationElement
    {

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

        [ConfigurationProperty("encryptHeader", IsRequired = false)]
        public bool? EncryptHeader
        {
            get
            {
                return base["encryptHeader"] as bool?;
            }
        }
    }

    public sealed class TripleEncryptionConfigurationElement : ConfigurationElement
    {

        [ConfigurationProperty("type", IsRequired = true)]
        public string Type
        {
            get
            {
                return base["type"] as string;
            }
        }

        [ConfigurationProperty("secretOne", IsRequired = true)]
        public string SecretOne
        {
            get
            {
                return base["secretOne"] as string;
            }
        }

        [ConfigurationProperty("secretTwo", IsRequired = true)]
        public string SecretTwo
        {
            get
            {
                return base["secretTwo"] as string;
            }
        }

        [ConfigurationProperty("secretThree", IsRequired = true)]
        public string SecretThree
        {
            get
            {
                return base["secretThree"] as string;
            }
        }

        [ConfigurationProperty("encryptHeader", IsRequired = false)]
        public bool? EncryptHeader
        {
            get
            {
                return base["encryptHeader"] as bool?;
            }
        }
    }
}
