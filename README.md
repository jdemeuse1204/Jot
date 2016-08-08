# Jot
**Jot** is a .NET library for use with JSON Web Tokens (JWT).  Jot will take care of all your JWT creation, encryption, and verification for you.  **Jot** was made extremely flexible, if you want to use your own encryption algorithm, serialization, or set custom claims it's all there for you. JWT verification done right!

## Current Version
1.0.0

## Getting Started
Jot is very easy to get started, use nuget to add the reference to your project

#Setup
The best way to use **Jot** is to utilize the projects app/web configuration file.  
```xml
<?xml version="1.0" encoding="utf-8" ?>
<configuration>
  <!-- MUST GO BEFORE STARTUP SECTION -->
  <configSections>
    <section name="Jot" type="Jot.JwtAuthConfigurationSection, Jot" />
  </configSections>
  <startup>
    <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.5.2" />
  </startup>

  <Jot>
    <Token timeOut="30"/>
    <SingleEncryption type="256" secret="SomeLongSecret"/>
  </Jot>
</configuration>
```

## Encryption Setup
**Jot** comes with two encryption options, Single or Triple Secret Encryption.
-Single Secret Encryption encrypts the claim with one secret passcode.
-Triple Secret Encryption encrypts the header with one secret, claims with the second secret, and signature with a third secret making the Jwt more secure.

1. Single Secret Encryption Config
```xml
<?xml version="1.0" encoding="utf-8" ?>
<configuration>
  <!-- MUST GO BEFORE STARTUP SECTION -->
  <configSections>
    <section name="Jot" type="Jot.JwtAuthConfigurationSection, Jot" />
  </configSections>
  <startup>
    <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.5.2" />
  </startup>

  <Jot>
    <Token timeOut="30"/>
    <SingleEncryption type="256" secret="SomeLongSecret"/>
  </Jot>
</configuration>
```

2. Triple Secret Encryption Config
```xml
<?xml version="1.0" encoding="utf-8" ?>
<configuration>
  <!-- MUST GO BEFORE STARTUP SECTION -->
  <configSections>
    <section name="Jot" type="Jot.JwtAuthConfigurationSection, Jot" />
  </configSections>
  <startup>
    <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.5.2" />
  </startup>

  <Jot>
    <Token timeOut="30"/>
     <TripleEncryption type="256" secretOne="SecretOneEncryption" secretTwo="SecretTwoEncryption" secretThree="SecretThreeEncryption" />
  </Jot>
</configuration>
```

#Token Creation

## Creating a Token
```C#
public string GetNewToken()
{
  // the constructor values do not need to be used if you are using the app/web config
  // for the example we will pretend we are not the config
  var provider = new JwtTokenProvider(30, JwtEncryption.AesHmac256);
  
  // if you use the config this is not needed either
  var encryptionPackage = new SingleEncryptionSecret("SomeCoolSecret");
  
  // iat, exp, and nbf are always set by default
  // unless you override claims creation
  var token = provider.Create();

  // here is your encoded token.  Use as you please
  return provider.Encode(token, encryptionPackage);
}
```
## Adding New Claims
```C#
public string GetNewToken()
{
  // the constructor values do not need to be used if you are using the app/web config
  // for the example we will pretend we are not the config
  var provider = new JwtTokenProvider(30, JwtEncryption.AesHmac256);
  
  // if you use the config this is not needed either
  var encryptionPackage = new SingleEncryptionSecret("SomeCoolSecret");
  
  // add a new claim by specifying it in the payload
  var payload = new JwtClaimPayload
  {
    {"tst", "SomeValue"}
  };
  
  var token = provider.Create(payload);

  return provider.Encode(token, encryptionPackage);
}
```

## Using the web/app config
When using **Jot** you will be asked to specify secret's for encryption, Jwt timeouts, etc.  The best way for all of these is to use the projects config file.
```xml
<?xml version="1.0" encoding="utf-8" ?>
<configuration>
  <!-- MUST GO BEFORE STARTUP SECTION -->
  <configSections>
    <section name="Jot" type="Jot.JwtAuthConfigurationSection, Jot" />
  </configSections>
  <startup>
    <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.5.2" />
  </startup>

  <Jot>
    <Token timeOut="30"/>
    <SingleEncryption type="256" secret="SomeLongSecret"/>
  </Jot>
</configuration>
```
```C#
public string GetNewToken()
{
  // you will notice we no longer need our constructor options
  // they will now come from the config
  var provider = new JwtTokenProvider();
  
  var token = provider.Create();

  return provider.Encode(token);
}
```

# Token Events

## Default Claims (https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1.4)
- iat => "Issued At"
- exp => "Expiration"
- rol => "Role"
- jti => "Claim Id"
- iss => "Issuer"
- aud => "Audience"
- nbf => "Not Before"
- sub => "Subject"
- usr => "User"


## Authors
**James DeMeuse**

+ [http://twitter.com/John_Papa](http://twitter.com/John_Papa)

## Credits
Thank you to https://stormpath.com/blog/jwt-the-right-way

## Copyright
Copyright © 2016

## License
Jot is under MIT license - http://www.opensource.org/licenses/mit-license.php
