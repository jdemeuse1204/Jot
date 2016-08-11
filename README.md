# Jot
**Jot** is a .NET library for use with JSON Web Tokens (JWT).  Jot will take care of all your JWT creation, encryption(hashing), and verification for you.  **Jot** was made extremely flexible, if you want to use your own hash algorithm, serialization, or set custom claims it's all there for you.  What set's **Jot** apart from others is the ability to use **Ghost Claims**.  This feature helps guard against a JWT being decoded by someone you do not want decoding your JWT.  See below for an explanation on **Ghost Claims**.  **Jot** was built on .NET 4.0.

## Current Version
1.0.0

## Getting Started
Jot is very easy to get started, use nuget to add the reference to your project

##Customization
**Jot** is highly customizable, allowing end users to configure just about anything.  Developers can configure everything from how the token is verified, to custom hash algorithms, to validating custom claims.  Out of the box, it will produce a standard JWT according to specifications referenced below.  Here is a list of everything that can be customized:

1.  Validating Claim Id's (Jti)
2.  Ghost Claims
3.  Token Validation
4.  Serialization
5.  Deserialzation
6.  Hashing the signature
7.  Custom Claims
8.  Validating Custom Claims
9.  Token TimeOut
10.  Custom Headers

#Token Creation

1.  Creating a JWT using the app/web config
Please see the config section on how to configure your project to use the config settings.

```C#
public string GetNewToken()
{
  // the constructor values do not need to be used if you are using the app/web config
  // in this example we are using the configuration file found 
  // in the Jot App/Web Configuration section
  var jot = new JotProvider();
  
  // iat, exp, and nbf are always set by default
  // unless you wish to set them to different values
  // see the Adding/Setting claims section
  var token = jot.Create();

  // here is your encoded token.  Use as you please
  return jot.Encode(token);
}
```

2.  Creating a JWT NOT using the app/web config

```C#
public string GetNewToken()
{
  var secret = "SomeCoolSecret!";

  // the constructor values do not need to be used if you are using the app/web config
  // in this example we are using the constructor 
  var jot = new JotProvider(30, HashAlgorithm.HS512);
  
  // iat, exp, and nbf are always set by default
  // unless you wish to set them to different values
  // see the Adding/Setting claims section
  var token = jot.Create();

  // here is your encoded token.  Use as you please
  return jot.Encode(token, secret);
}
```

# Adding/Setting Claims
Here is a list of all the default claims in Jot (https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1.4)
- iat => "Issued At"
- exp => "Expiration"
- rol => "Role"
- jti => "Claim Id"
- iss => "Issuer"
- aud => "Audience"
- nbf => "Not Before"
- sub => "Subject"
- usr => "User"

1. SetClaim method

```C#
public string AddingANewClaim()
{
  // please note, assume this example uses the config
  // for all configuration options
  var jot = new JotProvider();
  
  // iat, exp, and nbf are always set by default
  // unless you wish to set them to different values
  // see the Adding/Setting claims section
  var token = jot.Create();
  
  // there is no "add" claim, if the key does
  // not exist it will be added
  token.SetClaim("claimKey","claimValue");

  // here is your encoded token.  Use as you please
  return jot.Encode(token);
}
```

2. Using OnCreate handler

```C#
public string AddClaimUsingOnCreateHandler()
{
  // please note, assume this example uses the config
  // for all configuration options
  var jot = new JotProvider();
  
  // Override the OnCreate method and return the claims
  // you wish to set.  The idea way to do this is
  // inherit from Jot and set this method
  // on the constructor
  jot.OnCreate += (tkn) =>
  {
    tkn.SetClaim("claimKey", "claimValue");
  };
  
  var token = jot.Create();

  return jot.Encode(token);
}
```

3. Create method parameters

```C#
public string AddClaimUsingCreateMethodParameters()
{
  // please note, assume this example uses the config
  // for all configuration options
  var jot = new JotProvider();
  
  // Create your payload.  If the claim exists, the value will be set,
  // if the claim does not exist the claim will be added and value will be set
  var payload = new Dictionary<string, object>
  {
      {"iat", 0},
      {"exp", 0},
      {"rol", "sdf"},
      {"jti", ""},
      {"iss", ""},
      {"aud", ""},
      {"nbf", ""},
      {"sub", ""},
      {"usr", ""}
  };
  
  var token = jot.Create(payload);

  return jot.Encode(token);
}
```

# Hash Options
Please keep in mind **Jot** uses hashing, not encrypting.  Encryption is reversible, meaning it can be unencrypted.  Hashing is not reversible.
<br/>
<br/>
Built-in Hash Options

+ HS256
+ HS384
+ HS512

1.  OnHash handler
If you do not want to use the built in hash methods, you may use your own.  See below

```C#
public string UsingTheOhHashHandler()
{
  // please note, assume this example uses the config
  // for all configuration options
  var jot = new JotProvider();
  
  // simply add a method to the OnHash handler.  This will be
  // used instead of the default methods
  jot.OnHash += (encrypt, secret) =>
  {
      var key = Encoding.UTF8.GetBytes(secret);

      using (var sha = new HMACSHA384(key))
      {
          return sha.ComputeHash(encrypt);
      }
  };
  
  var token = jot.Create();

  return jot.Encode(token);
}
```

2.  Using the config
Change the **type** in the Encryption node to change encryption.  See defaults above for options

```xml
  <Jot>
    <Token timeOut="30" anonymousAlgorithmInHeader="true"/>
    <Encryption type="HS512" useGhostClaims="false" secret="sjdfhikjsjhdkfjjhsdlkfhsakd"/>
  </Jot>
```

3.  Using the jots constructor

```C#
public string UseTheProviderConstructor()
{
  // Set the hash algorithm you wish to use in the jots constructor
  var jot = new JotProvider(30, HashAlgorithm.HS512);
  
  var token = jot.Create();

  return jot.Encode(token);
}
```

# Hash Secret/Key
There are two different options for the hash key/secret

1.  Use the Encode method parameter

```C#
public string UseSecretInEncodeMethodAsParameter()
{
  var secret = "MySuperSecretSecret";

  var jot = new JotProvider(30, HashAlgorithm.HS512);
  
  var token = jot.Create();

  return jot.Encode(token, secret);
}
```

2.  Use the config

```C#
public string UseSecretInEncodeMethodAsParameter()
{
  var jot = new JotProvider(30, HashAlgorithm.HS512);
  
  var token = jot.Create();

  return jot.Encode(token);
}
```

Config file
**secret** in the encryption node is how you change your secret/key
```xml
  <Jot>
    <Token timeOut="30" anonymousAlgorithmInHeader="true"/>
    <Encryption type="HS512" useGhostClaims="false" secret="sjdfhikjsjhdkfjjhsdlkfhsakd"/>
  </Jot>
```

# Token Verification

TokenValidationResult
-NotBeforeFailed,
-TokenExpired,
-TokenNotCorrectlyFormed,
-SignatureNotValid,
-OnTokenValidateFailed,
-OnJtiValidateFailed,
-CustomCheckFailed,
-CreatedTimeCheckFailed,
-Passed

1.  Default Verificaiton<br/><br/>
Claims Verified By Default:

+ nbf
+ exp
+ iat
+ jti (if OnJtiValidate handler has method)

```C#
public TokenValidationResult DefaultVerification(string encodedTokenFromWebPage)
{
  // lets assume the encodedTokenFromWebPage is the token being passed in
  var jot = new JotProvider();
  
  // please see above for the results from Validate
  return jot.Validate(encodedTokenFromWebPage);
}
```

2.  Using the JotValidationContainer
The JotValidationContainer lets the user customize the tokens verification

```C#
public TokenValidationResult DefaultVerification(string encodedTokenFromWebPage)
{
  // lets assume the encodedTokenFromWebPage is the token being passed in
  var jot = new JotProvider();

  var validationContainer = new JotValidationContainer();
  
  // here we are telling the Not Before (nbf) claim to be skipped
  // By default, the claim will be checked unless you
  // manually skip it
  validationContainer.SkipClaimVerification(JotDefaultClaims.NBF);
  
  // here we are telling the Creation Date (iat) claim to be skipped
  // By default, the claim will be checked unless you
  // manually skip it
  validationContainer.SkipClaimVerification(JotDefaultClaims.IAT);
  
  // here we are adding a custom verificaiton to the Issuer (iss) claim
  // the claim must equal github.com
  validationContainer.AddCustomClaimVerification("iss", "github.com");
  
  // When validate is called, the above validations will be run
  // note, you must pass the validationContainer into the validate function
  return jot.Validate(encodedTokenFromWebPage, validationContainer);
}
```

3.  Validate without the config secret

```C#
public TokenValidationResult DefaultVerification(string encodedTokenFromWebPage)
{
  // lets assume the encodedTokenFromWebPage is the token being passed in
  var jot = new JotProvider();
  
  var secret = "MySuperSecretSecret";

  // if you do not use the config file, you can pass in your secret to the
  // validate method
  return jot.Validate(encodedTokenFromWebPage, secret);
}
```

# Token Serialization
Claims and Headers are serialized as a JSON string before they are Base64Url encoded.  If you do not wish to use the default serialization in **Jot** you may use your own method

```C#
public TokenValidationResult DefaultVerification(string encodedTokenFromWebPage)
{
  // lets assume the encodedTokenFromWebPage is the token being passed in
  var jot = new JotProvider();
  
  // in this example, Newtonsoft's JSON serializer is used to serialize
  jot.OnSerialize += serialize => JsonConvert.SerializeObject(serialize);

  // in this example, Newtonsoft's JSON converter is used to deserialize
  jot.OnDeserialize += jsonString => JsonConvert.DeserializeObject<Dictionary<string, object>>(jsonString);
  
  // when the token is encoded/decoded/validated the above methods will
  // be used for serializing and deserializing the token
}
```

# Ghost Claims
Before explaining **Ghost Claims**, you must understand the parts to a JSON Web Token.  If you understand the parts skip to the next paragraph.  There are three parts to a JWT.  They are header, claims, and signature.  The header and claims are just Base64Url encoded strings, but the signature is a hash of the concatenation of the Base64Url encoded headers plus a period plus Base64Url encoded claims. (  Hash(base64UrlEncode(headers) + "." +
base64UrlEncode(claims),  secret)).  

**Ghost Claims** are added to the claims before they are Base64Url encoded and become part of the signature.  **Ghost Claims** are not part of the normal claims segment, but only exist in the signature.  The server knows what the **Ghost Claims** are, but the Token does not know what they are.  This makes the token a lot harder to decrypt, because only your server knows what they **Ghost Claims** are.  Think of **Ghost Claims** like a second secret/key to your Token.  When the Token is validated, the **Ghost Claims** are factored into the signature, and must match the Token being validated.

Pseudo Code - How it works
```

  claims = Our Claims We Set
  claimPlusGhostClaims = (claims + Ghost Claims)
  headers = Headers We Set
  
  claimsSegment = Base64Url encoded claims
  claimsPlusGhostClaimsSegment = Base64Url encoded claimPlusGhostClaims
  headerSegment = Base64Url encoded headers
  signature = Hash of headers + . + claimsPlusGhostClaimsSegment

  token = headerSegment + . + claimsSegment + . + signature
```

# Web/App config setup

Settings

-Token:
  * timeOut - this is the time out of the token in minutes
  * anonymousAlgorithmInHeader - in the header of a JWT the typ claim exposes the hash method.  If you do not wish to share the hash method, you may make the typ header say "Anonymous."  The has method comes from the Jot on the server, the typ header is not used.  It is set for conventions sake.

-Encryption
  * type - This is the hash type that will be used for the signature.  Options are HS256, HS384, and HS512.
  * useGhostClaims - tells your **Jot** whether or not to use **Ghost Claims**
  * secret - secret/key to hash the signature of a token

1.  App.config

```xml
<?xml version="1.0" encoding="utf-8" ?>
<configuration>
  <!-- MUST GO BEFORE STARTUP SECTION -->
  <configSections>
    <section name="Jot" type="Jot.JotAuthConfigurationSection, Jot" />
  </configSections>
  <startup>
    <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.5.2" />
  </startup>

  <Jot>
    <Token timeOut="30" anonymousAlgorithmInHeader="true"/>
    <Encryption type="HS512" useGhostClaims="false" secret="sjdfhikjsjhdkfjjhsdlkfhsakd"/>
  </Jot>
</configuration>
```

2.  Web.config

```xml
<?xml version="1.0" encoding="utf-8" ?>
<configuration>
  <!-- PUT AT THE TOP OF THE WEB.CONFIG -->
  <configSections>
    <section name="Jot" type="Jot.JotAuthConfigurationSection, Jot" />
  </configSections>

  <!--  other sections  -->
   <!-- Best place to put this is after the appSettings section -->
   <appSettings> ... </appSettings>
  <Jot>
    <Token timeOut="30" anonymousAlgorithmInHeader="true"/>
    <Encryption type="HS512" useGhostClaims="false" secret="sjdfhikjsjhdkfjjhsdlkfhsakd"/>
  </Jot>
</configuration>
```

## Authors
**James DeMeuse**

+ [http://twitter.com/TheMiddleMan124](http://twitter.com/TheMiddleMan124)
+ james.demeuse@gmail.com

## Credits

+ Thank you to https://stormpath.com/blog/jwt-the-right-way
+ Url Encoding https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-08#appendix-C
+ Jwt Claims https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1.4
+ Jwt Formation https://jwt.io/
+ Jwt Ghost Claims Idea http://security.stackexchange.com/questions/64350/compromised-json-web-token-jwt-bearer-token

## Copyright
Copyright © 2016

## License
Jot is under MIT license - http://www.opensource.org/licenses/mit-license.php
