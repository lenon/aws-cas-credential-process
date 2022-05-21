# aws-cas-credential-process

`aws-cas-credential-process` is a [credential process][cred-proc] for AWS CLI.
It can be used to authenticate through any CAS SSO that is configured as [SAML
2.0 identity provider][cas-saml] on AWS.

How the process works:

1. AWS CLI calls the credential process whenever it requires authentication.
2. The credential process requests the identity provider using your stored
   credentials, get the SAML response, and assume role using this response as
   input.
3. Assumed role credentials are passed to AWS CLI and then stored temporarily in
   your system's keyring. They are used again until they expire.
4. When expired, new credentials will be requested through the identity
   provider.

Credentials are stored in your system's keyring (Keychain on macOS, GNOME
Keyring on Linux).

Note (1): this project has been tested with AWS CLI v2. It may work with v1,
though.

Note (2): this project has been tested and works for CAS instances configured
with [`mfa-duo`][mfa-duo] MFA provider.

## Installation

Download the latest version:

```
# macOS (Intel)
curl -fsSL https://github.com/lenon/aws-cas-credential-process/releases/latest/download/aws-cas-credential-process-darwin-amd64.tar.gz | tar zxf -

# macOS (ARM)
curl -fsSL https://github.com/lenon/aws-cas-credential-process/releases/latest/download/aws-cas-credential-process-darwin-arm64.tar.gz | tar zxf -

# Linux
curl -fsSL https://github.com/lenon/aws-cas-credential-process/releases/latest/download/aws-cas-credential-process-linux-amd64.tar.gz | tar zxf -
```

See the complete list of precompiled binaries [here][releases].

Then move it anywhere in your PATH:

```
mv dist/aws-cas-credential-process* /usr/local/bin/aws-cas-credential-process
```

## Usage

Configure your credentials:

```
aws-cas-credential-process store
```

And then configure AWS CLI (`~/.aws/config`) with your org's identity provider
and roles:

```
[profile sso]
credential_process = aws-cas-credential-process login --url 'https://<SSO URL>/cas/idp/profile/SAML2/Unsolicited/SSO?providerId=urn:amazon:webservices' --role-arn 'arn:aws:iam::<AWS ACCOUNT>:role/<ROLE NAME>'

[profile myacc1]
source_profile = sso
role_arn = arn:aws:iam::<AWS ACCOUNT>:role/<ROLE NAME>

[profile myacc2]
source_profile = sso
role_arn = arn:aws:iam::<AWS ACCOUNT>:role/<ROLE NAME>
```

To test if the authentication works, run the following command:

```
aws sts get-caller-identity --profile myacc1
```

You may need to approve your MFA login now.

[mfa-duo]:https://apereo.github.io/cas/5.0.x/installation/Configuring-Multifactor-Authentication.html#duo-security
[releases]:https://github.com/lenon/aws-cas-credential-process/releases
[cred-proc]:https://awscli.amazonaws.com/v2/documentation/api/latest/topic/config-vars.html#sourcing-credentials-from-external-processes
[cas-saml]:https://apereo.github.io/cas/6.4.x/authentication/Configuring-SAML2-Authentication.html
