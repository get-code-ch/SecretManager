#SecretManager
## Introduction
SecretManager is a tool who help to store securely password and get it from an application 
## Private key
### Format
Private key file must be PKCS#8 format

### Filename and location
File must be located in user .ssh directory and named secretmanager.key
### Private key generation
<pre><code>openssl genpkey -out secretmanager.key -algorithm RSA -pkeyopt rsa_keygen_bits:3072</code></pre>
