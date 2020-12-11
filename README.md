# DecrtyptADFSTrustToken 
Quick'n'dirty way to decrypt ADFS issued tokens, that are encrypted as whole, won't work with encrypted assertions only.

## Installation
|Unzip and use. | [![Download DecrtyptADFSTrustToken](https://img.shields.io/badge/download-v0.0.1.0.zip-blue?style=for-the-badge)](https://github.com/martin-rublik/DecryptADFSTrustToken/releases/download/v0-alpha/v0.0.1.0.zip)|
| :------------ | :---------------|



## Usage
**-i**, **--infile**         Required. Input file with encrypted ADFS token.

**-o**, **--outfile**        Output file - decrypted token. If not used token will be printed to stdout.

**-k**, **--p12file**        Required. PFX/PKCS12 file to use for decryption.

**-p**, **--p12password**    Required. PKCS12 password.

## Sample Usage
`DecrtyptADFSTrustToken.exe -i dumped-encrypted.xml -o unencrypted-saml.xml -k sp-certificate-and-key.pfx -p Pa$$w0rd`
