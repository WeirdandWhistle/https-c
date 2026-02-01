# https-c
https in c using Lib-Sodium crytographics libarys

note for future:
if a new certificate is ever generate heres how to get the new key.hex
`openssl pkey -in key.pem -outform der | openssl asn1parse -inform der`
this will give you a decoded asn1 overview. take the hex octet string which sould be 34 bytes long and takes the first two bytes off which should be smth like `0x04` `0x20`
if the hex string is longer or shoter than 34 bytes ask chatgpt.


to gen a new `secp256r1` key you can use the `openssl ecparam -out ec_key.pem -name secp256r1 -genkey` command

to convert from PEM to DER format use the `openssl x509 -inform PEM -in cert.pem -outform DER -out cert.der` command

to generate a certificate use the `openssl req -new -key key.pem -x509 -noenc -days 365 -out cert.pem` command
