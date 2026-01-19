# https-c
https in c using Lib-Sodium crytographics libarys

note for future:
if a new certificate is ever generate heres how to get the new key.hex
`openssl pkey -in key.pem -outform der | openssl asn1parse -inform der`
this will give you a decoded asn1 overview. take the hex octet string which sould be 34 bytes long and takes the first two bytes off which should be smth like `0x04` `0x20`
if the hex string is longer or shoter than 34 bytes ask chatgpt.

