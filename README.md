# ASN1 Compiler Test
An example of using `asn1c`.

## Usage

This will create an executable called createkeypair that accepts a public key, private key, and keypair file in that order.

```
mkdir build
cd build
cmake ..
make
./createkeypair [publickey.bin] [privatekey.bin] [keypair.bin]
```
