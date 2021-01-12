# CryptoStuff

Some crypto related things using available python libraries:

hybrid_crypto.py

An example of hybrid cryptography employing both symmetric and asymmetric methods
using the pycryptodome library (https://pycryptodome.readthedocs.io/en/latest/)

A plaintext message from one person (Principal) to another is encrypted using AES
(symmetric cryptography) and the AES symmetric key is encrypted using an RSA public key
(asymmetric cryptography).

Then the RSA encrypted symmetric key, symmetrically encrypted message,
initialisation vector and number of bytes of padding can be sent to the other person.
That person can recieve the data and use their private key to decrypt the symmetric key,
which can then decrypt the sent message back to the original plaintext.

inspect_cert.py

Parses X.509 security certificates using the cryptography library (https://cryptography.io)
Reads in two security certificates - a certificate to inspect and a second certificate,
which may have issued it. Checks if the second issued the first and prints the contents of
the first certificate. If the second certificate issued the first, the VERIFIABLE variable
will be set to true. Otherwise, it will be set to false.
