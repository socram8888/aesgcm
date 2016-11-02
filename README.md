aesgcm
======
Portable, simple and small tool to encrypt and decrypt data using AES-GCM.

Usage
-----
This toolkit contains two different commands:
 - ```aesenc```, whose purpose is to encrypt and sign.
 - ```aesdec```, which decrypts and checks data signature.

Both read from standard input, and write to standard output. A simple example to create an encrypted .tar.xz, prompting the user for a password before starting the encryption, is as follows:

	tar --create folder_to_backup --xz | aesenc >encrypted_backup

To decrypt and then unpack the .tar, this time specifying the password on the command line, you can use:

	aesdec -k thisismykey <encrypted_backup | tar --extract --xz
