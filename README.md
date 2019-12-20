aesgcm
======
Portable, simple and small tool to encrypt and decrypt data using a password and AES-256-GCM.

Usage
-----

This tool reads from standard input, and writes to standard output. A simple example to create an encrypted .tar.xz, prompting the user for a password before starting the encryption, is as follows:

```bash
tar --create folder_to_backup --xz | aesgcm >encrypted_backup
```

To decrypt and then unpack the .tar, this time specifying the password on the command line, you can use:

```bash
aesgcm -d -k thisismykey <encrypted_backup | tar --extract --xz
```

For more information see the manpage.
