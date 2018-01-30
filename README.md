RC4Crypt
========
Encrypts/decrypts using RC4.

Operates on files or stdio.  The key can be read from a file or the command
line.

Installation
------------
```bash
go get github.com/magisterquis/rc4crypt
```

Usage
-----
```
Usage: rc4crypt [options]

Encrypts/decrypts using RC4.  Input and output are normally stdin and stdout,
respectively, unless -in and -out are used.  The key is normally read from the
file given with -key, but a key may be passed on the command line by prefixing
it with "@" (e.g. -key "@badidea").  Putting the key on the command line is
generally a bad idea, as is using RC4.

Please note that RC4 is broken and should be considered more obfuscation than
encryption.

Options:
  -in file
        Read from file instead of stdin
  -key file
        Name of file from which to read key, or key itself prefixed with "@" (default "key.rc4")
  -out file
        Write to file instead of stdout
  -v    Print informative messages
```
