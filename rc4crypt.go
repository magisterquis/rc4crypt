// tool to encrypt/decrypt a stream with RC4
package main

/*
 * rc4crypt.go
 * Encrypt/decrypt a stream using RC4
 * By J. Stuart McMurray
 * Created 20180128
 * Last Modified 20180128
 */

import (
	"crypto/rc4"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

const (
	// BUFLEN is the size of the read/write buffer */
	BUFLEN = 1024

	// MAXKEYLEN is the maximum allowable key size
	MAXKEYLEN = 256
	// MINKEYLEN is the minimum allowable key size
	MINKEYLEN = 1
)

/* Verbose logger */
var verbose = func(string, ...interface{}) {}

func main() {
	var (
		inN = flag.String(
			"in",
			"",
			"Read from `file` instead of stdin",
		)
		outN = flag.String(
			"out",
			"",
			"Write to `file` instead of stdout",
		)
		keyFile = flag.String(
			"key",
			"key.rc4",
			"Name of `file` from which to read key, or key "+
				"itself prefixed with \"@\"",
		)
		verbOn = flag.Bool(
			"v",
			false,
			"Print informative messages",
		)
	)
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`Usage: %v [options]

Encrypts/decrypts using RC4.  Input and output are normally stdin and stdout,
respectively, unless -in and -out are used.  The key is normally read from the
file given with -key, but a key may be passed on the command line by prefixing
it with "@" (e.g. -key "@badidea").  Putting the key on the command line is
generally a bad idea, as is using RC4.

Please note that RC4 is broken and should be considered more obfuscation than
encryption.

Options:
`,
			os.Args[0],
		)
		flag.PrintDefaults()
	}
	flag.Parse()

	/* Make a verbose logger */
	if *verbOn {
		verbose = log.Printf
	}

	/* Get key */
	k, err := getKey(*keyFile)
	if nil != err {
		fmt.Fprintf(
			os.Stderr,
			"Unable to get key from %q: %v\n",
			*keyFile,
			err,
		)
		os.Exit(2)
	}

	/* Open streams */
	var (
		in  = os.Stdin
		out = os.Stdout
	)
	if "" != *inN {
		if in, err = os.Open(*inN); nil != err {
			fmt.Fprintf(
				os.Stderr,
				"Unable to open input file %q: %v\n",
				*inN,
				err,
			)
			os.Exit(4)
		}
		verbose("Reading input from %v", in.Name())
	}
	if "" != *outN {
		if out, err = os.Create(*outN); nil != err {
			fmt.Fprintf(
				os.Stderr,
				"Unable to open output file %q: %v\n",
				*outN,
				err,
			)
			os.Exit(3)
		}
		verbose("Writing output to %v", out.Name())
	}

	/* Set up RC4 */
	c, err := rc4.NewCipher(k)
	if nil != err {
		fmt.Fprintf(os.Stderr, "Error setting up crypto: %v\n", err)
		os.Exit(5)
	}

	/* Read, crypt, write */
	var (
		b = make([]byte, BUFLEN)
		n int
	)
	for {
		/* Read a chunk */
		n, err = in.Read(b)
		/* If we got anything, crypt and send it out */
		if 0 < n {
			/* Crypt chunk */
			c.XORKeyStream(b[:n], b[:n])
			if _, oerr := out.Write(b[:n]); nil != oerr {
				fmt.Fprintf(os.Stderr, "Write error: %v", err)
				os.Exit(7)
			}
		}
		/* Exit on error */
		if nil != err {
			/* EOF's are ok, though */
			if io.EOF == err {
				break
			}
			fmt.Fprintf(os.Stderr, "Read error: %v", err)
			os.Exit(6)
		}
	}

	verbose("Done.")
}

/* getKey reads the key from the file named fn, or, if fn starts with @,
returns the rest of fn. */
func getKey(fn string) ([]byte, error) {
	var (
		k   []byte
		err error
	)
	/* Keys on the command line are easy */
	if strings.HasPrefix(fn, "@") {
		k = []byte(fn[1:])
		verbose("Got key from command line")
	} else {
		/* Slurp keyfile */
		k, err = ioutil.ReadFile(fn)
		if nil != err {
			return nil, err
		}
		verbose("Read key from %v", fn)
	}
	/* Make sure key is the right side */
	if MAXKEYLEN < len(k) {
		return nil, fmt.Errorf("key too long (>%v bytes)", MAXKEYLEN)
	}
	if MINKEYLEN > len(k) {
		return nil, fmt.Errorf("key too short (<%v byte)", MINKEYLEN)
	}
	return k, err
}
