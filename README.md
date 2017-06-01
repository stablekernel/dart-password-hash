# password_hash

[![Build Status](https://travis-ci.org/stablekernel/dart-password-hash.svg?branch=master)](https://travis-ci.org/stablekernel/dart-password-hash)

Implements PBKDF2 algorithm for securely hashing passwords.

Usage:

```
var generator = new PBKDF2();
var salt = Salt.generateAsBase64String();
var hash = generator.generateKey("mytopsecretpassword", salt, 1000, 32);
```


