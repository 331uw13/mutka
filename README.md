<h1>
  <img src="https://github.com/331uw13/test/blob/main/logo.png?raw=true" width="50">
  <span style="vertical-align: 10px;">Mutka - E2EE Private group chat library.</span>
</h1>

> [!WARNING]
> This library is not production ready and has not been fully tested yet! Use at your own risk.
--------------------------------------------------------------------

### - Description
```
The goal is to create completely free and open source C library
for fully non-centralized end to end encrypted
group chats with high level of security and privacy.

The name comes from Finnish, literally meaning "curve" or "bend"
```

### - About Cryptography, Security and Privacy
```
Mutka uses AES-256-GCM with X25519 and ML-KEM-1024 hybrid keypair system.
ML-DSA-87 is used for signatures.

ML-KEM-1024 and ML-DSA-87 offer great resistance against
quantum computers which would in the future otherwise be able to break
classic encryption (https://en.wikipedia.org/wiki/Harvest_now,_decrypt_later).


Trust between clients is based on "identity keys"
which are long term ML-DSA-87 keypair stored locally and they are used
for authentication between clients.
Private identity key is encrypted with user chosen passphase.

All server members must share their public identity key manually
with each member they trust in order to communicate.
This adds more protection against maliciously modified servers and MITM attacks.
```

### - About Memory safety
```
Using vanilla C has very known risks about memory safety which could lead into compromised machines.
To mitigate the risks of memory corruptions the project should be compiled using Fil-C
which offer to make C memory safe language.
https://fil-c.org/
```

### - Releases
```
```

### - Compiling from source with Fil-C
```bash
# Clone the repository.
git clone https://github.com/331uw13/mutka.git
cd mutka

# Download Fil-C source code.
wget https://github.com/pizlonator/fil-c/archive/refs/tags/v0.675.tar.gz
tar -xvf v0.675.tar.gz
cd fil-c-0.675
./build_all.sh

# After Fil-C has been compiled succesfully.
# Download OpenSSL 3.6.0.
cd projects
wget https://github.com/openssl/openssl/releases/download/openssl-3.6.0/openssl-3.6.0.tar.gz
tar -xvf openssl-3.6.0.tar.gz
cd openssl-3.6.0

# Set compiler to Fil-C clang
export CC="../../build/bin/clang -fno-sanitize=all -fvisibility=default"

# Configure OpenSSL build script and start build.
./Configure linux-x86_64 no-shared no-afalgeng no-asm -DOPENSSL_NO_VERSIONING
make LDFLAGS="-L../../pizfix/lib/ -lpizlo" -j16

# Copy OpenSSL build output, the source code of OpenSSL 3.6.0 is no longer needed.
mkdir -p ../../../external/openssl
cp libssl.a libcrypto.a ../../../external/openssl
cp -r ./include ../../../external/openssl

# Change directory back to repository root directory.
cd ../../../
rm -r fil-c-0.675/projects/openssl-3.6.0

# If everything completed without errors
# You should now have all dependencies for building the library.
```

### - Documentation
> I will include link, when the documentation is ready. For now you can start by reading **"./libmutka/include/packets.h"**

### - Future planned improvements
```
* Network packet obfuscation.
* TOR and i2P support.
```
