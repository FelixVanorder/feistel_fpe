# feistel_fpe
Feistel Cipher with Format-Preserving Encryption (for small natural number domains).

## Dependencies

* OpenSSL
* https://github.com/Microsoft/GSL

## Build

Copy [GSL](https://github.com/Microsoft/GSL) into your source directory into directory "microsoft/". 

### With GCC >= 5.0.1

g++ -std=c++14 -I./ ./vdr/mac/tests/test_vrd_mac_hmac_sha256.cpp -lcrypto -lssl -o test-hmac-sha256
g++ -std=c++14 -I./ ./vdr/hash/tests/test_vrd_hash_sha2.cpp -lcrypto -lssl -o test-sha256
g++ -std=c++14 -I./ ./vdr/cipher/tests/test_vrd_cipher_aes.cpp -lcrypto -lssl -o test-aes
g++ -std=c++14 -I./ ./vdr/cipher/tests/test_vrd_cipher_fpe_feistel.cpp -lcrypto -lssl -o test-fpe-feistel

