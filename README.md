# openssl_examples
# David Cluytes
# Email: david.cluytens@gmail.com

Example test code for extracting a quic 5.0 header
AES_128_GCM decrypt and HKDF / TLS13 expand - extract code

build: 
gcc hkfd_extract_expand_tls13.c quic_ssl_utils.c -lssl -lcrypto -I/usr/local/include -L/usr/local/lib

