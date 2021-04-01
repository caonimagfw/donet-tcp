# TLS Handshake Proxy
## Background 
  - Due to South Korean Governement's announcement which indicates that they will start Internet Censorship (widely known as warning.go.kr in S. Korea) based on TLS SNI inspection, force encrypting TLS handshake flights are now essential for S. Koreans to use the Internet safely - without any interference from gov -. 

## Details
  1. This project inspects all TCP packets and captures TLS Handshake packets which starts with `0x16`.
  2. All handshake packets will be redirected to remote TCP server where user has set up when starting proxy server, with whole data encrypted with AES-256-CBC method.
  3. TCP server
  - decrypts data from client
  - opens a TCP socket to host where user tries to connect
  - send decrypted data to socket and waits for response
  - Encrypts response and delivers encrypted data back to proxy server
  4. Again, proxy server 
  - Decrypts data from TCP server
  - Sends it back to user
  5. All normal packets, such as TLS packets which has been already established private tunnel with server will be sent directly to server without any redirection.
## Languages  
  - .NET Core C#

## Target Operating System
  ### *nix
  - Linux
  - macOS 
  - *BSD (Not tested)
# How-to
  0. WIP
  <!-- 0. Generate AES passpharse
  - Passpharse can be any readable Text file. If you have trouble deciding your own passphrase, run `./keygen > passphrase` to generate a 512-byte long string with hex characters and use it as a passphrase.  
  1. Build
  - This project does not require any make/build processes.
  2. Install Dependencies
  - `yarn install`
  3. Run
  - Proxy Server(On your local machine)
    `./client <Proxy Server IP> <Redirection Server IP> <Redirection Server Port> <AES Key Path>`
  - Redirection Server
    `./server <AES Key Path>` -->
    