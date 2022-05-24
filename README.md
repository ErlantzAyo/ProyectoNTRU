# NTRU for Post-Quantum tasks

## Scenario

`Client` connects to `Server` and sends a value. This value is encrypted by using a post-quantum algorithm. Expected outcome: only the private key owner can read the value and this value is resistant against conventional and quantum attacks.

## Detailed scenario

1. Client connects to server
2. Server sends the public key
3. Client generates a secure key, a secure ciphertext, and encrypt the value (see later)
4. Client sends the ciphertext+encripted value
5. Server extracts the real value
 

## Using KEM for encryption

KEM algorithms are designed for TLS (exchange a random secure key), so they are not well fit for encrypting arbitrary data. The normal procedure is to exchange a random key, so only the receiver can retrieve it from the encapsulated data. By using that key, the rest of data exchanged between client and server is encrypted by using symmetric algorithms.

To allow using KEM without session handling, we could encrypt the data in the following manner:

1. Generate the key by using assymetric encryption
2. Encrypt the value with that key by using symmetric encryption
3. Only the receiver cand decipher the real value in two steps: Assymetric decryption(to get the key), then symmetric decryption (to get the value).

## Format of data exchanged (the payload)

`[ciphertext][nonce][encdata][auth_tag]` in binary (non encoded), snce the payload is flushed directly to the socket.
