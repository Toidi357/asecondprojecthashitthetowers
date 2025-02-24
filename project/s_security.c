#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int SERVER_STATE = 0;
/*
State Table:
    0: init, awaiting cli hello
    1: sending server hello
    2: keys generated, waiting for finished
    3: good to go
*/

uint8_t S_CLI_HELLO[1024];
size_t S_CLI_HELLO_SIZE;
uint8_t S_SER_HELLO[1024];
size_t S_SER_HELLO_SIZE;
EVP_PKEY *EPHMERAL_PRIV_KEY;

void s_init_sec()
{
    load_certificate("server_cert.bin");

    generate_private_key();
    derive_public_key();
    EPHMERAL_PRIV_KEY = get_private_key();

    init_io();
}

ssize_t s_input_sec(uint8_t *buf, size_t max_length)
{
    if (SERVER_STATE == 0)
        return 0; // no sending until we get a client hello

    if (SERVER_STATE == 1) // send server hello
    {
        // Create Server Hello
        tlv *ser_hello = create_tlv(SERVER_HELLO);

        // do the nonce
        tlv *nn = create_tlv(NONCE);
        uint8_t nonce[NONCE_SIZE];
        generate_nonce(nonce, NONCE_SIZE);
        add_val(nn, nonce, NONCE_SIZE);
        add_tlv(ser_hello, nn);

        // do the certificate
        tlv *cert = deserialize_tlv(certificate, cert_size);
        add_tlv(ser_hello, cert);

        // do the generated public key
        tlv *pub_key = create_tlv(PUBLIC_KEY);
        add_val(pub_key, public_key, pub_key_size);
        add_tlv(ser_hello, pub_key);

        // do the signature
        load_private_key("server_key.bin");
        uint8_t signature[72];
        uint8_t signature_data[1024];
        size_t signature_data_size = S_CLI_HELLO_SIZE;
        memcpy(signature_data, S_CLI_HELLO, S_CLI_HELLO_SIZE);

        uint16_t lenn = serialize_tlv(buf, nn);
        memcpy(signature_data + signature_data_size, buf, lenn);
        signature_data_size += lenn;

        memcpy(signature_data + signature_data_size, certificate, cert_size);
        signature_data_size += cert_size;

        lenn = serialize_tlv(buf, pub_key);
        memcpy(signature_data + signature_data_size, buf, lenn);
        signature_data_size += lenn;

        tlv *signature_tlv = create_tlv(HANDSHAKE_SIGNATURE);
        size_t sig_size = sign(signature, signature_data, signature_data_size);
        add_val(signature_tlv, signature, sig_size);
        add_tlv(ser_hello, signature_tlv);
        set_private_key(EPHMERAL_PRIV_KEY);
        // END of signature

        // serialize
        uint16_t len = serialize_tlv(buf, ser_hello);
        memcpy(S_SER_HELLO, buf, len);
        S_SER_HELLO_SIZE = len;
        free_tlv(ser_hello);

        // update State
        SERVER_STATE = 2;
        return len;
    }

    if (SERVER_STATE == 2)
        return 0;

    if (SERVER_STATE == 3)
    {
        size_t bytes_read = input_io(buf, 943);

        if (bytes_read == 0)
            return 0;

        tlv *data = create_tlv(DATA);
        tlv *iv = create_tlv(IV);
        tlv *ciphertext = create_tlv(CIPHERTEXT);
        tlv *mac = create_tlv(MAC);

        // generate an IV
        uint8_t temp[1024];
        generate_nonce(temp, IV_SIZE);
        add_val(iv, temp, IV_SIZE);

        // generate ciphertext tlv
        size_t ciphertext_size = encrypt_data(iv->val, temp, buf, bytes_read);
        add_val(ciphertext, temp, ciphertext_size);

        // generate MAC
        uint8_t _[1024];
        serialize_tlv(_, iv);
        uint16_t lenn = serialize_tlv(_ + 18, ciphertext);
        hmac(temp, _, lenn + 18); // size of IV TLV is always 18 bytes
        add_val(mac, temp, MAC_SIZE);

        // build and send out
        add_tlv(data, iv);
        add_tlv(data, ciphertext);
        add_tlv(data, mac);
        uint16_t len = serialize_tlv(buf, data);
        free_tlv(data);
        return len;
    }
}

void s_output_sec(uint8_t *buf, size_t length)
{
    if (SERVER_STATE == 0) // expect client hello
    {
        // save the entire client hello to use for server hello signature generation
        memcpy(S_CLI_HELLO, buf, length);
        S_CLI_HELLO_SIZE = length;

        // deserialize the packet
        tlv *cli_hello = deserialize_tlv(buf, length);
        if (cli_hello == NULL)
            return;
        tlv *cli_pub_key = get_tlv(cli_hello, PUBLIC_KEY);

        // save the client's ephermeral public key
        load_peer_public_key(cli_pub_key->val, cli_pub_key->length);

        free_tlv(cli_hello);

        // update State
        SERVER_STATE = 1;
        return;
    }

    if (SERVER_STATE == 1)
        return;

    if (SERVER_STATE == 2)
    {
        // perform key exchange
        derive_secret();
        uint8_t salt[1024];
        size_t salt_size = S_CLI_HELLO_SIZE + S_SER_HELLO_SIZE;
        memcpy(salt, S_CLI_HELLO, S_CLI_HELLO_SIZE);
        memcpy(salt + S_CLI_HELLO_SIZE, S_SER_HELLO, S_SER_HELLO_SIZE);
        derive_keys(salt, salt_size);

        // create MAC digest
        uint8_t digest[MAC_SIZE];
        hmac(digest, salt, salt_size);

        // compare digests
        tlv *fin = deserialize_tlv(buf, length);
        tlv *trs = get_tlv(fin, TRANSCRIPT);
        if (strncmp((char *)digest, (char *)(trs->val), MAC_SIZE) != 0)
        {
            fprintf(stderr, "Bad transcript\n");
            exit(4);
        }

        free_tlv(fin);

        // update State
        SERVER_STATE = 3;
        return;
    }

    if (SERVER_STATE == 3)
    {
        tlv *recvd = deserialize_tlv(buf, length);
        if (recvd == NULL)
            return;

        tlv *iv = get_tlv(recvd, IV);
        tlv *ciphertext = get_tlv(recvd, CIPHERTEXT);
        tlv *mac = get_tlv(recvd, MAC);

        uint8_t temp[1024];

        // verify mac
        uint8_t digest[MAC_SIZE];
        serialize_tlv(temp, iv);
        uint16_t lenn = serialize_tlv(temp + 18, ciphertext); // size of IV TLV is always 18 bytes
        hmac(digest, temp, lenn + 18);
        if (strncmp((char *)digest, (char *)(mac->val), MAC_SIZE) != 0)
        {
            fprintf(stderr, "Bad MAC\n");
            exit(5);
        }

        // decrypt text
        size_t bytes_recvd = decrypt_cipher(buf, ciphertext->val, ciphertext->length, iv->val);

        free_tlv(recvd);

        output_io(buf, bytes_recvd);
    }
}
