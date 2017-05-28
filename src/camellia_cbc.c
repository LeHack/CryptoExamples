/*
 * This is a very simple implementation of a file encoder/decoder using
 * Camellia in CBC mode with PKCS#7 padding
 *
 * Syntax:
 *  ./camellia_cbc [encrypt|decrypt] [keylength] [input.file] [output.file]
 * Example:
 *  ./camellia_cbc encrypt 256 myfile.doc myfile.doc.enc
 *  ./camellia_cbc decrypt 256 myfile.doc.enc myfile.doc
 *
 * !!! WARNING !!!
 * This is a proof of concept. DO NOT use it to encode anything you actually want to protect.
 * While it could work, I'd strongly advice to use tools more suitable/safer like GPG.
 */

#include <openssl/camellia.h>
#include <openssl/conf.h>
#include <openssl/err.h>

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>

#define BS 16 // Camellia uses a 128b / 16B blocksize
#define SECRET "klucz"

CAMELLIA_KEY key;
unsigned char iv[] = "abcdefgh"; // should be derived from passphrase instead of just being hardcoded

int print_errors(const char *msg) {
    unsigned long err;
    int errFound = 0;

    while ((err = ERR_get_error())) {
        errFound++;
        printf("%s: %s\n", msg, ERR_error_string(err, NULL));
    }

    return errFound;
}

int decrypt(int keylen, int infd, int outfd) {
    unsigned char inbuff[BS], outbuf[BS];
    int n = 0, outbufready = 0, prev_n = 0, padding = 0;

    while (1) {
        if (n) {
            bzero(outbuf, BS);
            Camellia_cbc_encrypt(inbuff, outbuf, BS, &key, iv, 0);
            if (print_errors("Problem while decrypting data block"))
                return 1;
            outbufready = 1;
        }

        bzero(inbuff, BS);
        if ((n = read(infd, inbuff, BS)) == -1) {
            perror("read error");
            break;
        }

        if (!outbufready)
            continue;

        if (n && write(outfd, outbuf, BS) == -1)
            perror("write error");
        else if (!n) {
            padding = outbuf[BS - 1];
            if (BS - padding > 0 && write(outfd, outbuf, BS - padding) == -1)
                perror("write error");
            break;
        }

        prev_n = n;
    }

    return 1;
}

int encrypt(int keylen, int infd, int outfd) {
    unsigned char inbuf[BS], outbuf[BS];
    int n = 0, i = 0;

    while (1) {
        bzero(inbuf, BS);
        if ((n = read(infd, inbuf, BS)) == -1) {
            perror("read error");
            break;
        }
        // add padding, if required
        for(i = n; i < BS; i++)
            inbuf[i] = BS - n;

        bzero(outbuf, BS);
        Camellia_cbc_encrypt(inbuf, outbuf, BS, &key, iv, 1);
        if (print_errors("Problem while encrypting data block"))
            return 1;

        if (write(outfd, outbuf, BS) == -1)
            perror("write error");

        if (n < BS)
            break; // exit
    }

    return 1;
}

int main (int argc, char *argv[]) {
    int flags1 = 0, flags2 = 0, outfd = 0, infd = 0, mode = 0;

    if (argv[1] != NULL) {
        if (strcmp(argv[1], "encrypt") == 0)
            mode = 1;

        if (strcmp(argv[1], "decrypt") == 0)
            mode = 2;

        // reset mode if one of params is missing
        if (argv[2] == NULL || argv[3] == NULL || argv[4] == NULL)
            mode = 0;
    }

    if (mode == 0) {
        printf("Bad or incomplete parameters\n");
        printf("Syntax: encrypt/decrypt keylength infile outfile\n");
        return 1;
    }

    flags1 = O_RDONLY;
    flags2 = O_RDONLY | O_WRONLY | O_CREAT;

    int keylen = 0;
    sscanf(argv[2], "%d", &keylen);
    if (keylen != 128 && keylen != 192 && keylen != 256) {
        printf("Error: key length must be one of: 128, 192 or 256.\n");
        return 1;
    }

    if ((infd = open(argv[3], flags1, S_IRUSR | S_IWUSR)) == -1)
        perror("open input file error");

    if ((outfd = open(argv[4], flags2, S_IRUSR | S_IWUSR)) == -1)
        perror("open output file error");

    ftruncate(outfd, 0);
    ERR_load_crypto_strings();

    // generate keys
    Camellia_set_key(SECRET, keylen, &key);

    if (mode == 1)
        encrypt(keylen, infd, outfd);
    else
        decrypt(keylen, infd, outfd);

    close(infd);
    fsync(outfd);
    close(outfd);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
