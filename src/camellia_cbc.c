/*
 * This is a very simple implementation of a file encoder/decoder using
 * Camellia in CBC mode with PKCS#7 padding
 *
 * Syntax:
 *  ./camellia_cbc [encrypt|decrypt] [input.file] [output.file]
 * Example:
 *  ./camellia_cbc encrypt myfile.doc myfile.doc.enc
 *  ./camellia_cbc decrypt myfile.doc.enc myfile.doc
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

#define IP_SIZE 16
#define OP_SIZE 16
#define SECRET "klucz"

CAMELLIA_KEY key;
unsigned char iv[8];

int generate_key() {
    int fd;
    if ((fd = open("/dev/random", O_RDONLY)) == -1)
        perror("open error");

    if ((read(fd, iv, 8)) == -1)
        perror("read iv error");

    close(fd);
    return 0;
}

int decrypt(int infd, int outfd) {
    unsigned char inbuff[OP_SIZE], outbuf[IP_SIZE];
    int n = 0, bufready = 0, prev_n = 0, olen = 0;

    while (1) {
        if (n > 0) {
            bzero(&outbuf, IP_SIZE);
            Camellia_cbc_encrypt(inbuff, outbuf, 16, &key, iv, 0);
            bufready = 1;
        }

        bzero(&inbuff, OP_SIZE);
        if ((n = read(infd, inbuff, OP_SIZE)) == -1) {
            perror("read error");
            break;
        }

        if (bufready && n == 0) {
            olen = IP_SIZE - outbuf[IP_SIZE - 1];
            if (prev_n == OP_SIZE)
                olen = IP_SIZE;
            if ((write(outfd, outbuf, olen)) == -1)
                perror("write error");
            break;
        }
        else if (bufready && n == OP_SIZE) {
            if ((write(outfd, outbuf, n)) == -1)
                perror("write error");
        }

        prev_n = n;
    }

    return 1;
}

int encrypt(int infd, int outfd) {
    unsigned char inbuff[IP_SIZE], outbuf[OP_SIZE];
    int n, i;

    while (1) {
        bzero(&inbuff, IP_SIZE);

        if ((n = read(infd, inbuff, IP_SIZE)) == -1) {
            perror("read error");
            break;
        }
        else if (n == 0)
            break;
        else if (n < IP_SIZE) {
            for(i = n; i < IP_SIZE; i++)
                inbuff[i] = IP_SIZE - n;
        }
        Camellia_cbc_encrypt(inbuff, outbuf, 16, &key, iv, 1);

        if ((n = write(outfd, outbuf, IP_SIZE)) == -1)
            perror("write error");
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
        if (argv[2] == NULL || argv[3] == NULL)
            mode = 0;
    }

    if (mode == 0) {
        printf("Bad or incomplete parameters\n");
        printf("Syntax: encrypt/decrypt infile outfile\n");
        return 1;
    }

    flags1 = flags1 | O_RDONLY;
    flags2 = flags2 | O_RDONLY;
    flags2 = flags2 | O_WRONLY;
    flags2 = flags2 | O_CREAT;

    // wygenerowanie zestawu kluczy
    Camellia_set_key(SECRET, 128, &key);

    ERR_load_crypto_strings();

    if ((infd = open(argv[2], flags1, S_IRUSR | S_IWUSR)) == -1)
        perror("open input file error");

    if ((outfd = open(argv[3], flags2, S_IRUSR | S_IWUSR)) == -1)
        perror("open output file error");

    ftruncate(outfd, 0);
    if (mode == 1)
        encrypt(infd, outfd);
    else
        decrypt(infd, outfd);

    close(infd);
    fsync(outfd);
    close(outfd);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
