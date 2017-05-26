/*
 * This is a very simple implementation of a file encoder/decoder using
 * RSA cypher with PKCS#7 padding
 *
 * Syntax:
 *  ./rsa [genkey|encrypt|decrypt] [params]
 * Example:
 *  ./rsa genkey 2048 priv.key pub.key
 *  ./rsa encrypt myfile.doc myfile.doc.enc
 *  ./rsa decrypt myfile.doc.enc myfile.doc
 *
 * !!! WARNING !!!
 * This is a proof of concept. DO NOT use it to encode anything you actually want to protect.
 * While it could work, I'd strongly advice to use tools more suitable/safer like GPG.
 */

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define PASSLEN 64


void print_errors(const char *msg) {
    unsigned long err;

    while ((err = ERR_get_error()))
        printf("%s: %s\n", msg, ERR_error_string(err, NULL));

    return;
}

void disable_echo() {
    struct termios term;

    /* Turn echoing off */
    tcgetattr(fileno(stdin), &term);
    term.c_lflag &= ~ECHO;
    tcsetattr(fileno(stdin), TCSAFLUSH, &term);

    return;
}

void enable_echo() {
    struct termios term;

    /* Restore echo. */
    tcgetattr(fileno(stdin), &term);
    term.c_lflag |= ECHO;
    tcsetattr(fileno(stdin), TCSAFLUSH, &term);
}

void get_passwd(char * pass, int passlen) {
    bzero(pass, passlen);

    while (strlen(pass) < 10) {
        printf("Enter private key passphrase: ");
        fflush(stdout);
        disable_echo();
        fgets(pass, passlen, stdin);
        enable_echo();
        printf("\n");
        // cut off last character (<Enter>)
        pass[strlen(pass)-1] = '\0';
        if (strlen(pass) < 10) {
            printf("Error: specified passphrase is too short (%d), it must contain at least 10 characters.\n", (int)strlen(pass));
            bzero(pass, passlen);
        }
    }

    return;
}

void generate_keys(int keylen, FILE * prvkey, FILE * pubkey) {
    unsigned char termbuf[1024], seedbuffer[32];
    char * pass;
    int randfd = 0;

    RSA * keypair = NULL;
    BIO * keybio = NULL;
    BIGNUM * pubexp = NULL; // Public exponent

    // start with asking the user for a passphrase to encrypt the private key with
    // (storing unencrypted private keys is never a good idea, even in a proof-of-concept)
    pass = malloc(PASSLEN * sizeof(char));
    get_passwd(pass, PASSLEN);

    // also make sure to seed the random numbers generator
    printf("Seeding random numbers generator...");
    fflush(stdout);
    if ((randfd = open("/dev/random", O_RDONLY)) == -1)
        perror("/dev/random open error");

    if (read(randfd, seedbuffer, 32) == -1)
        perror("seed read error");

    RAND_seed(seedbuffer, 32);
    close(randfd);

    // prepare RSA struct
    printf("OK\nGenerating RSA (%d bits) keypair...", keylen);
    fflush(stdout);

    keypair = RSA_new();
    if (keypair == NULL)
        print_errors("Problem while preparing RSA structure");

    // and BIGNUM struct
    pubexp = BN_new();
    BN_set_word(pubexp, 17);

    // generate the keys
    if (RSA_generate_key_ex(keypair, keylen, pubexp, NULL) == 0)
        print_errors("Problem while generating RSA keys");
    else
        printf("OK\n");

    // create a new BIO for storing the key data
    keybio = BIO_new(BIO_s_mem());
    // print the data into the BIO
    RSA_print(keybio, keypair, 4);

    // and print it out to the terminal
    bzero(&termbuf, 1024);
    while (BIO_read(keybio, termbuf, 1024) > 0) {
        printf("%s", termbuf);
        bzero(&termbuf, 1024);
    }

    // finally dump both keys into files
    printf("Storing keypair...");
    fflush(stdout);

    if (PEM_write_RSA_PUBKEY(pubkey, keypair) == 0)
        print_errors("Problem while storing RSA public key");

    if (PEM_write_RSAPrivateKey(prvkey, keypair, EVP_camellia_128_cbc(), pass, strlen(pass), NULL, NULL) == 0)
        print_errors("Problem while storing RSA private key");

    printf("OK\n");
    RSA_free(keypair);
    free(pass);

    return;
}

/* TODO */
void decrypt(int infd, int outfd) {
//    unsigned char inbuff[OP_SIZE], outbuf[IP_SIZE];
//    int n = 0, bufready = 0, prev_n = 0, olen = 0;
//
//    while (1) {
//        if (n > 0) {
//            bzero(&outbuf, IP_SIZE);
//            Camellia_cbc_encrypt(inbuff, outbuf, 16, &key, iv, 0);
//            bufready = 1;
//        }
//
//        bzero(&inbuff, OP_SIZE);
//        if ((n = read(infd, inbuff, OP_SIZE)) == -1) {
//            perror("read error");
//            break;
//        }
//
//        if (bufready && n == 0) {
//            olen = IP_SIZE - outbuf[IP_SIZE - 1];
//            if (prev_n == OP_SIZE)
//                olen = IP_SIZE;
//            if ((write(outfd, outbuf, olen)) == -1)
//                perror("write error");
//            break;
//        }
//        else if (bufready && n == OP_SIZE) {
//            if ((write(outfd, outbuf, n)) == -1)
//                perror("write error");
//        }
//
//        prev_n = n;
//    }

    return;
}

/* TODO */
void encrypt(int infd, int outfd) {
//    unsigned char inbuff[IP_SIZE], outbuf[OP_SIZE];
//    int n, i;
//
//    while (1) {
//        bzero(&inbuff, IP_SIZE);
//
//        if ((n = read(infd, inbuff, IP_SIZE)) == -1) {
//            perror("read error");
//            break;
//        }
//        else if (n == 0)
//            break;
//        else if (n < IP_SIZE) {
//            for(i = n; i < IP_SIZE; i++)
//                inbuff[i] = IP_SIZE - n;
//        }
//        Camellia_cbc_encrypt(inbuff, outbuf, 16, &key, iv, 1);
//
//        if ((n = write(outfd, outbuf, IP_SIZE)) == -1)
//            perror("write error");
//    }
//
    return;
}

int validate_params(char *argv[]) {
    int mode = 0;

    if (argv[1] != NULL) {
        if (strcmp(argv[1], "genkey") == 0)
            mode = 1;

        if (strcmp(argv[1], "encrypt") == 0)
            mode = 2;

        if (strcmp(argv[1], "decrypt") == 0)
            mode = 3;

        // reset mode if any of the params is missing
        if (argv[2] == NULL || argv[3] == NULL || (mode == 1 && argv[4] == NULL))
            mode = 0;
    }

    if (mode == 0) {
        printf("Bad or incomplete parameters\n");
        printf("Syntax:\n");
        printf("\tgenkey keylength priv.key pub.key\n");
        printf("\t[encrypt|decrypt] infile outfile\n");
    }

    return mode;
}

int main (int argc, char *argv[]) {
    int rflags = 0, wflags = 0,
        prvkeyfd = 0, pubkeyfd = 0, infd = 0, outfd = 0;
    FILE *prvkey = NULL, *pubkey = NULL;

    int mode = validate_params(argv);
    if (mode == 0) {
        return 1;
    }

    rflags = O_RDONLY;
    wflags = O_RDONLY | O_WRONLY | O_CREAT;
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // generating a keypair
    if (mode == 1) {
        if ((prvkeyfd = open(argv[3], wflags, S_IRUSR | S_IWUSR)) == -1)
            perror("cannot open file to write the private key");
        if ((pubkeyfd = open(argv[4], wflags, S_IRUSR | S_IWUSR)) == -1)
            perror("cannot open file to write the public key");

        int keylen = 0;
        sscanf(argv[2], "%d", &keylen);
        if (keylen < 1024) {
            printf("Error: minimum key length is 1024.\n");
            return 1;
        }

        // turn file descriptors into streams, since that's what generate_keys expects
        prvkey = fdopen(prvkeyfd, "wb");
        pubkey = fdopen(pubkeyfd, "wb");
        generate_keys(keylen, prvkey, pubkey);

        fflush(prvkey); fsync(prvkeyfd); close(prvkeyfd);
        fflush(pubkey); fsync(pubkeyfd); close(pubkeyfd);
    }
    // encryption/descryption
    else {
        if ((infd = open(argv[2], rflags, S_IRUSR | S_IWUSR)) == -1)
            perror("open input file error");

        if ((outfd = open(argv[3], wflags, S_IRUSR | S_IWUSR)) == -1)
            perror("open output file error");

        ftruncate(outfd, 0);
        if (mode == 1)
            encrypt(infd, outfd);
        else
            decrypt(infd, outfd);

        close(infd);
        fsync(outfd); close(outfd);
    }

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
