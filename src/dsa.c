/*
 * This is a very simple implementation of a file signing utility
 * DSA cypher with SHA224 checksum
 *
 * Syntax:
 *  ./dsa [genkey|sing|verify] [params]
 * Example:
 *  ./dsa genkey 2048 priv.key pub.key
 *  ./dsa sign priv.key myfile.doc myfile.doc.sig
 *  ./dsa verify pub.key myfile.doc myfile.doc.sig
 *
 * !!! WARNING !!!
 * This is a proof of concept. DO NOT use it to encode anything you actually want to protect.
 * While it could work, I'd strongly advice to use tools more suitable/safer like GPG.
 */

#include <openssl/dsa.h>
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

void get_passwd(char * pass, const int passlen, const int minlimit) {
    bzero(pass, passlen);

    while (strlen(pass) < minlimit) {
        printf("Enter private key passphrase: ");
        fflush(stdout);
        disable_echo();
        fgets(pass, passlen, stdin);
        enable_echo();
        printf("\n");
        // cut off last character (<Enter>)
        pass[strlen(pass)-1] = '\0';
        if (strlen(pass) < minlimit) {
            printf("Error: specified passphrase is too short (%d), it must contain at least %d characters.\n", (int)strlen(pass), minlimit);
            bzero(pass, passlen);
        }
    }

    return;
}

int seed_rand() {
    unsigned char seedbuffer[32];
    int randfd = 0;

    printf("Seeding random numbers generator...");
    fflush(stdout);

    if ((randfd = open("/dev/random", O_RDONLY)) == -1) {
        perror("/dev/random open error");
        return 0;
    }

    if (read(randfd, seedbuffer, 32) == -1) {
        perror("seed read error");
        return 0;
    }

    RAND_seed(seedbuffer, 32);
    close(randfd);

    printf("OK\n");

    return 1;
}

int generate_keys(int keylen, FILE * prvkey, FILE * pubkey) {
    unsigned char termbuf[1024];
    char * pass;
    int result = 1;

    DSA * keypair = NULL;
    BIO * keybio = NULL;
    BIGNUM * pubexp = NULL; // Public exponent

    // make sure to seed the random numbers generator
    if (!seed_rand())
        return 0;

    // start with asking the user for a passphrase to encrypt the private key with
    // (storing unencrypted private keys is never a good idea, even in a proof-of-concept)
    pass = malloc(PASSLEN * sizeof(char));
    get_passwd(pass, PASSLEN, 10);

    // prepare RSA struct
    printf("Generating DSA (%d bits) keypair...", keylen);
    fflush(stdout);

    keypair = DSA_new();
    if (keypair == NULL) {
        print_errors("Problem while preparing DSA structure");
        free(pass);
        return 0;
    }

    // and BIGNUM struct
    pubexp = BN_new();
    BN_set_word(pubexp, 17);

    // generate the keys
    int gen_keys = (
        BN_generate_prime_ex(pubexp, keylen, 0, NULL, NULL, NULL)
        && DSA_generate_parameters_ex(keypair, keylen, NULL, 0, NULL, NULL, NULL)
        && DSA_generate_key(keypair)
    );

    if (!gen_keys) {
        print_errors("Problem while generating DSA keys");
        free(pass);
        DSA_free(keypair);
        return 0;
    }
    else
        printf("OK\n");

    // create a new BIO for storing the key data
    keybio = BIO_new(BIO_s_mem());
    // print the data into the BIO
    DSA_print(keybio, keypair, 4);

    // and print it out to the terminal
    bzero(termbuf, 1024);
    while (BIO_read(keybio, termbuf, 1024) > 0) {
        printf("%s", termbuf);
        bzero(termbuf, 1024);
    }

    // finally dump both keys into files
    printf("Storing keypair...");
    fflush(stdout);

    if (PEM_write_DSA_PUBKEY(pubkey, keypair) == 0) {
        print_errors("Problem while storing DSA public key");
        result = 0;
    }

    if (result && PEM_write_DSAPrivateKey(prvkey, keypair, EVP_camellia_128_cbc(), pass, strlen(pass), NULL, NULL) == 0) {
        print_errors("Problem while storing DSA private key");
        result = 0;
    }

    if (result)
        printf("OK\n");
    else
        printf("ERR\n");

    DSA_free(keypair);
    free(pass);

    return result;
}

int pass_callback(char * buf, int size, int rwflag, void * u) {
    get_passwd(buf, size, 1);
//    buf[0]='a';buf[1]='b';buf[2]='c';buf[3]='d';buf[4]='e';buf[5]='1';buf[6]='2';buf[7]='3';buf[8]='4';buf[9]='5';buf[10]='\0';
    return strlen(buf);
}

DSA * createDSAFromFD(int keyfd, int public) {
    FILE * fp = fdopen(keyfd, "rb");
    if(fp == NULL) {
        printf("Unable to open key stream\n");
        return NULL;
    }

    DSA * dsa = DSA_new();

    if (public)
        dsa = PEM_read_DSA_PUBKEY(fp, &dsa, NULL, NULL);
    else
        dsa = PEM_read_DSAPrivateKey(fp, &dsa, pass_callback, NULL);

    if (dsa == NULL) {
        print_errors("Error while reading key");
    }

    return dsa;
}

int prepare_ssh224_digest(int infd, unsigned char * digest) {
    const int readsize = 1024;
    unsigned char inbuf[readsize];
    int n = 0, result = 1;

    SHA256_CTX * ctx;
    ctx = malloc(sizeof(SHA256_CTX));

    bzero(ctx, sizeof(SHA256_CTX));
    if (SHA224_Init(ctx) == 0) {
        print_errors("Could not init SHA context");
        free(ctx);
        return 0;
    }

    while (1) {
        bzero(inbuf, readsize);
        if ((n = read(infd, inbuf, readsize)) == -1) {
            perror("read error");
            result = 0;
            break;
        }
        // no more data
        if (!n)
            break;

        if (SHA224_Update(ctx, inbuf, n) == 0) {
            print_errors("Error while creating SHA digest during update");
            result = 0;
            break;
        }
    }

    bzero(digest, SHA224_DIGEST_LENGTH * sizeof(char));
    if (result && SHA224_Final(digest, ctx) == 0) {
        print_errors("Error while creating SHA digest during final");
        result = 0;
    }

    free(ctx);

    return result;
}

int verify(DSA * pubkey, int infd, int sigfd) {
    unsigned char * sign, * digest;
    int n = 0, result = 1, verify = 0;

    int siglen = DSA_size(pubkey);
    sign = malloc(siglen);

    bzero(sign, siglen);
    if ((n = read(sigfd, sign, siglen)) == -1) {
        perror("signature read error");
        free(sign);
        return 0;
    }

    digest = malloc(SHA224_DIGEST_LENGTH * sizeof(char));
    result = prepare_ssh224_digest(infd, digest);

    if (result) {
        result = DSA_verify(0, digest, SHA224_DIGEST_LENGTH, sign, n, pubkey);
        if (result < 0)
            print_errors("Error while verifying DSA signature");
        else if (result)
            printf("Signature correct.\n");
        else
            printf("Signature incorrect.\n");
    }

    free(sign);
    free(digest);

    return result;
}

int sign(DSA * prvkey, int infd, int sigfd) {
    int result = 1, siglen = 0;

    unsigned char * digest, * sign;
    digest = malloc(SHA224_DIGEST_LENGTH * sizeof(char));
    sign   = malloc(DSA_size(prvkey));

    result = prepare_ssh224_digest(infd, digest);

    bzero(sign, DSA_size(prvkey));
    if (result && DSA_sign(0, digest, SHA224_DIGEST_LENGTH, sign, &siglen, prvkey) == 0) {
        print_errors("Error while creating SHA digest during final");
        result = 0;
    }

    free(digest);

    if (write(sigfd, sign, siglen) == -1) {
        perror("write error");
        result = 0;
    }

    free(sign);

    return result;
}

int validate_params(int argc, char *argv[]) {
    int mode = 0;

    if (argv[1] != NULL) {
        if (strcmp(argv[1], "genkey") == 0)
            mode = 1;

        if (strcmp(argv[1], "sign") == 0)
            mode = 2;

        if (strcmp(argv[1], "verify") == 0)
            mode = 3;

        // reset mode if any of the params is missing
        if (argc < 5)
            mode = 0;
    }

    if (mode == 0) {
        printf("Bad or incomplete parameters\n");
        printf("Syntax:\n");
        printf("\tgenkey keylength priv.key pub.key\n");
        printf("\tsign priv.key file file.sig\n");
        printf("\tverify pub.key file file.sig\n");
    }

    return mode;
}

int main (int argc, char *argv[]) {
    int rflags = 0, wflags = 0, error = 0,
        prvkeyfd = 0, pubkeyfd = 0, infd = 0, sigfd = 0, keyfd = 0;
    FILE * prvkey = NULL, * pubkey = NULL;
    DSA * key = NULL;

    int mode = validate_params(argc, argv);
    if (mode == 0) {
        return 1;
    }

    rflags = O_RDONLY;
    wflags = O_RDONLY | O_WRONLY | O_CREAT;
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // generating a keypair
    if (mode == 1) {
        int keylen = 0;
        sscanf(argv[2], "%d", &keylen);
        if (keylen < 1024) {
            printf("Error: minimum key length is 1024.\n");
            return 1;
        }

        if ((prvkeyfd = open(argv[3], wflags, S_IRUSR | S_IWUSR)) == -1) {
            perror("cannot open file to write the private key");
            return 1;
        }
        if ((pubkeyfd = open(argv[4], wflags, S_IRUSR | S_IWUSR)) == -1) {
            perror("cannot open file to write the public key");
            return 1;
        }
        // turn file descriptors into streams, since that's what generate_keys expects
        prvkey = fdopen(prvkeyfd, "wb");
        pubkey = fdopen(pubkeyfd, "wb");

        if (!generate_keys(keylen, prvkey, pubkey))
            error = 1;
        else {
            fflush(prvkey); fsync(prvkeyfd);
            fflush(pubkey); fsync(pubkeyfd);
        }

        close(prvkeyfd);
        close(pubkeyfd);
    }
    // encryption/description
    else {
        if ((keyfd = open(argv[2], rflags, S_IRUSR | S_IWUSR)) == -1) {
            perror("open key file error");
            return 1;
        }

        if ((infd = open(argv[3], rflags, S_IRUSR | S_IWUSR)) == -1) {
            perror("open input file error");
            return 1;
        }

        if (mode == 2) {
            if ((sigfd = open(argv[4], wflags, S_IRUSR | S_IWUSR)) == -1) {
                perror("open signature file error");
                error = 1;
            }
            else {
                ftruncate(sigfd, 0);
                key = createDSAFromFD(keyfd, 0);
                if (key == NULL || !sign(key, infd, sigfd))
                    error = 1;
            }
        }
        else {
            if ((sigfd = open(argv[4], rflags, S_IRUSR | S_IWUSR)) == -1) {
                perror("open signature file error");
                error = 1;
            }
            else {
                key = createDSAFromFD(keyfd, 1);
                if (key == NULL || !verify(key, infd, sigfd))
                    error = 1;
            }
        }

        DSA_free(key);
        close(keyfd);
        close(infd);
        fsync(sigfd); close(sigfd);
    }

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return error;
}
