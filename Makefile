# Tool invocations
CC=gcc
SRC=src
CFLAGS=-I~/openssl/include/ -L~/openssl/lib/

ODIR=bin
LIBS=-lcrypto

all: Camellia_CBC Camellia_ECB RSA

RSA:
	@echo 'Building RSA: $@'
	@mkdir -p $(ODIR)
	@$(CC) -o $(ODIR)/rsa $(SRC)/rsa.c $(CFLAGS) $(LIBS)

Camellia_CBC: 
	@echo 'Building Camellia CBC variant: $@'
	@mkdir -p $(ODIR)
	@$(CC) -o $(ODIR)/camellia_cbc $(SRC)/camellia_cbc.c $(CFLAGS) $(LIBS)

Camellia_ECB: 
	@echo 'Building Camellia ECB variant: $@'
	@mkdir -p $(ODIR)
	@$(CC) -o $(ODIR)/camellia_ecb $(SRC)/camellia_ecb.c $(CFLAGS) $(LIBS)

clean:
	@echo 'Removing: camellia_cbc camellia_ecb rsa'
	@rm -rf $(ODIR)/camellia_cbc $(ODIR)/camellia_ecb $(ODIR)/rsa

.PHONY: all clean
