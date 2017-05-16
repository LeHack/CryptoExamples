# Tool invocations
CC=gcc
SRC=src
CFLAGS=-I~/openssl/include/ -L~/openssl/lib/

ODIR=bin
LIBS=-lcrypto

all: Camellia_CBC Camellia_ECB

Camellia_CBC: 
	@echo 'Building CBC variant: $@'
	@mkdir -p $(ODIR)
	@$(CC) -o $(ODIR)/camellia_cbc $(SRC)/camellia_cbc.c $(CFLAGS) $(LIBS)

Camellia_ECB: 
	@echo 'Building ECB variant: $@'
	@mkdir -p $(ODIR)
	@$(CC) -o $(ODIR)/camellia_ecb $(SRC)/camellia_ecb.c $(CFLAGS) $(LIBS)

clean:
	@echo 'Removing: camellia_cbc camellia_ecb'
	@rm -rf $(ODIR)/camellia_cbc $(ODIR)/camellia_ecb

.PHONY: all clean
