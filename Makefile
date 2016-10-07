LDFLAGS=-lpcap

# Change these according to your needs:
CFLAGS=-Wall -g # -DLOG_SESSIONID

all: tls-hello-dump

tls-hello-dump: tls-hello-dump.o inet_hashtable.o

tls-hello-dump.o: cipher_suites.h inet_hashtable.h tls-hello-dump.c
	gcc ${CFLAGS} -c tls-hello-dump.c

inet_hashtable.o: inet_hashtable.h inet_hashtable.c
	gcc ${CFLAGS} -c inet_hashtable.c

clean:
	rm -f tls-hello-dump tls-hello-dump.o inet_hashtable.o

.PHONY: clean
