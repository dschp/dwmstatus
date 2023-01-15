LIBRESSL_INC = /opt/libressl/include
LIBRESSL_LIB = /opt/libressl/gnu/lib64

CC_ARGS =

-include config.mk

all: dwmstatus mailstatus

dwmstatus: dwmstatus.c
	$(CC) $(CC_ARGS) -o dwmstatus dwmstatus.c -lX11

mailstatus: mailstatus.c
	$(CC) $(CC_ARGS) -o mailstatus mailstatus.c -I$(LIBRESSL_INC) -L$(LIBRESSL_LIB) -ltls

clean:
	rm -f *.o dwmstatus mailstatus

