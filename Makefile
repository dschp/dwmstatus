LIBRESSL_INC = /opt/libressl/include
LIBRESSL_LIB = /opt/libressl/gnu/lib64

all: dwmstatus mailstatus

dwmstatus: dwmstatus.c
	$(CC) -o dwmstatus dwmstatus.c -lX11

mailstatus: mailstatus.c
	$(CC) -o mailstatus mailstatus.c -I$(LIBRESSL_INC) -L$(LIBRESSL_LIB) -ltls

clean:
	rm -f *.o dwmstatus

