all: dwmstatus

dwmstatus: dwmstatus.c
	$(CC) -o dwmstatus dwmstatus.c -lX11

clean:
	rm -f *.o dwmstatus

