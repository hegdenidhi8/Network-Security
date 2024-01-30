all: purenc purdec

purenc: purenc.c
	gcc -o purenc purenc.c `libgcrypt-config --cflags --libs`

purdec: purdec.c
	gcc -o purdec purdec.c `libgcrypt-config --cflags --libs` 

clean:
	rm  purenc purdec