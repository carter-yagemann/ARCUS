CC=gcc

all: cmppath.c pt.c obj/libxed.a
	$(CC) -O3 -I./xed/include/public -I./obj -I./xed/include/public/xed pt.c obj/libxed.a -lz -o pt
	$(CC) -O3 -I./xed/include/public -I./obj -I./xed/include/public/xed cmppath.c obj/libxed.a -fopenmp -lz -o cmppath

debug: cmppath.c pt.c obj/libxed.a
	$(CC) -g -I./xed/include/public -I./obj -I./xed/include/public/xed pt.c obj/libxed.a -lz -o pt
	$(CC) -g -I./xed/include/public -I./obj -I./xed/include/public/xed cmppath.c obj/libxed.a -fopenmp -lz -o cmppath

obj/libxed.a:
	./xed/mfile.py

clean:
	rm -f pt
	rm -f cmppath
	./xed/mfile.py clean
	rm -rf obj
