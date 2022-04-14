CC=gcc

all: cmppath.c pt.c obj/libxed.a build/bin/ptxed
	$(CC) -O3 -I./xed/include/public -I./obj -I./xed/include/public/xed pt.c obj/libxed.a -lz -o pt
	$(CC) -O3 -I./xed/include/public -I./obj -I./xed/include/public/xed cmppath.c obj/libxed.a -fopenmp -lz -o cmppath

debug: cmppath.c pt.c obj/libxed.a build/bin/ptxed
	$(CC) -g -I./xed/include/public -I./obj -I./xed/include/public/xed pt.c obj/libxed.a -lz -o pt
	$(CC) -g -I./xed/include/public -I./obj -I./xed/include/public/xed cmppath.c obj/libxed.a -fopenmp -lz -o cmppath

obj/libxed.a:
	./xed/mfile.py

build/bin/ptxed:
	mkdir -p build
	cd build && \
	cmake -DPTDUMP=ON -DPTXED=ON -DPTTC=ON -DSIDEBAND=ON -DPEVENT=ON -DFEATURE_ELF=ON -DFEATURE_THREADS=ON -DXED_INCLUDE=./obj/wkit/include/xed -DXED_LIBDIR=./obj/ ../libipt/ && \
	cd ..
	cmake --build build

clean:
	rm -f pt
	rm -f cmppath
	./xed/mfile.py clean
	rm -rf obj
	rm -rf build
