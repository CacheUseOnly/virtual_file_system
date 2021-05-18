override CFLAGS := -std=gnu99 -O0 -g -pthread $(CFLAGS)
# override CFLAGS := -Wall -Werror -std=gnu99 -O0 -g -pthread $(CFLAGS)
override LDLIBS := -pthread $(LDLIBS)

fs.o:	fs.c disk.c

.PHONY: clean

test:
	gcc -o test test.c fs.c disk.c -g

clean:
	rm -f tls.o
