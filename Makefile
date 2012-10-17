PROG=seecore
LIBS=-lelf -ldw -lunwind-generic -lunwind-coredump

$(PROG): util.c seecore.c
	$(CC) -g -o $@ $(LIBS) -Wall -Wextra -Wno-unused $+

run: seecore
	./$(PROG) test/threads test/core.24970

clean:
	rm -f $(PROG)
