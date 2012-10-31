PROG=seecore
LIBS=-lelf -ldw -lunwind-generic -lunwind-coredump
CFLAGS+=-g -Wall -Wextra -Wno-unused

$(PROG): seecore.c util.c evaluator.c variable.c stack.c corefile.c
	$(CC) $(CFLAGS) -o $@ $(LIBS) $+

run: seecore
	./$(PROG) test/threads test/core.24970

clean:
	rm -f $(PROG)
