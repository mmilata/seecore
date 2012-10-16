PROG=seecore

$(PROG): util.c seecore.c
	$(CC) -g -o $@ -lelf -ldw -Wall -Wextra -Wno-unused $+

run: seecore
	./$(PROG) test/threads test/core.24970

clean:
	rm -f $(PROG)
