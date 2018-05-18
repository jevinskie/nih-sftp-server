CFLAGS = -O0 -g -Wall -Wextra -Werror -std=iso9899:1999 -pedantic-errors

TARGETS = nih-sftp-server nih-sftp-server.o

all: $(TARGETS)

.PHONY: clean

clean:
	rm -f $(TARGETS)
