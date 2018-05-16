CFLAGS = -O0 -g

TARGETS = nih-sftp-server nih-sftp-server.o

all: $(TARGETS)

.PHONY: clean

clean:
	rm -f $(TARGETS)
