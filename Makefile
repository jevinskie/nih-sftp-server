CFLAGS = -Ofast

TARGETS = nih-sftp-server nih-sftp-server.o

all: $(TARGETS)

.PHONY: clean

clean:
	rm -f $(TARGETS)
