CFLAGS = -Ofast -flto -ffunction-sections -fdata-sections
LDFLAGS = -Ofast -flto -Wl,-dead_strip

TARGETS = nih-sftp-server nih-sftp-server.o

all: $(TARGETS)

.PHONY: clean

clean:
	rm -f $(TARGETS)
