CC = gcc
CFLAGS = -Wall -g -I/usr/include/mysql
#LDFLAGS = -lcrypto -lssl -lmysqlclient  -L /usr/lib/mysql/ -lpthread -lrt
#LDFLAGS = -lpthread -lrt -lssl -I /usr/include/mysql -L /usr/lib64/mysql/ -lmysqlclient
LDFLAGS = -lpthread -lrt -lssl -lmysqlclient -L/usr/lib64/mysql/ 

SRCS := $(wildcard *.c)
OBJS := $(patsubst %.c,%.o,$(SRCS))

EXEC = dadmonitor 

.PHONY: clean


all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $^ -o $@ $(LDFLAGS) 

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f `file * | grep ELF | cut -d: -f1`
	rm -f *~
