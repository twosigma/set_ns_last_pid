TARGETS=set_ns_last_pid example_client

all: $(TARGETS)

set_ns_last_pid: server/set_ns_last_pid.c server/fork_hack.c server/fork_hack.h
	gcc -O3 $^ -o $@ -Wall -Wextra -lpthread $(CFLAGS) -lrt

example_client: client/example_client.c
	gcc -O3 $^ -o $@ -Wall -Wextra $(CFLAGS)

clean:
	rm -f $(TARGETS)
