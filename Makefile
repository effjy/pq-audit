# pq-audit — Makefile (pkg-config driven, mirrors pq-sign conventions)
CC      ?= cc
CSTD    ?= -std=c11
WARN     = -Wall -Wextra -Wshadow -Wconversion -Wpointer-arith
OPT     ?= -O2
PKGS     = openssl liboqs libargon2
CFLAGS  += $(CSTD) $(WARN) $(OPT) -Iinclude -Ivendor/pqsign $(shell pkg-config --cflags $(PKGS))
LDLIBS  += $(shell pkg-config --libs $(PKGS))

# our code
SRC    = src/main.c src/segment.c src/util.c src/seal.c src/fs.c src/merkle.c \
         src/daemon.c
# vendored pq-sign library (copied from the pq-sign repo, unmodified)
VENDOR = vendor/pqsign/util.c vendor/pqsign/keyfile.c vendor/pqsign/sigfile.c \
         vendor/pqsign/pqoqs.c
OBJ    = $(SRC:.c=.o) $(VENDOR:.c=.o)
BIN    = pq-audit

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDLIBS)

# our objects depend on our header; vendored objects do not (kept verbatim)
src/%.o: src/%.c include/pqaudit.h
	$(CC) $(CFLAGS) -c -o $@ $<
vendor/pqsign/%.o: vendor/pqsign/%.c
	$(CC) $(CFLAGS) -Wno-conversion -c -o $@ $<

check: $(BIN)
	./tests/run.sh

asan: clean
	$(MAKE) OPT="-O1 -g -fsanitize=address,undefined" $(BIN)
	ASAN_OPTIONS=detect_leaks=$(LSAN) ./tests/run.sh
# LeakSanitizer needs ptrace; set LSAN=0 in sandboxes/containers that block it.
LSAN ?= 1

clean:
	rm -f $(OBJ) $(BIN)

.PHONY: all check asan clean
