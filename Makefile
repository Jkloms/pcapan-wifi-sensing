# make | make samples | make example | make debug (ASan) | make clean

CC      ?= gcc
CFLAGS  ?= -O2 -g
LDFLAGS ?=
ALL_CFLAGS = $(CFLAGS) -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Wpedantic \
             $(shell pkg-config --cflags cairo libpcap 2>/dev/null)
LDLIBS  = $(shell pkg-config --libs cairo libpcap 2>/dev/null || echo -lcairo -lpcap) -lm

SRC = src/main.c src/common.c src/parser.c src/stats.c src/sensing.c src/anomaly.c \
      src/charts.c src/plots.c src/report.c src/export.c
OBJ = $(SRC:.c=.o)

all: pcapan

pcapan: $(OBJ)
	$(CC) $(ALL_CFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

src/%.o: src/%.c src/*.h
	$(CC) $(ALL_CFLAGS) -c -o $@ $<

tools/gen_pcap: tools/gen_pcap.c
	$(CC) $(ALL_CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

samples: tools/gen_pcap
	./tools/gen_pcap samples

example: pcapan samples
	./pcapan -o examples/wifi_mix samples/wifi_mix.pcap

debug: clean
	$(MAKE) pcapan CFLAGS="-O0 -g -fsanitize=address,undefined" LDFLAGS="-fsanitize=address,undefined"

clean:
	rm -f pcapan $(OBJ) tools/gen_pcap

.PHONY: all samples example debug clean
