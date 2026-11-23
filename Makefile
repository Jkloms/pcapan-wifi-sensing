# Makefile - przepis budowania projektu.
# Użycie:
#   make           - buduje program ./pcapan
#   make samples   - buduje generator i tworzy przykładowe pliki .pcap w samples/
#   make example   - generuje przykładowy raport w examples/
#   make debug     - wersja z AddressSanitizerem (wykrywa błędy pamięci)
#   make clean     - usuwa pliki wynikowe kompilacji

CC      ?= gcc
CFLAGS  ?= -O2 -g
LDFLAGS ?=
# Flagi stałe: standard C11, wszystkie ostrzeżenia kompilatora.
# pkg-config podaje właściwe flagi kompilatora i linkera dla bibliotek.
ALL_CFLAGS = $(CFLAGS) -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Wpedantic \
             $(shell pkg-config --cflags cairo libpcap 2>/dev/null)
LDLIBS  = $(shell pkg-config --libs cairo libpcap 2>/dev/null || echo -lcairo -lpcap) -lm

SRC = src/main.c src/common.c src/parser.c src/stats.c src/anomaly.c \
      src/charts.c src/plots.c src/report.c
OBJ = $(SRC:.c=.o)

all: pcapan

# Linkowanie: łączymy pliki obiektowe .o w jeden plik wykonywalny
pcapan: $(OBJ)
	$(CC) $(ALL_CFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

# Kompilacja: każdy plik .c -> .o (zależy też od nagłówków)
src/%.o: src/%.c src/*.h
	$(CC) $(ALL_CFLAGS) -c -o $@ $<

tools/gen_pcap: tools/gen_pcap.c
	$(CC) $(ALL_CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

samples: tools/gen_pcap
	./tools/gen_pcap samples

example: pcapan samples
	./pcapan -o examples/mixed samples/mixed.pcap

debug: clean
	$(MAKE) pcapan CFLAGS="-O0 -g -fsanitize=address,undefined" LDFLAGS="-fsanitize=address,undefined"

clean:
	rm -f pcapan $(OBJ) tools/gen_pcap

.PHONY: all samples example debug clean
