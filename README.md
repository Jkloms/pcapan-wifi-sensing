# pcapan: analizator ruchu TCP/UDP z plików .pcap

`pcapan` to narzędzie w języku C dla systemu Linux. Wczytuje plik `.pcap` (albo `.pcapng`) i tworzy:

* **raport PDF** z podsumowaniem, listą wykrytych nieprawidłowości, wykresami i tabelami,
* **10 wykresów PNG** (ruch w czasie, przepustowość, protokoły, top hosty, top usługi, rozmiary pakietów, flagi TCP, stany połączeń, RTT, hosty kontaktujące najwięcej celów),
* krótkie podsumowanie w terminalu.

Wykrywane nieprawidłowości: **skanowanie portów** (TCP i UDP), **skanowanie sieci**, **SYN flood**, **UDP flood**, **wysoki poziom retransmisji TCP**, **masowe zrywanie połączeń (RST)**, **nietypowe flagi TCP** (NULL / XMAS / SYN+FIN) oraz **nagłe skoki natężenia ruchu**.

Przykładowy raport znajdziesz w [`examples/mixed/raport.pdf`](examples/mixed/raport.pdf).

---

## 1. Szybki start

```bash
# 1) zależności (Ubuntu / Debian)
sudo apt install build-essential pkg-config libpcap-dev libcairo2-dev fonts-dejavu-core

# 2) kompilacja
make

# 3) przykładowe pliki .pcap (generator jest częścią projektu)
make samples

# 4) analiza
./pcapan -o wynik samples/mixed.pcap
# -> wynik/raport.pdf oraz wynik/*.png
```

Fedora: `sudo dnf install gcc make pkgconf libpcap-devel cairo-devel dejavu-sans-fonts`.

### Opcje

| Opcja | Znaczenie | Domyślnie |
|---|---|---|
| `-o KATALOG` | katalog wyjściowy | `raport` |
| `-p N` | próg skanowania portów (liczba różnych portów) | 15 |
| `-n N` | próg skanowania sieci (liczba różnych hostów) | 15 |
| `-s N` | próg SYN flood (niedokończone połączenia) | 100 |
| `-r PROCENT` | próg retransmisji (% pakietów TCP) | 3 |
| `-u N` | próg UDP flood (pakiety/s) | 500 |
| `-h` | pomoc | |

Własny ruch możesz nagrać np. tak: `sudo tcpdump -i any -w moj.pcap`, a potem `./pcapan moj.pcap`.

### Cele Makefile

| Polecenie | Co robi |
|---|---|
| `make` | buduje `./pcapan` |
| `make samples` | buduje `tools/gen_pcap` i tworzy 6 plików w `samples/` |
| `make example` | tworzy przykładowy raport w `examples/mixed/` |
| `make debug` | buduje wersję z AddressSanitizerem (wykrywa błędy pamięci) |
| `make clean` | usuwa pliki skompilowane |

---

## 2. Architektura

Program to **potok** (pipeline): dane płyną w jedną stronę przez kolejne moduły. Każdy moduł ma jedno zadanie i parę plików `.h` (interfejs) i `.c` (implementacja).

```
 plik.pcap
    │
    ▼
┌──────────┐  packet_t   ┌──────────┐   stats_t    ┌───────────┐
│  parser  │ ──────────► │  stats   │ ───────────► │  anomaly  │
│ libpcap  │ (1 pakiet)  │ liczniki │              │ detektory │
└──────────┘             │ przepływy│              └─────┬─────┘
                         └────┬─────┘                    │ anomalies_t
                              │                          │
                              ▼                          ▼
                         ┌──────────┐  plik PNG    ┌───────────┐
                         │  plots   │ ───────────► │  report   │ ──► raport.pdf
                         │ (charts) │              │   (PDF)   │
                         └──────────┘              └───────────┘
```

`main.c` tylko łączy te kroki: otwiera plik, w pętli podaje pakiety z parsera do statystyk, potem uruchamia detektory, wykresy i raport.

### Pliki

```
pcapan/
├── Makefile             przepis budowania
├── README.md            ten plik
├── src/
│   ├── main.c           punkt wejścia: opcje, pętla główna, podsumowanie w terminalu
│   ├── common.h/.c      wspólne typy: ip_addr_t, packet_t; funkcje do adresów
│   ├── parser.h/.c      odczyt .pcap (libpcap) i dekodowanie nagłówków
│   ├── stats.h/.c       liczniki, oś czasu, hosty, porty, PRZEPŁYWY (tablice haszujące)
│   ├── anomaly.h/.c     detektory nieprawidłowości
│   ├── charts.h/.c      generyczne wykresy PNG (cairo): słupkowe i liniowe
│   ├── plots.h/.c       przygotowanie danych ze statystyk pod konkretne wykresy
│   └── report.h/.c      składanie raportu PDF (cairo-pdf)
├── tools/
│   ├── gen_pcap.c       generator przykładowych plików .pcap
│   └── lsan.supp        filtr znanych "wycieków" w bibliotece fontconfig (dla make debug)
├── samples/             wygenerowane pliki .pcap (tworzy je `make samples`)
└── examples/mixed/      przykładowy raport PDF i wykresy PNG
```

### Zależności

| Biblioteka | Do czego | Dlaczego ta |
|---|---|---|
| **libpcap** | czytanie plików .pcap / .pcapng | standard (używa jej tcpdump i Wireshark) |
| **cairo** | wykresy PNG **i** raport PDF | jedna lekka biblioteka do obu formatów |
| **libm** | `sqrt`, `log10`, `pow` | standardowa biblioteka matematyczna C |

Reszta to standardowa biblioteka C i POSIX (`stdio`, `stdlib`, `string`, `getopt`, `inet_ntop`, `mkdir`).

---

## 3. Moduły po kolei

Najlepiej czytać kod w tej kolejności: `common.h` → `parser.c` → `stats.h` → `stats.c` → `anomaly.c` → `main.c`, a na końcu `charts.c`, `plots.c`, `report.c`.

### 3.1. `parser` – od bajtów do pakietu

Plik `.pcap` to nagłówek pliku i ciąg rekordów: każdy ma znacznik czasu, długość i surowe bajty ramki. libpcap (`pcap_open_offline`, `pcap_next_ex`) podaje nam te rekordy, a my sami dekodujemy nagłówki:

```
Ethernet (14 B) → [VLAN 4 B] → IPv4 (20+ B) / IPv6 (40 B) → TCP (20+ B) / UDP (8 B) → dane
```

* Obsługiwane typy łącza: Ethernet (także z VLAN), Linux "cooked" SLL i SLL2 (`tcpdump -i any`), loopback BSD, surowe IP.
* Liczby w sieci są zapisane w kolejności **big-endian**, dlatego czytamy je funkcjami `rd16`/`rd32`, a nie przez rzutowanie wskaźnika.
* Przed każdym odczytem sprawdzamy długość. Obcięty pakiet zwraca `PARSE_BAD` zamiast czytać poza buforem.
* Wynik to wypełniona struktura `packet_t`: czas, adresy, porty, flagi TCP, numery sekwencyjne, długość danych.

### 3.2. `stats` – liczniki i przepływy

Dla każdego pakietu `stats_add_packet()`:

1. zwiększa liczniki globalne (pakiety i bajty, TCP/UDP, IPv4/IPv6, flagi TCP, histogram rozmiarów),
2. dopisuje pakiet do **osi czasu** (tablica: 1 element = 1 sekunda, rośnie przez `realloc`),
3. aktualizuje **hosty** (ile wysłał i odebrał każdy adres IP),
4. znajduje albo tworzy **przepływ** (flow), czyli dwukierunkową rozmowę `(protokół, klient:port, serwer:port)`.

Przepływy i hosty trzymamy w **tablicach haszujących** z łańcuchowaniem. Hash przepływu jest symetryczny (XOR hashy obu końców), więc pakiet A→B i odpowiedź B→A trafiają do tego samego kubełka.

W przepływie TCP śledzimy:
* **handshake** (SYN → SYN+ACK → ACK) i na tej podstawie stan połączenia (`flow_state_str`),
* **RTT**, czyli czas od SYN do SYN+ACK,
* **retransmisje**: pamiętamy najwyższy numer sekwencyjny wysłany w danym kierunku. Segment z danymi, który nie wychodzi poza ten numer, to dane już widziane, więc liczymy go jako retransmisję.

### 3.3. `anomaly` – detektory

Detektory działają **po** wczytaniu całego pliku. Główna sztuczka: z przepływów robimy tablicę prostych rekordów "A próbowało połączyć się z B na porcie P", sortujemy ją `qsort` i przechodzimy po **grupach** sąsiednich rekordów.

| Detektor | Jak działa | Próg |
|---|---|---|
| Skanowanie portów | grupy (A, B, protokół): liczba różnych portów, z czego co najmniej połowa nieudanych | `-p` (15) |
| Skanowanie sieci | grupy (A, protokół, port): liczba różnych hostów B | `-n` (15) |
| SYN flood | grupy (serwer, port): liczba połączeń z SYN bez dokończonego handshake | `-s` (100), min. 50% prób |
| Retransmisje | retransmisje / pakiety TCP | `-r` (3%) |
| RST | przepływy TCP z flagą RST / wszystkie przepływy TCP | 30% |
| UDP flood | grupy po "ofierze" (strona, która więcej odbiera): pakiety/s | `-u` (500/s), min. 1000 pakietów |
| Nietypowe flagi | pakiety bez flag (NULL), FIN+PSH+URG (XMAS), SYN+FIN | > 0 |
| Skok ruchu | sekunda z liczbą pakietów > średnia + 4σ (i ≥ 2× średnia, ≥ 100) | 4σ |

Każda wykryta anomalia ma poziom (INFO / OSTRZEŻENIE / KRYTYCZNE) i opis po polsku.

### 3.4. `charts` i `plots` – wykresy

`charts.c` nic nie wie o sieciach. Rysuje generyczne wykresy (poziome i pionowe słupkowe, liniowe) z tablic etykiet i liczb, używając cairo. `plots.c` zamienia statystyki na te tablice (np. wybiera top 10 hostów funkcją `top_n`) i wywołuje odpowiedni wykres.

### 3.5. `report` – PDF

Cairo rysuje do PDF tymi samymi funkcjami co do PNG. W `report.c` jest mały "silnik układu strony" (`pdf_t`). Pamięta bieżącą pozycję Y i sam zaczyna nową stronę, gdy brakuje miejsca (`ensure`). Na nim zbudowane są akapity z zawijaniem wierszy, nagłówki, tabele (z powtarzaniem nagłówka na nowej stronie) i wstawianie PNG.

Sekcje raportu: kafelki z głównymi liczbami, (1) podsumowanie, (2) nieprawidłowości, (3) wykresy, (4) tabele: hosty, usługi, największe przepływy, (5) metodologia i progi.

### 3.6. `tools/gen_pcap` – dane testowe

Generator buduje pakiety bajt po bajcie (z poprawnymi sumami kontrolnymi IP/TCP/UDP) i zapisuje je przez `pcap_dump`. Wynik otworzy też Wireshark. Ziarno losowania jest stałe, więc pliki są zawsze takie same.

| Plik | Zawartość | Co powinien wykryć pcapan |
|---|---|---|
| `normal.pcap` | HTTP/HTTPS/SSH, DNS, NTP, ARP, mDNS po IPv6 | nic (0 fałszywych alarmów) |
| `portscan.pcap` | + skan portów 1–1024 i pakiety NULL/XMAS | skanowanie portów, RST, flagi |
| `synflood.pcap` | + 4000 SYN z fałszywych adresów | SYN flood |
| `udpflood.pcap` | + 8000 pakietów UDP w 4 s | UDP flood |
| `retrans.pcap` | łącze gubiące 8% segmentów | retransmisje |
| `mixed.pcap` | wszystko naraz (120 s) | wszystkie powyższe |

---

## 4. Mini-przewodnik po C (to, czego używa ten projekt)

**Pliki `.h` i `.c`.** Nagłówek (`.h`) to "spis treści": deklaracje typów i funkcji. Plik `.c` zawiera ich kod. `#include "stats.h"` wkleja nagłówek, żeby kompilator znał typy. `#ifndef X / #define X / #endif` (include guard) chroni przed wklejeniem go dwa razy.

**Kompilacja i linkowanie.** `gcc -c stats.c` zamienia każdy `.c` w plik obiektowy `.o`, a linker skleja wszystkie `.o` i biblioteki (`-lpcap -lcairo -lm`) w program. Robi to za nas `Makefile`. `pkg-config` podaje właściwe flagi dla bibliotek.

**Typy o stałym rozmiarze.** `uint8_t`, `uint16_t`, `uint32_t`, `uint64_t` (z `<stdint.h>`) mają zawsze 8/16/32/64 bity. To ważne przy nagłówkach sieciowych. `size_t` to typ na rozmiary i indeksy.

**`struct` i `typedef`.** `struct` grupuje pola (jak klasa bez metod). `typedef struct {...} packet_t;` pozwala pisać `packet_t` zamiast `struct ...`. Do pól sięgamy kropką (`pkt.sport`), a przez wskaźnik strzałką (`p->sport`).

**Wskaźniki.** `int *p` przechowuje *adres* zmiennej. `&x` to adres `x`, a `*p` to wartość pod adresem. Funkcje dostają wskaźniki, żeby móc zmieniać dane wywołującego (np. `parser_next(p, &pkt)` wypełnia `pkt`) i żeby nie kopiować dużych struktur. `const` przy wskaźniku znaczy "tylko czytam".

**Tablice i arytmetyka wskaźników.** Nazwa tablicy działa jak wskaźnik na pierwszy element. `pkt + 14` to adres 14 bajtów dalej, tak "przeskakujemy" nagłówek Ethernet. C **nie sprawdza granic tablic**, dlatego parser zawsze najpierw porównuje długości.

**Pamięć dynamiczna.** `malloc(n)` rezerwuje `n` bajtów na stercie, `calloc` dodatkowo je zeruje, `realloc` zmienia rozmiar (tak rosną nasze tablice dynamiczne), a `free` oddaje pamięć. Każdy `malloc` musi mieć swój `free`. Sprawdza to `make debug` (AddressSanitizer). Zawsze sprawdzaj, czy `malloc` nie zwrócił `NULL`.

**Napisy.** Napis w C to tablica `char` zakończona bajtem `'\0'`. Do bufora piszemy przez `snprintf(buf, sizeof buf, ...)`, który nigdy nie wyjdzie poza bufor (w przeciwieństwie do `sprintf`/`strcpy`).

**Operacje bitowe.** Flagi TCP to bity w jednym bajcie: `flags & TCP_SYN` sprawdza bit, `flags |= x` ustawia bity, `x >> 4` przesuwa w prawo (np. wersja IP to górne 4 bity bajtu).

**`static`.** Funkcja `static` jest widoczna tylko w swoim pliku (funkcja "prywatna" modułu). Zmienna `static` wewnątrz funkcji żyje przez cały czas działania programu.

**Typ nieprzezroczysty.** W `parser.h` jest tylko `typedef struct parser parser_t;`, a zawartość struktury zna wyłącznie `parser.c`. Reszta programu używa samego wskaźnika, więc to enkapsulacja jak w programowaniu obiektowym.

**Wskaźniki na funkcje.** `qsort(tab, n, rozmiar, cmp)` sortuje dowolną tablicę. `cmp` to funkcja porównująca, przekazana jako wskaźnik. Dostaje `const void *` (wskaźnik "na cokolwiek") i sama rzutuje go na właściwy typ.

**Tablica haszująca.** Tablica "kubełków", w której każdy kubełek to lista jednokierunkowa (`hnext`). Funkcja haszująca zamienia klucz (np. adresy i porty) na numer kubełka, więc szukamy tylko w jednej krótkiej liście, a nie w całej tablicy.

**Obsługa błędów.** C nie ma wyjątków. Funkcje zwracają kod (`0` = OK, `-1` = błąd albo `NULL`), a wywołujący musi go sprawdzić. `goto oom;` w `anomaly.c` to akceptowany w C sposób na wspólne sprzątanie po błędzie.

**`enum`, `switch`, `#define`.** `enum` nadaje nazwy stałym liczbowym (`PARSE_OK`, `SEV_CRIT`), `switch` wybiera gałąź po wartości, a `#define` to stała lub makro preprocesora, zamieniane tekstowo przed kompilacją.

---

## 5. Ograniczenia i pomysły na rozwój

* Nagłówki rozszerzeń IPv6 i fragmentacja IP są pomijane (fragmenty poza pierwszym nie są analizowane).
* Pakiety przestawione w kolejności są liczone jako retransmisje (uproszczenie).
* Oś czasu ma rozdzielczość 1 s i jest ograniczona do 7 dni nagrania.
* Pomysły: analiza zapytań DNS (najczęstsze domeny), wykrywanie beaconingu (regularne połączenia), eksport CSV/JSON, porównanie dwóch plików.
