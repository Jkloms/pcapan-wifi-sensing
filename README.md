# pcapan: wykrywanie ruchu człowieka i zakłóceń w Wi-Fi (WiFi sensing)

Projekt hackathonowy napisany w C. Program czyta nagranie sieci Wi-Fi (`.pcap`) i robi trzy rzeczy:

1. **Szuka ruchu człowieka.** Kiedy ktoś chodzi po pokoju, fale radiowe odbijają się od niego inaczej, więc siła sygnału (RSSI) zaczyna skakać. Okresy, w których tak się dzieje, zaznaczamy na wykresach.
2. **Wykrywa zakłócenia.** Bierzemy pod uwagę zakłócenia radiowe (dużo powtórzonych ramek, wyższy szum) oraz problemy łącza (wzrost RTT, retransmisje TCP, przerwy w ruchu).
3. **Analizuje ruch TCP/UDP.** Liczy pakiety, przepływy i usługi, a dodatkowo wykrywa proste ataki (skan portów, SYN flood, UDP flood).

Wynik zapisuje w katalogu `raport/`: 4-stronicowy `raport.pdf`, 10 wykresów PNG i pliki CSV.

## Uruchomienie (Ubuntu)

```bash
sudo apt install build-essential libpcap-dev libcairo2-dev
make                 # buduje ./pcapan
make samples         # tworzy pliki testowe w samples/
make example         # raport dla samples/wifi_mix.pcap -> examples/wifi_mix/
./pcapan -o wynik samples/wifi_ruch.pcap
```

Własne nagranie zrobisz kartą Wi-Fi w trybie monitor, np. `sudo airmon-ng start wlan0`, a potem `sudo tcpdump -i wlan0mon -w moje.pcap`. Plik musi mieć nagłówki radiotap. Zwykłe nagrania z Ethernetu też działają, tylko bez części radiowej.

## Pliki testowe (`tools/gen_pcap.c`)

| Plik | Co w nim jest |
|---|---|
| `wifi_spokoj.pcap` | pusty pokój: nic nie powinno zostać wykryte |
| `wifi_ruch.pcap` | 3 okresy ruchu (20–35 s, 60–68 s, 90–110 s) |
| `wifi_zaklocenia.pcap` | zakłócenia radiowe, wolne łącze, 5 s przerwy |
| `wifi_mix.pcap` | wszystko naraz (to jest przykładowy raport) |
| `eth_ataki.pcap` | Ethernet: skan portów, SYN flood, UDP flood |

Ruch symulujemy tak, że w wybranych okresach RSSI dostaje wahania o kilka dB. W spokoju zostaje tylko mały szum (σ ≈ 0,7 dB).

## Jak działa wykrywanie (`src/sensing.c`)

| Zdarzenie | Reguła |
|---|---|
| Podejrzenie ruchu | Liczymy odchylenie std RSSI w oknie 3 s dla nadajnika słyszanego najdłużej (zwykle punktu dostępowego). Ruch to wartość powyżej progu = 2 × poziom ciszy (25. percentyl), ale co najmniej 1,5 dB. |
| Zakłócenia radiowe | Ponad 25% ramek z flagą Retry albo szum o 6 dB wyższy niż mediana. |
| Wzrost opóźnienia | RTT (dane → ACK) powyżej max(3 × mediana, mediana + 50 ms). |
| Retransmisje TCP | Co najmniej 3 na sekundę i co najmniej 10% pakietów TCP. |
| Przerwa | Co najmniej 3 s bez pakietów TCP/UDP. |

Sąsiednie sekundy łączymy w okresy. Okres ruchu musi trwać co najmniej 2 s.

## Budowa programu

```
plik.pcap -> parser -> stats -> sensing (ruch, zakłócenia, łącze) --+-> plots  (PNG)
                             -> anomaly (ataki)                    +-> export (CSV)
                                                                   +-> report (PDF)
```

| Moduł | Zadanie |
|---|---|
| `parser.c` | czyta pakiety (libpcap) i ręcznie dekoduje radiotap, 802.11, Ethernet, IP, TCP i UDP |
| `stats.c` | liczniki i oś czasu (co 1 s), RSSI dla każdego nadajnika, przepływy, RTT, retransmisje |
| `sensing.c` | serie sekundowe i wykrywanie zdarzeń (tabela powyżej) |
| `anomaly.c` | ataki: skanowanie, SYN/UDP flood, nietypowe flagi TCP |
| `charts.c` | wykresy w bibliotece cairo (linie z pasami okresów i linią progu, słupki) |
| `plots.c` | lista 10 wykresów raportu |
| `report.c` | raport PDF |
| `export.c` | pliki CSV: `zdarzenia.csv`, `sekundy.csv` (dane wykresów), `ataki.csv`, `przeplywy.csv` |

## C w pigułce, czyli co warto znać, żeby czytać ten kod

- **`.h` i `.c`**: plik `.h` opisuje, co moduł udostępnia, a `.c` zawiera kod. `#include` wkleja nagłówek do pliku.
- **`struct`** grupuje dane (np. `packet_t` to jeden pakiet). **`enum`** to nazwane stałe (np. typy zdarzeń).
- **Wskaźniki**: `const stats_t *s` to adres struktury, a `s->pole` czyta pole przez wskaźnik.
- **Pamięć**: `malloc`/`calloc`/`realloc` rezerwują pamięć, a `free` ją zwalnia. `make debug` buduje wersję z AddressSanitizerem, który wyłapuje błędy pamięci.
- **Bajty z sieci**: liczby w nagłówkach IP/TCP są big-endian (`rd16`), a w radiotap little-endian (`le16`). Zawsze sprawdzamy długość pakietu przed odczytem.
- **`NAN`**: tak oznaczamy "brak danych w tej sekundzie". Wykres przerywa wtedy linię.
- **Wskaźnik na funkcję**: `plot_fn` w `plots.h` pozwala trzymać wykresy w tablicy `PLOTS[]`.

## Ograniczenia

- Ruch rozpoznajemy tylko po RSSI. Prawdziwe systemy WiFi sensing używają CSI (dane z wielu podnośnych), których zwykła karta nie zapisuje do pcap.
- Progi są dobrane pod nasze pliki testowe. Dla innego pomieszczenia trzeba je sprawdzić na nagraniu "pustego pokoju".
- Szyfrowane ramki Wi-Fi (WPA2) są liczone do RSSI, ale ich zawartości TCP/UDP nie analizujemy.
