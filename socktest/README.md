# Chování BIRD socketů

## Požadavky

### Kombinace
- Sockety
   - UDP
   - Raw
- IP
   - IPv4
   - IPv6
- Způsob vysílání
   - Unicast
   - Multicast (`224.0.0.9`, `ff02::9`)
   - Directed broadcast podle masky sítě
   - Universal broadcast (`255.255.255.255`)

### Vlastnosti

- Na straně odesílání
    - Odesila na spravne rozhrani, ackoli routovaci tabulka je jina, ale cilova adresa je dostupna na dane siti
    - Na odesilacim rozhrani je vice adres
    - Odesila se spravnou nastavenou zdrojovou adresou, ktera nemusi byt na danem rozhrani, ale musi byt alespon na nekterem jinem rozhrani
    - Overit, ze packety maji cilovou adresu takovou, kterou ocekavame

- Na straně přijímání
    - Nemelo by prijmout packet z jineho rozhrani nez je nastaveny
    - Precist source-addr a local iface

## Testcase

### Nastavení
- Interface s prefixem /24
    - 2 IPv4 adresy (aliasy)
    - 2 IPv6 adresy (aliasy)
- Odstranene smerovani v routovaci tabulce (ping nefunguje)

#### Odesílání
- Jako lokální adresa se použije adresa jiného lokálního zařízení
- TTL 3

#### Přijímání

1. Nastaví se na *správný* interface
2. Nastaví se na *jiný* interface a nemělo by to nic přijmout

### Ukázky (IPv4, raw socket)

#### Unicast
     ./rcv -i lnk111
     ./snd -c 10 -i lnk111 -t 3 -l 192.168.214.188 10.210.1.51

#### Multicast
     ./rcv -i lnk111 -m 224.0.0.9
     ./snd -c 10 -i lnk111 -t 3 -l 192.168.214.188 -m 224.0.0.9

#### Directed Broadcast
     ./rcv -i lnk111 -b
     ./snd -c 10 -i lnk111 -t 3 -l 192.168.214.188 -b 10.210.1.255

#### Universal Broadcast
     ./rcv -i lnk111 -b
     ./snd -c 10 -i lnk111 -t 3 -l 192.168.214.188 -b 255.255.255.255

### Kontrola
- `tcpdump -i <iface> -vvvn`
    - Správný interface
    - Správná IP na obou koncích

#### Přijímání
1.
    - Přijmutí
    - Taková IP odesílatele, kterou jsme nastavili
    - Správně rozpoznané rozhraní, na kterém jsme packet přijmuli
    - Správná hodnota TTL
2.
    - Nepřijme nic

## Výsledky

### Linux

<table style="text-align: center;">
  <tr>
    <th colspan="2"></td><th>Unicast</td><th>Multicast</td><th>Broadcast</td>
  </tr>

  <tr>
    <th rowspan="2" style="vertical-align: middle">IPv4</th><th>Raw</th>
    <td rowspan="2">OK</td>
    <td rowspan="2">OK</td>
    <td rowspan="2">OK</td>
  </tr>
  <tr>
    <th>UDP</th>
  </tr>

  <tr>
    <th rowspan="2" style="vertical-align: middle">IPv6</th><th>Raw</th>
    <td rowspan="2">OK<sup>1</sup></td>
    <td rowspan="2">OK<sup>1</sup></td>
    <td rowspan="2">-</td>
  </tr>
  <tr>
    <th>UDP</th>

  </tr>
</table>

<sup>1</sup>) Zdrojová adresa musí být jedna z adres nastavených na daném zařízení, nelze vybrat adresu z jiného zařízení

### FreeBSD

<table style="text-align: center;">
  <tr>
    <th colspan="2"></td><th>Unicast</td><th>Multicast</td><th>Broadcast</td>
  </tr>

  <tr>
    <th rowspan="2" style="vertical-align: middle">IPv4</th><th>Raw</th>
    <td>OK<sup>2,4,5</sup></td>
    <td rowspan="2">OK</td>
    <td rowspan="2">OK<sup>2,3,4</sup></td>
  </tr>
  <tr>
    <th>UDP</th>
    <td>OK<sup>2,5</sup></td>
  </tr>

  <tr>
    <th rowspan="2" style="vertical-align: middle">IPv6</th><th>Raw</th>
    <td rowspan="2">OK<sup>1,2,4,5</sup></td>
    <td rowspan="2">OK<sup>1,2</sup></td>
    <td rowspan="2">-</td>
  </tr>
  <tr>
    <th>UDP</th>
  </tr>
</table>

<sup>1</sup>) Zdrojová adresa musí být jedna z adres nastavených na daném zařízení, nelze vybrat adresu z jiného zařízení.<br />
<sup>2</sup>) Pakety jsou BIRDem přijímány i na jiných zařízení. <br />
<sup>3</sup>) Directed broadcast funguje. Universal broadcast lze poslat pomocí <code>IP_ONESBCAST</code> (directed přepíše na universal)<br />
<sup>4</sup>) Přijímá multicast bez přihlášení do skupiny.<br />
<sup>5</sup>) Vyžaduje správné nastavení směrovacích tabulek. <br />

`SO_DONTROUTE` umožní odesílání IPv4 Unicast zpráv i při nesprávném nastavení směrovacích tabulek, nicméně při IPv4 Multicastu (Raw/UDP) způsobí chybu `Network is unreachable`.

### OpenBSD

<table style="text-align: center;">
  <tr>
    <th colspan="2"></td><th>Unicast</td><th>Multicast</td><th>Broadcast</td>
  </tr>

  <tr>
    <th rowspan="2" style="vertical-align: middle">IPv4</th><th>Raw</th>
    <td>OK<sup>2,5</sup></td>
    <td>OK</td>
    <td>OK<sup>2,7</sup></td>
  </tr>
  <tr>
    <th>UDP</th>
    <td>OK<sup>2,5,6</sup></td>
    <td>OK<sup>6</sup></td>
    <td>OK<sup>2,6,7</sup></td>
  </tr>

  <tr>
    <th rowspan="2" style="vertical-align: middle">IPv6</th><th>Raw</th>
    <td rowspan="2">OK<sup>1,2,5</sup></td>
    <td rowspan="2">OK<sup>1</sup></td>
    <td rowspan="2">-</td>
  </tr>
  <tr>
    <th>UDP</th>
  </tr>
</table>

<sup>1</sup>) Zdrojová adresa musí být jedna z adres nastavených na daném zařízení, nelze vybrat adresu z jiného zařízení.<br />
<sup>2</sup>) Pakety jsou BIRDem přijímány i na jiných zařízení. <br />
<sup>3</sup>) Directed broadcast funguje. Universal broadcast lze poslat pomocí <code>IP_ONESBCAST</code> (directed přepíše na universal)<br />
<sup>4</sup>) Přijímá multicast bez přihlášení do skupiny.<br />
<sup>5</sup>) Vyžaduje správné nastavení směrovacích tabulek. <br />
<sup>6</sup>) Při odesílání nelze nastavit zdrojovou adresou. Chybí <code>IP_SENDSRCADDR</code>. <br />
<sup>7</sup>) Universal broadcast se odesílá na systémový výchozí interface. <code>IP_ONESBCAST</code> na systému neexistuje.

`SO_DONTROUTE` vrací chybu `Operation not supported`.

### NetBSD

<table style="text-align: center;">
  <tr>
    <th colspan="2"></td><th>Unicast</td><th>Multicast</td><th>Broadcast</td>
  </tr>

  <tr>
    <th rowspan="2" style="vertical-align: middle">IPv4</th><th>Raw</th>
    <td>OK<sup>2,5</sup></td>
    <td>OK<sup></sup></td>
    <td>OK<sup>5,7</sup></td>
  </tr>
  <tr>
    <th>UDP</th>
    <td>OK<sup>2,5,6</sup></td>
    <td>OK<sup>6</sup></td>
    <td>OK<sup>5,6,7</sup></td>
  </tr>

  <tr>
    <th rowspan="2" style="vertical-align: middle">IPv6</th><th>Raw</th>
    <td rowspan="2">OK<sup>1,2,5</sup></td>
    <td rowspan="2">OK<sup>1,8</sup></td>
    <td rowspan="2">-</td>
  </tr>
  <tr>
    <th>UDP</th>
  </tr>
</table>

<sup>1</sup>) Zdrojová adresa musí být jedna z adres nastavených na daném zařízení, nelze vybrat adresu z jiného zařízení.<br />
<sup>2</sup>) Pakety jsou BIRDem přijímány i na jiných zařízení. <br />
<sup>3</sup>) Directed broadcast funguje. Universal broadcast lze poslat pomocí <code>IP_ONESBCAST</code> (directed přepíše na universal)<br />
<sup>4</sup>) Přijímá multicast bez přihlášení do skupiny.<br />
<sup>5</sup>) Vyžaduje správné nastavení směrovacích tabulek. <br />
<sup>6</sup>) Při odesílání nelze nastavit zdrojovou adresou. Chybí <code>IP_SENDSRCADDR</code>. <br />
<sup>7</sup>) Universal broadcast se odesílá na systémový výchozí interface. <code>IP_ONESBCAST</code> na systému neexistuje. <br />
<sup>8</sup>) TTL nelze nastavit a odesílá TTL 1

`SO_DONTROUTE` **neumožní** odesílání IPv4 Unicast zpráv při nesprávném nastavení směrovacích tabulek a samozřejmě při IPv4 Multicastu (Raw/UDP) způsobí chybu `Network is unreachable`.

