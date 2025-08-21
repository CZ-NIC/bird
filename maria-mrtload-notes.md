## úplně obecně

- ten styl je dost slušnej, 

## koncepčně k MRT loadu

- napiš prosím aspoň rudimentární dokumentaci do `doc/bird.sgml` → od řádku 4614 dál
  je sekce `MRT` … která potřebuje evidentně poněkud výrazně reformulovat, ale
  zkus tam prosím někam aspoň vrazit podsekci o loadingu, reformulace počkají
- místo `FILE *` přímo prosím použij `struct rfile`:
  - `struct rfile *rf_open(pool *p, const char *name, const char *mode)`
- zvážila bych loadovat ten dump po větších kusech a číst z něj standardně funkcema
    `get_u(8,16,24,32,64)` apod. z `lib/unaligned.h` místo `mrtload_two_octet` apod.
- na začátek `mrtload.c` určitě patří delší komentář s popisem, co ta věc vlastně dělá,
  jakože jak vyrábí channely, jakým způsobem přistupuje k `rte_src` apod., jaké jsou caveats

## `mrt_load.h`

- `MRTLOAD_CTX_*` určitě nepatří do H souboru, to jsou privátní parametry
- parametr `time_replay` mi připadá neintuitivně pojmenovaný, co třeba něco jako `replay_accel`?
- `addr_fam` je `afi`, nebo `net_type`?
- prosím prosím komentáře ke všem položkám struktur, takhle se strašně těžko orientuje, co je co zač
  (kromě technických věcí jako `struct proto p;` na prvním místě `mrtload_proto` apod.)

## `mrt_load.c`

řádek 177: 

```
if (afi == 0)
  afi = peer->afi;
else if (afi != peer->afi)
  return;
```

`mrt_parse_general_header` → `case` za sebou nepotřebuje závorku a tbh vypadá to neočekávaně

`mrtload_hook` → `while (loaded < (1<<14))` vypadá hrozně arbitrárně, prosím komentář do kódu, dtto `mrtload_hook_replay`

pojmenování funkce na řádku 606 (`mrtload`) nesedí do stylu, možná `mrtload_start_loading`?

do `mrtload_shutdown` určitě nepatří mazání vlastních rout, to udělá tabulka sama,
a kontexty stejně tak není potřeba snad mazat vůbec, protože jsou alokované z `p->ctx_pool`,
který se smaže sám vypnutím protokolu, takže nejspíš ten shutdown hook vůbec není potřeba
(přepnutí na `PS_DOWN` se udělá automaticky, když tam není)

mhm, `mrtload_reconfigure()` by asi měl přinejmenším zavolat rekonfiguraci channelů,
a nejsu si jistá, jestli i něco dalšího

co když přijde reconf dřív, než jsme doloadovali?

ha! zavírá se někde ten soubor, co se loaduje?


## mrtload.Y

- konfigurační syntaxe vypadá docela krejzy (s tím pomůže dokumentace, kde
  napíšeme, jak se ta věc vlastně používá)

## styl obecně

- asi by stálo za to, pokud máme nějaké společné MRT věci, je mít v `mrt.c`,
  a zbytek v `dump.c` a `load.c`, protože teď `mrt_load.c` vypadá dost jako
  přílepek
- `mrtload.Y` je dostatečně malý na to, aby mohl být součástí `config.Y` imho
- chceme `mrt_load`, nebo `mrtload`?
- možná i v konfiguraci by mohlo fungovat `PROTOCOL MRT LOAD`
- přihodila jsem do c,h souborů naše standardní "hlavičky" v komentářích;
  pokud tam chceš jiný mail, tak si ho tam přepiš
