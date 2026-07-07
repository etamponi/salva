"""salva — assistente per la messa in sicurezza di infrastrutture Linux.

Due funzioni principali:
  * consigli  (best practice curate, `salva advice`)
  * audit     (controlli read-only sul sistema, `salva check`)

Tutti i controlli sono di sola lettura: salva non modifica nulla, si limita
a osservare la configurazione e a suggerire come correggerla.
"""

__version__ = "0.2.2"
