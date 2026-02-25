**Istruzioni di esecuzione**
------------
Creazione ambiente

Assicurati di avere Python 3.11+ installato.

Posizionati nella root del progetto:
```
ToolAnalisiDomini/
```
Crea e attiva l’ambiente virtuale:
```
python -m venv .venv
.venv\Scripts\activate
```
Nota: su Linux / macOS utilizzare source .venv/bin/activate.

Installazione dipendenze
```
pip install -r requirements.txt
```
Configurazione credenziali API (variabili d’ambiente)

Su PowerShell:
```
$env:SHODAN_API_KEY="LA_TUA_CHIAVE_SHODAN"
$env:VT_API_KEY="LA_TUA_CHIAVE_VIRUSTOTAL"
```
Se una delle due variabili non è impostata, il tool salterà automaticamente
l’integrazione corrispondente e lo segnalerà nel report finale.

Esecuzione analisi
```
python main.py --domain example.com --output-dir output
```
