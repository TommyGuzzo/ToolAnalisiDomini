Creazione ambiente
Assicurati di avere Python 3.11+.
Posizionati nella root del progetto (ToolAnalisiDomini).
Installazione dipendenze
python -m venv .venv.venv\Scripts\activate  # su Windowspip install -r requirements.txt
Configurazione credenziali API via variabili d’ambiente
Su PowerShell:
$env:SHODAN_API_KEY="LA_TUA_CHIAVE_SHODAN"$env:VT_API_KEY="LA_TUA_CHIAVE_VIRUSTOTAL"
(Se una delle due non è impostata, il tool salterà la relativa integrazione segnalandolo nel report.)
Esecuzione analisi
python main.py --domain example.com --output-dir output