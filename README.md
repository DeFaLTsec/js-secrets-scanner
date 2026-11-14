# 🔎 JS-Secrets-Scanner (`jsscan`)

Escáner asíncrono que encuentra **secretos, tokens y endpoints** en JavaScript:
páginas web, chunks de webpack, source maps y archivos locales.

> ⚠️ **Uso legal**: ejecútalo únicamente contra sistemas propios o con autorización
> expresa y por escrito (pentest, bug bounty dentro de alcance).

## Características
- Descubre `<script src>`, chunks referenciados y **source maps** (`sourcesContent`).
- Reglas en YAML fáciles de ampliar (`rules/default.yml`).
- Filtro de falsos positivos (placeholders) y **entropía de Shannon**.
- Valores **redactados** por defecto en los reportes.
- Salida en consola (rich), JSON y HTML.
- Soporte de proxy (Burp), cabeceras/cookies y modo `--stdin`.

## Instalación
```bash
git clone https://github.com/<tu-usuario>/js-secrets-scanner
cd js-secrets-scanner
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Uso
```bash
jsscan https://objetivo.tld                       # una URL
jsscan -l urls.txt --json out.json --html out.html
cat urls.txt | jsscan --stdin --proxy http://127.0.0.1:8080
jsscan ./bundle_descargado/                       # directorio local
jsscan https://objetivo.tld -H "Cookie: session=abc" -k
```
Código de salida: `0` sin hallazgos, `1` con hallazgos (útil en CI).

## Añadir reglas
```yaml
- id: mi-token
  name: Mi servicio token
  severity: high
  regex: '\bmy_[a-z0-9]{32}\b'
```

## Tests
```bash
pytest
```

## Roadmap
- [ ] Verificación opcional de claves (`--verify`, solo lectura)
- [ ] Reglas para más proveedores
- [ ] Plantilla de GitHub Action
- [ ] Salida SARIF

## Licencia
MIT
