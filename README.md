# 🛡️ BYEVIRUS v3.0

Scanner de segurança local para Linux, escrito em **Python puro (stdlib)** — sem dependências externas.

Varre o sistema em busca de indicadores de comprometimento (IoC) e gera relatórios estruturados em **JSON + TXT**, com score de risco e exit codes para automação.

---

## ✨ O que ele detecta

| Módulo | O que verifica |
|---|---|
| 🔌 **Extensões** | Extensões de navegador (Chrome, Brave, Edge, Chromium, Vivaldi, Opera) com permissões perigosas (`cookies`, `passwords`, `webRequest`, acesso a todos os sites, etc.) |
| 📁 **Arquivos** | Executáveis/scripts em pastas quentes (`/tmp`, `/dev/shm`, Downloads, Desktop), com análise de conteúdo por **regex** e hash **SHA-256** |
| 🌐 **Portas** | Portas clássicas de backdoor/C2 abertas (4444 Metasploit, 5555 ADB, 31337 Back Orifice, etc.) |
| ⚙️ **Processos** | Ferramentas de ataque rodando (netcat, msfconsole, mimikatz, hydra, sqlmap, etc.) |
| 🚀 **Persistência** | Código suspeito em `.bashrc`, `.zshrc`, cron, autostart e **systemd** (unit files e user services) |

---

## 🚀 Uso

```bash
# Scan completo (relatórios JSON + TXT na pasta atual)
python3 byevirus_v3.py

# Diretórios extras para varrer
python3 byevirus_v3.py -d /opt/servidor -d /var/www

# Apenas relatório JSON, salvo em ./relatorios
python3 byevirus_v3.py -f json -o ./relatorios

# Rodar só alguns módulos
python3 byevirus_v3.py --modulos portas,processos

# Modo silencioso (só erros)
python3 byevirus_v3.py -q
```

### Parâmetros

| Flag | Descrição |
|---|---|
| `-d, --dir` | Diretório extra para varrer (pode repetir) |
| `-o, --output` | Pasta onde os relatórios serão salvos (padrão: atual) |
| `-f, --formato` | `txt`, `json` ou `ambos` (padrão: `ambos`) |
| `-q, --quiet` | Só log de erro |
| `--modulos` | `todos` ou lista separada por vírgula: `extensões,arquivos,portas,processos,persistência` |

---

## 🔢 Exit codes

| Código | Significado |
|---|---|
| `0` | Sistema limpo |
| `1` | Pelo menos um achado de risco **MEDIO** |
| `2` | Pelo menos um achado de risco **ALTO/CRÍTICO** |

Ideal para scripts, cron e CI/CD:

```bash
#!/bin/bash
python3 byevirus_v3.py -q -o ./relatorios || {
    echo "⚠️ Ameaças detectadas!" | mail -s "Alerta BYEVIRUS" admin@exemplo.com
}
```

Ou no crontab (scan diário às 6h):

```cron
0 6 * * * cd /opt/byevirus && python3 byevirus_v3.py -q -o ./relatorios
```

---

## 📊 Saída

**Console:**
```
================================================================
  SCAN COMPLETO em 2.3s — 5 achados | score de risco 14
  🚨 CRITICO: 1
  🔴 ALTO: 3
  🟡 MEDIO: 1
  📄 relatorios/relatorio_20260914_061500.txt
  📄 relatorios/relatorio_20260914_061500.json
================================================================
```

**JSON** (exemplo de achado):
```json
{
  "modulo": "arquivos",
  "severidade": "CRITICO",
  "titulo": "/tmp/payload.sh",
  "descricao": ".sh | 2048 bytes | perms 0o777",
  "metadados": {
    "sha256": "a94f8b2...",
    "padroes": ["shell reversa/bind", "conexão de rede via socket"]
  }
}
```

> 💡 **Dica:** copie o `sha256` de qualquer arquivo suspeito e cole em [VirusTotal](https://www.virustotal.com) para verificar se é malware conhecido.

---

## ⚠️ Limitações (seja honesto com você mesmo)

- **Não é antivírus nem SIEM.** É um scanner de IoCs estáticos — ele acha *indícios*, não provas.
- Não remove nada automaticamente. Toda ação de quarentena/remoção é sua decisão.
- Análise de conteúdo lê no máx. 200 KB por arquivo e é baseada em padrões conhecidos — malware bom se esconde.
- Roda melhor como root para acessar todos os arquivos, mas também funciona como usuário comum (com cobertura reduzida).

---

## 🗺️ Roadmap (ideias para v4)

- [ ] Modo daemon com varredura agendada + banco SQLite histórico
- [ ] Alertas em tempo real (Telegram / email / webhook)
- [ ] Correlação de eventos (porta aberta + processo suspeito = CRÍTICO)
- [ ] Verificação de hashes contra listas públicas (MalwareBazaar)
- [ ] Quarentena automática opcional

---

## 📜 Licença

Código aberto — use, modifique e distribua livremente. Use com responsabilidade, apenas em sistemas que você tem autorização para analisar.
