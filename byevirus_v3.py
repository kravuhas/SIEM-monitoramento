#!/usr/bin/env python3
"""
================================================================
 BYEVIRUS v3.0 - Scanner de Segurança Local
 Melhorias sobre a v2.0:
   - Arquitetura modular (cada módulo retorna Findings tipados)
   - CLI com argparse (diretórios extras, formato de relatório, verbose)
   - Severidade numérica com score (LOW/MEDIUM/HIGH/CRITICAL)
   - Hash SHA-256 dos arquivos suspeitos (para checar no VirusTotal)
   - Scanner de arquivos com ThreadPoolExecutor (paralelo)
   - Padrões de código suspeito via REGEX (muito mais preciso que substring)
   - Relatório em JSON + TXT estruturado
   - Log profissional com módulo `logging`
   - Código de saída (exit code) para uso em scripts/cron
   - Sem dependências externas (só stdlib)
================================================================
"""

import argparse
import hashlib
import json
import logging
import os
import re
import stat
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

VERSION = "3.0"

# ----------------------------------------------------------------
# SEVERIDADE
# ----------------------------------------------------------------
SEV_INFO, SEV_LOW, SEV_MED, SEV_HIGH, SEV_CRIT = 0, 1, 2, 3, 4
SEVERIDADE_NOME  = {0: "INFO", 1: "BAIXO", 2: "MEDIO", 3: "ALTO", 4: "CRITICO"}
SEVERIDADE_EMOJI = {0: "ℹ️ ", 1: "🟢", 2: "🟡", 3: "🔴", 4: "🚨"}

log = logging.getLogger("byevirus")


# ----------------------------------------------------------------
# FINDING (resultado tipado de qualquer módulo)
# ----------------------------------------------------------------
@dataclass
class Finding:
    modulo: str
    severidade: int
    titulo: str
    descricao: str = ""
    metadados: dict = field(default_factory=dict)

    @property
    def emoji(self):
        return SEVERIDADE_EMOJI[self.severidade]


# ----------------------------------------------------------------
# CONFIGURAÇÃO
# ----------------------------------------------------------------
PERMISSOES_PERIGOSAS = [
    "tabs", "webRequest", "webRequestBlocking", "cookies", "history",
    "passwords", "bookmarks", "downloads", "clipboardRead", "geolocation",
    "nativeMessaging", "proxy", "privacy", "contentSettings", "management",
    "declarativeNetRequest", "declarativeNetRequestFeedback",
]

# Regex >> substring: reduz falsos positivos e pega variações
PADROES_CODIGO_SUSPEITO = [
    (r"reverse[_-]?shell|bind[_-]?shell", "shell reversa/bind"),
    (r"subprocess\.(call|run|Popen).*shell\s*=\s*True", "subprocess com shell=True"),
    (r"\b(os\.system|os\.popen|commands\.getoutput)\b", "execução de comando via os"),
    (r"(eval|exec)\s*\(\s*(base64|bytes\.fromhex|codecs\.decode)", "eval/exec ofuscado"),
    (r"base64\.b64decode", "decodificação base64"),
    (r"ctypes\.(windll|cdll|CDLL)", "carregamento de DLL nativa"),
    (r"\b(keylogger|rootkit|backdoor|trojan|ransomware|wannacry)\b", "termo malware"),
    (r"socket\.socket.*\.connect\(", "conexão de rede via socket"),
    (r"\bparamiko\b", "SSH programático (paramiko)"),
    (r"\b(msfvenom|metasploit|msfconsole)\b", "ferramenta de ataque"),
]
PADROES_REGEX = [(re.compile(p, re.IGNORECASE), nome) for p, nome in PADROES_CODIGO_SUSPEITO]

EXTENSOES_PERIGOSAS = {
    ".exe", ".bat", ".sh", ".bin", ".run", ".vbs", ".ps1",
    ".php", ".jar", ".msi", ".elf", ".out", ".ko", ".so",
    ".scr", ".com", ".cmd", ".dll",
}

PASTAS_SUSPEITAS = [
    "/tmp", "/var/tmp", "/dev/shm",
    str(Path.home() / "Downloads"),
    str(Path.home() / "Desktop"),
]

PORTAS_SUSPEITAS = {
    "4444": "Metasploit reverse shell", "1337": "Backdoor clássico",
    "31337": "Back Orifice", "5555": "ADB / Android Debug",
    "6666": "Malware comum", "9999": "Trojan comum",
    "1234": "Backdoor genérico", "8888": "Tunnel/Proxy suspeito",
    "2222": "SSH alternativo suspeito", "12345": "NetBus trojan",
}

PROCESSOS_SUSPEITOS = [
    "ncat", "netcat", "nc -l", "msfconsole", "msfvenom", "wireshark",
    "tcpdump", "keylogger", "hydra", "sqlmap", "john", "hashcat",
    "aircrack", "ettercap", "bettercap", "arpspoof", "mimikatz", "responder",
]

LOCAIS_PERSISTENCIA = [
    "~/.bashrc", "~/.zshrc", "~/.profile", "~/.bash_profile",
    "~/.config/autostart", "/etc/cron.d", "/var/spool/cron", "/etc/init.d",
    "~/.config/systemd/user", "/etc/systemd/system", "/etc/rc.local",
]


# ----------------------------------------------------------------
# HELPERS
# ----------------------------------------------------------------
def sha256_arquivo(caminho: Path, bloco=65536) -> str:
    h = hashlib.sha256()
    try:
        with open(caminho, "rb") as f:
            for chunk in iter(lambda: f.read(bloco), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return "indisponível"


def ler_com_regex(caminho: Path, limite=200_000) -> list:
    """Retorna lista de nomes de padrões suspeitos encontrados no arquivo."""
    try:
        conteudo = caminho.read_text(encoding="utf-8", errors="ignore")[:limite]
    except OSError:
        return []
    return [nome for rx, nome in PADROES_REGEX if rx.search(conteudo)]


def run(cmd: list) -> str:
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=10).decode("utf-8", "ignore")
    except Exception:
        return ""


# ----------------------------------------------------------------
# MÓDULOS
# ----------------------------------------------------------------
def escanear_extensoes() -> list:
    log.info("Módulo extensões")
    navegadores = {
        "Chrome":   "~/.config/google-chrome/Default/Extensions",
        "Chromium": "~/.config/chromium/Default/Extensions",
        "Brave":    "~/.config/brave-browser/Default/Extensions",
        "Edge":     "~/.config/microsoft-edge/Default/Extensions",
        "Vivaldi":  "~/.config/vivaldi/Default/Extensions",
        "Opera":    "~/.config/opera/Extensions",
    }
    achados = []
    for nav, pasta in navegadores.items():
        p = Path(pasta).expanduser()
        if not p.is_dir():
            continue
        for id_ext in p.iterdir():
            if not id_ext.is_dir():
                continue
            for versao in id_ext.iterdir():
                manifest_path = versao / "manifest.json"
                if not manifest_path.is_file():
                    continue
                try:
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError, OSError):
                    continue
                perms = [x for x in manifest.get("permissions", [])
                               + manifest.get("host_permissions", []) if isinstance(x, str)]
                riscos = [x for x in perms if x in PERMISSOES_PERIGOSAS]
                if any(x in ("<all_urls>", "http://*/*", "https://*/*") for x in perms):
                    riscos.append("ACESSO A TODOS OS SITES")
                sev = SEV_CRIT if len(riscos) >= 3 else SEV_MED if riscos else SEV_LOW
                achados.append(Finding(
                    modulo="extensoes", severidade=sev,
                    titulo=f"[{nav}] {manifest.get('name', 'Desconhecido')} v{manifest.get('version', '?')}",
                    descricao=", ".join(riscos) if riscos else "Sem permissões perigosas",
                    metadados={"navegador": nav, "permissoes_risco": riscos,
                               "descricao": manifest.get("description", "")[:120]},
                ))
    return achados


def _analisar_arquivo(caminho: Path) -> Finding | None:
    ext = caminho.suffix.lower()
    if ext not in EXTENSOES_PERIGOSAS:
        return None
    padroes = ler_com_regex(caminho) if ext in {".sh", ".py", ".php", ".ps1", ".bat", ".vbs"} else []
    try:
        info = caminho.stat()
        perms = oct(stat.S_IMODE(info.st_mode))
    except OSError:
        perms = "?"
    sev = SEV_CRIT if padroes else SEV_HIGH
    return Finding(
        modulo="arquivos", severidade=sev,
        titulo=str(caminho),
        descricao=f"{ext} | {info.st_size} bytes | perms {perms}" if perms != "?" else ext,
        metadados={"extensao": ext, "tamanho": info.st_size, "permissoes": perms,
                   "sha256": sha256_arquivo(caminho), "padroes": padroes},
    )


def escanear_arquivos(pastas_extra: list) -> list:
    log.info("Módulo arquivos")
    alvos = [Path(p).expanduser() for p in PASTAS_SUSPEITAS + pastas_extra]
    candidatos = []
    for pasta in alvos:
        if not pasta.is_dir():
            continue
        try:
            candidatos += [f for f in pasta.iterdir()
                           if f.is_file() and f.suffix.lower() in EXTENSOES_PERIGOSAS]
        except PermissionError:
            log.warning("Sem permissão em %s", pasta)
    # Scripts .py na pasta atual
    candidatos += [f for f in Path(".").glob("*.py")
                   if f.name != Path(__file__).name and f.is_file()]
    with ThreadPoolExecutor(max_workers=8) as pool:
        resultados = list(pool.map(_analisar_arquivo, candidatos))
    achados = [r for r in resultados if r is not None]
    # Scripts python com padrões suspeitos (mesmo sem extensão perigosa)
    for f in Path(".").glob("*.py"):
        if f.name == Path(__file__).name:
            continue
        padroes = ler_com_regex(f)
        if padroes:
            achados.append(Finding(
                modulo="arquivos", severidade=SEV_MED,
                titulo=str(f.resolve()),
                descricao="padrões suspeitos em script local",
                metadados={"padroes": padroes, "sha256": sha256_arquivo(f)},
            ))
    return achados


def escanear_portas() -> list:
    log.info("Módulo portas")
    saida = run(["ss", "-tuln"])
    achados = []
    for porta, motivo in PORTAS_SUSPEITAS.items():
        if re.search(rf":{porta}\b", saida):
            linha = next((l.strip() for l in saida.splitlines() if re.search(rf":{porta}\b", l)), "")
            achados.append(Finding(
                modulo="portas", severidade=SEV_HIGH,
                titulo=f"Porta {porta} aberta",
                descricao=motivo, metadados={"porta": porta, "ss": linha},
            ))
    return achados


def escanear_processos() -> list:
    log.info("Módulo processos")
    saida = run(["ps", "aux"]).lower()
    return [Finding(modulo="processos", severidade=SEV_HIGH,
                    titulo=f"Processo suspeito: {proc}",
                    metadados={"processo": proc})
            for proc in PROCESSOS_SUSPEITOS if proc.lower() in saida]


def escanear_persistencia() -> list:
    log.info("Módulo persistência")
    achados = []
    for local in LOCAIS_PERSISTENCIA:
        p = Path(local).expanduser()
        if not p.exists():
            continue
        if p.is_file():
            padroes = ler_com_regex(p)
            if padroes:
                achados.append(Finding(
                    modulo="persistencia", severidade=SEV_CRIT,
                    titulo=f"Código suspeito em {p}",
                    descricao=", ".join(padroes[:3]),
                    metadados={"local": str(p), "padroes": padroes},
                ))
        elif p.is_dir():
            try:
                itens = list(p.iterdir())
            except PermissionError:
                continue
            for item in itens:
                if item.is_file() and item.suffix.lower() in {".sh", ".desktop", ".py", ".service"}:
                    padroes = ler_com_regex(item)
                    if padroes:
                        achados.append(Finding(
                            modulo="persistencia", severidade=SEV_CRIT,
                            titulo=f"Código suspeito em {item}",
                            descricao=", ".join(padroes[:3]),
                            metadados={"local": str(item), "padroes": padroes},
                        ))
    return achados


# ----------------------------------------------------------------
# RELATÓRIO
# ----------------------------------------------------------------
def gerar_relatorios(achados: list, saida_dir: Path, formato: str):
    agora = datetime.now()
    timestamp = agora.strftime("%Y%m%d_%H%M%S")
    saida_dir.mkdir(parents=True, exist_ok=True)

    contagem = {s: sum(1 for a in achados if a.severidade == s) for s in SEVERIDADE_NOME}
    resumo = {
        "scanner": f"BYEVIRUS v{VERSION}",
        "gerado_em": agora.isoformat(),
        "host": os.uname().nodename,
        "total": len(achados),
        "por_severidade": {SEVERIDADE_NOME[k]: v for k, v in contagem.items() if v},
        "score_risco": sum(a.severidade for a in achados),
    }

    arquivos = []
    if formato in ("txt", "ambos"):
        txt = saida_dir / f"relatorio_{timestamp}.txt"
        with open(txt, "w", encoding="utf-8") as f:
            f.write("=" * 64 + "\n  BYEVIRUS v%s - RELATÓRIO DE SEGURANÇA\n" % VERSION)
            f.write(f"  {resumo['gerado_em']} | Host: {resumo['host']}\n" + "=" * 64 + "\n\n")
            f.write(f"Total: {resumo['total']} | Score de risco: {resumo['score_risco']}\n")
            for sev in sorted(SEVERIDADE_NOME, reverse=True):
                if contagem[sev]:
                    f.write(f"  {SEVERIDADE_EMOJI[sev]} {SEVERIDADE_NOME[sev]}: {contagem[sev]}\n")
            f.write("\n" + "=" * 64 + "\nDETALHES\n" + "=" * 64 + "\n\n")
            for a in sorted(achados, key=lambda x: -x.severidade):
                f.write(f"{a.emoji} [{SEVERIDADE_NOME[a.severidade]}] ({a.modulo}) {a.titulo}\n")
                if a.descricao:
                    f.write(f"    {a.descricao}\n")
                for k, v in a.metadados.items():
                    f.write(f"    {k}: {v}\n")
                f.write("-" * 64 + "\n")
        arquivos.append(txt)

    if formato in ("json", "ambos"):
        js = saida_dir / f"relatorio_{timestamp}.json"
        payload = {**resumo, "achados": [
            {**asdict(a), "severidade": SEVERIDADE_NOME[a.severidade]} for a in achados
        ]}
        js.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        arquivos.append(js)

    return arquivos, resumo


# ----------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description=f"BYEVIRUS v{VERSION} - Scanner de segurança local",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("-d", "--dir", action="append", default=[],
                    help="diretório extra para varrer (pode repetir)")
    ap.add_argument("-o", "--output", default=".",
                    help="diretório dos relatórios (padrão: atual)")
    ap.add_argument("-f", "--formato", choices=["txt", "json", "ambos"], default="ambos")
    ap.add_argument("-q", "--quiet", action="store_true", help="só log de erro")
    ap.add_argument("--modulos", default="todos",
                    help="módulos: todos | extensões,arquivos,portas,processos,persistência")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(levelname)s [%(name)s] %(message)s",
    )

    mapa_modulos = {
        "extensões": escanear_extensoes, "arquivos": lambda: escanear_arquivos(args.dir),
        "portas": escanear_portas, "processos": escanear_processos,
        "persistência": escanear_persistencia,
    }
    ativos = list(mapa_modulos) if args.modulos == "todos" else [
        m.strip() for m in args.modulos.split(",")]

    inicio = time.time()
    achados = []
    for nome in ativos:
        fn = mapa_modulos.get(nome)
        if fn is None:
            log.error("Módulo desconhecido: %s", nome)
            continue
        achados += fn()

    arquivos, resumo = gerar_relatorios(achados, Path(args.output), args.formato)

    print("\n" + "=" * 64)
    print(f"  SCAN COMPLETO em {time.time() - inicio:.1f}s — "
          f"{resumo['total']} achados | score de risco {resumo['score_risco']}")
    for sev in sorted(SEVERIDADE_NOME, reverse=True):
        n = sum(1 for a in achados if a.severidade == sev)
        if n:
            print(f"  {SEVERIDADE_EMOJI[sev]} {SEVERIDADE_NOME[sev]}: {n}")
    for a in arquivos:
        print(f"  📄 {a}")
    print("=" * 64)

    # Exit code: 0 = limpo, 1 = médio+, 2 = alto+
    tem_alto = any(a.severidade >= SEV_HIGH for a in achados)
    tem_medio = any(a.severidade == SEV_MED for a in achados)
    sys.exit(2 if tem_alto else 1 if tem_medio else 0)


if __name__ == "__main__":
    main()
