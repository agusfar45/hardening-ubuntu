"""
simulador.py - Imita los comandos de sistema que usa hardening_ubuntu.sh, para probarlo sin Ubuntu.

Cada comando (sshd, systemctl, ufw, ...) es un script de 1 línea en esta carpeta que llama a este
archivo con su nombre. El estado vive en $HARDENING_STUB_ESTADO y los archivos de configuración en
$HARDENING_RAIZ (la "raíz" falsa del sistema). Cada llamada se anota en llamadas.log.

Lo importante que reproduce:
  - sshd -T calcula la configuración EFECTIVA como OpenSSH: expande los Include en orden y
    GANA EL PRIMER VALOR (así se puede probar la trampa del 50-cloud-init.conf)
  - sshd -t rechaza opciones desconocidas
  - ufw guarda reglas sin duplicar y escribe /etc/ufw/user.rules
"""
import glob
import hashlib
import base64
import json
import os
import re
import sys
from pathlib import Path

RAIZ = Path(os.environ["HARDENING_RAIZ"])
ESTADO = Path(os.environ["HARDENING_STUB_ESTADO"])
ESTADO.mkdir(parents=True, exist_ok=True)

DEFAULTS_SSHD = {"port": "22", "passwordauthentication": "yes", "kbdinteractiveauthentication": "yes",
                 "permitrootlogin": "prohibit-password", "pubkeyauthentication": "yes", "maxauthtries": "6",
                 "loglevel": "INFO", "x11forwarding": "no", "permitemptypasswords": "no", "logingracetime": "120",
                 "allowagentforwarding": "yes", "clientaliveinterval": "0", "clientalivecountmax": "3", "usepam": "no"}
CONOCIDAS = set(DEFAULTS_SSHD) | {"include", "match", "subsystem", "acceptenv", "printmotd", "allowusers",
                                  "hostkey", "chrootdirectory", "forcecommand", "authorizedkeysfile"}
DEFAULTS_SYSCTL = {"net.ipv4.tcp_syncookies": "1", "net.ipv4.conf.all.accept_redirects": "1",
                   "net.ipv4.conf.all.send_redirects": "1", "net.ipv4.conf.all.log_martians": "0",
                   "net.ipv4.conf.all.rp_filter": "2"}


def leer_json(nombre, defecto):
    p = ESTADO / nombre
    return json.loads(p.read_text()) if p.exists() else defecto


def guardar_json(nombre, dato):
    (ESTADO / nombre).write_text(json.dumps(dato))


def lineas_sshd(ruta, visitados=None):
    """Recorre la configuración como sshd: los Include se expanden en el lugar, en orden alfabético."""
    for linea in Path(ruta).read_text(encoding="utf-8").splitlines():
        linea = linea.split("#", 1)[0].strip()
        if not linea:
            continue
        partes = linea.split(None, 1)
        clave, valor = partes[0].lower(), (partes[1] if len(partes) > 1 else "")
        if clave == "include":
            for patron in valor.split():
                for inc in sorted(glob.glob(str(RAIZ) + patron)):
                    yield from lineas_sshd(inc)
        else:
            yield clave, valor


def sshd(args):
    principal = RAIZ / "etc/ssh/sshd_config"
    if "-t" in args:
        if os.environ.get("HARDENING_STUB_SSHD_FALLA") == "1":
            print("/etc/ssh/sshd_config.d/00-hardening.conf: line 3: Bad configuration option: simulada", file=sys.stderr)
            return 255
        for clave, _ in lineas_sshd(principal):
            if clave not in CONOCIDAS:
                print(f"Bad configuration option: {clave}", file=sys.stderr)
                return 255
        return 0
    if "-T" in args:
        efectiva = {}
        for clave, valor in lineas_sshd(principal):
            if clave == "match":
                break
            efectiva.setdefault(clave, valor.lower() if clave != "allowusers" else valor)  # GANA EL PRIMERO
        for k, v in DEFAULTS_SSHD.items():
            efectiva.setdefault(k, v.lower())
        for k, v in efectiva.items():
            print(f"{k} {v}")
        return 0
    return 1


def systemctl(args):
    activos = set(leer_json("activos.json", []))
    if args[:2] == ["is-active", "--quiet"]:
        return 0 if args[2] in activos else 3
    servicio = args[-1]
    if args[0] in ("enable", "start", "restart") or "--now" in args:
        activos.add(servicio)
    guardar_json("activos.json", sorted(activos))
    return 0


def dpkg(args):
    return 0 if args[0] == "-s" and args[1] in leer_json("paquetes.json", []) else 1


def apt_get(args):
    if "install" in args:
        instalados = set(leer_json("paquetes.json", []))
        instalados.update(a for a in args[args.index("install") + 1:] if not a.startswith("-"))
        guardar_json("paquetes.json", sorted(instalados))
    return 0


def ufw(args):
    e = leer_json("ufw.json", {"activo": False, "entrada": "allow", "salida": "allow", "reglas": [], "logging": "off"})
    if args[0] == "status":
        print(f"Status: {'active' if e['activo'] else 'inactive'}")
        if "verbose" in args:
            print(f"Logging: {e['logging']}\nDefault: {e['entrada']} (incoming), {e['salida']} (outgoing), disabled (routed)")
        for r in e["reglas"]:
            print(r)
        return 0
    if args[0] == "default":
        e["entrada" if args[2] == "incoming" else "salida"] = args[1]
    elif args[0] in ("allow", "limit"):
        regla = " ".join(args)
        if regla in e["reglas"]:
            print("Skipping adding existing rule")
        else:
            e["reglas"].append(regla)
            print("Rule added")
        reglas = RAIZ / "etc/ufw/user.rules"
        reglas.parent.mkdir(parents=True, exist_ok=True)
        reglas.write_text("*filter\n" + "".join(f"### tuple ### {r}\n" for r in e["reglas"]) + "COMMIT\n")
    elif args[0] == "logging":
        e["logging"] = args[1]
    elif args[-1] == "enable":
        e["activo"] = True
    elif args[-1] == "disable":
        e["activo"] = False
    guardar_json("ufw.json", e)
    return 0


def fail2ban_client(args):
    jail = RAIZ / "etc/fail2ban/jail.d/hardening.local"
    activo = "fail2ban" in leer_json("activos.json", [])
    ok = activo and jail.exists() and re.search(r"\[sshd\]\s*\nenabled = true", jail.read_text())
    return 0 if ok else 255


def auditctl(args):
    if "-s" in args:
        print("enabled 2" if os.environ.get("HARDENING_STUB_AUDIT_INMUTABLE") == "1" else "enabled 1")
        return 0
    if "-l" in args and (ESTADO / "audit_cargado").exists():
        for f in sorted((RAIZ / "etc/audit/rules.d").glob("*.rules")):
            for linea in f.read_text().splitlines():
                if linea.startswith("-"):
                    print(linea)
    return 0


def augenrules(args):
    (ESTADO / "audit_cargado").touch()
    return 0


def sysctl(args):
    if "--system" in args:
        (ESTADO / "sysctl_aplicado").touch()
        return 0
    valores = dict(DEFAULTS_SYSCTL)
    if (ESTADO / "sysctl_aplicado").exists():
        for f in sorted((RAIZ / "etc/sysctl.d").glob("*.conf")):
            for linea in f.read_text().splitlines():
                if "=" in linea and not linea.startswith("#"):
                    k, v = linea.split("=", 1)
                    valores[k.strip()] = v.strip()
    print(valores.get(args[-1], "0"))
    return 0


def ssh_keygen(args):
    archivo = Path(args[args.index("-f") + 1])
    patron = re.compile(r"(?:^|\s)(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp\d+)\s+([A-Za-z0-9+/=]{40,})(\s+(.*))?$")
    huellas = []
    for linea in archivo.read_text().splitlines():
        m = patron.search(linea)
        if m:
            h = base64.b64encode(hashlib.sha256(m.group(2).encode()).digest()).decode().rstrip("=")
            tipo = {"ssh-ed25519": "ED25519", "ssh-rsa": "RSA"}.get(m.group(1), "ECDSA")
            huellas.append(f"256 SHA256:{h} {m.group(4) or 'sin comentario'} ({tipo})")
    if not huellas:
        print(f"{archivo} is not a public key file.", file=sys.stderr)
        return 255
    print("\n".join(huellas))
    return 0


COMANDOS = {"sshd": sshd, "systemctl": systemctl, "dpkg": dpkg, "apt-get": apt_get, "ufw": ufw,
            "fail2ban-client": fail2ban_client, "auditctl": auditctl, "augenrules": augenrules,
            "sysctl": sysctl, "ssh-keygen": ssh_keygen}

if __name__ == "__main__":
    nombre, args = sys.argv[1], sys.argv[2:]
    with open(ESTADO / "llamadas.log", "a", encoding="utf-8") as f:
        f.write(" ".join([nombre, *args]) + "\n")
    sys.exit(COMANDOS[nombre](args))
