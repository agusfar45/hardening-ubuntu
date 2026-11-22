"""
Pruebas de hardening_ubuntu.sh sobre un servidor Ubuntu FALSO (carpeta temporal + comandos simulados).
Correr desde la raíz del repo:  python -m unittest -v

El servidor falso reproduce el del Caso 3: SSH con contraseña y root habilitados, un
50-cloud-init.conf que fuerza PasswordAuthentication yes, el usuario 'soporte2' en el grupo
sudo, una cuenta extra con UID 0 y otra sin contraseña.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ_REPO = Path(__file__).resolve().parent.parent
SCRIPT = RAIZ_REPO / "hardening_ubuntu.sh"
STUBS = RAIZ_REPO / "tests" / "stubs"
CLAVE = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyParaPruebasNoEsRealxxxxxxxxxxxxxxxxx admin@notebook"


def bash():
    for candidato in (r"C:\Program Files\Git\bin\bash.exe", shutil.which("bash")):
        if candidato and Path(candidato).exists() and "System32" not in candidato:
            return candidato
    raise unittest.SkipTest("no se encontró bash")


def posix(p):
    """Ruta que entiende el bash de Git en Windows (C:\\x -> C:/x)."""
    return str(p).replace("\\", "/")


def crear_servidor(raiz: Path, version="24.04", con_clave=True, con_include=True):
    def w(rel, texto, modo=0o644):
        p = raiz / rel.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(texto, encoding="utf-8", newline="\n")
        p.chmod(modo)

    w("/etc/os-release", f'NAME="Ubuntu"\nVERSION="{version} LTS"\nID=ubuntu\nVERSION_ID="{version}"\n')
    w("/etc/ssh/sshd_config", ("Include /etc/ssh/sshd_config.d/*.conf\n\n" if con_include else "")
      + "PermitRootLogin yes\nKbdInteractiveAuthentication no\nUsePAM yes\nX11Forwarding yes\n"
        "PrintMotd no\nAcceptEnv LANG LC_*\nSubsystem sftp /usr/lib/openssh/sftp-server\n")
    w("/etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n")
    w("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Admin:/home/admin:/bin/bash\n"
                     "soporte2:x:1001:1001::/home/soporte2:/bin/bash\ntoor:x:0:0::/root:/bin/bash\n"
                     "invitado:x:1002:1002::/home/invitado:/bin/bash\n")
    w("/etc/shadow", "root:*:20000:0:99999:7:::\nadmin:$6$abc$hash:20000:0:99999:7:::\n"
                     "soporte2:$6$def$hash:20406:0:99999:7:::\ntoor:$6$x$y:20000:0:99999:7:::\n"
                     "invitado::20000:0:99999:7:::\n", 0o640)
    w("/etc/group", "root:x:0:\nsudo:x:27:admin,soporte2\nadmin:x:1000:\n")
    w("/etc/default/ufw", 'IPV6=yes\nDEFAULT_INPUT_POLICY="DROP"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\n')
    if con_clave:
        w("/home/admin/.ssh/authorized_keys", CLAVE + "\n", 0o600)
    for herramienta in ("usr/sbin/useradd", "usr/sbin/usermod", "usr/bin/curl", "usr/bin/wget", "usr/bin/shred"):
        w(herramienta, "")
    for carpeta in ("etc/rsyslog.d", "etc/apt/apt.conf.d", "etc/fail2ban/jail.d", "etc/audit/rules.d", "etc/sysctl.d"):
        (raiz / carpeta).mkdir(parents=True, exist_ok=True)


def huella_arbol(raiz: Path, excluir=("var/backups", "var/log")):
    """SHA-256 de todos los archivos (para comprobar que algo no cambió)."""
    h = hashlib.sha256()
    for p in sorted(raiz.rglob("*")):
        rel = p.relative_to(raiz).as_posix()
        if p.is_file() and not rel.startswith(excluir):
            h.update(rel.encode() + p.read_bytes())
    return h.hexdigest()


class Servidor(unittest.TestCase):
    version, con_clave, con_include = "24.04", True, True

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.raiz = Path(self.tmp.name) / "raiz"
        self.estado = Path(self.tmp.name) / "estado"
        crear_servidor(self.raiz, self.version, self.con_clave, self.con_include)
        self.estado.mkdir()
        (self.estado / "activos.json").write_text('["ssh"]')

    def tearDown(self):
        self.tmp.cleanup()

    def correr(self, *args, **env_extra):
        env = {**os.environ, "HARDENING_RAIZ": posix(self.raiz), "HARDENING_STUB_ESTADO": str(self.estado),
               "HARDENING_PY": sys.executable, "SUDO_USER": "admin",
               "SSH_CONNECTION": "192.168.1.10 51000 192.168.1.20 22", "PYTHONIOENCODING": "utf-8",
               "PATH": posix(STUBS) + os.pathsep + os.environ["PATH"] if os.name != "nt"
               else f"{posix(STUBS)}:/usr/bin:/bin:/mingw64/bin", **env_extra}
        p = subprocess.run([bash(), posix(SCRIPT), *args], capture_output=True, env=env)
        salida = p.stdout.decode("utf-8", "replace") + p.stderr.decode("utf-8", "replace")
        return p.returncode, salida

    def llamadas(self):
        f = self.estado / "llamadas.log"
        return f.read_text(encoding="utf-8") if f.exists() else ""

    def leer(self, rel):
        return (self.raiz / rel.lstrip("/")).read_text(encoding="utf-8")

    def respaldo(self):
        dirs = sorted((self.raiz / "var/backups").glob("hardening-*"))
        return dirs[-1] if dirs else None


class Auditoria(Servidor):
    def test_detecta_los_problemas_del_caso3(self):
        codigo, out = self.correr("--auditar")
        self.assertEqual(codigo, 1, out)
        for esperado in ("acepta contraseñas (PasswordAuthentication yes)", "root puede entrar (PermitRootLogin yes)",
                         "UID 0 además de root: toor", "SIN contraseña: invitado", "Grupo sudo: admin,soporte2",
                         "ufw inactivo", "fail2ban: sin protección", "auditd: no hay reglas",
                         "Sin actualizaciones de seguridad automáticas"):
            self.assertIn(esperado, out)
        self.assertEqual(self.llamadas().count("systemctl"), 0)  # auditar no toca servicios

    def test_auditar_y_simular_no_cambian_nada(self):
        antes = huella_arbol(self.raiz)
        self.correr("--auditar")
        codigo, out = self.correr("--simular", "--ssh-desde", "192.168.1.0/24")
        self.assertEqual(codigo, 0, out)
        self.assertIn("+PasswordAuthentication no", out)       # muestra el diff
        self.assertIn("[simulación] ufw --force enable", out)
        self.assertEqual(huella_arbol(self.raiz), antes)
        self.assertIsNone(self.respaldo())
        self.assertNotIn("apt-get install", self.llamadas())


class Aplicar(Servidor):
    def test_aplicar_corrige_todo_y_verifica(self):
        codigo, out = self.correr("--aplicar", "--ssh-desde", "192.168.1.0/24", "--syslog-remoto", "logs.example:514")
        dropin = self.leer("/etc/ssh/sshd_config.d/00-hardening.conf")
        self.assertIn("PasswordAuthentication no", dropin)
        # la configuración EFECTIVA ganó al 50-cloud-init.conf gracias al prefijo 00-
        self.assertIn("SSH: no acepta contraseñas", out.split("--- Después ---")[1])
        self.assertIn("SSH: root no puede entrar", out.split("--- Después ---")[1])
        self.assertIn("allow from 192.168.1.0/24 to any port 22 proto tcp", json.loads((self.estado / "ufw.json").read_text())["reglas"][0])
        self.assertIn("banaction = ufw", self.leer("/etc/fail2ban/jail.d/hardening.local"))
        reglas = self.leer("/etc/audit/rules.d/90-hardening.rules")
        for clave in ("-w /usr/sbin/useradd -p x -k usuarios", "-w /usr/bin/curl -p x -k transferencia",
                      "-w /usr/bin/shred -p x -k antiforense", "-k borrado_logs", "-k comandos_root"):
            self.assertIn(clave, reglas)
        self.assertNotIn("/usr/bin/rsync", reglas)  # solo vigila lo que existe
        self.assertIn('target="logs.example" port="514"', self.leer("/etc/rsyslog.d/90-hardening-remoto.conf"))
        self.assertIn("systemctl reload ssh", self.llamadas())
        self.assertNotIn("systemctl restart ssh\n", self.llamadas())  # reload: no corta la sesión
        # lo que sigue en falta después son problemas de cuentas, que el script informa pero no toca
        despues = out.split("--- Después ---")[1]
        self.assertIn("UID 0 además de root: toor", despues)
        self.assertNotIn("[FALTA] SSH", despues)
        self.assertNotIn("[FALTA] Firewall", despues)
        self.assertEqual(codigo, 1)  # quedan cuentas para revisar

    def test_idempotente(self):
        self.correr("--aplicar")
        primer_respaldo = self.respaldo()
        codigo, out = self.correr("--aplicar")
        self.assertIn("(sin cambios)", out)
        self.assertIn("Skipping adding existing rule", out)
        reglas = json.loads((self.estado / "ufw.json").read_text())["reglas"]
        self.assertEqual(len(reglas), len(set(reglas)))
        self.assertEqual(self.llamadas().count("systemctl reload ssh"), 1)  # la 2.ª vez no recarga

    def test_revertir_deja_todo_como_estaba(self):
        antes = huella_arbol(self.raiz)
        self.correr("--aplicar", "--syslog-remoto", "logs.example:514")
        self.assertNotEqual(huella_arbol(self.raiz), antes)
        respaldo = "/" + self.respaldo().relative_to(self.raiz).as_posix()
        codigo, out = self.correr("--revertir", respaldo)
        self.assertEqual(codigo, 0, out)
        self.assertEqual(huella_arbol(self.raiz, excluir=("var/backups", "var/log", "var/log/journal")), antes)
        self.assertIn("ufw --force disable", self.llamadas())  # estaba inactivo antes

    def test_revertir_rechaza_respaldo_alterado(self):
        self.correr("--aplicar")
        r = self.respaldo()
        self.assertIn("RESPALDO", (r / "MANIFIESTO").read_text())
        (r / "etc/default/ufw").write_text('DEFAULT_INPUT_POLICY="ACCEPT"\n')  # alguien tocó el respaldo
        codigo, out = self.correr("--revertir", "/" + r.relative_to(self.raiz).as_posix())
        self.assertEqual(codigo, 2)
        self.assertIn("no coincide con su hash", out)


class Protecciones(Servidor):
    def test_sin_clave_no_deshabilita_contrasenas(self):
        (self.raiz / "home/admin/.ssh/authorized_keys").write_text("esto no es una clave\n")
        codigo, out = self.correr("--aplicar")
        self.assertIn("NO se deshabilitan las contraseñas", out)
        self.assertFalse((self.raiz / "etc/ssh/sshd_config.d/00-hardening.conf").exists())
        self.assertNotIn("systemctl reload ssh", self.llamadas())
        self.assertTrue((self.raiz / "etc/fail2ban/jail.d/hardening.local").exists())  # el resto sí se aplica

    def test_firewall_no_deja_afuera_a_quien_lo_corre(self):
        codigo, out = self.correr("--aplicar", "--ssh-desde", "10.0.0.0/8")  # la conexión viene de 192.168.1.10
        self.assertIn("No se activa el firewall", out)
        self.assertNotIn("ufw --force enable", self.llamadas())

    def test_sshd_t_falla_y_se_restaura(self):
        original = self.leer("/etc/ssh/sshd_config")
        codigo, out = self.correr("--aplicar", HARDENING_STUB_SSHD_FALLA="1")
        self.assertIn("sshd -t rechazó la configuración", out)
        self.assertFalse((self.raiz / "etc/ssh/sshd_config.d/00-hardening.conf").exists())
        self.assertEqual(self.leer("/etc/ssh/sshd_config"), original)
        self.assertNotIn("systemctl reload ssh", self.llamadas())

    def test_permitir_usuarios_sin_el_admin(self):
        codigo, out = self.correr("--aplicar", "--permitir-usuarios", "otro")
        self.assertIn("te quedarías afuera", out)
        self.assertFalse((self.raiz / "etc/ssh/sshd_config.d/00-hardening.conf").exists())

    def test_no_ubuntu(self):
        (self.raiz / "etc/os-release").write_text('ID=debian\nVERSION_ID="12"\n')
        codigo, out = self.correr("--auditar")
        self.assertEqual(codigo, 2)
        self.assertIn("es para Ubuntu", out)


class Ubuntu2004(Servidor):
    version, con_include = "20.04", False

    def test_agrega_include_al_principio(self):
        codigo, out = self.correr("--aplicar")
        principal = self.leer("/etc/ssh/sshd_config")
        self.assertTrue(principal.startswith("Include /etc/ssh/sshd_config.d/*.conf\n"))
        self.assertIn("SSH: no acepta contraseñas", out.split("--- Después ---")[1])


class Variantes(Servidor):
    def test_fail2ban_journal_o_auth_log(self):
        self.correr("--aplicar")
        self.assertIn("backend = systemd", self.leer("/etc/fail2ban/jail.d/hardening.local"))
        self.assertIn("python3-systemd", self.llamadas())
        # con auth.log (Ubuntu con rsyslog) se usa el backend por defecto
        (self.raiz / "var/log/auth.log").write_text("")
        (self.raiz / "etc/fail2ban/jail.d/hardening.local").unlink()
        self.correr("--aplicar")
        self.assertNotIn("backend", self.leer("/etc/fail2ban/jail.d/hardening.local"))

    def test_ssh_por_socket_sin_servicio_activo(self):
        (self.estado / "activos.json").write_text('["ssh.socket"]')  # Ubuntu 24.04 recién arrancado
        codigo, out = self.correr("--aplicar")
        self.assertIn("activación por socket", out)
        self.assertNotIn("systemctl reload ssh", self.llamadas())
        self.assertIn("SSH: no acepta contraseñas", out.split("--- Después ---")[1])


class AuditoriaApagada(Servidor):
    """Encontrado en el CI: en la imagen de Ubuntu 22.04 de GitHub, auditd corre y las reglas se cargan,
    pero el kernel tiene la auditoría apagada (enabled 0) y no registra nada."""

    def test_detecta_y_activa(self):
        (self.estado / "audit_cargado").touch()
        (self.raiz / "etc/audit/rules.d/90-hardening.rules").write_text("-w /usr/sbin/useradd -p x -k usuarios\n")
        codigo, out = self.correr("--auditar", HARDENING_STUB_AUDIT_APAGADO="1")
        self.assertIn("auditoría del kernel está APAGADA (enabled 0)", out)
        codigo, out = self.correr("--aplicar", HARDENING_STUB_AUDIT_APAGADO="1")
        self.assertIn("-e 1", self.leer("/etc/audit/rules.d/90-hardening.rules"))
        self.assertIn("reglas cargadas y auditoría del kernel activa", out.split("--- Después ---")[1])

    def test_override_de_journald_solo_con_systemd_viejo(self):
        override = self.raiz / "etc/systemd/system/systemd-journald.service.d/90-hardening-auditoria.conf"
        self.correr("--aplicar", HARDENING_STUB_SYSTEMD="249")  # Ubuntu 22.04
        self.assertIn("ExecStartPost=-/sbin/auditctl -e 1", override.read_text())
        self.assertIn("systemctl daemon-reload", self.llamadas())
        override.unlink()
        self.correr("--aplicar", HARDENING_STUB_SYSTEMD="255")  # Ubuntu 24.04: no hace falta
        self.assertFalse(override.exists())


class CambioDePuerto(Servidor):
    def test_puerto_nuevo_y_socket(self):
        (self.estado / "activos.json").write_text('["ssh", "ssh.socket"]')
        codigo, out = self.correr("--aplicar", "--puerto-ssh", "2222")
        self.assertIn("Port 2222", self.leer("/etc/ssh/sshd_config.d/00-hardening.conf"))
        ufw = json.loads((self.estado / "ufw.json").read_text())["reglas"]
        self.assertIn("limit 2222/tcp comment hardening-ssh", ufw)
        self.assertIn("limit 22/tcp comment hardening-ssh-anterior", ufw)  # no se cierra el viejo todavía
        self.assertIn("systemctl restart ssh.socket", self.llamadas())
        self.assertIn("port = 2222", self.leer("/etc/fail2ban/jail.d/hardening.local"))


if __name__ == "__main__":
    unittest.main()
