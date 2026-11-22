# hardening_ubuntu.sh — endurecimiento de servidores Ubuntu

[![Pruebas](https://github.com/agusfar45/hardening-ubuntu/actions/workflows/pruebas.yml/badge.svg)](https://github.com/agusfar45/hardening-ubuntu/actions/workflows/pruebas.yml)

Script en Bash que aplica a un servidor Ubuntu (20.04, 22.04, 24.04) las medidas que **habrían evitado o
dejado registrado** el ataque del [Caso 3 de mi laboratorio forense](https://github.com/agusfar45/laboratorio-perito-informatico/blob/main/writeups/caso3_servidor.md).
Audita antes y después, muestra los cambios antes de hacerlos, guarda respaldo de todo lo que toca y se
puede revertir.

## Del ataque a la medida

| Lo que pasó en el Caso 3 | Medida | Dónde |
|---|---|---|
| Fuerza bruta SSH desde 3 IPs (741 intentos) | SSH **solo con clave**, `MaxAuthTries 3`; **fail2ban** banea por ufw; SSH limitado por tasa o solo desde la red de administración | `paso_ssh`, `paso_fail2ban`, `paso_ufw` |
| Entró con la contraseña de `backup` | Sin login por contraseña (`PasswordAuthentication no`, `KbdInteractiveAuthentication no`) | `paso_ssh` |
| `useradd soporte2` + `usermod -aG sudo` | **auditd** registra creación y modificación de usuarios y cambios en `/etc/passwd`, `/etc/group` y `sudoers`; la auditoría lista los miembros de `sudo` y las cuentas con UID 0 | `paso_auditd`, `auditar` |
| `curl -T /tmp/.c.tgz http://…` (exfiltración) | auditd registra cada ejecución de `curl`, `wget`, `scp`, `rsync`, `nc` | `paso_auditd` |
| `shred -u access.log` (antiforense) | auditd registra `shred` y todo borrado o renombrado en `/var/log`; **journal persistente** y copia a un **syslog remoto** que el intruso no controla | `paso_auditd`, `paso_journald` |
| No se sabía con qué credencial entró | `LogLevel VERBOSE`: el log guarda la **huella de la clave** usada en cada login | `paso_ssh` |

Además: actualizaciones de seguridad automáticas y parámetros de red del kernel (syncookies, sin
redirects, `log_martians`, etc.).

## Uso

```bash
sudo ./hardening_ubuntu.sh --auditar                              # estado actual; no cambia nada
sudo ./hardening_ubuntu.sh --simular --ssh-desde 192.168.1.0/24   # muestra los cambios (diff); no cambia nada
sudo ./hardening_ubuntu.sh --aplicar --ssh-desde 192.168.1.0/24   # aplica, con respaldo
sudo ./hardening_ubuntu.sh --revertir /var/backups/hardening-20261114-091500
```

| Opción | Efecto |
|---|---|
| `--ssh-desde CIDR` | SSH solo desde esa red. Sin esta opción, SSH queda abierto con límite de tasa (`ufw limit`) |
| `--puerto-ssh N` | Cambia el puerto. El anterior queda abierto hasta que lo cierres vos |
| `--permitir-usuarios "a b"` | `AllowUsers`: solo esos usuarios entran por SSH |
| `--syslog-remoto HOST:PUERTO` | Copia todos los logs a otro servidor por TCP, con cola en disco si no responde |
| `--omitir ssh,ufw,...` | Saltea pasos (`ssh`, `ufw`, `fail2ban`, `auditd`, `journald`, `actualizaciones`, `sysctl`) |

Después, para investigar con auditd: `sudo ausearch -k transferencia -i`, `-k usuarios`, `-k borrado_logs`,
`-k comandos_root`.

### Ejemplo: antes y después (servidor de prueba con los problemas del Caso 3)

```
--- Antes ---
  [FALTA] SSH: acepta contraseñas (PasswordAuthentication yes)
          Es lo que hizo posible la fuerza bruta del Caso 3
  [FALTA] SSH: root puede entrar (PermitRootLogin yes)
  [FALTA] Cuentas con UID 0 además de root: toor
  [AVISO] Grupo sudo: admin,soporte2
          Confirmar que todos sean legítimos (Caso 3: el intruso agregó a 'soporte2')
  [FALTA] Firewall: ufw inactivo
  [FALTA] fail2ban: sin protección de SSH
  [FALTA] auditd: no hay reglas para usuarios, sudo, transferencias y borrado de logs
  ...
Resultado: 9 en falta, 7 avisos

--- Después ---
  [ OK  ] SSH: no acepta contraseñas
  [ OK  ] SSH: root no puede entrar
  [ OK  ] SSH: LogLevel VERBOSE (registra la huella de la clave de cada login)
  [FALTA] Cuentas con UID 0 además de root: toor
  [ OK  ] Firewall: ufw activo
  [ OK  ] fail2ban: jail sshd activa
  [ OK  ] auditd: reglas de auditoría cargadas
  ...
Resultado: 2 en falta, 2 avisos
```

Las cuentas sospechosas (`toor`, `soporte2`) **se informan pero no se tocan**: borrar o bloquear una cuenta
es una decisión del administrador. Además, en un incidente esa cuenta es evidencia.

## Cómo evita dejarte afuera

Endurecer SSH en un servidor remoto puede dejarte sin acceso. El script:

1. **No deshabilita las contraseñas si tu usuario no tiene una clave válida** en `~/.ssh/authorized_keys`
   (lo comprueba con `ssh-keygen -l` y muestra las huellas).
2. Valida con `sshd -t` y después revisa la **configuración efectiva** con `sshd -T`. Si algo no quedó como
   debía, restaura el respaldo y no recarga SSH.
3. No activa el firewall si **tu conexión actual** (`$SSH_CONNECTION`) quedaría fuera de `--ssh-desde`.
4. No aplica `--permitir-usuarios` si la lista no te incluye.
5. Recarga SSH con `reload`: la sesión abierta no se corta. Al final pide probar el acceso desde otra terminal.

## Detalles que aprendí haciéndolo

- **En `sshd_config` gana el primer valor, no el último.** Las imágenes cloud de Ubuntu traen
  `/etc/ssh/sshd_config.d/50-cloud-init.conf` con `PasswordAuthentication yes`. Un archivo `99-hardening.conf`
  **perdería** contra ese y SSH seguiría aceptando contraseñas. Por eso el archivo es `00-hardening.conf` y el
  script verifica el valor efectivo con `sshd -T` en lugar de confiar en lo que escribió.
- **Ubuntu 20.04 no incluye `sshd_config.d`:** se agrega el `Include` al principio de `sshd_config`.
- **Ubuntu 22.10+ activa SSH por socket:** si nadie se conectó, `ssh.service` está inactivo y `reload` falla.
  Para cambiar el puerto, además, hay que reiniciar `ssh.socket`.
- **Sin `/var/log/auth.log`** (Ubuntu mínimo, sin rsyslog), fail2ban no encuentra el log de SSH. En ese caso
  usa `backend = systemd` para leer el journal.
- **Bash:** `algo | función` ejecuta la función en un subshell y sus variables se pierden. El script usa
  `función < <(algo)`.

## Pruebas

Dos niveles, los dos en [GitHub Actions](.github/workflows/pruebas.yml):

1. **Servidor simulado** ([tests/](tests/)): una carpeta con un Ubuntu falso con los problemas del Caso 3 y
   simuladores de `sshd`, `ufw`, `systemctl`, `fail2ban-client`, `auditctl`, etc. El de `sshd -T` aplica la
   regla de "gana el primero". Son 15 pruebas, ejecutables también en Windows con Git Bash
   (`python -m unittest -v`):
   - auditoría;
   - que simular no cambie nada;
   - aplicar, idempotencia, revertir y respaldo alterado;
   - cada protección;
   - Ubuntu 20.04;
   - cambio de puerto con socket;
   - fail2ban con journal.
2. **Ubuntu 22.04 y 24.04 reales** (máquinas virtuales descartables de GitHub):
   1. Se arma un servidor que acepta contraseña y se confirma que entra.
   2. Se aplica el script.
   3. Se comprueba que **entra con clave y rechaza la contraseña**, que ufw, fail2ban y auditd están activos
      y que auditd registra un uso de `curl`.
   4. Se corre de nuevo para verificar que no cambia nada.
   5. Se revierte y se confirma que vuelve a aceptar contraseña.

Además, `shellcheck` sobre el script.

## Limitaciones

- No controla el tráfico **saliente**: la exfiltración del Caso 3 iba por HTTP al puerto 80, que un servidor
  normalmente necesita. auditd la deja registrada, pero no la impide. Para eso hacen falta un proxy de salida
  o una lista blanca de destinos.
- `rp_filter = 1` (estricto) puede romper ruteo asimétrico en servidores con varias interfaces.
- El syslog remoto va por TCP sin cifrar. En producción, rsyslog con TLS (`gtls`) o una VPN.
- Es una línea base, no reemplaza a CIS Benchmarks ni a una evaluación del servidor puntual.

---

Agustín Farfán · Ingeniería en Informática (UCASAL) ·
[laboratorio forense](https://github.com/agusfar45/laboratorio-perito-informatico) ·
[analizador de pcap](https://github.com/agusfar45/analizador-pcap-forense) ·
[adb_triage](https://github.com/agusfar45/adb-triage-android)
