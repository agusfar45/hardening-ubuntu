#!/usr/bin/env bash
# =============================================================================
# hardening_ubuntu.sh — Endurecimiento de un servidor Ubuntu (20.04 / 22.04 / 24.04)
#
# Aplica las recomendaciones del Caso 3 de mi laboratorio forense (servidor
# comprometido por fuerza bruta SSH, con persistencia, exfiltración y borrado de logs):
#
#   SSH        solo con clave, sin root, menos intentos, LogLevel VERBOSE
#   ufw        entrada denegada por defecto; SSH limitado o solo desde una red
#   fail2ban   bloqueo de IPs que fallan el login (integrado con ufw)
#   auditd     registro de creación de usuarios, cambios de sudo, uso de curl/wget,
#              borrado de logs y comandos ejecutados como root
#   logs       journal persistente y, opcional, copia a un servidor syslog remoto
#   otros      actualizaciones de seguridad automáticas y parámetros de red del kernel
#
# Modos:
#   sudo ./hardening_ubuntu.sh --auditar              revisa el estado; no cambia nada
#   sudo ./hardening_ubuntu.sh --simular  [opciones]  muestra qué cambiaría (diff); no cambia nada
#   sudo ./hardening_ubuntu.sh --aplicar  [opciones]  aplica, con respaldo de cada archivo
#   sudo ./hardening_ubuntu.sh --revertir /var/backups/hardening-AAAAMMDD-HHMMSS
#
# Opciones:
#   --ssh-desde CIDR        SSH solo desde esa red (ej. 192.168.1.0/24); si no, SSH abierto con límite de tasa
#   --puerto-ssh N          cambia el puerto de SSH (deja abierto el anterior hasta que lo cierres vos)
#   --permitir-usuarios "a b"   AllowUsers: solo esos usuarios pueden entrar por SSH
#   --syslog-remoto HOST:PUERTO copia todos los logs a un servidor remoto por TCP
#   --omitir LISTA          pasos a saltear, separados por coma:
#                           ssh,ufw,fail2ban,auditd,journald,actualizaciones,sysctl
#
# Protecciones para no quedarse afuera:
#   - no deshabilita las contraseñas si el usuario que corre sudo no tiene una clave válida
#   - valida la configuración con `sshd -t` y comprueba la configuración EFECTIVA con `sshd -T`;
#     si algo falla, restaura el respaldo y no recarga SSH
#   - no activa el firewall si tu conexión actual quedaría fuera de --ssh-desde
#   - recarga SSH con `reload`: la sesión abierta no se corta
# =============================================================================
set -Eeuo pipefail
trap 'echo "Error inesperado en la línea $LINENO: $BASH_COMMAND" >&2' ERR

VERSION="1.0"
RAIZ="${HARDENING_RAIZ:-}"       # SOLO para las pruebas: prefijo de todas las rutas del sistema
TS="$(date +%Y%m%d-%H%M%S)"
MODO=""; SIMULAR=0
PUERTO_SSH=""; SSH_DESDE=""; SYSLOG_REMOTO=""; PERMITIR_USUARIOS=""; OMITIR=""; DIR_REVERTIR=""
DIR_BACKUP="$RAIZ/var/backups/hardening-$TS"
MANIFIESTO="$DIR_BACKUP/MANIFIESTO"
ARCHIVO_LOG="$RAIZ/var/log/hardening-$TS.log"
FALLAS=0; AVISOS=0; CAMBIO=0; ADMIN=""; HOME_ADMIN=""

if [[ -t 1 ]]; then
  ROJO=$'\e[31m'; VERDE=$'\e[32m'; AMARILLO=$'\e[33m'; NEGRITA=$'\e[1m'; NORMAL=$'\e[0m'
else
  ROJO=""; VERDE=""; AMARILLO=""; NEGRITA=""; NORMAL=""
fi

# ----------------------------------------------------------------------------- utilidades

uso() { sed -n '3,37p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

log() {
  printf '%s\n' "$*"
  if [[ $MODO == aplicar || $MODO == revertir ]] && (( ! SIMULAR )); then
    mkdir -p "$(dirname "$ARCHIVO_LOG")"
    printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" | sed 's/\x1b\[[0-9;]*m//g' >> "$ARCHIVO_LOG"
  fi
}

morir() { log "${ROJO}ERROR:${NORMAL} $*"; exit 2; }
titulo() { log ""; log "${NEGRITA}== $* ==${NORMAL}"; }
omitido() { [[ ",$OMITIR," == *",$1,"* ]]; }

ejecutar() {
  if (( SIMULAR )); then log "  [simulación] $*"; return 0; fi
  log "  \$ $*"
  "$@"
}

control() {  # $1 = OK | FALTA | AVISO   $2 = descripción   $3 = detalle (opcional)
  case $1 in
    OK)    log "  ${VERDE}[ OK  ]${NORMAL} $2" ;;
    FALTA) log "  ${ROJO}[FALTA]${NORMAL} $2"; FALLAS=$((FALLAS + 1)) ;;
    AVISO) log "  ${AMARILLO}[AVISO]${NORMAL} $2"; AVISOS=$((AVISOS + 1)) ;;
  esac
  if [[ -n ${3:-} ]]; then log "          $3"; fi
  return 0
}

ya_respaldado() { [[ -f $MANIFIESTO ]] && awk -v r="$1" '$3 == r { e = 1 } END { exit !e }' "$MANIFIESTO"; }

respaldar() {  # $1 = ruta del sistema (sin RAIZ). Se respalda una sola vez por corrida.
  local rel="$1"
  (( SIMULAR )) && return 0
  mkdir -p "$DIR_BACKUP"
  ya_respaldado "$rel" && return 0
  if [[ -e $RAIZ$rel ]]; then
    mkdir -p "$DIR_BACKUP$(dirname "$rel")"
    cp -a "$RAIZ$rel" "$DIR_BACKUP$rel"
    echo "RESPALDO $(sha256sum "$RAIZ$rel" | cut -d' ' -f1) $rel" >> "$MANIFIESTO"
  else
    echo "NUEVO - $rel" >> "$MANIFIESTO"
  fi
}

restaurar() {  # $1 = ruta del sistema: vuelve al respaldo de ESTA corrida
  local rel="$1" linea
  linea="$(awk -v r="$rel" '$3 == r' "$MANIFIESTO" 2>/dev/null || true)"
  case $linea in
    RESPALDO*) cp -a "$DIR_BACKUP$rel" "$RAIZ$rel"; log "  restaurado $rel" ;;
    NUEVO*)    rm -f "$RAIZ$rel"; log "  eliminado $rel" ;;
  esac
}

escribir() {  # $1 = ruta del sistema, $2 = permisos; contenido por stdin. Deja CAMBIO=1 si cambió.
  local rel="$1" modo="$2" tmp
  CAMBIO=0
  tmp="$(mktemp)"
  cat > "$tmp"
  if [[ -f $RAIZ$rel ]] && cmp -s "$tmp" "$RAIZ$rel"; then
    log "  = $rel (sin cambios)"
    rm -f "$tmp"; return 0
  fi
  if (( SIMULAR )); then
    log "  ~ $rel se escribiría así:"
    local ref="$RAIZ$rel"; [[ -f $ref ]] || ref=/dev/null
    diff -u --label "$rel (actual)" --label "$rel (nuevo)" "$ref" "$tmp" | sed 's/^/      /' || true
    rm -f "$tmp"; CAMBIO=1; return 0
  fi
  respaldar "$rel"
  mkdir -p "$(dirname "$RAIZ$rel")"
  install -m "$modo" "$tmp" "$RAIZ$rel"
  rm -f "$tmp"
  log "  + $rel"
  CAMBIO=1
}

sshd_valor() { sshd -T 2>/dev/null | awk -v k="$1" '$1 == k { print $2; exit }'; }

ip_en_red() {  # $1 = IP, $2 = CIDR
  python3 -c 'import ipaddress, sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network(sys.argv[2], strict=False) else 1)' "$1" "$2"
}

home_de() { awk -F: -v u="$1" '$1 == u { print $6 }' "$RAIZ/etc/passwd"; }

recargar_ssh() {
  # En Ubuntu 24.04 SSH se activa por socket: si nadie se conectó todavía, ssh.service está
  # inactivo y "reload" fallaría. En ese caso la configuración nueva se lee al arrancar.
  if systemctl is-active --quiet ssh; then
    ejecutar systemctl reload ssh
  else
    log "  ssh.service no está corriendo (activación por socket): la configuración se aplica en la próxima conexión"
  fi
}

journal_sin_authlog() { [[ ! -f $RAIZ/var/log/auth.log ]]; }

# ----------------------------------------------------------------------------- auditoría

auditar() {
  titulo "Auditoría"
  FALLAS=0; AVISOS=0
  local v

  if command -v sshd > /dev/null; then
    v="$(sshd_valor passwordauthentication)"
    if [[ $v == no ]]; then control OK "SSH: no acepta contraseñas"
    else control FALTA "SSH: acepta contraseñas (PasswordAuthentication ${v:-?})" "Es lo que hizo posible la fuerza bruta del Caso 3"; fi
    v="$(sshd_valor kbdinteractiveauthentication)"
    if [[ $v == no ]]; then control OK "SSH: sin autenticación interactiva (teclado)"
    else control FALTA "SSH: KbdInteractiveAuthentication ${v:-?}" "Es otra vía para pedir contraseña"; fi
    v="$(sshd_valor permitrootlogin)"
    case $v in
      no) control OK "SSH: root no puede entrar" ;;
      prohibit-password|without-password) control AVISO "SSH: root puede entrar con clave (PermitRootLogin $v)" ;;
      *) control FALTA "SSH: root puede entrar (PermitRootLogin ${v:-?})" ;;
    esac
    v="$(sshd_valor maxauthtries)"
    if [[ ${v:-6} -le 3 ]]; then control OK "SSH: hasta $v intentos por conexión"
    else control AVISO "SSH: MaxAuthTries ${v:-6}" "Con 3 alcanza para quien tiene la clave"; fi
    v="$(sshd_valor loglevel)"
    if [[ ${v^^} == VERBOSE ]]; then control OK "SSH: LogLevel VERBOSE (registra la huella de la clave de cada login)"
    else control AVISO "SSH: LogLevel ${v:-INFO}" "En VERBOSE el log dice QUÉ clave se usó: dato clave en una pericia"; fi
    v="$(sshd_valor x11forwarding)"
    if [[ $v == no ]]; then control OK "SSH: sin reenvío X11"
    else control AVISO "SSH: X11Forwarding ${v:-?}"; fi
  else
    control AVISO "SSH: openssh-server no está instalado"
  fi

  v="$(awk -F: '$3 == 0 && $1 != "root" { printf "%s ", $1 }' "$RAIZ/etc/passwd")"
  if [[ -z $v ]]; then control OK "Cuentas: solo root tiene UID 0"
  else control FALTA "Cuentas con UID 0 además de root: ${v% }" "Una cuenta con UID 0 es root con otro nombre"; fi
  if [[ -r $RAIZ/etc/shadow ]]; then
    v="$(awk -F: '$2 == "" { printf "%s ", $1 }' "$RAIZ/etc/shadow")"
    if [[ -z $v ]]; then control OK "Cuentas: ninguna sin contraseña"
    else control FALTA "Cuentas SIN contraseña: ${v% }"; fi
  fi
  v="$(awk -F: '($1 == "sudo" || $1 == "admin") && $4 != "" { printf "%s ", $4 }' "$RAIZ/etc/group")"
  if [[ -n $v ]]; then control AVISO "Grupo sudo: ${v% }" "Confirmar que todos sean legítimos (Caso 3: el intruso agregó a 'soporte2')"; fi

  if command -v ufw > /dev/null; then
    v="$(ufw status verbose 2>/dev/null || true)"
    if grep -q "Status: active" <<< "$v"; then control OK "Firewall: ufw activo"
    else control FALTA "Firewall: ufw inactivo"; fi
    if grep -q "deny (incoming)" <<< "$v"; then control OK "Firewall: entrada denegada por defecto"
    else control FALTA "Firewall: la entrada no está denegada por defecto"; fi
  else
    control FALTA "Firewall: ufw no está instalado"
  fi

  if fail2ban-client status sshd > /dev/null 2>&1; then control OK "fail2ban: jail sshd activa"
  else control FALTA "fail2ban: sin protección de SSH"; fi

  if ! auditctl -l 2>/dev/null | grep -q "usuarios"; then
    control FALTA "auditd: no hay reglas para usuarios, sudo, transferencias y borrado de logs"
  elif auditctl -s 2>/dev/null | grep -q "^enabled 0"; then
    # Visto en la imagen de Ubuntu 22.04 de GitHub Actions: reglas cargadas, kernel sin auditar
    control FALTA "auditd: las reglas están cargadas pero la auditoría del kernel está APAGADA (enabled 0)" \
      "No se registra nada aunque 'auditctl -l' muestre las reglas. Se activa con: auditctl -e 1"
  else
    control OK "auditd: reglas cargadas y auditoría del kernel activa"
  fi

  if [[ -d $RAIZ/var/log/journal ]] || grep -rqs "^Storage=persistent" "$RAIZ"/etc/systemd/journald.conf*; then
    control OK "Logs: journal persistente"
  else control AVISO "Logs: el journal se pierde al reiniciar"; fi
  if grep -rqsE 'omfwd|^[^#]*@@?[A-Za-z0-9]' "$RAIZ"/etc/rsyslog.d/ "$RAIZ/etc/rsyslog.conf"; then
    control OK "Logs: se copian a un servidor remoto"
  else control AVISO "Logs: solo locales" "Un intruso con root puede borrarlos (Caso 3: shred). Usar --syslog-remoto"; fi

  if grep -qs 'Unattended-Upgrade "1"' "$RAIZ/etc/apt/apt.conf.d/20auto-upgrades"; then
    control OK "Actualizaciones de seguridad automáticas"
  else control FALTA "Sin actualizaciones de seguridad automáticas"; fi

  local malos=""
  for par in net.ipv4.tcp_syncookies=1 net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.all.send_redirects=0 \
             net.ipv4.conf.all.log_martians=1 net.ipv4.conf.all.rp_filter=1; do
    v="$(sysctl -n "${par%%=*}" 2>/dev/null || echo "?")"
    [[ $v == "${par#*=}" ]] || malos+="${par%%=*}=$v "
  done
  if [[ -z $malos ]]; then control OK "Kernel: parámetros de red endurecidos"
  else control AVISO "Kernel: $malos"; fi

  log ""
  log "${NEGRITA}Resultado: $FALLAS en falta, $AVISOS avisos${NORMAL}"
}

# ----------------------------------------------------------------------------- pasos

verificar_sistema() {
  if [[ -z $RAIZ && $EUID -ne 0 ]]; then morir "hay que ejecutarlo con sudo"; fi
  [[ -r $RAIZ/etc/os-release ]] || morir "no se encontró /etc/os-release"
  # Se lee con awk y no con ". /etc/os-release": ese archivo define VERSION y pisaría la nuestra
  local id version_id
  id="$(awk -F= '$1 == "ID" { gsub(/"/, "", $2); print $2 }' "$RAIZ/etc/os-release")"
  version_id="$(awk -F= '$1 == "VERSION_ID" { gsub(/"/, "", $2); print $2 }' "$RAIZ/etc/os-release")"
  [[ $id == ubuntu ]] || morir "este script es para Ubuntu (detectado: ${id:-?})"
  case $version_id in 20.04|22.04|24.04|24.10|25.04|25.10) ;; *) morir "versión de Ubuntu no probada: $version_id" ;; esac
  log "Sistema: Ubuntu $version_id · hardening_ubuntu.sh v$VERSION"

  ADMIN="${SUDO_USER:-}"
  if [[ -n $ADMIN && $ADMIN != root ]]; then
    HOME_ADMIN="$(home_de "$ADMIN")"
    log "Administrador: $ADMIN ($HOME_ADMIN)"
  else
    ADMIN=""
    log "${AMARILLO}No se pudo determinar el administrador (ejecutalo con sudo desde tu usuario, no como root).${NORMAL}"
  fi
}

instalar_paquetes() {
  titulo "Paquetes"
  local quiero=() faltan=() p
  omitido ufw || quiero+=(ufw)
  if ! omitido fail2ban; then
    quiero+=(fail2ban)
    if journal_sin_authlog; then quiero+=(python3-systemd); fi  # para leer el journal (backend = systemd)
  fi
  omitido auditd || quiero+=(auditd)
  omitido actualizaciones || quiero+=(unattended-upgrades)
  [[ -n $SYSLOG_REMOTO ]] && quiero+=(rsyslog)
  for p in "${quiero[@]}"; do dpkg -s "$p" > /dev/null 2>&1 || faltan+=("$p"); done
  if (( ${#faltan[@]} == 0 )); then log "  = todos instalados"; return 0; fi
  ejecutar apt-get update -qq
  ejecutar env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${faltan[@]}"
}

claves_validas() {  # muestra las huellas de las claves autorizadas; falla si no hay ninguna válida
  local archivo="$1" huellas
  [[ -s $archivo ]] || return 1
  huellas="$(ssh-keygen -l -f "$archivo" 2>/dev/null)" || return 1
  [[ -n $huellas ]] || return 1
  log "  Claves autorizadas de $ADMIN:"
  while IFS= read -r l; do log "    $l"; done <<< "$huellas"
}

paso_ufw() {
  titulo "Firewall (ufw)"
  local puerto_actual puerto
  puerto_actual="$(sshd_valor port)"; puerto_actual="${puerto_actual:-22}"
  puerto="${PUERTO_SSH:-$puerto_actual}"
  if [[ -n $SSH_DESDE && -n ${SSH_CONNECTION:-} ]]; then
    local ip_cliente="${SSH_CONNECTION%% *}"
    if ! ip_en_red "$ip_cliente" "$SSH_DESDE"; then
      control FALTA "No se activa el firewall: tu conexión viene de $ip_cliente, fuera de $SSH_DESDE" \
        "Te quedarías afuera. Corregí --ssh-desde o conectate desde esa red"
      return 0
    fi
  fi
  if ! (( SIMULAR )) && ! ufw status 2>/dev/null | grep -q "Status: active"; then
    mkdir -p "$DIR_BACKUP"; echo "ESTADO ufw inactivo" >> "$MANIFIESTO"
  fi
  respaldar /etc/default/ufw; respaldar /etc/ufw/user.rules; respaldar /etc/ufw/user6.rules
  ejecutar ufw default deny incoming
  ejecutar ufw default allow outgoing
  if [[ -n $SSH_DESDE ]]; then
    ejecutar ufw allow from "$SSH_DESDE" to any port "$puerto" proto tcp comment hardening-ssh
  else
    ejecutar ufw limit "$puerto/tcp" comment hardening-ssh
  fi
  if [[ $puerto != "$puerto_actual" ]]; then
    ejecutar ufw limit "$puerto_actual/tcp" comment hardening-ssh-anterior
    log "  ${AMARILLO}El puerto $puerto_actual queda abierto hasta que pruebes el $puerto:${NORMAL} después, ufw delete limit $puerto_actual/tcp"
  fi
  ejecutar ufw logging low
  ejecutar ufw --force enable
}

paso_ssh() {
  titulo "SSH"
  if ! command -v sshd > /dev/null; then control AVISO "openssh-server no está instalado: se omite"; return 0; fi
  if [[ -z $ADMIN ]] || ! claves_validas "$RAIZ$HOME_ADMIN/.ssh/authorized_keys"; then
    control FALTA "NO se deshabilitan las contraseñas: ${ADMIN:-el administrador} no tiene una clave válida en ~/.ssh/authorized_keys" \
      "Desde tu PC: ssh-copy-id usuario@servidor; probá entrar con la clave y volvé a correr el script"
    return 0
  fi
  if [[ -n $PERMITIR_USUARIOS && " $PERMITIR_USUARIOS " != *" $ADMIN "* ]]; then
    control FALTA "--permitir-usuarios no incluye a $ADMIN: te quedarías afuera. Se omite SSH"
    return 0
  fi

  local cambios=0
  # Ubuntu 20.04 no incluye sshd_config.d: se agrega el Include al PRINCIPIO
  # (escribir va con "< <(...)" y no con una tubería: en una tubería correría en un subshell
  #  y la variable CAMBIO se perdería)
  if ! grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$RAIZ/etc/ssh/sshd_config"; then
    escribir /etc/ssh/sshd_config 644 < <(echo "Include /etc/ssh/sshd_config.d/*.conf"; cat "$RAIZ/etc/ssh/sshd_config")
    cambios=$((cambios + CAMBIO))
  fi
  # 00-: sshd usa el PRIMER valor que encuentra. Un 99-hardening.conf perdería contra el
  # 50-cloud-init.conf de las imágenes cloud, que trae "PasswordAuthentication yes".
  escribir /etc/ssh/sshd_config.d/00-hardening.conf 644 < <(
    echo "# hardening_ubuntu.sh v$VERSION. Se lee antes que los demás archivos (00-)."
    if [[ -n $PUERTO_SSH ]]; then echo "Port $PUERTO_SSH"; fi
    cat << 'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowAgentForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
EOF
    if [[ -n $PERMITIR_USUARIOS ]]; then echo "AllowUsers $PERMITIR_USUARIOS"; fi
  )
  cambios=$((cambios + CAMBIO))
  (( SIMULAR )) && return 0

  if (( cambios )); then
    local err
    if ! err="$(sshd -t 2>&1)"; then
      control FALTA "sshd -t rechazó la configuración; se restaura el respaldo y SSH no se recarga" "$err"
      restaurar /etc/ssh/sshd_config.d/00-hardening.conf; restaurar /etc/ssh/sshd_config
      return 0
    fi
  fi
  # La configuración EFECTIVA es la que importa: otro archivo podría ganarle a la nuestra
  local par v
  for par in passwordauthentication=no kbdinteractiveauthentication=no permitrootlogin=no; do
    v="$(sshd_valor "${par%%=*}")"
    if [[ $v != "${par#*=}" ]]; then
      control FALTA "La configuración efectiva sigue con ${par%%=*} $v: otro archivo la define antes" \
        "$(grep -rils "^[[:space:]]*${par%%=*}" "$RAIZ/etc/ssh/sshd_config" "$RAIZ"/etc/ssh/sshd_config.d/ 2>/dev/null | tr '\n' ' ')"
      restaurar /etc/ssh/sshd_config.d/00-hardening.conf; restaurar /etc/ssh/sshd_config
      return 0
    fi
  done
  if (( cambios )); then
    recargar_ssh
    if [[ -n $PUERTO_SSH ]] && systemctl is-active --quiet ssh.socket; then
      # Ubuntu 22.10+ usa activación por socket: el puerto lo toma ssh.socket
      ejecutar systemctl daemon-reload
      ejecutar systemctl restart ssh.socket
    fi
  fi
  control OK "SSH: solo claves, sin root, LogLevel VERBOSE (configuración efectiva verificada)"
}

paso_fail2ban() {
  titulo "fail2ban"
  local puerto ignorar="127.0.0.1/8 ::1"
  puerto="${PUERTO_SSH:-$(sshd_valor port)}"; puerto="${puerto:-22}"
  [[ -n $SSH_DESDE ]] && ignorar+=" $SSH_DESDE"
  local backend=""
  # Sin /var/log/auth.log (Ubuntu mínimo sin rsyslog) la jail no arranca: se lee el journal
  if journal_sin_authlog; then backend="backend = systemd"; fi
  escribir /etc/fail2ban/jail.d/hardening.local 644 < <(cat << EOF
# hardening_ubuntu.sh v$VERSION
[DEFAULT]
bantime = 1h
bantime.increment = true
findtime = 10m
maxretry = 5
ignoreip = $ignorar
banaction = ufw

[sshd]
enabled = true
port = $puerto
mode = aggressive
$backend
EOF
)
  ejecutar systemctl enable --now fail2ban
  (( CAMBIO )) && ejecutar systemctl restart fail2ban
  return 0
}

paso_auditd() {
  titulo "auditd"
  local reglas="" ruta
  reglas+="## hardening_ubuntu.sh v$VERSION — consultar con: ausearch -k <clave> -i"$'\n'
  reglas+="## Cuentas y privilegios (Caso 3: useradd soporte2, usermod -aG sudo)"$'\n'
  for ruta in /etc/passwd /etc/shadow /etc/group /etc/gshadow; do reglas+="-w $ruta -p wa -k identidad"$'\n'; done
  reglas+="-w /etc/sudoers -p wa -k privilegios"$'\n'"-w /etc/sudoers.d/ -p wa -k privilegios"$'\n'
  for ruta in /usr/sbin/useradd /usr/sbin/usermod /usr/sbin/userdel /usr/sbin/adduser /usr/sbin/groupmod; do
    if [[ -e $RAIZ$ruta ]]; then reglas+="-w $ruta -p x -k usuarios"$'\n'; fi
  done
  reglas+="## Acceso remoto"$'\n'"-w /etc/ssh/sshd_config -p wa -k ssh_config"$'\n'"-w /etc/ssh/sshd_config.d/ -p wa -k ssh_config"$'\n'
  if [[ -d $RAIZ/root/.ssh ]]; then reglas+="-w /root/.ssh/ -p wa -k claves_ssh"$'\n'; fi
  reglas+="## Herramientas de transferencia (Caso 3: curl -T para exfiltrar)"$'\n'
  for ruta in /usr/bin/curl /usr/bin/wget /usr/bin/scp /usr/bin/sftp /usr/bin/rsync /usr/bin/nc.openbsd /usr/bin/ncat /usr/bin/socat; do
    if [[ -e $RAIZ$ruta ]]; then reglas+="-w $ruta -p x -k transferencia"$'\n'; fi
  done
  reglas+="## Antiforense (Caso 3: shred -u access.log)"$'\n'
  if [[ -e $RAIZ/usr/bin/shred ]]; then reglas+="-w /usr/bin/shred -p x -k antiforense"$'\n'; fi
  reglas+="-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,truncate -F dir=/var/log -F auid>=1000 -F auid!=unset -k borrado_logs"$'\n'
  reglas+="## Comandos ejecutados como root por usuarios que iniciaron sesión"$'\n'
  reglas+="-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k comandos_root"$'\n'
  reglas+="-a always,exit -F arch=b32 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k comandos_root"$'\n'
  reglas+="## Activar la auditoría del kernel: hay imágenes que la traen apagada (auditctl -s: enabled 0)"$'\n'
  reglas+="-e 1"$'\n'
  escribir /etc/audit/rules.d/90-hardening.rules 640 < <(printf '%s' "$reglas")
  ejecutar systemctl enable --now auditd
  if (( CAMBIO )) && ! (( SIMULAR )); then
    if auditctl -s 2>/dev/null | grep -q "enabled 2"; then
      control AVISO "auditd está en modo inmutable: las reglas nuevas se cargan al reiniciar"
    else
      ejecutar augenrules --load
    fi
  fi
  asegurar_auditoria "las reglas se cargaron con la auditoría del kernel apagada"

  # Con systemd < 253 (Ubuntu 22.04), cada vez que systemd-journald arranca apaga la auditoría del
  # kernel (comprobado en el CI). Con las actualizaciones automáticas, una actualización de systemd
  # la dejaría apagada sin aviso. El override la vuelve a activar en cada arranque de journald.
  local version_systemd
  version_systemd="$(systemctl --version 2>/dev/null | awk 'NR == 1 { print $2 + 0 }')"
  if [[ ${version_systemd:-999} -lt 253 ]]; then
    escribir /etc/systemd/system/systemd-journald.service.d/90-hardening-auditoria.conf 644 << 'EOF'
# hardening_ubuntu.sh — systemd < 253: journald apaga la auditoría del kernel al arrancar
[Service]
ExecStartPost=-/sbin/auditctl -e 1
EOF
    (( CAMBIO )) && ejecutar systemctl daemon-reload
  fi
  return 0
}

asegurar_auditoria() {  # $1 = qué la apagó. Vuelve a activar la auditoría del kernel si está en "enabled 0".
  (( SIMULAR )) && return 0
  omitido auditd && return 0
  command -v auditctl > /dev/null || return 0
  if auditctl -s 2>/dev/null | grep -q "^enabled 0"; then
    log "  ${AMARILLO}La auditoría del kernel está apagada ($1): se vuelve a activar${NORMAL}"
    ejecutar auditctl -e 1
    if grep -qw "audit=0" "$RAIZ/proc/cmdline" 2>/dev/null; then
      control AVISO "El kernel arrancó con audit=0: la auditoría queda activa hasta el próximo reinicio" \
        "Para que sea permanente, sacar audit=0 de GRUB_CMDLINE_LINUX en /etc/default/grub y correr update-grub"
    fi
  fi
  return 0
}

paso_journald() {
  titulo "Logs"
  escribir /etc/systemd/journald.conf.d/90-hardening.conf 644 << EOF
# hardening_ubuntu.sh v$VERSION — el journal sobrevive a los reinicios
[Journal]
Storage=persistent
SystemMaxUse=1G
Compress=yes
EOF
  if (( CAMBIO )); then
    (( SIMULAR )) || mkdir -p "$RAIZ/var/log/journal"
    ejecutar systemctl restart systemd-journald
    asegurar_auditoria "después de reiniciar systemd-journald"
  fi
  if [[ -n $SYSLOG_REMOTO ]]; then
    local host="${SYSLOG_REMOTO%:*}" puerto="${SYSLOG_REMOTO##*:}"
    [[ $host != "$SYSLOG_REMOTO" && $puerto =~ ^[0-9]+$ ]] || morir "--syslog-remoto debe ser HOST:PUERTO"
    escribir /etc/rsyslog.d/90-hardening-remoto.conf 644 << EOF
# hardening_ubuntu.sh v$VERSION — copia de todos los logs a un servidor remoto (TCP).
# Si el remoto no responde, los mensajes esperan en disco y se envían después.
*.* action(type="omfwd" target="$host" port="$puerto" protocol="tcp"
           queue.type="LinkedList" queue.filename="hardening_remoto" queue.maxDiskSpace="1g"
           queue.saveOnShutdown="on" action.resumeRetryCount="-1")
EOF
    (( CAMBIO )) && ejecutar systemctl restart rsyslog
  fi
  return 0
}

paso_actualizaciones() {
  titulo "Actualizaciones de seguridad"
  escribir /etc/apt/apt.conf.d/20auto-upgrades 644 << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
  return 0
}

paso_sysctl() {
  titulo "Kernel (red)"
  escribir /etc/sysctl.d/90-hardening.conf 644 << EOF
# hardening_ubuntu.sh v$VERSION
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
EOF
  if (( CAMBIO )); then
    ejecutar sysctl --system
    asegurar_auditoria "después de aplicar sysctl"
  fi
  return 0
}

# ----------------------------------------------------------------------------- reversión

revertir() {
  local dir="$1" tipo hash rel ufw_inactivo=0
  [[ -f $dir/MANIFIESTO ]] || morir "no hay MANIFIESTO en $dir"
  titulo "Reversión desde $dir"
  # primero se comprueba que el respaldo no haya sido modificado
  while read -r tipo hash rel; do
    if [[ $tipo == RESPALDO ]] && [[ "$(sha256sum "$dir$rel" | cut -d' ' -f1)" != "$hash" ]]; then
      morir "el respaldo de $rel no coincide con su hash: no se revierte nada"
    fi
  done < "$dir/MANIFIESTO"
  while read -r tipo hash rel; do
    case $tipo in
      RESPALDO) cp -a "$dir$rel" "$RAIZ$rel"; log "  restaurado $rel" ;;
      NUEVO)    rm -f "$RAIZ$rel"; log "  eliminado $rel" ;;
      ESTADO)   [[ $hash == ufw ]] && ufw_inactivo=1 ;;
    esac
  done < <(tac "$dir/MANIFIESTO")
  if sshd -t 2> /dev/null; then recargar_ssh; else log "  ${ROJO}sshd -t falla: revisá la configuración antes de recargar SSH${NORMAL}"; fi
  if (( ufw_inactivo )); then ejecutar ufw --force disable; else ejecutar ufw reload || true; fi
  ejecutar systemctl restart fail2ban || true
  ejecutar augenrules --load || true
  ejecutar systemctl daemon-reload || true
  ejecutar systemctl restart systemd-journald || true
  ejecutar sysctl --system > /dev/null || true
  if grep -q "/etc/rsyslog.d/" "$dir/MANIFIESTO"; then ejecutar systemctl restart rsyslog || true; fi
  log ""
  log "${VERDE}Reversión terminada.${NORMAL} Registro: $ARCHIVO_LOG"
}

# ----------------------------------------------------------------------------- main

main() {
  while (( $# )); do
    case $1 in
      --auditar) MODO=auditar ;;
      --simular) MODO=aplicar; SIMULAR=1 ;;
      --aplicar) MODO=aplicar ;;
      --revertir) MODO=revertir; DIR_REVERTIR="${2:?falta el directorio del respaldo}"; shift ;;
      --ssh-desde) SSH_DESDE="${2:?}"; shift ;;
      --puerto-ssh) PUERTO_SSH="${2:?}"; shift; [[ $PUERTO_SSH =~ ^[0-9]+$ ]] || morir "puerto inválido" ;;
      --permitir-usuarios) PERMITIR_USUARIOS="${2:?}"; shift ;;
      --syslog-remoto) SYSLOG_REMOTO="${2:?}"; shift ;;
      --omitir) OMITIR="${2:?}"; shift ;;
      -h|--help) uso 0 ;;
      *) echo "Opción desconocida: $1" >&2; uso 2 ;;
    esac
    shift
  done
  [[ -n $MODO ]] || uso 2

  case $MODO in
    auditar)
      verificar_sistema
      auditar
      exit $(( FALLAS > 0 )) ;;
    revertir)
      [[ -z $RAIZ && $EUID -ne 0 ]] && morir "hay que ejecutarlo con sudo"
      revertir "$RAIZ${DIR_REVERTIR#"$RAIZ"}" ;;
    aplicar)
      verificar_sistema
      (( SIMULAR )) && log "${AMARILLO}MODO SIMULACIÓN: no se cambia nada${NORMAL}"
      log "${NEGRITA}--- Antes ---${NORMAL}"
      auditar
      instalar_paquetes
      omitido ufw             || paso_ufw
      omitido ssh             || paso_ssh
      omitido fail2ban        || paso_fail2ban
      omitido auditd          || paso_auditd
      omitido journald        || paso_journald
      omitido actualizaciones || paso_actualizaciones
      omitido sysctl          || paso_sysctl
      asegurar_auditoria "al terminar los pasos"
      (( SIMULAR )) && { log ""; log "Simulación terminada: no se modificó nada."; exit 0; }
      log ""
      log "${NEGRITA}--- Después ---${NORMAL}"
      auditar
      log ""
      if [[ -f $MANIFIESTO ]]; then
        log "Respaldo: ${DIR_BACKUP#"$RAIZ"}  (para volver atrás: sudo $0 --revertir ${DIR_BACKUP#"$RAIZ"})"
      else
        log "No hubo cambios: el sistema ya tenía esta configuración."
      fi
      log "Registro: ${ARCHIVO_LOG#"$RAIZ"}"
      log "${AMARILLO}${NEGRITA}Antes de cerrar esta sesión, probá entrar por SSH desde OTRA terminal.${NORMAL}"
      exit $(( FALLAS > 0 )) ;;
  esac
}

main "$@"
