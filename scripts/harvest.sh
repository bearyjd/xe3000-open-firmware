#!/usr/bin/env bash
# Phase 1 harvest (host side). Streams scripts/remote/collect.sh to the router over ONE ssh session, saves the framed
# stream, splits it into files, marks unterminated frames PARTIAL, and writes a tarball + sha256.
#
#   ROUTER_HOST=<host> scripts/harvest.sh [--probe | --with-logs]
#       collect (ROUTER_HOST has no default and is never hardcoded)
#         --probe        only learn which busybox tools exist (uname, busybox --list, command -v); collects nothing else
#         --with-logs    also snapshot logread (off by default: logs may carry credentials)
#   scripts/harvest.sh [--probe | --with-logs] --dry-print
#       print the exact remote command and the exact remote script; does NOT connect
#
# HARVEST_TIMEOUT (seconds, default 600) bounds the whole ssh session. Prints only counts and paths.
# Nothing but `sh -s glinet-harvest-collect ...` ever runs on the router. A stuck run can be stopped with
#   ssh root@$ROUTER_HOST "pkill -f '[s]h -s glinet-harvest-collect'"
# (bracket form: the pattern does not match the shell that runs pkill). This script prints it but never runs it.
set -euo pipefail
umask 077
export LC_ALL=C

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
COLLECT="$HERE/remote/collect.sh"
OUT_BASE=${HARVEST_OUT:-$HERE/../harvest/raw}
TAG=glinet-harvest-collect

NAME_RE='^[A-Za-z0-9._@:+=,#-]+(/[A-Za-z0-9._@:+=,#-]+)*$'
KIND_RE='^[a-z][a-z0-9-]{0,31}$'
VERSION_RE='^@@COLLECT-VERSION 2 ([A-Za-z0-9-]{8,64})$'
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=3)

stop_hint() {
  printf '%s\n' "# harvest: stop a stuck run with (never run automatically): ssh root@\$ROUTER_HOST \"pkill -f '[s]h -s glinet-harvest-collect'\""
}

usage() {
  {
    printf 'usage: ROUTER_HOST=<host> harvest.sh [--probe | --with-logs]\n       harvest.sh [--probe | --with-logs] --dry-print\n'
    stop_hint
  } >&2
}

die() { printf 'harvest: %s\n' "$*" >&2; exit 1; }

# Make untrusted text safe for the manifest/terminal: printable ASCII only, bounded.
clean() {
  local s=${1//[^A-Za-z0-9._\/@:+=,# -]/?}
  printf '%s' "${s:0:120}"
}

valid_name() {
  local n=$1 seg
  if ! [[ ${#n} -le 200 && $n =~ $NAME_RE && $n != *.PARTIAL ]]; then
    return 1
  fi
  local IFS=/
  for seg in $n; do
    [[ $seg == . || $seg == .. ]] && return 1
  done
  return 0
}

# split_stream STREAM FRAMESDIR MANIFEST ; sets n_ok n_partial n_rej n_missing n_skipped saw_done
# Only END/DONE lines carrying the nonce announced by the first @@COLLECT-VERSION line are trusted, so file content
# cannot forge a frame boundary. Everything before that announcement is ignored.
split_stream() {
  local stream=$1 frames=$2 manifest=$3
  local line nonce="" in_frame=0 discard=0 have_prev=0 prev="" fkind="" fname="" fpath="" extra reason rest
  n_ok=0 n_partial=0 n_rej=0 n_missing=0 n_skipped=0 n_capped=0 n_notimeout=0 saw_done=0

  while IFS= read -r line || [[ -n $line ]]; do
    if [[ -z $nonce ]]; then
      [[ $line =~ $VERSION_RE ]] && nonce=${BASH_REMATCH[1]}
      continue
    fi
    if ((in_frame)); then
      if [[ $line == "@@END-$nonce "* ]]; then
        rest=${line#"@@END-$nonce "}
        if [[ $rest =~ ^([^\ ]+)\ ([0-9]+)$ && ${BASH_REMATCH[1]} == "$fname" ]]; then
          # Exactly one trailing blank line is the collector's framing newline; drop it.
          if ((!discard)); then
            if ((have_prev)) && [[ -n $prev ]]; then printf '%s\n' "$prev" >&3; fi
            exec 3>&-
            n_ok=$((n_ok + 1))
            printf 'OK\t%s\t%s\texit=%s\n' "$fkind" "$fname" "${BASH_REMATCH[2]}" >>"$manifest"
            # 124 = coreutils timeout, 143 = BusyBox timeout (exec'd, SIGTERM): the command was cut off.
            if [[ ${BASH_REMATCH[2]} == 124 || ${BASH_REMATCH[2]} == 143 ]]; then
              n_capped=$((n_capped + 1))
              printf 'CAPPED\t%s\t%s\t%s\n' "$fkind" "$fname" "${BASH_REMATCH[2]}" >>"$manifest"
            fi
          fi
          in_frame=0 discard=0 have_prev=0 prev=""
          continue
        fi
      fi
      if ((!discard)); then
        if ((have_prev)); then printf '%s\n' "$prev" >&3; fi
        prev=$line have_prev=1
      fi
      continue
    fi
    case $line in
      '@@BEGIN '*)
        read -r _ fkind fname extra <<<"$line" || true
        reason=""
        if [[ -n ${extra:-} || -z ${fname:-} ]]; then reason=malformed
        elif [[ ! $fkind =~ $KIND_RE ]]; then reason=bad-kind
        elif ! valid_name "$fname"; then reason=bad-name
        else
          fpath="$frames/$fkind/${fname//\//%}"
          if [[ -e $fpath || -e $fpath.PARTIAL ]]; then reason=duplicate; fi
        fi
        in_frame=1 have_prev=0 prev=""
        if [[ -n $reason ]]; then
          discard=1
          n_rej=$((n_rej + 1))
          printf 'REJECTED\t%s\t%s\n' "$reason" "$(clean "${fname:-}")" >>"$manifest"
        else
          discard=0
          mkdir -p "$frames/$fkind"
          exec 3>"$fpath"
        fi
        ;;
      '@@MISSING '*)
        n_missing=$((n_missing + 1)); printf 'MISSING\t%s\n' "$(clean "${line#@@MISSING }")" >>"$manifest" ;;
      '@@SKIPPED '*)
        n_skipped=$((n_skipped + 1)); printf 'SKIPPED\t%s\n' "$(clean "${line#@@SKIPPED }")" >>"$manifest"
        if [[ $line == *' no-timeout' ]]; then n_notimeout=$((n_notimeout + 1)); fi
        ;;
      "@@DONE-$nonce "*) saw_done=1 ;;
      *) ;;
    esac
  done < <(tr -d '\0' <"$stream")

  if ((in_frame)) && ((!discard)); then
    if ((have_prev)); then printf '%s\n' "$prev" >&3; fi
    exec 3>&-
    mv -- "$fpath" "$fpath.PARTIAL"
    n_partial=$((n_partial + 1))
    printf 'PARTIAL\t%s\t%s\t%s\n' "$fkind" "$fname" "${fpath##*/}.PARTIAL" >>"$manifest"
  fi
}

main() {
  local probe=0 logs=0 dry=0 arg remote_cmd
  for arg in "$@"; do
    case $arg in
      --dry-print) dry=1 ;;
      --probe) probe=1 ;;
      --with-logs) logs=1 ;;
      *) usage; exit 64 ;;
    esac
  done
  if ((probe && logs)); then usage; die "--probe and --with-logs cannot be combined"; fi

  remote_cmd="sh -s $TAG"
  if ((probe)); then remote_cmd="$remote_cmd probe"; fi
  if ((logs)); then remote_cmd="$remote_cmd COLLECT_LOGS=1"; fi

  if ((dry)); then
    printf '%s\n' "# harvest: remote command (nothing else is ever run): ssh ${SSH_OPTS[*]} root@\$ROUTER_HOST '$remote_cmd'"
    stop_hint
    printf '%s\n' "# harvest: the script below is sent on stdin of that command"
    cat -- "$COLLECT"
    return 0
  fi

  [[ -n ${ROUTER_HOST:-} ]] || die "ROUTER_HOST is required (no default)"
  [[ $ROUTER_HOST =~ ^[A-Za-z0-9][A-Za-z0-9._:-]*$ ]] || die "ROUTER_HOST has an invalid format"
  local limit=${HARVEST_TIMEOUT:-600}
  [[ $limit =~ ^[1-9][0-9]*$ ]] || die "HARVEST_TIMEOUT must be a positive number of seconds"
  command -v timeout >/dev/null 2>&1 || die "the 'timeout' command (coreutils) is required"

  local ts suffix="" dir frames manifest stream ssh_rc=0
  ts=$(date -u +%Y%m%dT%H%M%SZ)
  if ((probe)); then suffix=-probe; fi
  mkdir -p "$OUT_BASE"
  chmod 0700 "$OUT_BASE"
  dir="$OUT_BASE/$ts$suffix"
  mkdir -m 0700 "$dir" || die "output directory already exists: $dir"
  frames="$dir/frames"
  manifest="$dir/manifest.tsv"
  stream="$dir/stream.txt"
  mkdir -m 0700 "$frames"
  : >"$manifest"

  timeout -k 10 "$limit" ssh "${SSH_OPTS[@]}" "root@$ROUTER_HOST" "$remote_cmd" \
    <"$COLLECT" >"$stream" 2>"$dir/ssh.stderr" || ssh_rc=$?

  split_stream "$stream" "$frames" "$manifest"
  {
    printf 'mode\t%s\n' "${suffix:-full}"
    printf 'ssh_exit\t%s\n' "$ssh_rc"
    printf 'done_marker\t%s\n' "$saw_done"
  } >>"$manifest"

  tar -C "$OUT_BASE" -cf "$OUT_BASE/$ts$suffix.tar" "$ts$suffix"
  (cd "$OUT_BASE" && sha256sum "$ts$suffix.tar" >"$ts$suffix.tar.sha256")

  printf 'frames_ok=%s partial=%s rejected=%s missing=%s skipped=%s capped=%s done_marker=%s ssh_exit=%s\n' \
    "$n_ok" "$n_partial" "$n_rej" "$n_missing" "$n_skipped" "$n_capped" "$saw_done" "$ssh_rc"
  printf 'dir=%s\ntar=%s\nsha256=%s\n' "$dir" "$OUT_BASE/$ts$suffix.tar" "$OUT_BASE/$ts$suffix.tar.sha256"
  if ((probe)); then
    local f
    for f in "$frames"/probe/*; do
      [[ -f $f ]] && cat -- "$f"
    done
  fi
  if ((n_notimeout > 0)); then
    printf 'NOTICE\tno-timeout\n' >>"$manifest"
    printf "NOTICE: the router has no 'timeout' applet, so the hwmon, thermal, power_supply and debugfs gpio reads were skipped to avoid hangs\n" >&2
  fi
  if ((n_capped > 0)); then
    printf 'NOTICE: %s frame(s) were capped by the per-read timeout (exit 124/143); their content is truncated\n' "$n_capped" >&2
  fi
  if ((ssh_rc != 0 || n_partial > 0 || saw_done == 0)); then
    printf 'INCOMPLETE: do not treat this harvest as whole (see manifest.tsv)\n' >&2
    return 2
  fi
}

main "$@"
