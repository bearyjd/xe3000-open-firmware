#!/usr/bin/env bash
# Phase 1 harvest (host side). Streams scripts/remote/collect.sh to the router over ONE ssh session, saves the framed
# stream, splits it into files, marks unterminated frames PARTIAL, and writes a tarball + sha256.
#
#   ROUTER_HOST=<host> scripts/harvest.sh     collect (ROUTER_HOST has no default and is never hardcoded)
#   scripts/harvest.sh --dry-print            print the exact remote script; does NOT connect
#
# Prints only counts and paths. Nothing but `sh -s` ever runs on the router.
set -euo pipefail
umask 077

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
COLLECT="$HERE/remote/collect.sh"
OUT_BASE=${HARVEST_OUT:-$HERE/../harvest/raw}

NAME_RE='^[A-Za-z0-9._@:+=,#-]+(/[A-Za-z0-9._@:+=,#-]+)*$'
KIND_RE='^[a-z][a-z0-9-]{0,31}$'
END_RE='^@@END ([^ ]+) ([0-9]+)$'

die() { printf 'harvest: %s\n' "$*" >&2; exit 1; }

# Make untrusted text safe for the manifest/terminal: printable ASCII only, bounded.
clean() {
  local s=${1//[^A-Za-z0-9._\/@:+=,# -]/?}
  printf '%s' "${s:0:120}"
}

valid_name() {
  local n=$1 seg
  [[ ${#n} -le 200 && $n =~ $NAME_RE && $n != *.PARTIAL ]] || return 1
  local IFS=/
  for seg in $n; do
    [[ $seg == . || $seg == .. ]] && return 1
  done
  return 0
}

# split_stream STREAM FRAMESDIR MANIFEST ; sets n_ok n_partial n_rej n_missing n_skipped saw_done
split_stream() {
  local stream=$1 frames=$2 manifest=$3
  local line in_frame=0 discard=0 have_prev=0 prev="" fkind="" fname="" fpath="" tag extra reason
  n_ok=0 n_partial=0 n_rej=0 n_missing=0 n_skipped=0 saw_done=0

  while IFS= read -r line || [[ -n $line ]]; do
    if ((in_frame)); then
      if [[ $line =~ $END_RE && ${BASH_REMATCH[1]} == "$fname" ]]; then
        # Exactly one trailing blank line is the collector's framing newline; drop it.
        if ((!discard)); then
          if ((have_prev)) && [[ -n $prev ]]; then printf '%s\n' "$prev" >&3; fi
          exec 3>&-
          n_ok=$((n_ok + 1))
          printf 'OK\t%s\t%s\texit=%s\n' "$fkind" "$fname" "${BASH_REMATCH[2]}" >>"$manifest"
        fi
        in_frame=0 discard=0 have_prev=0 prev=""
        continue
      fi
      if ((!discard)); then
        if ((have_prev)); then printf '%s\n' "$prev" >&3; fi
        prev=$line have_prev=1
      fi
      continue
    fi
    case $line in
      '@@BEGIN '*)
        read -r tag fkind fname extra <<<"$line" || true
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
        n_skipped=$((n_skipped + 1)); printf 'SKIPPED\t%s\n' "$(clean "${line#@@SKIPPED }")" >>"$manifest" ;;
      '@@DONE '*) saw_done=1 ;;
      *) ;;
    esac
  done <"$stream"

  if ((in_frame)) && ((!discard)); then
    if ((have_prev)); then printf '%s\n' "$prev" >&3; fi
    exec 3>&-
    mv -- "$fpath" "$fpath.PARTIAL"
    n_partial=$((n_partial + 1))
    printf 'PARTIAL\t%s\t%s\t%s\n' "$fkind" "$fname" "${fpath##*/}.PARTIAL" >>"$manifest"
  fi
}

main() {
  if [[ ${1:-} == --dry-print ]]; then
    cat -- "$COLLECT"
    return 0
  fi
  [[ $# -eq 0 ]] || die "usage: harvest.sh [--dry-print]"
  [[ -n ${ROUTER_HOST:-} ]] || die "ROUTER_HOST is required (no default)"
  [[ $ROUTER_HOST =~ ^[A-Za-z0-9][A-Za-z0-9._:-]*$ ]] || die "ROUTER_HOST has an invalid format"

  local ts dir frames manifest stream ssh_rc=0
  ts=$(date -u +%Y%m%dT%H%M%SZ)
  mkdir -p -m 0700 "$OUT_BASE"
  dir="$OUT_BASE/$ts"
  mkdir -m 0700 "$dir" || die "output directory already exists: $dir"
  frames="$dir/frames"
  manifest="$dir/manifest.tsv"
  stream="$dir/stream.txt"
  mkdir -m 0700 "$frames"
  : >"$manifest"

  ssh -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=5 \
    "root@$ROUTER_HOST" 'sh -s' <"$COLLECT" >"$stream" 2>"$dir/ssh.stderr" || ssh_rc=$?

  split_stream "$stream" "$frames" "$manifest"
  {
    printf 'ssh_exit\t%s\n' "$ssh_rc"
    printf 'done_marker\t%s\n' "$saw_done"
  } >>"$manifest"

  tar -C "$OUT_BASE" -cf "$OUT_BASE/$ts.tar" "$ts"
  (cd "$OUT_BASE" && sha256sum "$ts.tar" >"$ts.tar.sha256")

  printf 'frames_ok=%s partial=%s rejected=%s missing=%s skipped=%s done_marker=%s ssh_exit=%s\n' \
    "$n_ok" "$n_partial" "$n_rej" "$n_missing" "$n_skipped" "$saw_done" "$ssh_rc"
  printf 'dir=%s\ntar=%s\nsha256=%s\n' "$dir" "$OUT_BASE/$ts.tar" "$OUT_BASE/$ts.tar.sha256"
  if ((ssh_rc != 0 || n_partial > 0 || saw_done == 0)); then
    printf 'INCOMPLETE: do not treat this harvest as whole (see manifest.tsv)\n' >&2
    return 2
  fi
}

main "$@"
