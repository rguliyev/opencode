#!/usr/bin/env bash
#
# gcloud-remote-auth.sh — reliable headless/remote Google auth for ADC.
#
# WHY THIS EXISTS:
#   `gcloud auth login --update-adc` on a remote server prints a URL, then needs
#   the verification code pasted back. The code is cryptographically bound to the
#   `code_challenge` of the EXACT gcloud process that printed the URL. If that
#   process dies (e.g. stdin hits EOF) before the code comes back, the code is
#   useless ("invalid_grant: Invalid code verifier"). The fix is to keep ONE
#   gcloud process alive on a non-EOF stdin (a FIFO held open read+write) so it
#   waits as long as needed while the user completes the browser step.
#
# USAGE (driven by an agent/orchestrator, two phases):
#
#   1) Start the flow and get the URL:
#        gcloud-remote-auth.sh start
#      -> prints the sign-in URL. Give that URL to the user.
#
#   2) After the user returns the verification code:
#        gcloud-remote-auth.sh code '<VERIFICATION_CODE>'
#      -> submits the code to the SAME waiting process and reports success.
#
#   Helpers:
#        gcloud-remote-auth.sh status   # show current gcloud output / state
#        gcloud-remote-auth.sh verify   # mint an ADC token to confirm it works
#        gcloud-remote-auth.sh clean    # kill stray process + remove temp files
#
# NOTES:
#   - The verification code is single-use and bound to the URL from `start`.
#     Never reuse an old code; always use the URL from the most recent `start`.
#   - Re-running `start` begins a fresh session (new URL/challenge).
#
set -u

# One global login for all agents, with its credentials kept under the
# OpenCode scratch root instead of ~/.config/gcloud. Ignore per-task overrides
# so a sign-in by one agent still serves every session.
export CLOUDSDK_CONFIG="/data/rguliyev/tmp/opencode/gcloud-remote-auth/config"
umask 077
WORKDIR="/data/rguliyev/tmp/opencode/.gcloud-remote-auth"
FIFO="$WORKDIR/auth.in"
LOG="$WORKDIR/auth.log"
DONE="$WORKDIR/auth.done"
PIDFILE="$WORKDIR/auth.pid"

GCLOUD_LOGIN_ARGS=(auth login --update-adc --no-launch-browser --enable-gdrive-access)
# Optional extra args, appended after the defaults above (which already
# include --enable-gdrive-access for Docs/Drive API scopes on every run).
if [ -n "${GCLOUD_REMOTE_AUTH_EXTRA_ARGS:-}" ]; then
  # shellcheck disable=SC2206
  GCLOUD_LOGIN_ARGS+=($GCLOUD_REMOTE_AUTH_EXTRA_ARGS)
fi

die() { echo "ERROR: $*" >&2; exit 1; }

mkdir -p -m 700 "$CLOUDSDK_CONFIG" || die "cannot create $CLOUDSDK_CONFIG"
chmod 700 "$CLOUDSDK_CONFIG" || die "cannot protect $CLOUDSDK_CONFIG"

cmd_clean() {
  # Never cancel a sign-in the human may be completing for another session.
  if [ "${1:-}" != "--force" ] && pending_signin; then
    echo "REFUSED: a sign-in started in the last 15 minutes is still waiting for the human's code; use 'start' to get its URL." >&2
    return 1
  fi
  if [ -f "$PIDFILE" ]; then
    local p; p="$(cat "$PIDFILE" 2>/dev/null || true)"
    [ -n "${p:-}" ] && kill "$p" 2>/dev/null || true
  fi
  # also kill any lingering gcloud login reading our FIFO
  pkill -f "gcloud.*auth.*login.*--update-adc" 2>/dev/null || true
  rm -f "$FIFO" "$LOG" "$DONE" "$PIDFILE"
  rmdir "$WORKDIR" 2>/dev/null || true
}

authenticated() {
  gcloud auth print-access-token >/dev/null 2>&1 && gcloud auth application-default print-access-token >/dev/null 2>&1
}

cmd_start() {
  command -v gcloud >/dev/null 2>&1 || die "gcloud not found in PATH"
  # Another agent may already have signed in; don't send the human a link.
  if authenticated; then
    echo "ALREADY AUTHENTICATED: the global gcloud login and ADC are valid; no sign-in needed."
    return 0
  fi
  # Another agent may have a sign-in waiting; share its URL instead of
  # cancelling it, so one browser sign-in and one code serve everyone.
  if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null && [ ! -f "$DONE" ]; then
    local pending
    pending="$(grep -Eo 'https://accounts\.google\.com/o/oauth2/auth[^[:space:]]*' "$LOG" 2>/dev/null | tail -n1 || true)"
    if [ -n "$pending" ]; then
      echo "PENDING: a sign-in is already waiting; use this URL (one code completes it for every session):"
      echo "$pending"
      return 0
    fi
  fi
  cmd_clean --force
  mkdir -p "$WORKDIR" || die "cannot create $WORKDIR"
  mkfifo "$FIFO" || die "cannot create FIFO $FIFO"

  # Launch gcloud with the FIFO held open read+write (fd 3) so stdin never EOFs.
  # Do NOT pre-feed an answer here: some gcloud versions show a GCE-style
  # "are you sure you want to continue (Y/n)" confirmation before the
  # verification-code prompt, others (the current one) skip straight to the
  # code prompt. Blindly pre-writing "Y" into the FIFO gets read AS the
  # verification code itself when no confirmation prompt appears, instantly
  # failing the whole flow ("invalid_grant: Malformed auth code") before the
  # user ever gets a chance to paste the real code. The loop below watches
  # the log and only answers "Y" if that confirmation prompt actually shows
  # up first — see below.
  nohup bash -c '
    exec 3<>"'"$FIFO"'"
    gcloud '"${GCLOUD_LOGIN_ARGS[*]}"' <&3 > "'"$LOG"'" 2>&1
    echo "EXIT_CODE=$?" >> "'"$LOG"'"
    touch "'"$DONE"'"
  ' >/dev/null 2>&1 &
  echo "$!" > "$PIDFILE"

  # Wait for the URL to appear in the log. Along the way, watch for a
  # yes/no confirmation prompt (older gcloud behavior) and answer it via the
  # FIFO — the same external-write technique cmd_code uses to submit the
  # real code later — the moment it's seen; this write is only ever
  # attempted after the prompt text is already in the log, i.e. only once
  # gcloud is provably blocked reading fd 3 for that prompt, so it can't
  # race ahead of a reader. If no confirmation prompt ever appears (current
  # gcloud), this is simply a no-op and behavior is unchanged.
  local url="" answered_confirm=0
  for _ in $(seq 1 30); do
    if [ "$answered_confirm" -eq 0 ] && grep -qiE '\(y/n\)|are you sure' "$LOG" 2>/dev/null; then
      printf 'Y\n' > "$FIFO"
      answered_confirm=1
    fi
    url="$(grep -Eo 'https://accounts\.google\.com/o/oauth2/auth[^[:space:]]*' "$LOG" 2>/dev/null | tail -n1 || true)"
    [ -n "$url" ] && break
    sleep 1
  done
  [ -n "$url" ] || { echo "Failed to obtain sign-in URL. Log:"; cat "$LOG" 2>/dev/null; exit 1; }

  echo "$url"
}

cmd_code() {
  local code="${1:-}"
  [ -n "$code" ] || die "usage: gcloud-remote-auth.sh code '<VERIFICATION_CODE>'"
  [ -p "$FIFO" ] || die "no active auth session; run 'start' first"

  printf '%s\n' "$code" > "$FIFO"

  # Wait for completion.
  for _ in $(seq 1 30); do
    [ -f "$DONE" ] && break
    sleep 2
  done

  if grep -q "Application Default Credentials (ADC) were updated" "$LOG" 2>/dev/null \
     && grep -q "EXIT_CODE=0" "$LOG" 2>/dev/null; then
    grep -E "logged in as|current project|ADC" "$LOG" 2>/dev/null
    echo "SUCCESS: ADC updated."
    rm -f "$FIFO" "$DONE" "$PIDFILE"; rmdir "$WORKDIR" 2>/dev/null || true
    return 0
  else
    echo "FAILED. Recent gcloud output:" >&2
    tail -n 20 "$LOG" 2>/dev/null >&2
    echo "(If this was 'invalid_grant', the code was stale/mismatched — run 'start' again for a fresh URL.)" >&2
    return 1
  fi
}

# Say first whether the shared login works; the log of a finished sign-in
# is not an error and was misread as one.
cmd_status() {
  if authenticated; then echo "AUTHENTICATED: the global gcloud login and ADC are valid."; else echo "EXPIRED: run 'start' to sign in."; fi
  if pending_signin; then echo "A sign-in is waiting for the human's code (see 'start' for the URL)."; fi
}

# A sign-in started under 15 minutes ago whose process is still waiting.
pending_signin() {
  [ -f "$PIDFILE" ] && [ ! -f "$DONE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null &&
    [ -n "$(find "$PIDFILE" -mmin -15 2>/dev/null)" ]
}

cmd_verify() {
  if authenticated; then
    echo "OK: the global gcloud login and ADC mint valid access tokens."
    gcloud auth list --format='value(account)' 2>/dev/null
  else
    echo "FAILED: ADC token could not be obtained."; exit 1
  fi
}

case "${1:-}" in
  start)  cmd_start ;;
  code)   shift; cmd_code "${1:-}" ;;
  status) cmd_status ;;
  verify) cmd_verify ;;
  clean)  shift; cmd_clean "${1:-}" && echo "cleaned" ;;
  *) echo "usage: $0 {start|code '<CODE>'|status|verify|clean}" >&2; exit 2 ;;
esac
