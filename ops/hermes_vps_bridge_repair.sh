#!/usr/bin/env bash
set -Eeuo pipefail
export HOME="${HOME:-/root}"

root=/opt/faressystem
source_commit=b95a77bde2cc348ddeced3f07697a1fac390b5cc
request_id=owner-hermes-config-drift-vps-bridge-repair-20260726-012
runner="$root/scripts/bridge/pc_command_runner.py"
tmp=$(mktemp -d "/tmp/${request_id}.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

fail_json() {
  local blocker="$1"
  python3 - "$blocker" <<'PY'
import json,sys
text=str(sys.argv[1])
for needle in ('token=','secret=','password=','api_key=','authorization=','cookie='):
    if needle in text.lower():
        text='redacted_runtime_error'
if len(text)>700:text=text[:700]
print(json.dumps({
  'schema':'faressystem.hermes.vps_bridge_repair_proof/v1',
  'status':'failed_with_evidence',
  'transport':'vps_pc_command_runner',
  'blocker':text,
  'secrets_emitted':False,
},separators=(',',':')))
PY
  exit 1
}

[[ -d "$root" ]] || fail_json canonical_vps_root_missing
[[ -f "$runner" ]] || fail_json canonical_pc_command_runner_missing

if ! git -C "$root" cat-file -e "${source_commit}^{commit}" 2>/dev/null; then
  git -C "$root" fetch --quiet --no-tags origin "$source_commit" >"$tmp/git-fetch.out" 2>"$tmp/git-fetch.err" \
    || fail_json "private_source_fetch_failed:$(tail -c 400 "$tmp/git-fetch.err" | tr '\n\r' ' ')"
fi

declare -A sources=(
  [repair.ps1]='ops/runtime_recovery/hermes_config_drift_repair.ps1'
  [core.py]='scripts/hermes_runtime_guard.py'
  [policy.py]='scripts/hermes_runtime_guard_policy.py'
  [watchdog.ps1]='scripts/hermes_pc_gateway_watchdog.ps1'
  [patch.json]='state/worker_pack/compiled/hermes/runtime_patch.json'
  [prefill.json]='state/worker_pack/compiled/hermes/prefill_messages.json'
)
for name in "${!sources[@]}"; do
  git -C "$root" show "${source_commit}:${sources[$name]}" >"$tmp/$name" \
    || fail_json "private_source_missing:${sources[$name]}"
  [[ -s "$tmp/$name" ]] || fail_json "private_source_empty:${sources[$name]}"
done

python3 - "$tmp" "$request_id" <<'PY'
import base64,sys
from pathlib import Path
stage=Path(sys.argv[1]); request_id=sys.argv[2]
encoded={name:base64.b64encode((stage/name).read_bytes()).decode('ascii') for name in (
    'repair.ps1','core.py','policy.py','watchdog.ps1','patch.json','prefill.json'
)}
worker=f'''$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$OutputEncoding=[Console]::OutputEncoding
$env:PYTHONUTF8='1'
$id='{request_id}'
$root='C:\\FaresSystem'
$outDir=Join-Path $root 'ops\\chatgpt_results'
$rawPath=Join-Path $outDir ($id+'.raw.json')
$summaryPath=Join-Path $outDir ($id+'.summary.json')
$stage=Join-Path $env:TEMP $id
function Save-Summary($Value){{
  New-Item -ItemType Directory -Force -Path $outDir|Out-Null
  [IO.File]::WriteAllText($summaryPath,($Value|ConvertTo-Json -Depth 10 -Compress),[Text.Encoding]::ASCII)
}}
function Write-B64([string]$Name,[string]$Value){{
  [IO.File]::WriteAllBytes((Join-Path $stage $Name),[Convert]::FromBase64String($Value))
}}
try{{
  if(Test-Path -LiteralPath $stage){{Remove-Item -LiteralPath $stage -Recurse -Force}}
  New-Item -ItemType Directory -Force -Path $stage,$outDir|Out-Null
  Write-B64 'repair.ps1' '{encoded['repair.ps1']}'
  Write-B64 'core.py' '{encoded['core.py']}'
  Write-B64 'policy.py' '{encoded['policy.py']}'
  Write-B64 'watchdog.ps1' '{encoded['watchdog.ps1']}'
  Write-B64 'patch.json' '{encoded['patch.json']}'
  Write-B64 'prefill.json' '{encoded['prefill.json']}'
  $rows=@(& (Join-Path $stage 'repair.ps1') `
    -CoreBase64 '{encoded['core.py']}' `
    -PolicyBase64 '{encoded['policy.py']}' `
    -WatchdogBase64 '{encoded['watchdog.ps1']}' `
    -PatchBase64 '{encoded['patch.json']}' `
    -PrefillBase64 '{encoded['prefill.json']}' 2>&1)
  $rc=$LASTEXITCODE
  $text=$rows -join "`n"
  [IO.File]::WriteAllText($rawPath,$text,[Text.UTF8Encoding]::new($false))
  $p=$text|ConvertFrom-Json -ErrorAction Stop
  $blocker=[string]$p.blocker
  if($blocker.Length -gt 220){{$blocker=$blocker.Substring(0,220)}}
  Save-Summary ([ordered]@{{
    status=[string]$p.status
    cfg=[string]$p.config_sha256_after
    baseline=[string]$p.baseline_sha256_after
    cfg_before=[string]$p.config_sha256_before
    baseline_before=[string]$p.baseline_sha256_before
    provider=[string]$p.primary_provider
    base_url=[string]$p.primary_base_url
    model=[string]$p.primary_model
    probe=[string]$p.provider_probe
    canary=[string]$p.hermes_oneshot_canary
    gateway=[int]$p.gateway_process_count
    gateway_pid=$p.gateway_pid
    telegram=[string]$p.telegram_state
    watchdog=[bool]$p.watchdog.enabled
    override=[string]$p.session_model_override_provider
    backup=[string]$p.backup_root
    blocker=$blocker
  }})
  exit $rc
}}catch{{
  $message=[string]$_.Exception.Message
  if($message.Length -gt 300){{$message=$message.Substring(0,300)}}
  Save-Summary ([ordered]@{{status='failed_with_evidence';blocker=$message}})
  exit 1
}}
'''
(stage/'worker.ps1').write_text(worker,encoding='utf-8',newline='\n')
worker_b64=base64.b64encode(worker.encode('utf-8')).decode('ascii')
summary=f"C:\\FaresSystem\\ops\\chatgpt_results\\{request_id}.summary.json"
raw=f"C:\\FaresSystem\\ops\\chatgpt_results\\{request_id}.raw.json"
launch=f'''$ErrorActionPreference='Stop'
$summary='{summary}'
$raw='{raw}'
Remove-Item -LiteralPath $summary,$raw -Force -ErrorAction SilentlyContinue
$worker=Join-Path $env:TEMP '{request_id}.worker.ps1'
[IO.File]::WriteAllBytes($worker,[Convert]::FromBase64String('{worker_b64}'))
Start-Process -FilePath powershell.exe -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$worker) -WindowStyle Hidden
[ordered]@{{status='launched';worker=$worker}}|ConvertTo-Json -Compress
'''
(stage/'launch.ps1').write_text(launch,encoding='utf-8',newline='\n')
PY

launch_b64=$(base64 -w0 "$tmp/launch.ps1")
set +e
python3 "$runner" run --script-b64 "$launch_b64" --timeout-seconds 45 \
  >"$tmp/launch.out" 2>"$tmp/launch.err"
launch_rc=$?
set -e
if [[ $launch_rc -ne 0 ]]; then
  fail_json "pc_bridge_launch_failed:$(tail -c 700 "$tmp/launch.err" | tr '\n\r' ' ')"
fi

summary=''
for _attempt in $(seq 1 120); do
  cat >"$tmp/poll.ps1" <<PS1
\$p='C:\\FaresSystem\\ops\\chatgpt_results\\${request_id}.summary.json'
if(Test-Path -LiteralPath \$p){Get-Content -LiteralPath \$p -Raw}else{Write-Output 'PENDING'}
PS1
  poll_b64=$(base64 -w0 "$tmp/poll.ps1")
  set +e
  poll_out=$(python3 "$runner" run --script-b64 "$poll_b64" --timeout-seconds 35 2>"$tmp/poll.err")
  poll_rc=$?
  set -e
  if [[ $poll_rc -eq 0 ]]; then
    poll_out=$(printf '%s' "$poll_out" | tr -d '\r' | sed -e 's/[[:space:]]*$//')
    if [[ -n "$poll_out" && "$poll_out" != 'PENDING' ]]; then
      summary="$poll_out"
      break
    fi
  fi
  sleep 5
done
[[ -n "$summary" ]] || summary='{"status":"failed_with_evidence","blocker":"repair_summary_timeout"}'
printf '%s\n' "$summary" >"$tmp/summary.json"

cat >"$tmp/independent.ps1" <<'PS1'
$c='C:\Users\fares\AppData\Local\hermes\config.yaml'
$h=(Get-FileHash -LiteralPath $c -Algorithm SHA256).Hash
$b=(Get-Content -LiteralPath ($c+'.sha256') -Raw).Trim()
$w=Get-ScheduledTask -TaskName 'Azani.PC.HermesGatewayWatchdog' -ErrorAction SilentlyContinue
[ordered]@{
  hash_match=($h -eq $b)
  hash=$h
  baseline=$b
  watchdog=if($w){[string]$w.State}else{'Missing'}
}|ConvertTo-Json -Compress
PS1
independent_b64=$(base64 -w0 "$tmp/independent.ps1")
set +e
python3 "$runner" run --script-b64 "$independent_b64" --timeout-seconds 45 \
  >"$tmp/independent.out" 2>"$tmp/independent.err"
independent_rc=$?
set -e
if [[ $independent_rc -ne 0 ]]; then
  printf '%s\n' '{"probe_failed":true}' >"$tmp/independent.json"
else
  tr -d '\r' <"$tmp/independent.out" >"$tmp/independent.json"
fi

python3 - "$tmp/summary.json" "$tmp/independent.json" <<'PY'
import json,sys

def load(path):
    try:
        return json.load(open(path,encoding='utf-8-sig'))
    except Exception as exc:
        return {'parse_error':str(exc)}
summary=load(sys.argv[1]); independent=load(sys.argv[2])
verified=(
    summary.get('status')=='verified' and
    bool(summary.get('cfg')) and summary.get('cfg')==summary.get('baseline') and
    summary.get('provider')=='custom' and
    summary.get('probe')=='PROVIDER_OK' and
    summary.get('canary')=='HERMES_PROVIDER_OK' and
    summary.get('gateway')==1 and
    summary.get('telegram')=='connected' and
    summary.get('watchdog') is True and
    summary.get('override') in ('',None) and
    independent.get('hash_match') is True and
    independent.get('watchdog') not in ('Disabled','Missing',None)
)
proof={
  'schema':'faressystem.hermes.vps_bridge_repair_proof/v1',
  'status':'verified' if verified else 'failed_with_evidence',
  'transport':'vps_pc_command_runner',
  'repair_summary':summary,
  'independent_postcheck':independent,
  'secrets_emitted':False,
}
print(json.dumps(proof,separators=(',',':')))
raise SystemExit(0 if verified else 1)
PY
