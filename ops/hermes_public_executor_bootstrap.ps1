$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$OutputEncoding=[Console]::OutputEncoding
$id='owner-hermes-config-drift-public-repair-20260726-009'
$root='C:\FaresSystem'
$sha='b95a77bde2cc348ddeced3f07697a1fac390b5cc'
$stage=Join-Path $env:TEMP $id
$outDir=Join-Path $root 'ops\chatgpt_results'
$raw=Join-Path $outDir ($id+'.raw.json')
$summary=Join-Path $outDir ($id+'.summary.json')
$git=(Get-Command git.exe -ErrorAction SilentlyContinue).Source
if(-not $git){$git='C:\Program Files\Git\cmd\git.exe'}
function Save-Summary($v){
  New-Item -ItemType Directory -Force -Path $outDir|Out-Null
  [IO.File]::WriteAllText($summary,($v|ConvertTo-Json -Depth 8 -Compress),[Text.Encoding]::ASCII)
}
function Git-Show([string]$rel,[string]$dest){
  $psi=New-Object Diagnostics.ProcessStartInfo
  $psi.FileName=$git
  $psi.Arguments="-C `"$root`" show `"${sha}:$rel`""
  $psi.UseShellExecute=$false
  $psi.RedirectStandardOutput=$true
  $psi.RedirectStandardError=$true
  $p=[Diagnostics.Process]::Start($psi)
  $stdout=$p.StandardOutput.ReadToEnd();$stderr=$p.StandardError.ReadToEnd();$p.WaitForExit()
  if($p.ExitCode -ne 0){throw "git_show_failed:$rel:$stderr"}
  [IO.File]::WriteAllText($dest,$stdout,[Text.UTF8Encoding]::new($false))
}
function B64([string]$name){[Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $stage $name)))}
try{
  if(-not (Test-Path -LiteralPath $git -PathType Leaf)){throw 'git_missing'}
  if(-not (Test-Path -LiteralPath $root -PathType Container)){throw 'canonical_root_missing'}
  $env:GIT_TERMINAL_PROMPT='0'
  & $git -C $root fetch --no-tags origin main 2>&1|Out-Null
  if($LASTEXITCODE -ne 0){throw 'git_fetch_failed'}
  if(Test-Path -LiteralPath $stage){Remove-Item -LiteralPath $stage -Recurse -Force}
  New-Item -ItemType Directory -Force -Path $stage,$outDir|Out-Null
  $files=@{
    'repair.ps1'='ops/runtime_recovery/hermes_config_drift_repair.ps1'
    'core.py'='scripts/hermes_runtime_guard.py'
    'policy.py'='scripts/hermes_runtime_guard_policy.py'
    'watchdog.ps1'='scripts/hermes_pc_gateway_watchdog.ps1'
    'patch.json'='state/worker_pack/compiled/hermes/runtime_patch.json'
    'prefill.json'='state/worker_pack/compiled/hermes/prefill_messages.json'
  }
  foreach($name in $files.Keys){Git-Show $files[$name] (Join-Path $stage $name)}
  $rows=@(& (Join-Path $stage 'repair.ps1') -CoreBase64 (B64 'core.py') -PolicyBase64 (B64 'policy.py') -WatchdogBase64 (B64 'watchdog.ps1') -PatchBase64 (B64 'patch.json') -PrefillBase64 (B64 'prefill.json') 2>&1)
  $rc=$LASTEXITCODE;$text=$rows -join "`n"
  [IO.File]::WriteAllText($raw,$text,[Text.UTF8Encoding]::new($false))
  $p=$text|ConvertFrom-Json -ErrorAction Stop
  $blocker=[string]$p.blocker;if($blocker.Length -gt 140){$blocker=$blocker.Substring(0,140)}
  Save-Summary ([ordered]@{status=[string]$p.status;cfg=[string]$p.config_sha256_after;baseline=[string]$p.baseline_sha256_after;provider=[string]$p.primary_provider;model=[string]$p.primary_model;probe=[string]$p.provider_probe;canary=[string]$p.hermes_oneshot_canary;gateway=[int]$p.gateway_process_count;telegram=[string]$p.telegram_state;watchdog=[bool]$p.watchdog.enabled;override=[string]$p.session_model_override_provider;blocker=$blocker})
  exit $rc
}catch{
  $m=[string]$_.Exception.Message;if($m.Length -gt 220){$m=$m.Substring(0,220)}
  Save-Summary ([ordered]@{status='failed_with_evidence';blocker=$m})
  exit 1
}
