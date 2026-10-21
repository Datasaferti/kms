<#
.SYNOPSIS
    Verifica e remove vestigios do KMS Pico / ativadores KMS em Windows 10 e 11.

.DESCRIPTION
    O script comeca perguntando se voce deseja VERIFICAR o computador. A
    verificacao e somente leitura: procura processos, arquivos, pastas, tarefas
    agendadas, servicos, chaves de registro, regras de firewall, linhas do hosts,
    adaptador TAP e exclusoes do Defender ligados ao KMS Pico.

    - Se NADA for encontrado, exibe: "SEU COMPUTADOR NAO CONTEM ESTE MALWARE".
    - Se algo for encontrado, mostra a lista e pergunta se deseja REMOVER agora.

    Na remocao, cria ponto de restauracao antes de qualquer alteracao, limpa os
    vestigios, reseta a ativacao do Windows/Office para o estado legitimo e roda
    uma verificacao rapida do Windows Defender ao final.

    Tudo o que e feito aparece no console com o status de cada item:
    [ENCONTRADO]/[REMOVIDO] | [LIMPO]/[AUSENTE] | [PENDENTE] | [INFO].

    AVISO/ISENCAO: script criado para limpar e desativar o malware KMS Pico.
    O processo e seguro (ponto de restauracao + log no console), porem o uso e
    opcional e por sua conta e risco: nao nos responsabilizamos caso a
    desinstalacao traga problemas a ativacao do Office e do Windows, seja ela
    qualquer que seja a versao (OEM, Retail, Volume/KMS corporativo ou pirata).

.NOTES
    Uso 1 - Arquivo .ps1:
        powershell -NoProfile -ExecutionPolicy Bypass -File .\removeKMSPico.ps1

    Uso 2 - Arquivo salvo como .txt (quando o antivirus apaga o .ps1),
            PowerShell ABERTO COMO ADMINISTRADOR:
        iex (Get-Content "$env:USERPROFILE\Desktop\removeKMSPico.txt" -Raw)

    Uso 3 - Mesmo .txt, PowerShell NORMAL (o script pede UAC e relanca lendo
            o proprio .txt, sem criar nenhum .ps1 no disco):
        $env:KMS_SOURCE = "$env:USERPROFILE\Desktop\removeKMSPico.txt"
        iex (Get-Content $env:KMS_SOURCE -Raw)

    Parametro opcional (uso 1) / variavel de ambiente (usos 2 e 3):
        -SkipDefenderScan            Nao roda a verificacao rapida do Defender.
        $env:KMS_SKIP_SCAN = '1'     Equivalente via iex.

    Se nao for executado como Administrador, o script se auto-eleva via UAC.
    Via iex com $env:KMS_SOURCE definido, a janela elevada le o proprio .txt;
    sem KMS_SOURCE, ele tenta baixar o script do GitHub para o TEMP (ultimo
    recurso - o GitHub pode bloquear o arquivo).

    AVISO: em redes corporativas com servidor KMS legitimo (dominio/empresa),
    consulte o TI antes de executar - o script limpa configuracoes de canal KMS.
#>

[CmdletBinding()]
param(
    [switch]$SkipDefenderScan
)

# Fonte remota do script (usada quando roda via iex / Invoke-Expression)
$script:RemoteSource = 'https://raw.githubusercontent.com/Datasaferti/kms/refs/heads/main/removeKMSPico.ps1'

# Via iex nao da para passar -SkipDefenderScan: use a variavel de ambiente
if (-not $SkipDefenderScan -and $env:KMS_SKIP_SCAN -eq '1') { $SkipDefenderScan = $true }

# Minimo PowerShell 5.1 (checado em codigo para funcionar tambem via iex)
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host 'Este script requer Windows PowerShell 5.1 ou superior.' -ForegroundColor Red
    if ($PSCommandPath) { exit 1 } else { return }
}

# ============================================================================
# 0. AUTO-ELEVACAO PARA ADMINISTRADOR (.ps1 direto ou .txt via iex + KMS_SOURCE)
# ============================================================================
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $elevSource = $null
    $elevMode   = $null
    if ($PSCommandPath) {
        $elevSource = $PSCommandPath
        $elevMode   = 'File'
    } elseif ($env:KMS_SOURCE -and (Test-Path -LiteralPath $env:KMS_SOURCE)) {
        # .txt (ou qualquer extensao) indicado pelo usuario antes do iex
        $elevSource = $env:KMS_SOURCE
        $elevMode   = 'Iex'
    }
    if ($elevSource) {
        Write-Host 'Solicitando elevacao de administrador (UAC)...' -ForegroundColor Yellow
        $elevOk = $false
        try {
            if ($elevMode -eq 'File') {
                $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$elevSource`""
                if ($SkipDefenderScan) { $argList += ' -SkipDefenderScan' }
            } else {
                # A janela elevada le o proprio arquivo .txt: nenhum .ps1 no disco
                $apos = [char]39
                $safePath = $elevSource.Replace("$apos", "$apos$apos")
                $innerCmd = "iex (Get-Content -LiteralPath '$safePath' -Raw)"
                if ($SkipDefenderScan) { $innerCmd = "`$env:KMS_SKIP_SCAN = '1'; " + $innerCmd }
                $argList = "-NoProfile -ExecutionPolicy Bypass -Command `"$innerCmd`""
            }
            Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs -ErrorAction Stop
            $elevOk = $true
        } catch {
            Write-Host 'Elevacao negada ou falhou.' -ForegroundColor Red
        }
        if ($elevOk) {
            Write-Host 'Nova janela do PowerShell (administrador) iniciada. Continue nela.' -ForegroundColor Green
            if ($PSCommandPath) { exit 0 } else { return }
        }
        Write-Host 'Este script PRECISA de administrador para limpar o sistema.' -ForegroundColor Yellow
        Write-Host 'Abra o PowerShell como administrador e execute novamente.' -ForegroundColor White
        if ($PSCommandPath) { exit 1 } else { return }
    }
    # Sem arquivo local conhecido (iex remoto): tenta baixar do GitHub (ultimo recurso)
    Write-Host 'Solicitando elevacao de administrador (UAC)...' -ForegroundColor Yellow
    $tmp = Join-Path $env:TEMP 'removeKMSPico.ps1'
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $script:RemoteSource -OutFile $tmp -UseBasicParsing -ErrorAction Stop
        $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$tmp`""
        if ($SkipDefenderScan) { $argList += ' -SkipDefenderScan' }
        Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs -ErrorAction Stop
        Write-Host 'Nova janela do PowerShell (administrador) iniciada. Continue nela.' -ForegroundColor Green
        if ($PSCommandPath) { exit 0 } else { return }
    } catch {
        Write-Host ("Nao foi possivel elevar/baixar o script: {0}" -f $_.Exception.Message) -ForegroundColor Red
        Write-Host 'O GitHub pode ter bloqueado o arquivo. Salve o script como .txt e use:' -ForegroundColor White
        Write-Host '  $env:KMS_SOURCE = "C:\caminho\removeKMSPico.txt"' -ForegroundColor Cyan
        Write-Host '  iex (Get-Content $env:KMS_SOURCE -Raw)' -ForegroundColor Cyan
        if ($PSCommandPath) { exit 1 } else { return }
    }
}

$host.UI.RawUI.WindowTitle = 'Limpeza Cirurgica - Vestigios do KMS Pico'

# ============================================================================
# ESTATISTICAS E FUNCOES AUXILIARES
# ============================================================================
$script:Stats   = @{ Removido = 0; NaoEncontrado = 0; Pendente = 0 }
$script:Pending = New-Object System.Collections.Generic.List[string]

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    Write-Host ("  {0}" -f $Title) -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
}

function Write-Status {
    param([string]$Status, [string]$Message)
    switch ($Status) {
        'OK'   { Write-Host '  [REMOVIDO] ' -NoNewline -ForegroundColor Green;   $script:Stats.Removido++ }
        'MISS' { Write-Host '  [AUSENTE]   ' -NoNewline -ForegroundColor DarkGray; $script:Stats.NaoEncontrado++ }
        'PEND' { Write-Host '  [PENDENTE] ' -NoNewline -ForegroundColor Yellow;  $script:Stats.Pendente++ }
        'INFO' { Write-Host '  [INFO]      ' -NoNewline -ForegroundColor Cyan }
        default{ Write-Host '  [-]         ' -NoNewline }
    }
    Write-Host $Message
}

function Remove-Target {
    param([string]$Path, [string]$Label)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (Test-Path -LiteralPath $Path) {
        try {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
            Write-Status OK ("{0} -> {1}" -f $Label, $Path)
        } catch {
            Write-Status PEND ("{0} -> {1} ({2})" -f $Label, $Path, $_.Exception.Message)
            $script:Pending.Add("Excluir manualmente: $Path")
        }
    } else {
        Write-Status MISS ("{0} ({1})" -f $Label, $Path)
    }
}

function Invoke-CscriptArg {
    param([string]$VbsPath, [string[]]$Arguments)
    $out  = & cscript.exe //nologo "$VbsPath" @Arguments 2>&1
    $code = $LASTEXITCODE
    return [pscustomobject]@{ Exit = $code; Output = ($out | Out-String) }
}

# ============================================================================
# LISTAS DE ALVOS CONHECIDOS (usadas na verificacao e na limpeza)
# ============================================================================
$targets = @(
    @{ Label = 'Pasta de instalacao (x64)';        Path = "$env:ProgramFiles\KMSpico" },
    @{ Label = 'Pasta de instalacao (x86)';        Path = "${env:ProgramFiles(x86)}\KMSpico" },
    @{ Label = 'Pasta de instalacao x64 (espaco)'; Path = "$env:ProgramFiles\KMS Pico" },
    @{ Label = 'Pasta de instalacao x86 (espaco)'; Path = "${env:ProgramFiles(x86)}\KMS Pico" },
    @{ Label = 'Pasta de sistema (logs)';          Path = "$env:windir\KMSpico" },
    @{ Label = 'Dados do programa (KMS)';          Path = "$env:ProgramData\KMS" },
    @{ Label = 'Dados do programa (KMSpico)';      Path = "$env:ProgramData\KMSpico" },
    @{ Label = 'AppData local (KMSpico)';          Path = "$env:LOCALAPPDATA\KMSpico" },
    @{ Label = 'AppData roaming (KMSpico)';        Path = "$env:APPDATA\KMSpico" },
    @{ Label = 'Menu Iniciar (todos usuarios)';    Path = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\KMSpico" },
    @{ Label = 'Menu Iniciar (usuario atual)';     Path = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\KMSpico" },
    @{ Label = 'Cache de tarefa agendada (pasta)'; Path = "$env:windir\System32\Tasks\KMSpico" },
    @{ Label = 'Cache de tarefa SvcTask_KMS';      Path = "$env:windir\System32\Tasks\SvcTask_KMS" }
)
$regKeys = @(
    'HKLM:\SOFTWARE\KMSpico',
    'HKLM:\SOFTWARE\WOW6432Node\KMSpico',
    'HKLM:\SOFTWARE\KMS Pico',
    'HKCU:\Software\KMSpico',
    'HKCU:\Software\KMS Pico'
)
$uninstRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
)
$runPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
$variants = @(
    "$env:ProgramData\KMSAuto", "${env:ProgramFiles(x86)}\KMSAuto", "$env:ProgramFiles\KMSAuto",
    "$env:windir\AutoKMS", "$env:ProgramData\AutoKMS", "${env:ProgramFiles(x86)}\AutoKMS",
    "$env:windir\KMS"
)

# ============================================================================
# CABECALHO
# ============================================================================
$cv    = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
$build = 0
if ($cv -and $cv.CurrentBuildNumber) { [void][int]::TryParse([string]$cv.CurrentBuildNumber, [ref]$build) }
if     ($build -ge 22000) { $winLabel = 'Windows 11' }
elseif ($build -ge 10240) { $winLabel = 'Windows 10' }
else                      { $winLabel = 'Windows (versao anterior ao 10)' }

Write-Host ''
Write-Host ('=' * 78) -ForegroundColor Cyan
Write-Host '   LIMPEZA CIRURGICA - VESTIGIOS DO KMS PICO' -ForegroundColor Cyan
Write-Host '   Rastros + ativacao + firewall/hosts/TAP + verificacao Defender' -ForegroundColor Cyan
Write-Host ('=' * 78) -ForegroundColor Cyan
Write-Host ("  Sistema .....: {0} (build {1})" -f $winLabel, $build)
Write-Host ("  Usuario .....: {0}" -f $identity.Name)
Write-Host ("  Data/hora ...: {0}" -f (Get-Date -Format 'dd/MM/yyyy HH:mm'))
Write-Host ''
Write-Host '  AVISO: em redes corporativas com servidor KMS legitimo (dominio/empresa),' -ForegroundColor DarkYellow
Write-Host '  consulte o TI antes de executar: o script limpa configuracoes de canal KMS.' -ForegroundColor DarkYellow

# ============================================================================
# SOBRE ESTE SCRIPT (proposito + isencao de responsabilidade)
# ============================================================================
Write-Host ''
Write-Host '  SOBRE ESTE SCRIPT:' -ForegroundColor Cyan
Write-Host '   Criado para fazer a limpeza e a desativacao do malware KMS Pico' -ForegroundColor White
Write-Host '   (ativador pirata) instalado no computador.' -ForegroundColor White
Write-Host '   O processo e seguro: cria um ponto de restauracao antes de qualquer' -ForegroundColor White
Write-Host '   alteracao e mostra cada acao no console antes de executa-la.' -ForegroundColor White
Write-Host ''
Write-Host '  ISENCAO DE RESPONSABILIDADE:' -ForegroundColor DarkYellow
Write-Host '   O uso e opcional e por sua conta e risco. Nao nos responsabilizamos' -ForegroundColor DarkYellow
Write-Host '   caso a desinstalacao traga problemas a ativacao do Office e do Windows,' -ForegroundColor DarkYellow
Write-Host '   seja ela qualquer que seja a versao (OEM, Retail, Volume/KMS ou pirata).' -ForegroundColor DarkYellow

# ============================================================================
# MENU - PERGUNTA INICIAL: VERIFICAR?
# ============================================================================
Write-Host ''
Write-Host ('=' * 78) -ForegroundColor Cyan
$resp1 = Read-Host '  Deseja verificar se existe o KMS Pico instalado neste computador? (S/N)'
if ($resp1 -notmatch '^(?i)[sy]') {
    Write-Host ''
    Write-Host '  Verificacao nao realizada. Nenhuma alteracao foi feita no computador.' -ForegroundColor Gray
    Read-Host 'Pressione ENTER para sair'
    if ($PSCommandPath) { exit 0 } else { return }
}

# ============================================================================
# VERIFICACAO (SOMENTE LEITURA - nada e removido nesta etapa)
# ============================================================================
Write-Section 'VERIFICACAO - PROCURANDO VESTIGIOS DO KMS PICO (somente leitura)'
Write-Host '  Aguarde: varrendo o sistema (pode levar alguns segundos)...' -ForegroundColor DarkGray
$script:DetList  = New-Object System.Collections.Generic.List[string]
$script:DetCount = 0

function Add-Finding {
    param([string]$Message)
    Write-Host '  [ENCONTRADO] ' -NoNewline -ForegroundColor Yellow
    Write-Host $Message
    $script:DetList.Add($Message)
    $script:DetCount++
}
function Add-Clean {
    param([string]$Message)
    Write-Host '  [LIMPO]      ' -NoNewline -ForegroundColor DarkGray
    Write-Host $Message
}

# 01 - Processos do ativador
$dProcs = @(Get-Process -Name @('KMSPico', 'KMSELDI', 'AutoPico', 'ServiceKMS', 'UnSec') -ErrorAction SilentlyContinue)
$dProcs += @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path -match '(?i)kmspico' })
$dProcs = @($dProcs | Where-Object { $_ } | Sort-Object Id -Unique)
if ($dProcs.Count -gt 0) {
    foreach ($p in $dProcs) { Add-Finding ("Processo do ativador em execucao: {0} (PID {1})" -f $p.ProcessName, $p.Id) }
} else {
    Add-Clean 'Nenhum processo do ativador em execucao'
}

# 02 - Pastas e arquivos conhecidos
$dPaths = @($targets | Where-Object { $_.Path -and (Test-Path -LiteralPath $_.Path) })
if ($dPaths.Count -gt 0) {
    foreach ($t in $dPaths) { Add-Finding ("Pasta/arquivo do ativador: {0}" -f $t.Path) }
} else {
    Add-Clean 'Nenhuma pasta/arquivo conhecido do ativador (Program Files, ProgramData, AppData, Windows)'
}

# 03 - Atalhos (.lnk)
$dlnkDirs = @([Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('CommonDesktopDirectory'), [Environment]::GetFolderPath('Programs')) | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique
$dlnks = @()
foreach ($d in $dlnkDirs) {
    $dlnks += @(Get-ChildItem -LiteralPath $d -Filter '*.lnk' -ErrorAction SilentlyContinue | Where-Object { $_.BaseName -match '(?i)kms|pico' })
}
if ($dlnks.Count -gt 0) {
    foreach ($l in $dlnks) { Add-Finding ("Atalho do ativador: {0}" -f $l.FullName) }
} else {
    Add-Clean 'Nenhum atalho do ativador na area de trabalho / menu iniciar'
}

# 04 - Instaladores em Downloads e area de trabalho
$dInstDirs = @((Join-Path $env:USERPROFILE 'Downloads'), [Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('CommonDesktopDirectory')) | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique
$dInst = @()
foreach ($d in $dInstDirs) {
    $dInst += @(Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)kms.?pico' })
}
if ($dInst.Count -gt 0) {
    foreach ($f in $dInst) { Add-Finding ("Instalador do ativador: {0}" -f $f.FullName) }
} else {
    Add-Clean 'Nenhum instalador (setup/zip) do KMS Pico em Downloads ou area de trabalho'
}

# 05 - Variantes de outros ativadores
$dVar = @($variants | Where-Object { Test-Path -LiteralPath $_ })
if ($dVar.Count -gt 0) {
    foreach ($v in $dVar) { Add-Finding ("Variante de ativador (KMSAuto/AutoKMS): {0}" -f $v) }
} else {
    Add-Clean 'Nenhuma variante conhecida (KMSAuto/AutoKMS) encontrada'
}

# 06 - Tarefas agendadas
$dTasks = @(@(Get-ScheduledTask -ErrorAction SilentlyContinue) | Where-Object {
    ($_.TaskName -match '(?i)kms|pico') -or
    ($_.TaskPath -match '(?i)kms|pico') -or
    ((@($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ') -match '(?i)kmspico|servicekms|autopico|kmseldi')
})
if ($dTasks.Count -gt 0) {
    foreach ($t in $dTasks) { Add-Finding ("Tarefa agendada: {0}{1}" -f $t.TaskPath, $t.TaskName) }
} else {
    Add-Clean 'Nenhuma tarefa agendada do ativador'
}

# 07 - Servicos
$dSvc = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
    ($_.Name -match '(?i)servicekms|kmseldi|autopico') -or ($_.PathName -match '(?i)kmspico')
})
if ($dSvc.Count -gt 0) {
    foreach ($s in $dSvc) { Add-Finding ("Servico do ativador: {0} ({1})" -f $s.Name, $s.PathName) }
} else {
    Add-Clean 'Nenhum servico do KMS Pico instalado'
}

# 08 - Chaves de registro
$dRegFound = 0
foreach ($k in $regKeys) {
    if (Test-Path -LiteralPath $k) { Add-Finding ("Chave de registro: {0}" -f $k); $dRegFound++ }
}
if ($dRegFound -eq 0) { Add-Clean 'Nenhuma chave de registro do ativador (HKLM/HKCU)' }

# 09 - Entradas de desinstalacao (Programas e Recursos)
$dUnFound = 0
foreach ($root in $uninstRoots) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    $subs = @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)
    foreach ($s in $subs) {
        $props = Get-ItemProperty -LiteralPath $s.PSPath -ErrorAction SilentlyContinue
        $dn = ''
        if ($props -and $props.DisplayName) { $dn = [string]$props.DisplayName }
        if ($s.PSChildName -match '(?i)kms|pico' -or $dn -match '(?i)kms.?pico|kms pico') {
            $lbl = $s.PSChildName
            if ($dn) { $lbl = $dn }
            Add-Finding ("Entrada de desinstalacao (Programas e Recursos): {0}" -f $lbl)
            $dUnFound++
        }
    }
}
if ($dUnFound -eq 0) { Add-Clean 'Nenhuma entrada de desinstalacao (Programas e Recursos) do ativador' }

# 10 - Inicializacao automatica (Run / RunOnce)
$dRunFound = 0
foreach ($rp in $runPaths) {
    if (-not (Test-Path -LiteralPath $rp)) { continue }
    $names = @(Get-Item -LiteralPath $rp -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property -ErrorAction SilentlyContinue)
    foreach ($n in $names) {
        $val = ''
        try { $val = [string](Get-ItemProperty -LiteralPath $rp -Name $n -ErrorAction Stop).$n } catch { continue }
        if ($val -match '(?i)kmspico|autopico|servicekms|kmseldi|kms.?pico') {
            Add-Finding ("Inicializacao automatica [{0}] = {1}" -f $n, $val)
            $dRunFound++
        }
    }
}
if ($dRunFound -eq 0) { Add-Clean 'Nenhuma entrada de inicializacao automatica (Run/RunOnce) do ativador' }

# 11 - Firewall
try {
    $dFw = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.DisplayName -match '(?i)kms|pico' })
    if ($dFw.Count -gt 0) {
        foreach ($r in $dFw) { Add-Finding ("Regra de firewall: {0}" -f $r.DisplayName) }
    } else {
        Add-Clean 'Nenhuma regra de firewall do ativador (por nome)'
    }
} catch {
    Write-Status INFO ("Nao foi possivel enumerar o firewall: {0}" -f $_.Exception.Message)
}

# 12 - Arquivo hosts
$dHostsPath = "$env:windir\System32\drivers\etc\hosts"
if (Test-Path -LiteralPath $dHostsPath) {
    $dLines    = @(Get-Content -LiteralPath $dHostsPath -ErrorAction SilentlyContinue)
    $dKmsLines = @($dLines | Where-Object { $_ -match '(?i)kms' })
    if ($dKmsLines.Count -gt 0) {
        foreach ($b in $dKmsLines) { Add-Finding ("Linha do arquivo hosts: {0}" -f $b.Trim()) }
    } else {
        Add-Clean 'Arquivo hosts sem linhas com KMS'
    }
}

# 13 - Adaptador TAP
$dTaps = @(Get-PnpDevice -Class Net -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -match '(?i)kms|pico' })
if ($dTaps.Count -gt 0) {
    foreach ($t in $dTaps) { Add-Finding ("Adaptador de rede do ativador: {0}" -f $t.FriendlyName) }
} else {
    Add-Clean 'Nenhum adaptador de rede com nome KMS/Pico'
}

# 14 - Exclusoes do Defender
$dMp = Get-MpPreference -ErrorAction SilentlyContinue
if ($dMp) {
    $dExcFound = 0
    foreach ($field in @('ExclusionPath', 'ExclusionProcess', 'ExclusionExtension', 'ExclusionIpAddress')) {
        $dBad = @(@($dMp.$field) | Where-Object { $_ -and ($_ -match '(?i)kms|pico') })
        if ($dBad.Count -gt 0) {
            foreach ($b in $dBad) { Add-Finding ("Exclusao do Defender [{0}]: {1}" -f $field, $b) }
            $dExcFound++
        }
    }
    if ($dExcFound -eq 0) { Add-Clean 'Nenhuma exclusao suspeita no Windows Defender' }
}

# 15 - Canal de ativacao do Windows (KMS corporativo de dominio nao conta como malware)
$dAppId   = '55c92734-d682-4d71-983e-d6ec3f16059f'
$dLics    = @(Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "ApplicationID='$dAppId' AND PartialProductKey IS NOT NULL" -ErrorAction SilentlyContinue)
$dKmsLics = @($dLics | Where-Object { $_.Description -match '(?i)KMSCLIENT' })
if ($dKmsLics.Count -gt 0) {
    $isDomain = $false
    try { $isDomain = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch { $isDomain = $false }
    if ($isDomain) {
        Write-Status INFO 'Ativacao em canal KMS (VOLUME_KMSCLIENT) com o PC em dominio: pode ser KMS legitimo da empresa'
    } else {
        Add-Finding 'Ativacao do Windows em canal KMS (VOLUME_KMSCLIENT): tipica de ativador pirata'
    }
} else {
    Add-Clean 'Ativacao do Windows fora do canal KMS (OEM/Retail/digital)'
}

# ============================================================================
# RESULTADO DA VERIFICACAO + PERGUNTA DE REMOCAO
# ============================================================================
Write-Host ''
if ($script:DetCount -eq 0) {
    Write-Host ('=' * 78) -ForegroundColor Green
    Write-Host '   SEU COMPUTADOR NAO CONTEM ESTE MALWARE' -ForegroundColor Green
    Write-Host ('=' * 78) -ForegroundColor Green
    Write-Host '  Nenhum vestigio do KMS Pico foi encontrado (processos, arquivos, registro,' -ForegroundColor White
    Write-Host '  tarefas, servicos, firewall, hosts, adaptador TAP e exclusoes do Defender).' -ForegroundColor White
    Write-Host '  Nenhuma alteracao foi feita no computador.' -ForegroundColor White
    Read-Host 'Pressione ENTER para sair'
    if ($PSCommandPath) { exit 0 } else { return }
}
Write-Host ('=' * 78) -ForegroundColor Yellow
Write-Host ("   ATENCAO: {0} indicador(es) do KMS Pico / ativadores encontrado(s) neste PC" -f $script:DetCount) -ForegroundColor Yellow
Write-Host ('=' * 78) -ForegroundColor Yellow
$resp2 = Read-Host '  Deseja remover agora (limpeza completa com ponto de restauracao)? (S/N)'
if ($resp2 -notmatch '^(?i)[sy]') {
    Write-Host ''
    Write-Host '  Remocao cancelada. Nada foi alterado e os itens listados continuam no PC.' -ForegroundColor Gray
    Read-Host 'Pressione ENTER para sair'
    if ($PSCommandPath) { exit 0 } else { return }
}

# ============================================================================
# PASSO 1/10 - PONTO DE RESTAURACAO
# ============================================================================
Write-Section 'PASSO 1/10 - PONTO DE RESTAURACAO (seguranca antes de tudo)'
$before = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue)
try {
    Checkpoint-Computer -Description 'Pre-Limpeza KMS Pico' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
    Start-Sleep -Seconds 2
    $after = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue)
    if ($after.Count -gt $before.Count) {
        Write-Status OK 'Ponto de restauracao criado: Pre-Limpeza KMS Pico'
    } else {
        Write-Status PEND 'Ponto nao criado: limite de 24h atingido ou Restauracao do Sistema desativada'
        $script:Pending.Add('Habilitar a Restauracao do Sistema (Painel de Controle > Recuperacao) e criar um ponto')
    }
} catch {
    Write-Status PEND ("Nao foi possivel criar o ponto de restauracao: {0}" -f $_.Exception.Message)
    $script:Pending.Add('Criar ponto de restauracao manualmente (Painel de Controle > Recuperacao)')
}

# ============================================================================
# PASSO 2/10 - PROCESSOS DO ATIVADOR
# ============================================================================
Write-Section 'PASSO 2/10 - PROCESSOS DO ATIVADOR'
$procNames = @('KMSPico', 'KMSELDI', 'AutoPico', 'ServiceKMS', 'UnSec')
$procs  = @(Get-Process -Name $procNames -ErrorAction SilentlyContinue)
$procs += @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path -match '(?i)kmspico' })
$procs  = @($procs | Where-Object { $_ } | Sort-Object Id -Unique)
if ($procs.Count -eq 0) {
    Write-Status MISS 'Nenhum processo do KMS Pico em execucao'
} else {
    foreach ($p in $procs) {
        try {
            Stop-Process -Id $p.Id -Force -ErrorAction Stop
            Write-Status OK ("Processo finalizado: {0} (PID {1})" -f $p.ProcessName, $p.Id)
        } catch {
            Write-Status PEND ("Nao consegui finalizar o processo {0} (PID {1})" -f $p.ProcessName, $p.Id)
            $script:Pending.Add("Finalizar manualmente o processo $($p.ProcessName) (PID $($p.Id))")
        }
    }
}

# ============================================================================
# PASSO 3/10 - ARQUIVOS, PASTAS, ATALHOS E INSTALADORES
# ============================================================================
Write-Section 'PASSO 3/10 - ARQUIVOS, PASTAS, ATALHOS E INSTALADORES'
# $targets definido na secao "LISTAS DE ALVOS CONHECIDOS"
foreach ($t in $targets) { Remove-Target -Path $t.Path -Label $t.Label }

# Atalhos (.lnk) na area de trabalho e menu iniciar
$deskUser = [Environment]::GetFolderPath('Desktop')
$deskAll  = [Environment]::GetFolderPath('CommonDesktopDirectory')
$lnkDirs  = @($deskUser, $deskAll, [Environment]::GetFolderPath('Programs')) | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique
$lnkFound = 0
foreach ($d in $lnkDirs) {
    $lnks = @(Get-ChildItem -LiteralPath $d -Filter '*.lnk' -ErrorAction SilentlyContinue | Where-Object { $_.BaseName -match '(?i)kms|pico' })
    foreach ($l in $lnks) {
        try {
            Remove-Item -LiteralPath $l.FullName -Force -ErrorAction Stop
            Write-Status OK ("Atalho removido: {0}" -f $l.FullName)
            $lnkFound++
        } catch {
            Write-Status PEND ("Atalho nao removido: {0}" -f $l.FullName)
        }
    }
}
if ($lnkFound -eq 0) { Write-Status MISS 'Nenhum atalho do ativador na area de trabalho / menu iniciar' }

# Instaladores (setup/zip) do KMS Pico em Downloads e area de trabalho
$dl       = Join-Path $env:USERPROFILE 'Downloads'
$instDirs = @($dl, $deskUser, $deskAll) | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique
$instFound = 0
foreach ($d in $instDirs) {
    $files = @(Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)kms.?pico' })
    foreach ($f in $files) {
        try {
            Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop
            Write-Status OK ("Instalador do ativador excluido: {0}" -f $f.FullName)
            $instFound++
        } catch {
            Write-Status PEND ("Instalador nao excluido: {0}" -f $f.FullName)
        }
    }
}
if ($instFound -eq 0) { Write-Status MISS 'Nenhum instalador (setup/zip) do KMS Pico em Downloads ou area de trabalho' }

# Variantes de outros ativadores (apenas aviso, fora do escopo do KMS Pico)
Write-Host ''
Write-Host '  Variantes de outros ativadores (apenas aviso, nao foram removidas):' -ForegroundColor DarkGray
# $variants definido na secao "LISTAS DE ALVOS CONHECIDOS"
$varFound = $false
foreach ($v in $variants) {
    if (Test-Path -LiteralPath $v) {
        $varFound = $true
        Write-Status INFO ("Variante de ativador detectada: {0}" -f $v)
        $script:Pending.Add("Avaliar e remover a variante de ativador encontrada: $v")
    }
}
if (-not $varFound) { Write-Status MISS 'Nenhuma variante conhecida (KMSAuto/AutoKMS) encontrada' }

# ============================================================================
# PASSO 4/10 - TAREFAS AGENDADAS
# ============================================================================
Write-Section 'PASSO 4/10 - TAREFAS AGENDADAS'
$allTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue)
$kmsTasks = @($allTasks | Where-Object {
    ($_.TaskName -match '(?i)kms|pico') -or
    ($_.TaskPath -match '(?i)kms|pico') -or
    ((@($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ') -match '(?i)kmspico|servicekms|autopico|kmseldi')
})
if ($kmsTasks.Count -eq 0) {
    Write-Status MISS 'Nenhuma tarefa agendada do ativador'
} else {
    foreach ($t in $kmsTasks) {
        $fullName = "{0}{1}" -f $t.TaskPath, $t.TaskName
        try {
            Unregister-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName -Confirm:$false -ErrorAction Stop
            Write-Status OK ("Tarefa removida: {0}" -f $fullName)
        } catch {
            Write-Status PEND ("Nao foi possivel remover a tarefa: {0} ({1})" -f $fullName, $_.Exception.Message)
            $script:Pending.Add("Remover manualmente a tarefa agendada: $fullName")
        }
    }
}

# ============================================================================
# PASSO 5/10 - SERVICOS
# ============================================================================
Write-Section 'PASSO 5/10 - SERVICOS'
$services = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
    ($_.Name -match '(?i)servicekms|kmseldi|autopico') -or ($_.PathName -match '(?i)kmspico')
})
if ($services.Count -eq 0) {
    Write-Status MISS 'Nenhum servico do KMS Pico instalado'
} else {
    foreach ($s in $services) {
        Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue
        $del = sc.exe delete "$($s.Name)"
        if ($LASTEXITCODE -eq 0) {
            Write-Status OK ("Servico removido: {0} ({1})" -f $s.Name, $s.PathName)
        } else {
            Write-Status PEND ("Nao foi possivel remover o servico {0}: {1}" -f $s.Name, (($del | Out-String).Trim()))
            $script:Pending.Add("Remover manualmente o servico: $($s.Name) (comando: sc delete $($s.Name))")
        }
    }
    Write-Status INFO 'Observacao: a remocao total do servico vale apos reiniciar o PC'
}

# ============================================================================
# PASSO 6/10 - REGISTRO DO WINDOWS
# ============================================================================
Write-Section 'PASSO 6/10 - REGISTRO DO WINDOWS (chaves, Run/RunOnce, desinstalacao)'

# $regKeys e $uninstRoots definidos na secao "LISTAS DE ALVOS CONHECIDOS"
foreach ($k in $regKeys) { Remove-Target -Path $k -Label 'Chave de registro' }

# Entradas de desinstalacao (Programas e Recursos; KMSpico usa Inno Setup -> *_is1)
$unFound = 0
foreach ($root in $uninstRoots) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    $subs = @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)
    foreach ($s in $subs) {
        $props = Get-ItemProperty -LiteralPath $s.PSPath -ErrorAction SilentlyContinue
        $dn = ''
        if ($props -and $props.DisplayName) { $dn = [string]$props.DisplayName }
        if ($s.PSChildName -match '(?i)kms|pico' -or $dn -match '(?i)kms.?pico|kms pico') {
            try {
                Remove-Item -LiteralPath $s.PSPath -Recurse -Force -ErrorAction Stop
                if ($dn) { $label = $dn } else { $label = $s.PSChildName }
                Write-Status OK ("Entrada de desinstalacao removida: {0}" -f $label)
                $unFound++
            } catch {
                Write-Status PEND ("Entrada de desinstalacao nao removida: {0}" -f $s.PSChildName)
                $script:Pending.Add("Remover do registro a entrada de desinstalacao: $($s.PSPath)")
            }
        }
    }
}
if ($unFound -eq 0) { Write-Status MISS 'Nenhuma entrada de desinstalacao (Programas e Recursos) do ativador' }

# Inicializacao automatica (Run / RunOnce)
# $runPaths definido na secao "LISTAS DE ALVOS CONHECIDOS"
$runFound = 0
foreach ($rp in $runPaths) {
    if (-not (Test-Path -LiteralPath $rp)) { continue }
    $names = @(Get-Item -LiteralPath $rp -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property -ErrorAction SilentlyContinue)
    foreach ($n in $names) {
        $val = ''
        try { $val = [string](Get-ItemProperty -LiteralPath $rp -Name $n -ErrorAction Stop).$n } catch { continue }
        if ($val -match '(?i)kmspico|autopico|servicekms|kmseldi|kms.?pico') {
            try {
                Remove-ItemProperty -LiteralPath $rp -Name $n -Force -ErrorAction Stop
                Write-Status OK ("Inicializacao automatica removida [{0}] = {1}" -f $n, $val)
                $runFound++
            } catch {
                Write-Status PEND ("Inicializacao automatica nao removida [{0}]" -f $n)
                $script:Pending.Add("Remover do registro o valor de Run: [$rp] $n")
            }
        }
    }
}
if ($runFound -eq 0) { Write-Status MISS 'Nenhuma entrada de inicializacao automatica (Run/RunOnce) do ativador' }

# ============================================================================
# PASSO 7/10 - FIREWALL E ARQUIVO HOSTS
# ============================================================================
Write-Section 'PASSO 7/10 - FIREWALL E ARQUIVO HOSTS'
try {
    $fwRules = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.DisplayName -match '(?i)kms|pico' })
    if ($fwRules.Count -eq 0) {
        Write-Status MISS 'Nenhuma regra de firewall do ativador (por nome)'
    } else {
        foreach ($r in $fwRules) {
            Remove-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue
            Write-Status OK ("Regra de firewall removida: {0}" -f $r.DisplayName)
        }
    }
} catch {
    Write-Status INFO ("Nao foi possivel enumerar o firewall: {0}" -f $_.Exception.Message)
}

$hostsPath = "$env:windir\System32\drivers\etc\hosts"
if (Test-Path -LiteralPath $hostsPath) {
    $lines    = @(Get-Content -LiteralPath $hostsPath -ErrorAction SilentlyContinue)
    $kmsLines = @($lines | Where-Object { $_ -match '(?i)kms' })
    $msLines  = @($lines | Where-Object { $_ -match '(?i)(127\.0\.0\.1|0\.0\.0\.0)\s+\S*microsoft\S*' })
    if ($kmsLines.Count -gt 0) {
        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $bak   = "$hostsPath.bak_KMS_$stamp"
        try {
            Copy-Item -LiteralPath $hostsPath -Destination $bak -Force -ErrorAction Stop
            $clean = @($lines | Where-Object { -not ($_ -match '(?i)kms') })
            Set-Content -LiteralPath $hostsPath -Value $clean -Encoding ASCII -Force -ErrorAction Stop
            foreach ($b in $kmsLines) { Write-Status OK ("Linha do hosts removida: {0}" -f $b.Trim()) }
            Write-Status INFO ("Backup do hosts salvo em: {0}" -f $bak)
        } catch {
            Write-Status PEND ("Nao foi possivel editar o arquivo hosts: {0}" -f $_.Exception.Message)
            $script:Pending.Add('Editar manualmente o hosts (C:\Windows\System32\drivers\etc\hosts) e remover linhas com KMS')
        }
    } else {
        Write-Status MISS 'Arquivo hosts sem linhas com KMS'
    }
    if ($msLines.Count -gt 0) {
        foreach ($m in $msLines) {
            Write-Status INFO ("Verifique (pode ser bloqueio proprio de telemetria, nao mexi): {0}" -f $m.Trim())
        }
    }
} else {
    Write-Status MISS 'Arquivo hosts nao encontrado (inesperado)'
}

# ============================================================================
# PASSO 8/10 - ADAPTADOR TAP VIRTUAL (REDE FALSA USADA PELO EMULADOR KMS)
# ============================================================================
Write-Section 'PASSO 8/10 - ADAPTADOR TAP VIRTUAL'
$kmsTaps = @(Get-PnpDevice -Class Net -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -match '(?i)kms|pico' })
if ($kmsTaps.Count -eq 0) {
    Write-Status MISS 'Nenhum adaptador de rede com nome KMS/Pico'
} else {
    foreach ($t in $kmsTaps) {
        $null = & pnputil.exe /remove-device "$($t.InstanceId)" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Status OK ("Adaptador TAP do ativador removido: {0}" -f $t.FriendlyName)
        } else {
            Write-Status PEND ("Nao foi possivel remover o adaptador: {0}" -f $t.FriendlyName)
            $script:Pending.Add("Gerenciador de Dispositivos > Adaptadores de rede > desinstalar: $($t.FriendlyName)")
        }
    }
}
$otherTaps = @(Get-PnpDevice -Class Net -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -match '(?i)tap-' })
$otherTaps = @($otherTaps | Where-Object { @($kmsTaps | ForEach-Object { $_.InstanceId }) -notcontains $_.InstanceId })
if ($otherTaps.Count -gt 0) {
    foreach ($o in $otherTaps) {
        Write-Status INFO ("TAP remanescente (pode ser de VPN legitima, nao mexi): {0}" -f $o.FriendlyName)
    }
}

# ============================================================================
# PASSO 9/10 - WINDOWS DEFENDER (EXCLUSOES E PROTECAO)
# ============================================================================
Write-Section 'PASSO 9/10 - WINDOWS DEFENDER (EXCLUSOES E PROTECAO)'
$mp = Get-MpPreference -ErrorAction SilentlyContinue
if ($mp) {
    $fields = @('ExclusionPath', 'ExclusionProcess', 'ExclusionExtension', 'ExclusionIpAddress')
    foreach ($field in $fields) {
        $vals = @($mp.$field) | Where-Object { $_ }
        $bad  = @($vals | Where-Object { $_ -match '(?i)kms|pico' })
        if ($bad.Count -gt 0) {
            try {
                switch ($field) {
                    'ExclusionPath'      { Remove-MpPreference -ExclusionPath $bad -ErrorAction Stop }
                    'ExclusionProcess'   { Remove-MpPreference -ExclusionProcess $bad -ErrorAction Stop }
                    'ExclusionExtension' { Remove-MpPreference -ExclusionExtension $bad -ErrorAction Stop }
                    'ExclusionIpAddress' { Remove-MpPreference -ExclusionIpAddress $bad -ErrorAction Stop }
                }
                foreach ($b in $bad) {
                    Write-Status OK ("Exclusao do Defender removida [{0}]: {1}" -f $field, $b)
                }
            } catch {
                Write-Status PEND ("Nao foi possivel remover exclusoes do Defender [{0}]" -f $field)
                $script:Pending.Add("Seguranca do Windows > Exclusoes: remover manualmente: $($bad -join ', ')")
            }
        } else {
            Write-Status MISS ("Exclusoes suspeitas [{0}]" -f $field)
        }
    }
    try {
        $st = Get-MpComputerStatus -ErrorAction Stop
        if ($st.RealTimeProtectionDisabled) {
            try {
                Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
                Write-Status OK 'Protecao em tempo real reativada (confirme no Seguranca do Windows)'
            } catch {
                Write-Status PEND 'Protecao em tempo real esta DESATIVADA (protecao contra adulteracao pode estar bloqueando)'
                $script:Pending.Add('Reativar a protecao em tempo real no Seguranca do Windows')
            }
        } else {
            Write-Status INFO 'Protecao em tempo real do Defender ativa'
        }
    } catch {
        Write-Status INFO ("Estado do Defender nao disponivel: {0}" -f $_.Exception.Message)
    }
    $polKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    if (Test-Path -LiteralPath $polKey) {
        $pol = Get-ItemProperty -LiteralPath $polKey -ErrorAction SilentlyContinue
        if ($pol -and ($pol.DisableAntiSpyware -eq 1)) {
            Remove-ItemProperty -LiteralPath $polKey -Name 'DisableAntiSpyware' -Force -ErrorAction SilentlyContinue
            Write-Status OK 'Politica DisableAntiSpyware (desliga o Defender) removida do registro'
        }
        if ($pol -and ($pol.DisableRealtimeMonitoring -eq 1)) {
            Remove-ItemProperty -LiteralPath $polKey -Name 'DisableRealtimeMonitoring' -Force -ErrorAction SilentlyContinue
            Write-Status OK 'Politica DisableRealtimeMonitoring removida do registro'
        }
    } else {
        Write-Status MISS 'Politicas de grupo desativando o Defender'
    }
} else {
    Write-Status INFO 'Windows Defender nao disponivel (antivirus de terceiros?) - exclusoes nao verificadas'
}

# ============================================================================
# PASSO 10/10 - ATIVACAO: RESET PARA ESTADO LEGITIMO (WINDOWS + OFFICE)
# ============================================================================
Write-Section 'PASSO 10/10 - ATIVACAO: RESET PARA ESTADO LEGITIMO (WINDOWS + OFFICE)'
$slmgr = Join-Path $env:windir 'System32\slmgr.vbs'
if (Test-Path -LiteralPath $slmgr) {
    $r = Invoke-CscriptArg -VbsPath $slmgr -Arguments @('/ckms')
    if ($r.Exit -eq 0) {
        Write-Status OK 'Servidor KMS falso apagado da configuracao do Windows (slmgr /ckms)'
    } else {
        Write-Status PEND 'Falha ao limpar o servidor KMS do Windows (slmgr /ckms)'
    }
    $appId   = '55c92734-d682-4d71-983e-d6ec3f16059f'
    $lics    = @(Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "ApplicationID='$appId' AND PartialProductKey IS NOT NULL" -ErrorAction SilentlyContinue)
    $kmsLics = @($lics | Where-Object { $_.Description -match '(?i)KMSCLIENT' })
    if ($kmsLics.Count -gt 0) {
        foreach ($l in $kmsLics) {
            Write-Status INFO ("Ativacao por KMS detectada (falsa): {0}" -f $l.Description)
        }
        $oa  = $null
        $sls = Get-CimInstance -ClassName SoftwareLicensingService -ErrorAction SilentlyContinue
        if ($sls) { $oa = $sls.OA3xOriginalProductKey }
        if ($oa) {
            $r2 = Invoke-CscriptArg -VbsPath $slmgr -Arguments @('/ipk', $oa)
            if ($r2.Exit -eq 0) {
                Write-Status OK 'Chave original do fabricante (OEM, gravada no firmware) reinstalada'
                Write-Status INFO 'Conecte o PC a internet e aguarde: o Windows deve se ativar de forma legitima'
            } else {
                Write-Status PEND 'Nao consegui reinstalar a chave OEM do firmware'
                $script:Pending.Add('Instalar a chave legitima do Windows em Configuracoes > Sistema > Ativacao')
            }
        } else {
            $r3 = Invoke-CscriptArg -VbsPath $slmgr -Arguments @('/upk')
            if ($r3.Exit -eq 0) {
                Write-Status OK 'Chave generica (GVLK) usada pelo ativador foi desinstalada'
            } else {
                Write-Status PEND 'Nao consegui desinstalar a chave generica do ativador'
            }
            Write-Status PEND 'Este PC NAO tem chave OEM no firmware: sera preciso chave/conta legitima para ativar'
            $script:Pending.Add('Ativar o Windows com licenca legitima em Configuracoes > Sistema > Ativacao')
        }
    } else {
        Write-Status INFO 'Nenhuma ativacao por KMS (VOLUME_KMSCLIENT) encontrada no Windows - nada falso aqui'
        foreach ($l in $lics) {
            Write-Status INFO ("Canal atual do Windows: {0}" -f $l.Description)
        }
    }
} else {
    Write-Status PEND 'slmgr.vbs nao encontrado (instalacao do Windows incompleta?)'
}

# Office (2013 ou anterior: pastas Office12/14/15; tambem cobre C2R Office16 se existir)
Write-Host ''
$officeRoots = @(
    "${env:ProgramFiles(x86)}\Microsoft Office",
    "$env:ProgramFiles\Microsoft Office"
)
$osppFiles = @()
foreach ($root in $officeRoots) {
    if (Test-Path -LiteralPath $root) {
        $osppFiles += @(Get-ChildItem -LiteralPath $root -Recurse -Filter 'OSPP.VBS' -ErrorAction SilentlyContinue)
    }
}
$osppFiles = @($osppFiles | Sort-Object -Property FullName -Unique)
if ($osppFiles.Count -eq 0) {
    Write-Status MISS 'Nenhuma instalacao de Office encontrada (ospp.vbs ausente) - nada a fazer no Office'
} else {
    foreach ($ospp in $osppFiles) {
        Write-Host ("  Office detectado em: {0}" -f $ospp.DirectoryName) -ForegroundColor DarkGray
        $r = Invoke-CscriptArg -VbsPath $ospp.FullName -Arguments @('/remhst')
        if ($r.Exit -eq 0) {
            Write-Status OK 'Host/servidor KMS falso removido da configuracao do Office (ospp /remhst)'
        } else {
            Write-Status PEND ("ospp /remhst retornou o codigo {0}" -f $r.Exit)
        }
        $dstat  = Invoke-CscriptArg -VbsPath $ospp.FullName -Arguments @('/dstatus')
        $lines  = @($dstat.Output -split "`r?`n")
        $inKms  = $false
        $last5  = @()
        foreach ($line in $lines) {
            if ($line -match '^\s*$') { $inKms = $false; continue }
            if ($line -match '(?i)KMSCLIENT') { $inKms = $true }
            if ($inKms -and $line -match '(?i)5\s*(caracter|character)' -and $line -match '([A-Z0-9]{5})\s*$') {
                $last5 += $Matches[1]
                $inKms = $false
            }
        }
        $last5 = @($last5 | Sort-Object -Unique)
        if ($last5.Count -gt 0) {
            foreach ($k in $last5) {
                $ru = Invoke-CscriptArg -VbsPath $ospp.FullName -Arguments @('/unpkey', $k)
                if ($ru.Exit -eq 0) {
                    Write-Status OK ("Chave KMS falsa do Office removida (termina em {0})" -f $k)
                } else {
                    Write-Status PEND ("Falha ao remover a chave do Office que termina em {0}" -f $k)
                    $script:Pending.Add("Office: remover manualmente a chave final $k (ospp.vbs /unpkey $k)")
                }
            }
            Write-Status PEND 'Reative o Office com licenca legitima (conta Microsoft ou chave de produto)'
            $script:Pending.Add('Ativar o Office com licenca legitima')
        } else {
            Write-Status INFO 'Nenhuma chave de ativacao KMS (volume) instalada neste Office'
        }
    }
}

# ============================================================================
# EXTRA - VERIFICACAO RAPIDA DO DEFENDER (SCAN FINAL)
# ============================================================================
Write-Section 'VERIFICACAO RAPIDA DO DEFENDER (SCAN FINAL)'
if ($SkipDefenderScan) {
    Write-Status INFO 'Scan ignorado (parametro -SkipDefenderScan)'
} else {
    try {
        Write-Host '  Rodando verificacao rapida (pode levar alguns minutos)...' -ForegroundColor DarkGray
        Start-MpScan -ScanType QuickScan -ErrorAction Stop
        Write-Status OK 'Verificacao rapida concluida'
        Write-Status INFO 'Rode tambem uma verificacao COMPLETA: Seguranca do Windows > Protecao contra virus > Opcoes de verificacao'
    } catch {
        Write-Status PEND ("Nao foi possivel rodar a verificacao: {0}" -f $_.Exception.Message)
        $script:Pending.Add('Rodar verificacao completa do Windows Defender manualmente')
    }
}

# ============================================================================
# RESUMO FINAL
# ============================================================================
Write-Section 'RESUMO FINAL'
Write-Host ("  Itens removidos/ajustados .....: {0}" -f $script:Stats.Removido)      -ForegroundColor Green
Write-Host ("  Itens nao encontrados .........: {0}" -f $script:Stats.NaoEncontrado) -ForegroundColor DarkGray
Write-Host ("  Pendencias / acoes manuais ....: {0}" -f $script:Stats.Pendente)      -ForegroundColor Yellow
if ($script:Pending.Count -gt 0) {
    Write-Host ''
    Write-Host '  PENDENCIAS:' -ForegroundColor Yellow
    $i = 1
    foreach ($p in $script:Pending) {
        Write-Host ("   {0}. {1}" -f $i, $p) -ForegroundColor Yellow
        $i++
    }
}
Write-Host ''
Write-Host '  PROXIMOS PASSOS RECOMENDADOS:' -ForegroundColor Cyan
Write-Host '   1. Reinicie o PC para concluir a remocao (servicos/adaptador).' -ForegroundColor White
Write-Host '   2. Rode uma verificacao COMPLETA do Defender (ou o Microsoft Safety Scanner).' -ForegroundColor White
Write-Host '   3. Ative o Windows e o Office com licenca legitima (Configuracoes > Ativacao).' -ForegroundColor White
Write-Host '   4. Se o ativador rodou por muito tempo, considere trocar senhas importantes:' -ForegroundColor White
Write-Host '      ativadores falsos frequentemente vem com trojans que roubam credenciais.' -ForegroundColor White
Write-Host ''
Write-Host 'Fim da limpeza cirurgica.' -ForegroundColor Green
Read-Host 'Pressione ENTER para sair'
