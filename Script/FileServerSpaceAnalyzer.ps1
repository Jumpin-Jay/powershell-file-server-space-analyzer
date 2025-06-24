# Analisador de Espaço em Servidor de Arquivos
# Versão: 2.3 - Otimizada com melhor detecção de deduplicação
# Desenvolvido por: Mathews Buzetti
#
# 🛡️ SEGURANÇA: Este script é 100% READ-ONLY
# - NUNCA remove arquivos dos usuários
# - NUNCA modifica dados existentes  
# - Apenas cria relatórios de análise

#########################################################
################# PARÂMETROS AJUSTÁVEIS #################
#########################################################
$TamanhoMinimoArquivosMB = 500
$DiasArquivosAntigos = 90
$TopArquivosGrandesAntigos = 1000
$TamanhoMinimoArquivosDuplicadosMB = 50
$TopGruposDuplicados = 2000
$ModoSilencioso = $true
$MaxErrosPorTipo = 50
$GerarRelatorioErros = $true
#########################################################

$Global:ConfigGlobal = @{
    DiretoriosIgnorar = @(
        "*\System Volume Information", "*\`$RECYCLE.BIN", "*\Windows\WinSxS",
        "*\Windows\Temp", "*\Windows\SoftwareDistribution", "*\Windows\Logs",
        "*\Windows\Panther", "*\Windows\servicing", "*\ProgramData\Microsoft\Windows\WER",
        "*\Users\*\AppData\Local\Temp", "*\Users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files"
    )
    LogHabilitado = $true
    ArquivoLog = "C:\temp\AnaliseArquivos.log"
    MostrarLogConsole = $false
}

$Global:CaminhosFalharam = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$Global:CaminhosAcessiveis = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$Global:TentativasEvitadas = 0

$Global:ErrosEncontrados = @{
    "SemPermissao" = [System.Collections.ArrayList]::new()
    "CaminhosLongos" = [System.Collections.ArrayList]::new()
    "ArquivosNaoEncontrados" = [System.Collections.ArrayList]::new()
    "OutrosErros" = [System.Collections.ArrayList]::new()
    "Contadores" = @{
        "SemPermissao" = 0; "CaminhosLongos" = 0; "ArquivosNaoEncontrados" = 0
        "OutrosErros" = 0; "TotalErros" = 0; "TotalArquivosProcessados" = 0
        "TotalPastasInacessiveis" = 0; "PercentualCobertura" = 0
    }
}

function Format-Number {
    param (
        [Parameter(Mandatory=$true)]$Value,
        [int]$DecimalPlaces = 2,
        [switch]$NoDecimal
    )
    
    try {
        $NumericValue = [double]$Value
        if ($NoDecimal) {
            return $NumericValue.ToString("N0", [System.Globalization.CultureInfo]::InvariantCulture)
        } else {
            return $NumericValue.ToString("N$DecimalPlaces", [System.Globalization.CultureInfo]::InvariantCulture)
        }
    } catch {
        return $Value.ToString()
    }
}

function Format-FileSize {
    param (
        [long]$SizeBytes,
        [switch]$PreferirGB
    )
    
    $SizeKB = $SizeBytes / 1KB
    $SizeMB = $SizeBytes / 1MB
    $SizeGB = $SizeBytes / 1GB
    $SizeTB = $SizeBytes / 1TB
    
    if ($SizeTB -ge 1) {
        return @{
            "Value" = $SizeTB
            "Unit" = "TB"
            "Formatted" = "$(Format-Number -Value $SizeTB -DecimalPlaces 2) TB"
            "OriginalGB" = $SizeGB
        }
    } elseif ($SizeGB -ge 1) {
        return @{
            "Value" = $SizeGB
            "Unit" = "GB"
            "Formatted" = "$(Format-Number -Value $SizeGB -DecimalPlaces 2) GB"
            "OriginalGB" = $SizeGB
        }
    } elseif ($SizeMB -ge 1) {
        return @{
            "Value" = $SizeMB
            "Unit" = "MB"
            "Formatted" = "$(Format-Number -Value $SizeMB -DecimalPlaces 1) MB"
            "OriginalGB" = $SizeGB
        }
    } else {
        return @{
            "Value" = $SizeKB
            "Unit" = "KB"
            "Formatted" = "$(Format-Number -Value $SizeKB -NoDecimal) KB"
            "OriginalGB" = $SizeGB
        }
    }
}

function Format-FileSizeForceGB {
    param ([double]$SizeGB)
    
    if ($SizeGB -ge 1024) {
        $SizeTB = $SizeGB / 1024
        return @{
            "Value" = $SizeTB
            "Unit" = "TB"
            "Formatted" = "$(Format-Number -Value $SizeTB -DecimalPlaces 2) TB"
            "OriginalGB" = $SizeGB
        }
    } else {
        return @{
            "Value" = $SizeGB
            "Unit" = "GB"
            "Formatted" = "$(Format-Number -Value $SizeGB -DecimalPlaces 2) GB"
            "OriginalGB" = $SizeGB
        }
    }
}

function Get-ConsistentValues {
    param (
        [double]$EspacoDuplicadosGB,
        [double]$EspacoGrandesAntigosGB,
        [double]$EspacoTemporariosGB,
        [double]$EconomiaDeduplicacaoGB = 0
    )
    
    # CORREÇÃO: Calcular total em GB SEM arredondamento intermediário
    $TotalGB = $EspacoDuplicadosGB + $EspacoGrandesAntigosGB + $EspacoTemporariosGB + $EconomiaDeduplicacaoGB
    
    # Formatação APENAS para exibição
    $FormatTotal = Format-FileSizeForceGB -SizeGB $TotalGB
    $FormatDuplicados = Format-FileSizeForceGB -SizeGB $EspacoDuplicadosGB
    $FormatGrandesAntigos = Format-FileSizeForceGB -SizeGB $EspacoGrandesAntigosGB
    $FormatTemporarios = Format-FileSizeForceGB -SizeGB $EspacoTemporariosGB
    
    return @{
        "TotalGB" = $TotalGB
        "TotalFormatted" = $FormatTotal
        "DuplicadosFormatted" = $FormatDuplicados
        "GrandesAntigosFormatted" = $FormatGrandesAntigos
        "TemporariosFormatted" = $FormatTemporarios
        "DeduplicacaoGB" = $EconomiaDeduplicacaoGB
    }
}

function Escrever-Log {
    param ([string]$Mensagem, [string]$Tipo = "INFO")
    
    if (-not $Global:ConfigGlobal.LogHabilitado) { return }
    
    $PastaLog = Split-Path -Path $Global:ConfigGlobal.ArquivoLog -Parent
    if (-not (Test-Path -Path $PastaLog)) {
        New-Item -Path $PastaLog -ItemType Directory -Force | Out-Null
    }
    
    $Data = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Data] [$Tipo] $Mensagem"
    Add-Content -Path $Global:ConfigGlobal.ArquivoLog -Value $LogEntry -Encoding UTF8
    
    if ($Global:ConfigGlobal.MostrarLogConsole -and (-not $ModoSilencioso) -and $Tipo -ne "DEBUG") {
        switch ($Tipo) {
            "ERROR"   { Write-Host $LogEntry -ForegroundColor Red }
            "WARNING" { Write-Host $LogEntry -ForegroundColor Yellow }
            "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
            default   { Write-Host $LogEntry -ForegroundColor Cyan }
        }
    }
    elseif ($Tipo -eq "ERROR") {
        Write-Host $LogEntry -ForegroundColor Red
    }
}

function Classificar-TipoErro {
    param ([System.Management.Automation.ErrorRecord]$Erro, [string]$Caminho = "")
    
    $TipoErro = "OutrosErros"
    $Descricao = $Erro.Exception.Message
    
    if ($Erro.Exception -is [System.UnauthorizedAccessException]) {
        $TipoErro = "SemPermissao"; $Descricao = "Acesso negado"
    }
    elseif ($Erro.Exception -is [System.IO.PathTooLongException]) {
        $TipoErro = "CaminhosLongos"; $Descricao = "Caminho excede 260 caracteres"
    }
    elseif ($Erro.Exception -is [System.IO.FileNotFoundException] -or 
            $Erro.Exception -is [System.IO.DirectoryNotFoundException]) {
        $TipoErro = "ArquivosNaoEncontrados"; $Descricao = "Arquivo ou diretório não encontrado"
    }
    elseif ($Descricao -match "parte do caminho|path.*not.*found|cannot find") {
        $TipoErro = "CaminhosLongos"; $Descricao = "Caminho muito longo ou inválido"
    }
    elseif ($Descricao -match "access.*denied|unauthorized|permission") {
        $TipoErro = "SemPermissao"; $Descricao = "Sem permissão de acesso"
    }
    
    return @{ "Tipo" = $TipoErro; "Caminho" = $Caminho; "Descricao" = $Descricao; "Timestamp" = Get-Date }
}

function Registrar-Erro {
    param ([System.Management.Automation.ErrorRecord]$Erro, [string]$Caminho = "")
    
    $InfoErro = Classificar-TipoErro -Erro $Erro -Caminho $Caminho
    $TipoErro = $InfoErro.Tipo
    
    $Global:ErrosEncontrados.Contadores[$TipoErro]++
    $Global:ErrosEncontrados.Contadores.TotalErros++
    
    if ($Global:ErrosEncontrados[$TipoErro].Count -lt $MaxErrosPorTipo) {
        $Global:ErrosEncontrados[$TipoErro].Add([PSCustomObject]@{
            Caminho = $InfoErro.Caminho; Descricao = $InfoErro.Descricao
            Timestamp = $InfoErro.Timestamp; ErroCompleto = $Erro.Exception.Message
        }) | Out-Null
    }
    
    if (-not $ModoSilencioso -and $Global:ErrosEncontrados.Contadores[$TipoErro] % 10 -eq 1) {
        $emoji = switch ($TipoErro) {
            "SemPermissao" { "🔒" }; "CaminhosLongos" { "📏" }
            "ArquivosNaoEncontrados" { "❓" }; default { "⚠️" }
        }
        Write-Host "  $emoji Erros ${TipoErro}: $($Global:ErrosEncontrados.Contadores[$TipoErro])" -ForegroundColor Yellow
    }
}

function Get-ChildItemSeguro {
    param ([string]$Path, [switch]$File, [switch]$Recurse, [string[]]$Include = @())
    
    if ($Global:CaminhosFalharam.Contains($Path)) {
        $Global:TentativasEvitadas++
        return @()
    }
    
    if ($Global:CaminhosAcessiveis.Contains($Path)) {
        # Caminho já verificado como acessível
    } else {
        if ($Path.Length -gt 240) {
            $Global:CaminhosFalharam.Add($Path) | Out-Null
            $ErroSimulado = [System.Management.Automation.ErrorRecord]::new(
                [System.IO.PathTooLongException]::new("Caminho muito longo"),
                "PathTooLong", [System.Management.Automation.ErrorCategory]::InvalidArgument, $Path
            )
            Registrar-Erro -Erro $ErroSimulado -Caminho $Path
            return @()
        }
        
        $PathNormalized = $Path.ToLower()
        $FoldersToSkipCompletely = @(
            "\windows\winsxs", "\system volume information", "\`$recycle.bin",
            "\windows\softwareDistribution", "\windows\logs", "\windows\temp",
            "\windows\panther", "\windows\servicing", "\programdata\microsoft\windows\wer",
            "\users\all users\microsoft\windows\wer", "\recovery", "\perflogs",
            "\dfsrprivate", "\sysvol"
        )
        
        foreach ($skipPattern in $FoldersToSkipCompletely) {
            if ($PathNormalized.Contains($skipPattern)) {
                $Global:CaminhosFalharam.Add($Path) | Out-Null
                return @()
            }
        }
        
        try {
            $null = [System.IO.Directory]::EnumerateDirectories($Path).GetEnumerator()
            $Global:CaminhosAcessiveis.Add($Path) | Out-Null
        }
        catch [System.UnauthorizedAccessException] {
            $Global:CaminhosFalharam.Add($Path) | Out-Null
            $ErroSimulado = [System.Management.Automation.ErrorRecord]::new(
                [System.UnauthorizedAccessException]::new("Acesso negado (pré-verificação)"),
                "AccessDenied", [System.Management.Automation.ErrorCategory]::PermissionDenied, $Path
            )
            Registrar-Erro -Erro $ErroSimulado -Caminho $Path
            return @()
        }
        catch {
            $Global:CaminhosFalharam.Add($Path) | Out-Null
            Registrar-Erro -Erro $_ -Caminho $Path
            return @()
        }
    }
    
    $Parametros = @{ Path = $Path; ErrorAction = 'SilentlyContinue'; ErrorVariable = 'erros' }
    if ($File) { $Parametros.File = $true }
    if ($Recurse) { $Parametros.Recurse = $true }
    if ($Include.Count -gt 0) { $Parametros.Include = $Include }
    
    try {
        $Arquivos = Get-ChildItem @Parametros
        
        foreach ($erro in $erros) {
            $CaminhoErro = $erro.TargetObject
            if (-not $Global:CaminhosFalharam.Contains($CaminhoErro)) {
                $Global:CaminhosFalharam.Add($CaminhoErro) | Out-Null
                Registrar-Erro -Erro $erro -Caminho $CaminhoErro
            } else {
                $Global:TentativasEvitadas++
            }
        }
        
        $Global:ErrosEncontrados.Contadores.TotalArquivosProcessados += $Arquivos.Count
        return $Arquivos
    }
    catch {
        if (-not $Global:CaminhosFalharam.Contains($Path)) {
            $Global:CaminhosFalharam.Add($Path) | Out-Null
            Registrar-Erro -Erro $_ -Caminho $Path
        } else {
            $Global:TentativasEvitadas++
        }
        return @()
    }
}

function Gerar-RelatoriosErro {
    param ([string]$DiretorioSaida)
    
    if (-not $GerarRelatorioErros) { return }
    
    Escrever-Log "Gerando relatórios de erro..." "INFO"
    
    if ($Global:ErrosEncontrados.SemPermissao.Count -gt 0) {
        $CaminhoCSV = Join-Path -Path $DiretorioSaida -ChildPath "ErrosPermissao.csv"
        $Global:ErrosEncontrados.SemPermissao | 
            Select-Object Caminho, Descricao, Timestamp |
            Export-Csv -Path $CaminhoCSV -NoTypeInformation -Encoding UTF8
        Escrever-Log "Relatório de erros de permissão salvo: $CaminhoCSV" "SUCCESS"
    }
    
    if ($Global:ErrosEncontrados.CaminhosLongos.Count -gt 0) {
        $CaminhoCSV = Join-Path -Path $DiretorioSaida -ChildPath "CaminhosMuitoLongos.csv"
        $Global:ErrosEncontrados.CaminhosLongos | 
            Select-Object Caminho, Descricao, Timestamp |
            Export-Csv -Path $CaminhoCSV -NoTypeInformation -Encoding UTF8
        Escrever-Log "Relatório de caminhos longos salvo: $CaminhoCSV" "SUCCESS"
    }
    
    if ($Global:ErrosEncontrados.OutrosErros.Count -gt 0 -or $Global:ErrosEncontrados.ArquivosNaoEncontrados.Count -gt 0) {
        $CaminhoCSV = Join-Path -Path $DiretorioSaida -ChildPath "OutrosErros.csv"
        $TodosOutrosErros = @()
        $TodosOutrosErros += $Global:ErrosEncontrados.OutrosErros
        $TodosOutrosErros += $Global:ErrosEncontrados.ArquivosNaoEncontrados
        
        $TodosOutrosErros | 
            Select-Object Caminho, Descricao, Timestamp, ErroCompleto |
            Export-Csv -Path $CaminhoCSV -NoTypeInformation -Encoding UTF8
        Escrever-Log "Relatório de outros erros salvo: $CaminhoCSV" "SUCCESS"
    }
    
    $ResumoErros = @"
=== RESUMO DE ERROS DA ANÁLISE v2.3 ===
Data/Hora: $(Get-Date)

ESTATÍSTICAS:
- Total de arquivos processados: $($Global:ErrosEncontrados.Contadores.TotalArquivosProcessados)
- Total de erros encontrados: $($Global:ErrosEncontrados.Contadores.TotalErros)

DETALHAMENTO POR TIPO:
- Sem permissão: $($Global:ErrosEncontrados.Contadores.SemPermissao)
- Caminhos longos: $($Global:ErrosEncontrados.Contadores.CaminhosLongos)
- Arquivos não encontrados: $($Global:ErrosEncontrados.Contadores.ArquivosNaoEncontrados)
- Outros erros: $($Global:ErrosEncontrados.Contadores.OutrosErros)

RECOMENDAÇÕES:
1. Para erros de permissão: Solicitar acesso administrativo ou permissões específicas
2. Para caminhos longos: Renomear arquivos/pastas ou usar robocopy com -LiteralPath
3. Para arquivos não encontrados: Verificar integridade do sistema de arquivos
"@
    
    $CaminhoResumo = Join-Path -Path $DiretorioSaida -ChildPath "ResumoErros.txt"
    $ResumoErros | Out-File -FilePath $CaminhoResumo -Encoding UTF8
    Escrever-Log "Resumo de erros salvo: $CaminhoResumo" "SUCCESS"
}

function Criar-DiretorioRelatorios {
    $DataAtual = Get-Date -Format "yyyy-MM-dd_HHmmss"
    $DiretorioBase = "C:\temp"
    $DiretorioRelatorios = Join-Path -Path $DiretorioBase -ChildPath "AnaliseFileServer_$DataAtual"
    
    if (-not (Test-Path -Path $DiretorioBase)) {
        try {
            New-Item -Path $DiretorioBase -ItemType Directory -Force | Out-Null
        } catch {
            Escrever-Log "Não foi possível criar C:\temp, usando perfil do usuário" "WARNING"
            $DiretorioRelatorios = Join-Path -Path $env:USERPROFILE -ChildPath "AnaliseFileServer_$DataAtual"
        }
    }
    
    if (-not (Test-Path -Path $DiretorioRelatorios)) {
        New-Item -Path $DiretorioRelatorios -ItemType Directory -Force | Out-Null
    }
    
    return $DiretorioRelatorios
}

function Verificar-Requisitos {
    $EhAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $EhAdmin) {
        Escrever-Log "AVISO: Não está executando como administrador. Algumas pastas podem ser inacessíveis." "WARNING"
    }
    
    $Versao = $PSVersionTable.PSVersion
    if ($Versao.Major -lt 5) {
        Escrever-Log "AVISO: Este script foi projetado para PowerShell 5.0+. Versão atual: $($Versao.ToString())" "WARNING"
    }
}

function Criar-BarraCompleta {
    param ([string]$Texto, [string]$Cor = "Blue")
    
    try {
        try {
            $larguraConsole = $Host.UI.RawUI.WindowSize.Width
            if ($larguraConsole -lt 40) { $larguraConsole = 80 }
        } catch {
            $larguraConsole = 80
        }
        
        $barra = " " * $larguraConsole
        
        if ($Texto.Length -lt $larguraConsole - 4) {
            $inicio = [math]::Floor(($larguraConsole - $Texto.Length) / 2)
            $barra = $barra.Remove($inicio, $Texto.Length).Insert($inicio, $Texto)
        } else {
            $textoTruncado = $Texto.Substring(0, $larguraConsole - 6) + "..."
            $barra = $barra.Remove(2, $textoTruncado.Length).Insert(2, $textoTruncado)
        }
        
        Write-Host $barra -BackgroundColor $Cor -ForegroundColor White
    }
    catch {
        Write-Host "=== $Texto ===" -ForegroundColor White -BackgroundColor $Cor
    }
}

function Detectar-WindowsDeduplication {
    param ([string]$Caminho)
    
    try {
        $LetraUnidade = ""
        if ($Caminho -match "^([A-Za-z]):") {
            $LetraUnidade = $matches[1] + ":"
        } else {
            $LetraUnidade = "C:"
        }
        
        Escrever-Log "Verificando Windows Deduplication para unidade: $LetraUnidade" "INFO"
        
        $DedupModule = Get-Module -ListAvailable -Name "Deduplication" -ErrorAction SilentlyContinue
        if (-not $DedupModule) {
            Escrever-Log "Módulo Deduplication não disponível no sistema" "INFO"
            return @{ "Habilitado" = $false; "Motivo" = "Módulo Deduplication não disponível" }
        }
        
        Import-Module Deduplication -ErrorAction SilentlyContinue
        
        try {
            $DedupVolume = Get-DedupVolume -Volume $LetraUnidade -ErrorAction SilentlyContinue
            
            if ($DedupVolume -and $DedupVolume.Enabled -eq $true) {
                Escrever-Log "Deduplicação encontrada via Get-DedupVolume - Enabled: $($DedupVolume.Enabled)" "INFO"
                
                $DedupStatus = Get-DedupStatus -Volume $LetraUnidade -ErrorAction SilentlyContinue
                
                if ($DedupStatus) {
                    $EspacoNaoOtimizado = if ($DedupStatus.UnoptimizedSize) { $DedupStatus.UnoptimizedSize } else { 0 }
                    $EspacoOtimizado = if ($DedupStatus.OptimizedSize) { $DedupStatus.OptimizedSize } else { 0 }
                    $EspacoUsado = if ($DedupStatus.UsedSpace) { $DedupStatus.UsedSpace } else { 0 }
                    $CapacidadeTotal = if ($DedupStatus.Capacity) { $DedupStatus.Capacity } else { 0 }
                    
                    $EspacoLogico = $EspacoNaoOtimizado + $EspacoOtimizado
                    $EspacoFisico = $EspacoUsado
                    
                    if ($EspacoLogico -gt 0 -and $EspacoFisico -gt 0) {
                        $TaxaDeduplicacao = $EspacoLogico / $EspacoFisico
                        $EconomiaPercentual = ((1 - (1 / $TaxaDeduplicacao)) * 100)
                        
                        Escrever-Log "Deduplicação ativa detectada - Taxa: $(Format-Number -Value $TaxaDeduplicacao -DecimalPlaces 2)x, Economia: $(Format-Number -Value $EconomiaPercentual -DecimalPlaces 1)%" "SUCCESS"
                        
                        return @{
                            "Habilitado" = $true
                            "EspacoLogicoGB" = $EspacoLogico / 1GB
                            "EspacoFisicoGB" = $EspacoFisico / 1GB
                            "TaxaDeduplicacao" = $TaxaDeduplicacao
                            "EconomiaPercentual" = $EconomiaPercentual
                            "CapacidadeGB" = $CapacidadeTotal / 1GB
                            "Status" = "Ativa com dados otimizados"
                        }
                    } else {
                        Escrever-Log "Deduplicação habilitada mas ainda não otimizou dados" "INFO"
                        return @{
                            "Habilitado" = $true
                            "EspacoLogicoGB" = 0
                            "EspacoFisicoGB" = 0
                            "TaxaDeduplicacao" = 1.0
                            "EconomiaPercentual" = 0
                            "Status" = "Habilitada mas ainda não otimizada"
                        }
                    }
                } else {
                    Escrever-Log "Volume tem deduplicação habilitada mas sem status disponível" "INFO"
                    return @{
                        "Habilitado" = $true
                        "EspacoLogicoGB" = 0
                        "EspacoFisicoGB" = 0
                        "TaxaDeduplicacao" = 1.0
                        "EconomiaPercentual" = 0
                        "Status" = "Habilitada sem estatísticas disponíveis"
                    }
                }
            }
        } catch {
            Escrever-Log "Erro ao executar Get-DedupVolume: $($_.Exception.Message)" "WARNING"
        }
        
        try {
            $DedupStatus = Get-DedupStatus -Volume $LetraUnidade -ErrorAction SilentlyContinue
            
            if ($DedupStatus) {
                Escrever-Log "Metadata de deduplicação encontrada via Get-DedupStatus" "INFO"
                
                $EspacoNaoOtimizado = if ($DedupStatus.UnoptimizedSize) { $DedupStatus.UnoptimizedSize } else { 0 }
                $EspacoOtimizado = if ($DedupStatus.OptimizedSize) { $DedupStatus.OptimizedSize } else { 0 }
                $EspacoUsado = if ($DedupStatus.UsedSpace) { $DedupStatus.UsedSpace } else { 0 }
                
                $EspacoLogico = $EspacoNaoOtimizado + $EspacoOtimizado
                
                if ($EspacoLogico -gt 0 -and $EspacoUsado -gt 0) {
                    $TaxaDeduplicacao = $EspacoLogico / $EspacoUsado
                    $EconomiaPercentual = ((1 - (1 / $TaxaDeduplicacao)) * 100)
                    
                    return @{
                        "Habilitado" = $true
                        "EspacoLogicoGB" = $EspacoLogico / 1GB
                        "EspacoFisicoGB" = $EspacoUsado / 1GB
                        "TaxaDeduplicacao" = $TaxaDeduplicacao
                        "EconomiaPercentual" = $EconomiaPercentual
                        "Status" = "Detectada via metadata"
                    }
                }
            }
        } catch {
            Escrever-Log "Erro ao executar Get-DedupStatus: $($_.Exception.Message)" "WARNING"
        }
        
        try {
            $DedupJobs = Get-ScheduledTask -TaskPath "\Microsoft\Windows\Deduplication\" -ErrorAction SilentlyContinue
            
            if ($DedupJobs -and $DedupJobs.Count -gt 0) {
                Escrever-Log "Jobs de deduplicação encontrados no agendador de tarefas" "INFO"
                return @{
                    "Habilitado" = $true
                    "EspacoLogicoGB" = 0
                    "EspacoFisicoGB" = 0
                    "TaxaDeduplicacao" = 1.0
                    "EconomiaPercentual" = 0
                    "Status" = "Configurada (jobs agendados detectados)"
                }
            }
        } catch {
            Escrever-Log "Erro ao verificar jobs agendados: $($_.Exception.Message)" "WARNING"
        }
        
        Escrever-Log "Deduplicação não está ativa ou configurada" "INFO"
        
    } catch {
        Escrever-Log "Erro geral ao verificar deduplicação: $($_.Exception.Message)" "ERROR"
        return @{ "Habilitado" = $false; "Motivo" = "Erro ao verificar: $($_.Exception.Message)" }
    }
    
    return @{ "Habilitado" = $false; "Motivo" = "Deduplicação não está ativa" }
}

# CORREÇÃO PRINCIPAL: Função recalculada para manter precisão matemática
function Calcular-PotencialRecuperacaoReal {
    param (
        [array]$DadosGrandesAntigos, 
        [array]$DadosDuplicados, 
        [array]$DadosTemporarios, 
        [hashtable]$InfoDeduplicacao = $null
    )
    
    Escrever-Log "Calculando potencial real de recuperação (com precisão matemática corrigida)..." "INFO"
    
    $ArquivosProcessados = @{}
    $ArquivosMantidosDuplicados = @{}
    
    # CORREÇÃO: Manter fator como número exato, sem arredondamento
    $FatorDeduplicacao = if ($null -ne $InfoDeduplicacao -and $InfoDeduplicacao.Habilitado) {
        $InfoDeduplicacao.TaxaDeduplicacao
    } else { 1.0 }
    
    # CATEGORIA 1: Arquivos Duplicados - VALORES BRUTOS SEM ARREDONDAMENTO
    $EspacoDuplicadosMB = 0.0  # Double preciso
    
    if ($null -ne $DadosDuplicados -and $DadosDuplicados.Count -gt 0) {
        $GruposPorHash = $DadosDuplicados | Group-Object -Property Hash
        
        foreach ($grupo in $GruposPorHash) {
            $arquivosGrupo = $grupo.Group
            $tamanhoArquivoMB = [double]$arquivosGrupo[0].SizeMB
            
            $espacoRecuperavelMB = ($arquivosGrupo.Count - 1) * $tamanhoArquivoMB
            $EspacoDuplicadosMB += $espacoRecuperavelMB
            
            $arquivoMantido = $arquivosGrupo | Sort-Object { $_.Path.Length } | Select-Object -First 1
            
            $ArquivosMantidosDuplicados[$arquivoMantido.Hash] = @{
                Caminho = $arquivoMantido.Path
                TamanhoMB = $tamanhoArquivoMB
                NomeArquivo = Split-Path -Path $arquivoMantido.Path -Leaf
            }
            
            foreach ($arquivo in $arquivosGrupo) {
                $caminhoNorm = $arquivo.Path.ToLower()
                $ArquivosProcessados[$caminhoNorm] = @{
                    TamanhoMB = if ($arquivo.Path -eq $arquivoMantido.Path) { 0 } else { $tamanhoArquivoMB }
                    Categorias = @("Duplicado")
                    Caminho = $arquivo.Path
                    Hash = $arquivo.Hash
                    NomeArquivo = Split-Path -Path $arquivo.Path -Leaf
                    SeraMantido = ($arquivo.Path -eq $arquivoMantido.Path)
                    TamanhoRealMB = $tamanhoArquivoMB
                }
            }
        }
    }
    
    # CATEGORIA 2: Arquivos Grandes/Antigos - VALORES BRUTOS SEM ARREDONDAMENTO
    $EspacoGrandesAntigosMB = 0.0  # Double preciso
    if ($null -ne $DadosGrandesAntigos -and $DadosGrandesAntigos.Count -gt 0) {
        foreach ($arquivo in $DadosGrandesAntigos) {
            $CaminhoNormalizado = $arquivo.FullName.ToLower()
            $TamanhoMB = [double]$arquivo.Length / 1MB
            $NomeArquivo = Split-Path -Path $arquivo.FullName -Leaf
            
            if ($ArquivosProcessados.ContainsKey($CaminhoNormalizado)) {
                $ArquivosProcessados[$CaminhoNormalizado].Categorias += "GrandeAntigo"
                
                if ($ArquivosProcessados[$CaminhoNormalizado].SeraMantido -eq $true) {
                    $EspacoGrandesAntigosMB += $TamanhoMB
                }
            }
            else {
                $ArquivosProcessados[$CaminhoNormalizado] = @{
                    TamanhoMB = $TamanhoMB
                    Categorias = @("GrandeAntigo")
                    Caminho = $arquivo.FullName
                    NomeArquivo = $NomeArquivo
                    SeraMantido = $false
                    TamanhoRealMB = $TamanhoMB
                }
                $EspacoGrandesAntigosMB += $TamanhoMB
            }
        }
    }
    
    # CATEGORIA 3: Arquivos Temporários - VALORES BRUTOS SEM ARREDONDAMENTO
    $EspacoTemporariosMB = 0.0  # Double preciso
    if ($null -ne $DadosTemporarios -and $DadosTemporarios.Count -gt 0) {
        foreach ($temporario in $DadosTemporarios) {
            $TamanhoMB = if ($temporario.TotalSize) { 
                [double]$temporario.TotalSize / 1MB 
            } elseif ($temporario.SizeMB) {
                [double]$temporario.SizeMB
            } else { 0.0 }
            
            $ChaveTempo = "$($temporario.Extension)_$TamanhoMB"
            
            $JaProcessadoComoOutraCategoria = $false
            foreach ($arquivoProcessado in $ArquivosProcessados.Values) {
                $extensaoProcessada = [System.IO.Path]::GetExtension($arquivoProcessado.Caminho)
                if ($extensaoProcessada -eq $temporario.Extension -and 
                    [Math]::Abs($arquivoProcessado.TamanhoRealMB - $TamanhoMB) -lt 1) {
                    $JaProcessadoComoOutraCategoria = $true
                    $arquivoProcessado.Categorias += "Temporario"
                    break
                }
            }
            
            if (-not $JaProcessadoComoOutraCategoria -and -not $ArquivosProcessados.ContainsKey($ChaveTempo)) {
                $TamanhoRecuperavelMB = $TamanhoMB * 0.9  # 90% recuperável
                $ArquivosProcessados[$ChaveTempo] = @{
                    TamanhoMB = $TamanhoRecuperavelMB
                    Categorias = @("Temporario")
                    Caminho = "Arquivos .$($temporario.Extension)"
                    NomeArquivo = "*$($temporario.Extension)"
                    SeraMantido = $false
                    TamanhoRealMB = $TamanhoMB
                }
                $EspacoTemporariosMB += $TamanhoRecuperavelMB
            }
        }
    }
    
    # CORREÇÃO: Conversão para GB sem arredondamento intermediário
    $EspacoDuplicadosGB = $EspacoDuplicadosMB / 1024.0
    $EspacoGrandesAntigosGB = $EspacoGrandesAntigosMB / 1024.0
    $EspacoTemporariosGB = $EspacoTemporariosMB / 1024.0
    
    # CORREÇÃO: Soma direta em GB sem arredondamento
    $TotalLogicoGB = $EspacoDuplicadosGB + $EspacoGrandesAntigosGB + $EspacoTemporariosGB
    
    # APLICAR DEDUPLICAÇÃO SEM ARREDONDAMENTO
    $EspacoDuplicadosFisico = $EspacoDuplicadosGB / $FatorDeduplicacao
    $EspacoGrandesAntigosFisico = $EspacoGrandesAntigosGB / $FatorDeduplicacao
    $EspacoTemporariosFisico = $EspacoTemporariosGB / $FatorDeduplicacao
    
    # SOMA FINAL SEM ARREDONDAMENTO
    $TotalFisicoGB = $EspacoDuplicadosFisico + $EspacoGrandesAntigosFisico + $EspacoTemporariosFisico
    
    # Calcular sobreposições
    $SobreposicoesDetectadas = 0
    $ArquivosMantidosComAcao = 0
    
    foreach ($arquivo in $ArquivosProcessados.Values) {
        $cats = $arquivo.Categorias
        
        if ($arquivo.SeraMantido -eq $true -and $cats.Count -gt 1) {
            $ArquivosMantidosComAcao++
        }
        
        if ($cats.Count -gt 1) {
            $SobreposicoesDetectadas++
        }
    }
    
    # LOG DOS VALORES BRUTOS PARA DEBUG
    Escrever-Log "Valores brutos calculados (sem arredondamento):" "DEBUG"
    Escrever-Log "  Duplicados: $EspacoDuplicadosGB GB (lógico), $EspacoDuplicadosFisico GB (físico)" "DEBUG"
    Escrever-Log "  Grandes/Antigos: $EspacoGrandesAntigosGB GB (lógico), $EspacoGrandesAntigosFisico GB (físico)" "DEBUG"
    Escrever-Log "  Temporários: $EspacoTemporariosGB GB (lógico), $EspacoTemporariosFisico GB (físico)" "DEBUG"
    Escrever-Log "  Total: $TotalLogicoGB GB (lógico), $TotalFisicoGB GB (físico)" "DEBUG"
    
    # RETURN COM ARREDONDAMENTO APENAS NO FINAL
    return @{
        # Valores lógicos (o que os usuários veem) - ARREDONDADOS APENAS AQUI
        "EspacoDuplicadosLogico" = [math]::Round($EspacoDuplicadosGB, 2)
        "EspacoGrandesAntigosLogico" = [math]::Round($EspacoGrandesAntigosGB, 2)
        "EspacoTemporariosLogico" = [math]::Round($EspacoTemporariosGB, 2)
        "TotalLogicoGB" = [math]::Round($TotalLogicoGB, 2)
        "TotalLogicoTB" = [math]::Round($TotalLogicoGB / 1024, 2)
        
        # Valores físicos (o que realmente será liberado no disco) - ARREDONDADOS APENAS AQUI
        "EspacoDuplicados" = [math]::Round($EspacoDuplicadosFisico, 2)
        "EspacoGrandesAntigos" = [math]::Round($EspacoGrandesAntigosFisico, 2)
        "EspacoTemporarios" = [math]::Round($EspacoTemporariosFisico, 2)
        "TotalReal" = [math]::Round($TotalFisicoGB, 2)
        "TotalRealTB" = [math]::Round($TotalFisicoGB / 1024, 2)
        
        # Metadados
        "DeduplicacaoAtiva" = ($FatorDeduplicacao -gt 1.0)
        "FatorDeduplicacao" = [math]::Round($FatorDeduplicacao, 2)
        "ArquivosAnalisados" = $ArquivosProcessados.Count
        "ArquivosMantidosComAcaoAdicional" = $ArquivosMantidosComAcao
        "SobreposicoesDetectadas" = $SobreposicoesDetectadas
        
        # VALORES BRUTOS PARA USO INTERNO (sem arredondamento)
        "EspacoDuplicadosGBRaw" = $EspacoDuplicadosGB
        "EspacoGrandesAntigosGBRaw" = $EspacoGrandesAntigosGB
        "EspacoTemporariosGBRaw" = $EspacoTemporariosGB
        "TotalLogicoGBRaw" = $TotalLogicoGB
        "TotalFisicoGBRaw" = $TotalFisicoGB
    }
}

# CORREÇÃO: Função para cálculo correto de percentual com validação de divisão por zero
function Calcular-PercentualReal {
    param (
        [double]$EspacoRecuperavelGB,
        [double]$EspacoUsadoGB
    )
    
    # CORREÇÃO: Validação de divisão por zero
    if ($EspacoUsadoGB -eq 0 -or $EspacoUsadoGB -le 0.01) { 
        Escrever-Log "AVISO: Espaço usado é zero ou muito pequeno ($EspacoUsadoGB GB), percentual será 0%" "WARNING"
        return 0.0 
    }
    
    # Calcular percentual com precisão
    $Percentual = ($EspacoRecuperavelGB / $EspacoUsadoGB) * 100.0
    
    # LOG para debug
    Escrever-Log "DEBUG - Cálculo percentual corrigido:" "DEBUG"
    Escrever-Log "  Recuperável: $EspacoRecuperavelGB GB" "DEBUG"
    Escrever-Log "  Usado: $EspacoUsadoGB GB" "DEBUG"
    Escrever-Log "  Percentual: $Percentual%" "DEBUG"
    
    return [math]::Round($Percentual, 2)
}

function Obter-EspacoDisco {
    param ([string]$Caminho)
    
    try {
        if ($Caminho -match "^[a-zA-Z]:") {
            $Letra = $Caminho.Substring(0, 1)
            $DriveInfo = Get-PSDrive $Letra | Select-Object Used, Free
            
            if ($null -ne $DriveInfo) {
                $EspacoTotal = ($DriveInfo.Used + $DriveInfo.Free)
                return @{
                    "EspacoTotal" = $EspacoTotal; "EspacoUsado" = $DriveInfo.Used
                    "EspacoLivre" = $DriveInfo.Free
                    "EspacoTotalGB" = [math]::Round($EspacoTotal / 1GB, 2)
                    "EspacoUsadoGB" = [math]::Round($DriveInfo.Used / 1GB, 2)
                    "EspacoLivreGB" = [math]::Round($DriveInfo.Free / 1GB, 2)
                }
            }
        } else {
            $DiskInfo = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $Caminho -like "$($_.DeviceID)*" }
            
            if ($null -ne $DiskInfo) {
                $EspacoTotal = $DiskInfo.Size
                $EspacoLivre = $DiskInfo.FreeSpace
                $EspacoUsado = $EspacoTotal - $EspacoLivre
                
                return @{
                    "EspacoTotal" = $EspacoTotal; "EspacoUsado" = $EspacoUsado; "EspacoLivre" = $EspacoLivre
                    "EspacoTotalGB" = [math]::Round($EspacoTotal / 1GB, 2)
                    "EspacoUsadoGB" = [math]::Round($EspacoUsado / 1GB, 2)
                    "EspacoLivreGB" = [math]::Round($EspacoLivre / 1GB, 2)
                }
            } else {
                Escrever-Log "Não foi possível obter informações precisas de espaço para $Caminho, usando estimativa." "WARNING"
                
                $ArquivosTemp = [System.IO.Path]::GetTempFileName()
                Get-ChildItemSeguro -Path $Caminho -File -Recurse | 
                    Select-Object Length | 
                    Export-Csv -Path $ArquivosTemp -NoTypeInformation
                
                $EspacoEstimado = (Import-Csv -Path $ArquivosTemp | 
                    Measure-Object -Property Length -Sum).Sum
                
                Remove-Item -Path $ArquivosTemp -Force -ErrorAction SilentlyContinue
                
                return @{
                    "EspacoTotal" = $EspacoEstimado; "EspacoUsado" = $EspacoEstimado; "EspacoLivre" = 0
                    "EspacoTotalGB" = [math]::Round($EspacoEstimado / 1GB, 2)
                    "EspacoUsadoGB" = [math]::Round($EspacoEstimado / 1GB, 2)
                    "EspacoLivreGB" = 0; "Estimado" = $true
                }
            }
        }
    } catch {
        Escrever-Log "Erro ao obter informações de espaço do disco: $_" "ERROR"
    }
    
    return $null
}

function Analisar-TiposArquivo {
    param ([string]$Caminho = "C:\", [string]$SaidaCSV = "")
    
    Escrever-Log "Analisando distribuição de tipos de arquivo em $Caminho..." "INFO"
    $ArquivoTemp = [System.IO.Path]::GetTempFileName()
    
    try {
        $ArquivosProcessados = @{}
        
        $Arquivos = Get-ChildItemSeguro -Path $Caminho -File -Recurse
        
        foreach ($arquivo in $Arquivos) {
            $Ignorar = $false
            foreach ($padraoIgnorar in $Global:ConfigGlobal.DiretoriosIgnorar) {
                if ($arquivo.FullName -like $padraoIgnorar) {
                    $Ignorar = $true
                    break
                }
            }
            
            if (-not $Ignorar -and -not $ArquivosProcessados.ContainsKey($arquivo.FullName)) {
                $ArquivosProcessados[$arquivo.FullName] = $true
                
                [PSCustomObject]@{
                    Extension = $arquivo.Extension
                    Length = $arquivo.Length
                } | Export-Csv -Path $ArquivoTemp -Append -NoTypeInformation -Encoding UTF8
            }
        }
        
        $ArquivosPorExtensao = Import-Csv -Path $ArquivoTemp -Encoding UTF8 | 
            Group-Object -Property Extension | 
            ForEach-Object {
                $Extensao = if ([string]::IsNullOrEmpty($_.Name)) { "(sem extensão)" } else { $_.Name }
                $TotalArquivos = $_.Count
                $TamanhoTotal = ($_.Group | Measure-Object -Property Length -Sum).Sum
                $SizeFormatted = (Format-FileSize -SizeBytes $TamanhoTotal).Formatted
                
                [PSCustomObject]@{
                    Extension = $Extensao; FileCount = $TotalArquivos; TotalSize = $TamanhoTotal
                    SizeMB = [math]::Round($TamanhoTotal / 1MB, 2)
                    SizeGB = [math]::Round($TamanhoTotal / 1GB, 2)
                    SizeKB = [math]::Round($TamanhoTotal / 1KB, 2)
                    SizeFormatted = $SizeFormatted
                }
            } | Sort-Object -Property TotalSize -Descending
        
        if ($SaidaCSV -ne "") {
            $ArquivosPorExtensao | 
                Select-Object Extension, FileCount, SizeFormatted, SizeKB, SizeMB, SizeGB, TotalSize |
                Export-Csv -Path $SaidaCSV -NoTypeInformation -Encoding UTF8
            Escrever-Log "Distribuição de tipos exportada para $SaidaCSV" "SUCCESS"
        }
        
        if (-not $ModoSilencioso) {
            Write-Host "`nDistribuição de espaço por tipo de arquivo:" -ForegroundColor Cyan
            
            $ArquivosPorExtensao | Select-Object -First 10 | Format-Table -Property @{
                Label = "Extensão"; Expression = { $_.Extension }
            }, @{
                Label = "Qtd Arquivos"; Expression = { $_.FileCount }; Align = "Right"
            }, @{
                Label = "Tamanho"; Expression = { $_.SizeFormatted }; Align = "Right"
            }, @{
                Label = "% do Total"
                Expression = { 
                    $TotalGeral = ($ArquivosPorExtensao | Measure-Object -Property TotalSize -Sum).Sum
                    $Percentual = ($_.TotalSize / $TotalGeral) * 100
                    "{0:N2}%" -f $Percentual
                }; Align = "Right"
            } -AutoSize
        }
        
        $ArquivosProcessados.Clear()
        [System.GC]::Collect()
        
        return $ArquivosPorExtensao
        
    } catch {
        Escrever-Log "Erro durante análise de tipo de arquivo: $_" "ERROR"
    } finally {
        if (Test-Path -Path $ArquivoTemp) {
            Remove-Item -Path $ArquivoTemp -Force
        }
    }
}

function Encontrar-ArquivosGrandesAntigos {
    param (
        [string]$Caminho = "C:\",
        [int]$TamanhoMinimoMB = $TamanhoMinimoArquivosMB,
        [int]$DiasAntigos = $DiasArquivosAntigos,
        [int]$Top = $TopArquivosGrandesAntigos,
        [string]$SaidaCSV = "",
        [array]$DuplicadosParaExcluir = @()
    )
    
    $DataLimite = (Get-Date).AddDays(-$DiasAntigos)
    Escrever-Log "Buscando arquivos grandes ($TamanhoMinimoMB MB) OU antigos ($DiasAntigos dias) em $Caminho..." "INFO"
    Escrever-Log "Critério OR com ordenação por impacto" "INFO"
    $ArquivoTemp = [System.IO.Path]::GetTempFileName()
    
    try {
        $ArquivosProcessados = @{}
        
        $DuplicadosParaRemover = @{}
        foreach ($duplicado in $DuplicadosParaExcluir) {
            if ($duplicado.RecoverableMB -gt 0) {
                $DuplicadosParaRemover[$duplicado.Path.ToLower()] = $true
            }
        }
        
        $Arquivos = Get-ChildItemSeguro -Path $Caminho -File -Recurse
        
        foreach ($arquivo in $Arquivos) {
            $EhGrande = $arquivo.Length -gt ($TamanhoMinimoMB * 1MB)
            $EhAntigo = $arquivo.LastWriteTime -lt $DataLimite
            
            if ($EhGrande -or $EhAntigo) {
                $CaminhoNormalizado = $arquivo.FullName.ToLower()
                if ($DuplicadosParaRemover.ContainsKey($CaminhoNormalizado)) {
                    continue
                }
                
                $Ignorar = $false
                foreach ($padraoIgnorar in $Global:ConfigGlobal.DiretoriosIgnorar) {
                    if ($arquivo.FullName -like $padraoIgnorar) {
                        $Ignorar = $true
                        break
                    }
                }
                
                if (-not $Ignorar -and -not $ArquivosProcessados.ContainsKey($arquivo.FullName)) {
                    $ArquivosProcessados[$arquivo.FullName] = $true
                    
                    $CategoriaFinal = ""
                    if ($EhGrande -and $EhAntigo) {
                        $CategoriaFinal = "Grande + Antigo"
                    } elseif ($EhGrande) {
                        $CategoriaFinal = "Grande"
                    } else {
                        $CategoriaFinal = "Antigo"
                    }
                    
                    $StatusDuplicado = ""
                    foreach ($duplicado in $DuplicadosParaExcluir) {
                        if ($duplicado.Path.ToLower() -eq $CaminhoNormalizado -and $duplicado.RecoverableMB -eq 0) {
                            $StatusDuplicado = " (Duplicado - Preservado)"
                            break
                        }
                    }
                    
                    [PSCustomObject]@{
                        FullName = $arquivo.FullName
                        Length = $arquivo.Length
                        LastWriteTime = $arquivo.LastWriteTime
                        CreationTime = $arquivo.CreationTime
                        Extension = $arquivo.Extension
                        Categoria = $CategoriaFinal + $StatusDuplicado
                        CategoriaBase = $CategoriaFinal
                        EhGrande = $EhGrande
                        EhAntigo = $EhAntigo
                        IdadeDias = [math]::Round((New-TimeSpan -Start $arquivo.LastWriteTime -End (Get-Date)).TotalDays)
                    } | Export-Csv -Path $ArquivoTemp -Append -NoTypeInformation -Encoding UTF8
                }
            }
        }
        
        $Resultados = Import-Csv -Path $ArquivoTemp -Encoding UTF8 |
            Sort-Object -Property @{
                Expression = {
                    $cat = $_.Categoria
                    if ($cat -like "*Grande + Antigo*") { 1 }
                    elseif ($cat -like "*Grande*" -and $cat -notlike "*Antigo*") { 2 }
                    elseif ($cat -like "*Antigo*" -and $cat -notlike "*Grande*") { 3 }
                    else { 4 }
                }
            }, @{
                Expression = {[long]$_.Length}; Descending = $true
            } |
            Select-Object -First $Top
        
        if ($SaidaCSV -ne "") {
            $Resultados | 
                Select-Object @{Name="Caminho"; Expression={$_.FullName}},
                             @{Name="Categoria"; Expression={$_.Categoria}},
                             @{Name="Tamanho"; Expression={(Format-FileSize -SizeBytes ([long]$_.Length)).Formatted}},
                             @{Name="Tamanho (MB)"; Expression={[math]::Round([long]$_.Length / 1MB, 2)}},
                             @{Name="Tamanho (GB)"; Expression={[math]::Round([long]$_.Length / 1GB, 2)}},
                             @{Name="Idade (dias)"; Expression={$_.IdadeDias}},
                             @{Name="Última Modificação"; Expression={$_.LastWriteTime}},
                             @{Name="Data de Criação"; Expression={$_.CreationTime}} |
                Export-Csv -Path $SaidaCSV -NoTypeInformation -Encoding UTF8
            
            Escrever-Log "Resultados exportados para $SaidaCSV" "SUCCESS"
        }
        
        if (-not $ModoSilencioso) {
            $Resultados | Format-Table -Property @{
                Label = "Categoria"; Expression = { $_.Categoria }
            }, @{
                Label = "Tamanho"; Expression = { (Format-FileSize -SizeBytes ([long]$_.Length)).Formatted }; Align = "Right"
            }, @{
                Label = "Idade (dias)"; Expression = { $_.IdadeDias }; Align = "Right"
            }, @{
                Label = "Última Modificação"; Expression = { $_.LastWriteTime }
            }, FullName -AutoSize
        }
        
        $ArquivosExcluidos = $DuplicadosParaRemover.Count
        $TotalEncontrados = $Resultados.Count
        Escrever-Log "Análise grandes OU antigos: $TotalEncontrados únicos encontrados (excluídos $ArquivosExcluidos duplicados removíveis)" "SUCCESS"
        
        $ArquivosProcessados.Clear()
        [System.GC]::Collect()
        
        return $Resultados
        
    } catch {
        Escrever-Log "Erro ao buscar arquivos grandes/antigos: $_" "ERROR"
    } finally {
        if (Test-Path -Path $ArquivoTemp) {
            Remove-Item -Path $ArquivoTemp -Force
        }
    }
}

function Encontrar-ArquivosDuplicados {
    param (
        [string]$Caminho = "C:\",
        [int]$TamanhoMinimoMB = $TamanhoMinimoArquivosDuplicadosMB,
        [string]$SaidaCSV = "",
        [string]$DiretorioTrabalho = "",
        [int]$TopGruposMaiores = $TopGruposDuplicados
    )
    
    if ([string]::IsNullOrEmpty($DiretorioTrabalho)) {
        $DiretorioTrabalho = Join-Path -Path $env:TEMP -ChildPath "DuplicadosAnalise_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    }
    
    if (-not (Test-Path -Path $DiretorioTrabalho)) {
        New-Item -Path $DiretorioTrabalho -ItemType Directory -Force | Out-Null
    }
    
    $ArquivoTamanhos = Join-Path -Path $DiretorioTrabalho -ChildPath "tamanhos.csv"
    $ArquivoHashes = Join-Path -Path $DiretorioTrabalho -ChildPath "hashes.csv"
    $ArquivoDuplicados = Join-Path -Path $DiretorioTrabalho -ChildPath "duplicados.csv"
    
    Escrever-Log "Iniciando busca por arquivos duplicados em $Caminho (maiores que $TamanhoMinimoMB MB)..." "INFO"
    
    if (-not $ModoSilencioso) {
        Write-Host "🔍 Etapa 1/4: Coletando arquivos candidatos..." -ForegroundColor Yellow
    }
    
    try {
        $ArquivosProcessados = @{}
        $ContadorArquivos = 0
        
        $Arquivos = Get-ChildItemSeguro -Path $Caminho -File -Recurse
        
        foreach ($arquivo in $Arquivos) {
            if ($arquivo.Length -gt ($TamanhoMinimoMB * 1MB)) {
                $Ignorar = $false
                foreach ($padraoIgnorar in $Global:ConfigGlobal.DiretoriosIgnorar) {
                    if ($arquivo.FullName -like $padraoIgnorar) {
                        $Ignorar = $true
                        break
                    }
                }
                
                $ChaveArquivo = $arquivo.FullName.ToLower()
                
                if (-not $Ignorar -and -not $ArquivosProcessados.ContainsKey($ChaveArquivo)) {
                    $ArquivosProcessados[$ChaveArquivo] = $true
                    $ContadorArquivos++
                    
                    [PSCustomObject]@{
                        FullName = $arquivo.FullName
                        Length = $arquivo.Length
                    } | Export-Csv -Path $ArquivoTamanhos -Append -NoTypeInformation -Encoding UTF8
                    
                    if ($ContadorArquivos % 1000 -eq 0) {
                        if (-not $ModoSilencioso) {
                            Write-Host "   📁 Processados: $ContadorArquivos arquivos" -ForegroundColor Cyan
                        }
                        Escrever-Log "Processados $ContadorArquivos arquivos únicos" "DEBUG"
                    }
                }
            }
        }
        
        $ArquivosProcessados.Clear()
        [System.GC]::Collect()
        
        if (-not (Test-Path -Path $ArquivoTamanhos)) {
            if (-not $ModoSilencioso) {
                Write-Host "   ⚠️ Nenhum arquivo candidato encontrado" -ForegroundColor Yellow
            }
            return @()
        }
        
        if (-not $ModoSilencioso) {
            Write-Host "🔍 Etapa 2/4: Agrupando por tamanho..." -ForegroundColor Yellow
        }
        
        $Arquivos = Import-Csv -Path $ArquivoTamanhos -Encoding UTF8
        $ArquivosPorTamanho = $Arquivos | Group-Object -Property Length
        $GruposPotenciais = $ArquivosPorTamanho | Where-Object { $_.Count -gt 1 }
        
        if ($GruposPotenciais.Count -eq 0) {
            if (-not $ModoSilencioso) {
                Write-Host "   ✅ Nenhum grupo de arquivos com mesmo tamanho encontrado" -ForegroundColor Green
            }
            return @()
        }
        
        if (-not $ModoSilencioso) {
            Write-Host "   📊 Grupos potenciais: $($GruposPotenciais.Count)" -ForegroundColor Cyan
            Write-Host "🔍 Etapa 3/4: Calculando hashes MD5..." -ForegroundColor Yellow
        }
        
        $ArquivosComHash = @()
        $HashesProcessados = @{}
        $ContadorHashes = 0
        $TotalArquivosParaHash = ($GruposPotenciais | ForEach-Object { $_.Group }).Count
        
        foreach ($Grupo in $GruposPotenciais) {
            $ArquivosNoGrupo = $Grupo.Group
            
            foreach ($Arquivo in $ArquivosNoGrupo) {
                try {
                    $CaminhoNormalizado = $Arquivo.FullName.ToLower()
                    
                    if ($HashesProcessados.ContainsKey($CaminhoNormalizado)) {
                        continue
                    }
                    
                    if (Test-Path -Path $Arquivo.FullName -PathType Leaf) {
                        $Hash = Get-FileHash -Path $Arquivo.FullName -Algorithm MD5 -ErrorAction Stop
                        
                        $HashesProcessados[$CaminhoNormalizado] = $Hash.Hash
                        $ContadorHashes++
                        
                        $ArquivoInfo = [PSCustomObject]@{
                            FullName = $Arquivo.FullName
                            Length = $Arquivo.Length
                            Hash = $Hash.Hash
                        }
                        
                        $ArquivosComHash += $ArquivoInfo
                        
                        if ($ContadorHashes % 100 -eq 0 -and -not $ModoSilencioso) {
                            $Percentual = [math]::Round(($ContadorHashes / $TotalArquivosParaHash) * 100, 1)
                            Write-Host "   🔐 Hashes: $ContadorHashes/$TotalArquivosParaHash ($Percentual%)" -ForegroundColor Cyan
                        }
                        
                        if ($ArquivosComHash.Count % 1000 -eq 0) {
                            $ArquivosComHash | Export-Csv -Path $ArquivoHashes -Append -NoTypeInformation -Encoding UTF8
                            $ArquivosComHash = @()
                            [System.GC]::Collect()
                        }
                    }
                } catch {
                    Registrar-Erro -Erro $_ -Caminho $Arquivo.FullName
                }
            }
        }
        
        if ($ArquivosComHash.Count -gt 0) {
            $ArquivosComHash | Export-Csv -Path $ArquivoHashes -Append -NoTypeInformation -Encoding UTF8
        }
        
        $HashesProcessados.Clear()
        [System.GC]::Collect()
        
        if (-not (Test-Path -Path $ArquivoHashes)) {
            if (-not $ModoSilencioso) {
                Write-Host "   ⚠️ Nenhum hash calculado com sucesso" -ForegroundColor Yellow
            }
            return @()
        }
        
        if (-not $ModoSilencioso) {
            Write-Host "🔍 Etapa 4/4: Identificando duplicados..." -ForegroundColor Yellow
        }
        
        $ArquivosHash = Import-Csv -Path $ArquivoHashes -Encoding UTF8
        $GruposPorHash = $ArquivosHash | Group-Object -Property Hash
        $GruposDuplicados = $GruposPorHash | Where-Object { $_.Count -gt 1 } | 
                           Sort-Object -Property @{Expression={[long]$_.Group[0].Length * ($_.Count - 1)}; Descending=$true} |
                           Select-Object -First $TopGruposMaiores
        
        if ($GruposDuplicados.Count -eq 0) {
            if (-not $ModoSilencioso) {
                Write-Host "   ✅ Nenhum arquivo duplicado encontrado" -ForegroundColor Green
            }
            return @()
        }
        
        if (-not $ModoSilencioso) {
            Write-Host "   🎯 Grupos de duplicados encontrados: $($GruposDuplicados.Count)" -ForegroundColor Green
        }
        
        $GrupoNum = 1
        $ResultadosDuplicados = @()
        
        foreach ($Grupo in $GruposDuplicados) {
            $ArquivosGrupo = $Grupo.Group
            $CaminhosDiferentes = $ArquivosGrupo | Select-Object -ExpandProperty FullName | Sort-Object -Unique
            
            if ($CaminhosDiferentes.Count -le 1) {
                continue
            }
            
            $TamanhoBytes = [long]$ArquivosGrupo[0].Length
            $TamanhoMB = $TamanhoBytes / 1MB
            $TamanhoGB = $TamanhoBytes / 1GB
            
            $PrimeiroArquivo = $true
            foreach ($Caminho in $CaminhosDiferentes) {
                $ResultadosDuplicados += [PSCustomObject]@{
                    GroupID = $GrupoNum; Path = $Caminho; SizeBytes = $TamanhoBytes
                    SizeMB = [math]::Round($TamanhoMB, 2); SizeGB = [math]::Round($TamanhoGB, 2)
                    Hash = $Grupo.Name; FilesInGroup = $CaminhosDiferentes.Count
                    RecoverableMB = if (-not $PrimeiroArquivo) { [math]::Round($TamanhoMB, 2) } else { 0 }
                }
                $PrimeiroArquivo = $false
            }
            
            $GrupoNum++
        }
        
        if ($SaidaCSV -ne "") {
            $ResultadosDuplicados | Export-Csv -Path $SaidaCSV -NoTypeInformation -Encoding UTF8
            Escrever-Log "Resultados exportados para $SaidaCSV" "SUCCESS"
        }
        
        $ResultadosDuplicados | Export-Csv -Path $ArquivoDuplicados -NoTypeInformation -Encoding UTF8
        
        if (-not $ModoSilencioso) {
            $TotalRecuperavel = ($ResultadosDuplicados | Where-Object { $_.RecoverableMB -gt 0 } | Measure-Object -Property RecoverableMB -Sum).Sum
            Write-Host "   💾 Espaço recuperável: $([math]::Round($TotalRecuperavel / 1024, 2)) GB" -ForegroundColor Green
        }
        
        Escrever-Log "Análise de duplicados concluída: $($GruposDuplicados.Count) grupos encontrados" "SUCCESS"
        
        return $ResultadosDuplicados
        
    } catch {
        Registrar-Erro -Erro $_ -Caminho $Caminho
        Escrever-Log "Erro durante busca por arquivos duplicados: $_" "ERROR"
        if (-not $ModoSilencioso) {
            Write-Host "   ❌ Erro na análise de duplicados: $_" -ForegroundColor Red
        }
        return @()
    }
}

function Encontrar-ArquivosTemporariosDetalhados {
    param (
        [string]$Caminho = "C:\",
        [string]$SaidaCSV = "",
        [array]$ExtensoesDesnecessarias = @(".tmp", ".temp", ".bak", ".old", ".dmp", ".chk", ".log", ".etl", ".part", ".crdownload",
        ".download", "~*", ".cache", ".wbk", ".gid", ".prv", ".laccdb", ".fbk", ".thumbs.db", ".ds_store", "desktop.ini", ".fuse_hidden*",
        ".nfs*", ".swp", ".swo", ".tmp.*", ".bak.*", ".backup", ".autosave", ".recover", ".~lock*", ".dropbox.cache")
    )
    
    Escrever-Log "Iniciando busca detalhada por arquivos temporários em $Caminho..." "INFO"
    $ArquivoTemp = [System.IO.Path]::GetTempFileName()
    
    try {
        foreach ($ext in $ExtensoesDesnecessarias) {
            if ($ext -like "*`**") {
                $filtro = $ext.Replace("*", "*")
                $Arquivos = Get-ChildItemSeguro -Path $Caminho -File -Recurse
                $Arquivos | Where-Object { $_.Name -like $filtro } |
                    Select-Object FullName, Length, LastWriteTime, @{Name="Extension"; Expression={$ext}} |
                    Export-Csv -Path $ArquivoTemp -Append -NoTypeInformation -Encoding UTF8
            } else {
                $Arquivos = Get-ChildItemSeguro -Path $Caminho -File -Recurse -Include "*$ext"
                $Arquivos | Select-Object FullName, Length, LastWriteTime, @{Name="Extension"; Expression={$_.Extension}} |
                    Export-Csv -Path $ArquivoTemp -Append -NoTypeInformation -Encoding UTF8
            }
        }
        
        if (-not (Test-Path -Path $ArquivoTemp) -or (Get-Item -Path $ArquivoTemp).Length -eq 0) {
            return @()
        }
        
        $Resultados = Import-Csv -Path $ArquivoTemp -Encoding UTF8 | 
            Sort-Object -Property @{Expression = {[long]$_.Length}; Descending = $true}
        
        if ($SaidaCSV -ne "" -and $Resultados.Count -gt 0) {
            $Resultados | 
                Select-Object @{Name="Caminho"; Expression={$_.FullName}},
                           @{Name="Extensão"; Expression={$_.Extension}},
                           @{Name="Tamanho"; Expression={(Format-FileSize -SizeBytes ([long]$_.Length)).Formatted}},
                           @{Name="Tamanho (MB)"; Expression={[math]::Round([long]$_.Length / 1MB, 2)}},
                           @{Name="Última Modificação"; Expression={$_.LastWriteTime}} |
                Export-Csv -Path $SaidaCSV -NoTypeInformation -Encoding UTF8
            
            Escrever-Log "Detalhes de arquivos temporários exportados para $SaidaCSV" "SUCCESS"
        }
        
        return $Resultados
        
    } catch {
        Escrever-Log "Erro ao buscar arquivos temporários detalhados: $_" "ERROR"
        return @()
    } finally {
        if (Test-Path -Path $ArquivoTemp) {
            Remove-Item -Path $ArquivoTemp -Force
        }
    }
}

# CORREÇÃO: Função HTML atualizada para usar fonte única de dados
function Criar-RelatorioHTML {
    param (
        [string]$DiretorioRelatorios, [string]$Caminho, [array]$DadosTipos,
        [array]$DadosGrandesAntigos, [array]$DadosDuplicados, [array]$DadosTemporarios,
        [hashtable]$InfoDisco, [hashtable]$PotencialReal = $null, [hashtable]$InfoDeduplicacao = $null,
        [int]$TamanhoMinimoArquivosMB = 500, [int]$DiasArquivosAntigos = 90
    )
    
    $TotalErros = $Global:ErrosEncontrados.Contadores.TotalErros
    $ErrosSemPermissao = $Global:ErrosEncontrados.Contadores.SemPermissao
    $ErrosCaminhosLongos = $Global:ErrosEncontrados.Contadores.CaminhosLongos
    $ErrosArquivosNaoEncontrados = $Global:ErrosEncontrados.Contadores.ArquivosNaoEncontrados
    $ErrosOutros = $Global:ErrosEncontrados.Contadores.OutrosErros
    
    $LetraDisco = if ($Caminho -match "^([A-Za-z]):") { $matches[1] } else { $Caminho }
    
    $DataRelatorio = Get-Date -Format "dd/MM/yyyy HH:mm"
    $HTMLPath = Join-Path -Path $DiretorioRelatorios -ChildPath "RelatorioSanitizacao.html"
    
    $EspacoTotalGB = $InfoDisco.EspacoTotalGB
    $EspacoUsadoGB = $InfoDisco.EspacoUsadoGB
    $EspacoLivreGB = $InfoDisco.EspacoLivreGB
    $PercentualUsado = [math]::Round(($EspacoUsadoGB / $EspacoTotalGB) * 100, 2)
    $PercentualLivre = [math]::Round(($EspacoLivreGB / $EspacoTotalGB) * 100, 2)
    
    $TotalFormatted = Format-FileSize -SizeBytes ($EspacoTotalGB * 1GB)
    $UsadoFormatted = Format-FileSize -SizeBytes ($EspacoUsadoGB * 1GB)
    
    # CORREÇÃO: Usar APENAS o PotencialReal como fonte única de dados
    $MensagemDeduplicacao = ""
    $ClasseAdicionalProgress = ""
    
    if ($null -ne $PotencialReal -and $PotencialReal.DeduplicacaoAtiva) {
        $MensagemDeduplicacao = "✅ VALORES CORRIGIDOS (considerando Windows Deduplication ativa - Taxa: $($PotencialReal.FatorDeduplicacao.ToString("F2", [System.Globalization.CultureInfo]::InvariantCulture))x)"
        $ClasseAdicionalProgress = "dedup-aware"
        
        # USAR APENAS VALORES DO POTENCIAL REAL
        $EspacoDuplicados = $PotencialReal.EspacoDuplicados
        $EspacoGrandesAntigos = $PotencialReal.EspacoGrandesAntigos
        $EspacoTemporarios = $PotencialReal.EspacoTemporarios
        $TotalRecuperavel = $PotencialReal.TotalReal
        
        # CORREÇÃO: Usar função corrigida com validação de zero
        $PercentualRecuperavel = Calcular-PercentualReal -EspacoRecuperavelGB $TotalRecuperavel -EspacoUsadoGB $EspacoUsadoGB
        
        $EspacoDuplicadosLogico = $PotencialReal.EspacoDuplicadosLogico
        $EspacoGrandesAntigosLogico = $PotencialReal.EspacoGrandesAntigosLogico
        $EspacoTemporariosLogico = $PotencialReal.EspacoTemporariosLogico
        $TotalRecuperavelLogico = $PotencialReal.TotalLogicoGB
        
    } elseif ($null -ne $PotencialReal) {
        $MensagemDeduplicacao = "✅ VALORES CORRIGIDOS (sem sobreposições - deduplicação não detectada)"
        
        # USAR APENAS VALORES DO POTENCIAL REAL
        $EspacoDuplicados = $PotencialReal.EspacoDuplicados
        $EspacoGrandesAntigos = $PotencialReal.EspacoGrandesAntigos
        $EspacoTemporarios = $PotencialReal.EspacoTemporarios
        $TotalRecuperavel = $PotencialReal.TotalReal
        
        # CORREÇÃO: Usar função corrigida com validação de zero
        $PercentualRecuperavel = Calcular-PercentualReal -EspacoRecuperavelGB $TotalRecuperavel -EspacoUsadoGB $EspacoUsadoGB
        
        $EspacoDuplicadosLogico = $EspacoDuplicados
        $EspacoGrandesAntigosLogico = $EspacoGrandesAntigos
        $EspacoTemporariosLogico = $EspacoTemporarios
        $TotalRecuperavelLogico = $TotalRecuperavel
        
    } else {
        # FALLBACK - usar cálculos simples mas ainda com validação
        $MensagemDeduplicacao = "⚠️ VALORES COM POSSÍVEIS SOBREPOSIÇÕES"
        
        $EspacoDuplicados = if ($DadosDuplicados.Count -gt 0) {
            ($DadosDuplicados | Where-Object { $_.RecoverableMB -gt 0 } | Measure-Object -Property RecoverableMB -Sum).Sum / 1024
        } else { 0 }
        
        $EspacoTemporarios = if ($DadosTemporarios.Count -gt 0) {
            ($DadosTemporarios | Measure-Object -Property TotalSize -Sum).Sum / 1GB
        } else { 0 }
        
        $EspacoGrandesAntigos = if ($DadosGrandesAntigos.Count -gt 0) {
            ($DadosGrandesAntigos | Measure-Object -Property Length -Sum).Sum / 1GB
        } else { 0 }
        
        $TotalRecuperavel = $EspacoDuplicados + $EspacoTemporarios + $EspacoGrandesAntigos
        
        # CORREÇÃO: Usar função corrigida mesmo no fallback
        $PercentualRecuperavel = Calcular-PercentualReal -EspacoRecuperavelGB $TotalRecuperavel -EspacoUsadoGB $EspacoUsadoGB
        
        $EspacoDuplicadosLogico = $EspacoDuplicados
        $EspacoGrandesAntigosLogico = $EspacoGrandesAntigos
        $EspacoTemporariosLogico = $EspacoTemporarios
        $TotalRecuperavelLogico = $TotalRecuperavel
    }
    
    # CORREÇÃO: Usar Get-ConsistentValues com valores corretos
    $ValoresConsistentes = Get-ConsistentValues -EspacoDuplicadosGB $EspacoDuplicados -EspacoGrandesAntigosGB $EspacoGrandesAntigos -EspacoTemporariosGB $EspacoTemporarios
    $TotalRecuperavelGB = $ValoresConsistentes.TotalGB
    $RecuperavelFormatted = $ValoresConsistentes.TotalFormatted
    
    # CORREÇÃO: Calcular percentuais com valores consistentes
    $PercentualContribuicaoDuplicados = if ($TotalRecuperavelGB -gt 0) { [math]::Round(($EspacoDuplicados / $TotalRecuperavelGB) * 100, 1) } else { 0 }
    $PercentualContribuicaoTemporarios = if ($TotalRecuperavelGB -gt 0) { [math]::Round(($EspacoTemporarios / $TotalRecuperavelGB) * 100, 1) } else { 0 }
    $PercentualContribuicaoGrandesAntigos = if ($TotalRecuperavelGB -gt 0) { [math]::Round(($EspacoGrandesAntigos / $TotalRecuperavelGB) * 100, 1) } else { 0 }
    
    $Top5Tipos = $DadosTipos | Select-Object -First 5
    
    # CORREÇÃO FINAL DO GRÁFICO: DEBUG e garantia de uso do valor exato
    # O total geral usa $TotalRecuperavelGB - o gráfico DEVE usar o mesmo valor
    Escrever-Log "DEBUG GRÁFICO - TotalRecuperavelGB: $TotalRecuperavelGB" "DEBUG"
    Escrever-Log "DEBUG GRÁFICO - EspacoDuplicados: $EspacoDuplicados" "DEBUG"
    Escrever-Log "DEBUG GRÁFICO - EspacoGrandesAntigos: $EspacoGrandesAntigos" "DEBUG"
    
    # USAR EXATAMENTE O MESMO VALOR QUE O TOTAL GERAL
    $ValorCentralGrafico = $TotalRecuperavelGB  # MESMO valor usado no total geral
    
    # Para deduplicação, adicionar economia apenas se ativa
    if ($null -ne $PotencialReal -and $PotencialReal.DeduplicacaoAtiva) {
        $EconomiaDeduplicacao = $PotencialReal.TotalLogicoGB - $PotencialReal.TotalReal
        $ValorCentralGrafico = $TotalRecuperavelGB + $EconomiaDeduplicacao
    }
    
    Escrever-Log "DEBUG GRÁFICO - ValorCentralGrafico FINAL: $ValorCentralGrafico" "DEBUG"
    
    # Usar valores já calculados para percentuais (sem recalcular)
    $TotalParaPercentuais = $ValorCentralGrafico
    
    if ($TotalParaPercentuais -gt 0) {
        $PercentDuplicados = [math]::Round(($EspacoDuplicados / $TotalParaPercentuais) * 100, 0)
        $PercentGrandesAntigos = [math]::Round(($EspacoGrandesAntigos / $TotalParaPercentuais) * 100, 0)
        $PercentDeduplicacao = if ($EconomiaDeduplicacao -gt 0) { [math]::Round(($EconomiaDeduplicacao / $TotalParaPercentuais) * 100, 0) } else { 0 }
        
        $Total = $PercentDuplicados + $PercentGrandesAntigos + $PercentDeduplicacao
        if ($Total -ne 100) {
            $Ajuste = 100 - $Total
            $PercentGrandesAntigos += $Ajuste
        }
    } else {
        $PercentDuplicados = 50; $PercentGrandesAntigos = 50; $PercentDeduplicacao = 0
    }
    
    $GrausDuplicados = $PercentDuplicados * 3.6
    $GrausFimDuplicados = $GrausDuplicados
    $GrausFimGrandesAntigos = $GrausFimDuplicados + ($PercentGrandesAntigos * 3.6)
    $GrausFimDeduplicacao = $GrausFimGrandesAntigos + ($PercentDeduplicacao * 3.6)
    
    $ConicGradient = if ($PercentDeduplicacao -gt 0) {
        "conic-gradient(#D7263D 0deg ${GrausFimDuplicados}deg, #FFA500 ${GrausFimDuplicados}deg ${GrausFimGrandesAntigos}deg, #2ecc71 ${GrausFimGrandesAntigos}deg 360deg)"
    } else {
        "conic-gradient(#D7263D 0deg ${GrausFimDuplicados}deg, #FFA500 ${GrausFimDuplicados}deg 360deg)"
    }
    
    $CentralFormatted = Format-FileSize -SizeBytes ($ValorCentralGrafico * 1GB)
    
    $CountGrandesAntigos = if ($DadosGrandesAntigos -ne $null) { $DadosGrandesAntigos.Count } else { 0 }
    
    $CardDeduplicacao = ""
    if ($null -ne $InfoDeduplicacao -and $InfoDeduplicacao.Habilitado) {
        $TaxaFormatada = Format-Number -Value $InfoDeduplicacao.TaxaDeduplicacao -DecimalPlaces 2
        $EconomiaFormatada = Format-Number -Value $InfoDeduplicacao.EconomiaPercentual -DecimalPlaces 1
        $EspacoLogicoFormatado = Format-Number -Value $InfoDeduplicacao.EspacoLogicoGB -DecimalPlaces 2
        $EspacoFisicoFormatado = Format-Number -Value $InfoDeduplicacao.EspacoFisicoGB -DecimalPlaces 2
        $CardDeduplicacao = @"
            <div class="card dedup-card">
                <h3>Windows Deduplication</h3>
                <div class="card-data">
                    <i class="fas fa-compress-alt"></i>
                    ${TaxaFormatada}x
                </div>
                <div class="card-subtext">Taxa de compressão ativa <span class="status-indicator success"><i class="fas fa-check"></i>Ativo</span></div>
                <div class="dedup-details">
                    <span><strong>Espaço lógico:</strong> $EspacoLogicoFormatado GB</span>
                    <span><strong>Espaço físico:</strong> $EspacoFisicoFormatado GB</span>
                    <span><strong>Economia:</strong> ${EconomiaFormatada}% <i class="fas fa-chart-pie" style="color: #2ecc71; margin-left: 5px; font-size: 0.9em;" title="Representada em verde no gráfico"></i></span>
                </div>
            </div>
"@
    } else {
        $CardDeduplicacao = @"
            <div class="card dedup-card disabled">
                <h3>Windows Deduplication</h3>
                <div class="card-data">
                    <i class="fas fa-times-circle"></i>
                    Desabilitado
                </div>
                <div class="card-subtext">Deduplicação não está ativa <span class="status-indicator danger"><i class="fas fa-exclamation-triangle"></i>Inativo</span></div>
                <div class="dedup-details">
                    <span><strong>Recomendação:</strong> Considere habilitar para economizar espaço</span>
                    <span><strong>Potencial:</strong> 10-80% de economia dependendo dos dados</span>
                </div>
            </div>
"@
    }

    $HTML = @"
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório de Sanitização v2.3 (Read-Only) - $Caminho</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600;700&display=swap');
        
        :root {
            --duplicados-color: #D7263D;
            --grandes-antigos-color: #FFA500;
            --critical: #c0392b; --critical-dark: #b03a2e; --critical-light: #e74c3c;
            --urgent: #d35400; --urgent-dark: #a04000; --warning: #f1c40f; --warning-dark: #f39c12;
            --caution: #e67e22; --neutral: #95a5a6; --neutral-dark: #7f8c8d;
            --primary: #0066cc; --primary-light: #4895ef; --primary-dark: #003d7a;
            --alert-red: #e74c3c; --alert-orange: #f39c12; --alert-yellow: #f1c40f; --alert-amber: #e67e22;
            --success: #2ecc71; --warning: #f39c12; --danger: #e74c3c; --info: #3498db;
            --white: #ffffff; --light-100: #f8f9fa; --light-200: #e9ecef; --light-300: #dee2e6;
            --gray-100: #ced4da; --gray-200: #adb5bd; --gray-300: #6c757d; --gray-400: #495057;
            --dark-100: #343a40; --dark-200: #212529;
            --shadow-sm: 0 2px 5px rgba(0,0,0,0.05); --shadow-md: 0 4px 16px rgba(0,0,0,0.08); --shadow-lg: 0 8px 24px rgba(0,0,0,0.12);
            --space-xs: 0.25rem; --space-sm: 0.5rem; --space-md: 1rem; --space-lg: 1.5rem; --space-xl: 2rem; --space-xxl: 3rem;
            --radius-sm: 4px; --radius-md: 8px; --radius-lg: 16px; --radius-xl: 24px; --radius-full: 9999px;
            --transition-fast: 0.15s ease; --transition-normal: 0.3s ease; --transition-slow: 0.5s ease;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif; }
        
        html { scroll-behavior: smooth; scroll-padding-top: 80px; }
        
        body { background-color: var(--light-100); color: var(--dark-200); line-height: 1.6; overflow-x: hidden; }
        
        h1, h2, h3, h4, h5, h6 { font-family: 'Poppins', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif; font-weight: 600; letter-spacing: -0.02em; color: var(--dark-200); }
        
        .container { width: 100%; max-width: 1200px; margin: 0 auto; padding: 0 var(--space-lg); }
        
        .navbar { position: sticky; top: 0; z-index: 1000; background-color: var(--white); box-shadow: var(--shadow-md); padding: var(--space-md) 0; transition: all var(--transition-normal); }
        
        .navbar .container { display: flex; justify-content: space-between; align-items: center; }
        
        .navbar-brand { font-size: 1.35rem; font-weight: 700; color: var(--primary); text-decoration: none; display: flex; align-items: center; gap: var(--space-sm); }
        
        .navbar-brand i { font-size: 1.4rem; }
        
        .navbar-links { display: flex; gap: var(--space-xl); }
        
        .navbar-links a { color: var(--gray-400); text-decoration: none; font-weight: 500; font-size: 0.95rem; transition: color var(--transition-fast); position: relative; }
        
        .navbar-links a:after { content: ''; position: absolute; bottom: -5px; left: 0; width: 0; height: 2px; background-color: var(--primary); transition: width var(--transition-normal); }
        
        .navbar-links a:hover { color: var(--primary); }
        
        .navbar-links a:hover:after { width: 100%; }
        
        .hero { background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%); color: var(--white); padding: var(--space-xxl) 0; margin-bottom: var(--space-xxl); }
        
        .hero h1 { font-size: 2.5rem; margin-bottom: var(--space-md); color: var(--white); line-height: 1.3; }
        
        .hero p { font-size: 1.1rem; opacity: 0.9; max-width: 700px; margin-bottom: var(--space-lg); }
        
        .hero-stats { background-color: rgba(255, 255, 255, 0.1); border-radius: var(--radius-lg); backdrop-filter: blur(10px); padding: var(--space-lg); display: flex; gap: var(--space-xl); margin-top: var(--space-xl); flex-wrap: wrap; }
        
        .hero-stat { flex: 1; min-width: 200px; }
        
        .hero-stat-value { font-size: 2rem; font-weight: 700; margin-bottom: var(--space-xs); }
        
        .hero-stat-label { font-size: 0.9rem; opacity: 0.8; }
        
        .hero-stat.highlight-value .hero-stat-value { color: #2ecc71; }
        
        .hero-stat.highlight-value .hero-stat-label { color: #2ecc71; }
        
        .trend-indicator { display: inline-flex; align-items: center; margin-left: 8px; font-size: 0.85em; font-weight: bold; }
        
        .trend-up { color: var(--success); }
        
        .trend-down { color: var(--danger); }
        
        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: var(--space-lg); margin-bottom: var(--space-xxl); }
        
        .card { background: var(--white); border-radius: var(--radius-lg); box-shadow: var(--shadow-md); padding: var(--space-xl); transition: all var(--transition-normal); border: 1px solid var(--light-300); position: relative; overflow: hidden; }
        
        .card:hover { transform: translateY(-5px); box-shadow: var(--shadow-lg); }
        
        .card::before { content: ''; position: absolute; top: 0; left: 0; width: 4px; height: 100%; background: linear-gradient(to bottom, var(--primary), var(--primary-dark)); }
        
        .card.error-card::before { background: linear-gradient(to bottom, var(--warning), var(--danger)); }
        
        .card.dedup-card::before { background: linear-gradient(to bottom, var(--info), var(--primary-light)); }
        
        .card.dedup-card.disabled::before { background: linear-gradient(to bottom, var(--danger), var(--critical)); }
        
        .card:nth-child(3)::before { background: linear-gradient(to bottom, var(--critical), var(--critical-dark)); }
        
        .card h3 { font-size: 1.15rem; margin-bottom: var(--space-lg); color: var(--dark-200); position: relative; padding-bottom: var(--space-sm); }
        
        .card h3::after { content: ''; position: absolute; bottom: 0; left: 0; width: 50px; height: 3px; background: linear-gradient(to right, var(--primary), var(--primary-dark)); border-radius: var(--radius-full); }
        
        .card-data { font-size: 1.8rem; font-weight: 700; margin-bottom: var(--space-xs); color: var(--primary-dark); display: flex; align-items: center; gap: var(--space-sm); }
        
        .card:nth-child(3) .card-data::after { content: "⚠️"; font-size: 1.2rem; margin-left: 5px; }
        
        .card-data i { font-size: 1.35rem; color: var(--primary); background-color: var(--light-100); padding: var(--space-sm); border-radius: var(--radius-md); }
        
        .card:nth-child(3) .card-data i { color: var(--white); background-color: var(--critical); }
        
        .error-card .card-data i { color: var(--white); background-color: var(--warning); }
        
        .dedup-card .card-data i { color: var(--white); background-color: var(--info); }
        
        .dedup-card.disabled .card-data i { color: var(--white); background-color: var(--danger); }
        
        .card-subtext { font-size: 0.95rem; color: var(--gray-300); }
        
        .error-details, .dedup-details { margin-top: 10px; font-size: 0.85rem; }
        
        .error-details span, .dedup-details span { display: block; margin: 2px 0; color: var(--gray-400); }
        
        .section { background: var(--white); border-radius: var(--radius-lg); box-shadow: var(--shadow-md); padding: var(--space-xl); margin-bottom: var(--space-xxl); border: 1px solid var(--light-300); }
        
        .section-header { margin-bottom: var(--space-xl); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: var(--space-md); }
        
        .section h2 { font-size: 1.5rem; color: var(--dark-200); display: flex; align-items: center; gap: var(--space-sm); }
        
        .section h2 i { font-size: 1.25rem; color: var(--primary); background-color: var(--light-100); padding: var(--space-sm); border-radius: var(--radius-md); }
        
        .progress-container { margin-bottom: var(--space-lg); }
        
        .progress-label { display: flex; justify-content: space-between; margin-bottom: var(--space-xs); }
        
        .progress-label span { font-size: 0.9rem; color: var(--gray-400); font-weight: 500; }
        
        .progress-label strong { font-size: 0.9rem; color: var(--dark-100); }
        
        .progress-bar { height: 10px; background-color: var(--light-200); border-radius: var(--radius-full); overflow: hidden; position: relative; }
        
        .progress-fill { height: 100%; border-radius: var(--radius-full); transition: width 0.8s cubic-bezier(0.34, 1.56, 0.64, 1); position: relative; }
        
        .full-disk-fill { background: linear-gradient(to right, var(--caution), var(--critical)); }
        .temp-fill { background: linear-gradient(to right, var(--info), var(--primary)); }
        .dup-fill { background: linear-gradient(to right, var(--warning-dark), var(--warning)); }
        .grandes-antigos-fill { background: linear-gradient(to right, var(--urgent-dark), var(--urgent)); }
        .total-fill { background: linear-gradient(to right, var(--success), var(--primary-light)); }
        
        .tabs { display: flex; margin-bottom: var(--space-lg); overflow-x: auto; overflow-y: visible; scrollbar-width: thin; scrollbar-color: var(--gray-200) var(--light-100); gap: var(--space-xs); position: relative; padding: var(--space-sm) var(--space-xs) var(--space-lg) var(--space-xs); }
        
        .tabs::-webkit-scrollbar { height: 4px; }
        .tabs::-webkit-scrollbar-track { background: var(--light-100); border-radius: var(--radius-full); }
        .tabs::-webkit-scrollbar-thumb { background-color: var(--gray-200); border-radius: var(--radius-full); }
        
        .tab { padding: var(--space-md) var(--space-lg); cursor: pointer; background: var(--light-100); border: none; border-radius: var(--radius-md); font-weight: 500; color: var(--gray-300); transition: all var(--transition-normal); white-space: nowrap; outline: none; margin: 2px; }
        
        .tab:hover { color: var(--primary); background: var(--light-200); box-shadow: 0 1px 4px rgba(0, 102, 204, 0.2); transform: translateY(-0.5px); }
        
        .tab.active { color: var(--white); background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%); box-shadow: 0 2px 8px rgba(0, 102, 204, 0.4), 0 0 0 1px rgba(0, 102, 204, 0.2); border-radius: var(--radius-md); position: relative; z-index: 10; transform: translateY(-1px); }
        
        .tab-content { display: none; animation: fadeIn 0.5s ease forwards; }
        
        .tab-content.active { display: block; }
        
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        
        table { width: 100%; border-collapse: collapse; margin-bottom: var(--space-xl); border-radius: var(--radius-md); overflow: hidden; box-shadow: var(--shadow-sm); }
        
        table th, table td { padding: var(--space-md) var(--space-lg); text-align: left; vertical-align: middle; }
        
        table th:nth-child(2), table td:nth-child(2) { 
            min-width: 110px; 
            width: 110px; 
            vertical-align: top;
            padding: var(--space-lg) var(--space-md);
        }
        
        table th { background-color: var(--primary-dark); color: var(--white); font-weight: 600; position: sticky; top: 0; z-index: 10; }
        
        table tr { border-bottom: 1px solid var(--light-300); transition: background-color var(--transition-fast); min-height: 60px; }
        
        table tr:nth-child(even) { background-color: rgba(0, 102, 204, 0.05); }
        
        table tr:nth-child(odd) { background-color: var(--white); }
        
        table tr:hover { background-color: var(--light-200); }
        
        table tr.highlight-row { background-color: rgba(46, 204, 113, 0.1); }
        
        table tr.highlight-row:hover { background-color: rgba(46, 204, 113, 0.2); }
        
        .chart-container { display: grid; grid-template-columns: repeat(auto-fit, minmax(500px, 1fr)); gap: var(--space-lg); margin: var(--space-xl) 0; }
        
        .chart { background: var(--white); border-radius: var(--radius-lg); padding: var(--space-xl); box-shadow: var(--shadow-md); border: 1px solid var(--light-300); height: 100%; min-height: 450px; }
        
        .chart h3 { font-size: 1.1rem; margin-bottom: var(--space-lg); color: var(--dark-200); text-align: center; position: relative; padding-bottom: var(--space-sm); }
        
        .chart h3::after { content: ''; position: absolute; bottom: 0; left: 50%; transform: translateX(-50%); width: 50px; height: 3px; background: linear-gradient(to right, var(--primary), var(--primary-dark)); border-radius: var(--radius-full); }
        
        .bar-chart { height: 300px; display: flex; align-items: flex-end; justify-content: space-around; gap: var(--space-md); padding-top: var(--space-xl); padding-bottom: var(--space-xl); }
        
        .bar { width: 80px; min-width: 80px; position: relative; border-radius: var(--radius-sm) var(--radius-sm) 0 0; transition: height 0.8s cubic-bezier(0.34, 1.56, 0.64, 1), opacity 0.3s ease; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2); opacity: 0; animation: fadeInBar 0.5s ease forwards; animation-delay: calc(var(--index) * 0.1s); }
        
        .bar.bar-type-1 { background: linear-gradient(to top, var(--critical-dark), var(--critical)); position: relative; }
        .bar.bar-type-2 { background: linear-gradient(to top, var(--urgent-dark), var(--urgent)); }
        .bar.bar-type-3 { background: linear-gradient(to top, var(--warning-dark), var(--warning)); }
        .bar.bar-type-4 { background: linear-gradient(to top, var(--caution), var(--warning-dark)); }
        .bar.bar-type-5 { background: linear-gradient(to top, var(--neutral-dark), var(--neutral)); }
        
        @keyframes fadeInBar { to { opacity: 1; } }
        
        .bar:hover { box-shadow: 0 6px 16px rgba(0, 0, 0, 0.3); filter: brightness(1.1); }
        
        .bar-label { position: absolute; bottom: -30px; left: 0; right: 0; text-align: center; font-size: 0.85rem; color: var(--gray-400); font-weight: 500; }
        
        .bar-value { position: absolute; top: -25px; left: 0; right: 0; text-align: center; font-size: 0.85rem; font-weight: 600; color: var(--dark-100); }
        
        .donut-chart-container { position: relative; height: 300px; display: flex; justify-content: center; align-items: center; }
        
        .donut-chart { position: relative; width: 200px; height: 200px; border-radius: 50%; background: $ConicGradient; box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1); border: 2px solid #ffffff; }
        
        .donut-hole { position: absolute; width: 130px; height: 130px; top: 35px; left: 35px; background-color: var(--white); border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-direction: column; box-shadow: inset 0 4px 8px rgba(0,0,0,0.1); }
        
        .donut-hole span:first-child { font-size: 1.5rem; font-weight: 700; background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; margin-bottom: var(--space-xs); }
        
        .donut-hole span:last-child { font-size: 0.75rem; color: var(--gray-300); }
        
        .legend { display: flex; flex-wrap: wrap; justify-content: center; gap: var(--space-md); margin-top: var(--space-lg); width: 100%; }
        
        .legend-item { display: flex; align-items: center; font-size: 0.8rem; font-weight: 500; color: var(--dark-100); margin-bottom: 8px; white-space: nowrap; flex-shrink: 0; max-width: 250px; overflow: hidden; text-overflow: ellipsis; }
        
        .legend-main { display: flex; justify-content: center; gap: var(--space-lg); width: 100%; flex-wrap: wrap; min-width: 600px; }
        
        .legend-note { width: 100%; text-align: center; margin-top: 12px; padding-top: 10px; border-top: 1px solid var(--light-300); color: var(--gray-400); font-size: 0.9rem; }
        
        .legend-note i { margin-right: 5px; color: var(--gray-300); }
        
        .legend-item .legend-color { width: 12px; height: 12px; border-radius: var(--radius-sm); margin-right: var(--space-xs); }
        
        .legend-item:nth-child(1) .legend-color { background-color: #D7263D; }
        .legend-item:nth-child(2) .legend-color { background-color: #FFA500; }
        .legend-item:nth-child(3) .legend-color { background-color: #2ecc71; }
        
        .legend-item:nth-child(3) {
            background: rgba(46, 204, 113, 0.05);
            padding: 8px;
            border-radius: var(--radius-sm);
            border-left: 3px solid #2ecc71;
            margin-top: 5px;
            animation: dedupGlow 3s ease-in-out infinite;
        }
        
        @keyframes dedupGlow {
            0%, 100% { 
                background: rgba(46, 204, 113, 0.05);
                border-left-color: #2ecc71; 
            }
            50% { 
                background: rgba(46, 204, 113, 0.15);
                border-left-color: #27ae60; 
            }
        }
        
        .chart.dedup-active h3 {
            background: linear-gradient(135deg, var(--success) 0%, var(--primary) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .collapsible-card { background-color: var(--white); border-radius: var(--radius-lg); margin-bottom: var(--space-md); box-shadow: var(--shadow-sm); border: 1px solid var(--light-300); overflow: hidden; transition: all var(--transition-normal); }
        
        .collapsible-card:first-of-type { border-left: 4px solid var(--critical); }
        
        .collapsible-card:hover { box-shadow: var(--shadow-md); }
        
        .collapsible { width: 100%; padding: var(--space-lg); display: flex; justify-content: space-between; align-items: center; background-color: var(--white); cursor: pointer; border: none; text-align: left; font-size: 1.05rem; font-weight: 600; color: var(--dark-100); transition: all var(--transition-fast); }
        
        .collapsible:hover { background-color: var(--light-100); }
        
        .collapsible i { font-size: 1rem; transition: transform var(--transition-normal); }
        
        .collapsible.active i { transform: rotate(180deg); }
        
        .content { max-height: 0; overflow: hidden; transition: max-height var(--transition-normal); padding: 0 var(--space-lg); }
        
        .content-inner { padding: var(--space-md) 0 var(--space-lg); border-top: 1px solid var(--light-300); }
        
        .chip-container { display: flex; flex-wrap: wrap; gap: var(--space-xs); margin-top: var(--space-sm); }
        
        .chip { display: inline-flex; align-items: center; gap: 6px; padding: 6px var(--space-sm); background-color: var(--light-100); border: 1px solid var(--light-300); border-radius: var(--radius-full); font-size: 0.75rem; color: var(--gray-400); transition: all 0.2s ease; }
        
        .chip:hover { background-color: var(--light-200); transform: translateY(-2px); box-shadow: var(--shadow-sm); }
        
        .chip i { font-size: 0.9rem; }
        
        .callout { position: relative; padding: 15px 20px 15px 60px; margin: 20px 0; background-color: rgba(240, 249, 255, 0.7); border-left: 4px solid var(--primary); border-radius: var(--radius-md); box-shadow: var(--shadow-md); }
        
        .callout::before { content: "\f0eb"; font-family: "Font Awesome 5 Free"; font-weight: 900; position: absolute; left: 20px; top: 50%; transform: translateY(-50%); font-size: 24px; color: var(--primary); }
        
        .callout.action { background-color: rgba(240, 255, 244, 0.7); border-left: 4px solid var(--success); }
        
        .callout.action::before { content: "\f04b"; color: var(--success); }
        
        .callout.warning { background-color: rgba(255, 248, 225, 0.7); border-left: 4px solid var(--warning); }
        
        .callout.warning::before { content: "\f071"; color: var(--warning); }
        
        .callout h4 { margin: 0 0 8px 0; font-size: 1.1rem; }
        
        .callout p { margin: 0; font-size: 0.95rem; }
        
        .effort-indicator { display: flex; align-items: center; margin-top: 10px; margin-bottom: 15px; }
        
        .effort-indicator-label { font-size: 0.75rem; color: var(--gray-300); margin-right: 10px; min-width: 100px; }
        
        .effort-dots { display: flex; gap: 5px; }
        
        .effort-dot { width: 12px; height: 12px; border-radius: 50%; background-color: var(--light-300); }
        
        .effort-dot.active { background-color: var(--primary); }
        
        .impact-bar { margin-top: 12px; margin-bottom: 5px; }
        
        .impact-label { display: flex; justify-content: space-between; margin-bottom: 5px; font-size: 0.75rem; }
        
        .impact-label-text { color: var(--gray-300); }
        
        .impact-percentage { color: var(--primary); font-weight: 600; }
        
        .impact-bar-container { height: 6px; background-color: var(--light-200); border-radius: 3px; overflow: hidden; }
        
        .impact-bar-fill { height: 100%; background-color: var(--primary); border-radius: 3px; }
        
        .highlight-number { font-size: 1.1rem; font-weight: 600; color: var(--primary-dark); }
        
        .action-item { background-color: var(--white); border-radius: var(--radius-lg); padding: var(--space-lg); margin-bottom: var(--space-lg); box-shadow: var(--shadow-sm); border: 1px solid var(--light-300); transition: all var(--transition-normal); position: relative; overflow: hidden; }
        
        .action-item::before { content: ''; position: absolute; top: 0; left: 0; width: 4px; height: 100%; }
        
        .action-item.critical::before { background: linear-gradient(to bottom, var(--critical), var(--critical-dark)); }
        .action-item.warning::before { background: linear-gradient(to bottom, var(--warning), var(--warning-dark)); }
        .action-item.info::before { background: linear-gradient(to bottom, var(--info), var(--primary)); }
        
        .action-item:hover { transform: translateX(5px); box-shadow: var(--shadow-md); }
        
        .action-item h3 { font-size: 1.15rem; margin-bottom: var(--space-sm); color: var(--dark-200); display: flex; align-items: center; gap: var(--space-sm); }
        
        .action-item h3 i { font-size: 1rem; color: var(--white); background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%); padding: var(--space-xs); border-radius: var(--radius-sm); }
        
        .action-item p { margin-bottom: var(--space-md); color: var(--gray-400); padding-left: calc(24px + var(--space-sm)); }
        
        .priority-tag { display: inline-flex; align-items: center; padding: 3px 8px; border-radius: 12px; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; margin-left: 10px; }
        
        .priority-high { background-color: rgba(231, 76, 60, 0.15); color: #c0392b; }
        .priority-medium { background-color: rgba(243, 156, 18, 0.15); color: #d35400; }
        .priority-low { background-color: rgba(52, 152, 219, 0.15); color: #2980b9; }
        
        footer { background: linear-gradient(135deg, var(--dark-100) 0%, var(--dark-200) 100%); color: var(--white); padding: var(--space-xxl) 0; margin-top: var(--space-xxl); position: relative; overflow: hidden; }
        
        footer::before { content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 2px; background: linear-gradient(to right, transparent, var(--primary), transparent); }
        
        footer .container { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: var(--space-lg); }
        
        footer a { color: var(--primary-light); text-decoration: none; transition: color var(--transition-fast); }
        
        footer a:hover { color: var(--info); text-decoration: underline; }
        
        .count-animation { display: inline-block; }
        
        .scroll-top { position: fixed; bottom: 20px; right: 20px; width: 50px; height: 50px; border-radius: 50%; background: var(--white); display: flex; align-items: center; justify-content: center; cursor: pointer; box-shadow: var(--shadow-lg); z-index: 1000; opacity: 0; visibility: hidden; transition: all var(--transition-normal); border: 1px solid var(--light-300); }
        
        .scroll-top.active { opacity: 1; visibility: visible; }
        
        .scroll-top:hover { transform: translateY(-5px); }
        
        .scroll-top i { color: var(--primary); font-size: 1.2rem; }
        
        .animate-fade-up { opacity: 0; transform: translateY(20px); transition: opacity 0.8s ease, transform 0.8s ease; }
        
        .animated { opacity: 1; transform: translateY(0); }
        
        .mt-1 { margin-top: var(--space-sm); }
        .mt-2 { margin-top: var(--space-md); }
        .mt-3 { margin-top: var(--space-lg); }
        .mt-4 { margin-top: var(--space-xl); }
        .mt-5 { margin-top: var(--space-xxl); }
        
        .mb-1 { margin-bottom: var(--space-sm); }
        .mb-2 { margin-bottom: var(--space-md); }
        .mb-3 { margin-bottom: var(--space-lg); }
        .mb-4 { margin-bottom: var(--space-xl); }
        .mb-5 { margin-bottom: var(--space-xxl); }
        
        .text-primary { color: var(--primary); }
        .text-success { color: var(--success); }
        .text-warning { color: var(--warning); }
        .text-danger { color: var(--danger); }
        .text-info { color: var(--info); }
        .text-gray { color: var(--gray-300); }
        
        .tooltip { position: relative; cursor: help; }
        
        .tooltip::before {
            content: attr(data-tooltip);
            position: absolute;
            bottom: 125%;
            left: 50%;
            transform: translateX(-50%);
            background-color: var(--dark-200);
            color: var(--white);
            padding: 8px 12px;
            border-radius: var(--radius-md);
            font-size: 0.875rem;
            white-space: nowrap;
            opacity: 0;
            visibility: hidden;
            transition: all var(--transition-normal);
            z-index: 1000;
            box-shadow: var(--shadow-lg);
        }
        
        .tooltip::after {
            content: '';
            position: absolute;
            bottom: 115%;
            left: 50%;
            transform: translateX(-50%);
            border: 5px solid transparent;
            border-top-color: var(--dark-200);
            opacity: 0;
            visibility: hidden;
            transition: all var(--transition-normal);
        }
        
        .tooltip:hover::before,
        .tooltip:hover::after {
            opacity: 1;
            visibility: visible;
        }
        
        .dedup-explanation {
            background: linear-gradient(135deg, rgba(52, 152, 219, 0.1) 0%, rgba(155, 89, 182, 0.1) 100%);
            border: 1px solid rgba(52, 152, 219, 0.3);
            border-radius: var(--radius-lg);
            padding: var(--space-lg);
            margin: var(--space-lg) 0;
            position: relative;
        }
        
        .dedup-explanation::before {
            content: "⚡";
            font-family: inherit;
            font-weight: 900;
            position: absolute;
            top: 15px;
            left: 15px;
            font-size: 24px;
            color: var(--info);
        }
        
        .dedup-explanation h4 {
            margin: 0 0 15px 40px;
            color: var(--info);
            font-size: 1.1rem;
        }
        
        .dedup-explanation p {
            margin: 0 0 10px 40px;
            font-size: 0.95rem;
            color: var(--gray-400);
        }
        
        .dedup-comparison {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: var(--space-md);
            margin: 15px 0 0 40px;
        }
        
        .dedup-value {
            background: var(--white);
            padding: 12px;
            border-radius: var(--radius-md);
            border: 1px solid var(--light-300);
        }
        
        .dedup-value-label {
            font-size: 0.8rem;
            color: var(--gray-300);
            margin-bottom: 5px;
            text-transform: uppercase;
            font-weight: 600;
        }
        
        .dedup-value-amount {
            font-size: 1.1rem;
            font-weight: 700;
            color: var(--primary-dark);
        }
        
        .dedup-value.logical {
            border-left: 4px solid var(--warning);
        }
        
        .dedup-value.physical {
            border-left: 4px solid var(--success);
        }
        
        .progress-container.dedup-aware {
            position: relative;
        }
        
        .progress-container.dedup-aware::after {
            content: "⚡";
            position: absolute;
            right: -25px;
            top: 50%;
            transform: translateY(-50%);
            font-size: 1rem;
            color: var(--info);
            cursor: help;
        }
        
        .progress-container.dedup-aware::before {
            content: "Valores ajustados para deduplicação ativa";
            position: absolute;
            right: -25px;
            top: -25px;
            font-size: 0.6rem;
            color: var(--info);
            opacity: 0;
            visibility: hidden;
            background: var(--dark-200);
            color: var(--white);
            padding: 4px 8px;
            border-radius: var(--radius-sm);
            white-space: nowrap;
            transition: all var(--transition-normal);
            z-index: 1000;
        }
        
        .progress-container.dedup-aware:hover::before {
            opacity: 1;
            visibility: visible;
        }
        .status-indicator {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 8px;
            border-radius: var(--radius-full);
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        .status-indicator.success {
            background-color: rgba(46, 204, 113, 0.15);
            color: var(--success);
        }
        
        .status-indicator.warning {
            background-color: rgba(243, 156, 18, 0.15);
            color: var(--warning);
        }
        
        .status-indicator.danger {
            background-color: rgba(231, 76, 60, 0.15);
            color: var(--danger);
        }
        
        .status-indicator i {
            font-size: 0.7rem;
        }
        
        .category-badge {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 3px 6px;
            border-radius: var(--radius-full);
            font-size: 0.65rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.3px;
            margin-right: 0;
        }
        
        .badge-critical {
            background-color: rgba(192, 57, 43, 0.15);
            color: #c0392b;
            border: 1px solid rgba(192, 57, 43, 0.3);
        }
        
        .badge-high {
            background-color: rgba(230, 126, 34, 0.15);
            color: #e67e22;
            border: 1px solid rgba(230, 126, 34, 0.3);
        }
        
        .badge-medium {
            background-color: rgba(241, 196, 15, 0.15);
            color: #f1c40f;
            border: 1px solid rgba(241, 196, 15, 0.3);
        }
        
        .badge-info {
            background-color: rgba(52, 152, 219, 0.15);
            color: #3498db;
            border: 1px solid rgba(52, 152, 219, 0.3);
        }
        
        .category-badge:hover {
            transform: scale(1.05);
            box-shadow: 0 2px 8px rgba(0,0,0,0.15);
        }
        
        .badge-critical:hover {
            background-color: rgba(192, 57, 43, 0.25);
        }
        
        .badge-high:hover {
            background-color: rgba(230, 126, 34, 0.25);
        }
        
        .badge-medium:hover {
            background-color: rgba(241, 196, 15, 0.25);
        }
        
        .badge-info:hover {
            background-color: rgba(52, 152, 219, 0.25);
        }
        
        .category-cell {
            white-space: nowrap;
            overflow: visible;
            text-overflow: initial;
            min-width: 120px;
            max-width: none;
        }
        
        .badge-container {
            display: flex;
            flex-direction: column;
            gap: 3px;
            align-items: flex-start;
            width: 100%;
        }
        
        .badge-container .category-badge {
            width: fit-content;
            white-space: nowrap;
            min-width: 70px;
            text-align: center;
            justify-content: center;
        }
        
        .category-cell .category-badge {
            margin-bottom: 0;
            display: inline-block;
        }
        
        .progress-fill::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            height: 100%;
            width: 30%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
            animation: shimmer 2s infinite;
        }
        
        @keyframes shimmer {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(400%); }
        }
        
        @media print {
            .navbar, .scroll-top, .tabs { display: none !important; }
            .section { page-break-inside: avoid; margin-bottom: 1rem; }
            .chart-container { grid-template-columns: 1fr; }
            .dashboard { grid-template-columns: repeat(2, 1fr); }
            body { font-size: 12px; }
            .hero { background: var(--white) !important; color: var(--dark-200) !important; }
            .card { border: 1px solid var(--gray-200); }
        }
        
        @keyframes slideInFromBottom {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .card:nth-child(1) { animation: slideInFromBottom 0.6s ease 0.1s both; }
        .card:nth-child(2) { animation: slideInFromBottom 0.6s ease 0.2s both; }
        .card:nth-child(3) { animation: slideInFromBottom 0.6s ease 0.3s both; }
        .card:nth-child(4) { animation: slideInFromBottom 0.6s ease 0.4s both; }
        .card:nth-child(5) { animation: slideInFromBottom 0.6s ease 0.5s both; }
        .card:nth-child(6) { animation: slideInFromBottom 0.6s ease 0.6s both; }
        
        @media (max-width: 1024px) {
            .dashboard { grid-template-columns: repeat(2, 1fr); }
            .chart-container { grid-template-columns: 1fr; }
            .hero-stats { flex-direction: column; gap: var(--space-md); }
            .bar-chart { height: 300px; gap: var(--space-sm); }
            .bar { width: 70px; min-width: 70px; }
            .category-cell { min-width: 110px; }
            .legend-main { gap: var(--space-md); }
            .legend-item { font-size: 0.82rem; }
        }
        
        @media (max-width: 900px) {
            .legend-main { flex-direction: column; align-items: center; gap: var(--space-sm); }
            .legend-item { justify-content: center; }
        }
        
        @media (max-width: 768px) {
            .dashboard { grid-template-columns: 1fr; }
            .chart-container { grid-template-columns: 1fr; }
            footer .container { flex-direction: column; text-align: center; }
            .navbar .container { flex-direction: column; gap: var(--space-md); }
            .navbar-links { width: 100%; justify-content: center; flex-wrap: wrap; gap: var(--space-md); }
            .hero h1 { font-size: 2rem; }
            .hero-stat { min-width: 150px; }
            .dedup-comparison { grid-template-columns: 1fr; }
            .dedup-explanation { padding-left: 15px; }
            .dedup-explanation h4, .dedup-explanation p, .dedup-comparison { margin-left: 25px; }
            .tabs { padding: var(--space-md) var(--space-sm) var(--space-xl) var(--space-sm); overflow-x: auto; overflow-y: visible; }
            .bar-chart { height: 250px; flex-direction: column; align-items: center; gap: var(--space-lg); }
            .bar { width: 60px; min-width: 60px; height: 80px !important; }
            .bar-label { position: static; margin-top: 10px; }
            .bar-value { position: static; margin-bottom: 5px; }
            .category-cell { min-width: 100px; }
            .legend-main { flex-direction: column; align-items: center; gap: var(--space-sm); }
            .legend-item { font-size: 0.8rem; justify-content: center; }
        }
        
        .card:focus-within {
            outline: 2px solid var(--primary);
            outline-offset: 2px;
        }
        
        .tab:focus {
            outline: 2px solid var(--primary);
            outline-offset: 2px;
        }
        
        .tab.active:focus {
            outline: 2px solid var(--white);
            outline-offset: 2px;
        }
        
        .loading {
            position: relative;
            overflow: hidden;
        }
        
        .loading::after {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.4), transparent);
            animation: loading 1.5s infinite;
        }
        
        @keyframes loading {
            0% { left: -100%; }
            100% { left: 100%; }
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <a href="#" class="navbar-brand">
                <i class="fas fa-shield-alt"></i>
                Sanitização do File Server
            </a>
            <div class="navbar-links">
                <a href="#overview">Visão Geral</a>
                <a href="#details">Detalhes</a>
                <a href="#recommendations">Recomendações</a>
                <a href="#actions">Ações</a>
            </div>
        </div>
    </nav>
    
    <section class="hero">
        <div class="container">
            <h1>Relatório de Sanitização do File Server</h1>
            <p>Análise completa 100% read-only com tratamento robusto de erros e recomendações para otimização de armazenamento para: $Caminho</p>
            
            <div class="hero-stats">
                <div class="hero-stat">
                    <div class="hero-stat-value count-animation" data-count="$(Format-Number -Value $TotalFormatted.Value -DecimalPlaces 2)" data-suffix=" $($TotalFormatted.Unit)">$(Format-Number -Value $TotalFormatted.Value -DecimalPlaces 2) $($TotalFormatted.Unit)</div>
                    <div class="hero-stat-label">Espaço Total</div>
                </div>
                
                <div class="hero-stat">
                    <div class="hero-stat-value count-animation" data-count="$(Format-Number -Value $UsadoFormatted.Value -DecimalPlaces 2)" data-suffix=" $($UsadoFormatted.Unit)">$(Format-Number -Value $UsadoFormatted.Value -DecimalPlaces 2) $($UsadoFormatted.Unit)</div>
                    <div class="hero-stat-label">Espaço Usado</div>
                </div>
                
                <div class="hero-stat highlight-value">
                    <div class="hero-stat-value count-animation" data-count="$(Format-Number -Value $RecuperavelFormatted.Value -DecimalPlaces 2)" data-suffix=" $($RecuperavelFormatted.Unit)">$(Format-Number -Value $RecuperavelFormatted.Value -DecimalPlaces 2) $($RecuperavelFormatted.Unit)</div>
                    <div class="hero-stat-label">Potencial de Recuperação <span class="trend-indicator trend-up">↑</span></div>
                </div>
                
                <div class="hero-stat">
                    <div class="hero-stat-value count-animation" data-count="$(Format-Number -Value $PercentualRecuperavel -DecimalPlaces 2)" data-suffix="%">$(Format-Number -Value $PercentualRecuperavel -DecimalPlaces 2)%</div>
                    <div class="hero-stat-label">Espaço Recuperável</div>
                </div>
            </div>
        </div>
    </section>
    
    <div class="container" id="overview">
        <div class="dashboard animate-fade-up">
            <div class="card">
                <h3>Informações do Disco $LetraDisco</h3>
                <div class="card-data">
                    <i class="fas fa-hdd"></i>
                    $(Format-Number -Value $EspacoUsadoGB -DecimalPlaces 2) GB
                </div>
                <div class="card-subtext">Espaço usado de $(Format-Number -Value $EspacoTotalGB -DecimalPlaces 2) GB total ($(Format-Number -Value $PercentualUsado -DecimalPlaces 2)%)</div>
            </div>
            
            <div class="card">
                <h3>Espaço Livre</h3>
                <div class="card-data">
                    <i class="fas fa-check-circle"></i>
                    $(Format-Number -Value $EspacoLivreGB -DecimalPlaces 2) GB
                </div>
                <div class="card-subtext">$(Format-Number -Value $PercentualLivre -DecimalPlaces 2)% do espaço total disponível</div>
            </div>
            
            <div class="card">
                <h3>Arquivos Duplicados</h3>
                <div class="card-data">
                    <i class="fas fa-copy"></i>
                    $(Format-Number -Value $EspacoDuplicados -DecimalPlaces 2) GB
                </div>
                <div class="card-subtext">$(Format-Number -Value ($DadosDuplicados | Group-Object -Property GroupID).Count -NoDecimal) grupos de duplicados</div>
            </div>
            
            <div class="card">
                <h3>Grandes OU Antigos</h3>
                <div class="card-data">
                    <i class="fas fa-archive"></i>
                    $(Format-Number -Value $CountGrandesAntigos -NoDecimal) arquivos
                </div>
                <div class="card-subtext">Arquivos grandes ($(Format-Number -Value $TamanhoMinimoArquivosMB -NoDecimal) MB) OU antigos ($(Format-Number -Value $DiasArquivosAntigos -NoDecimal) dias)</div>
            </div>
            
            $CardDeduplicacao
            
            <div class="card error-card">
                <h3>Erros de Análise</h3>
                <div class="card-data">
                    <i class="fas fa-exclamation-triangle"></i>
                    $(Format-Number -Value $TotalErros -NoDecimal)
                </div>
                <div class="card-subtext">Total de erros encontrados durante a análise</div>
                <div class="error-details">
                    <span><strong>Sem permissão:</strong> $(Format-Number -Value $ErrosSemPermissao -NoDecimal)</span>
                    <span><strong>Caminhos longos:</strong> $(Format-Number -Value $ErrosCaminhosLongos -NoDecimal)</span>
                </div>
            </div>
        </div>
        
        <div class="section animate-fade-up">
            <div class="section-header">
                <h2><i class="fas fa-chart-pie"></i> Potencial de Recuperação</h2>
            </div>
            
            <div class="progress-container">
                <div class="progress-label">
                    <span>Utilização do Disco</span>
                    <strong class="text-warning">$(Format-Number -Value $EspacoUsadoGB -DecimalPlaces 2) GB ($(Format-Number -Value $PercentualUsado -DecimalPlaces 2)%)</strong>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill full-disk-fill" style="width: $(Format-Number -Value $PercentualUsado -DecimalPlaces 1)%;"></div>
                </div>
            </div>
            
            <div class="progress-container $ClasseAdicionalProgress">
                <div class="progress-label">
                    <span>Arquivos Duplicados</span>
                    <strong class="text-warning">$(Format-Number -Value $EspacoDuplicados -DecimalPlaces 2) GB</strong>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill dup-fill" style="width: $(Format-Number -Value ([math]::Min([math]::Round(($EspacoDuplicados / $EspacoUsadoGB) * 100, 2), 100)) -DecimalPlaces 1)%;"></div>
                </div>
            </div>
            
            <div class="progress-container $ClasseAdicionalProgress">
                <div class="progress-label">
                    <span>Grandes OU Antigos</span>
                    <strong class="text-warning">$(Format-Number -Value $EspacoGrandesAntigos -DecimalPlaces 2) GB</strong>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill grandes-antigos-fill" style="width: $(Format-Number -Value ([math]::Min([math]::Round(($EspacoGrandesAntigos / $EspacoUsadoGB) * 100, 2), 100)) -DecimalPlaces 1)%;"></div>
                </div>
            </div>
            
            <div class="progress-container $ClasseAdicionalProgress">
                <div class="progress-label">
                    <span>Total Recuperável</span>
                    <strong class="text-success">$(Format-Number -Value $RecuperavelFormatted.Value -DecimalPlaces 2) $($RecuperavelFormatted.Unit) ($(Format-Number -Value $PercentualRecuperavel -DecimalPlaces 2)%)</strong>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill total-fill" style="width: $(Format-Number -Value ([math]::Min($PercentualRecuperavel, 100)) -DecimalPlaces 1)%;"></div>
                </div>
            </div>
"@

    # Adicionar explicação da deduplicação se estiver ativa
    if ($null -ne $PotencialReal -and $PotencialReal.DeduplicacaoAtiva) {
        $FatorDeduplicacaoFormatado = Format-Number -Value $PotencialReal.FatorDeduplicacao -DecimalPlaces 2
        $ExemploEconomia = Format-Number -Value ([math]::Round(100 / $PotencialReal.FatorDeduplicacao, 0)) -NoDecimal
        $TotalLogicoFormatado = Format-Number -Value $TotalRecuperavelLogico -DecimalPlaces 2
        $TotalFisicoFormatado = Format-Number -Value $TotalRecuperavel -DecimalPlaces 2
        $HTML += @"
            
            <div class="dedup-explanation">
                <h4>Windows Deduplication Detectada</h4>
                <p><strong>Importante:</strong> Os valores mostrados foram ajustados considerando que a deduplicação está ativa (Taxa: ${FatorDeduplicacaoFormatado}x).</p>
                <p>Isso significa que quando você remove arquivos, o espaço físico liberado no disco será menor que o tamanho lógico dos arquivos.</p>
                <p><strong>Exemplo:</strong> Se você remove 100GB de duplicados "lógicos", apenas ${ExemploEconomia}GB serão liberados fisicamente no disco.</p>
                <p><strong><i class="fas fa-chart-pie" style="color: #2ecc71;"></i> Gráfico:</strong> A seção verde no gráfico mostra a economia adicional proporcionada pela deduplicação ativa.</p>
                
                <div class="dedup-comparison">
                    <div class="dedup-value logical">
                        <div class="dedup-value-label">Espaço Lógico</div>
                        <div class="dedup-value-amount">$TotalLogicoFormatado GB</div>
                        <small>Tamanho "aparente" dos arquivos</small>
                    </div>
                    <div class="dedup-value physical">
                        <div class="dedup-value-label">Espaço Físico</div>
                        <div class="dedup-value-amount">$TotalFisicoFormatado GB</div>
                        <small>Espaço real liberado no disco</small>
                    </div>
                </div>
            </div>
"@
    }

    # RESTO DO HTML - incluindo todas as seções restantes
    $HTML += @"
        </div>
        
        <div class="section animate-fade-up" id="details">
            <div class="section-header">
                <h2><i class="fas fa-info-circle"></i> Informações Detalhadas</h2>
            </div>
            
            <div class="tabs">
                <button class="tab active" onclick="openTab(event, 'overview-tab')">Visão Geral</button>
                <button class="tab" onclick="openTab(event, 'types-tab')">Tipos de Arquivo</button>
                <button class="tab" onclick="openTab(event, 'duplicates-tab')">Duplicados</button>
                <button class="tab" onclick="openTab(event, 'large-old-tab')">Grandes OU Antigos</button>
                <button class="tab" onclick="openTab(event, 'errors-tab')">Erros v2.3</button>
            </div>
            
            <div id="overview-tab" class="tab-content active">
                <h3 class="mb-2">Resumo da Análise</h3>
                <p class="mb-1"><strong>Espaço analisado:</strong> $(Format-Number -Value $EspacoUsadoGB -DecimalPlaces 2) GB</p>
                <p class="mb-1"><strong>Espaço total disponível:</strong> $(Format-Number -Value $EspacoTotalGB -DecimalPlaces 2) GB ($(Format-Number -Value $PercentualLivre -DecimalPlaces 1)% livre)</p>
                <p class="mb-1"><strong>Potencial de recuperação:</strong> $(Format-Number -Value $RecuperavelFormatted.Value -DecimalPlaces 2) $($RecuperavelFormatted.Unit) ($(Format-Number -Value $PercentualRecuperavel -DecimalPlaces 1)% do espaço usado)</p>
                $(if ($null -ne $PotencialReal -and $PotencialReal.DeduplicacaoAtiva) { 
                    "<p class=""mb-3""><strong>Windows Deduplication:</strong> Ativa (Taxa: $(Format-Number -Value $PotencialReal.FatorDeduplicacao -DecimalPlaces 2)x) - Valores ajustados para espaço físico real</p>" 
                } else { 
                    "<p class=""mb-3""><strong>Windows Deduplication:</strong> Não detectada ou inativa</p>" 
                })
                
                <div class="chart-container">
                    <div class="chart">
                        <h3>Top 5 Tipos de Arquivo</h3>
                        <div class="bar-chart">
"@

    # Adicionar barras dinamicamente para os top 5 tipos de arquivo
    $MaxValue = if ($Top5Tipos.Count -gt 0) { $Top5Tipos | Select-Object -First 1 -ExpandProperty SizeGB } else { 1 }
    $MaxHeight = 280

    for ($i = 0; $i -lt [math]::Min($Top5Tipos.Count, 5); $i++) {
        $Tipo = $Top5Tipos[$i]
        $RelativeHeight = [math]::Round(($Tipo.SizeGB / $MaxValue) * $MaxHeight, 0)
        $BarValue = $Tipo.SizeFormatted
        
        $HTML += @"
                            <div class="bar bar-type-$($i+1)" style="height: ${RelativeHeight}px; --index: $($i+1);">
                                <div class="bar-value">$BarValue</div>
                                <div class="bar-label">$($Tipo.Extension)</div>
                            </div>
"@
    }

    $HTML += @"
                        </div>
                    </div>
                    
                    <div class="chart$(if ($PercentDeduplicacao -gt 0) { " dedup-active" })">
                        <h3>$(if ($PercentDeduplicacao -gt 0) { "Recuperação + Economia Deduplicação <i class='fas fa-magic' style='color: #2ecc71; font-size: 0.8em;'></i>" } else { "Composição da Recuperação" })</h3>
                        <div class="donut-chart-container">
                            <div class="donut-chart"></div>
                            <div class="donut-hole">
                                <span>$(Format-Number -Value $CentralFormatted.Value -DecimalPlaces 2)</span>
                                <span>$($CentralFormatted.Unit) $(if ($PercentDeduplicacao -gt 0) { "Total" } else { "recuperáveis" })</span>
                            </div>
                        </div>
                        <div class="legend">
                            <div class="legend-main">
                                <div class="legend-item">
                                    <div class="legend-color"></div>
                                    <span>Duplicados: $((Format-FileSize -SizeBytes ($EspacoDuplicados * 1GB)).Formatted) (${PercentDuplicados}%)</span>
                                </div>
                                <div class="legend-item">
                                    <div class="legend-color"></div>
                                    <span>Grandes+Antigos: $((Format-FileSize -SizeBytes ($EspacoGrandesAntigos * 1GB)).Formatted) (${PercentGrandesAntigos}%)</span>
                                </div>
$(if ($PercentDeduplicacao -gt 0) {
    @"
                                <div class="legend-item">
                                    <div class="legend-color"></div>
                                    <span>Deduplicação: $((Format-FileSize -SizeBytes ($EconomiaDeduplicacao * 1GB)).Formatted) (${PercentDeduplicacao}%)</span>
                                </div>
"@
})
                            </div>
$(if ($PercentDeduplicacao -gt 0) {
    @"
                            <div class="legend-note">
                                <i class="fas fa-magic"></i>
                                A seção verde mostra a economia proporcionada pela deduplicação ativa
                            </div>
"@
} else {
    @"
                            <div class="legend-note">
                                <i class="fas fa-info-circle"></i>
                                Valores mostram o potencial de recuperação de espaço
                            </div>
"@
})
                        </div>
                    </div>
                </div>
            </div>
            
            <div id="types-tab" class="tab-content">
                <h3 class="mb-2">Distribuição por Tipo de Arquivo</h3>
                <p class="mb-3">Análise dos tipos de arquivo que mais ocupam espaço no disco</p>
                
                <table>
                    <thead>
                        <tr>
                            <th>Extensão</th>
                            <th>Tamanho</th>
                            <th>Quantidade</th>
                            <th>% do Total</th>
                        </tr>
                    </thead>
                    <tbody>
"@

    $Top10Tipos = $DadosTipos | Select-Object -First 10
    $TotalSize = ($DadosTipos | Measure-Object -Property TotalSize -Sum).Sum

    foreach ($Tipo in $Top10Tipos) {
        $Percent = if ($TotalSize -gt 0) { [math]::Round(($Tipo.TotalSize / $TotalSize) * 100, 2) } else { 0 }
        
        $HTML += @"
                        <tr>
                            <td>$($Tipo.Extension)</td>
                            <td>$($Tipo.SizeFormatted)</td>
                            <td>$(Format-Number -Value $Tipo.FileCount -NoDecimal)</td>
                            <td>$(Format-Number -Value $Percent -DecimalPlaces 2)%</td>
                        </tr>
"@
    }

    $HTML += @"
                    </tbody>
                </table>
            </div>
            
            <div id="duplicates-tab" class="tab-content">
                <h3 class="mb-2">Arquivos Duplicados</h3>
                <p class="mb-3">Foram encontrados $(Format-Number -Value ($DadosDuplicados | Group-Object -Property GroupID).Count -NoDecimal) grupos de arquivos duplicados, ocupando $(Format-Number -Value $EspacoDuplicados -DecimalPlaces 2) GB de espaço recuperável.</p>
                
                <div class="collapsible-card">
                    <button class="collapsible">
                        Top 5 Grupos de Duplicados
                        <span class="priority-tag priority-high">Prioridade Alta</span>
                        <i class="fas fa-chevron-down"></i>
                    </button>
                    <div class="content">
                        <div class="content-inner">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Grupo</th>
                                        <th>Arquivos</th>
                                        <th>Tamanho Total</th>
                                        <th>Recuperável</th>
                                    </tr>
                                </thead>
                                <tbody>
"@

    $Top5Grupos = $DadosDuplicados | Group-Object -Property GroupID | 
                 Select-Object -First 5 | 
                 Sort-Object -Property { ($_.Group | Where-Object { $_.RecoverableMB -gt 0 } | Measure-Object -Property RecoverableMB -Sum).Sum } -Descending

    foreach ($Grupo in $Top5Grupos) {
        $FirstFile = $Grupo.Group[0]
        $RecuperavelMB = ($Grupo.Group | Where-Object { $_.RecoverableMB -gt 0 } | Measure-Object -Property RecoverableMB -Sum).Sum
        
        $TamanhoTotalFormatted = (Format-FileSize -SizeBytes ([double]$FirstFile.SizeMB * 1MB)).Formatted
        $RecuperavelFormatted = (Format-FileSize -SizeBytes ($RecuperavelMB * 1MB)).Formatted
        
        $HTML += @"
                                    <tr>
                                        <td>$($Grupo.Name)</td>
                                        <td>$(Format-Number -Value $Grupo.Count -NoDecimal)</td>
                                        <td>$TamanhoTotalFormatted</td>
                                        <td>$RecuperavelFormatted</td>
                                    </tr>
"@
    }

    $HTML += @"
                                </tbody>
                            </table>
                            <p class="mt-2"><strong>Ação recomendada:</strong> Revisão e remoção dos arquivos duplicados após verificação de segurança.</p>
                            <p><strong>Relatório detalhado:</strong> Consulte o arquivo CSV completo para ver todos os grupos de duplicados.</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <div id="large-old-tab" class="tab-content">
                <h3 class="mb-2">Grandes OU Antigos</h3>
                <p class="mb-3">Foram encontrados $(Format-Number -Value $DadosGrandesAntigos.Count -NoDecimal) arquivos grandes ($(Format-Number -Value $TamanhoMinimoArquivosMB -NoDecimal) MB) OU antigos ($(Format-Number -Value $DiasArquivosAntigos -NoDecimal) dias), ocupando $(Format-Number -Value $EspacoGrandesAntigos -DecimalPlaces 2) GB de espaço.</p>
                
                <div class="collapsible-card">
                    <button class="collapsible">
                        Top 5 Arquivos Grandes OU Antigos
                        <span class="priority-tag priority-high">Prioridade Alta</span>
                        <i class="fas fa-chevron-down"></i>
                    </button>
                    <div class="content">
                        <div class="content-inner">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Arquivo</th>
                                        <th>Categoria</th>
                                        <th>Tamanho</th>
                                        <th>Idade (dias)</th>
                                        <th>Última Modificação</th>
                                    </tr>
                                </thead>
                                <tbody>
"@

    $Top5GrandesAntigos = $DadosGrandesAntigos | Sort-Object -Property @{
        Expression = {
            $cat = if ($_.Categoria) { $_.Categoria } else { "N/A" }
            if ($cat -like "*Grande + Antigo*") { 1 }
            elseif ($cat -like "*Grande*" -and $cat -notlike "*Antigo*") { 2 }
            elseif ($cat -like "*Antigo*" -and $cat -notlike "*Grande*") { 3 }
            else { 4 }
        }
    }, @{
        Expression = {[long]$_.Length}; Descending = $true
    } | Select-Object -First 5

    foreach ($Arquivo in $Top5GrandesAntigos) {
        $NomeArquivo = Split-Path -Path $Arquivo.FullName -Leaf
        $Categoria = if ($Arquivo.Categoria) { $Arquivo.Categoria } else { "N/A" }
        $IdadeDias = if ($Arquivo.IdadeDias) { $Arquivo.IdadeDias } else { [math]::Round((New-TimeSpan -Start $Arquivo.LastWriteTime -End (Get-Date)).TotalDays) }
        $TamanhoFormatado = (Format-FileSize -SizeBytes ([long]$Arquivo.Length)).Formatted
        
        $BadgeClass = "badge-info"
        $CategoriaLimpa = $Categoria
        
        if ($Categoria -like "*Grande + Antigo*") {
            $BadgeClass = "badge-critical"
            $CategoriaLimpa = "Grande + Antigo"
        }
        elseif ($Categoria -like "*Grande*" -and $Categoria -notlike "*Antigo*") {
            $BadgeClass = "badge-high"
            $CategoriaLimpa = "Grande"
        }
        elseif ($Categoria -like "*Antigo*" -and $Categoria -notlike "*Grande*") {
            $BadgeClass = "badge-medium"
            $CategoriaLimpa = "Antigo"
        }
        
        $BadgeDuplicado = ""
        if ($Categoria -like "*(Duplicado - Preservado)*") {
            $BadgeDuplicado = '<span class="category-badge badge-info">PRESERVADO DO DUPLICADOS</span>'
        }
        
        $BadgeHTML = if ($BadgeDuplicado -ne "") {
            @"
<div class="badge-container">
                                                <span class="category-badge $BadgeClass">$CategoriaLimpa</span>
                                                $BadgeDuplicado
                                            </div>
"@
        } else {
            @"
<div class="badge-container">
                                                <span class="category-badge $BadgeClass">$CategoriaLimpa</span>
                                            </div>
"@
        }
        
        $HTML += @"
                                    <tr>
                                        <td>$NomeArquivo</td>
                                        <td class="category-cell">
                                            $BadgeHTML
                                        </td>
                                        <td>$TamanhoFormatado</td>
                                        <td>$(
                                            $diasNumerico = [double]$IdadeDias
                                            if ($diasNumerico -ge 365) { 
                                                "$(Format-Number -Value ($diasNumerico / 365) -DecimalPlaces 1) anos" 
                                            } else { 
                                                "$(Format-Number -Value $diasNumerico -NoDecimal) dias" 
                                            }
                                        )</td>
                                        <td>$($Arquivo.LastWriteTime)</td>
                                    </tr>
"@
    }

    $HTML += @"
                                </tbody>
                            </table>
                            <p class="mt-2"><strong>Critério:</strong> Arquivos $(Format-Number -Value $TamanhoMinimoArquivosMB -NoDecimal) MB ou $(Format-Number -Value $DiasArquivosAntigos -NoDecimal) dias (ordenados por impacto)</p>
                            <p class="mt-2"><strong>Ação recomendada:</strong> Considerar a migração desses arquivos para armazenamento externo, cloud ou arquivá-los se não forem acessados frequentemente.</p>
                            <p><strong>Relatório detalhado:</strong> Consulte o arquivo CSV completo para ver todos os arquivos grandes OU antigos.</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <div id="errors-tab" class="tab-content">
                <h3 class="mb-2">Relatório de Erros v2.3</h3>
                <p class="mb-3">Durante a análise foram encontrados <strong>$(Format-Number -Value $TotalErros -NoDecimal)</strong> erros que impediram o acesso a alguns arquivos e pastas.</p>
                
                <div class="callout warning">
                    <h4>Nova Funcionalidade v2.3</h4>
                    <p>Esta versão inclui tratamento robusto de erros de permissão e caminhos muito longos, garantindo que a análise continue mesmo com problemas de acesso.</p>
                </div>
                
                <table>
                    <thead>
                        <tr>
                            <th>Tipo de Erro</th>
                            <th>Quantidade</th>
                            <th>Descrição</th>
                            <th>Arquivo CSV</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Sem Permissão</td>
                            <td>$(Format-Number -Value $ErrosSemPermissao -NoDecimal)</td>
                            <td>Arquivos e pastas sem permissão de acesso</td>
                            <td>ErrosPermissao.csv</td>
                        </tr>
                        <tr>
                            <td>Caminhos Longos</td>
                            <td>$(Format-Number -Value $ErrosCaminhosLongos -NoDecimal)</td>
                            <td>Caminhos que excedem 240 caracteres</td>
                            <td>CaminhosMuitoLongos.csv</td>
                        </tr>
                        <tr>
                            <td>Arquivos Não Encontrados</td>
                            <td>$(Format-Number -Value $ErrosArquivosNaoEncontrados -NoDecimal)</td>
                            <td>Arquivos que não puderam ser acessados</td>
                            <td>OutrosErros.csv</td>
                        </tr>
                        <tr>
                            <td>Outros Erros</td>
                            <td>$(Format-Number -Value $ErrosOutros -NoDecimal)</td>
                            <td>Demais problemas encontrados</td>
                            <td>OutrosErros.csv</td>
                        </tr>
                        <tr class="highlight-row">
                            <td><strong>Total</strong></td>
                            <td><strong>$(Format-Number -Value $TotalErros -NoDecimal)</strong></td>
                            <td>Todos os erros registrados</td>
                            <td>ResumoErros.txt</td>
                        </tr>
                    </tbody>
                </table>
                
                <h4 class="mt-3">Recomendações para Resolução:</h4>
                <ul style="margin-left: 20px; margin-top: 10px;">
                    <li><strong>Erros de Permissão:</strong> Verificar configurações de segurança e ACLs</li>
                    <li><strong>Caminhos Longos:</strong> Renomear arquivos/pastas para encurtar caminhos</li>
                    <li><strong>Ferramentas:</strong> Considerar robocopy ou PowerShell com parâmetro -LiteralPath para caminhos longos</li>
                    <li><strong>Execução como Administrador:</strong> Executar o script com privilégios elevados para reduzir erros de permissão</li>
                </ul>
                
                <div class="callout action mt-3">
                    <h4>Próximos Passos</h4>
                    <p>Consulte os arquivos CSV gerados para obter uma lista detalhada dos caminhos problemáticos. Use essas informações para solicitar permissões ou ajustar a estrutura de pastas conforme necessário.</p>
                </div>
            </div>
        </div>
        
        <div class="section animate-fade-up" id="recommendations">
            <div class="section-header">
                <h2><i class="fas fa-lightbulb"></i> Recomendações de Limpeza</h2>
            </div>
            
            <div class="collapsible-card">
                <button class="collapsible">
                    1. Remoção de Arquivos Duplicados
                    <span class="priority-tag priority-high">Prioridade Alta</span>
                    <i class="fas fa-chevron-down"></i>
                </button>
                <div class="content">
                    <div class="content-inner">
                        <p><strong>Espaço total recuperável:</strong> <span class="highlight-number">$(Format-Number -Value $EspacoDuplicados -DecimalPlaces 2) GB</span></p>
                        <p><strong>Grupos de arquivos:</strong> $(Format-Number -Value ($DadosDuplicados | Group-Object -Property GroupID).Count -NoDecimal)</p>
                        
                        <div class="impact-bar">
                            <div class="impact-label">
                                <span class="impact-label-text">Contribuição para recuperação total</span>
                                <span class="impact-percentage">$(Format-Number -Value $PercentualContribuicaoDuplicados -DecimalPlaces 1)%</span>
                            </div>
                            <div class="impact-bar-container">
                                <div class="impact-bar-fill" style="width: $(Format-Number -Value $PercentualContribuicaoDuplicados -DecimalPlaces 1)%;"></div>
                            </div>
                        </div>
                        
                        <div class="effort-indicator">
                            <span class="effort-indicator-label">Nível de esforço:</span>
                            <div class="effort-dots">
                                <div class="effort-dot active"></div>
                                <div class="effort-dot active"></div>
                                <div class="effort-dot"></div>
                            </div>
                            <span style="font-size: 0.75rem; margin-left: 8px; color: var(--gray-300);">Médio</span>
                        </div>
                        
                        <div class="callout action" style="margin: 15px 0 10px 0;">
                            <h4>Potencial de Economia Rápida</h4>
                            <p>Esta ação oferece um ganho imediato e pode ser implementada com impacto mínimo nas operações diárias.</p>
                        </div>
                        
                        <p class="mt-2"><strong>Ação recomendada:</strong> Para cada grupo de arquivos duplicados, manter apenas uma cópia (preferencialmente a original) e remover as demais após confirmação.</p>
                        <p><strong>Relatório detalhado:</strong> <a href="#" target="_blank">ArquivosDuplicados.csv</a></p>
                        
                        <div class="chip-container">
                            <div class="chip"><i class="fas fa-file-alt"></i> Relatório</div>
                            <div class="chip"><i class="fas fa-trash-alt"></i> Remoção</div>
                            <div class="chip"><i class="fas fa-check-circle"></i> Validação</div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="collapsible-card">
                <button class="collapsible">
                    2. Arquivos Temporários e Logs
                    <span class="priority-tag priority-medium">Prioridade Média</span>
                    <i class="fas fa-chevron-down"></i>
                </button>
                <div class="content">
                    <div class="content-inner">
                        <p><strong>Potencial de recuperação:</strong> <span class="highlight-number">$(Format-Number -Value $EspacoTemporarios -DecimalPlaces 2) GB</span></p>
                        <p><strong>Tipos de arquivos:</strong> .tmp, .temp, .log, .bak, etc.</p>
                        
                        <div class="impact-bar">
                            <div class="impact-label">
                                <span class="impact-label-text">Contribuição para recuperação total</span>
                                <span class="impact-percentage">$(Format-Number -Value $PercentualContribuicaoTemporarios -DecimalPlaces 1)%</span>
                            </div>
                            <div class="impact-bar-container">
                                <div class="impact-bar-fill" style="width: $(Format-Number -Value $PercentualContribuicaoTemporarios -DecimalPlaces 1)%;"></div>
                            </div>
                        </div>
                        
                        <div class="effort-indicator">
                            <span class="effort-indicator-label">Nível de esforço:</span>
                            <div class="effort-dots">
                                <div class="effort-dot active"></div>
                                <div class="effort-dot"></div>
                                <div class="effort-dot"></div>
                            </div>
                            <span style="font-size: 0.75rem; margin-left: 8px; color: var(--gray-300);">Baixo</span>
                        </div>
                        
                        <div class="callout action" style="margin: 15px 0 10px 0;">
                            <h4>Limpeza de Manutenção</h4>
                            <p>Esta ação contribui para a saúde do sistema e pode ser automatizada para execução periódica.</p>
                        </div>
                        
                        <p class="mt-2"><strong>Ação recomendada:</strong> Remover arquivos temporários e logs antigos que não são mais necessários.</p>
                        <p><strong>Relatório detalhado:</strong> <a href="#" target="_blank">ArquivosTemporarios.csv</a></p>
                        
                        <div class="chip-container">
                            <div class="chip"><i class="fas fa-file-alt"></i> Relatório</div>
                            <div class="chip"><i class="fas fa-broom"></i> Limpeza</div>
                            <div class="chip"><i class="fas fa-calendar-alt"></i> Programação</div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="collapsible-card">
                <button class="collapsible">
                    3. Arquivar ou Migrar Grandes OU Antigos (Por Prioridade)
                    <span class="priority-tag priority-high">Prioridade Alta</span>
                    <i class="fas fa-chevron-down"></i>
                </button>
                <div class="content">
                    <div class="content-inner">
                        <p><strong>Potencial de recuperação:</strong> <span class="highlight-number">$(Format-Number -Value $EspacoGrandesAntigos -DecimalPlaces 2) GB</span></p>
                        <p><strong>Quantidade:</strong> $(Format-Number -Value $DadosGrandesAntigos.Count -NoDecimal) arquivos grandes ($(Format-Number -Value $TamanhoMinimoArquivosMB -NoDecimal) MB) OU antigos ($(Format-Number -Value $DiasArquivosAntigos -NoDecimal) dias)</p>
                        
                        <div class="impact-bar">
                            <div class="impact-label">
                                <span class="impact-label-text">Contribuição para recuperação total</span>
                                <span class="impact-percentage">$(Format-Number -Value $PercentualContribuicaoGrandesAntigos -DecimalPlaces 1)%</span>
                            </div>
                            <div class="impact-bar-container">
                                <div class="impact-bar-fill" style="width: $(Format-Number -Value $PercentualContribuicaoGrandesAntigos -DecimalPlaces 1)%;"></div>
                            </div>
                        </div>
                        
                        <div class="effort-indicator">
                            <span class="effort-indicator-label">Nível de esforço:</span>
                            <div class="effort-dots">
                                <div class="effort-dot active"></div>
                                <div class="effort-dot active"></div>
                                <div class="effort-dot active"></div>
                            </div>
                            <span style="font-size: 0.75rem; margin-left: 8px; color: var(--gray-300);">Alto</span>
                        </div>
                        
                        <div class="callout action" style="margin: 15px 0 10px 0;">
                            <h4>Maior Potencial de Economia</h4>
                            <p>Esta ação representa uma parte significativa do potencial total de recuperação de espaço no servidor.</p>
                        </div>
                        
                        <p class="mt-2"><strong>Ação recomendada:</strong> Revisar arquivos grandes OU antigos. Focar primeiro em <span class="category-badge badge-critical">GRANDE + ANTIGO</span>, depois <span class="category-badge badge-high">GRANDE</span> e por último <span class="category-badge badge-medium">ANTIGO</span>.</p>
                        <p><strong>Relatório detalhado:</strong> <a href="#" target="_blank">GrandesAntigos.csv</a></p>
                        
                        <div class="chip-container">
                            <div class="chip"><i class="fas fa-file-alt"></i> Relatório</div>
                            <div class="chip"><i class="fas fa-external-link-alt"></i> Migração</div>
                            <div class="chip"><i class="fas fa-archive"></i> Arquivamento</div>
                            <div class="chip"><i class="fas fa-sort-amount-down"></i> Ordenado</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="section animate-fade-up" id="actions">
            <div class="section-header">
                <h2><i class="fas fa-play-circle"></i> Plano de Ação</h2>
            </div>
            
            <div class="action-item critical">
                <h3><i class="fas fa-copy"></i> 1. Remover Arquivos Duplicados</h3>
                <p>Revisar o arquivo "ArquivosDuplicados.csv" para identificar e remover arquivos duplicados seguros. Manter apenas uma cópia de cada grupo de arquivos, preferencialmente a original.</p>
                
                <div class="impact-bar mt-2">
                    <div class="impact-label">
                        <span class="impact-label-text">Impacto na economia total</span>
                        <span class="impact-percentage">$(Format-Number -Value $PercentualContribuicaoDuplicados -DecimalPlaces 1)%</span>
                    </div>
                    <div class="impact-bar-container">
                        <div class="impact-bar-fill" style="width: $(Format-Number -Value $PercentualContribuicaoDuplicados -DecimalPlaces 1)%;"></div>
                    </div>
                </div>
            </div>
            
            <div class="action-item warning">
                <h3><i class="fas fa-broom"></i> 2. Limpar Arquivos Temporários</h3>
                <p>Limpar arquivos temporários (.tmp, .log, .bak) que não são mais necessários. Pode-se usar o arquivo "ArquivosTemporarios.csv" para identificação específica.</p>
                
                <div class="impact-bar mt-2">
                    <div class="impact-label">
                        <span class="impact-label-text">Impacto na economia total</span>
                        <span class="impact-percentage">$(Format-Number -Value $PercentualContribuicaoTemporarios -DecimalPlaces 1)%</span>
                    </div>
                    <div class="impact-bar-container">
                        <div class="impact-bar-fill" style="width: $(Format-Number -Value $PercentualContribuicaoTemporarios -DecimalPlaces 1)%;"></div>
                    </div>
                </div>
            </div>
            
            <div class="action-item info">
                <h3><i class="fas fa-archive"></i> 3. Arquivar ou Migrar Grandes OU Antigos (Por Prioridade)</h3>
                <p>Revisar os arquivos grandes OU antigos identificados no relatório. Focar primeiro em <span class="category-badge badge-critical">GRANDE + ANTIGO</span>, depois <span class="category-badge badge-high">GRANDE</span> e por último <span class="category-badge badge-medium">ANTIGO</span>.</p>
                
                <div class="impact-bar mt-2">
                    <div class="impact-label">
                        <span class="impact-label-text">Impacto na economia total</span>
                        <span class="impact-percentage">$(Format-Number -Value $PercentualContribuicaoGrandesAntigos -DecimalPlaces 1)%</span>
                    </div>
                    <div class="impact-bar-container">
                        <div class="impact-bar-fill" style="width: $(Format-Number -Value $PercentualContribuicaoGrandesAntigos -DecimalPlaces 1)%;"></div>
                    </div>
                </div>
            </div>
            
            <div class="action-item info">
                <h3><i class="fas fa-cogs"></i> 4. Implementar Política de Armazenamento</h3>
                <p>Estabelecer políticas de uso de espaço em disco, incluindo limites para tipos de arquivos, cotas de usuário e limpeza periódica de arquivos temporários e antigos.</p>
                
                <div class="effort-indicator">
                    <span class="effort-indicator-label">Nível de esforço:</span>
                    <div class="effort-dots">
                        <div class="effort-dot active"></div>
                        <div class="effort-dot active"></div>
                        <div class="effort-dot active"></div>
                    </div>
                    <span style="font-size: 0.75rem; margin-left: 8px; color: var(--gray-300);">Alto</span>
                </div>
            </div>
            
            <div class="action-item warning">
                <h3><i class="fas fa-shield-alt"></i> 5. Resolver Problemas de Acesso v2.3</h3>
                <p>Verificar e corrigir os $(Format-Number -Value $TotalErros -NoDecimal) erros de acesso encontrados durante a análise. Consulte os arquivos CSV gerados para obter listas detalhadas de caminhos problemáticos.</p>
                
                <div class="effort-indicator">
                    <span class="effort-indicator-label">Nível de esforço:</span>
                    <div class="effort-dots">
                        <div class="effort-dot active"></div>
                        <div class="effort-dot active"></div>
                        <div class="effort-dot"></div>
                    </div>
                    <span style="font-size: 0.75rem; margin-left: 8px; color: var(--gray-300);">Médio</span>
                </div>
            </div>
        </div>
    </div>
    
    <footer>
        <div class="container">
            <div>
                <p>&copy; 2025 Relatório de Sanitização do File Server - Gerado em $DataRelatorio</p>
            </div>
            <div>
                <p>Desenvolvido por Mathews Buzetti - Versão 2.3</p>
            </div>
        </div>
    </footer>
    
    <div class="scroll-top" onclick="scrollToTop()">
        <i class="fas fa-arrow-up"></i>
    </div>
    
    <script>
        function openTab(evt, tabName) {
            var i, tabcontent, tablinks;
            
            tabcontent = document.getElementsByClassName("tab-content");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].className = tabcontent[i].className.replace(" active", "");
            }
            
            tablinks = document.getElementsByClassName("tab");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }
            
            document.getElementById(tabName).className += " active";
            evt.currentTarget.className += " active";
        }
        
        var coll = document.getElementsByClassName("collapsible");
        
        for (var i = 0; i < coll.length; i++) {
            coll[i].addEventListener("click", function() {
                this.classList.toggle("active");
                var content = this.nextElementSibling;
                
                if (content.style.maxHeight) {
                    content.style.maxHeight = null;
                } else {
                    content.style.maxHeight = content.scrollHeight + "px";
                }
            });
        }
        
        window.onscroll = function() {scrollFunction()};
        
        function scrollFunction() {
            var scrollBtn = document.querySelector(".scroll-top");
            if (document.body.scrollTop > 300 || document.documentElement.scrollTop > 300) {
                scrollBtn.classList.add("active");
            } else {
                scrollBtn.classList.remove("active");
            }
        }
        
        function scrollToTop() {
            window.scrollTo({ top: 0, behavior: "smooth" });
        }
        
        document.addEventListener("DOMContentLoaded", function() {
            var animateElements = document.querySelectorAll(".animate-fade-up");
            
            function checkIfInView() {
                var windowHeight = window.innerHeight;
                var windowTopPosition = window.scrollY;
                var windowBottomPosition = windowTopPosition + windowHeight;
                
                animateElements.forEach(function(element) {
                    var elementHeight = element.offsetHeight;
                    var elementTopPosition = element.offsetTop;
                    var elementBottomPosition = elementTopPosition + elementHeight;
                    
                    if (elementBottomPosition >= windowTopPosition && elementTopPosition <= windowBottomPosition) {
                        element.classList.add("animated");
                    }
                });
            }
            
            window.addEventListener("scroll", checkIfInView);
            window.addEventListener("resize", checkIfInView);
            
            checkIfInView();
            initCountAnimations();
        });
        
        function initCountAnimations() {
            const countElements = document.querySelectorAll('.count-animation');
            
            countElements.forEach(el => {
                const targetValue = parseFloat(el.getAttribute('data-count'));
                const suffix = el.getAttribute('data-suffix') || '';
                const duration = 2000;
                const framesPerSecond = 60;
                const totalFrames = duration / 1000 * framesPerSecond;
                const increment = targetValue / totalFrames;
                
                let currentValue = 0;
                let currentFrame = 0;
                
                const counter = setInterval(() => {
                    currentFrame++;
                    currentValue += increment;
                    
                    if (currentValue >= targetValue) {
                        el.textContent = targetValue.toLocaleString('en-US', {
                            minimumFractionDigits: 2,
                            maximumFractionDigits: 2
                        }) + suffix;
                        clearInterval(counter);
                    } else {
                        el.textContent = currentValue.toLocaleString('en-US', {
                            minimumFractionDigits: 2,
                            maximumFractionDigits: 2
                        }) + suffix;
                    }
                }, 1000 / framesPerSecond);
            });
        }
    </script>
</body>
</html>
"@

    $HTML | Out-File -FilePath $HTMLPath -Encoding utf8
    
    Write-Host "Relatório HTML v2.3 gerado em: $HTMLPath" -ForegroundColor Green
    
    return $HTMLPath
}

function Analisar-PotencialLimpeza {
    param (
        [string]$Caminho = "C:\",
        [int]$TamanhoMinimoMB = $TamanhoMinimoArquivosMB,
        [int]$DiasAntigos = $DiasArquivosAntigos
    )
    
    # Reset error counters
    $Global:ErrosEncontrados.Contadores.TotalErros = 0
    $Global:ErrosEncontrados.Contadores.SemPermissao = 0
    $Global:ErrosEncontrados.Contadores.CaminhosLongos = 0
    $Global:ErrosEncontrados.Contadores.ArquivosNaoEncontrados = 0
    $Global:ErrosEncontrados.Contadores.OutrosErros = 0
    $Global:ErrosEncontrados.SemPermissao.Clear()
    $Global:ErrosEncontrados.CaminhosLongos.Clear()
    $Global:ErrosEncontrados.ArquivosNaoEncontrados.Clear()
    $Global:ErrosEncontrados.OutrosErros.Clear()
    
    $TempoInicial = Get-Date
    $DiretorioRelatorios = Criar-DiretorioRelatorios
    
    Clear-Host
    
    Criar-BarraCompleta -Texto "SANITIZAÇÃO DE FILE SERVER v2.3 - 100% READ-ONLY" -Cor Blue
    
    Write-Host "`n📂 Caminho:" -NoNewline -ForegroundColor Gray
    Write-Host " $Caminho" -ForegroundColor Yellow

    Write-Host "📊 Relatórios:" -NoNewline -ForegroundColor Gray
    Write-Host " $DiretorioRelatorios" -ForegroundColor Yellow

    Write-Host "📏 Grandes OU antigos:" -NoNewline -ForegroundColor Gray
    Write-Host " Maiores que $TamanhoMinimoMB MB OU mais antigos que $DiasAntigos dias" -ForegroundColor Yellow
    
    Write-Host "🔒 Segurança:" -NoNewline -ForegroundColor Gray
    Write-Host " Script 100% read-only - NUNCA remove arquivos" -ForegroundColor Green
    
    Write-Host "✅ Matemática:" -NoNewline -ForegroundColor Gray
    Write-Host " Cálculos corrigidos - sem arredondamento duplo" -ForegroundColor Green
    
    Write-Host "⚠️  Esta análise pode levar várias horas em um servidor de arquivos de 30TB`n" -ForegroundColor DarkYellow
    
    $saidaTipos = Join-Path -Path $DiretorioRelatorios -ChildPath "DistribuicaoTipos.csv"
    $saidaGrandesAntigos = Join-Path -Path $DiretorioRelatorios -ChildPath "GrandesAntigos.csv"
    $saidaDuplicados = Join-Path -Path $DiretorioRelatorios -ChildPath "ArquivosDuplicados.csv"
    $saidaTemporarios = Join-Path -Path $DiretorioRelatorios -ChildPath "ArquivosTemporarios.csv"
    
    $InfoDisco = Obter-EspacoDisco -Caminho $Caminho
    $InfoDeduplicacao = Detectar-WindowsDeduplication -Caminho $Caminho
    
    if ($null -eq $InfoDisco) {
        $InfoDisco = @{
            "EspacoTotal" = 0; "EspacoUsado" = 0; "EspacoLivre" = 0
            "EspacoTotalGB" = 0; "EspacoUsadoGB" = 0; "EspacoLivreGB" = 0; "Estimado" = $true
        }
    }
    
    # Etapa 1: Distribuição de tipos
    Write-Progress -Activity "Sanitização File Server v2.3 - Etapa 1/4" -Status "Analisando distribuição de arquivos..." -PercentComplete 25
    
    $tiposArquivo = Analisar-TiposArquivo -Caminho $Caminho -SaidaCSV $saidaTipos
    
    Write-Progress -Activity "Sanitização File Server v2.3 - Etapa 1/4" -Status "Analisando distribuição de arquivos..." -PercentComplete 25 -Completed
    
    # Etapa 2: Arquivos duplicados (PRIMEIRO para evitar contagem dupla)
    Write-Progress -Activity "Sanitização File Server v2.3 - Etapa 2/4" -Status "Localizando arquivos duplicados..." -PercentComplete 50
    
    $DiretorioTrabalho = Join-Path -Path $DiretorioRelatorios -ChildPath "Temp"
    
    $ConfigOriginalMostrarLogConsole = $Global:ConfigGlobal.MostrarLogConsole
    $Global:ConfigGlobal.MostrarLogConsole = $false
    
    $arquivosDuplicados = Encontrar-ArquivosDuplicados -Caminho $Caminho -TamanhoMinimoMB $TamanhoMinimoArquivosDuplicadosMB -SaidaCSV $saidaDuplicados -DiretorioTrabalho $DiretorioTrabalho -TopGruposMaiores $TopGruposDuplicados
    
    $Global:ConfigGlobal.MostrarLogConsole = $ConfigOriginalMostrarLogConsole
    
    Write-Progress -Activity "Sanitização File Server v2.3 - Etapa 2/4" -Status "Localizando arquivos duplicados..." -PercentComplete 50 -Completed
    
    # Etapa 3: Grandes OU Antigos (SEGUNDO - com exclusão automática de duplicados removíveis)
    Write-Progress -Activity "Sanitização File Server v2.3 - Etapa 3/4" -Status "Localizando grandes OU antigos ($TamanhoMinimoMB MB OU $DiasAntigos dias)..." -PercentComplete 75
    
    $arquivosGrandesAntigos = Encontrar-ArquivosGrandesAntigos -Caminho $Caminho -TamanhoMinimoMB $TamanhoMinimoMB -DiasAntigos $DiasAntigos -Top $TopArquivosGrandesAntigos -SaidaCSV $saidaGrandesAntigos -DuplicadosParaExcluir $arquivosDuplicados
    
    Write-Progress -Activity "Sanitização File Server v2.3 - Etapa 3/4" -Status "Localizando grandes OU antigos ($TamanhoMinimoMB MB OU $DiasAntigos dias)..." -PercentComplete 75 -Completed
    
    # Etapa 4: Arquivos temporários detalhados
    $ExtensoesDesnecessarias = @(
        ".tmp", ".temp", ".bak", ".old", ".dmp", ".chk", ".log", ".etl", ".part", ".crdownload",
        ".download", "~*", ".cache", ".wbk", ".gid", ".prv", ".laccdb", ".fbk", ".thumbs.db", 
        ".ds_store", "desktop.ini", ".fuse_hidden*", ".nfs*", ".swp", ".swo", ".tmp.*", ".bak.*", 
        ".backup", ".autosave", ".recover", ".~lock*", ".dropbox.cache"
    )
    
    $ArquivosTemporarios = Encontrar-ArquivosTemporariosDetalhados -Caminho $Caminho -SaidaCSV $saidaTemporarios -ExtensoesDesnecessarias $ExtensoesDesnecessarias
    
    # CORREÇÃO: Calcular potencial real com função corrigida
    $PotencialReal = Calcular-PotencialRecuperacaoReal -DadosGrandesAntigos $arquivosGrandesAntigos -DadosDuplicados $arquivosDuplicados -DadosTemporarios $ArquivosTemporarios -InfoDeduplicacao $InfoDeduplicacao
    
    # CORREÇÃO: Usar valores corretos em GB
    $TotalRecuperavelGB = $PotencialReal.TotalReal
    $EspacoUsadoGB = $InfoDisco.EspacoUsadoGB
    $PercentualRecuperavel = Calcular-PercentualReal -EspacoRecuperavelGB $TotalRecuperavelGB -EspacoUsadoGB $EspacoUsadoGB
    
    # Gerar relatórios de erro
    Gerar-RelatoriosErro -DiretorioSaida $DiretorioRelatorios
    
    # Gerar relatório HTML
    Write-Progress -Activity "Sanitização File Server v2.3 - Etapa 4/4" -Status "Gerando relatório HTML..." -PercentComplete 100
    
    $CaminhoHTML = Criar-RelatorioHTML -DiretorioRelatorios $DiretorioRelatorios -Caminho $Caminho -DadosTipos $tiposArquivo -DadosGrandesAntigos $arquivosGrandesAntigos -DadosDuplicados $arquivosDuplicados -DadosTemporarios $ArquivosTemporarios -InfoDisco $InfoDisco -PotencialReal $PotencialReal -InfoDeduplicacao $InfoDeduplicacao -TamanhoMinimoArquivosMB $TamanhoMinimoMB -DiasArquivosAntigos $DiasArquivosAntigos
    
    Write-Progress -Activity "Sanitização File Server v2.3 - Etapa 4/4" -Status "Gerando relatório HTML..." -PercentComplete 100 -Completed
    
    # SAÍDA FINAL SIMPLIFICADA E FOCADA
    $TempoFinal = Get-Date
    $TempoDecorrido = $TempoFinal - $TempoInicial
    $TempoFormatado = "{0:mm}:{0:ss}" -f $TempoDecorrido
    
    Write-Host "`n✅ ANÁLISE CONCLUÍDA EM $TempoFormatado!" -ForegroundColor Green
    
    Write-Host "`n📊 RESULTADOS:" -ForegroundColor Yellow
    if ($PotencialReal.DeduplicacaoAtiva) {
        $TotalTB = $TotalRecuperavelGB / 1024
        Write-Host "   💽 Espaço recuperável (físico): $(Format-Number -Value $TotalTB -DecimalPlaces 2) TB ($(Format-Number -Value $PercentualRecuperavel -DecimalPlaces 1)%)" -ForegroundColor Green
        Write-Host "   🔧 Windows Deduplication ativa (Taxa: $(Format-Number -Value $PotencialReal.FatorDeduplicacao -DecimalPlaces 2)x)" -ForegroundColor Cyan
    } else {
        $TotalTB = $TotalRecuperavelGB / 1024
        Write-Host "   💽 Espaço recuperável: $(Format-Number -Value $TotalTB -DecimalPlaces 2) TB ($(Format-Number -Value $PercentualRecuperavel -DecimalPlaces 1)%)" -ForegroundColor Green
    }
    
    if ($Global:ErrosEncontrados.Contadores.TotalErros -gt 0) {
        Write-Host "   ⚠️ Erros encontrados: $(Format-Number -Value $Global:ErrosEncontrados.Contadores.TotalErros -NoDecimal) (ver relatório para detalhes)" -ForegroundColor Yellow
    } else {
        Write-Host "   ✅ Análise 100% completa sem erros" -ForegroundColor Green
    }
    
    Write-Host "`n📄 RELATÓRIOS:" -ForegroundColor Yellow
    Write-Host "   🌐 HTML: $CaminhoHTML" -ForegroundColor Cyan
    Write-Host "   📁 CSVs: $DiretorioRelatorios" -ForegroundColor Cyan
    
    if ($InfoDeduplicacao.Habilitado) {
        Write-Host "`n💡 Deduplicação: Ativa ($(Format-Number -Value $InfoDeduplicacao.EconomiaPercentual -DecimalPlaces 1)% economia atual)" -ForegroundColor Blue
    } else {
        Write-Host "`n💡 Deduplicação: Inativa (considere habilitar para 10-80% economia adicional)" -ForegroundColor Blue
    }
    
    Write-Host "`n🔒 Script 100% read-only - nenhum arquivo foi modificado" -ForegroundColor Green
    
    # Limpeza silenciosa de arquivos temporários de trabalho
    $DiretorioTemp = Join-Path -Path $DiretorioRelatorios -ChildPath "Temp"
    if (Test-Path -Path $DiretorioTemp) {
        Remove-Item -Path $DiretorioTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    return $DiretorioRelatorios
}

function Iniciar-AnaliseEspaco {
    param (
        [Parameter(Mandatory=$false)] [int]$TamanhoMinimoMB = $TamanhoMinimoArquivosMB,
        [Parameter(Mandatory=$false)] [int]$DiasAntigos = $DiasArquivosAntigos,
        [Parameter(Mandatory=$false)] [switch]$ModoDetalhado = $false
    )
    
    if ($ModoDetalhado) {
        $global:ModoSilencioso = $false
        $Global:ConfigGlobal.MostrarLogConsole = $true
    } else {
        $global:ModoSilencioso = $true
        $Global:ConfigGlobal.MostrarLogConsole = $false
    }
    
    Clear-Host
    
    try {
        Criar-BarraCompleta -Texto "SANITIZAÇÃO DE FILE SERVER v2.3 - 100% READ-ONLY" -Cor Magenta
    } catch {
        Write-Host "===== SANITIZAÇÃO DE FILE SERVER v2.3 - 100% READ-ONLY =====" -ForegroundColor Magenta
    }
    
    Write-Host "`n▶ OBJETIVO: " -NoNewline -ForegroundColor Yellow
    Write-Host "Identificar arquivos que podem ser removidos para liberar espaço"
    
    Write-Host "▶ MÉTODO: " -NoNewline -ForegroundColor Yellow
    Write-Host "Análise completa com exportação CSV e relatório visual HTML"
    
    Write-Host "▶ SEGURANÇA: " -NoNewline -ForegroundColor Yellow
    Write-Host "Script 100% READ-ONLY - NUNCA remove arquivos dos usuários"

    Write-Host "▶ VERSÃO: " -NoNewline -ForegroundColor Yellow
    Write-Host "2.3 - Critério OR com badges por impacto: grandes OU antigos"
    
    Write-Host "`n🛡️ GARANTIAS DE SEGURANÇA:" -ForegroundColor Green
    Write-Host "   ✅ NUNCA remove arquivos dos usuários" -ForegroundColor White
    Write-Host "   ✅ NUNCA modifica dados existentes" -ForegroundColor White
    Write-Host "   ✅ Apenas cria relatórios de análise" -ForegroundColor White
    Write-Host "   ✅ Script é 100% somente leitura" -ForegroundColor White
    
    Write-Host "`n🎯 NOVIDADES v2.3:" -ForegroundColor Green
    Write-Host "   🛡️ Script 100% read-only - máxima segurança" -ForegroundColor White
    Write-Host "   ✅ Grandes OU antigos com badges por impacto (interface limpa)" -ForegroundColor White
    Write-Host "   ✅ Detecção aprimorada de Windows Deduplication" -ForegroundColor White
    Write-Host "   ✅ Limpeza simplificada - apenas arquivos temporários de trabalho" -ForegroundColor White
    Write-Host "   ✅ Card dedicado para status de deduplicação" -ForegroundColor White
    Write-Host "   ✅ Análise continua mesmo com problemas de acesso" -ForegroundColor White
    
    Verificar-Requisitos
    
    Write-Host "`n📂 TIPO DE ANÁLISE:" -ForegroundColor Cyan
    Write-Host "   1. Analisar caminho local (C:\, D:\pasta, etc)" -ForegroundColor White
    Write-Host "   2. Analisar apenas caminho de rede (\\servidor\compartilhamento)" -ForegroundColor White
    $tipoAnalise = Read-Host "`n  Escolha (1 ou 2, padrão: 1)"
    
    $apenasRede = ($tipoAnalise -eq "2")
    
    if ($apenasRede) {
        Write-Host "`n🌐 Modo de análise: APENAS CAMINHOS DE REDE" -ForegroundColor Yellow
        Write-Host "`n📂 Digite o caminho de rede para analisar:" -ForegroundColor Cyan
        Write-Host "   - Formato: \\192.168.1.2\compartilhamento ou \\servidor\compartilhamento" -ForegroundColor DarkGray
        
        $caminhoValido = $false
        while (-not $caminhoValido) {
            $caminho = Read-Host "`n  Caminho de rede"
            
            if (-not ($caminho -match "^\\\\\w+")) {
                Write-Host "❌ O caminho digitado não é um caminho de rede válido." -ForegroundColor Red
                Write-Host "   O caminho deve começar com \\ (ex: \\servidor\compartilhamento)" -ForegroundColor Red
                continue
            }
            
            if (-not (Test-Path -Path $caminho)) {
                Write-Host "❌ O caminho de rede não existe ou não está acessível." -ForegroundColor Red
                Write-Host "   - NOVA v2.3: O script continuará a análise mesmo com alguns erros de acesso" -ForegroundColor Green
                $tentar = Read-Host "   Tentar novamente? (S/N, padrão: S)"
                
                if ($tentar -eq "N" -or $tentar -eq "n") {
                    Write-Host "`nOperação cancelada pelo usuário." -ForegroundColor Cyan
                    Read-Host "`nPressione Enter para sair"
                    return
                }
                continue
            }
            
            $caminhoValido = $true
        }
    } else {
        Write-Host "`n💻 Modo de análise: APENAS CAMINHOS LOCAIS" -ForegroundColor Yellow
        Write-Host "`n📂 Digite o caminho local para analisar:" -ForegroundColor Cyan
        Write-Host "   - Local: C:\ ou D:\pasta" -ForegroundColor DarkGray
        $caminho = Read-Host "`n  Caminho (padrão: C:\)"
        
        if ([string]::IsNullOrWhiteSpace($caminho)) {
            $caminho = "C:\"
        }
        
        if (-not (Test-Path -Path $caminho)) {
            Write-Host "`n❌ ERRO: O caminho não existe ou não está acessível." -ForegroundColor Red
            Write-Host "   - NOVA v2.3: O script continuará a análise mesmo com alguns erros de acesso" -ForegroundColor Green
            Read-Host "`nPressione Enter para sair"
            return
        }
    }
    
    if ($caminho -match "^\\\\\w+") {
        Write-Host "`n⚠️  AVISO: Você escolheu um caminho de rede." -ForegroundColor Yellow
        Write-Host "   A análise através da rede pode demorar mais devido a limitações de banda." -ForegroundColor Yellow
        Write-Host "   ✅ NOVA v2.3: Tratamento robusto de erros garante que a análise não trave!" -ForegroundColor Green
        $confirma = Read-Host "`n  Continuar mesmo assim? (S/N, padrão: S)"
        
        if ($confirma -eq "N" -or $confirma -eq "n") {
            Write-Host "`nOperação cancelada pelo usuário." -ForegroundColor Cyan
            Read-Host "`nPressione Enter para sair"
            return
        }
    }
    
    if (-not $TamanhoMinimoMB) {
        Write-Host "`n📏 Digite o tamanho mínimo para arquivos grandes OU antigos (em MB):" -ForegroundColor Cyan
        $tamanhoInput = Read-Host "  Tamanho (padrão: $TamanhoMinimoArquivosMB MB)"
        
        if ([string]::IsNullOrWhiteSpace($tamanhoInput)) {
            $TamanhoMinimoMB = $TamanhoMinimoArquivosMB
        } else {
            $TamanhoMinimoMB = [int]$tamanhoInput
        }
    }
    
    if (-not $DiasAntigos) {
        Write-Host "`n🕒 Digite a idade mínima para arquivos grandes OU antigos (em dias):" -ForegroundColor Cyan
        $diasInput = Read-Host "  Idade (padrão: $DiasArquivosAntigos dias)"
        
        if ([string]::IsNullOrWhiteSpace($diasInput)) {
            $DiasAntigos = $DiasArquivosAntigos
        } else {
            $DiasAntigos = [int]$diasInput
        }
    }
    
    try {
        $diretorioRelatorios = Analisar-PotencialLimpeza -Caminho $caminho -TamanhoMinimoMB $TamanhoMinimoMB -DiasAntigos $DiasAntigos
        
        Write-Host "`n✅ Script executado com sucesso!" -ForegroundColor Green
        
        if ($Global:ErrosEncontrados.Contadores.TotalErros -gt 0) {
            Write-Host "`n📊 ESTATÍSTICAS FINAIS DE ERRO:" -ForegroundColor Yellow
            Write-Host "   • Total:" -NoNewline -ForegroundColor Gray
            Write-Host " $(Format-Number -Value $Global:ErrosEncontrados.Contadores.TotalErros -NoDecimal) erros encontrados" -ForegroundColor Red
            Write-Host "   • Sem permissão:" -NoNewline -ForegroundColor Gray
            Write-Host " $(Format-Number -Value $Global:ErrosEncontrados.Contadores.SemPermissao -NoDecimal)" -ForegroundColor Red
            Write-Host "   • Caminhos longos:" -NoNewline -ForegroundColor Gray
            Write-Host " $(Format-Number -Value $Global:ErrosEncontrados.Contadores.CaminhosLongos -NoDecimal)" -ForegroundColor Yellow
            Write-Host "`n💡 Consulte o relatório HTML para recomendações de resolução!" -ForegroundColor Green
        } else {
            Write-Host "`n🎉 Análise 100% completa - nenhum erro de acesso!" -ForegroundColor Green
        }
        
        # Mensagem específica sobre deduplicação
        $InfoDeduplicacao = Detectar-WindowsDeduplication -Caminho $caminho
        if ($InfoDeduplicacao.Habilitado) {
            Write-Host "`n⚡ Windows Deduplication está ativa:" -ForegroundColor Cyan
            Write-Host "   • Taxa de compressão: $(Format-Number -Value $InfoDeduplicacao.TaxaDeduplicacao -DecimalPlaces 1)x" -ForegroundColor White
            Write-Host "   • Economia atual: $(Format-Number -Value $InfoDeduplicacao.EconomiaPercentual -DecimalPlaces 1)%" -ForegroundColor Green
            Write-Host "   • Os valores de recuperação foram ajustados para refletir o espaço físico real" -ForegroundColor White
        } else {
            Write-Host "`n💡 Windows Deduplication não está ativa:" -ForegroundColor Yellow
            Write-Host "   • Considere habilitar para obter 10-80% de economia adicional" -ForegroundColor White
            Write-Host "   • Especialmente útil para servidores de arquivos com dados duplicados" -ForegroundColor White
        }
        
        $htmlPath = Join-Path -Path $diretorioRelatorios -ChildPath "RelatorioSanitizacao.html"
        if (Test-Path -Path $htmlPath) {
            try {
                Start-Process $htmlPath
                Write-Host "`n📊 Relatório HTML v2.3:" -NoNewline -ForegroundColor Gray
                Write-Host " Aberto automaticamente!" -ForegroundColor Green
            } catch {
                Write-Host "`n📊 Relatório HTML v2.3 gerado em:" -NoNewline -ForegroundColor Gray
                Write-Host " $htmlPath" -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Host "`n❌ Ocorreu um erro durante a análise:" -ForegroundColor Red
        Write-Host "   $_" -ForegroundColor Red
        Write-Host "`n💡 v2.3:" -NoNewline -ForegroundColor Gray
        Write-Host " Mesmo com erros, alguns resultados podem ter sido gerados!" -ForegroundColor Yellow
    }
    
    Write-Host "`n" -NoNewline
    Read-Host "Pressione Enter para sair"
}

# Iniciar o script v2.3
Iniciar-AnaliseEspaco
