<#
.SYNOPSIS
    Gerenciador Interativo de Portas e Firewall para Windows
.DESCRIPTION
    Lista e numera portas abertas, permite encerrar processos ou bloquear portas
    no Firewall sem fechar o aplicativo, e permite restaurar/desbloquear portas
    previamente bloqueadas.
#>

[CmdletBinding()]
param(
    [switch]$ApenasSeguras
)

try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch {}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Processos do Windows que nunca devem ser encerrados
$Script:ProcessosCriticos = @(
    "System", "Idle", "Registry", "smss", "csrss", "wininit", 
    "services", "lsass", "svchost", "fontdrvhost", "winlogon", "spoolsv"
)

# Portas comuns de dev/servidores
$Script:PortasComunsDevOuApps = @(
    3000, 3001, 4200, 5000, 5173, 8000, 8080, 8081, 8086, 8888, 9000, 9200, 27017, 3306, 5432, 6379
)

function Obter-RegrasBloqueadas {
    $regras = @()
    try {
        $fwRules = Get-NetFirewallRule -Name "FindPort_Block_*" -ErrorAction SilentlyContinue
        foreach ($r in $fwRules) {
            $portFilter = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            $portaNum = if ($portFilter.LocalPort) { $portFilter.LocalPort } else { "N/A" }
            $proto = if ($portFilter.Protocol) { $portFilter.Protocol } else { "TCP" }
            $regras += [PSCustomObject]@{
                RuleName    = $r.Name
                DisplayName = $r.DisplayName
                Porta       = $portaNum
                Protocolo   = $proto
                Descricao   = $r.Description
                Enabled     = $r.Enabled
            }
        }
    } catch {}
    return $regras
}

function Obter-PortasAbertas {
    param([bool]$FiltrarSeguras = $false)

    $regrasBloqueadas = Obter-RegrasBloqueadas
    $portasBloqueadasSet = @{}
    foreach ($rb in $regrasBloqueadas) {
        if ($rb.Porta -ne "N/A") {
            $portasBloqueadasSet["$($rb.Protocolo)_$($rb.Porta)"] = $true
        }
    }

    try {
        $tcpConns = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
    } catch {
        $tcpConns = @()
    }

    $todosPids = $tcpConns.OwningProcess | Select-Object -Unique
    $tabelaProcessos = @{}

    foreach ($pidItem in $todosPids) {
        if ($pidItem -eq 0) {
            $tabelaProcessos[$pidItem] = [PSCustomObject]@{
                ProcessName = "System Idle"
                Path        = "Kernel/Sistema"
            }
            continue
        }
        try {
            $proc = Get-Process -Id $pidItem -ErrorAction Stop
            $caminho = try { $proc.Path } catch { "Elevacao necessaria" }
            $tabelaProcessos[$pidItem] = [PSCustomObject]@{
                ProcessName = $proc.ProcessName
                Path        = if ($caminho) { $caminho } else { "N/A" }
            }
        } catch {
            $tabelaProcessos[$pidItem] = [PSCustomObject]@{
                ProcessName = "Desconhecido"
                Path        = "N/A"
            }
        }
    }

    $lista = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($conn in $tcpConns) {
        $pidNum = $conn.OwningProcess
        $procInfo = $tabelaProcessos[$pidNum]
        $procName = if ($procInfo) { $procInfo.ProcessName } else { "PID: $pidNum" }
        $procPath = if ($procInfo) { $procInfo.Path } else { "N/A" }
        $porta = [int]$conn.LocalPort
        $endereco = $conn.LocalAddress

        $podeFechar = "Nao"
        $categoria = "Outro"
        $motivo = ""

        if ($pidNum -eq 4 -or $Script:ProcessosCriticos -contains $procName) {
            $categoria = "Sistema Critico"
            $podeFechar = "NUNCA"
            $motivo = "Processo essencial do Windows"
        }
        elseif ($procName -like "*node*" -or $procName -like "*python*" -or $procName -like "*java*" -or $procName -like "*mysqld*" -or $procName -like "*postgres*" -or $Script:PortasComunsDevOuApps -contains $porta) {
            $categoria = "Dev / Servidor Local"
            $podeFechar = "SIM"
            $motivo = "Servidor local ou ferramenta de desenvolvimento"
        }
        elseif ($procName -like "*steam*" -or $procName -like "*discord*" -or $procName -like "*spotify*" -or $procName -like "*torrent*" -or $procName -like "*anydesk*" -or $procName -like "*adb*" -or $procName -like "*Code*") {
            $categoria = "Aplicativo de Usuario"
            $podeFechar = "SIM"
            $motivo = "Aplicativo em segundo plano"
        }
        elseif ($procName -eq "svchost") {
            $categoria = "Servico do Windows"
            $podeFechar = "CUIDADO"
            $motivo = "Servico de rede/compartilhamento"
        }
        else {
            $categoria = "Aplicativo / Terceiros"
            $podeFechar = "SIM (Se inativo)"
            $motivo = "Aplicativo terceiro"
        }

        $estaBloqueada = $portasBloqueadasSet.ContainsKey("TCP_$porta")
        $statusFw = if ($estaBloqueada) { "BLOQUEADA [FW]" } else { "Livre" }

        $lista.Add([PSCustomObject]@{
            Porta       = $porta
            Proto       = "TCP"
            Endereco    = $endereco
            PID         = $pidNum
            Processo    = $procName
            PodeFechar  = $podeFechar
            Firewall    = $statusFw
            Categoria   = $categoria
            Motivo      = $motivo
            Caminho     = $procPath
        })
    }

    $itens = $lista | Sort-Object Porta -Unique
    if ($FiltrarSeguras) {
        $itens = $itens | Where-Object { $_.PodeFechar -like "SIM*" }
    }

    return $itens
}

function Bloquear-PortaFirewall {
    param(
        [int]$Porta,
        [string]$Proto = "TCP",
        [string]$NomeProcesso = ""
    )

    $isAdmin = Test-IsAdmin
    if (-not $isAdmin) {
        Write-Host ""
        Write-Host "ERRO: O bloqueio de portas no Firewall exige privilegios de Administrador!" -ForegroundColor Red
        Write-Host "Abra o PowerShell como Administrador ou selecione a opcao [A] no menu principal." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        return $false
    }

    $ruleName = "FindPort_Block_${Proto}_${Porta}"
    $displayName = "FindPort: Bloqueio Porta $Porta ($Proto)"
    $desc = "Bloqueado pelo FindPort em $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss') - App: $NomeProcesso"

    try {
        # Remove regra anterior com mesmo nome caso ja exista
        Remove-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue

        New-NetFirewallRule -Name $ruleName `
                            -DisplayName $displayName `
                            -Direction Inbound `
                            -LocalPort $Porta `
                            -Protocol $Proto `
                            -Action Block `
                            -Description $desc `
                            -ErrorAction Stop | Out-Null

        Write-Host ""
        Write-Host "[OK] Porta $Porta ($Proto) bloqueada com sucesso no Firewall do Windows!" -ForegroundColor Green
        Write-Host "O aplicativo continuara rodando normalmente, mas conexoes de rede serao bloqueadas." -ForegroundColor Cyan
        Start-Sleep -Seconds 2
        return $true
    } catch {
        Write-Host "Falha ao criar regra de Firewall: $_" -ForegroundColor Red
        Start-Sleep -Seconds 2
        return $false
    }
}

function Desbloquear-PortaFirewall {
    param([string]$RuleName)

    $isAdmin = Test-IsAdmin
    if (-not $isAdmin) {
        Write-Host ""
        Write-Host "ERRO: O desbloqueio de regras no Firewall exige privilegios de Administrador!" -ForegroundColor Red
        Write-Host "Abra o PowerShell como Administrador ou use a opcao [A]." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        return $false
    }

    try {
        Remove-NetFirewallRule -Name $RuleName -ErrorAction Stop
        Write-Host ""
        Write-Host "[OK] Regra removida com sucesso! A porta foi DESBLOQUEADA." -ForegroundColor Green
        Start-Sleep -Seconds 2
        return $true
    } catch {
        Write-Host "Falha ao remover regra do Firewall: $_" -ForegroundColor Red
        Start-Sleep -Seconds 2
        return $false
    }
}

function Executar-Elevado {
    $scriptPath = $MyInvocation.MyCommand.Path
    if (-not $scriptPath) {
        $scriptPath = "$PSScriptRoot\find_ports.ps1"
    }
    Write-Host "Iniciando nova janela do PowerShell com privilegios de Administrador..." -ForegroundColor Cyan
    Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -NoExit -File `"$scriptPath`""
}

# =========================================================================
# LOOP PRINCIPAL DA INTERFACE
# =========================================================================
$filtroSegurasAtivo = $ApenasSeguras

while ($true) {
    Clear-Host
    $isAdmin = Test-IsAdmin

    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "           FINDPORT - GERENCIADOR DE PORTAS & FIREWALL (WINDOWS)               " -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    
    if ($isAdmin) {
        Write-Host "  Modo de Execucao: ADMINISTRADOR (Permissao Total: Processos & Firewall)" -ForegroundColor Green
    } else {
        Write-Host "  Modo de Execucao: USUARIO COMUM (Para Firewall, use a opcao [A] para elevar)" -ForegroundColor Yellow
    }
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor DarkGray

    # 1. Verifica e lista portas bloqueadas anteriormente
    $regrasBloqueadas = Obter-RegrasBloqueadas
    if ($regrasBloqueadas.Count -gt 0) {
        Write-Host "  🛡️  PORTAS ATUALMENTE BLOQUEADAS POR VOCE NO FIREWALL:" -ForegroundColor Magenta
        $bIndex = 1
        foreach ($rb in $regrasBloqueadas) {
            Write-Host "     [B$bIndex] Porta $($rb.Porta) ($($rb.Protocolo)) - Regra: $($rb.DisplayName) $($rb.Descricao)" -ForegroundColor Yellow
            $bIndex++
        }
        Write-Host "     (Dica: Digite 'D' para desbloquear alguma dessas portas)" -ForegroundColor DarkGray
        Write-Host "--------------------------------------------------------------------------------" -ForegroundColor DarkGray
    }

    # 2. Carrega lista de portas abertas
    Write-Host "Carregando portas em escuta..." -ForegroundColor Gray
    $portasAbertas = Obter-PortasAbertas -FiltrarSeguras $filtroSegurasAtivo

    $filtroTxt = if ($filtroSegurasAtivo) { "Apenas seguras para fechar (Filtro ATIVO)" } else { "Todas as portas abertas" }
    Write-Host "Modo de exibicao: $filtroTxt | Total listado: $($portasAbertas.Count)" -ForegroundColor White
    Write-Host ""

    # Cabeçalho da tabela numerada
    $formato = "{0,-5} | {1,-6} | {2,-5} | {3,-7} | {4,-20} | {5,-14} | {6,-12} | {7,-18}"
    Write-Host ($formato -f "#", "PORTA", "PROTO", "PID", "PROCESSO", "PODE FECHAR?", "FIREWALL", "CATEGORIA") -ForegroundColor Cyan
    Write-Host ("-" * 95) -ForegroundColor DarkGray

    $contador = 1
    $mapaIndices = @{}

    foreach ($item in $portasAbertas) {
        $mapaIndices[$contador] = $item
        
        $corLinha = "White"
        if ($item.PodeFechar -eq "NUNCA") {
            $corLinha = "DarkGray"
        } elseif ($item.Firewall -like "*BLOQUEADA*") {
            $corLinha = "Magenta"
        } elseif ($item.PodeFechar -like "SIM*") {
            $corLinha = "Green"
        }

        $numFmt = "[$contador]"
        $procTrunc = if ($item.Processo.Length -gt 19) { $item.Processo.Substring(0, 16) + "..." } else { $item.Processo }
        $catTrunc = if ($item.Categoria.Length -gt 17) { $item.Categoria.Substring(0, 14) + "..." } else { $item.Categoria }

        Write-Host ($formato -f $numFmt, $item.Porta, $item.Proto, $item.PID, $procTrunc, $item.PodeFechar, $item.Firewall, $catTrunc) -ForegroundColor $corLinha
        $contador++
    }

    Write-Host ("-" * 95) -ForegroundColor DarkGray
    Write-Host "OPCOES:" -ForegroundColor Cyan
    Write-Host "  [1-$($contador-1)] Selecionar numero da porta para gerenciar (Encerrar / Bloquear)" -ForegroundColor White
    if ($regrasBloqueadas.Count -gt 0) {
        Write-Host "  [D]     Desbloquear porta(s) bloqueada(s) no Firewall" -ForegroundColor Magenta
    }
    Write-Host "  [F]     Alternar filtro: $(if ($filtroSegurasAtivo) {'Mostrar TODAS as portas'} else {'Mostrar APENAS seguras de fechar'})" -ForegroundColor Yellow
    Write-Host "  [R]     Atualizar lista (Recarregar)" -ForegroundColor White
    if (-not $isAdmin) {
        Write-Host "  [A]     Reiniciar script como Administrador" -ForegroundColor Cyan
    }
    Write-Host "  [S/Q]   Sair" -ForegroundColor White
    Write-Host ""

    $escolha = Read-Host "Digite sua opcao"
    $escolha = $escolha.Trim()

    if ($escolha -match "^[sSqQ]$") {
        Write-Host "Encerrando FindPort. Ate logo!" -ForegroundColor Cyan
        break
    }
    elseif ($escolha -match "^[rR]$") {
        continue
    }
    elseif ($escolha -match "^[fF]$") {
        $filtroSegurasAtivo = -not $filtroSegurasAtivo
        continue
    }
    elseif ($escolha -match "^[aA]$" -and -not $isAdmin) {
        Executar-Elevado
        break
    }
    elseif ($escolha -match "^[dD]$" -or $escolha -match "^b\d+$") {
        # Menu de Desbloqueio
        Clear-Host
        Write-Host "================================================================================" -ForegroundColor Magenta
        Write-Host "                     DESBLOQUEIO DE PORTAS NO FIREWALL                          " -ForegroundColor Magenta
        Write-Host "================================================================================" -ForegroundColor Magenta
        
        $regrasBloqueadas = Obter-RegrasBloqueadas
        if ($regrasBloqueadas.Count -eq 0) {
            Write-Host "Nenhuma regra de bloqueio encontrada." -ForegroundColor Yellow
            Start-Sleep -Seconds 2
            continue
        }

        $i = 1
        foreach ($rb in $regrasBloqueadas) {
            Write-Host "  [$i] Porta $($rb.Porta) ($($rb.Protocolo)) - Nome: $($rb.DisplayName)" -ForegroundColor White
            if ($rb.Descricao) {
                Write-Host "      Obs: $($rb.Descricao)" -ForegroundColor DarkGray
            }
            $i++
        }
        Write-Host ""
        Write-Host "  [T] Desbloquear TODAS as portas listadas" -ForegroundColor Yellow
        Write-Host "  [0] Voltar ao menu principal" -ForegroundColor Gray
        Write-Host ""

        $desbEscolha = Read-Host "Escolha o numero da porta para desbloquear"
        if ($desbEscolha -eq "0" -or [string]::IsNullOrWhiteSpace($desbEscolha)) {
            continue
        }
        elseif ($desbEscolha -match "^[tT]$") {
            foreach ($rb in $regrasBloqueadas) {
                Desbloquear-PortaFirewall -RuleName $rb.RuleName
            }
        }
        elseif ($desbEscolha -as [int] -and [int]$desbEscolha -ge 1 -and [int]$desbEscolha -le $regrasBloqueadas.Count) {
            $regraSelecionada = $regrasBloqueadas[[int]$desbEscolha - 1]
            Desbloquear-PortaFirewall -RuleName $regraSelecionada.RuleName
        } else {
            Write-Host "Opcao invalida." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
        continue
    }

    # Verifica se selecionou um número da lista
    if ($escolha -as [int] -and $mapaIndices.ContainsKey([int]$escolha)) {
        $selecionado = $mapaIndices[[int]$escolha]

        Clear-Host
        Write-Host "================================================================================" -ForegroundColor Cyan
        Write-Host "               GERENCIAR PORTA $($selecionado.Porta) ($($selecionado.Proto))    " -ForegroundColor Cyan
        Write-Host "================================================================================" -ForegroundColor Cyan
        Write-Host "  Porta:       $($selecionado.Porta) ($($selecionado.Proto))" -ForegroundColor White
        Write-Host "  Endereco:    $($selecionado.Endereco)" -ForegroundColor White
        Write-Host "  Processo:    $($selecionado.Processo) (PID: $($selecionado.PID))" -ForegroundColor White
        Write-Host "  Executavel:  $($selecionado.Caminho)" -ForegroundColor DarkGray
        Write-Host "  Categoria:   $($selecionado.Categoria)" -ForegroundColor White
        Write-Host "  Pode Fechar: $($selecionado.PodeFechar) - $($selecionado.Motivo)" -ForegroundColor Yellow
        Write-Host "  Firewall:    $($selecionado.Firewall)" -ForegroundColor White
        Write-Host "--------------------------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "O QUE VOCE DESEJA FAZER?" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  [1] Encerrar o processo (Finaliza o aplicativo e libera a porta)" -ForegroundColor Red
        Write-Host "  [2] Bloquear a porta no Firewall (SEM fechar o aplicativo)" -ForegroundColor Yellow
        Write-Host "  [0] Voltar ao menu principal" -ForegroundColor Gray
        Write-Host ""

        $acao = Read-Host "Selecione a acao desejada (1, 2 ou 0)"

        if ($acao -eq "1") {
            # Encerrar Processo
            if ($selecionado.PodeFechar -eq "NUNCA") {
                Write-Host ""
                Write-Host "⚠️ BLOQUEIO DE SEGURANCA: O processo '$($selecionado.Processo)' (PID $($selecionado.PID)) e vital para o funcionamento do Windows!" -ForegroundColor Red
                Write-Host "Finaliza-lo pode travar o computador imediatamente ou causar Tela Azul." -ForegroundColor Red
                $forcar = Read-Host "Tem certeza absoluta que deseja tentar forcar? (Digite 'SIM' em maiusculo para confirmar)"
                if ($forcar -ne "SIM") {
                    Write-Host "Acao cancelada por seguranca." -ForegroundColor Green
                    Start-Sleep -Seconds 2
                    continue
                }
            } else {
                $conf = Read-Host "Confirma o encerramento de '$($selecionado.Processo)' (PID $($selecionado.PID))? (S/N)"
                if ($conf -notmatch "^[sSyY]") {
                    Write-Host "Operacao cancelada." -ForegroundColor Gray
                    Start-Sleep -Seconds 1
                    continue
                }
            }

            try {
                Stop-Process -Id $selecionado.PID -Force -ErrorAction Stop
                Write-Host ""
                Write-Host "[OK] Processo '$($selecionado.Processo)' (PID $($selecionado.PID)) finalizado com sucesso! A porta $($selecionado.Porta) foi liberada." -ForegroundColor Green
                Start-Sleep -Seconds 2
            } catch {
                Write-Host ""
                Write-Host "Falha ao finalizar processo: $_" -ForegroundColor Red
                Write-Host "Dica: Caso receba 'Acesso Negado', execute o PowerShell como Administrador." -ForegroundColor Yellow
                Start-Sleep -Seconds 3
            }
        }
        elseif ($acao -eq "2") {
            # Bloquear porta no Firewall
            Bloquear-PortaFirewall -Porta $selecionado.Porta -Proto $selecionado.Proto -NomeProcesso $selecionado.Processo
        }
        else {
            Write-Host "Voltando ao menu..." -ForegroundColor Gray
        }
    } else {
        Write-Host "Opcao invalida. Digite o numero de uma porta ou uma das letras do menu." -ForegroundColor Red
        Start-Sleep -Seconds 1
    }
}
