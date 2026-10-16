# 🛡️ FindPort - Gerenciador Interativo de Portas e Firewall (Windows)

Script PowerShell interativo que lista e numera as portas abertas no seu Windows, identifica o processo responsável (PID, nome e caminho) e permite que você decida:
1. **Encerrar o processo** (matar o aplicativo e liberar a porta).
2. **Bloquear a porta no Firewall** (bloqueia o tráfego externo/rede **sem fechar o aplicativo**).
3. **Desbloquear portas**: Ao rodar o script novamente, ele detecta e lista no topo todas as portas que você bloqueou, permitindo desbloqueá-las a qualquer momento.

---

## 🚀 Como Executar

Abra o **PowerShell** (preferencialmente como **Administrador** para poder aplicar regras de Firewall) na pasta do projeto:

```powershell
.\find_ports.ps1
```

> **Nota:** Se você abrir em um PowerShell comum (não-administrador), o script avisa no topo e disponibiliza a opção **`[A]`** para reabrir como Administrador com apenas uma tecla.

---

## 🖥️ Como Funciona o Menu Interativo

### 1. Painel Inicial
Ao iniciar, o script exibe:
- **Painel de Portas Bloqueadas** (se houver regras criadas pelo FindPort):
  ```text
  🛡️ PORTAS ATUALMENTE BLOQUEADAS POR VOCE NO FIREWALL:
     [B1] Porta 8080 (TCP) - Regra: FindPort: Bloqueio Porta 8080 (TCP)
  ```
- **Tabela Numerada com Portas Abertas:**
  ```text
  #     | PORTA  | PROTO | PID     | PROCESSO             | PODE FECHAR?   | FIREWALL     | CATEGORIA         
  -----------------------------------------------------------------------------------------------
  [1]   | 5037   | TCP   | 20796   | adb                  | SIM            | Livre        | Aplicativo de Usu...
  [2]   | 7070   | TCP   | 3836    | AnyDesk              | SIM            | Livre        | Aplicativo de Usu...
  [3]   | 8086   | TCP   | 19776   | node                 | SIM            | Livre        | Dev / Servidor Lo...
  [4]   | 135    | TCP   | 1320    | svchost              | NUNCA          | Livre        | Sistema Critico   
  ```

### 2. Ações Disponíveis
Basta digitar:
- **`[Número da Porta]`** (ex: `3`): Abre as opções para aquela porta:
  - **`[1]` Encerrar o processo**: Finaliza o processo via `Stop-Process -Force` (com proteção contra encerramento acidental de processos críticos do Windows como `System`, `svchost`, `lsass`).
  - **`[2]` Bloquear a porta no Firewall (SEM fechar o app)**: Cria uma regra de bloqueio de entrada no Firewall do Windows. O app continua aberto, mas não recebe mais conexões.
  - **`[0]` Voltar ao menu principal**.
- **`[D]`**: Menu de **Desbloqueio** — lista todas as regras de bloqueio criadas e permite desbloquear uma porta específica ou todas de uma vez (`T`).
- **`[F]`**: Alterna o filtro entre **Mostrar todas as portas** e **Mostrar apenas seguras para fechar**.
- **`[R]`**: Atualiza e recarrega a lista de portas em tempo real.
- **`[A]`**: Reinicia o script com permissões de Administrador (se estiver em modo comum).
- **`[S]` ou `[Q]`**: Sair do script.

---

## 🔒 Segurança e Categorias

- 🟢 **SIM (Pode fechar)**: Servidores locais (Node, Python, Java, MySQL) ou apps de usuário (AnyDesk, Discord, Steam, etc.).
- 🔴 **NUNCA (Crítico)**: Processos vitais do Windows (`System`, `svchost`, `lsass`, `wininit`, etc.). O script impede o encerramento acidental.
- 🟡 **CUIDADO**: Serviços de rede ou compartilhamento do Windows.
