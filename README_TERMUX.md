# 📱 FindPort para Termux (Android)

Uma versão adaptada do **FindPort** especialmente projetada para o ambiente **Termux no Android**.

Permite auditar portas em escuta (**TCP e UDP**), detectar serviços populares do Termux/Android (como Termux OpenSSH na porta `8022`, ADB Wireless na `5555`, servidores locais Node/Python, VNC, etc.), classificar exposição de rede (Local vs Aberta), encerrar processos travados e gerenciar regras de firewall com **iptables**.

---

## 🚀 Instalação Rápida no Termux

### 1. Pré-requisitos
No terminal do Termux, instale as ferramentas necessárias executando:
```bash
pkg update && pkg install -y iproute2 procps grep gawk
```

### 2. Tornar o script executável
Se você copiou os arquivos para o seu celular ou clonou o repositório:
```bash
chmod +x findport.sh
```

### 3. (Opcional) Instalar como comando global
Para executar apenas digitando `findport` de qualquer pasta:
```bash
chmod +x install_termux.sh
./install_termux.sh
```

---

## ⚡ Como Executar

### Modo Padrão (Sem Root)
Permite auditar portas e finalizar processos iniciados pelo próprio Termux (Node.js, Python, SSH, PHP, etc.):
```bash
./findport.sh
```
*(ou apenas `findport` se executou o instalador)*

### Modo Root (Total: Firewall iptables e todos os processos)
Se o seu dispositivo Android possui **Root** (Magisk, KernelSU ou APatch):
```bash
tsu
findport
```
*ou:*
```bash
su -c "bash findport.sh"
```
> **Nota sobre o Firewall:** O bloqueio e desbloqueio de portas via `iptables` requer privilégios de Root no Linux/Android. Sem Root, você pode utilizar normalmente a auditoria, filtros e encerramento de processos do seu usuário.

---

## 🌟 Recursos Incluídos

1. **Auditoria TCP & UDP**: Coleta conexões via `ss`, `netstat`, `lsof` ou diretamente pelo `/proc/net/` do kernel.
2. **Dicionário Android/Termux**:
   - `8022`: Termux OpenSSH
   - `5555`: ADB sobre Wi-Fi
   - `5901`: Servidor VNC
   - `6000`: Termux:X11
   - `3000`, `5000`, `5173`, `8080`, `8000`: Servidores Dev (Node, Flask, Vite, Django)
   - `3306`, `5432`, `6379`, `27017`: Bancos de dados locais
3. **Proteção de Processos Críticos**: Trava de segurança para impedir o encerramento acidental de componentes vitais do Android (`init`, `zygote`, `system_server`, `surfaceflinger`, etc.).
4. **Gerenciador de Firewall (`iptables`)**:
   - Bloqueia conexões externas em portas selecionadas mantendo o processo rodando.
   - Menu dedicado **`[D]`** para desbloquear portas a qualquer momento.
5. **Busca e Filtros Interativos**:
   - `[B]` para buscar por nome ou número de porta.
   - `[F]` para alternar visualização apenas de processos seguros.
6. **Log de Auditoria (`findport_audit.log`)**: Histórico de ações de encerramento e regras de firewall com data e hora.
