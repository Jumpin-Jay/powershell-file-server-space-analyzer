# 🗂️ File Server Space Analyzer - PowerShell

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Mathews_Buzetti-blue)](https://www.linkedin.com/in/mathewsbuzetti)
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=flat-square&logo=powershell&logoColor=white)
![Status](https://img.shields.io/badge/Status-Production-green?style=flat-square)
![Security](https://img.shields.io/badge/Security-100%25%20Read--Only-brightgreen?style=flat-square)

**Aplica-se a:** ✔️ Windows Server 2016/2019/2022 ✔️ File Servers ✔️ Network Shares ✔️ Local Storage

## 📋 Metadados

| Metadado | Descrição |
|----------|-----------|
| **Título** | File Server Space Analyzer - Otimização de Armazenamento |
| **Versão** | 2.3 |
| **Data** | 24/06/2025 |
| **Autor** | Mathews Buzetti |
| **Tags** | `powershell`, `file-server`, `space-analysis`, `deduplication`, `html-report`, `storage-optimization` |
| **Status** | ✅ Aprovado para ambiente de produção |

## 🔒 Garantia de Segurança

> ### ⚠️ **SCRIPT 100% READ-ONLY - MÁXIMA SEGURANÇA**
> - ✅ **NUNCA remove arquivos dos usuários**
> - ✅ **NUNCA modifica dados existentes**  
> - ✅ **Apenas cria relatórios de análise**
> - ✅ **Script é 100% somente leitura**

## 💻 Funcionalidades

### 🎯 Recursos Principais v2.3
* **Análise de Duplicados**: Detecção precisa usando hash MD5 com agrupamento inteligente
* **Grandes OU Antigos**: Critério OR com badges por impacto (Grande + Antigo > Grande > Antigo)
* **Arquivos Temporários**: Identificação e análise de arquivos desnecessários (.tmp, .bak, .log, etc)
* **Windows Deduplication**: Detecção automática e ajuste de valores para espaço físico real
* **Dashboard HTML Interativo**: Relatório visual com gráficos, métricas e recomendações
* **Tratamento Robusto de Erros**: Análise continua mesmo com problemas de acesso
* **Otimização de Performance**: Processamento em lotes para grandes volumes de dados

### 🔍 Análises Avançadas
* Cálculo preciso de potencial de recuperação sem arredondamento duplo
* Detecção de sobreposições entre categorias para evitar dupla contagem
* Suporte a caminhos de rede e locais
* Análise de eficiência da deduplicação ativa
* Exportação completa para CSV com dados detalhados

### 📈 Dashboard HTML Moderno
* **Métricas de Resumo**: Contadores com animação e indicadores visuais
* **Gráficos Interativos**: Pizza donut com breakdown por categoria
* **Visualizações**: Top 5 tipos de arquivo com gráfico de barras animado
* **Tabelas Responsivas**: Interface com abas e conteúdo colapsível
* **Badges de Prioridade**: Sistema visual de classificação por impacto
* **Modo Responsivo**: Funciona perfeitamente em desktop, tablet e mobile

## 📋 Pré-requisitos

* Windows 10/11 ou Windows Server 2016/2019/2022
* PowerShell 5.1 ou superior
* Permissões de leitura nos diretórios a serem analisados
* Espaço livre em C:\temp (ou pasta configurada) para relatórios
* Navegador moderno para visualizar o dashboard HTML (Chrome, Edge, Firefox)

## 🚀 Como Usar

### Método 1: Execução Interativa (Recomendado)

1. **Download do Script**:
   
   [![Download Script](https://img.shields.io/badge/Download%20Script-FileServerSpaceAnalyzer.ps1-blue?style=flat-square&logo=powershell)](https://github.com/mathewsbuzetti/powershell-file-server-space-analyzer/blob/main/Script/FileServerSpaceAnalyzer.ps1)

2. **Execução**:
   ```powershell
   # Abra o PowerShell como Administrador
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   .\FileServerSpaceAnalyzer.ps1
   ```

3. **Configuração Interativa**:
   - Escolha entre análise local ou de rede
   - Digite o caminho a ser analisado
   - Configure tamanhos mínimos e idade dos arquivos
   - Aguarde a análise ser concluída

### Método 2: Parâmetros Diretos

```powershell
# Análise de servidor local
.\FileServerSpaceAnalyzer.ps1 -TamanhoMinimoMB 1000 -DiasAntigos 180

# Análise detalhada com logs verbosos
.\FileServerSpaceAnalyzer.ps1 -ModoDetalhado
```

### 🎛️ Parâmetros Configuráveis

```powershell
# Configurações principais (edite no início do script)
$TamanhoMinimoArquivosMB = 500          # Tamanho mínimo para "grandes"
$DiasArquivosAntigos = 90               # Idade mínima para "antigos"
$TopArquivosGrandesAntigos = 1000       # Quantidade máxima a analisar
$TamanhoMinimoArquivosDuplicadosMB = 50 # Tamanho mínimo para duplicados
$TopGruposDuplicados = 2000             # Top grupos de duplicados
$ModoSilencioso = $true                 # Reduz verbosidade
```

## 📊 Resultados e Relatórios

### Dashboard HTML Interativo
O relatório principal é um dashboard HTML moderno que inclui:

1. **Hero Section**: Métricas principais com animações
2. **Cards de Resumo**: Estatísticas visuais por categoria
3. **Gráficos**: 
   - Pizza donut para composição da recuperação
   - Barras para top 5 tipos de arquivo
4. **Seções Detalhadas**:
   - Visão geral com progress bars
   - Abas para tipos, duplicados, grandes/antigos
   - Seção de erros v2.3 com estatísticas
5. **Recomendações**: Plano de ação priorizado
6. **Design Responsivo**: Funciona em qualquer dispositivo

### Arquivos Gerados
```
C:\temp\AnaliseFileServer_YYYY-MM-DD_HHMMSS\
├── RelatorioSanitizacao.html           # Dashboard principal
├── DistribuicaoTipos.csv               # Análise por tipo de arquivo
├── ArquivosDuplicados.csv              # Lista completa de duplicados
├── GrandesAntigos.csv                  # Arquivos grandes OU antigos
├── ArquivosTemporarios.csv             # Arquivos temporários encontrados
├── ErrosPermissao.csv                  # Erros de acesso (se houver)
├── CaminhosMuitoLongos.csv             # Caminhos problemáticos
└── ResumoErros.txt                     # Resumo de problemas encontrados
```

## 🔧 Configurações Avançadas

### Performance e Otimização
```powershell
# Para servidores grandes (>10TB)
$MaxErrosPorTipo = 100                  # Aumentar limite de erros
$TopGruposDuplicados = 5000             # Mais grupos de duplicados

# Para análise rápida
$TamanhoMinimoArquivosMB = 1000         # Focar apenas em arquivos muito grandes
$TopArquivosGrandesAntigos = 500        # Reduzir quantidade analisada
```

### Tratamento de Erros
O script v2.3 inclui tratamento robusto para:
- ❌ Erros de permissão de acesso
- 📏 Caminhos muito longos (>240 caracteres)
- 🔒 Arquivos e pastas protegidos pelo sistema
- 🌐 Problemas de conectividade de rede
- 💾 Limitações de memória em análises grandes

## 💡 Windows Deduplication

### Detecção Automática
O script detecta automaticamente se a Windows Deduplication está ativa e ajusta os cálculos:

- **Taxa de Compressão**: Mostra a eficiência atual
- **Valores Ajustados**: Espaço físico real que será liberado
- **Recomendações**: Sugere habilitação se não estiver ativa

### Benefícios da Deduplication
- 10-80% de economia de espaço adicional
- Especialmente eficaz em servidores com dados duplicados
- Redução do backup e replicação

## 📈 Interpretando os Resultados

### Priorização por Impacto
1. **🔴 Crítico**: Arquivos Grande + Antigo (máximo impacto)
2. **🟠 Alto**: Arquivos apenas Grandes (impacto significativo)
3. **🟡 Médio**: Arquivos apenas Antigos (menor impacto)
4. **🔵 Info**: Duplicados e temporários (fácil limpeza)

### Métricas Importantes
- **Potencial de Recuperação**: Espaço total que pode ser liberado
- **Percentual do Disco**: Quanto representa do espaço usado
- **Sobreposições**: Arquivos contados em múltiplas categorias
- **Deduplicação**: Economia adicional disponível

## 🛡️ Segurança e Boas Práticas

### Antes da Execução
1. ✅ Execute em horário de baixo uso do servidor
2. ✅ Tenha backup atualizado dos dados críticos
3. ✅ Teste em ambiente de desenvolvimento primeiro
4. ✅ Verifique espaço livre para relatórios

### Durante a Análise
- O script é 100% read-only - não modifica arquivos
- Performance pode ser impactada temporariamente
- Monitorar logs para identificar problemas de acesso

### Após a Análise
1. 📋 Revisar relatório HTML antes de qualquer ação
2. 🔍 Validar arquivos duplicados antes da remoção
3. 📁 Confirmar que arquivos "antigos" podem ser arquivados
4. 💾 Considerar backup antes de limpeza massiva

## 🚨 Limitações e Considerações

### Performance
- Análise de servidores grandes (>30TB) pode levar várias horas
- Uso intensivo de CPU durante cálculo de hashes MD5
- Impacto temporário na performance de rede/disco

### Precisão
- Hashes MD5 têm probabilidade mínima de colisão
- Arquivos em uso podem não ser detectados corretamente
- Permissões insuficientes podem limitar a análise

### Compatibilidade
- Testado no Windows Server 2016/2019/2022
- Requer PowerShell 5.1+ para funcionalidades completas
- Alguns recursos podem variar entre versões do Windows

## 🔄 Versionamento

### Versão 2.3 (Atual)
- ✅ Script 100% read-only com máxima segurança
- ✅ Critério OR para grandes OU antigos com badges por impacto
- ✅ Detecção aprimorada de Windows Deduplication
- ✅ Dashboard HTML com design moderno e responsivo
- ✅ Tratamento robusto de erros v2.3
- ✅ Cálculos matemáticos corrigidos sem arredondamento duplo
- ✅ Sistema de badges visuais para classificação de prioridade

### Roadmap Futuro
- 🔜 Suporte a múltiplos servidores em paralelo
- 🔜 Integração com APIs de monitoramento
- 🔜 Relatórios programados e automatizados
- 🔜 Dashboard web em tempo real

---

## 📞 Suporte e Contato

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Mathews_Buzetti-blue)](https://www.linkedin.com/in/mathewsbuzetti)

Para dúvidas, sugestões ou relato de problemas:
- 📧 Entre em contato via LinkedIn
- 🐛 Abra uma issue no GitHub
- 💡 Contribuições são bem-vindas via Pull Request

---

**⚡ Desenvolvido por Mathews Buzetti - Especialista em Infraestrutura e Automação**

*Copyright © 2025 - Licenciado sob MIT com restrições adicionais*
