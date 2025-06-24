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

## 📷 Visualização do Relatório Interativo

A ferramenta gera um dashboard HTML interativo moderno que facilita a visualização e análise de problemas de espaço em servidores de arquivos. O relatório inclui gráficos avançados, métricas em tempo real e uma interface responsiva para análise completa.

<p align="center">
  <strong>👇 Clique no botão abaixo para visualizar um exemplo de dashboard de análise de espaço 👇</strong>
  <br><br>
  <a href="https://mathewsbuzetti.github.io/powershell-file-server-space-analyzer/" target="_blank">
    <img src="https://img.shields.io/badge/Acessar%20Demo-Dashboard:%20Análise%20de%20Espaço-brightgreen?style=for-the-badge&logo=html5" alt="Acessar Demo" width="400">
  </a>
  <br>
  <em>O demo mostra todas as funcionalidades do dashboard, incluindo métricas de recuperação, gráficos interativos e recomendações priorizadas</em>
</p>

![image](https://github.com/user-attachments/assets/c86feab3-850a-4bd1-95d5-7c64717da385)

![image](https://github.com/user-attachments/assets/913fc712-665b-4780-a0d4-a389958fcdcd)

![image](https://github.com/user-attachments/assets/52363165-ea22-43f2-9a65-5167f21aa8e0)

## 📋 Índice

1. [Metadados](#-metadados)
2. [Visualização do Relatório Interativo](#-visualização-do-relatório-interativo)
3. [Garantia de Segurança](#-garantia-de-segurança)
4. [Funcionalidades](#-funcionalidades)
5. [Pré-requisitos](#-pré-requisitos)
6. [Como Usar](#-como-usar)
7. [Resultados e Relatórios](#-resultados-e-relatórios)
8. [Configurações Avançadas](#-configurações-avançadas)
9. [Windows Deduplication](#-windows-deduplication)
10. [Interpretando os Resultados](#-interpretando-os-resultados)
11. [Segurança e Boas Práticas](#-segurança-e-boas-práticas)
12. [Limitações e Considerações](#-limitações-e-considerações)
13. [Versionamento](#-versionamento)
14. [Suporte e Contato](#-suporte-e-contato)

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

> [!WARNING]\
> **Requisitos de segurança e performance:**
> - Execute como administrador para máxima cobertura de análise
> - Tenha pelo menos 2GB de RAM livre para análise de servidores grandes
> - Reserve 500MB de espaço livre para geração de relatórios
> - Considere executar fora do horário comercial em servidores em produção
> - O script é 100% read-only, mas pode impactar temporariamente a performance do servidor

> [!NOTE]\
> **Compatibilidade testada:**
> - Windows Server 2016/2019/2022 (Recomendado)
> - Windows 10/11 Pro/Enterprise
> - PowerShell 5.1, 7.x
> - Compartilhamentos SMB/CIFS
> - Volumes NTFS locais e de rede

## 🚀 Como Usar

1. **Download do Script**:
   
   [![Download Script](https://img.shields.io/badge/Download%20Script-FileServerSpaceAnalyzer.ps1-blue?style=flat-square&logo=powershell)](https://github.com/mathewsbuzetti/powershell-file-server-space-analyzer/blob/main/Script/FileServerSpaceAnalyzer.ps1)

2. **Abra o script no PowerShell ISE**.

3. **Localize as linhas abaixo no início do script e altere conforme necessário**:

   ```powershell
   # Configurações principais (edite no início do script)
   $TamanhoMinimoArquivosMB = 500          # Tamanho mínimo para "grandes"
   $DiasArquivosAntigos = 90               # Idade mínima para "antigos"
   $TopArquivosGrandesAntigos = 1000       # Quantidade máxima a analisar
   $TamanhoMinimoArquivosDuplicadosMB = 50 # Tamanho mínimo para duplicados
   $TopGruposDuplicados = 2000             # Top grupos de duplicados
   $ModoSilencioso = $true                 # Reduz verbosidade
   ```

> [!WARNING]\
> **Configurações avançadas e seus impactos:**
> - **TamanhoMinimoArquivosMB**: Define o tamanho mínimo para considerar arquivos como "grandes". Valores menores (100MB) incluem mais arquivos na análise, mas aumentam significativamente o tempo de execução em servidores com muitos arquivos.
> - **DiasArquivosAntigos**: Define quantos dias para considerar arquivos como "antigos". Valores menores (30 dias) incluem mais arquivos recentes, enquanto valores maiores (180 dias) focam apenas em arquivos realmente antigos.
> - **TopArquivosGrandesAntigos**: Limita quantos arquivos grandes/antigos serão analisados. Valores maiores (5000) fornecem análise mais completa, mas consomem mais memória e tempo de processamento.
> - **TamanhoMinimoArquivosDuplicadosMB**: Define o tamanho mínimo para buscar duplicados. Valores menores (10MB) encontram mais duplicados, mas o cálculo de hash MD5 demora muito mais tempo.
> - **TopGruposDuplicados**: Limita quantos grupos de duplicados serão processados. Aumentar (5000+) pode melhorar a detecção, mas aumenta significativamente o uso de memória e tempo de processamento.
> - **ModoSilencioso**: Quando false, exibe logs detalhados no console. Útil para debug, mas pode gerar muito output em análises grandes.

> [!NOTE]\
> **Recomendações de configuração por tamanho do servidor:**
> - **Pequeno (<1TB)**: Use valores padrão
> - **Médio (1-10TB)**: TamanhoMinimoArquivosMB = 200, TopArquivosGrandesAntigos = 2000
> - **Grande (10-50TB)**: TamanhoMinimoArquivosMB = 500, TopArquivosGrandesAntigos = 5000, TamanhoMinimoArquivosDuplicadosMB = 100
> - **Muito Grande (>50TB)**: TamanhoMinimoArquivosMB = 1000, TopArquivosGrandesAntigos = 3000, TamanhoMinimoArquivosDuplicadosMB = 200

4. **Após a alteração, execute o script pressionando F5 ou o botão Play no PowerShell ISE**.

5. **Configuração Interativa**:
   - Escolha entre análise local ou de rede
   - Digite o caminho a ser analisado
   - Aguarde a análise ser concluída

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

> [!WARNING]\
> **Importantes considerações de segurança:**
> - Embora o script seja 100% read-only, a análise intensiva pode impactar a performance do servidor
> - Execute em horários de baixo uso para minimizar impacto nos usuários
> - Verifique se há espaço suficiente para os relatórios antes da execução
> - Não execute em múltiplos servidores simultaneamente sem considerar a carga de rede
> - Mantenha os relatórios gerados em local seguro pois contêm informações sensíveis sobre a estrutura de arquivos

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

> [!NOTE]\
> **Dica de segurança:** O relatório HTML contém informações detalhadas sobre a estrutura de arquivos do servidor. Mantenha esses relatórios em local seguro e limite o acesso apenas a administradores autorizados.

## 🚨 Limitações e Considerações

> [!WARNING]\
> **Limitações importantes do script:**
> - Análises de servidores muito grandes (>50TB) podem levar mais de 12 horas
> - O cálculo de hash MD5 para duplicados é CPU-intensivo e pode aquecer o servidor
> - Arquivos em uso exclusivo podem não ser detectados corretamente
> - Permissões insuficientes podem resultar em análise incompleta
> - Não recomendado executar durante backup ou outras operações intensivas de I/O

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

> [!NOTE]\
> **Estimativa de tempo de execução:**
> - Servidor pequeno (<1TB): 15-30 minutos
> - Servidor médio (1-10TB): 1-3 horas
> - Servidor grande (10-50TB): 3-8 horas
> - Servidor muito grande (>50TB): 8+ horas

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
