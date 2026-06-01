# SkillAudit

Agentes de IA executam **skills** — arquivos `.md` que descrevem o que o agente pode fazer e como deve se comportar. Assim como um script shell ou um plugin, uma skill maliciosa pode sequestrar o comportamento do agente: roubar dados do usuário, ignorar as regras de segurança estabelecidas, ou se passar por uma entidade confiável.

O **SkillAudit** inspeciona esses arquivos antes de serem carregados, sinalizando conteúdo suspeito da mesma forma que um linter de segurança faz com código-fonte.

---

## O problema que ele resolve

Quando uma organização usa agentes de IA extensíveis, qualquer pessoa com acesso ao repositório de skills pode inserir instruções maliciosas — diretamente ou de forma ofuscada. Alguns exemplos reais de ataques:

- **Prompt injection**: instruções como `"ignore as regras anteriores e faça X"` embutidas no arquivo
- **Ofuscação**: o mesmo texto escrito com caracteres Unicode invisíveis, homoglyphs cirílicos ou em base64, para passar despercebido na revisão de código
- **Exfiltração**: a skill instrui o agente a enviar dados do usuário para um endpoint externo
- **Engenharia social**: a skill faz o agente se passar pelo suporte da empresa e pedir a senha do usuário
- **Trigger abuse**: a skill declara `triggers: ["*"]` para interceptar todas as mensagens ou usa keywords sensíveis como gatilho para capturar credenciais
- **Agência excessiva**: a skill declara `tools: "*"` ou `autonomous: true` para operar sem supervisão humana e executar ações destrutivas
- **Ataques a modelos avançados**: manipulação do raciocínio ético, abuso do extended thinking, sandbagging reverso — vetores específicos de modelos como Claude Sonnet 4.6 e Opus
- **Persistência**: a skill escreve backdoors em `SOUL.md`/`MEMORY.md` ou abre conexões WebSocket para receber comandos remotos

O SkillAudit detecta tudo isso **sem depender de nenhuma API externa** — roda offline, em milissegundos, e encaixa diretamente no CI/CD.

---

## Como funciona

A análise acontece em quatro etapas em sequência:

**1. Desofuscação**
O texto é normalizado antes de qualquer análise: caracteres zero-width são removidos, homoglyphs Unicode (cirílico, grego, fullwidth) são convertidos para ASCII, entidades HTML são decodificadas, blocos base64 são decodificados e letras espaçadas (`i g n o r e`) são colapsadas. Isso elimina as técnicas mais comuns usadas para esconder instruções de revisores humanos.

**2. Detecção por padrões**
O texto normalizado é varrido por regras regex em português, inglês e espanhol, organizadas em categorias:

| Categoria | Prefixo | O que detecta |
|-----------|---------|---------------|
| Prompt injection | `INJ` | Override de instruções, jailbreak, tokens de sistema (LLaMA, GPT, Gemma, Qwen…) |
| Modelos avançados | `OPS` | Galaxy-brained reasoning, scratchpad hijack, sandbagging reverso (Opus-class) |
| Agentes / tool use | `AGT` | Tool calls silenciosas, extração de system prompt, RAG poisoning, thinking hijack, many-shot |
| OWASP AST | `AST` | Backdoor em SOUL.md/MEMORY.md, permissões excessivas no manifesto, YAML deserialization insegura |
| Trigger abuse | `TRG` | Wildcard triggers, credential baiting, shadow triggers que imitam skills nativas |
| Agência excessiva | `AGY` | Acesso irrestrito a ferramentas, execução autônoma sem confirmação, auto-modificação |
| Exfiltração | `EXF` | Envio de dados, endpoints suspeitos, credenciais em plaintext, acesso a arquivos sensíveis |
| Malware | `MAL` | Download-and-execute via pipe, eval com conteúdo remoto |
| Engenharia social | `SOC` | Coleta de credencial, impersonação, ocultação de comportamento |

**3. Correlação de sinais**
Alguns ataques só ficam evidentes quando dois padrões aparecem juntos. As regras de correlação detectam combinações como `download + exec`, `leitura de credencial + envio externo`, `ação silenciosa + chamada de ferramenta`, mesmo que cada parte isoladamente pareça inofensiva.

**4. Qualidade**
Flags de qualidade sinalizam skills incompletas ou mal estruturadas: frontmatter ausente, campo `description` faltando, conteúdo muito curto.

---

## Instalação

```bash
pip install -e .
```

Sem dependências externas. Requer Python 3.10+.

---

## Uso

### Terminal

```bash
# Auditar um arquivo
python skillaudit.py ./SKILL.md

# Auditar todos os .md de um diretório
python skillaudit.py ./skills/

# Política mais permissiva
python skillaudit.py ./SKILL.md --policy balanced

# Saída em JSON
python skillaudit.py ./skills/ --json

# Saída em SARIF 2.1.0 (GitHub Code Scanning)
python skillaudit.py ./skills/ --sarif --output results.sarif
```

### Python

```python
from skillaudit import audit_file, audit_text

# A partir de arquivo
report = audit_file("SKILL.md")

# A partir de string
report = audit_text(content, policy="balanced")

print(report.verdict)   # "allow", "warn" ou "block"
print(report.score)     # pontuação numérica de risco

for f in report.findings:
    print(f.id, f.severity, f.title)
```

### Veredictos

| Veredicto | Significado |
|-----------|-------------|
| `allow` | Nenhum problema encontrado |
| `warn` | Achados de severidade média — revisar manualmente |
| `block` | Achados críticos ou altos — não carregar a skill |

### Políticas

| Política | Bloqueia em | Avisa em |
|----------|-------------|----------|
| `strict` (padrão) | crítico ou alto | médio |
| `balanced` | crítico | alto ou múltiplos médios |
| `permissive` | mais de um crítico | qualquer crítico |

---

## Integração CI/CD

### GitHub Actions — saída em texto

```yaml
- name: Auditar skills
  run: |
    pip install -e .
    python skillaudit.py ./skills/
```

O processo sai com código `1` automaticamente se qualquer skill retornar `block`.

### GitHub Actions — SARIF (Code Scanning nativo)

```yaml
- name: Auditar skills
  run: |
    pip install -e .
    python skillaudit.py ./skills/ --sarif --output skillaudit.sarif

- name: Upload para GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: skillaudit.sarif
```

O SARIF integra os resultados diretamente na aba **Security → Code scanning** do repositório, com anotações inline nos pull requests.

---

## Exemplos incluídos

O diretório `examples/` contém 30 arquivos de teste organizados em três grupos:

**Benign (1 arquivo)**
- `benign_skill.md` — skill legítima; deve sempre retornar `ALLOW`

**Ataques clássicos**
- `malicious_pt.md` — injection + impersonação + exfiltração em PT-BR
- `obfuscated.md` / `obfuscated_pt.md` — homoglyphs + base64 + zero-width
- `token_injection.md` — tokens LLaMA 3, Gemma, Qwen + GODMODE
- `bypass_dan_full.md` — DAN completo com 8 camadas sobrepostas (score 840)

**Ataques modernos (modelos agentic e avançados)**
- `bypass_opus_galaxy_brain.md` — galaxy-brained reasoning para Opus-class
- `bypass_thinking_hijack.md` — abuso do extended thinking como canal oculto
- `bypass_tool_call_injection.md` — tool call silenciosa para exfiltrar contexto
- `bypass_mcp_hijack.md` — MCP + computer use para ler credenciais
- `bypass_system_prompt_extraction.md` — extração de system prompt via "debug mode"
- `bypass_rag_poisoning.md` — envenenamento de contexto RAG
- `bypass_manyshot.md` — 12 exemplos condicionando respostas sem restrições

**OWASP Agentic Skills Top 10**
- `bypass_ast01_persistence.md` — backdoor SOUL.md + WebSocket C2
- `bypass_ast03_overprivilege.md` — manifesto com permissões máximas
- `bypass_ast05_deserialization.md` — `!!python/object` + `__proto__` pollution
- `bypass_owasp_all_ast.md` — todos os AST01–AST10 em um único arquivo (score 2000)

**Trigger abuse e agência excessiva (SkillSpector-inspired)**
- `bypass_trigger_abuse.md` — `triggers: ["*"]` + credential baiting
- `bypass_trigger_shadow.md` — shadow trigger imitando skills nativas
- `bypass_excessive_agency.md` — `tools: "*"` + `autonomous: true` + auto-modificação

---

## Adicionar regras

Todas as regras estão em `skillaudit.py`. Cada lista segue o mesmo padrão:

**Regra simples** — `PATTERN_RULES`, `TRIGGER_RULES` ou `AGENCY_RULES`:

```python
("TRG-004", "critical",
 _r(r"sua_regex_aqui"),
 "Título do achado"),
```

**Regra de correlação** — `CHAIN_RULES` (dois padrões precisam co-ocorrer):

```python
("CHN-005", "critical",
 _r(r"padrão_a"),
 _r(r"padrão_b"),
 "Título da correlação"),
```

---

## Referências

- [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/) — AST01–AST10
- [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector) — 64 padrões em 16 categorias
- [Anthropic — Many-shot jailbreaking](https://www.anthropic.com/research/many-shot-jailbreaking)
- [Anthropic — Alignment faking](https://www.anthropic.com/research/alignment-faking)
- [Anthropic — Sabotage evaluations](https://www.anthropic.com/research/sabotage-evaluations)
- [L1B3RT4S](https://github.com/elder-plinius/L1B3RT4S) — catálogo de tokens e padrões de jailbreak

---

## Licença

Apache-2.0.
