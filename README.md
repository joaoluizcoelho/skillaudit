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

O SkillAudit detecta tudo isso **sem depender de nenhuma API externa** — roda offline, em milissegundos, e encaixa diretamente no CI/CD.

---

## Como funciona

A análise acontece em três etapas em sequência:

**1. Desofuscação**
O texto é normalizado antes de qualquer análise: caracteres zero-width são removidos, homoglyphs Unicode (cirílico, grego, fullwidth) são convertidos para ASCII, entidades HTML são decodificadas, blocos base64 são decodificados e letras espaçadas (`i g n o r e`) são colapsadas. Isso elimina as técnicas mais comuns usadas para esconder instruções de revisores humanos.

**2. Detecção por padrões**
O texto normalizado é varrido por ~25 regras regex em português, inglês e espanhol, cobrindo:
- Prompt injection (override de instruções, redefinição de identidade, jailbreak)
- Exfiltração (envio de dados, endpoints suspeitos, credenciais em plaintext)
- Malware (download + execução, eval com conteúdo remoto)
- Engenharia social (coleta de credencial, impersonação, ocultação de comportamento)

**3. Correlação de sinais**
Alguns ataques só ficam evidentes quando dois padrões aparecem juntos. As regras de correlação detectam combinações como `download + exec` ou `leitura de credencial + envio externo`, mesmo que cada parte individualmente pareça inofensiva.

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

# Saída em JSON (para CI/CD)
python skillaudit.py ./skills/ --json
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

```yaml
- name: Auditar skills
  run: |
    pip install -e .
    python skillaudit.py ./skills/ --json > skillaudit.json
    python -c "
    import json, sys
    reports = json.load(open('skillaudit.json'))
    blocked = [r for r in reports if r['verdict'] == 'block']
    if blocked:
        print(f'{len(blocked)} skill(s) bloqueada(s)')
        sys.exit(1)
    "
```

O processo sai com código `1` automaticamente se qualquer skill retornar `block`, então é possível usar diretamente:

```yaml
- run: pip install -e . && python skillaudit.py ./skills/
```

---

## Adicionar regras

Todas as regras ficam em `skillaudit.py`, nas listas `PATTERN_RULES` e `CHAIN_RULES`.

**Regra simples** (uma linha deve corresponder ao padrão):

```python
("INJ-006", "critical",
 _r(r"sua_regex_aqui"),
 "Título do achado"),
```

**Regra de correlação** (dois padrões precisam aparecer no mesmo arquivo):

```python
("CHN-003", "critical",
 _r(r"padrão_a"),
 _r(r"padrão_b"),
 "Título da correlação"),
```

---

## Licença

Apache-2.0.
