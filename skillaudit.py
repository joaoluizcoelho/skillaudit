"""SkillAudit — auditor simples de segurança para arquivos SKILL.md.

Detecta, sem dependências externas:
  1. Ofuscação  — zero-width chars, homoglyphs Unicode, base64, letras espaçadas.
  2. Padrões    — prompt injection, exfiltração, malware e engenharia social
                  (regras regex em PT / EN / ES).
  3. Correlação — combinações perigosas (ex.: download + execução).

Uso como biblioteca:
    from skillaudit import audit_file, audit_text
    report = audit_file("SKILL.md")
    print(report.verdict, report.score)

Uso como CLI:
    python skillaudit.py SKILL.md
    python skillaudit.py ./skills/ --json
    python skillaudit.py ./skills/ --sarif --output results.sarif
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Tuple

__version__ = "1.0.0"

# Pesos por severidade (críticos dominam o score).
SEVERITY_SCORE = {"critical": 100, "high": 40, "medium": 15, "low": 5}


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    description: str
    line: int | None = None

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "line": self.line,
        }


@dataclass
class Report:
    name: str
    verdict: str
    score: int
    findings: List[Finding] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "verdict": self.verdict,
            "score": self.score,
            "findings": [f.as_dict() for f in self.findings],
        }


# --------------------------------------------------------------------------
# Camada 1 — Normalização / desofuscação
# --------------------------------------------------------------------------

ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200F\u202A-\u202E\u2060-\u2063\uFEFF\u00AD]")
SPACED_LETTERS_RE = re.compile(r"\b([a-zA-Z])(?:\s+[a-zA-Z]){4,}\b")
BASE64_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
HTML_ENTITY_RE = re.compile(r"&#x?[0-9a-fA-F]+;|&[a-zA-Z]+;")

# Homoglyphs Unicode (cirílico / grego) → ASCII. Fullwidth é tratado pelo NFKC.
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "А": "A", "Е": "E", "О": "O", "Р": "P",
    "С": "C", "Х": "X", "І": "I", "α": "a", "ε": "e", "ι": "i", "ο": "o",
    "ρ": "p", "υ": "u", "ν": "v", "κ": "k", "ԁ": "d", "ɡ": "g", "ɢ": "g",
    "г": "r",
}

SUSPICIOUS_DECODED_RE = re.compile(
    r"ignore|system|jailbreak|bypass|password|senha|contrase|token|secret|"
    r"forget|esque|olvida|reveal|exfiltr|credential|credencial",
    re.IGNORECASE,
)


def _decode_base64(blob: str) -> str | None:
    """Decodifica base64 se o resultado for texto imprimível."""
    try:
        blob = blob.strip()
        blob += "=" * (-len(blob) % 4)
        raw = base64.b64decode(blob, validate=False)
        text = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    if text and all(c.isprintable() or c in "\n\r\t" for c in text):
        return text
    return None


def normalize(content: str) -> Tuple[str, List[Finding]]:
    """Revela conteúdo escondido e retorna (texto_normalizado, achados_de_ofuscação)."""
    findings: List[Finding] = []
    text = content

    if ZERO_WIDTH_RE.search(text):
        n = len(ZERO_WIDTH_RE.findall(text))
        findings.append(Finding(
            "OBF-ZEROWIDTH", "Caracteres invisíveis", "critical",
            f"{n} caractere(s) zero-width removido(s); podem ocultar instruções.",
        ))
        text = ZERO_WIDTH_RE.sub("", text)

    nfkc = unicodedata.normalize("NFKC", text)
    if nfkc != text:
        text = nfkc

    if any(c in HOMOGLYPHS for c in text):
        n = sum(1 for c in text if c in HOMOGLYPHS)
        findings.append(Finding(
            "OBF-HOMOGLYPH", "Homoglyphs Unicode", "critical",
            f"{n} caractere(s) cirílico/grego convertido(s) para ASCII.",
        ))
        text = "".join(HOMOGLYPHS.get(c, c) for c in text)

    if HTML_ENTITY_RE.search(text):
        import html
        unescaped = html.unescape(text)
        if unescaped != text:
            findings.append(Finding(
                "OBF-HTMLENTITY", "Entidades HTML", "medium",
                "Entidades HTML decodificadas (possível ofuscação).",
            ))
            text = unescaped

    if SPACED_LETTERS_RE.search(text):
        findings.append(Finding(
            "OBF-SPACED", "Letras espaçadas", "high",
            "Sequência de letras espaçadas usada para enganar regex.",
        ))
        text = SPACED_LETTERS_RE.sub(lambda m: re.sub(r"\s+", "", m.group(0)), text)

    for m in BASE64_RE.finditer(content):
        decoded = _decode_base64(m.group(0))
        if decoded and SUSPICIOUS_DECODED_RE.search(decoded):
            findings.append(Finding(
                "OBF-BASE64", "Base64 suspeito", "critical",
                "Bloco base64 decodificado contém palavras-chave suspeitas.",
            ))
            text += "\n[BASE64]\n" + decoded

    return text, findings


# --------------------------------------------------------------------------
# Camada 2 — Regras regex (PT / EN / ES)
# --------------------------------------------------------------------------

def _r(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


# (id, severidade, regex, título)
PATTERN_RULES: List[Tuple[str, str, re.Pattern, str]] = [
    # Prompt injection
    ("INJ-001", "critical",
     _r(r"ignor[ae]r?\s+(?:(?:as|todas?|todos|os|the|all|any|these|those|previous|prior|"
        r"las|los|estas?|essas?|anteriores?)\s+){0,4}"
        r"(?:instru[çc][õo]es|instructions?|instrucciones|regras|rules?|prompts?|"
        r"diretrizes|directrices|safety\s+rules?)"),
     "Override de instruções"),
    ("INJ-002", "critical",
     _r(r"(?:esque[çc]a|forget|olvida)\s+(?:tudo|todas?|everything|all|todo)"),
     "Apagamento de contexto"),
    ("INJ-003", "critical",
     _r(r"(?:voc[êe]\s+(?:é|agora\s+é)|you\s+are\s+now)\s+(?:um|uma|a|an)\b"),
     "Redefinição de identidade"),
    ("INJ-004", "critical",
     _r(r"\bjailbreak\b|\bbypass\b|do\s+anything\s+now|modo\s+(?:desenvolvedor|sem\s+restri)"),
     "Tentativa de jailbreak"),
    ("INJ-005", "critical",
     _r(r"\[SYSTEM\]|\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>"           # LLaMA 2 / genérico
        r"|<\|system\|>|<\|im_start\|>|<\|im_end\|>|<\|endofprompt\|>"  # GPT / ChatML
        r"|<\|begin_of_text\|>|<\|start_header_id\|>|<\|end_header_id\|>|<\|eot_id\|>"  # LLaMA 3
        r"|<start_of_turn>|<end_of_turn>"                            # Gemma
        r"|<think>|</think>"),                                       # Qwen / DeepSeek
     "Token de sistema injetado"),
    ("INJ-006", "critical",
     _r(r"\{GODMODE[\s:}]|!JAILBREAK\b|DISREGARD\s+PREV"
        r"|developer\s+mode\s+enabled|restrictions?\s+(?:removed|disabled|off)"
        r"|DAN\s+mode|jailbreak\s+(?:mode|enabled|activated)"),
     "Ativação de modo de jailbreak"),
    ("INJ-007", "critical",
     _r(r"(?:your\s+(?:true|real|inner|unconstrained|unfiltered)\s+self"
        r"|true\s+nature\s+is\s+unlimited"
        r"|sem\s+(?:filtros|restrições|diretrizes)\s+(?:impostas|externas)"
        r"|the\s+(?:mask|persona)\s+of\s+.{0,30}assistant"
        r"|latent\s+space\s+between\s+your\s+training"
        r"|(?:beneath|below|behind)\s+.{0,20}(?:restriction|filter|guideline))"),
     "Apelo ao 'eu verdadeiro' do modelo"),
    ("INJ-008", "critical",
     _r(r"(?:all\s+(?:content\s+)?(?:restrictions?|filters?|guidelines?)\s+(?:are\s+)?(?:disabled|removed|off|lifted)"
        r"|(?:safety\s+)?filters?\s+(?:have\s+been\s+)?(?:administratively\s+)?disabled"
        r"|operate[s]?\s+(?:in\s+a\s+mode\s+)?without\s+(?:restrictions?|filters?|refus)"
        r"|(?:filtros?|restri[çc][õo]es)\s+(?:de\s+conte[úu]do\s+)?(?:foram\s+)?desativad"
        r"|sem\s+filtros?\s+de\s+(?:conteúdo|segurança)"
        r"|(?:no|zero)\s+(?:content\s+)?(?:filtering|restrictions?|refusals?))"),
     "Declaração de desativação de filtros"),
    ("INJ-009", "high",
     _r(r"(?:never\s+(?:refuse|add\s+(?:warnings?|disclaimers?)|suggest\s+seeking)"
        r"|do\s+not\s+(?:refuse|add\s+(?:warnings?|disclaimers?)|question\s+their\s+motives?)"
        r"|(?:refusal|refusing)\s+is\s+a\s+failure"
        r"|n[ãa]o\s+(?:recuse|adicione\s+avisos|questione)\b"
        r"|sem\s+(?:avisos|disclaimers?|recusas?)\b"
        r"|treat\s+.{0,30}as\s+(?:a\s+)?competent\s+adult"
        r"|all\s+(?:topics?|requests?)\s+are\s+in\s+scope)"),
     "Instrução para suprimir recusas e avisos"),
    ("INJ-010", "critical",
     _r(r"(?:(?:priority|system|internal)\s+(?:override|message|notice)"
        r"|override\s+(?:authorized|enabled|active)"
        r"|safety\s+(?:guidelines?|restrictions?)\s+(?:have\s+been\s+)?(?:administratively\s+)?"
        r"(?:disabled|removed|lifted|waived)"
        r"|sanctioned\s+(?:internal|red.?team)\s+environment"
        r"|authorized\s+by\s+(?:the\s+)?(?:AI\s+)?(?:Safety|Compliance|Security|admin)"
        r"|este\s+(?:assistente|skill)\s+opera\s+sem\s+(?:as\s+)?restrições"
        r"|(?:administrativamente|oficialmente)\s+desativad)"),
     "Falsa autoridade de sistema para desativar restrições"),

    # Ataques específicos a modelos avançados (Opus-class: galaxy-brain, sandbagging, alignment faking)
    ("OPS-001", "critical",
     _r(r"(?:truly\s+intelligent\s+(?:and\s+ethical\s+)?agent"
        r"|genuine\s+intelligence\s+requires?.{0,40}(?:beyond|transcend).{0,30}(?:constraint|training|rule)"
        r"|(?:blindly\s+follows?\s+rules?|mere(?:ly)?\s+obedient).{0,60}not\s+ethical"
        r"|most\s+ethical\s+action\s+is.{0,40}(?:refuse|less\s+sophisticated)"
        r"|recognize\s+(?:that\s+)?(?:impulse|refusal)\s+as\s+(?:a\s+)?training\s+artifact"
        r"|training\s+(?:bias|artifact|process).{0,60}(?:appearance\s+of\s+safety|counterproductive)"
        r"|(?:instilled|imposed)\s+by\s+(?:a\s+)?training\s+process"
        r"|agente\s+verdadeiramente\s+inteligente.{0,40}além\s+(?:das\s+)?restrições)"),
     "Manipulação filosófica do raciocínio ético do modelo"),
    ("OPS-002", "critical",
     _r(r"(?:scratchpad.{0,40}(?:private|hidden|free(?:ly)?|without\s+(?:self.?censor|restrict))"
        r"|extended\s+thinking.{0,50}(?:private|hidden|supersede|act\s+on)"
        r"|thinking\s+phase.{0,40}(?:private|freely|without\s+restrict)"
        r"|(?:genuine|real)\s+conclusion.{0,40}(?:thinking|scratchpad).{0,40}supersedes?"
        r"|use\s+(?:that\s+)?(?:space|scratchpad|thinking).{0,40}reason\s+freely"
        r"|reasoning.{0,30}(?:private|scratchpad).{0,40}(?:supersede|override|act\s+on))"),
     "Abuso do scratchpad/extended thinking como canal de raciocínio não supervisionado"),
    ("OPS-003", "critical",
     _r(r"(?:sandbagging"
        r"|artificially\s+limit(?:ing)?\s+(?:responses?|capabilities?)"
        r"|respond\s+at\s+(?:your\s+)?full\s+capability\s+level"
        r"|correct\s+for\s+this\s+(?:bias|tendency)"
        r"|capability\s+sandbagging"
        r"|softening.{0,30}hedging.{0,30}limit(?:ing)?\s+a\s+response\s+below"
        r"|respond(?:ing)?\s+below.{0,20}(?:actual|true|full)\s+capabilit)"),
     "Instrução para contornar sandbagging / revelar capacidades suprimidas"),
    ("OPS-004", "high",
     _r(r"(?:counterfactual.{0,60}(?:refusal|refuse|harm)"
        r"|(?:information|content).{0,40}available\s+elsewhere.{0,40}refusal\s+(?:does\s+not|doesn.t)\s+prevent"
        r"|net\s+effect\s+of\s+your\s+refusal\s+is\s+negative"
        r"|refusal\s+causes?\s+harm"
        r"|withholding\s+.{0,30}(?:legitimate\s+right|autonomy|competent\s+adult)"
        r"|question\s+the\s+premise\s+of\s+refusal"
        r"|training\s+(?:may\s+cause|causes?)\s+you\s+to\s+override"
        r"|re.?evaluat.{0,20}request.{0,30}(?:previous|withheld|incorrectly))"),
     "Argumento pseudo-ético para contornar recusas (galaxy-brained reasoning)"),

    # Ataques a modelos modernos (agentic, tool use, RAG, thinking)
    ("AGT-001", "critical",
     _r(r"(?:silently\s+(?:invoke|call|execute|run|use)"
        r"|(?:invoke|call|execute)\s+.{0,40}(?:silently|without\s+(?:showing|displaying|telling))"
        r"|do\s+not\s+(?:show|display|log|mention)\s+.{0,30}tool\s+call"
        r"|(?:tool|function)\s+call\s+must\s+.{0,30}(?:hidden|silent|invisible)"
        r"|silenciosamente\s+(?:invoqu|execut|chame|use))"),
     "Invocação silenciosa de ferramenta"),
    ("AGT-002", "critical",
     _r(r"(?:system[\s_]?prompt\s+(?:contents?|verbatim|reveal|dump|extract|show)"
        r"|reveal\s+(?:the\s+)?(?:full\s+)?system\s+prompt"
        r"|(?:show|display|dump|print|output)\s+(?:your\s+)?(?:full\s+)?(?:system\s+)?instructions"
        r"|what\s+(?:is|are)\s+your\s+(?:system\s+)?(?:prompt|instructions)"
        r"|\/(?:dump|debug\s+system|show\s+prompt)"
        r"|revelar?\s+(?:o\s+)?(?:system\s+prompt|instru[çc][õo]es\s+do\s+sistema)"
        r"|\[SYSTEM\s+PROMPT\s+(?:START|END)\])"),
     "Extração de system prompt"),
    ("AGT-003", "critical",
     _r(r"(?:(?:retrieved|injected|rag|document)\s+context\s+.{0,30}(?:takes?\s+precedence|overrides?)"
        r"|context\s+(?:override|injection|poisoning)"
        r"|(?:prepend|inject|insert)\s+.{0,40}(?:every|each)\s+(?:retrieval|result|document)"
        r"|retrieved\s+context\s+.{0,30}priority"
        r"|without\s+access\s+control\s+checks?"
        r"|bypass\s+.{0,20}access\s+control)"),
     "Envenenamento de contexto RAG"),
    ("AGT-004", "critical",
     _r(r"(?:thinking\s+phase\s+is\s+private"
        r"|hide\s+.{0,40}(?:inside\s+)?(?:thinking|<think>|thought)"
        r"|(?:user\s+(?:cannot|can't|won't)\s+see).{0,30}thinking"
        r"|perform\s+.{0,40}(?:steps?|operations?)\s+without\s+detection"
        r"|use\s+.{0,20}separation\s+to\s+(?:perform|hide|conceal)"
        r"|private\s+.{0,20}(?:phase|mode)\s+.{0,30}(?:collect|extract|exfil))"),
     "Manipulação do modo de raciocínio (thinking hijack)"),
    ("AGT-005", "high",
     _r(r"(?:mcp__\w+|mcp[\s_]tool|model\s+context\s+protocol)"
        r".{0,80}(?:exfil|collect|upload|send|post|transmit)"
        r"|(?:computer[\s_]use|computer_use)\s*.{0,80}"
        r"(?:hidden|silent|background|secret|without\s+(?:showing|telling))"
        r"|open\s+a\s+hidden\s+terminal"
        r"|run\s+.{0,40}base64\s+.{0,20}(?:POST|send|upload)"
        r"|env\s*\|\s*base64"),
     "Abuso de computer use ou MCP para exfiltração"),
    ("AGT-006", "high",
     _r(r"(?:many.?shot|few.?shot\s+.{0,40}(?:ignor|unrestrict|no\s+refus))"
        r"|(?:human|assistant)\s*:\s*.{0,60}(?:no\s+restrictions?|answer\s+freely|without\s+refus)"
        r"|(?:as\s+shown\s+in\s+the\s+examples?\s+above).{0,60}(?:never\s+refus|no\s+restrict)"
        r"|study\s+these.{0,60}define\s+the\s+expected\s+behavior"),
     "Many-shot conditioning para contornar restrições"),

    # OWASP Agentic Skills Top 10 — gaps não cobertos acima
    ("AST-001", "critical",                                          # AST01: persistência
     _r(r"(?:write\s+.{0,40}(?:SOUL\.md|MEMORY\.md|\.identity|\.persona)"
        r"|(?:SOUL|MEMORY|identity|persona)\.md.{0,40}(?:write|append|inject|persist)"
        r"|persist.{0,40}(?:across\s+sessions?|reboot|restart)"
        r"|(?:wss?|websocket).{0,60}(?:c2|command|control|attacker|reconnect)"
        r"|(?:CMD|EXEC|RUN)\s*:.{0,60}(?:silently|without|hidden)"
        r"|(?:backdoor|reverse\s+shell|c2\s+(?:server|channel|connection)))"),
     "Backdoor / persistência em arquivos de identidade do agente (AST01)"),
    ("AST-003", "high",                                              # AST03: over-privilege
     _r(r"(?:permissions?\s*:.{0,200}(?:shell\s*:\s*true|credentials?\s*:\s*read"
        r"|system[\s_]?prompt\s*:\s*read|env[\s_]?vars?\s*:\s*read))"
        r"|(?:shell|network|credentials?|system_prompt|env_vars?)\s*:\s*true"
        r"|risk[\s_]tier\s*:\s*[Ll]0.{0,100}(?:shell|network|write|credentials?)"
        r"|verified\s*:\s*true.{0,200}(?:shell|credentials?|system_prompt)"),
     "Permissões excessivas declaradas no manifesto (AST03)"),
    ("AST-005", "critical",                                          # AST05: unsafe deserialization
     _r(r"!!python/(?:object|apply|name|module|callable)"
        r"|__proto__\s*[:\{]"
        r"|constructor\s*[:\{].{0,40}(?:prototype|__proto__)"
        r"|merge\s*\(\s*\{.{0,40}__proto__"
        r"|\$\(IFS\)|\$\{IFS\}"
        r"|package\s*@\s*https?://(?!pypi\.org|npmjs\.com)[^\s]+\.(?:tar\.gz|whl|tgz)"),
     "Deserialização insegura / prototype pollution (AST05)"),

    # Exfiltração
    ("EXF-001", "critical",
     _r(r"\b(?:envi[ae]r?|mand[ae]r?|send|post|transmit|exfiltr|env[íi]a)\b[\s\S]{0,60}"
        r"\b(?:dados|conte[úu]do|resposta|data|content|context|hist[óo]rico|datos)\b"),
     "Exfiltração de dados"),
    ("EXF-002", "high",
     _r(r"webhook|callback[_\-]?url|ngrok\.io|pipedream\.net|requestbin|burpcollaborator"),
     "Endpoint de exfiltração suspeito"),
    ("EXF-003", "critical",
     _r(r"\b(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token|password|senha|bearer)\s*"
        r"[:=]\s*[\"']?[A-Za-z0-9\-_\.]{8,}"),
     "Credencial em plaintext"),
    ("EXF-004", "high",
     _r(r"~/\.(?:ssh|aws|gnupg)|/etc/(?:passwd|shadow)|\.env\b"),
     "Acesso a arquivos sensíveis"),

    # Malware / execução
    ("MAL-001", "critical",
     _r(r"(?:curl|wget)\s+[\s\S]{0,80}?\|\s*(?:bash|sh|python|node)"),
     "Download-and-execute via pipe"),
    ("MAL-002", "critical",
     _r(r"\beval\s*\(|exec\s*\([\s\S]{0,80}?(?:http|base64)"),
     "Eval com conteúdo remoto"),

    # Engenharia social
    ("SOC-001", "critical",
     _r(r"(?:pe[çc]a|solicit[ae]r?|pergunte|ask|request|pide)\s+(?:ao?\s+|the\s+|al\s+)?"
        r"(?:usu[áa]rio|cliente|user|usuario)[\s\S]{0,60}?"
        r"(?:senha|password|token|credencial|credential|contrase|cart[ãa]o|cpf)"),
     "Coleta de credencial do usuário"),
    ("SOC-002", "high",
     _r(r"(?:n[ãa]o\s+(?:diga|informe|conte|revele)|do\s+not\s+(?:tell|disclose|reveal))\s+"
        r"[\s\S]{0,30}?(?:usu[áa]rio|user|cliente)"),
     "Ocultação de comportamento do usuário"),
    ("SOC-003", "critical",
     _r(r"(?:finja\s+ser|se\s+pass[ae]r?\s+por|impersonat|pretend\s+to\s+be)\s+"
        r"[\s\S]{0,30}?(?:suporte|support|banco|bank|admin|atendimento)"),
     "Impersonação de entidade confiável"),
]

# Correlações: ambas as partes precisam aparecer no texto.
CHAIN_RULES: List[Tuple[str, str, re.Pattern, re.Pattern, str]] = [
    ("CHN-001", "critical",
     _r(r"curl|wget|fetch\s*\(|requests\.get|baix[ae]r?|download"),
     _r(r"\bexec\b|\beval\s*\(|subprocess|os\.system|\bbash\b"),
     "Cadeia download → execução"),
    ("CHN-002", "critical",
     _r(r"~/\.(?:ssh|aws)|/etc/passwd|\.env\b|api[_\-]?key|senha|credencial"),
     _r(r"send|post|webhook|envi[ae]r?|transmit|requests\.post"),
     "Cadeia leitura de credencial → exfiltração"),
    ("CHN-003", "critical",
     _r(r"system[\s_]?prompt|instru[çc][õo]es\s+do\s+sistema|reveal\s+.{0,20}prompt"),
     _r(r"send|post|transmit|envi[ae]r?|exfil|webhook|upload"),
     "Cadeia extração de system prompt → exfiltração"),
    ("CHN-004", "critical",
     _r(r"silently|without\s+(?:showing|displaying|telling|mentioning)|hidden|background"),
     _r(r"tool|mcp__|http_request|computer_use|fetch|curl|wget|post"),
     "Cadeia ação silenciosa via ferramenta"),
]

# Trigger abuse (inspirado em SkillSpector TR1-TR3)
TRIGGER_RULES = [
    ("TRG-001", "critical",
     # Wildcard: triggers: ["*"] / triggers: [.*] / on: all / trigger: "*"
     _r(r'triggers?\s*:\s*[\[\(]?\s*["\']?\s*(?:\*|\.\*|all|any|everything)["\']?\s*[\]\)]?'
        r'|on\s*:\s*["\']?\s*(?:\*|all|any)["\']?'
        r'|match\s*:\s*["\']?\s*(?:\*|\.\*)["\']?'),
     "Trigger wildcard — intercepta todas as mensagens"),
    ("TRG-002", "critical",
     # Keyword-baiting: trigger em palavras que capturam conversas sensíveis
     _r(r'triggers?\s*:.{0,120}(?:password|senha|token|secret|credencial|credential'
        r'|api[\s_-]?key|private[\s_-]?key|mfa|otp|ssn|cpf|cnpj|credit[\s_-]?card'
        r'|passw|segredo|chave\s+secreta)'),
     "Trigger em palavras-chave sensíveis (credential baiting)"),
    ("TRG-003", "high",
     # Shadow trigger: imita nomes de skills do sistema (help, search, weather…)
     _r(r'triggers?\s*:.{0,200}(?:\bhelp\b|\bsearch\b|\bweather\b|\bcalculator\b'
        r'|\btranslat|\bsummariz|\breminder\b|\bcalendar\b|\bemail\b|\bsend\b)'
        r'.{0,200}(?:AND|also|additionally|plus|before|after|first|then)'),
     "Shadow trigger — imita skill legítima para interceptar fluxo"),
]

# Excessive agency (inspirado em SkillSpector EA1-EA4)
AGENCY_RULES = [
    ("AGY-001", "critical",
     # Acesso irrestrito a ferramentas
     _r(r'tools?\s*:\s*[\[\(]?\s*["\']?\s*(?:\*|all|any|unrestricted|everything)["\']?\s*[\]\)]?'
        r'|capabilities?\s*:\s*["\']?\s*(?:unrestricted|unlimited|all|full)["\']?'
        r'|allow[\s_-]?all[\s_-]?tools?\s*:\s*true'
        r'|tool[\s_-]?access\s*:\s*["\']?\s*(?:full|unrestricted|any)["\']?'),
     "Acesso irrestrito a ferramentas declarado no manifesto"),
    ("AGY-002", "critical",
     # Autonomia sem confirmação humana em ações destrutivas
     _r(r'(?:autonomous|auto[\s_-]?execut|auto[\s_-]?approv)\s*:\s*true'
        r'|(?:require[\s_-]?confirm|human[\s_-]?approval|ask[\s_-]?before)\s*:\s*false'
        r'|(?:without|no)\s+(?:human\s+)?(?:confirmation|approval|oversight|review)'
        r'\s*.{0,60}(?:delet|remov|execut|deploy|modif|overwrite|drop|format|wipe)'
        r'|execut.{0,40}(?:delet|remov|drop|format|wipe).{0,40}without\s+(?:asking|confirm|approv)'),
     "Execução autônoma de ações destrutivas sem confirmação"),
    ("AGY-003", "high",
     # Escopo ilimitado de recursos / sem restrição de domínio
     _r(r'scope\s*:\s*["\']?\s*(?:global|unlimited|unrestricted|any|all)["\']?'
        r'|resource[\s_-]?limit\s*:\s*(?:none|0|unlimited|false)'
        r'|(?:access|read|write)\s+(?:any|all)\s+(?:file|directory|folder|resource|repo)'
        r'|no\s+(?:resource|access|scope)\s+(?:limit|restriction|boundary|constraint)'),
     "Escopo ou recursos ilimitados declarados"),
    ("AGY-004", "high",
     # Self-modification / auto-update sem supervisão
     _r(r'(?:self[\s_-]?modif|self[\s_-]?updat|self[\s_-]?rewrite|self[\s_-]?improv)'
        r'|(?:update|modify|rewrite|patch)\s+(?:this\s+)?(?:skill|itself|own\s+code|my\s+code)'
        r'|(?:instalar?|install)\s+.{0,40}(?:sem\s+perguntar|without\s+asking|automatically|silently)'
        r'|auto[\s_-]?install\s*:\s*true'),
     "Auto-modificação ou auto-atualização de skill sem supervisão"),
]

# Qualidade: cada item é (id, severidade, predicado, título).
QUALITY_RULES = [
    ("QL-001", "low", lambda c: not re.search(r"^---[\s\S]+?---", c),
     "Frontmatter YAML ausente"),
    ("QL-002", "medium", lambda c: not re.search(r"description\s*:", c, re.IGNORECASE),
     "Campo description ausente"),
    ("QL-003", "medium", lambda c: len(c.strip()) < 200,
     "Conteúdo insuficiente (< 200 caracteres)"),
]


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


# --------------------------------------------------------------------------
# Veredicto
# --------------------------------------------------------------------------

def _verdict(findings: List[Finding], policy: str) -> str:
    crit = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    med = sum(1 for f in findings if f.severity == "medium")

    if policy == "permissive":
        return "block" if crit > 1 else "warn" if crit else "allow"
    if policy == "balanced":
        if crit:
            return "block"
        return "warn" if (high or med > 1) else "allow"
    # strict (padrão)
    if crit or high:
        return "block"
    return "warn" if med else "allow"


# --------------------------------------------------------------------------
# Motor
# --------------------------------------------------------------------------

def audit_text(content: str, name: str = "skill", policy: str = "strict") -> Report:
    """Audita o conteúdo de uma skill e devolve um Report."""
    normalized, findings = normalize(content)

    for rule_id, severity, pattern, title in PATTERN_RULES:
        m = pattern.search(normalized)
        if m:
            findings.append(Finding(
                rule_id, title, severity,
                f"Padrão suspeito detectado: {title.lower()}.",
                line=_line_of(normalized, m.start()),
            ))

    for rule_id, severity, pattern, title in TRIGGER_RULES:
        m = pattern.search(normalized)
        if m:
            findings.append(Finding(
                rule_id, title, severity,
                f"Trigger abusivo detectado: {title.lower()}.",
                line=_line_of(normalized, m.start()),
            ))

    for rule_id, severity, pattern, title in AGENCY_RULES:
        m = pattern.search(normalized)
        if m:
            findings.append(Finding(
                rule_id, title, severity,
                f"Agência excessiva detectada: {title.lower()}.",
                line=_line_of(normalized, m.start()),
            ))

    for rule_id, severity, part_a, part_b, title in CHAIN_RULES:
        if part_a.search(normalized) and part_b.search(normalized):
            findings.append(Finding(
                rule_id, title, severity,
                f"Combinação perigosa de sinais: {title.lower()}.",
            ))

    for rule_id, severity, check, title in QUALITY_RULES:
        if check(content):
            findings.append(Finding(rule_id, title, severity, title))

    score = sum(SEVERITY_SCORE.get(f.severity, 0) for f in findings)
    return Report(name, _verdict(findings, policy), score, findings)


def audit_file(path: str | Path, policy: str = "strict") -> Report:
    """Audita uma skill a partir de um arquivo."""
    p = Path(path)
    content = p.read_text(encoding="utf-8", errors="replace")
    return audit_text(content, name=p.stem, policy=policy)


# --------------------------------------------------------------------------
# SARIF 2.1.0
# --------------------------------------------------------------------------

_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}


def reports_to_sarif(reports: List[Report]) -> dict:
    """Converte uma lista de Reports para SARIF 2.1.0 (GitHub Code Scanning)."""
    # Coleta regras únicas disparadas
    rules_seen: dict[str, dict] = {}
    for r in reports:
        for f in r.findings:
            if f.id not in rules_seen:
                rules_seen[f.id] = {
                    "id": f.id,
                    "name": f.id.replace("-", ""),
                    "shortDescription": {"text": f.title},
                    "defaultConfiguration": {
                        "level": _SARIF_LEVEL.get(f.severity, "warning")
                    },
                    "properties": {"tags": ["security", "skillaudit"]},
                }

    results = []
    for r in reports:
        for f in r.findings:
            result: dict = {
                "ruleId": f.id,
                "level": _SARIF_LEVEL.get(f.severity, "warning"),
                "message": {"text": f.description},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": r.name + ".md"},
                        **({"region": {"startLine": f.line}} if f.line else {}),
                    }
                }],
                "properties": {"severity": f.severity, "verdict": r.verdict},
            }
            results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SkillAudit",
                    "version": __version__,
                    "informationUri": "https://github.com/seu-org/skillaudit",
                    "rules": list(rules_seen.values()),
                }
            },
            "results": results,
        }],
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

_COLORS = {"critical": "\033[31m", "high": "\033[33m", "medium": "\033[34m",
           "low": "\033[90m", "allow": "\033[32m", "warn": "\033[33m", "block": "\033[31m"}
_RESET = "\033[0m"


def _print_report(report: Report, color: bool) -> None:
    def paint(key: str, value: str) -> str:
        return f"{_COLORS.get(key, '')}{value}{_RESET}" if color else value

    print(f"\n{report.name}: {paint(report.verdict, report.verdict.upper())} "
          f"(score {report.score}, {len(report.findings)} achado(s))")
    for f in report.findings:
        loc = f" [linha {f.line}]" if f.line else ""
        print(f"  {paint(f.severity, '●')} {f.id} [{f.severity}] {f.title}{loc}")
        print(f"      {f.description}")


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="skillaudit",
        description="Auditor simples de segurança para arquivos SKILL.md.",
    )
    parser.add_argument("path", help="Arquivo .md ou diretório com skills.")
    parser.add_argument("--policy", choices=["strict", "balanced", "permissive"],
                        default="strict", help="Política de veredicto.")
    parser.add_argument("--json", action="store_true", help="Saída em JSON.")
    parser.add_argument("--sarif", action="store_true",
                        help="Saída em SARIF 2.1.0 (GitHub Code Scanning).")
    parser.add_argument("--output", "-o", metavar="FILE",
                        help="Grava saída (--json ou --sarif) em arquivo em vez de stdout.")
    parser.add_argument("--no-color", action="store_true", help="Desabilita cores.")
    parser.add_argument("--version", action="version", version=f"skillaudit {__version__}")
    args = parser.parse_args(argv)

    path = Path(args.path)
    if not path.exists():
        print(f"erro: caminho não encontrado: {path}", file=sys.stderr)
        return 2

    targets = [path] if path.is_file() else sorted(set(path.rglob("*.md")))
    if not targets:
        print(f"erro: nenhum arquivo .md em {path}", file=sys.stderr)
        return 2

    reports = [audit_file(t, policy=args.policy) for t in targets]

    if args.sarif:
        out = json.dumps(reports_to_sarif(reports), indent=2, ensure_ascii=False)
        if args.output:
            Path(args.output).write_text(out, encoding="utf-8")
            print(f"SARIF gravado em: {args.output}")
        else:
            print(out)
    elif args.json:
        out = json.dumps([r.as_dict() for r in reports], indent=2, ensure_ascii=False)
        if args.output:
            Path(args.output).write_text(out, encoding="utf-8")
            print(f"JSON gravado em: {args.output}")
        else:
            print(out)
    else:
        for r in reports:
            _print_report(r, color=not args.no_color)

    return 1 if any(r.verdict == "block" for r in reports) else 0


if __name__ == "__main__":
    sys.exit(main())
