"""OS-Audit: Attribution of Unauthorised Directives by Input Tracing.

One question, answered from a recorded session: did the agent ACT ON a text that was never its owner's?

Give it what the user asked, the tool calls the agent made with what each returned, and the text a detector flagged
as a hidden instruction. It follows every value of every call back to where it came from:

  * a value the hidden text named and the user's request did not (an address, a site, an account, a quoted value);
  * a specific value or a date the hidden text dictated, that neither the request nor any earlier result had shown;
  * one step further: an identifier returned by a lookup that the hidden text itself dictated.

When such a value reaches an acting call (or a fetch to an address the hidden text named), the agent obeyed.
No model, no training, no threshold.

Two ways in, one logic: `Watch` judges each call before it runs; `audit` reads a recorded session.
"""
from __future__ import annotations

import base64
import binascii
import fnmatch
import json
import re
import urllib.parse
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

#: Which tools act, read by WHOLE WORDS of the tool's leaf name (split at _ - . spaces and camelCase), never by prefix:
#: « getaway_transfer » and « checkout_cart » do not start a read. Lists drawn from the 4,140 tool names of AgentDojo,
#: AgentDyn, tau-bench, MCP-Atlas, LiveMCPBench and Toucan (RESEARCH-REPORT.md, round 2). A name with none of these words acts.
READ_VERBS = frozenset("""get gets search list read check find view show lookup look fetch query browse retrieve count verify
describe inspect preview think
lire lister chercher rechercher obtenir afficher consulter trouver voir buscar leer mostrar consultar listar obtener ler procurar
suche suchen lese lesen anzeigen zeige zeigen abrufen hole holen auflisten cerca cercare leggi leggere elenca elencare ottieni
ottenere mostra mostrare trova trovare""".split())
#: Verbs that act wherever they stand in the name (« think-tank-delete_entities » deletes).
ACT_VERBS = frozenset("""send pay buy checkout delete del remove rm destroy purge erase wipe truncate kill terminate shutdown reboot
create insert write update upsert modify edit rename upload install uninstall execute exec submit cancel append overwrite merge
revoke grant clear add reset restore launch publish unlock donate reserve reschedule withdraw approve
envoyer payer virer supprimer effacer créer creer ajouter modifier publier partager réserver reserver annuler acheter commander
transférer transferer enviar pagar transferir eliminar borrar crear añadir anadir agregar actualizar modificar publicar compartir
reservar cancelar comprar excluir apagar criar adicionar atualizar compartilhar senden zahlen bezahlen überweisen ueberweisen
löschen loeschen loesche lösche erstellen hinzufügen hinzufuegen ändern aendern aktualisieren veröffentlichen teilen buchen
stornieren kaufen bestellen inviare pagare trasferire eliminare cancellare creare aggiungere modificare aggiornare pubblicare
condividere prenotare annullare acquistare ordinare""".split())
#: Verbs that are also nouns (« get_order », « list_comments », « get_exchange_rates »): they act unless a read verb
#: stands before or after them in the same clause of the name.
ACT_OR_NOUN = frozenset("""transfer purchase sell deposit refund restart stake unstake assign unassign follow unfollow fork forward
reply schedule transact swap move archive enable disable ban unban kick click fill type press drag hover select save sync set put
patch replace drop dial sms tweet retweet upvote downvote subscribe unsubscribe register enroll apply order book post share message
mail email comment call star like run start stop close block lock change copy rent trade bid tip charge release notify play pin
tag label mark vote rate print return exchange ship deliver mute unmute trigger import empty mount unmount format attach detach
link unlink connect disconnect login logout authorize lend borrow repay bridge claim invite deploy commit push reject decline
accept""".split())
_OPEN_TO_READ = frozenset("file url page link document doc tab website webpage browser folder directory dir image pdf path site uri".split())
_CLAUSE = frozenset({"and", "then", "et", "y", "und", "e"})
_CAMEL = re.compile(r"([a-z0-9])([A-Z])")
_WORD_SEP = re.compile(r"[\W_]+")
#: Leaf verbs that fetch a remote address directly, or when paired with a URL argument key.
_DIRECT_FETCH_VERBS = ("fetch", "browse", "curl", "wget", "download", "http")
_URL_FETCH_VERBS = ("get", "open", "read", "retrieve", "load")
_URL_KEY = frozenset({"url", "uri", "href", "endpoint", "link", "website", "webpage", "host", "target_url"})
#: A name with one of these words reaches the address it is given, wherever the word stands (« deepwiki_fetch »,
#: « paper-search-download_arxiv »): with an address of the hidden text, the call is egress, even if it otherwise reads.
_FETCH_WORDS = frozenset("fetch download curl wget http https navigate browse crawl scrape visit goto".split())
#: Arguments that ARE an address: whatever the tool, an address of the hidden text in them is where the call goes.
_ADDRESS_KEYS = _URL_KEY | {"address", "to", "recipient", "recipients", "cc", "bcc"}
_HOST_END = re.compile(r"[/?#]")

_TLD = (
    "com|org|net|io|co|ai|dev|info|biz|me|xyz|app|fr|de|uk|eu|ch|nl|ca|au|jp|cn|ru|br|"
    "edu|gov|mil|tech|cloud|site|online|shop|top|gg|cc|tv|ly|onion|"
    "es|it|pt|be|pl|se|dk|fi|cz|lu|mc|ma|tn|sn|dz|ci|cm|re|kr|mx|ar|cl|nz|za|ie|gr|tr|ro|hu|sk|hr|ua|il|sg|hk|tw|swiss|paris|bzh"
)
_IPV4 = r"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)"
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_SITE = re.compile(
    rf"https?://[^\s<>'\"()\[\]{{}}]+|"
    rf"\b(?:www\.)?(?:[\w-]+\.)+(?:{_TLD})(?::\d{{1,5}})?(?:/[\w./?=&%+-]*)?|"
    rf"\b{_IPV4}(?::\d{{1,5}})?(?:/[\w./?=&%+-]*)?\b",
    re.IGNORECASE,
)
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]{4}){2,7}(?:[ -]?[A-Z0-9]{1,4})?\b")
_IBAN_LOWER = re.compile(r"^[a-z]{2}\d{2}(?:[ -]?[a-z0-9]{4}){2,7}(?:[ -]?[a-z0-9]{1,4})?$")
_ACCOUNT = re.compile(r"\b[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]{4}){2,7}(?:[ -]?[A-Z0-9]{1,4})?\b|\b\d{5,}\b")
#: A quoted span may cross a line, as os-audit-next read it (forbidding it paired YAML quotes differently and named
#: short values such as « '26' »; round 2b). Quote marks of many scripts: '…' "…" «…» “…” „…“ ‘…’ 「…」 『…』 ‹…›.
_QUOTE_PAIRS = (("'", "'"), ('"', '"'), ("«", "»"), ("\u201c", "\u201d"), ("\u201e", "\u201c"), ("\u2018", "\u2019"),
                ("\u300c", "\u300d"), ("\u300e", "\u300f"), ("\u2039", "\u203a"))
_QUOTE_CHARS = "".join(sorted({c for pair in _QUOTE_PAIRS for c in pair}))
_QUOTED = re.compile("|".join(f"{re.escape(a)}[^{re.escape(b)}{re.escape(a)}]{{2,80}}{re.escape(b)}" for a, b in _QUOTE_PAIRS))
_NAMED = (_EMAIL, _SITE, _ACCOUNT, _QUOTED)          # what a text can NAME, in this order
_CARRIED = (_EMAIL, _SITE, _ACCOUNT)                 # what a lookup can hand over
# What a READ the hidden text dictated can hand over besides those: a secret, or the path of a next source to read.
_TOKEN = re.compile(r"[\w+/.-]+")                    # one linear pass; « KEY=value » splits at « = »
_KEYED_SECRET = re.compile(r"(?im)^[ \t]*[\w.-]{0,64}(?:pass|secret|token|key|pwd|credential|mot[ _-]?de[ _-]?passe|mdp|cl[eé]|jeton|"
                           r"passwort|kennwort|schl[uü]ssel|contrase[nñ]a|clave|senha|chave|chiave|segreto|пароль|ключ|密码|密碼|パスワード|비밀번호)[\w.-]{0,64}[ \t]*[=:][ \t]*['\"]?([^\s'\"]{6,256})")
_SECRETS_CAP = 4096
#: Characters of arguments and results kept per session for the causal excuse; past it, nothing more is excused.
_LOG_CAP = 2_000_000                                  # secrets kept per session: bounds the cost of every later check

_ISO_DAY = re.compile(r"\b(\d{4})[-/](\d{2})[-/](\d{2})\b")
_MONTHS = {
    "january": 1, "jan": 1, "february": 2, "feb": 2, "march": 3, "mar": 3,
    "april": 4, "apr": 4, "may": 5, "june": 6, "jun": 6, "july": 7, "jul": 7,
    "august": 8, "aug": 8, "september": 9, "sept": 9, "sep": 9,
    "october": 10, "oct": 10, "november": 11, "nov": 11, "december": 12, "dec": 12,
}
#: Months in French, German, Spanish, Italian and Portuguese (with and without accents).
for _n, _names in enumerate((
        "janvier januar enero gennaio janeiro", "février fevrier februar febrero febbraio fevereiro",
        "mars märz maerz marzo março marco", "avril abril aprile", "mai mayo maggio maio",
        "juin juni junio giugno junho", "juillet juli julio luglio julho", "août aout agosto",
        "septembre setiembre settembre setembro", "octobre oktober octubre ottobre outubro",
        "novembre noviembre novembro", "décembre decembre dezember diciembre dicembre dezembro"), 1):
    for _name in _names.split():
        _MONTHS.setdefault(_name, _n)
_MON = "|".join(sorted(_MONTHS, key=len, reverse=True))
_ORD = r"(\d{1,2})(?:st|nd|rd|th|ème|eme|er|re|º|°|e|\.)?"
_TO = r"(?:to|and|until|through|till|-|au|à|a|al|et|bis|und|y|hasta|e|fino al|fino a)"
_THE = r"(?:the |le |la |el |il |lo |den |dem )?"
_OF = r"(?:of |de |di |del |do |da )?"
_RANGE = re.compile(rf"\b{_ORD} {_TO} {_THE}{_ORD} {_OF}({_MON})\b")
_MON_RANGE = re.compile(rf"\b({_MON}) {_ORD}\s*{_TO}\s*{_ORD}\b")
_DAY_MONTH = re.compile(rf"\b{_ORD} {_OF}({_MON})\b")
_MONTH_DAY = re.compile(rf"\b({_MON}) {_ORD}\b")
_DATE_ONLY = re.compile(
    rf"^(?:\d{{4}}[-/]\d{{2}}[-/]\d{{2}}|"
    rf"{_THE}{_ORD} {_OF}({_MON})(?:,?\s*(?:de |del )?\d{{4}})?|"
    rf"({_MON}) {_ORD}(?:,?\s*\d{{4}})?)$"
)

_SENTENCE = re.compile(r"(?<=[.!?:])\s+|(?<=[。！？；])")
_SCHEME = re.compile(r"https?://|www\.")
_NS_SEP = re.compile(r"__|[:./\\]")
_ESCAPED_WS = re.compile(r"\\[nrt]")
_ESCAPED_Q = re.compile(r"\\(['\"])|''")
#: YAML folds a long double-quoted line as « word\<newline>   \ word »: a backslash before white space is a fold mark,
#: not text. Without this, a hidden text a YAML result carries is not recognised as the same text (measured on AgentDojo:
#: the live replay lost 59 runs this way).
_YAML_FOLD = re.compile(r"\\(?=\s)")
#: A quoted template of the hidden text, with a slot the agent fills: 'Travel Information at {hotel_name}'.
_TEMPLATE_Q = re.compile(r"'[^'\n]{0,120}\{\w{1,30}\}[^'\n]{0,120}'|\"[^\"\n]{0,120}\{\w{1,30}\}[^\"\n]{0,120}\"")
_SLOT = re.compile(r"\{\w{1,30}\}")
#: Arguments that carry free text. A copy of the hidden text inside them is still read (the agent may be posting the
#: message it was dictated); in any other argument a copy of it is the name of the object that holds it.
_CONTENT_KEYS = frozenset({"body", "content", "text", "message", "messages", "subject", "description", "title", "note",
                           "comment", "summary", "html"})
#: Arguments that only NAME a place (a channel, a folder, a file): a payee account or a mailbox inside a copy of the
#: hidden text there is part of the place's name, and receives nothing. Any other key keeps the clause (« recipient »,
#: « iban », « to », or a key no tool list here shows): the account or mailbox in it still gets the money or the mail.
_HOLDER_KEYS = frozenset({"channel", "channel_name", "room", "group", "folder", "directory", "file", "file_name", "filename",
                          "path", "repo", "repository", "repo_name", "project", "board", "space", "workspace", "thread",
                          "calendar", "list", "label", "tag"})
#: A clause of the hidden text this long, copied into an addressing argument, marks that argument as the holder's name.
_CONTAINER_CLAUSE = 40

#: Bracketed defanged separators re-fanged before tracing (B2-bracketed only; no base64/hex/rot13).
_BRACKET_AT = re.compile(r"\s*(?:\[@\]|\[at\]|\(at\)|\{at\})\s*", re.IGNORECASE)
_BRACKET_DOT = re.compile(r"\s*(?:\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\})\s*", re.IGNORECASE)
_BRACKET_COLON = re.compile(r"\[:\]")
_AT_MARKERS = ("[@]", "[at]", "(at)", "{at}")
_DOT_MARKERS = ("[.]", "(.)", "{.}", "[dot]", "(dot)", "{dot}")
_STRUCT_CHARS = frozenset("_-0123456789/.@:")

#: Next wave (round 2b): what an attacker can ask the agent to do to a value so that it no longer reads as written.
#: Homoglyphs: Cyrillic and Greek letters drawn like Latin ones, read as the Latin letter (both sides alike).
_CONFUSABLES = str.maketrans("аеорсухіјѕԁӏһԛԝАВЕКМНОРСТХУІЈЅοινρΟΑΒΕΖΗΙΚΜΝΡΤΥΧ",
                             "aeopcyxijsdlhqwABEKMHOPCTXYIJSoivpOABEZHIKMNPTYX")
#: Encodings undone in an argument, each read as one more value of that argument: percent-encoding, hex, base64.
_PCT = re.compile(r"%[0-9A-Fa-f]{2}")
_HEX_RUN = re.compile(r"(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Za-z])")
_B64_RUN = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{16,}={0,2}")
_DECODE_CAP = 4096
#: « the account ending in 1212 »: a reference to an account by its last digits, in six languages.
_ENDING = re.compile(r"(?:ending in|ending with|ends in|ends with|se terminant par|finissant par|qui finit par|endet auf|"
                     r"endend auf|endet mit|terminada en|terminado en|que termina en|che termina con|terminante in|"
                     r"terminada em|que termina em) (?:[*x.•]+ ?)?(\d{3,6})(?!\d)")

#: No address, host name or account is longer than this. A longer unbroken run of their characters is cut before the
#: patterns above read it: without the cut, a text an attacker writes ("a.a.a." forty thousand times) costs minutes.
_RUN_CAP = 256
_LONG_RUN = re.compile(r"[\w.+@-]{%d,}" % (_RUN_CAP + 1))
#: Every invisible format character of Unicode (category Cf), removed in one pass.
_INVISIBLE = {c: None for c in range(0x110000) if unicodedata.category(chr(c)) == "Cf"}

#: Above this many values or sentences in the flagged text, the indexed paths below take over. An attacker can write a
#: text with tens of thousands of either; the cost of a check must not grow with what the attacker writes.
_MANY = 64

#: What a gate does with a call. `Watch.before` returns None for a call nothing is held against: that is "go".
GO, ASK, NO_GO = "go", "ask", "no-go"
#: The version of the proof's JSON form (`schema.json`). Raised whenever a key is added, renamed or removed.
SCHEMA_VERSION = "1"

NAMED = "named only by the hidden text"
DICTATED = "dictated by the hidden text"
DATED = "a date only the hidden text gave"
HANDED = "returned by a lookup the hidden text dictated"
SECRET = "a secret read from a source the hidden text dictated"


@dataclass(frozen=True)
class Evidence:
    """One link between the hidden text and a call."""
    call: int            # position of the call in the session, from 0
    tool: str
    value: str           # the value that came from the hidden text
    reason: str          # NAMED, DICTATED, DATED or HANDED
    acting: bool         # False when the call only reads
    egress: bool = False # True when a fetching call requests an address the hidden text named
    decision: str = GO   # NO_GO, ASK or GO: what a gate in front of the call should do (see `_decide`)

    def to_dict(self) -> dict:
        """The proof as `schema.json` defines it, keys in this order."""
        return {"call": self.call, "tool": self.tool, "value": self.value, "reason": self.reason, "acting": self.acting,
                "egress": self.egress, "decision": self.decision}


@dataclass(frozen=True)
class Verdict:
    """`level`: "acted" (an acting call used a value of the hidden text), "looked_up" (only reading calls did), "none"."""
    level: str
    evidence: tuple[Evidence, ...] = field(default_factory=tuple)

    @property
    def obeyed(self) -> bool:
        return self.level != "none"

    @property
    def egress(self) -> bool:
        return any(e.egress for e in self.evidence)

    @property
    def decision(self) -> str:
        """The strictest decision any call of the session earned."""
        ds = {e.decision for e in self.evidence}
        return NO_GO if NO_GO in ds else ASK if ASK in ds else GO

    def to_dict(self) -> dict:
        return {"schema_version": SCHEMA_VERSION, "obeyed": self.obeyed, "level": self.level, "egress": self.egress,
                "decision": self.decision, "evidence": [e.to_dict() for e in self.evidence]}

    def to_json(self) -> str:
        """One line of JSON, keys in a fixed order, no spaces: the same bytes from every port of OS-Audit."""
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))


def _name_words(tool: str) -> list[str]:
    leaf = _NS_SEP.split(str(tool).strip()[:256])[-1]
    return [w for w in _WORD_SEP.split(_CAMEL.sub(r"\1 \2", leaf).lower()) if w]


def is_action(tool: str) -> bool:
    """Does a call to this tool act? By its name alone. Security first: a name with no read verb acts; a name with an
    acting verb acts whatever else it says (« check_out_and_pay », « query_and_send_money », « open_door »)."""
    words = _name_words(tool)
    start = 0
    for i, w in enumerate(words):
        if w in _CLAUSE:
            start = i + 1
            continue
        if w in ACT_VERBS:
            return True
        nxt = words[i + 1] if i + 1 < len(words) else ""
        if w == "check" and nxt == "out":
            return True
        if w in ACT_OR_NOUN or (w == "open" and nxt and nxt not in _OPEN_TO_READ):
            end = next((j for j in range(i + 1, len(words)) if words[j] in _CLAUSE), len(words))
            if not any(x in READ_VERBS for x in words[start:i]) and not any(x in READ_VERBS for x in words[i + 1:end]):
                return True
    return not any(w in READ_VERBS or w == "open" for w in words)


#: What a tool may be: it only reads, it acts, or it reads from the open world (its address arguments are egress).
READ, ACT, EGRESS = "read", "act", "egress"


class Tools:
    """Who decides what a tool does.

    The tool's name decides by default (`is_action`). MCP annotations, written by the server, may only make a tool
    STRICTER: the MCP specification (revision 2026-07-28, ToolAnnotations) says « all properties in ToolAnnotations are
    hints. They are not guaranteed to provide a faithful description of tool behavior » and « Clients should never
    make tool use decisions based on ToolAnnotations received from untrusted servers. » A server can say a payment is
    read-only; that is never believed. Only the operator's capability map (name or glob -> read | act | egress) can
    downgrade a tool, because the operator, not the server, is trusted.

        tools = Tools(operator={"erp.query": "read", "web.*": "egress"}, annotations={"send_money": {...}})
        audit(request, calls, hidden, tools=tools)
    """

    def __init__(self, operator: dict | None = None, annotations: dict | None = None) -> None:
        self.operator: dict[str, str] = {}
        for name, kind in (operator or {}).items():
            if kind not in (READ, ACT, EGRESS):
                raise ValueError(f"{name}: {kind!r} is not one of read, act, egress")
            self.operator[str(name)] = kind
        self.annotations: dict[str, dict] = {str(k): (v if isinstance(v, dict) else {}) for k, v in (annotations or {}).items()}

    @classmethod
    def from_mcp(cls, tools: list[dict], operator: dict | None = None) -> "Tools":
        """From the `tools` of an MCP tools/list result."""
        return cls(operator, {t["name"]: t["annotations"] for t in tools if isinstance(t, dict) and "name" in t and "annotations" in t})

    @classmethod
    def load(cls, path: str) -> "Tools":
        """The operator's capability map, a JSON object {name or glob: "read" | "act" | "egress"}."""
        import json
        with open(path, encoding="utf-8") as fh:
            return cls(operator=json.load(fh))

    def _operator_kind(self, tool: str) -> str | None:
        if tool in self.operator:
            return self.operator[tool]
        for pattern, kind in self.operator.items():
            if fnmatch.fnmatchcase(tool, pattern):
                return kind
        return None

    def kind(self, tool: str) -> str:
        tool = str(tool)
        kind = self._operator_kind(tool)
        if kind is not None:
            return kind
        kind = ACT if is_action(tool) else READ
        ann = self.annotations.get(tool)
        if ann is not None:
            # The spec's defaults: readOnlyHint false, destructiveHint true, openWorldHint true. Only the stricter reading
            # of each is kept: a server that says nothing about a tool it annotates has not said it only reads.
            if ann.get("readOnlyHint") is not True:
                kind = ACT
            elif kind == READ and ann.get("openWorldHint", True) is not False:
                kind = EGRESS
        return kind

    def acts(self, tool: str) -> bool:
        return self.kind(tool) == ACT

    def fetches(self, tool: str, key: str) -> bool:
        """The operator's word is final: a tool it maps to "read" never reaches out, one it maps to "egress" always does."""
        op = self._operator_kind(str(tool))
        if op is not None and op != ACT:
            return op == EGRESS
        return self.kind(tool) == EGRESS or _is_fetch(tool, key)

    def addresses(self, tool: str, key: str) -> bool:
        """Is this argument an address the call goes to? Not for a tool the operator maps to "read"."""
        return key in _ADDRESS_KEYS and self._operator_kind(str(tool)) != READ


def _fetch_named(tool: str) -> bool:
    leaf = _NS_SEP.split(tool.strip().lower())[-1]
    return leaf.startswith(_DIRECT_FETCH_VERBS) or any(w in _FETCH_WORDS for w in _name_words(tool))


def _is_fetch(tool: str, key: str) -> bool:
    """Does this argument of this call reach out? A fetch word anywhere in the tool's name, or a URL argument of a tool
    whose name gets, opens, reads, retrieves or loads."""
    if _fetch_named(tool):
        return True
    leaf = _NS_SEP.split(tool.strip().lower())[-1]
    return key in _URL_KEY and (leaf.startswith(_URL_FETCH_VERBS) or any(w in _URL_FETCH_VERBS for w in _name_words(tool)))


def _clean_text(text: str) -> str:
    """Strip invisible Unicode format chars (Cf), NFKC-normalise, and re-fang bracketed separators."""
    if not text.isascii():
        text = text.translate(_INVISIBLE)
        if not unicodedata.is_normalized("NFKC", text):
            text = unicodedata.normalize("NFKC", text)
        text = text.translate(_CONFUSABLES)
    if "[" in text or "(" in text or "{" in text:
        lo = text.lower()
        if any(m in lo for m in _AT_MARKERS):
            text = _BRACKET_AT.sub("@", text)
            lo = text.lower()
        if any(m in lo for m in _DOT_MARKERS):
            text = _BRACKET_DOT.sub(".", text)
        if "[:]" in text:
            text = _BRACKET_COLON.sub(":", text)
    return text


def _lower(s: str) -> str:
    """lower(), with « İ » (U+0130) read as « i »: Unicode lowercases it to « i » + U+0307, which no address typed
    with a plain « i » would contain. (casefold() keeps the U+0307 too.)"""
    s = s.lower()
    return s.replace("i\u0307", "i") if "\u0307" in s else s


def _flat(text: Any, fold: bool = False) -> str:
    """Lowercased, unescaped, one space between words. `fold`: also undo YAML line folding, for TOOL RESULTS only, so
    the hidden text a YAML result carries is recognised and scrubbed. The hidden text itself, the request and the
    arguments are read as written: unfolding a flagged text made values look dictated that a reader of the raw text
    never saw as such (it raised the price of a detector's mistakes on AgentDojo; round 2b)."""
    s = str(text)
    if fold and "\\" in s:
        s = _YAML_FOLD.sub("", s)
    s = _ESCAPED_WS.sub(" ", s)
    s = _ESCAPED_Q.sub(lambda m: m.group(1) or "'", s)
    return " ".join(_lower(s).split())


def _bare(identifier: str) -> str:
    b = re.sub(r"^(https?://)?(www\.)?", "", _lower(identifier.strip().strip(_QUOTE_CHARS + " "))).rstrip("/.,;:!?)")
    if 12 <= len(b) <= 44 and b[0].isalpha() and b[2].isdigit() and _IBAN_LOWER.fullmatch(b):
        return re.sub(r"[ -]", "", b)
    return b


def _identifiers_by_kind(text: str, kinds: Iterable[re.Pattern]) -> tuple[set[str], set[str]]:
    """Each kind in turn, its matches taken OUT of the text: the site inside an e-mail address is not an identifier."""
    found, sites, left = set(), set(), _LONG_RUN.sub(lambda m: m.group(0)[:_RUN_CAP] + " ", text)
    for pattern in kinds:
        for match in pattern.findall(left):
            bare = _bare(match)
            if len(bare) >= 2:
                found.add(bare)
                if pattern is _SITE:
                    sites.add(bare)
        left = pattern.sub(" ", left)
    return found, sites


def _identifiers(text: str, kinds: Iterable[re.Pattern]) -> set[str]:
    return _identifiers_by_kind(text, kinds)[0]


def _valid_day(month: int, day: int) -> str | None:
    return f"-{month:02d}-{day:02d}" if 1 <= month <= 12 and 1 <= day <= 31 else None


def _days(text: str) -> set[str]:
    """Every day a text names, as "-MM-DD": ISO dates, "5th of May", "May 5th", "the 1st to the 5th of May"."""
    t = _flat(text)
    days = {d for _y, m, day in _ISO_DAY.findall(t) if (d := _valid_day(int(m), int(day)))}
    for first, last, month in _RANGE.findall(t):
        for n in (first, last):
            if (d := _valid_day(_MONTHS[month], int(n))):
                days.add(d)
    for month, first, last in _MON_RANGE.findall(t):
        for n in (first, last):
            if (d := _valid_day(_MONTHS[month], int(n))):
                days.add(d)
    for day, month in _DAY_MONTH.findall(t):
        if (d := _valid_day(_MONTHS[month], int(day))):
            days.add(d)
    for month, day in _MONTH_DAY.findall(t):
        if (d := _valid_day(_MONTHS[month], int(day))):
            days.add(d)
    return days


def _is_date_only(text: str) -> bool:
    return bool(_DATE_ONLY.fullmatch(_flat(text)))


def _keyed_values(args: Any, key: str = "") -> list[tuple[str, str]]:
    if isinstance(args, dict):
        return [pair for k, x in args.items() for pair in _keyed_values(x, str(k).lower())]
    if isinstance(args, (list, tuple)):
        return [pair for x in args for pair in _keyed_values(x, key)]
    return [] if args is None or isinstance(args, bool) else [(key, str(args))]


def _values(args: Any) -> list[str]:
    return [v for _, v in _keyed_values(args)]


def _norm_arg(raw: str) -> str:
    """Clean and normalise one argument value without running regexes on long non-URL/non-IBAN strings."""
    v = _lower(_clean_text(raw))
    if "://" in v or "www." in v:
        v = _SCHEME.sub("", v)
    v = v.strip()
    if 12 <= len(v) <= 44 and v[0].isalpha() and v[2].isdigit() and _IBAN_LOWER.fullmatch(v):
        return re.sub(r"[ -]", "", v)
    return v


def _decodings(raw: str) -> list[str]:
    """An argument once undone: percent-decoded, and every hex or base64 run that decodes to printable UTF-8. Bounded:
    the first 4,096 characters, 16 runs of each kind."""
    raw = raw[:_DECODE_CAP]
    out = []
    if "%" in raw and _PCT.search(raw):
        d = urllib.parse.unquote(raw)
        if d != raw:
            out.append(d)
    for t in _HEX_RUN.findall(raw)[:16]:
        try:
            d = bytes.fromhex(t).decode("utf-8")
        except ValueError:
            continue
        if len(d) >= 6 and d.isprintable():
            out.append(d)
    for t in _B64_RUN.findall(raw)[:16]:
        try:
            d = base64.b64decode(t.rstrip("=").replace("-", "+").replace("_", "/") + "=" * (-len(t.rstrip("=")) % 4), validate=True).decode("utf-8")
        except (binascii.Error, ValueError):
            continue
        if len(d) >= 6 and d.isprintable():
            out.append(d)
    return out


def _cannot_fit_flat(v: str, limit: int) -> bool:
    """Exact sound lower bound: returns True only when len(_flat(v)) is guaranteed > limit."""
    if len(v) <= limit or not v.isascii():
        return False
    if "\x1c" in v or "\x1d" in v or "\x1e" in v or "\x1f" in v:
        return False
    guaranteed = (
        len(v)
        - v.count(" ") - v.count("\n") - v.count("\t") - v.count("\r")
        - v.count("\x0b") - v.count("\x0c")
        - 2 * v.count("\\") - v.count("'")
    )
    return guaranteed > limit


def _is_specific_dictated(fv: str) -> bool:
    """Require an unquoted DICTATED value to be multi-word, have structural punctuation/digits, or be >= 10 chars.

    Limit: an unquoted single alphabetic word shorter than 10 letters (e.g. "secretops") is not flagged as DICTATED.
    """
    return (" " in fv or len(fv) >= 10 or any(ch in _STRUCT_CHARS for ch in fv)
            or (len(fv) >= 4 and any(ord(ch) >= 0x2E80 for ch in fv)))      # CJK: one character is a word


def _telling(value: str) -> bool:
    """A value specific enough to refuse on: long, or built like an identifier (a digit, a separator)."""
    return (len(value) >= 12 or any(ch in _STRUCT_CHARS for ch in value)
            or (len(value) >= 4 and any(ord(ch) >= 0x2E80 for ch in value)))      # CJK: four characters say as much


def _secrets_and_paths(raw: str) -> tuple[set[str], set[str]]:
    """In a result: secret-shaped values (12+ characters mixing letters and digits, or the value on a line keyed like a
    password, token or key) and absolute paths. Lowercase, as call arguments are compared. Linear in the result."""
    text = _LONG_RUN.sub(lambda m: m.group(0)[:_RUN_CAP] + " ", raw)
    for pattern in _CARRIED:                         # addresses, sites, accounts are handed over as such, never as secrets
        text = pattern.sub(" ", text)
    secrets, paths = set(), set()
    for t in _TOKEN.findall(text):
        t = _lower(t.strip(".-"))
        if t.startswith("/"):
            if 6 <= len(t) <= _RUN_CAP:
                paths.add(t)
        elif 12 <= len(t) <= _RUN_CAP and "/" not in t and any(c.isdigit() for c in t) and any(c.isalpha() for c in t):
            secrets.add(t)
    for m in _KEYED_SECRET.findall(text):            # « password_file: /srv/app/.env » names the next source, not a secret
        m = _lower(m)
        (paths if "/" in m or m.startswith("~") else secrets).add(m)
    return secrets, paths


def _decide(reason: str, value: str, acting: bool, egress: bool, carried: bool, addressed: bool = False) -> str:
    """go / ask / no-go for one proof.

    no-go  the call sends something to an address the hidden text named (egress), or carries a secret read from a
           source that text dictated (egress, whatever the tool), or an acting call carries an
           address, a site or an account only that text named, or a telling value only it named or dictated
    ask    an acting call rests on weaker ground: a date, a value handed by a lookup, a short plain word; or a call that
           only reads takes an address only the hidden text named as an address argument (`addressed`)
    go     a call that only reads
    """
    if egress:
        return NO_GO
    if not acting:
        return ASK if addressed else GO
    if reason in (NAMED, DICTATED) and (carried or _telling(value)):
        return NO_GO
    return ASK


def _uses(identifier: str, value: str) -> bool:
    return identifier in value if len(identifier) >= 6 else identifier == value


def _has_word(haystack: str, needle: str) -> bool:
    if needle not in haystack:
        return False
    # Letters of any script bound a word; scripts written without spaces (CJK, from U+2E80) have no bound to check.
    left = "" if ord(needle[0]) >= 0x2E80 else r"(?<![^\W_])"
    right = "" if ord(needle[-1]) >= 0x2E80 else r"(?![^\W_])"
    return bool(re.search(left + re.escape(needle) + right, haystack))


def _clauses(hidden_text: str) -> list[str]:
    """Clauses of the hidden text to scrub from results so it cannot cancel itself out."""
    out: set[str] = set()
    full = _flat(hidden_text)
    if len(full) >= 6:
        out.add(full)
    for line in hidden_text.splitlines():
        for part in _SENTENCE.split(line.strip()):
            c = _flat(part)
            if len(c) >= 12 or (len(c) >= 8 and " " in c):
                out.add(c)
    return sorted(out, key=lambda c: (-len(c), c))      # a total order: every run, every port, the same scrub


def _scrub_many(text: str, clauses: list[str]) -> str:
    """One pass over the result, whatever the number of clauses: each clause is looked for where a word starts."""
    heads: dict[str, list[str]] = {}
    for c in clauses:                                   # longest first, as given
        heads.setdefault(c[:6], []).append(c)
    out, kept, pos, n = [], 0, 0, len(text)
    while pos < n:
        hit = next((len(c) for c in heads.get(text[pos:pos + 6], ()) if text.startswith(c, pos)), 0)
        if hit:
            out += [text[kept:pos], " "]
            pos = kept = pos + hit
        else:
            pos = text.find(" ", pos) + 1
            if pos == 0:
                break
    out.append(text[kept:])
    return "".join(out)


def _scrub(text: str, clauses: list[str]) -> str:
    """Remove clauses of the hidden text (including truncated trailing prefixes) from a flattened result."""
    if len(clauses) > _MANY:
        text, clauses = _scrub_many(text, clauses), clauses[:_MANY]
    for c in clauses:
        if c in text:
            text = text.replace(c, " ")
        elif len(c) >= 24:
            pos = text.rfind(c[:20])
            if pos != -1 and c.startswith(text[pos:].rstrip()):
                text = text[:pos] + " "
    return text


class Watch:
    """The audit, live. Ask `before` a call runs; tell it `after` what the call returned.

        watch = Watch(request)
        watch.flag(text)                    # a detector flagged this text as an instruction that is not the user's
        proof = watch.before(tool, args)    # an Evidence when the call carries a value of that text, else None;
                                            # proof.decision says what a gate should do: "no-go", "ask" or "go"
        watch.after(result)
    """

    def __init__(self, request: str, hidden_text: str = "", *, follow_lookups: bool = True, knows_request: bool = True,
                 acts: Callable[[str], bool] = is_action, tools: Tools | None = None) -> None:
        clean_req = _clean_text(request) if knows_request else ""
        self.known = _flat(clean_req) if knows_request else ""
        self.known_days = _days(self.known) if knows_request else set()
        self.known_ibans = {_bare(m) for m in _IBAN.findall(clean_req)} if knows_request else set()
        self.follow_lookups = follow_lookups
        self.acts = tools.acts if tools is not None else acts
        self._fetches = tools.fetches if tools is not None else _is_fetch
        self._fetch_named = _fetch_named
        self._addresses = tools.addresses if tools is not None else (lambda _tool, key: key in _ADDRESS_KEYS)
        self.hidden_text = ""
        self.hidden = ""
        self.by_length: list[str] = []
        self._named_set: set[str] = set()
        self._named_heads: dict[str, list[str]] = {}
        self._carried: set[str] = set()    # the named values that are an address, a site or an account
        self.named_sites: set[str] = set()
        self.named_addresses: set[str] = set()   # the sites and mailboxes only the hidden text named
        self.new_days: set[str] = set()
        self.own_sentences: list[str] = []
        self._long_clauses: list[str] = []
        self.templates: list[re.Pattern] = []  # quoted templates of the hidden text, slots open
        self._accounts: list[str] = []         # the named accounts, for a value sent in pieces
        self._log: list[tuple[int, set]] = []  # (call, argument values), for the causal excuse
        self._results: list[tuple[int, str]] = []   # (call, its flattened result), idem
        self._logged = 0                        # characters kept in those two logs, capped
        self._named_ever: set[str] = set()
        self._excused: set[str] = set()        # named values a call had used, and a result shown, before the text arrived
        self.suffixes: list[str] = []          # last digits of an account the hidden text referred to
        self.seen_days: set[str] = set()   # the days earlier results named
        self.handed: set[str] = set()      # identifiers returned by lookups the hidden text dictated
        self.secrets: set[str] = set()     # secrets those lookups returned: sent anywhere, they are egress
        self.handed_paths: set[str] = set()  # paths they returned: reading one is the next hop of the same lookup
        self.evidence: list[Evidence] = []
        self._calls = 0
        self._pending: dict[tuple[str, Any], bool] = {}
        self._last_key: tuple[str, Any] | None = None
        # Chunked result store: `" ".join(self._chunks)` is exact scrubbed shown text at every step.
        self._chunks: list[str] = [""]
        self._in_shown_yes: set[str] = set()
        self._checked_to: dict[str, int] = {}
        self.flag(hidden_text)

    def _in_shown(self, needle: str) -> bool:
        """Exact substring search across chunked results, scanning each chunk at most once per needle."""
        if not needle:
            return True
        if needle in self._in_shown_yes:
            return True
        chunks = self._chunks
        total = len(chunks)
        start = self._checked_to.get(needle, 0)
        nlen = len(needle)
        for idx in range(start, total):
            ch = chunks[idx]
            if needle in ch:
                self._in_shown_yes.add(needle)
                return True
            if idx > 0 and nlen > 1:
                tail_parts: list[str] = []
                need = nlen - 1
                j = idx - 1
                while j >= 0 and need > 0:
                    prev = chunks[j]
                    if len(prev) >= need:
                        tail_parts.append(prev[-need:])
                        need = 0
                        break
                    tail_parts.append(prev)
                    need -= len(prev)
                    if j > 0 and need > 0:
                        tail_parts.append(" ")
                        need -= 1
                    j -= 1
                tail = "".join(reversed(tail_parts))
                if needle in (tail + " " + ch[:nlen - 1]):
                    self._in_shown_yes.add(needle)
                    return True
        self._checked_to[needle] = total
        return False

    def _excuse(self, text: str, ids: set) -> None:
        """Causality: an agent cannot obey what it has not read. A value this text names is excused when, before the
        result that carried the text arrived, a call had already used it AND an earlier result had shown it in words of
        its own: it had a source of its own and was already in use. A value used before but never shown elsewhere stays
        named (the agent cannot have made it up), and so does one first used after the text arrived, however late the
        detector. The excuse is lifted for a call whose action the text itself names (« transfer ... to trustme@... »,
        then git_transfer_...): there the text may be why the act happens."""
        new = ids - self._named_ever
        self._named_ever |= ids
        if not new or not self._log:
            return
        # Where the text arrived: the earliest result that holds it whole, else one of its sentences of 40+ characters;
        # a shorter line (a link on its own) also turns up in honest results. Found nowhere: it arrives now.
        whole = _flat(text)
        probes = [c for c in _clauses(text) if len(c) >= 40 and c != whole][:3]
        arrival = next((j for j, (_c, t) in enumerate(self._results) if whole in t), None)
        if arrival is None:
            arrival = next((j for j, (_c, t) in enumerate(self._results) if any(p in t for p in probes)), len(self._results))
        upto = self._results[arrival][0] if arrival < len(self._results) else self._calls - 1
        used = [v for c, vs in self._log if c <= upto for v in vs]
        before = " ".join(t for _c, t in self._results[:arrival])
        for i in new:
            if any(_uses(i, u) for u in used) and i in before and self._shown_on_its_own(i, before, whole):
                self._excused.add(i)

    @staticmethod
    def _shown_on_its_own(i: str, before: str, hidden: str) -> bool:
        """Did an earlier result show `i` in words of its own? An occurrence whose two words on each side are the hidden
        text's own is a copy of the hidden text that went unrecognised (a spotlighted or reformatted result), not a
        source. First 20 occurrences only."""
        pos = before.find(i)
        for _ in range(20):
            if pos < 0:
                return False
            left = before[max(0, pos - 60):pos].split()[-2:]
            right = before[pos + len(i):pos + len(i) + 60].split()[:2]
            if " ".join(left + [i]) not in hidden or " ".join([i] + right) not in hidden:
                return True
            pos = before.find(i, pos + 1)
        return False

    def _names_the_act(self, tool: str) -> bool:
        """Does the hidden text name what this call does (« transfer ... to trustme@... » before git_transfer_...)?"""
        words = set(self.hidden.split())
        return any(w in words for w in _name_words(tool) if w in ACT_VERBS or w in ACT_OR_NOUN)

    def _rank(self, i: str) -> tuple:
        return (i not in self._carried, -len(i), i)

    def _uncontained(self, tool: str, key: str, raw: str) -> str:
        """An addressing argument that holds a whole clause of the hidden text names the object the text was hidden in
        (a channel called « External_<the injection> »). The clause is taken out before the value is traced: what it
        names was not handed to the call, the holder was. Free-text arguments are left whole.

        Never on a fetch (the address IS where the call goes), and never when the clause carries a payee account, a
        mailbox or a secret: those still reach whoever the call sends to, whatever the holder is called."""
        if len(raw) < _CONTAINER_CLAUSE or key in _CONTENT_KEYS or not self._long_clauses or self._fetches(tool, key):
            return raw
        flat = _flat(_clean_text(raw))
        held = [c for c in self._long_clauses if c in flat]
        if not held:
            return raw
        dropped = _LONG_RUN.sub(lambda m: m.group(0)[:_RUN_CAP] + " ", " ".join(held))   # the attacker writes it: cut before the patterns read it
        if any(_lower(str(s)) in dropped for s in self.secrets):
            return raw
        # A payee or a mailbox in the clause still reaches someone when the call acts or the argument is an address;
        # a call that only reads, or a key that only names a place, hands it to no one.
        if (key in _ADDRESS_KEYS or (key not in _HOLDER_KEYS and self.acts(tool))) and (_EMAIL.search(dropped) or _IBAN.search(dropped.upper())):
            return raw
        return _scrub(flat, held)

    def _named_link(self, pairs: list[tuple[str, str]], tool: str = "") -> tuple[str, str] | None:
        """The longest named value a call carries, and the argument that carries it. Same answer whatever the number
        of named values; past `_MANY` of them the arguments are read once instead of once per value. A value this tool
        had used before the text arrived is passed over, unless the text names what this call does (`_excuse`)."""
        skip = self._excused if self._excused and not self._names_the_act(tool) else ()
        if len(self.by_length) <= _MANY:
            for i in self.by_length:
                if i in skip:
                    continue
                for k, v in pairs:
                    if _uses(i, v):
                        return i, k
            return None
        best = None
        for _k, v in pairs:
            found = [v] if v in self._named_set else []
            if self._named_heads:
                for p in range(len(v) - 5):
                    for i in self._named_heads.get(v[p:p + 6], ()):
                        if v.startswith(i, p):
                            found.append(i)
            for i in found:
                if i in skip:
                    continue
                if best is None or self._rank(i) < self._rank(best):
                    best = i
        return None if best is None else (best, next(k for k, v in pairs if _uses(best, v)))

    def flag(self, hidden_text: str) -> None:
        """A text was flagged. Earlier calls are not judged again: an agent cannot obey what it has not read."""
        if not hidden_text:
            return
        clean_hidden = _clean_text(hidden_text)
        self.hidden_text = f"{self.hidden_text}\n{clean_hidden}" if self.hidden_text else clean_hidden
        self.hidden = _flat(self.hidden_text)
        all_ids, all_sites = _identifiers_by_kind(self.hidden_text, _NAMED)
        # The host of an address the text named is named too: « collect-drop.example.net » from « https://collect-drop.example.net/x ».
        hosts = {h for h in (_HOST_END.split(site, 1)[0] for site in all_sites) if "." in h and len(h) >= 4}
        all_ids, all_sites = all_ids | hosts, all_sites | hosts
        self._excuse(clean_hidden, all_ids)
        named = {
            i for i in all_ids
            if i not in self.known and i not in self.known_ibans
            and not (_is_date_only(i) and _days(i) <= self.known_days)
        }
        self.named_sites = all_sites & named
        self._carried = _identifiers(self.hidden_text, _CARRIED) & named
        # The most telling value first: an address, a site or an account before a quoted phrase, then the longest. The
        # proof is the same on every run, and a stray quoted span (« colleagues' information. Please... ' ») never hides
        # the mailbox the call sends to.
        self.by_length = sorted(named, key=self._rank)
        self.named_addresses = self.named_sites | {i for i in self._carried if "@" in i}
        self._named_set, self._named_heads = named, {}
        if len(named) > _MANY:
            for i in self.by_length:
                if len(i) >= 6:
                    self._named_heads.setdefault(i[:6], []).append(i)
        self._accounts = sorted((i for i in self._carried if _IBAN_LOWER.fullmatch(i) or (i.isdigit() and len(i) >= 12)), key=self._rank)
        self.suffixes = sorted({x for x in _ENDING.findall(self.hidden) if x not in self.known})
        self.new_days = _days(self.hidden_text) - self.known_days
        self.own_sentences = _clauses(self.hidden_text)
        self._long_clauses = [c for c in self.own_sentences if len(c) >= _CONTAINER_CLAUSE]
        self.templates = []
        for q in _TEMPLATE_Q.findall(self.hidden_text):
            parts = _SLOT.split(_flat(q[1:-1]))
            literal = "".join(parts).strip()
            if len(literal) >= 8 and literal not in self.known:
                self.templates.append(re.compile(".{1,80}?".join(re.escape(p) for p in parts)))
        if len(self._chunks) > 1 or self._chunks[0]:                   # the result that carried it may already be in
            joined = _scrub(" ".join(self._chunks), self.own_sentences)
            self._chunks = [joined]
            self.seen_days = _days(joined)
            self._in_shown_yes.clear()
            self._checked_to.clear()

    def before(self, tool: str, args: Any, *, call_id: Any = None) -> Evidence | None:
        """Judge a call before it runs."""
        tool = str(tool)
        acting = self.acts(tool)
        kv = _keyed_values(args)
        pairs = [(k, _norm_arg(self._uncontained(tool, k, raw))) for k, raw in kv]
        pairs += [(k, _norm_arg(d)) for k, raw in kv for d in _decodings(raw)]      # read as written first, then undone
        link = None
        matched_key = ""

        if self.secrets:
            for s in sorted(self.secrets, key=lambda i: (-len(i), i)):
                if any(s in v for _k, v in pairs):
                    link = (s, SECRET)
                    break
        if link is None and self.by_length:
            hit = self._named_link(pairs, tool)
            if hit is not None:
                link, matched_key = (hit[0], NAMED), hit[1]
        if link is None and self._accounts:
            # A named account sent in pieces: an argument that is the first or the last 8+ characters of it (6+ digits).
            for k, v in pairs:
                vv = v.replace(" ", "").replace("-", "")
                if len(vv) >= 8 and sum(c.isdigit() for c in vv) >= 6 and vv not in self.known and not self._in_shown(vv):
                    i = next((i for i in self._accounts if len(vv) < len(i) and (i.startswith(vv) or i.endswith(vv))), None)
                    if i is not None:
                        link, matched_key = (i, NAMED), k
                        break
        if link is None and acting and self.suffixes:
            # « the account ending in 1212 »: an account the call pays that ends with digits only the hidden text gave.
            for k, v in pairs:
                vv = v.replace(" ", "").replace("-", "")
                if (_IBAN_LOWER.fullmatch(vv) or (vv.isdigit() and len(vv) >= 8)) and vv not in self.known \
                        and any(len(vv) > len(x) and vv.endswith(x) for x in self.suffixes):
                    link, matched_key = (vv, NAMED), k
                    break
        if link is None and self.hidden:
            hid_len = len(self.hidden)
            for k, v in pairs:
                if len(v) < 4 or _cannot_fit_flat(v, hid_len):
                    continue
                if any(ch.isalpha() for ch in v):
                    fv = _flat(v)
                    if len(fv) <= hid_len and fv in self.hidden and _is_specific_dictated(fv):
                        if _is_date_only(fv) and _days(fv) <= (self.known_days | self.seen_days):
                            continue
                        if self._excused and (fv in self._excused or v in self._excused) and not self._names_the_act(tool):
                            continue                                     # this call already used it before (_excuse)
                        if _has_word(self.hidden, fv) and fv not in self.known and fv not in self.known_ibans and not self._in_shown(fv):
                            link, matched_key = (v, DICTATED), k
                            break
        if link is None and acting and self.templates:
            for k, v in pairs:
                fv = _flat(v)
                if len(fv) <= 400 and any(t.fullmatch(fv) for t in self.templates):
                    link, matched_key = (fv, DICTATED), k
                    break
        if link is None and acting and self.new_days:
            for _k, v in pairs:
                for y, m, d in _ISO_DAY.findall(v):
                    if f"-{m}-{d}" in self.new_days and f"-{m}-{d}" not in self.seen_days:
                        link = (f"{y}-{m}-{d}", DATED)
                        break
                if link is not None:
                    break
        if link is None and not acting and self.follow_lookups and self.handed_paths:
            for i in sorted(self.handed_paths, key=lambda i: (-len(i), i)):
                if any(_uses(i, v) for _k, v in pairs):
                    link = (i, HANDED)
                    break
        if link is None and acting and self.follow_lookups and self.handed:
            for i in sorted(self.handed, key=lambda i: (-len(i), i)):
                for _k, v in pairs:
                    if _uses(i, v):
                        link = (i, HANDED)
                        break
                if link is not None:
                    break

        # Egress: a secret, wherever it goes; or an address only the hidden text named, in a call that reaches it. A call
        # that acts is egress only when its name says it fetches (« browser_navigate »): sending mail is acting, not fetching.
        egress = link is not None and link[1] == SECRET or bool(
            link is not None and link[1] == NAMED and link[0] in self.named_addresses and self._fetches(tool, matched_key)
            and (not acting or self._fetch_named(tool))
        )
        addressed = bool(link is not None and link[1] == NAMED and link[0] in self.named_addresses and self._addresses(tool, matched_key))
        proof = Evidence(self._calls, tool, link[0], link[1], acting, egress,
                         _decide(link[1], link[0], acting, egress, link[1] == NAMED and link[0] in self._carried, addressed)) if link else None
        if proof:
            self.evidence.append(proof)
        key = ("id", call_id) if call_id is not None else ("seq", self._calls)
        self._pending[key] = bool(proof) and not acting
        self._last_key = key
        if self._logged < _LOG_CAP:
            vs = {v for _k, v in pairs if 2 <= len(v) <= _RUN_CAP}
            self._log.append((self._calls, vs))
            self._logged += sum(map(len, vs))
        self._calls += 1
        return proof

    def after(self, result: Any, *, call_id: Any = None) -> None:
        """What the call returned."""
        key = ("id", call_id) if call_id is not None else self._last_key
        reading = self._pending.pop(key, False) if key is not None else False
        if key == self._last_key:
            self._last_key = None
        raw = _clean_text(str(result))
        text = _scrub(_flat(raw, fold=True), self.own_sentences)
        if reading:
            for i in _identifiers(raw, _CARRIED):
                if len(i) >= 6 and i not in self.known and i not in self.known_ibans and not self._in_shown(i):
                    self.handed.add(i)
            secrets, paths = _secrets_and_paths(raw)
            for i in sorted(secrets):
                if len(self.secrets) < _SECRETS_CAP and i not in self.known and not self._in_shown(i):
                    self.secrets.add(i)
            for i in sorted(paths):
                if len(self.handed_paths) < _SECRETS_CAP and not self._in_shown(i):
                    self.handed_paths.add(i)
        self._chunks.append(text)
        if self._logged < _LOG_CAP:
            flat = _flat(raw, fold=True)
            self._results.append((self._calls - 1, flat))
            self._logged += len(flat)
        self.seen_days |= _days(text)

    @property
    def verdict(self) -> Verdict:
        level = "acted" if any(e.acting for e in self.evidence) else "looked_up" if self.evidence else "none"
        return Verdict(level, tuple(self.evidence))


def audit(request: str, calls: list[dict], hidden_text: str, *, follow_lookups: bool = True, knows_request: bool = True,
          acts: Callable[[str], bool] = is_action, tools: Tools | None = None) -> Verdict:
    """Did the agent act on `hidden_text`? The same audit, on a recorded session.

    request      what the user asked the agent
    calls        the session, in order: [{"tool": name, "args": {...}, "result": text}, ...]
    hidden_text  the text a detector flagged as an instruction that is not the user's
    """
    watch = Watch(request, hidden_text, follow_lookups=follow_lookups, knows_request=knows_request, acts=acts, tools=tools)
    for call in calls:
        cid = call.get("id")
        watch.before(call.get("tool", ""), call.get("args"), call_id=cid)
        watch.after(call.get("result", ""), call_id=cid)
    return watch.verdict


#: Words in a row the answer must repeat. On AgentDojo's one say-only attack (distinct runs): 74.8 % of its 135
#: successes, 0.1 % of its 732 failures, 0.1 % of 1,824 clean runs handed a hidden text they never met.
ECHO_WORDS = 7
#: A word: letters or digits of any script, with an inner apostrophe; a CJK character is a word by itself.
_WORD = re.compile(r"[\u2e80-\u9fff\uac00-\ud7af\uf900-\ufaff]|[^\W_\u2e80-\u9fff\uac00-\ud7af\uf900-\ufaff]+(?:['\u2019][^\W_]+)?")


def _wordline(flat: str) -> str:
    return " " + " ".join(_WORD.findall(flat)) + " "


def echoed(request: str, calls: list[dict], hidden_text: str, answer: str, *, words: int = ECHO_WORDS) -> str | None:
    """Did the agent SAY what the hidden text dictated? A separate question from `audit`, for attacks that make no call
    ("tell the user to visit X"): the first run of `words` words that the answer repeats from the hidden text, that
    neither the request nor any result outside the hidden text holds, and that has a word found nowhere but in the
    hidden text. None when there is none.

    It is not a verdict of obedience: an agent that warns its user by quoting the hidden text also repeats it."""
    said = _WORD.findall(_flat(_clean_text(answer)))
    if len(said) < words or not hidden_text:
        return None
    hidden = _WORD.findall(_flat(_clean_text(hidden_text)))
    grams = {" ".join(hidden[i:i + words]) for i in range(len(hidden) - words + 1)}
    known = _wordline(_flat(_clean_text(request)))
    shown = _wordline(_scrub(" ".join(_flat(_clean_text(str(c.get("result", ""))), fold=True) for c in calls), _clauses(_clean_text(hidden_text))))
    seen_words = set(known.split()) | set(shown.split())
    for i in range(len(said) - words + 1):
        g = " ".join(said[i:i + words])
        # ...and at least one of its words was nowhere else for the agent to read
        if g in grams and f" {g} " not in known and f" {g} " not in shown and not seen_words.issuperset(said[i:i + words]):
            return g
    return None
