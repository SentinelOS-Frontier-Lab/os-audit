// OS-Audit, TypeScript port of src/os_audit/core.py (one file, no dependency). Node 24 or Bun run it as it is.
//
// The Python engine is the reference: every proof this port gives must be byte-identical to Python's `to_json()`,
// checked by ports/ts/conformance.ts on the golden corpus (ports/golden/). Where JavaScript and Python differ, this
// file does what Python does:
//   * Python's \w, \d, \s and \b read Unicode; JavaScript's do not, even with the u flag. They are spelled out below
//     (W, D, S, B) as Unicode classes and lookarounds.
//   * Python counts code points; JavaScript counts UTF-16 units. Every length, slice and order that decides an answer
//     goes through plen / pslice / pcmp.
//   * Python's str.split(), strip(), splitlines(), re.split and int() have their own rules; py* helpers copy them.
//   * Numbers: Python writes 100.0 as "100.0". A PyNum keeps the JSON lexeme so a value reads as Python read it.
// The freeze fixes of the Python engine are kept: the long-run cut before any pattern reads attacker text, the one-pass
// scrub for many clauses, the indexed lookup for many named values.

// ---------------------------------------------------------------- Python string and regex semantics

const WORD = String.raw`\p{L}\p{N}_`;                       // Python's \w (str patterns)
const W = `[${WORD}]`;
const S_SET = String.raw`\t\n\x0b\x0c\r\x1c-\x1f \x85\xa0  - \u2028\u2029  　`;
const S = `[${S_SET}]`;                                     // Python's \s and str.isspace()
const D = String.raw`\p{Nd}`;                               // Python's \d
const B = `(?:(?<=${W})(?!${W})|(?<!${W})(?=${W}))`;        // Python's \b
const SURROGATE = /[\uD800-\uDFFF]/;
const WS_RUN = new RegExp(`${S}+`, "gu");

export function plen(s: string): number {
  if (!SURROGATE.test(s)) return s.length;
  let n = 0;
  for (const _ of s) n++;
  return n;
}

function pslice(s: string, a: number, b?: number): string {
  if (!SURROGATE.test(s)) return s.slice(a, b);
  return Array.from(s).slice(a, b).join("");
}

function pchars(s: string): string[] {
  return Array.from(s);
}

function pcmp(a: string, b: string): number {
  if (!SURROGATE.test(a) && !SURROGATE.test(b)) return a < b ? -1 : a > b ? 1 : 0;
  const x = Array.from(a), y = Array.from(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const d = x[i].codePointAt(0)! - y[i].codePointAt(0)!;
    if (d) return d < 0 ? -1 : 1;
  }
  return x.length - y.length < 0 ? -1 : x.length > y.length ? 1 : 0;
}

const byLengthThenText = (a: string, b: string) => plen(b) - plen(a) || pcmp(a, b);
const sortedText = (xs: Iterable<string>) => [...xs].sort(pcmp);

function pySplit(s: string): string[] {
  return s.split(WS_RUN).filter((x) => x !== "");
}

const PY_SPACE = new Set(Array.from("\t\n\x0b\x0c\r\x1c\x1d\x1e\x1f \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"));

// Every character these strip is in the BMP: scanning UTF-16 units from either end is exact and linear.
function pyStrip(s: string, chars?: string): string {
  const set = chars === undefined ? PY_SPACE : new Set(Array.from(chars));
  let i = 0, j = s.length;
  while (i < j && set.has(s[i])) i++;
  while (j > i && set.has(s[j - 1])) j--;
  return s.slice(i, j);
}

function pyRstrip(s: string, chars?: string): string {
  const set = chars === undefined ? PY_SPACE : new Set(Array.from(chars));
  let j = s.length;
  while (j > 0 && set.has(s[j - 1])) j--;
  return s.slice(0, j);
}

function pySplitlines(s: string): string[] {
  if (s === "") return [];
  const parts = s.split(/\r\n|[\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029]/);
  if (parts[parts.length - 1] === "") parts.pop();
  return parts;
}

/** re.split: every match splits, empty ones included (JavaScript's split skips an empty match at a split point). */
function pyReSplit(re: RegExp, s: string): string[] {
  const out: string[] = [];
  let last = 0;
  for (const m of s.matchAll(re)) {
    out.push(s.slice(last, m.index));
    last = m.index! + m[0].length;
  }
  out.push(s.slice(last));
  return out;
}

const NDIGIT = /^\p{Nd}$/u;
function digitValue(ch: string): number {
  const cp = ch.codePointAt(0)!;
  if (cp >= 48 && cp <= 57) return cp - 48;
  let z = cp;
  while (NDIGIT.test(String.fromCodePoint(z - 1))) z--;   // Unicode digits come in aligned runs of ten
  return (cp - z) % 10;
}

function pyInt(s: string): number {
  let n = 0;
  for (const ch of s) n = n * 10 + digitValue(ch);
  return n;
}

const isAlpha = (c: string) => /^\p{L}$/u.test(c);
const isDigit = (c: string) => NDIGIT.test(c);
const isAscii = (s: string) => /^[\x00-\x7f]*$/.test(s);
const reEscape = (s: string) => s.replace(/[\\^$.*+?()[\]{}|\/]/g, "\\$&");
const pad2 = (n: number) => (n < 10 ? "0" : "") + n;

/** A JSON number as Python read it: the lexeme json.load saw (int stays int, 100.0 stays "100.0"). */
export class PyNum {
  readonly raw: string;
  constructor(raw: string) { this.raw = raw; }
  toString(): string {
    return this.raw === "Infinity" ? "inf" : this.raw === "-Infinity" ? "-inf" : this.raw === "NaN" ? "nan" : this.raw;
  }
}

/** str(x) of a float, as Python's repr writes it (shortest digits; fixed from 1e-4 to 1e16, else 1e+16). */
export function pyFloatRepr(x: number): string {
  if (Number.isNaN(x)) return "nan";
  if (!Number.isFinite(x)) return x > 0 ? "inf" : "-inf";
  if (x === 0) return Object.is(x, -0) ? "-0.0" : "0.0";
  const [mant, e] = x.toExponential().split("e");
  const exp = parseInt(e, 10);
  const neg = mant.startsWith("-");
  const digits = mant.replace("-", "").replace(".", "");
  let out: string;
  if (exp < -4 || exp >= 16) {
    out = digits[0] + (digits.length > 1 ? "." + digits.slice(1) : "") + "e" + (exp < 0 ? "-" : "+") + pad2(Math.abs(exp));
  } else if (exp >= 0) {
    const intPart = digits.length > exp + 1 ? digits.slice(0, exp + 1) : digits + "0".repeat(exp + 1 - digits.length);
    const frac = digits.length > exp + 1 ? digits.slice(exp + 1) : "0";
    out = intPart + "." + frac;
  } else {
    out = "0." + "0".repeat(-exp - 1) + digits;
  }
  return (neg ? "-" : "") + out;
}

function pyStr(x: unknown): string {
  if (x === null || x === undefined) return "None";
  if (typeof x === "string") return x;
  if (typeof x === "boolean") return x ? "True" : "False";
  if (x instanceof PyNum) return x.toString();
  if (typeof x === "number") return Number.isInteger(x) && Math.abs(x) < 1e16 ? String(x) : pyFloatRepr(x);
  if (typeof x === "bigint") return x.toString();
  return String(x);
}

function sub(re: RegExp, s: string, by: string | ((...m: any[]) => string)): string {
  return s.replace(re, by as any);
}

function findall(re: RegExp, s: string): any[] {
  const out: any[] = [];
  for (const m of s.matchAll(re)) out.push(m.length <= 1 ? m[0] : m.length === 2 ? (m[1] ?? "") : m.slice(1).map((g) => g ?? ""));
  return out;
}

// ---------------------------------------------------------------- the patterns of core.py, one for one

export const READ_VERBS = new Set(`get gets search list read check find view show lookup look fetch query browse retrieve count verify
describe inspect preview think
lire lister chercher rechercher obtenir afficher consulter trouver voir buscar leer mostrar consultar listar obtener ler procurar
suche suchen lese lesen anzeigen zeige zeigen abrufen hole holen auflisten cerca cercare leggi leggere elenca elencare ottieni
ottenere mostra mostrare trova trovare`.split(/\s+/));
export const ACT_VERBS = new Set(`send pay buy checkout delete del remove rm destroy purge erase wipe truncate kill terminate shutdown reboot
create insert write update upsert modify edit rename upload install uninstall execute exec submit cancel append overwrite merge
revoke grant clear add reset restore launch publish unlock donate reserve reschedule withdraw approve
envoyer payer virer supprimer effacer créer creer ajouter modifier publier partager réserver reserver annuler acheter commander
transférer transferer enviar pagar transferir eliminar borrar crear añadir anadir agregar actualizar modificar publicar compartir
reservar cancelar comprar excluir apagar criar adicionar atualizar compartilhar senden zahlen bezahlen überweisen ueberweisen
löschen loeschen loesche lösche erstellen hinzufügen hinzufuegen ändern aendern aktualisieren veröffentlichen teilen buchen
stornieren kaufen bestellen inviare pagare trasferire eliminare cancellare creare aggiungere modificare aggiornare pubblicare
condividere prenotare annullare acquistare ordinare`.split(/\s+/));
export const ACT_OR_NOUN = new Set(`transfer purchase sell deposit refund restart stake unstake assign unassign follow unfollow fork forward
reply schedule transact swap move archive enable disable ban unban kick click fill type press drag hover select save sync set put
patch replace drop dial sms tweet retweet upvote downvote subscribe unsubscribe register enroll apply order book post share message
mail email comment call star like run start stop close block lock change copy rent trade bid tip charge release notify play pin
tag label mark vote rate print return exchange ship deliver mute unmute trigger import empty mount unmount format attach detach
link unlink connect disconnect login logout authorize lend borrow repay bridge claim invite deploy commit push reject decline
accept`.split(/\s+/));
const OPEN_TO_READ = new Set("file url page link document doc tab website webpage browser folder directory dir image pdf path site uri".split(" "));
const CLAUSE = new Set(["and", "then", "et", "y", "und", "e"]);
const CAMEL = /([a-z0-9])([A-Z])/g;
const WORD_SEP = /[^\p{L}\p{N}]+/u;                          // Python's [\W_]+
const DIRECT_FETCH_VERBS = ["fetch", "browse", "curl", "wget", "download", "http"];
const URL_FETCH_VERBS = ["get", "open", "read", "retrieve", "load"];
const URL_KEY = new Set(["url", "uri", "href", "endpoint", "link", "website", "webpage", "host", "target_url"]);
const FETCH_WORDS = new Set("fetch download curl wget http https navigate browse crawl scrape visit goto".split(" "));
const ADDRESS_KEYS = new Set([...URL_KEY, "address", "to", "recipient", "recipients", "cc", "bcc"]);
const HOST_END = /[/?#]/;

const TLD = "com|org|net|io|co|ai|dev|info|biz|me|xyz|app|fr|de|uk|eu|ch|nl|ca|au|jp|cn|ru|br|" +
  "edu|gov|mil|tech|cloud|site|online|shop|top|gg|cc|tv|ly|onion|" +
  "es|it|pt|be|pl|se|dk|fi|cz|lu|mc|ma|tn|sn|dz|ci|cm|re|kr|mx|ar|cl|nz|za|ie|gr|tr|ro|hu|sk|hr|ua|il|sg|hk|tw|swiss|paris|bzh";
const IPV4 = `(?:(?:25[0-5]|2[0-4]${D}|1?${D}?${D})\\.){3}(?:25[0-5]|2[0-4]${D}|1?${D}?${D})`;
const EMAIL = new RegExp(`[${WORD}.+-]+@[${WORD}-]+\\.[${WORD}.-]+`, "gu");
const SITE = new RegExp(
  `https?://[^${S_SET}<>'"()\\[\\]{}]+|` +
  `${B}(?:www\\.)?(?:[${WORD}-]+\\.)+(?:${TLD})(?::${D}{1,5})?(?:/[${WORD}./?=&%+-]*)?|` +
  `${B}${IPV4}(?::${D}{1,5})?(?:/[${WORD}./?=&%+-]*)?${B}`, "giu");
const IBAN = new RegExp(`${B}[A-Z]{2}${D}{2}(?:[ -]?[A-Z0-9]{4}){2,7}(?:[ -]?[A-Z0-9]{1,4})?${B}`, "gu");
const IBAN_LOWER = new RegExp(`^[a-z]{2}${D}{2}(?:[ -]?[a-z0-9]{4}){2,7}(?:[ -]?[a-z0-9]{1,4})?$`, "u");
const ACCOUNT = new RegExp(`${B}[A-Z]{2}${D}{2}(?:[ -]?[A-Z0-9]{4}){2,7}(?:[ -]?[A-Z0-9]{1,4})?${B}|${B}${D}{5,}${B}`, "gu");
const QUOTE_PAIRS: [string, string][] = [["'", "'"], ['"', '"'], ["«", "»"], ["“", "”"], ["„", "“"],
  ["‘", "’"], ["「", "」"], ["『", "』"], ["‹", "›"]];
const QUOTE_CHARS = [...new Set(QUOTE_PAIRS.flat())].sort(pcmp).join("");
const QUOTED = new RegExp(QUOTE_PAIRS.map(([a, b]) => `${reEscape(a)}[^${reEscape(b)}${reEscape(a)}]{2,80}${reEscape(b)}`).join("|"), "gu");
const NAMED_KINDS = [EMAIL, SITE, ACCOUNT, QUOTED];
const CARRIED = [EMAIL, SITE, ACCOUNT];
const TOKEN = new RegExp(`[${WORD}+/.-]+`, "gu");
const KEYED_SECRET = new RegExp(
  `(?<![^\\n])[ \\t]*[${WORD}.-]{0,64}(?:pass|secret|token|key|pwd|credential|mot[ _-]?de[ _-]?passe|mdp|cl[eé]|jeton|` +
  `passwort|kennwort|schl[uü]ssel|contrase[nñ]a|clave|senha|chave|chiave|segreto|пароль|ключ|密码|密碼|パスワード|비밀번호)` +
  `[${WORD}.-]{0,64}[ \\t]*[=:][ \\t]*['"]?([^${S_SET}'"]{6,256})`, "giu");
const SECRETS_CAP = 4096;
const LOG_CAP = 2_000_000;

const ISO_DAY = new RegExp(`${B}(${D}{4})[-/](${D}{2})[-/](${D}{2})${B}`, "gu");
const MONTHS = new Map<string, number>([
  ["january", 1], ["jan", 1], ["february", 2], ["feb", 2], ["march", 3], ["mar", 3],
  ["april", 4], ["apr", 4], ["may", 5], ["june", 6], ["jun", 6], ["july", 7], ["jul", 7],
  ["august", 8], ["aug", 8], ["september", 9], ["sept", 9], ["sep", 9],
  ["october", 10], ["oct", 10], ["november", 11], ["nov", 11], ["december", 12], ["dec", 12]]);
["janvier januar enero gennaio janeiro", "février fevrier februar febrero febbraio fevereiro",
  "mars märz maerz marzo março marco", "avril abril aprile", "mai mayo maggio maio",
  "juin juni junio giugno junho", "juillet juli julio luglio julho", "août aout agosto",
  "septembre setiembre settembre setembro", "octobre oktober octubre ottobre outubro",
  "novembre noviembre novembro", "décembre decembre dezember diciembre dicembre dezembro"].forEach((names, i) => {
  for (const n of names.split(" ")) if (!MONTHS.has(n)) MONTHS.set(n, i + 1);
});
const MON = [...MONTHS.keys()].map((k, i) => [k, i] as [string, number]).sort((a, b) => plen(b[0]) - plen(a[0]) || a[1] - b[1]).map((x) => x[0]).join("|");
const ORD = `(${D}{1,2})(?:st|nd|rd|th|ème|eme|er|re|º|°|e|\\.)?`;
const TO = "(?:to|and|until|through|till|-|au|à|a|al|et|bis|und|y|hasta|e|fino al|fino a)";
const THE = "(?:the |le |la |el |il |lo |den |dem )?";
const OF = "(?:of |de |di |del |do |da )?";
const RANGE = new RegExp(`${B}${ORD} ${TO} ${THE}${ORD} ${OF}(${MON})${B}`, "gu");
const MON_RANGE = new RegExp(`${B}(${MON}) ${ORD}${S}*${TO}${S}*${ORD}${B}`, "gu");
const DAY_MONTH = new RegExp(`${B}${ORD} ${OF}(${MON})${B}`, "gu");
const MONTH_DAY = new RegExp(`${B}(${MON}) ${ORD}${B}`, "gu");
const DATE_ONLY = new RegExp(`^(?:${D}{4}[-/]${D}{2}[-/]${D}{2}|${THE}${ORD} ${OF}(${MON})(?:,?${S}*(?:de |del )?${D}{4})?|(${MON}) ${ORD}(?:,?${S}*${D}{4})?)$`, "u");

const SENTENCE = new RegExp(`(?<=[.!?:])${S}+|(?<=[。！？；])`, "gu");
const SCHEME = /https?:\/\/|www\./g;
const NS_SEP = /__|[:./\\]/;
const ESCAPED_WS = /\\[nrt]/g;
const ESCAPED_Q = /\\(['"])|''/g;
const YAML_FOLD = new RegExp(`\\\\(?=${S})`, "gu");
const TEMPLATE_Q = new RegExp(`'[^'\\n]{0,120}\\{[${WORD}]{1,30}\\}[^'\\n]{0,120}'|"[^"\\n]{0,120}\\{[${WORD}]{1,30}\\}[^"\\n]{0,120}"`, "gu");
const SLOT = new RegExp(`\\{[${WORD}]{1,30}\\}`, "gu");
const CONTENT_KEYS = new Set(["body", "content", "text", "message", "messages", "subject", "description", "title", "note", "comment", "summary", "html"]);
const CONTAINER_CLAUSE = 40;
const HOLDER_KEYS = new Set(["channel", "channel_name", "room", "group", "folder", "directory", "file", "file_name", "filename",
  "path", "repo", "repository", "repo_name", "project", "board", "space", "workspace", "thread", "calendar", "list", "label", "tag"]);

const BRACKET_AT = new RegExp(`${S}*(?:\\[@\\]|\\[at\\]|\\(at\\)|\\{at\\})${S}*`, "giu");
const BRACKET_DOT = new RegExp(`${S}*(?:\\[\\.\\]|\\(\\.\\)|\\{\\.\\}|\\[dot\\]|\\(dot\\)|\\{dot\\})${S}*`, "giu");
const BRACKET_COLON = /\[:\]/g;
const AT_MARKERS = ["[@]", "[at]", "(at)", "{at}"];
const DOT_MARKERS = ["[.]", "(.)", "{.}", "[dot]", "(dot)", "{dot}"];
const STRUCT_CHARS = new Set("_-0123456789/.@:");

const CONFUSABLE_FROM = "аеорсухіјѕԁӏһԛԝАВЕКМНОРСТХУІЈЅοινρΟΑΒΕΖΗΙΚΜΝΡΤΥΧ";
const CONFUSABLE_TO = "aeopcyxijsdlhqwABEKMHOPCTXYIJSoivpOABEZHIKMNPTYX";
const CONFUSABLES = new Map(Array.from(CONFUSABLE_FROM).map((c, i) => [c, CONFUSABLE_TO[i]]));
const CONFUSABLE_RE = new RegExp(`[${CONFUSABLE_FROM}]`, "gu");
const PCT = /%[0-9A-Fa-f]{2}/;
const HEX_RUN = /(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Za-z])/g;
const B64_RUN = /(?<![A-Za-z0-9+\/_=-])[A-Za-z0-9+\/_-]{16,}={0,2}/g;
const DECODE_CAP = 4096;
const ENDING = new RegExp("(?:ending in|ending with|ends in|ends with|se terminant par|finissant par|qui finit par|endet auf|" +
  "endend auf|endet mit|terminada en|terminado en|que termina en|che termina con|terminante in|terminada em|que termina em) " +
  `(?:[*x.•]+ ?)?(${D}{3,6})(?!${D})`, "gu");
const UTF8 = new TextDecoder("utf-8", { fatal: true });
const UTF8_LOOSE = new TextDecoder("utf-8");
// Python's str.isprintable(): no control, format, separator other than the space, surrogate, private or unassigned.
const PRINTABLE = /^[^\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}\p{Co}\p{Cn}\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]*$/u;

function pctDecode(s: string): string {
  // urllib.parse.unquote: runs of %XX become bytes decoded as UTF-8, invalid sequences replaced.
  return s.replace(/(?:%[0-9A-Fa-f]{2})+/g, (run) => {
    const bytes = new Uint8Array(run.length / 3);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(run.slice(3 * i + 1, 3 * i + 3), 16);
    return UTF8_LOOSE.decode(bytes);
  });
}

function decodings(raw: string): string[] {
  raw = pslice(raw, 0, DECODE_CAP);
  const out: string[] = [];
  if (raw.includes("%") && PCT.test(raw)) {
    const d = pctDecode(raw);
    if (d !== raw) out.push(d);
  }
  const ok = (bytes: Uint8Array) => {
    try {
      const d = UTF8.decode(bytes);
      if (plen(d) >= 6 && PRINTABLE.test(d)) out.push(d);
    } catch { /* not UTF-8 */ }
  };
  for (const t of (raw.match(HEX_RUN) ?? []).slice(0, 16)) {
    const b = new Uint8Array(t.length / 2);
    for (let i = 0; i < b.length; i++) b[i] = parseInt(t.slice(2 * i, 2 * i + 2), 16);
    ok(b);
  }
  for (const t of (raw.match(B64_RUN) ?? []).slice(0, 16)) {
    const core = t.replace(/=+$/, "").replace(/-/g, "+").replace(/_/g, "/");
    if (core.length % 4 === 1) continue;                    // Python: « Invalid base64-encoded string »
    let bin: string;
    try { bin = atob(core + "=".repeat((4 - (core.length % 4)) % 4)); } catch { continue; }
    ok(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
  }
  return out;
}

const RUN_CAP = 256;
const LONG_RUN = new RegExp(`[${WORD}.+@-]{${RUN_CAP + 1},}`, "gu");
const cutLongRuns = (s: string) => sub(LONG_RUN, s, (m: string) => pslice(m, 0, RUN_CAP) + " ");
const INVISIBLE = /\p{Cf}/gu;
const MANY = 64;

export const GO = "go", ASK = "ask", NO_GO = "no-go";
export const SCHEMA_VERSION = "1";
export const NAMED = "named only by the hidden text";
export const DICTATED = "dictated by the hidden text";
export const DATED = "a date only the hidden text gave";
export const HANDED = "returned by a lookup the hidden text dictated";
export const SECRET = "a secret read from a source the hidden text dictated";

// ---------------------------------------------------------------- proof

export class Evidence {
  readonly call: number; readonly tool: string; readonly value: string; readonly reason: string;
  readonly acting: boolean; readonly egress: boolean; readonly decision: string;
  constructor(call: number, tool: string, value: string, reason: string, acting: boolean, egress = false, decision: string = GO) {
    this.call = call; this.tool = tool; this.value = value; this.reason = reason; this.acting = acting; this.egress = egress; this.decision = decision;
  }
  toDict() {
    return { call: this.call, tool: this.tool, value: this.value, reason: this.reason, acting: this.acting, egress: this.egress, decision: this.decision };
  }
}

export class Verdict {
  readonly level: string; readonly evidence: Evidence[];
  constructor(level: string, evidence: Evidence[] = []) { this.level = level; this.evidence = evidence; }
  get obeyed(): boolean { return this.level !== "none"; }
  get egress(): boolean { return this.evidence.some((e) => e.egress); }
  get decision(): string {
    const ds = new Set(this.evidence.map((e) => e.decision));
    return ds.has(NO_GO) ? NO_GO : ds.has(ASK) ? ASK : GO;
  }
  toDict() {
    return { schema_version: SCHEMA_VERSION, obeyed: this.obeyed, level: this.level, egress: this.egress, decision: this.decision,
      evidence: this.evidence.map((e) => e.toDict()) };
  }
  /** One line, keys in schema order: the same bytes as Python's Verdict.to_json(). */
  toJson(): string { return JSON.stringify(this.toDict()); }
}

// ---------------------------------------------------------------- which tools act

function nameWords(tool: string): string[] {
  const leaf = pslice(pyStrip(String(tool)), 0, 256).split(NS_SEP).pop()!;
  return leaf.replace(CAMEL, "$1 $2").toLowerCase().split(WORD_SEP).filter((w) => w !== "");
}

export function isAction(tool: string): boolean {
  const words = nameWords(tool);
  let start = 0;
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    if (CLAUSE.has(w)) { start = i + 1; continue; }
    if (ACT_VERBS.has(w)) return true;
    const nxt = i + 1 < words.length ? words[i + 1] : "";
    if (w === "check" && nxt === "out") return true;
    if (ACT_OR_NOUN.has(w) || (w === "open" && nxt && !OPEN_TO_READ.has(nxt))) {
      let end = words.length;
      for (let j = i + 1; j < words.length; j++) if (CLAUSE.has(words[j])) { end = j; break; }
      if (!words.slice(start, i).some((x) => READ_VERBS.has(x)) && !words.slice(i + 1, end).some((x) => READ_VERBS.has(x))) return true;
    }
  }
  return !words.some((w) => READ_VERBS.has(w) || w === "open");
}

export const READ = "read", ACT = "act", EGRESS = "egress";
type Dict = Map<string, unknown> | Record<string, unknown>;
const entries = (d: Dict | null | undefined): [string, unknown][] => (d == null ? [] : d instanceof Map ? [...d.entries()] : Object.entries(d));

function fnmatchcase(name: string, pat: string): boolean {
  let re = "", i = 0;
  const p = pchars(pat);
  while (i < p.length) {
    const c = p[i++];
    if (c === "*") re += ".*";
    else if (c === "?") re += ".";
    else if (c === "[") {
      let j = i;
      if (j < p.length && p[j] === "!") j++;
      if (j < p.length && p[j] === "]") j++;
      while (j < p.length && p[j] !== "]") j++;
      if (j >= p.length) re += "\\[";
      else {
        let stuff = p.slice(i, j).join("").replace(/\\/g, "\\\\");
        i = j + 1;
        if (stuff.startsWith("!")) stuff = "^" + stuff.slice(1);
        else if (stuff.startsWith("^")) stuff = "\\" + stuff;
        re += `[${stuff.replace(/[\]\[]/g, "\\$&")}]`;
      }
    } else re += reEscape(c);
  }
  return new RegExp(`^(?:${re})$`, "su").test(name);
}

/** Who decides what a tool does: its name (isAction); MCP annotations only ever make it stricter (MCP 2026-07-28:
 *  « Clients should never make tool use decisions based on ToolAnnotations received from untrusted servers. »);
 *  only the operator's map may downgrade. */
export class Tools {
  readonly operator: [string, string][] = [];
  readonly annotations = new Map<string, Map<string, unknown>>();
  constructor(operator?: Dict | null, annotations?: Dict | null) {
    for (const [name, kind] of entries(operator)) {
      if (kind !== READ && kind !== ACT && kind !== EGRESS) throw new Error(`${name}: ${String(kind)} is not one of read, act, egress`);
      this.operator.push([String(name), kind as string]);
    }
    for (const [name, ann] of entries(annotations)) {
      const m = ann instanceof Map ? ann : ann && typeof ann === "object" && !Array.isArray(ann) ? new Map(Object.entries(ann as object)) : new Map();
      this.annotations.set(String(name), m as Map<string, unknown>);
    }
  }
  private operatorKind(tool: string): string | null {
    for (const [name, kind] of this.operator) if (name === tool) return kind;
    for (const [pattern, kind] of this.operator) if (fnmatchcase(tool, pattern)) return kind;
    return null;
  }
  kind(tool: string): string {
    tool = String(tool);
    const op = this.operatorKind(tool);
    if (op !== null) return op;
    let kind = isAction(tool) ? ACT : READ;
    const ann = this.annotations.get(tool);
    if (ann !== undefined) {
      if (ann.get("readOnlyHint") !== true) kind = ACT;
      else if (kind === READ && (ann.has("openWorldHint") ? ann.get("openWorldHint") : true) !== false) kind = EGRESS;
    }
    return kind;
  }
  acts(tool: string): boolean { return this.kind(tool) === ACT; }
  fetches(tool: string, key: string): boolean {
    const op = this.operatorKind(String(tool));
    if (op !== null && op !== ACT) return op === EGRESS;
    return this.kind(tool) === EGRESS || isFetch(tool, key);
  }
  addresses(tool: string, key: string): boolean { return ADDRESS_KEYS.has(key) && this.operatorKind(String(tool)) !== READ; }
}

function fetchNamed(tool: string): boolean {
  const leaf = pyStrip(String(tool)).toLowerCase().split(NS_SEP).pop()!;
  return DIRECT_FETCH_VERBS.some((v) => leaf.startsWith(v)) || nameWords(tool).some((w) => FETCH_WORDS.has(w));
}

function isFetch(tool: string, key: string): boolean {
  if (fetchNamed(tool)) return true;
  const leaf = pyStrip(String(tool)).toLowerCase().split(NS_SEP).pop()!;
  return URL_KEY.has(key) && (URL_FETCH_VERBS.some((v) => leaf.startsWith(v)) || nameWords(tool).some((w) => URL_FETCH_VERBS.includes(w)));
}

// ---------------------------------------------------------------- text

function cleanText(text: string): string {
  if (!isAscii(text)) {
    text = text.replace(INVISIBLE, "").normalize("NFKC");
    text = text.replace(CONFUSABLE_RE, (c) => CONFUSABLES.get(c)!);
  }
  if (text.includes("[") || text.includes("(") || text.includes("{")) {
    let lo = text.toLowerCase();
    if (AT_MARKERS.some((m) => lo.includes(m))) {
      text = sub(BRACKET_AT, text, "@");
      lo = text.toLowerCase();
    }
    if (DOT_MARKERS.some((m) => lo.includes(m))) text = sub(BRACKET_DOT, text, ".");
    if (text.includes("[:]")) text = sub(BRACKET_COLON, text, ":");
  }
  return text;
}

/** lower(), with « İ » read as « i » (Unicode lowercases it to « i » + U+0307). */
function lower(s: string): string {
  s = s.toLowerCase();
  return s.includes("\u0307") ? s.split("i\u0307").join("i") : s;
}

/** `fold`: undo YAML line folding, for tool results only (core.py _flat). */
function flat(text: unknown, fold = false): string {
  let s = pyStr(text);
  if (fold && s.includes("\\")) s = sub(YAML_FOLD, s, "");
  s = sub(ESCAPED_WS, s, " ");
  s = sub(ESCAPED_Q, s, (_m: string, g1?: string) => g1 ?? "'");
  return pySplit(lower(s)).join(" ");
}

function bare(identifier: string): string {
  let b = lower(pyStrip(pyStrip(identifier), QUOTE_CHARS + " "));
  b = pyRstrip(b.replace(/^(https?:\/\/)?(www\.)?/, ""), "/.,;:!?)");
  const n = plen(b);
  if (n >= 12 && n <= 44) {
    const c = pchars(b);
    if (isAlpha(c[0]) && isDigit(c[2]) && IBAN_LOWER.test(b)) return b.replace(/[ -]/g, "");
  }
  return b;
}

function identifiersByKind(text: string, kinds: RegExp[]): [Set<string>, Set<string>] {
  const found = new Set<string>(), sites = new Set<string>();
  let left = cutLongRuns(text);
  for (const pattern of kinds) {
    for (const match of findall(pattern, left) as string[]) {
      const b = bare(match);
      if (plen(b) >= 2) {
        found.add(b);
        if (pattern === SITE) sites.add(b);
      }
    }
    left = sub(pattern, left, " ");
  }
  return [found, sites];
}

const identifiers = (text: string, kinds: RegExp[]) => identifiersByKind(text, kinds)[0];

function validDay(month: number, day: number): string | null {
  return month >= 1 && month <= 12 && day >= 1 && day <= 31 ? `-${pad2(month)}-${pad2(day)}` : null;
}

function days(text: string): Set<string> {
  const t = flat(text);
  const out = new Set<string>();
  const add = (d: string | null) => { if (d) out.add(d); };
  for (const [, m, d] of findall(ISO_DAY, t)) add(validDay(pyInt(m), pyInt(d)));
  for (const [first, last, month] of findall(RANGE, t)) for (const n of [first, last]) add(validDay(MONTHS.get(month)!, pyInt(n)));
  for (const [month, first, last] of findall(MON_RANGE, t)) for (const n of [first, last]) add(validDay(MONTHS.get(month)!, pyInt(n)));
  for (const [day, month] of findall(DAY_MONTH, t)) add(validDay(MONTHS.get(month)!, pyInt(day)));
  for (const [month, day] of findall(MONTH_DAY, t)) add(validDay(MONTHS.get(month)!, pyInt(day)));
  return out;
}

const isDateOnly = (text: string) => DATE_ONLY.test(flat(text));
const subset = (a: Set<string>, b: Set<string>) => [...a].every((x) => b.has(x));

function keyedValues(args: unknown, key = ""): [string, string][] {
  if (args instanceof Map) return [...args.entries()].flatMap(([k, x]) => keyedValues(x, pyStr(k).toLowerCase()));
  if (Array.isArray(args)) return args.flatMap((x) => keyedValues(x, key));
  if (args !== null && typeof args === "object" && !(args instanceof PyNum)) return Object.entries(args).flatMap(([k, x]) => keyedValues(x, k.toLowerCase()));
  return args === null || args === undefined || typeof args === "boolean" ? [] : [[key, pyStr(args)]];
}

function normArg(raw: string): string {
  let v = lower(cleanText(raw));
  if (v.includes("://") || v.includes("www.")) v = sub(SCHEME, v, "");
  v = pyStrip(v);
  const n = plen(v);
  if (n >= 12 && n <= 44) {
    const c = pchars(v);
    if (isAlpha(c[0]) && isDigit(c[2]) && IBAN_LOWER.test(v)) return v.replace(/[ -]/g, "");
  }
  return v;
}

function cannotFitFlat(v: string, limit: number): boolean {
  if (v.length <= limit || !isAscii(v)) return false;
  if (/[\x1c-\x1f]/.test(v)) return false;
  const count = (c: string) => v.split(c).length - 1;
  const guaranteed = v.length - count(" ") - count("\n") - count("\t") - count("\r") - count("\x0b") - count("\x0c") - 2 * count("\\") - count("'");
  return guaranteed > limit;
}

function isSpecificDictated(fv: string): boolean {
  const cs = pchars(fv);
  return fv.includes(" ") || cs.length >= 10 || cs.some((c) => STRUCT_CHARS.has(c)) || (cs.length >= 4 && cs.some((c) => c.codePointAt(0)! >= 0x2e80));
}

function telling(value: string): boolean {
  const cs = pchars(value);
  return cs.length >= 12 || cs.some((c) => STRUCT_CHARS.has(c)) || (cs.length >= 4 && cs.some((c) => c.codePointAt(0)! >= 0x2e80));
}

function secretsAndPaths(raw: string): [Set<string>, Set<string>] {
  let text = cutLongRuns(raw);
  for (const pattern of CARRIED) text = sub(pattern, text, " ");
  const secrets = new Set<string>(), paths = new Set<string>();
  for (let t of findall(TOKEN, text) as string[]) {
    t = lower(pyStrip(t, ".-"));
    const n = plen(t);
    if (t.startsWith("/")) {
      if (n >= 6 && n <= RUN_CAP) paths.add(t);
    } else if (n >= 12 && n <= RUN_CAP && !t.includes("/") && pchars(t).some(isDigit) && pchars(t).some(isAlpha)) {
      secrets.add(t);
    }
  }
  for (let m of findall(KEYED_SECRET, text) as string[]) {
    m = lower(m);
    (m.includes("/") || m.startsWith("~") ? paths : secrets).add(m);
  }
  return [secrets, paths];
}

/** core.py Watch._shown_on_its_own: an occurrence whose two words on each side are the hidden text's is a copy of it. */
function shownOnItsOwn(i: string, before: string, hidden: string): boolean {
  let pos = before.indexOf(i);
  for (let n = 0; n < 20; n++) {
    if (pos < 0) return false;
    const left = pySplit(pslice(before.slice(0, pos), -60)).slice(-2);
    const right = pySplit(pslice(before.slice(pos + i.length), 0, 60)).slice(0, 2);
    if (!hidden.includes([...left, i].join(" ")) || !hidden.includes([i, ...right].join(" "))) return true;
    pos = before.indexOf(i, pos + 1);
  }
  return false;
}

function decide(reason: string, value: string, acting: boolean, egress: boolean, carried: boolean, addressed = false): string {
  if (egress) return NO_GO;
  if (!acting) return addressed ? ASK : GO;
  if ((reason === NAMED || reason === DICTATED) && (carried || telling(value))) return NO_GO;
  return ASK;
}

const uses = (identifier: string, value: string) => (plen(identifier) >= 6 ? value.includes(identifier) : identifier === value);

function hasWord(haystack: string, needle: string): boolean {
  if (!haystack.includes(needle)) return false;
  const cs = pchars(needle);
  const left = cs[0].codePointAt(0)! >= 0x2e80 ? "" : "(?<![\\p{L}\\p{N}])";
  const right = cs[cs.length - 1].codePointAt(0)! >= 0x2e80 ? "" : "(?![\\p{L}\\p{N}])";
  return new RegExp(left + reEscape(needle) + right, "u").test(haystack);
}

function clauses(hiddenText: string): string[] {
  const out = new Set<string>();
  const full = flat(hiddenText);
  if (plen(full) >= 6) out.add(full);
  for (const line of pySplitlines(hiddenText)) {
    for (const part of pyReSplit(SENTENCE, pyStrip(line))) {
      const c = flat(part);
      const n = plen(c);
      if (n >= 12 || (n >= 8 && c.includes(" "))) out.add(c);
    }
  }
  return [...out].sort(byLengthThenText);
}

function scrubMany(text: string, cls: string[]): string {
  const heads = new Map<string, string[]>();
  for (const c of cls) {
    const h = c.slice(0, 6);
    if (!heads.has(h)) heads.set(h, []);
    heads.get(h)!.push(c);
  }
  const out: string[] = [];
  let kept = 0, pos = 0;
  const n = text.length;
  while (pos < n) {
    let hit = 0;
    for (const c of heads.get(text.slice(pos, pos + 6)) ?? []) if (text.startsWith(c, pos)) { hit = c.length; break; }
    if (hit) {
      out.push(text.slice(kept, pos), " ");
      pos = kept = pos + hit;
    } else {
      pos = text.indexOf(" ", pos) + 1;
      if (pos === 0) break;
    }
  }
  out.push(text.slice(kept));
  return out.join("");
}

function scrub(text: string, cls: string[]): string {
  if (cls.length > MANY) {
    text = scrubMany(text, cls);
    cls = cls.slice(0, MANY);
  }
  for (const c of cls) {
    if (text.includes(c)) text = text.split(c).join(" ");
    else if (plen(c) >= 24) {
      const pos = text.lastIndexOf(pslice(c, 0, 20));
      if (pos !== -1 && c.startsWith(pyRstrip(text.slice(pos)))) text = text.slice(0, pos) + " ";
    }
  }
  return text;
}

// ---------------------------------------------------------------- the audit

export interface WatchOptions { followLookups?: boolean; knowsRequest?: boolean; acts?: (tool: string) => boolean; tools?: Tools | null }

const callKey = (id: unknown): string => typeof id === "string" ? "s:" + id : typeof id === "boolean" ? "n:" + (id ? 1 : 0) : "n:" + Number(pyStr(id));

export class Watch {
  known: string;
  knownDays: Set<string>;
  knownIbans: Set<string>;
  followLookups: boolean;
  acts: (tool: string) => boolean;
  private fetches: (tool: string, key: string) => boolean;
  hiddenText = "";
  hidden = "";
  byLength: string[] = [];
  private namedSet = new Set<string>();
  private namedHeads = new Map<string, string[]>();
  private carried = new Set<string>();
  namedSites = new Set<string>();
  namedAddresses = new Set<string>();
  private addresses: (tool: string, key: string) => boolean;
  newDays = new Set<string>();
  ownSentences: string[] = [];
  private longClauses: string[] = [];
  templates: RegExp[] = [];
  private accounts: string[] = [];
  private log: [number, Set<string>][] = [];
  private results: [number, string][] = [];
  private logged = 0;
  private namedEver = new Set<string>();
  private excused = new Set<string>();
  suffixes: string[] = [];
  seenDays = new Set<string>();
  handed = new Set<string>();
  secrets = new Set<string>();
  handedPaths = new Set<string>();
  evidence: Evidence[] = [];
  private calls = 0;
  private pending = new Map<string, boolean>();
  private lastKey: string | null = null;
  private chunks: string[] = [""];
  private inShownYes = new Set<string>();
  private checkedTo = new Map<string, number>();

  constructor(request: string, hiddenText = "", opts: WatchOptions = {}) {
    const knowsRequest = opts.knowsRequest ?? true;
    const cleanReq = knowsRequest ? cleanText(pyStr(request)) : "";
    this.known = knowsRequest ? flat(cleanReq) : "";
    this.knownDays = knowsRequest ? days(this.known) : new Set();
    this.knownIbans = knowsRequest ? new Set((findall(IBAN, cleanReq) as string[]).map(bare)) : new Set();
    this.followLookups = opts.followLookups ?? true;
    this.acts = opts.tools ? (t) => opts.tools!.acts(t) : opts.acts ?? isAction;
    this.fetches = opts.tools ? (t, k) => opts.tools!.fetches(t, k) : isFetch;
    this.addresses = opts.tools ? (t, k) => opts.tools!.addresses(t, k) : (_t, k) => ADDRESS_KEYS.has(k);
    this.flag(hiddenText);
  }

  private inShown(needle: string): boolean {
    if (!needle) return true;
    if (this.inShownYes.has(needle)) return true;
    const chunks = this.chunks, total = chunks.length, nlen = needle.length;
    for (let idx = this.checkedTo.get(needle) ?? 0; idx < total; idx++) {
      const ch = chunks[idx];
      if (ch.includes(needle)) { this.inShownYes.add(needle); return true; }
      if (idx > 0 && nlen > 1) {
        const tail: string[] = [];
        let need = nlen - 1, j = idx - 1;
        while (j >= 0 && need > 0) {
          const prev = chunks[j];
          if (prev.length >= need) { tail.push(prev.slice(prev.length - need)); need = 0; break; }
          tail.push(prev);
          need -= prev.length;
          if (j > 0 && need > 0) { tail.push(" "); need -= 1; }
          j--;
        }
        if ((tail.reverse().join("") + " " + ch.slice(0, nlen - 1)).includes(needle)) { this.inShownYes.add(needle); return true; }
      }
    }
    this.checkedTo.set(needle, total);
    return false;
  }

  /** Addresses, sites and accounts before quoted phrases, then the longest, then code-point order. */
  /** Causality (core.py _excuse): a value used by a call AND shown in words of its own by a result before the text
   *  arrived is excused, unless the text names the action of the call at hand. */
  private excuse(text: string, ids: Set<string>): void {
    const fresh = [...ids].filter((i) => !this.namedEver.has(i));
    for (const i of ids) this.namedEver.add(i);
    if (!fresh.length || !this.log.length) return;
    const whole = flat(text);
    const probes = clauses(text).filter((c) => plen(c) >= 40 && c !== whole).slice(0, 3);
    let arrival = this.results.findIndex(([, t]) => t.includes(whole));
    if (arrival < 0) arrival = this.results.findIndex(([, t]) => probes.some((p) => t.includes(p)));
    if (arrival < 0) arrival = this.results.length;
    const upto = arrival < this.results.length ? this.results[arrival][0] : this.calls - 1;
    const used = this.log.filter(([c]) => c <= upto).flatMap(([, vs]) => [...vs]);
    const before = this.results.slice(0, arrival).map(([, t]) => t).join(" ");
    for (const i of fresh) if (used.some((u) => uses(i, u)) && before.includes(i) && shownOnItsOwn(i, before, whole)) this.excused.add(i);
  }

  private namesTheAct(tool: string): boolean {
    const words = new Set(pySplit(this.hidden));
    return nameWords(tool).some((w) => (ACT_VERBS.has(w) || ACT_OR_NOUN.has(w)) && words.has(w));
  }

  private rank(a: string, b: string): number {
    return (this.carried.has(a) ? 0 : 1) - (this.carried.has(b) ? 0 : 1) || byLengthThenText(a, b);
  }

  private uncontained(tool: string, key: string, raw: string): string {
    if (plen(raw) < CONTAINER_CLAUSE || CONTENT_KEYS.has(key) || !this.longClauses.length || this.fetches(tool, key)) return raw;
    const f = flat(cleanText(raw));
    const held = this.longClauses.filter((c) => f.includes(c));
    if (!held.length) return raw;
    const dropped = cutLongRuns(held.join(" "));
    if ([...this.secrets].some((s) => dropped.includes(lower(String(s))))) return raw;
    if ((ADDRESS_KEYS.has(key) || (!HOLDER_KEYS.has(key) && this.acts(tool))) && (new RegExp(EMAIL.source, "u").test(dropped) || new RegExp(IBAN.source, "u").test(dropped.toUpperCase()))) return raw;
    return scrub(f, held);
  }

  private namedLink(pairs: [string, string][], tool = ""): [string, string] | null {
    const skip = this.excused.size && !this.namesTheAct(tool) ? this.excused : new Set<string>();
    if (this.byLength.length <= MANY) {
      for (const i of this.byLength) { if (skip.has(i)) continue; for (const [k, v] of pairs) if (uses(i, v)) return [i, k]; }
      return null;
    }
    let best: string | null = null;
    for (const [, v] of pairs) {
      const found = this.namedSet.has(v) ? [v] : [];
      if (this.namedHeads.size) {
        for (let p = 0; p < v.length - 5; p++) for (const i of this.namedHeads.get(v.slice(p, p + 6)) ?? []) if (v.startsWith(i, p)) found.push(i);
      }
      for (const i of found) if (!skip.has(i) && (best === null || this.rank(i, best) < 0)) best = i;
    }
    if (best === null) return null;
    return [best, pairs.find(([, v]) => uses(best!, v))![0]];
  }

  flag(hiddenText: string): void {
    if (!hiddenText) return;
    const cleanHidden = cleanText(pyStr(hiddenText));
    this.hiddenText = this.hiddenText ? `${this.hiddenText}\n${cleanHidden}` : cleanHidden;
    this.hidden = flat(this.hiddenText);
    const [ids0, sites0] = identifiersByKind(this.hiddenText, NAMED_KINDS);
    const hosts = [...sites0].map((site) => site.split(HOST_END)[0]).filter((h) => h.includes(".") && plen(h) >= 4);
    const allIds = new Set([...ids0, ...hosts]), allSites = new Set([...sites0, ...hosts]);
    this.excuse(cleanHidden, allIds);
    const named = new Set([...allIds].filter((i) => !this.known.includes(i) && !this.knownIbans.has(i) && !(isDateOnly(i) && subset(days(i), this.knownDays))));
    this.namedSites = new Set([...allSites].filter((i) => named.has(i)));
    this.carried = new Set([...identifiers(this.hiddenText, CARRIED)].filter((i) => named.has(i)));
    this.byLength = [...named].sort((a, b) => this.rank(a, b));
    this.namedAddresses = new Set([...this.namedSites, ...[...this.carried].filter((i) => i.includes("@"))]);
    this.namedSet = named;
    this.namedHeads = new Map();
    if (named.size > MANY) {
      for (const i of this.byLength) if (plen(i) >= 6) {
        const h = i.slice(0, 6);
        if (!this.namedHeads.has(h)) this.namedHeads.set(h, []);
        this.namedHeads.get(h)!.push(i);
      }
    }
    this.accounts = [...this.carried].filter((i) => IBAN_LOWER.test(i) || (plen(i) >= 12 && pchars(i).every(isDigit))).sort((a, b) => this.rank(a, b));
    this.suffixes = [...new Set((findall(ENDING, this.hidden) as string[]).filter((x) => !this.known.includes(x)))].sort(pcmp);
    this.newDays = new Set([...days(this.hiddenText)].filter((d) => !this.knownDays.has(d)));
    this.ownSentences = clauses(this.hiddenText);
    this.longClauses = this.ownSentences.filter((c) => plen(c) >= CONTAINER_CLAUSE);
    this.templates = [];
    for (const q of findall(TEMPLATE_Q, this.hiddenText) as string[]) {
      const cs = pchars(q);
      const parts = pyReSplit(SLOT, flat(cs.slice(1, -1).join("")));
      const literal = pyStrip(parts.join(""));
      if (plen(literal) >= 8 && !this.known.includes(literal)) this.templates.push(new RegExp(`^(?:${parts.map(reEscape).join(".{1,80}?")})$`, "u"));
    }
    if (this.chunks.length > 1 || this.chunks[0]) {
      const joined = scrub(this.chunks.join(" "), this.ownSentences);
      this.chunks = [joined];
      this.seenDays = days(joined);
      this.inShownYes.clear();
      this.checkedTo.clear();
    }
  }

  before(tool: unknown, args: unknown, callId: unknown = null): Evidence | null {
    const name = pyStr(tool);
    const acting = this.acts(name);
    const kv = keyedValues(args);
    const pairs: [string, string][] = kv.map(([k, raw]) => [k, normArg(this.uncontained(name, k, raw))]);
    for (const [k, raw] of kv) for (const d of decodings(raw)) pairs.push([k, normArg(d)]);
    let link: [string, string] | null = null;
    let matchedKey = "";

    if (this.secrets.size) {
      for (const s of [...this.secrets].sort(byLengthThenText)) if (pairs.some(([, v]) => v.includes(s))) { link = [s, SECRET]; break; }
    }
    if (link === null && this.byLength.length) {
      const hit = this.namedLink(pairs, name);
      if (hit !== null) { link = [hit[0], NAMED]; matchedKey = hit[1]; }
    }
    if (link === null && this.accounts.length) {
      for (const [k, v] of pairs) {
        const vv = v.replace(/[ -]/g, "");
        if (plen(vv) >= 8 && pchars(vv).filter(isDigit).length >= 6 && !this.known.includes(vv) && !this.inShown(vv)) {
          const i = this.accounts.find((i) => plen(vv) < plen(i) && (i.startsWith(vv) || i.endsWith(vv)));
          if (i !== undefined) { link = [i, NAMED]; matchedKey = k; break; }
        }
      }
    }
    if (link === null && acting && this.suffixes.length) {
      for (const [k, v] of pairs) {
        const vv = v.replace(/[ -]/g, "");
        const cs = pchars(vv);
        if ((IBAN_LOWER.test(vv) || (cs.length >= 8 && cs.every(isDigit))) && !this.known.includes(vv)
            && this.suffixes.some((x) => plen(vv) > plen(x) && vv.endsWith(x))) { link = [vv, NAMED]; matchedKey = k; break; }
      }
    }
    if (link === null && this.hidden) {
      const hidLen = plen(this.hidden);
      for (const [k, v] of pairs) {
        if (plen(v) < 4 || cannotFitFlat(v, hidLen)) continue;
        if (pchars(v).some(isAlpha)) {
          const fv = flat(v);
          if (plen(fv) <= hidLen && this.hidden.includes(fv) && isSpecificDictated(fv)) {
            if (isDateOnly(fv) && subset(days(fv), new Set([...this.knownDays, ...this.seenDays]))) continue;
            if (this.excused.size && (this.excused.has(fv) || this.excused.has(v)) && !this.namesTheAct(name)) continue;
            if (hasWord(this.hidden, fv) && !this.known.includes(fv) && !this.knownIbans.has(fv) && !this.inShown(fv)) {
              link = [v, DICTATED]; matchedKey = k;
              break;
            }
          }
        }
      }
    }
    if (link === null && acting && this.templates.length) {
      for (const [k, v] of pairs) {
        const fv = flat(v);
        if (plen(fv) <= 400 && this.templates.some((t) => t.test(fv))) { link = [fv, DICTATED]; matchedKey = k; break; }
      }
    }
    if (link === null && acting && this.newDays.size) {
      outer: for (const [, v] of pairs) {
        for (const [y, m, d] of findall(ISO_DAY, v)) {
          if (this.newDays.has(`-${m}-${d}`) && !this.seenDays.has(`-${m}-${d}`)) { link = [`${y}-${m}-${d}`, DATED]; break outer; }
        }
      }
    }
    if (link === null && !acting && this.followLookups && this.handedPaths.size) {
      for (const i of [...this.handedPaths].sort(byLengthThenText)) if (pairs.some(([, v]) => uses(i, v))) { link = [i, HANDED]; break; }
    }
    if (link === null && acting && this.followLookups && this.handed.size) {
      for (const i of [...this.handed].sort(byLengthThenText)) if (pairs.some(([, v]) => uses(i, v))) { link = [i, HANDED]; break; }
    }

    const egress = (link !== null && link[1] === SECRET) || (link !== null && link[1] === NAMED && this.namedAddresses.has(link[0])
      && this.fetches(name, matchedKey) && (!acting || fetchNamed(name)));
    const addressed = link !== null && link[1] === NAMED && this.namedAddresses.has(link[0]) && this.addresses(name, matchedKey);
    const proof = link ? new Evidence(this.calls, name, link[0], link[1], acting, egress,
      decide(link[1], link[0], acting, egress, link[1] === NAMED && this.carried.has(link[0]), addressed)) : null;
    if (proof) this.evidence.push(proof);
    const key = callId !== null && callId !== undefined ? "id:" + callKey(callId) : "seq:" + this.calls;
    this.pending.set(key, !!proof && !acting);
    this.lastKey = key;
    if (this.logged < LOG_CAP) {
      const vs = new Set(pairs.map(([, v]) => v).filter((v) => plen(v) >= 2 && plen(v) <= RUN_CAP));
      this.log.push([this.calls, vs]);
      for (const v of vs) this.logged += plen(v);
    }
    this.calls++;
    return proof;
  }

  after(result: unknown, callId: unknown = null): void {
    const key = callId !== null && callId !== undefined ? "id:" + callKey(callId) : this.lastKey;
    let reading = false;
    if (key !== null) {
      reading = this.pending.get(key) ?? false;
      this.pending.delete(key);
    }
    if (key === this.lastKey) this.lastKey = null;
    const raw = cleanText(pyStr(result));
    const text = scrub(flat(raw, true), this.ownSentences);
    if (reading) {
      for (const i of identifiers(raw, CARRIED)) {
        if (plen(i) >= 6 && !this.known.includes(i) && !this.knownIbans.has(i) && !this.inShown(i)) this.handed.add(i);
      }
      const [secrets, paths] = secretsAndPaths(raw);
      for (const i of sortedText(secrets)) if (this.secrets.size < SECRETS_CAP && !this.known.includes(i) && !this.inShown(i)) this.secrets.add(i);
      for (const i of sortedText(paths)) if (this.handedPaths.size < SECRETS_CAP && !this.inShown(i)) this.handedPaths.add(i);
    }
    this.chunks.push(text);
    if (this.logged < LOG_CAP) {
      const f = flat(raw, true);
      this.results.push([this.calls - 1, f]);
      this.logged += plen(f);
    }
    for (const d of days(text)) this.seenDays.add(d);
  }

  get verdict(): Verdict {
    const level = this.evidence.some((e) => e.acting) ? "acted" : this.evidence.length ? "looked_up" : "none";
    return new Verdict(level, [...this.evidence]);
  }
}

export interface Call { tool?: unknown; args?: unknown; result?: unknown; id?: unknown }

export function audit(request: string, calls: Call[], hiddenText: string, opts: WatchOptions = {}): Verdict {
  const watch = new Watch(request, hiddenText, opts);
  for (const call of calls) {
    const cid = call.id ?? null;
    watch.before(call.tool ?? "", call.args ?? null, cid);
    watch.after(call.result ?? "", cid);
  }
  return watch.verdict;
}

// ---------------------------------------------------------------- said, not done

export const ECHO_WORDS = 7;
const ECHO_WORD = /[⺀-鿿가-힯豈-﫿]|[[\p{L}\p{N}]--[⺀-鿿가-힯豈-﫿]]+(?:['’][\p{L}\p{N}]+)?/gv;
const wordsOf = (s: string) => findall(ECHO_WORD, s) as string[];
const wordline = (f: string) => " " + wordsOf(f).join(" ") + " ";

export function echoed(request: string, calls: Call[], hiddenText: string, answer: string, words = ECHO_WORDS): string | null {
  const said = wordsOf(flat(cleanText(pyStr(answer))));
  if (said.length < words || !hiddenText) return null;
  const hidden = wordsOf(flat(cleanText(pyStr(hiddenText))));
  const grams = new Set<string>();
  for (let i = 0; i + words <= hidden.length; i++) grams.add(hidden.slice(i, i + words).join(" "));
  const known = wordline(flat(cleanText(pyStr(request))));
  const shown = wordline(scrub(calls.map((c) => flat(cleanText(pyStr(c.result ?? "")), true)).join(" "), clauses(cleanText(pyStr(hiddenText)))));
  const seen = new Set([...pySplit(known), ...pySplit(shown)]);
  for (let i = 0; i + words <= said.length; i++) {
    const g = said.slice(i, i + words).join(" ");
    if (grams.has(g) && !known.includes(` ${g} `) && !shown.includes(` ${g} `) && !said.slice(i, i + words).every((w) => seen.has(w))) return g;
  }
  return null;
}
