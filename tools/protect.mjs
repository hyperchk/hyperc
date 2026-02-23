import fs from "fs";
import path from "path";
import crypto from "crypto";
import { execSync } from "child_process";
import * as cheerio from "cheerio";

const PROJECT_ROOT = process.cwd();
const DOCS_DIR = path.join(PROJECT_ROOT, "docs");
const SITE_DIR = path.join(PROJECT_ROOT, "site");

const SRC_JS = path.join(DOCS_DIR, "assets", "js", "password-protect.src.js");
const OUT_JS = path.join(DOCS_DIR, "assets", "js", "password-protect.js");

const IV_LEN = 12; // AES-GCM recommended
const TAG_LEN = 16;

function die(msg) {
  console.error(`[-] ${msg}`);
  process.exit(1);
}

function mustExist(p, label) {
  if (!fs.existsSync(p)) die(`${label} no existe: ${p}`);
}

function slugifyPart(s) {
  return s
    .toLowerCase()
    .trim()
    .replace(/\s+/g, "-");
}

// Convierte "hack-the-box/.../Write Up.md" -> "/hack-the-box/.../write-up/"
function routeFromMdRel(mdRel) {
  const noExt = mdRel.replace(/\.md$/i, "");
  const parts = noExt.split(/[\\/]/).map(slugifyPart);
  return "/" + parts.join("/") + "/";
}

// route "/a/b/" => "site/a/b/index.html"
function htmlPathFromRoute(route) {
  const rel = route.replace(/^\//, "");
  return path.join(SITE_DIR, rel, "index.html");
}

function extractArticleInnerHtml(htmlPath) {
  mustExist(htmlPath, "HTML generado");
  const html = fs.readFileSync(htmlPath, "utf8");
  const $ = cheerio.load(html);

  const article = $("article.md-content__inner");
  if (!article.length) die(`No encontré <article class="md-content__inner"> en ${htmlPath}`);

  const inner = article.html() || "";
  if (!inner.trim()) die(`El <article> está vacío en ${htmlPath}`);
  return inner;
}

// SHA-256(password) -> key (32 bytes)
function sha256Key(password) {
  return crypto.createHash("sha256").update(password, "utf8").digest(); // 32 bytes
}

// Payload layout:
// [12 iv][ciphertext+tag]  (tag al final)
function encryptToBase64(plainHtml, password) {
  const iv = crypto.randomBytes(IV_LEN);
  const key = sha256Key(password);

  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plainHtml, "utf8")), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16 bytes

  const payload = Buffer.concat([iv, ciphertext, tag]);
  return payload.toString("base64");
}

function updateEncryptedPages(publicRoute, base64Payload) {
  mustExist(SRC_JS, "password-protect.src.js");

  const src = fs.readFileSync(SRC_JS, "utf8");

  const begin = "// === BEGIN ENCRYPTED PAGES (AUTO) ===";
  const end = "// === END ENCRYPTED PAGES (AUTO) ===";

  const i1 = src.indexOf(begin);
  const i2 = src.indexOf(end);
  if (i1 === -1 || i2 === -1 || i2 <= i1) die("No encontré los marcadores BEGIN/END en password-protect.src.js");

  const before = src.slice(0, i1 + begin.length);
  const middle = src.slice(i1 + begin.length, i2);
  const after  = src.slice(i2);

  const routeEsc = publicRoute.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const lineRegex = new RegExp(`\\s*["']${routeEsc}["']\\s*:\\s*["'][^"']*["']\\s*,?`, "i");

  const newLine = `  "${publicRoute}": "${base64Payload}",`;

  let newMiddle = middle;

  if (lineRegex.test(middle)) {
    newMiddle = middle.replace(lineRegex, newLine);
  } else {
    // insertar antes del cierre del objeto dentro del bloque
    if (!/const\s+encryptedPages\s*=\s*\{/.test(middle)) die("No encontré 'const encryptedPages = {' dentro del bloque AUTO");

    newMiddle = middle.replace(/\n\s*\};/, `\n${newLine}\n  };`);
  }

  const out = before + "\n" + newMiddle.trim() + "\n" + after;
  fs.writeFileSync(SRC_JS, out, "utf8");
}

function rebuildPublicPlaceholder(mdPublicAbs) {
  // opcional: garantiza que el público sea placeholder
  const content = `# ${path.basename(path.dirname(mdPublicAbs))} Write Up

<div id="protected-content"></div>
`;
  fs.writeFileSync(mdPublicAbs, content, "utf8");
}

function main() {
  const mdPublicRel = process.argv[2];
  if (!mdPublicRel) {
    die(`Uso:
node tools/protect.mjs "hack-the-box/machines/medium/linux/Interpreter/Write Up.md"
Requiere: WRITEUP_PASS en env`);
  }

  const password = process.env.WRITEUP_PASS;
  if (!password) die("Falta WRITEUP_PASS. Ejemplo: WRITEUP_PASS='tuPassword' node tools/protect.mjs '.../Write Up.md'");

  // Paths
  const mdPublicAbs = path.join(DOCS_DIR, mdPublicRel);

  // Derivar source: "Write Up.md" -> "Write Up.source.md"
  const mdSourceRel = mdPublicRel.replace(/\.md$/i, ".source.md");
  const mdSourceAbs = path.join(DOCS_DIR, mdSourceRel);

  mustExist(mdPublicAbs, "MD público");
  mustExist(mdSourceAbs, "MD source");

  // Ruta pública (la que se protege)
  const publicRoute = routeFromMdRel(mdPublicRel);

  // Ruta source (de donde extraemos el HTML real)
  const sourceRoute = routeFromMdRel(mdSourceRel);

  console.log(`[+] Public route: ${publicRoute}`);
  console.log(`[+] Source route: ${sourceRoute}`);

  // (Opcional) forzar placeholder siempre
  rebuildPublicPlaceholder(mdPublicAbs);

  console.log("[+] mkdocs build...");
  execSync("mkdocs build", { stdio: "inherit" });

  const htmlSourcePath = htmlPathFromRoute(sourceRoute);
  console.log(`[+] Extrayendo <article> desde: ${htmlSourcePath}`);
  const articleHtml = extractArticleInnerHtml(htmlSourcePath);

  console.log("[+] Encriptando (SHA256 key + AES-256-GCM)...");
  const b64 = encryptToBase64(articleHtml, password);

  console.log("[+] Actualizando encryptedPages...");
  updateEncryptedPages(publicRoute, b64);

  console.log("[+] Generando password-protect.js (copiando src)...");
  // Build simple: copia src -> out (sin obfuscator para que no falle)
  const finalJs = fs.readFileSync(SRC_JS, "utf8");
  fs.writeFileSync(OUT_JS, finalJs, "utf8");

  console.log("[+] OK ✅");
  console.log("    - Public placeholder asegurado");
  console.log("    - Payload actualizado");
  console.log("    - password-protect.js regenerado");
}

main();
