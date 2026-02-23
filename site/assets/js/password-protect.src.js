// password-protect.src.js


  // === BEGIN ENCRYPTED PAGES (AUTO) ===

  const encryptedPages = {

  };

  // === END ENCRYPTED PAGES (AUTO) ===


async function decryptPage(route, password) {
  const b64 = encryptedPages[route];
  if (!b64) return;

  const data = Uint8Array.from(atob(b64), c => c.charCodeAt(0));

  const iv = data.slice(0, 12);
  const tag = data.slice(data.length - 16);
  const ciphertext = data.slice(12, data.length - 16);

  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.digest("SHA-256", enc.encode(password));

  const key = await crypto.subtle.importKey(
    "raw",
    keyMaterial,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  try {
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      new Uint8Array([...ciphertext, ...tag])
    );

    const html = new TextDecoder().decode(decrypted);
    document.getElementById("protected-content").innerHTML = html;
  } catch {
    alert("Password incorrecto");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const route = window.location.pathname;
  if (!encryptedPages[route]) return;

  const password = prompt("Ingrese contraseña:");
  if (password) decryptPage(route, password);
});