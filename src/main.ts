import "./style.css";

type Entry = {
  id: string;
  title: string;
  username: string;
  password: string;
  category: string;
  notes: string;
  createdAt: number;
};

type VaultFile = {
  version: 1;
  salt: string;
  iv: string;
  data: string;
};

const app = document.querySelector<HTMLDivElement>("#app")!;
const storageKey = "bluevault-file";
const sessionKey = "bluevault-session";
let entries: Entry[] = [];
let masterPassword = "";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  bytes.forEach(byte => (binary += String.fromCharCode(byte)));
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 310_000,
      hash: "SHA-256"
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptVault(
  password: string,
  value: Entry[]
): Promise<VaultFile> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(JSON.stringify(value))
  );

  return {
    version: 1,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    data: bytesToBase64(new Uint8Array(encrypted))
  };
}

async function decryptVault(
  password: string,
  file: VaultFile
): Promise<Entry[]> {
  const salt = base64ToBytes(file.salt);
  const iv = base64ToBytes(file.iv);
  const key = await deriveKey(password, salt);

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    base64ToBytes(file.data)
  );

  return JSON.parse(decoder.decode(decrypted)) as Entry[];
}

function getFile(): VaultFile | null {
  const raw = localStorage.getItem(storageKey);
  return raw ? JSON.parse(raw) as VaultFile : null;
}

function renderLogin(): void {
  app.innerHTML = `
    <main class="app">
      <section class="card login">
        <div class="brand">
          <div class="logo">🔐</div>
          <div>
            <h1>BlueVault</h1>
            <p class="subtitle">Le tue password, protette localmente</p>
          </div>
        </div>

        <div style="height:20px"></div>

        <label>
          Password principale
          <input id="master" type="password" autocomplete="new-password"
            placeholder="Almeno 12 caratteri" />
        </label>

        <div class="actions">
          <button class="primary" id="unlock">Sblocca vault</button>
          <button class="secondary" id="new-vault">Crea nuovo vault</button>
        </div>

        <p class="subtitle" style="margin-top:16px">
          La password principale non viene salvata. Se la perdi, il vault non può
          essere recuperato.
        </p>
      </section>
    </main>
  `;

  document.querySelector("#unlock")!.addEventListener("click", unlock);
  document.querySelector("#new-vault")!.addEventListener("click", createVault);
}

async function createVault(): Promise<void> {
  const input = document.querySelector<HTMLInputElement>("#master")!;
  const password = input.value;

  if (password.length < 12) {
    alert("Usa una password principale di almeno 12 caratteri.");
    return;
  }

  masterPassword = password;
  entries = [];
  localStorage.setItem(
    storageKey,
    JSON.stringify(await encryptVault(masterPassword, entries))
  );
  sessionStorage.setItem(sessionKey, "unlocked");
  renderVault();
}

async function unlock(): Promise<void> {
  const input = document.querySelector<HTMLInputElement>("#master")!;
  const password = input.value;
  const file = getFile();

  if (!file) {
    alert("Non esiste ancora un vault. Premi “Crea nuovo vault”.");
    return;
  }

  try {
    entries = await decryptVault(password, file);
    masterPassword = password;
    sessionStorage.setItem(sessionKey, "unlocked");
    renderVault();
  } catch {
    alert("Password principale non corretta.");
  }
}

async function persist(): Promise<void> {
  const encrypted = await encryptVault(masterPassword, entries);
  localStorage.setItem(storageKey, JSON.stringify(encrypted));
}

function copyText(value: string): void {
  navigator.clipboard.writeText(value).then(() => {
    alert("Copiato. Gli appunti verranno cancellati tra 20 secondi.");
    window.setTimeout(() => {
      navigator.clipboard.writeText("").catch(() => undefined);
    }, 20_000);
  });
}

function generatePassword(length = 20): string {
  const alphabet =
    "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%";
  const random = new Uint32Array(length);
  crypto.getRandomValues(random);

  return Array.from(random, value => alphabet[value % alphabet.length]).join("");
}

function renderVault(): void {
  app.innerHTML = `
    <main class="app">
      <header class="header">
        <div class="brand">
          <div class="logo">🔐</div>
          <div>
            <h1>BlueVault</h1>
            <p class="subtitle">Vault locale cifrato</p>
          </div>
        </div>
        <button class="secondary" id="lock">Blocca</button>
      </header>

      <section class="card">
        <h2>Aggiungi credenziale</h2>
        <div style="height:16px"></div>

        <div class="grid">
          <label>
            Servizio
            <input id="title" placeholder="Esempio: Gmail" />
          </label>

          <label>
            Categoria
            <select id="category">
              <option>Email</option>
              <option>Siti web</option>
              <option>Wi‑Fi</option>
              <option>Shopping</option>
              <option>Altro</option>
            </select>
          </label>

          <label>
            Nome utente
            <input id="username" autocomplete="off" />
          </label>

          <label>
            Password
            <input id="password" type="password" autocomplete="new-password" />
          </label>

          <label class="full">
            Note
            <input id="notes" placeholder="Note facoltative" />
          </label>
        </div>

        <div class="actions">
          <button class="primary" id="save">Salva</button>
          <button class="secondary" id="generate">Genera password</button>
          <button class="secondary" id="export">Esporta backup cifrato</button>
          <label class="secondary" style="cursor:pointer">
            Importa backup
            <input id="import" type="file" accept=".json" hidden />
          </label>
        </div>
      </section>

      <div class="toolbar">
        <input id="search" placeholder="Cerca servizio o categoria..." />
      </div>

      <section id="entries" class="entries"></section>
    </main>
  `;

  document.querySelector("#lock")!.addEventListener("click", lock);
  document.querySelector("#save")!.addEventListener("click", saveEntry);
  document.querySelector("#generate")!.addEventListener("click", () => {
    document.querySelector<HTMLInputElement>("#password")!.value =
      generatePassword();
  });
  document.querySelector("#export")!.addEventListener("click", exportBackup);
  document.querySelector("#import")!.addEventListener("change", importBackup);
  document.querySelector("#search")!.addEventListener("input", renderEntries);

  renderEntries();
}

function renderEntries(): void {
  const container = document.querySelector<HTMLDivElement>("#entries");
  const search =
    document.querySelector<HTMLInputElement>("#search")?.value.toLowerCase() ??
    "";

  if (!container) return;

  const filtered = entries.filter(entry =>
    `${entry.title} ${entry.category} ${entry.username}`
      .toLowerCase()
      .includes(search)
  );

  if (filtered.length === 0) {
    container.innerHTML = `<div class="empty">Nessuna credenziale salvata.</div>`;
    return;
  }

  container.innerHTML = filtered
    .sort((a, b) => a.title.localeCompare(b.title))
    .map(entry => `
      <article class="entry">
        <div>
          <h3>${escapeHtml(entry.title)}</h3>
          <small>${escapeHtml(entry.category)} · ${escapeHtml(entry.username)}</small>
        </div>
        <div class="entry-actions">
          <button class="secondary" data-action="copy-user" data-id="${entry.id}">
            Copia utente
          </button>
          <button class="secondary" data-action="copy-pass" data-id="${entry.id}">
            Copia password
          </button>
          <button class="danger" data-action="delete" data-id="${entry.id}">
            Elimina
          </button>
        </div>
      </article>
    `)
    .join("");

  container.querySelectorAll<HTMLButtonElement>("button").forEach(button => {
    button.addEventListener("click", async () => {
      const id = button.dataset.id!;
      const entry = entries.find(item => item.id === id);
      if (!entry) return;

      if (button.dataset.action === "copy-user") copyText(entry.username);
      if (button.dataset.action === "copy-pass") copyText(entry.password);

      if (button.dataset.action === "delete") {
        if (confirm(`Eliminare ${entry.title}?`)) {
          entries = entries.filter(item => item.id !== id);
          await persist();
          renderEntries();
        }
      }
    });
  });
}

async function saveEntry(): Promise<void> {
  const title = document.querySelector<HTMLInputElement>("#title")!.value.trim();
  const username =
    document.querySelector<HTMLInputElement>("#username")!.value.trim();
  const password =
    document.querySelector<HTMLInputElement>("#password")!.value;
  const category =
    document.querySelector<HTMLSelectElement>("#category")!.value;
  const notes = document.querySelector<HTMLInputElement>("#notes")!.value;

  if (!title || !username || !password) {
    alert("Compila servizio, nome utente e password.");
    return;
  }

  entries.push({
    id: crypto.randomUUID(),
    title,
    username,
    password,
    category,
    notes,
    createdAt: Date.now()
  });

  await persist();
  renderVault();
}

function exportBackup(): void {
  const file = getFile();
  if (!file) return;

  const blob = new Blob([JSON.stringify(file, null, 2)], {
    type: "application/json"
  });

  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "bluevault-backup-cifrato.json";
  link.click();
  URL.revokeObjectURL(url);
}

function importBackup(event: Event): void {
  const input = event.target as HTMLInputElement;
  const file = input.files?.[0];
  if (!file) return;

  const reader = new FileReader();

  reader.onload = () => {
    try {
      const imported = JSON.parse(String(reader.result)) as VaultFile;

      if (
        imported.version !== 1 ||
        !imported.salt ||
        !imported.iv ||
        !imported.data
      ) {
        throw new Error("Formato non valido");
      }

      localStorage.setItem(storageKey, JSON.stringify(imported));
      alert("Backup importato. Blocca e sblocca il vault con la password corretta.");
      lock();
    } catch {
      alert("Backup non valido.");
    }
  };

  reader.readAsText(file);
}

function lock(): void {
  masterPassword = "";
  entries = [];
  sessionStorage.removeItem(sessionKey);
  renderLogin();
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, character => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  })[character] ?? character);
}

if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("/sw.js").catch(() => undefined);
}

renderLogin();
