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

const app = document.querySelector<HTMLDivElement>("#app");

if (!app) {
  throw new Error("Elemento #app non trovato");
}

const storageKey = "bluevault-file";
let entries: Entry[] = [];
let masterPassword = "";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

function toUint8Array(buffer: ArrayBuffer): Uint8Array {
  return new Uint8Array(buffer);
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
}

async function deriveKey(
  password: string,
  salt: Uint8Array
): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(encoder.encode(password)),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: toArrayBuffer(salt),
      iterations: 310_000,
      hash: "SHA-256"
    },
    material,
    {
      name: "AES-GCM",
      length: 256
    },
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

  const plaintext = encoder.encode(JSON.stringify(value));

  const encrypted = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: toArrayBuffer(iv)
    },
    key,
    toArrayBuffer(plaintext)
  );

  return {
    version: 1,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    data: bytesToBase64(toUint8Array(encrypted))
  };
}

async function decryptVault(
  password: string,
  file: VaultFile
): Promise<Entry[]> {
  const salt = base64ToBytes(file.salt);
  const iv = base64ToBytes(file.iv);
  const encrypted = base64ToBytes(file.data);
  const key = await deriveKey(password, salt);

  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: toArrayBuffer(iv)
    },
    key,
    toArrayBuffer(encrypted)
  );

  const parsed: unknown = JSON.parse(decoder.decode(decrypted));

  if (!Array.isArray(parsed)) {
    throw new Error("Dati del vault non validi");
  }

  return parsed as Entry[];
}

function getStoredFile(): VaultFile | null {
  const raw = localStorage.getItem(storageKey);

  if (!raw) {
    return null;
  }

  try {
    return JSON.parse(raw) as VaultFile;
  } catch {
    return null;
  }
}

function saveStoredFile(file: VaultFile): void {
  localStorage.setItem(storageKey, JSON.stringify(file));
}

function renderLogin(): void {
  app.innerHTML = `
    <main class="app">
      <section class="card login">
        <div class="brand">
          <div class="logo">🔐</div>
          <div>
            <h1>BlueVault</h1>
            <p class="subtitle">
              Le tue password, protette localmente
            </p>
          </div>
        </div>

        <div class="spacer"></div>

        <label>
          Password principale
          <input
            id="master"
            type="password"
            autocomplete="new-password"
            placeholder="Almeno 12 caratteri"
          />
        </label>

        <div class="actions">
          <button class="primary" id="unlock">
            Sblocca vault
          </button>

          <button class="secondary" id="new-vault">
            Crea nuovo vault
          </button>
        </div>

        <p class="subtitle warning-text">
          La password principale non viene salvata. Se la perdi, il vault non
          può essere recuperato.
        </p>
      </section>
    </main>
  `;

  document
    .querySelector<HTMLButtonElement>("#unlock")
    ?.addEventListener("click", () => {
      void unlock();
    });

  document
    .querySelector<HTMLButtonElement>("#new-vault")
    ?.addEventListener("click", () => {
      void createVault();
    });
}

async function createVault(): Promise<void> {
  const input = document.querySelector<HTMLInputElement>("#master");

  if (!input) {
    return;
  }

  const password = input.value;

  if (password.length < 12) {
    alert("Usa una password principale di almeno 12 caratteri.");
    return;
  }

  if (getStoredFile() && !confirm("Esiste già un vault. Sovrascriverlo?")) {
    return;
  }

  masterPassword = password;
  entries = [];

  const file = await encryptVault(masterPassword, entries);
  saveStoredFile(file);
  renderVault();
}

async function unlock(): Promise<void> {
  const input = document.querySelector<HTMLInputElement>("#master");
  const file = getStoredFile();

  if (!input) {
    return;
  }

  if (!file) {
    alert("Non esiste ancora un vault. Premi “Crea nuovo vault”.");
    return;
  }

  try {
    const password = input.value;
    entries = await decryptVault(password, file);
    masterPassword = password;
    renderVault();
  } catch {
    alert("Password principale non corretta o backup non valido.");
  }
}

async function persist(): Promise<void> {
  const file = await encryptVault(masterPassword, entries);
  saveStoredFile(file);
}

function copyText(value: string): void {
  navigator.clipboard
    .writeText(value)
    .then(() => {
      alert("Copiato. Gli appunti verranno cancellati tra 20 secondi.");

      window.setTimeout(() => {
        navigator.clipboard.writeText("").catch(() => undefined);
      }, 20_000);
    })
    .catch(() => {
      alert("Impossibile copiare negli appunti.");
    });
}

function generatePassword(length = 20): string {
  const alphabet =
    "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%";

  const random = new Uint32Array(length);
  crypto.getRandomValues(random);

  return Array.from(
    random,
    value => alphabet[value % alphabet.length]
  ).join("");
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

        <button class="secondary" id="lock">
          Blocca
        </button>
      </header>

      <section class="card">
        <h2>Aggiungi
