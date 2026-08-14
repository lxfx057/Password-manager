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
  let result = "";

  for (const byte of bytes) {
    result += String.fromCharCode(byte);
  }

  return btoa(result);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const result = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    result[index] = binary.charCodeAt(index);
  }

  return result;
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

  const value: unknown = JSON.parse(decoder.decode(decrypted));

  if (!Array.isArray(value)) {
    throw new Error("Vault non valido");
  }

  return value as Entry[];
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

function createElement<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);

  if (className) {
    element.className = className;
  }

  return element;
}

function addText(
  parent: HTMLElement,
  tag: keyof HTMLElementTagNameMap,
  text: string,
  className?: string
): HTMLElement {
  const element = document.createElement(tag);

  if (className) {
    element.className = className;
  }

  element.textContent = text;
  parent.appendChild(element);

  return element;
}

function renderLogin(): void {
  app.replaceChildren();

  const main = createElement("main", "app");
  const card = createElement("section", "card login");

  const brand = createElement("div", "brand");
  const logo = createElement("div", "logo");
  logo.textContent = "🔐";

  const brandText = createElement("div");
  addText(brandText, "h1", "BlueVault");
  addText(
    brandText,
    "p",
    "Le tue password, protette localmente",
    "subtitle"
  );

  brand.append(logo, brandText);

  const spacer = createElement("div", "spacer");

  const label = createElement("label");
  label.appendChild(document.createTextNode("Password principale"));

  const masterInput = createElement("input");
  masterInput.id = "master";
  masterInput.type = "password";
  masterInput.autocomplete = "new-password";
  masterInput.placeholder = "Almeno 12 caratteri";
  label.appendChild(masterInput);

  const actions = createElement("div", "actions");

  const unlockButton = createElement("button", "primary");
  unlockButton.textContent = "Sblocca vault";

  const newVaultButton = createElement("button", "secondary");
  newVaultButton.textContent = "Crea nuovo vault";

  actions.append(unlockButton, newVaultButton);

  const warning = addText(
    card,
    "p",
    "La password principale non viene salvata. Se la perdi, il vault non può essere recuperato.",
    "subtitle warning-text"
  );

  card.replaceChildren(brand, spacer, label, actions, warning);
  main.appendChild(card);
  app.appendChild(main);

  unlockButton.addEventListener("click", () => {
    void unlock();
  });

  newVaultButton.addEventListener("click", () => {
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
    masterPassword = input.value;
    entries = await decryptVault(masterPassword, file);
    renderVault();
  } catch {
    masterPassword = "";
    entries = [];
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

function createInput(
  id: string,
  placeholder: string,
  type = "text"
): HTMLInputElement {
  const input = createElement("input");

  input.id = id;
  input.type = type;
  input.placeholder = placeholder;

  return input;
}

function createField(
  text: string,
  input: HTMLInputElement | HTMLSelectElement
): HTMLLabelElement {
  const label = createElement("label");
  label.appendChild(document.createTextNode(text));
  label.appendChild(input);
  return label;
}

function renderVault(): void {
  app.replaceChildren();

  const main = createElement("main", "app");

  const header = createElement("header", "header");
  const brand = createElement("div", "brand");
  const logo = createElement("div", "logo");
  logo.textContent = "🔐";

  const brandText = createElement("div");
  addText(brandText, "h1", "BlueVault");
  addText(brandText, "p", "Vault locale cifrato", "subtitle");

  brand.append(logo, brandText);

  const lockButton = createElement("button", "secondary");
  lockButton.textContent = "Blocca";
  lockButton.addEventListener("click", lock);

  header.append(brand, lockButton);

  const card = createElement("section", "card");
  addText(card, "h2", "Aggiungi credenziale");
  card.appendChild(createElement("div", "spacer-small"));

  const grid = createElement("div", "grid");

  const titleInput = createInput("title", "Esempio: Gmail");
  const categoryInput = createElement("select");
  categoryInput.id = "category";

  for (const category of [
    "Email",
    "Siti web",
    "Wi‑Fi",
    "Shopping",
    "Altro"
  ]) {
    const option = createElement("option");
    option.value = category;
    option.textContent = category;
    categoryInput.appendChild(option);
  }

  const usernameInput = createInput("username", "");
  usernameInput.autocomplete = "off";

  const passwordInput = createInput(
    "password",
    "",
    "password"
  );
  passwordInput.autocomplete = "new-password";

  const notesInput = createInput("notes", "Note facoltative");

  const titleField = createField("Servizio", titleInput);
  const categoryField = createField("Categoria", categoryInput);
  const usernameField = createField("Nome utente", usernameInput);
  const passwordField = createField("Password", passwordInput);
  const notesField = createField("Note", notesInput);

  notesField.classList.add("full");
  grid.append(
    titleField,
    categoryField,
    usernameField,
    passwordField,
    notesField
  );

  const actions = createElement("div", "actions");

  const saveButton = createElement("button", "primary");
  saveButton.textContent = "Salva";

  const generateButton = createElement("button", "secondary");
  generateButton.textContent = "Genera password";

  const exportButton = createElement("button", "secondary");
  exportButton.textContent = "Esporta backup cifrato";

  const importLabel = createElement("label", "file-button");
  importLabel.textContent = "Importa backup";

  const importInput = createElement("input");
  importInput.id = "import";
  importInput.type = "file";
  importInput.accept = ".json";
  importInput.hidden = true;

  importLabel.appendChild(importInput);
  actions.append(saveButton, generateButton, exportButton, importLabel);

  card.append(grid, actions);

  const toolbar = createElement("div", "toolbar");
  const searchInput = createInput(
    "search",
    "Cerca servizio, utente o categoria..."
  );
  toolbar.appendChild(searchInput);

  const entriesContainer = createElement("section", "entries");
  entriesContainer.id = "entries";

  main.append(header, card, toolbar, entriesContainer);
  app.appendChild(main);

  saveButton.addEventListener("click", () => {
    void saveEntry();
  });

  generateButton.addEventListener("click", () => {
    passwordInput.value = generatePassword();
    passwordInput.type = "text";
  });

  exportButton.addEventListener("click", exportBackup);

  importInput.addEventListener("change", event => {
    void importBackup(event);
  });

  searchInput.addEventListener("input", renderEntries);

  renderEntries();
}

function renderEntries(): void {
  const container = document.querySelector<HTMLElement>("#entries");
  const searchInput = document.querySelector<HTMLInputElement>("#search");

  if (!container) {
    return;
  }

  const search = searchInput?.value.toLowerCase() ?? "";

  const filtered = entries
    .filter(entry => {
      const content = [
        entry.title,
        entry.username,
        entry.category,
        entry.notes
      ]
        .join(" ")
        .toLowerCase();

      return content.includes(search);
    })
    .sort((a, b) => a.title.localeCompare(b.title));

  container.replaceChildren();

  if (filtered.length === 0) {
    const empty = createElement("div", "empty");
    empty.textContent = "Nessuna credenziale salvata.";
    container.appendChild(empty);
    return;
  }

  for (const entry of filtered) {
    const article = createElement("article", "entry");

    const information = createElement("div");
    addText(information, "h3", entry.title);
    addText(
      information,
      "small",
      `${entry.category} · ${entry.username}`
    );

    const actions = createElement("div", "entry-actions");

    const copyUserButton = createElement("button", "secondary");
    copyUserButton.textContent = "Copia utente";
    copyUserButton.addEventListener("click", () => {
      copyText(entry.username);
    });

    const copyPasswordButton = createElement("button", "secondary");
    copyPasswordButton.textContent = "Copia password";
    copyPasswordButton.addEventListener("click", () => {
      copyText(entry.password);
    });

    const deleteButton = createElement("button", "danger");
    deleteButton.textContent = "Elimina";
    deleteButton.addEventListener("click", () => {
      void deleteEntry(entry.id, entry.title);
    });

    actions.append(copyUserButton, copyPasswordButton, deleteButton);
    article.append(information, actions);
    container.appendChild(article);
  }
}

async function deleteEntry(id: string, title: string): Promise<void> {
  if (!confirm(`Eliminare ${title}?`)) {
    return;
  }

  entries = entries.filter(entry => entry.id !== id);
  await persist();
  renderEntries();
}

async function saveEntry(): Promise<void> {
  const titleInput = document.querySelector<HTMLInputElement>("#title");
  const usernameInput =
    document.querySelector<HTMLInputElement>("#username");
  const passwordInput =
    document.querySelector<HTMLInputElement>("#password");
  const categoryInput =
    document.querySelector<HTMLSelectElement>("#category");
  const notesInput = document.querySelector<HTMLInputElement>("#notes");

  if (
    !titleInput ||
    !usernameInput ||
    !passwordInput ||
    !categoryInput ||
    !notesInput
  ) {
    return;
  }

  const title = titleInput.value.trim();
  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  const category = categoryInput.value;
  const notes = notesInput.value.trim();

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
  const file = getStoredFile();

  if (!file) {
    alert("Nessun vault disponibile.");
    return;
  }

  const blob = new Blob([JSON.stringify(file, null, 2)], {
    type: "application/json"
  });

  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.download = "bluevault-backup-cifrato.json";
  document.body.appendChild(link);
  link.click();
  link.remove();

  URL.revokeObjectURL(url);
}

async function importBackup(event: Event): Promise<void> {
  const input = event.target as HTMLInputElement;
  const file = input.files?.[0];

  if (!file) {
    return;
  }

  try {
    const text = await file.text();
    const imported = JSON.parse(text) as Partial<VaultFile>;

    if (
      imported.version !== 1 ||
      typeof imported.salt !== "string" ||
      typeof imported.iv !== "string" ||
      typeof imported.data !== "string"
    ) {
      throw new Error("Formato non valido");
    }

    localStorage.setItem(storageKey, JSON.stringify(imported));
    masterPassword = "";
    entries = [];

    alert(
      "Backup importato. Usa la password principale associata al backup."
    );

    renderLogin();
  } catch {
    alert("Backup non valido.");
  }
}

function lock(): void {
  masterPassword = "";
  entries = [];
  renderLogin();
}

if ("serviceWorker" in navigator) {
  navigator.serviceWorker
    .register("/sw.js")
    .catch(() => undefined);
}

renderLogin();
