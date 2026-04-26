document.addEventListener("DOMContentLoaded", async () => {
  console.log("✅ JavaScript loaded");
  const currentUser = document.getElementById("app")?.dataset?.user || null;
  const csrfToken = document.querySelector('input[name="csrf_token"]')?.value || '';
  console.log("Current user:", currentUser);


  // ————— Мінімальний IndexedDB-клонер для CryptoKey —————

  const DB_NAME = `messenger-key-db_${currentUser}`;

  function openKeyDB() {
    return new Promise((res, rej) => {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = e => e.target.result.createObjectStore("keys");
      req.onsuccess = e => res(e.target.result);
      req.onerror = e => rej(e.target.error);
    });
  }
  async function getKey(name) {
    const db = await openKeyDB();
    return new Promise(res => {
      const tx  = db.transaction("keys", "readonly");
      const req = tx.objectStore("keys").get(name);
      req.onsuccess = () => res(req.result);
      req.onerror   = () => res(undefined);
    });
  }
  async function setKey(name, value) {
    const db = await openKeyDB();
    return new Promise(res => {
      const tx  = db.transaction("keys", "readwrite");
      const req = tx.objectStore("keys").put(value, name);
      req.onsuccess = () => res();
      req.onerror   = () => res();
    });
  }
  // ——— Додати: deleteKey для очищення «битих» записів ———
  async function deleteKey(name) {
    const db = await openKeyDB();
    return new Promise(res => {
      const tx    = db.transaction("keys", "readwrite");
      const store = tx.objectStore("keys");
      store.delete(name);
      tx.oncomplete = () => res();
      tx.onerror    = () => res();
    });
  }
// —————————————————————————————————————————————


  // ===== Ініціалізація або завантаження ECDH-приватного ключа =====
  const keyName = `privKey_${currentUser}`;
  const pubName = `pubKey_${currentUser}`;

  let privKeyCrypto, pubKeyCrypto;

  try {
    // 1) Спробуємо підхопити JWK із IndexedDB
    const storedPrivJwk = await getKey(keyName);
    const storedPubJwk  = await getKey(pubName);

    // 2) Перевіряємо, чи це дійсний JWK (має поле "kty")
    if (storedPrivJwk?.kty && storedPubJwk?.kty) {
      privKeyCrypto = await crypto.subtle.importKey(
        "jwk", storedPrivJwk, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"]
      );
      pubKeyCrypto = await crypto.subtle.importKey(
        "jwk", storedPubJwk, { name: "ECDH", namedCurve: "P-256" }, false, []
      );

      // ДОДАНО: Завжди "нагадуємо" серверу свій ключ при завантаженні сторінки
      // (на випадок, якщо базу даних на сервері було очищено)
      fetch("/api/public_key", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
        body: JSON.stringify({ public_key: storedPubJwk })
      }).catch(e => console.warn("Не вдалося оновити ключ на сервері", e));

    } else {
      throw new Error("Invalid JWK");
    }

  } catch (err) {
    console.warn("🔄 Некоректний JWK, очищаємо записи й генеруємо заново", err);

    // 3) Видаляємо «биті» ключі
    await deleteKey(keyName);
    await deleteKey(pubName);

    // 4) Генеруємо пару з можливістю експорту
    const pair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveKey"]
    );

    // 5) Експортуємо обидва ключі в JWK
    const privJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
    const pubJwk  = await crypto.subtle.exportKey("jwk", pair.publicKey);

    // 6) Записуємо JWK у IndexedDB
    await setKey(keyName, privJwk);
    await setKey(pubName,  pubJwk);

    // 7) Відправляємо публічний на сервер
    const res = await fetch("/api/public_key", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": csrfToken
      },
      body: JSON.stringify({ public_key: pubJwk })
    });
    const result = await res.json();
    console.log("POST /api/public_key ➞", res.status, result);


    // 8) Використовуємо пару
    privKeyCrypto = pair.privateKey;
    pubKeyCrypto  = pair.publicKey;
  }




  // ====================================================
  // ===== MULTI-DEVICE FAN-OUT КРИПТОГРАФІЯ ============
  // ====================================================

  async function getSharedKeysForUser(username) {
    const resp = await fetch(`/api/public_key/${username}`);
    if (!resp.ok) return [];
    const { data: { public_keys } } = await resp.json();

    const keys = [];
    for (const jwk of public_keys) {
      try {
        const { key_ops, ...jwkClean } = jwk;
        const pub = await crypto.subtle.importKey("jwk", jwkClean, { name: "ECDH", namedCurve: "P-256" }, false, []);
        const shared = await crypto.subtle.deriveKey(
          { name: "ECDH", public: pub }, privKeyCrypto, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
        );
        keys.push(shared);
      } catch (e) { console.warn("Помилка генерації спільного ключа", e); }
    }
    return keys;
  }

  async function encryptBase(payload, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, payload);
    return {
      iv: btoa(String.fromCharCode(...iv)),
      data: btoa(String.fromCharCode(...new Uint8Array(encrypted)))
    };
  }

  // Fan-Out Шифрування тексту (робить масив шифротекстів)
  async function encryptFanOut(contentStr, sharedKeysArray) {
    const payload = new TextEncoder().encode(contentStr);
    const ivs = [], datas = [];
    for (const key of sharedKeysArray) {
      const enc = await encryptBase(payload, key);
      ivs.push(enc.iv); datas.push(enc.data);
    }
    return { iv: JSON.stringify(ivs), data: JSON.stringify(datas) };
  }

  // Fan-Out Шифрування файлів
  async function encryptArrayBufferFanOut(buffer, sharedKeysArray) {
    const ivs = [], datas = [];
    for (const key of sharedKeysArray) {
      const enc = await encryptBase(buffer, key);
      ivs.push(enc.iv); datas.push(enc.data);
    }
    return { iv: JSON.stringify(ivs), data: JSON.stringify(datas) };
  }

  // Fan-Out Дешифрування (перебирає ключі, поки не підійде правильний)
  async function decryptFanOutBase(ivStr, dataStr, senderUsername, isBuffer = false) {
    let ivArr, dataArr;
    try {
      ivArr = JSON.parse(ivStr); dataArr = JSON.parse(dataStr);
      if (!Array.isArray(ivArr)) throw new Error();
    } catch(e) {
      // Зворотна сумісність: якщо це старе повідомлення з 1 ключем
      ivArr = [ivStr]; dataArr = [dataStr];
    }

    const senderSharedKeys = await getSharedKeysForUser(senderUsername);
    for (const key of senderSharedKeys) {
      for (let i = 0; i < dataArr.length; i++) {
        try {
          const iv = Uint8Array.from(atob(ivArr[i]), c => c.charCodeAt(0));
          const data = Uint8Array.from(atob(dataArr[i]), c => c.charCodeAt(0));
          const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
          return isBuffer ? decrypted : new TextDecoder().decode(decrypted);
        } catch (e) { continue; } // Якщо ключ не підійшов — пробуємо наступний
      }
    }
    throw new Error("Жоден ключ не підійшов");
  }

  async function decryptFanOut(ivStr, dataStr, senderUsername) {
    return await decryptFanOutBase(ivStr, dataStr, senderUsername, false);
  }

  async function decryptToBlobFanOut(ivStr, dataStr, senderUsername, type) {
    const buffer = await decryptFanOutBase(ivStr, dataStr, senderUsername, true);
    return new Blob([buffer], { type });
  }

  // Базове дешифрування (лишилося тільки для Групових чатів)
  async function decryptDirect(payload, key) {
    const iv = Uint8Array.from(atob(payload.iv), c => c.charCodeAt(0));
    const data = Uint8Array.from(atob(payload.data), c => c.charCodeAt(0));
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
    return new TextDecoder().decode(decrypted);
  }

  // ===== Утиліти =====
  // ===== Антивірусна перевірка (Magic Bytes) =====
  async function validateFileSignature(file) {
    if (!file) return { isSafe: true, realType: null };

    const buffer = await file.slice(0, 4).arrayBuffer();
    const view = new Uint8Array(buffer);
    let hex = '';
    for (let i = 0; i < view.length; i++) {
      hex += view[i].toString(16).padStart(2, '0').toUpperCase();
    }

    const allowedSignatures = {
      "FFD8FFE0": "image/jpeg", "FFD8FFE1": "image/jpeg",
      "FFD8FFE2": "image/jpeg", "FFD8FFE3": "image/jpeg",
      "FFD8FFE8": "image/jpeg", "89504E47": "image/png",
      "47494638": "image/gif", "25504446": "application/pdf",
      "504B0304": "application/zip" // Для ZIP, DOCX, XLSX
    };

    for (const [sig, mimeType] of Object.entries(allowedSignatures)) {
      if (hex.startsWith(sig)) return { isSafe: true, realType: mimeType };
    }
    console.warn("🚫 Заблоковано підозрілий файл із сигнатурою:", hex);
    return { isSafe: false, realType: null };
  }
  function escapeHTML(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }
  function fileToBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.readAsDataURL(file);
      reader.onload = () => resolve(reader.result);
      reader.onerror = err => reject(err);
    });
  }
  function scrollToBottom() {
    const messagesDiv = document.getElementById("messages");
    if (messagesDiv) messagesDiv.scrollTop = messagesDiv.scrollHeight;
  }

  // ===== Додавання друзів =====
  const addFriendForm = document.getElementById("add-friend-form");
  // --- Змінні для пагінації ---
  let currentOffset = 0;
  const messageLimit = 50;
  let isLoadingMessages = false;
  let hasMoreMessages = true;
  let currentActiveContact = null;
  if (addFriendForm) {
    addFriendForm.addEventListener("submit", async e => {
      e.preventDefault();
      const username = document.getElementById("friend-username").value.trim();
      if (!username) { alert("❌ Введіть ім’я користувача"); return; }

      if (username === currentUser) {
        alert("❌ Ви не можете додати самого себе в контакти!");
        return;
      }

      try {
        const res= await fetch("/api/add_contact", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken
          },
          body: JSON.stringify({ username })
        });
        console.log("POST /api/public_key status:", res.status);
        const result = await res.json();
        console.log("Response:", result); // Тепер ми логуємо вже готову змінну
        if (res.ok) {
          alert("✅ Контакт додано");
          document.getElementById("friend-username").value = "";
          loadContacts();
        } else {
          alert("❌ " + result.error);
        }
      } catch (err) {
        console.error(err);
      }
    });
  }

  function loadContacts() {
      fetch("/api/contacts")
        .then(r => r.json())
        .then(data => {
          const ul = document.getElementById("contacts");
          const select = document.getElementById("group-members-select"); // Поле для груп

          if (ul) ul.innerHTML = "";
          if (select) select.innerHTML = ""; // Очищаємо перед оновленням

          (data.contacts || []).forEach(c => {
            // 1. Додаємо в ліве меню контактів
            if (ul) {
              const li = document.createElement("li");
              li.textContent = c;
              li.style.cursor = "pointer";
              li.addEventListener("click", () => openChat(c));
              ul.appendChild(li);
            }

            // 2. ДОДАНО: Одразу додаємо людину в меню вибору для групи
            if (select) {
              select.appendChild(new Option(c, c));
            }
          });
        })
        .catch(err => console.error(err));
    }

  // ===== Відкриття чату =====
// ===== Відкриття чату та завантаження повідомлень =====
  async function openChat(username, isLoadMore = false) {
    if (isLoadingMessages || (!hasMoreMessages && isLoadMore)) return;

    const chatWindow   = document.getElementById("chat-window");
    const chatUsername = document.getElementById("chat-username");
    const messagesDiv  = document.getElementById("messages");

    if (!isLoadMore) {
        document.getElementById("leave-group-btn").classList.add("hidden");
        currentActiveContact = username;
        currentActiveGroup = null;
        currentGroupKey = null;
        currentOffset = 0;
        hasMoreMessages = true;
        chatUsername.textContent = username;
        chatWindow.classList.remove("hidden");
        document.getElementById("empty-state").classList.add("hidden");
        messagesDiv.innerHTML = "";

        // Позначити як прочитане тільки при першому відкритті
        await fetch("/api/mark_as_read", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken
          },
          body: JSON.stringify({ sender: username })
        });

        // Перевірка fingerprint для MITM (виконуємо лише при першому відкритті чату)
        try {
          const resp = await fetch(`/api/public_key/${username}`);
          if (resp.ok) {
            const body = await resp.json();
            const jwk  = body.data.public_key;
            const raw  = jwk.x + jwk.y;
            const hash = await crypto.subtle.digest(
              "SHA-256",
              new TextEncoder().encode(raw)
            );
            const fp = Array.from(new Uint8Array(hash))
              .map(b => b.toString(16).padStart(2, "0"))
              .join("")
              .slice(0, 32);
            const fpKey = `fp_${username}`;
            const oldFp = localStorage.getItem(fpKey);
            if (oldFp && oldFp !== fp) {
              if (!confirm(
                `⚠️ Fingerprint для ${username} змінився!\n` +
                `Старий: ${oldFp}\nНовий: ${fp}\n\n` +
                `Натисніть OK, щоб підтвердити.`
              )) return;
            }
            localStorage.setItem(fpKey, fp);
          }
        } catch (err) {
          console.error("MITM check failed:", err);
        }
    }

    isLoadingMessages = true;

    // Завантаження історії (Fan-Out)
    try {
      const resp = await fetch(`/api/messages?contact=${username}&limit=${messageLimit}&offset=${currentOffset}`);
      const data = await resp.json();

      if (!data.messages || data.messages.length === 0) {
          hasMoreMessages = false;
          isLoadingMessages = false;
          return;
      }
      if (data.messages.length < messageLimit) hasMoreMessages = false;

      const oldScrollHeight = messagesDiv.scrollHeight;
      const tempFragment = document.createDocumentFragment();

      for (const msg of data.messages || []) {
        const div = document.createElement("div");
        let content = "[Неможливо прочитати]";
        const isMe = msg.sender_username === currentUser;

        try {
          const iv = isMe ? msg.iv_for_sender : msg.iv_for_receiver;
          const dat = isMe ? msg.content_for_sender : msg.content_for_receiver;

          if (iv && dat) {
            // Використовуємо нову Fan-Out функцію дешифрування
            content = await decryptFanOut(iv, dat, isMe ? currentUser : msg.sender_username);
          }
          div.classList.add("message", isMe ? "my-message" : "other-message");
        } catch (err) { console.warn("❌ Дешифрування не вдалося:", err); }

        div.innerHTML = `<strong>${isMe ? "Я" : escapeHTML(msg.sender_username)}:</strong> ${escapeHTML(content)}`;

        const mediaIv = isMe ? msg.iv_media_for_sender : msg.iv_media_for_receiver;
        const mediaDat = isMe ? msg.media_content_for_sender : msg.media_content_for_receiver;
        if (mediaDat && mediaIv) {
          try {
            const blob = await decryptToBlobFanOut(mediaIv, mediaDat, isMe ? currentUser : msg.sender_username, msg.media_type);
            const url = URL.createObjectURL(blob);
            if (msg.media_type.startsWith("image/")) {
              const img = document.createElement("img"); img.src = url; img.style.maxWidth = "200px"; div.appendChild(img);
            } else {
              const a = document.createElement("a"); a.href = url; a.download = `file_${msg.id}`; a.textContent = "Завантажити файл"; div.appendChild(a);
            }
          } catch (err) {}
        }
        tempFragment.appendChild(div);
      }

      if (isLoadMore) {
        messagesDiv.insertBefore(tempFragment, messagesDiv.firstChild);
        messagesDiv.scrollTop = messagesDiv.scrollHeight - oldScrollHeight;
      } else {
        messagesDiv.appendChild(tempFragment);
        scrollToBottom();
      }
      currentOffset += messageLimit;
    } catch (err) { console.error(err); }
    finally { isLoadingMessages = false; }
  }

  // ===== Динамічна required-валидація =====
  const messageInput = document.getElementById("message-input");
  const mediaInput   = document.getElementById("media-input");

  // Якщо обрали файл — текст уже не required, якщо прибрали файл — знову вмикаємо required
  mediaInput.addEventListener("change", () => {
    messageInput.required = mediaInput.files.length === 0;
  });


  // ===== Надсилання повідомлень =====
  const messageForm = document.getElementById("message-form");
  if (messageForm) {
    messageForm.addEventListener("submit", async e => {
      e.preventDefault();

      // Елементи форми
      const input = document.getElementById("message-input");
      const replyInput = document.getElementById("reply-to");
      const mediaInput = document.getElementById("media-input");
      const receiver = document.getElementById("chat-username").textContent;
      const file = mediaInput.files[0];
      const content = input.value.trim();
      let verifiedMediaType = null;

      if (file) {
        if (file.size > 7 * 1024 * 1024) {
          alert("❌ Файл занадто великий! Максимальний розмір — 7 МБ.");
          return;
        }

        const fileCheck = await validateFileSignature(file);
        if (!fileCheck.isSafe) {
          alert("🚫 Безпека: Формат файлу не підтримується або файл підроблено! Дозволені лише JPG, PNG, GIF, PDF та DOCX/ZIP.");
          mediaInput.value = "";
          messageInput.required = true;
          return;
        }
        verifiedMediaType = fileCheck.realType;
      }

      // Перевірки: має бути хоча б текст або файл
      if (!content && !file) {
        alert("❌ Введіть текст або виберіть файл для відправки");
        return;
      }

      // ОНОВЛЕНО: ЛОГІКА ВІДПРАВКИ В ГРУПУ (Текст + Медіа)
      if (currentActiveGroup && currentGroupKey) {
        try {
          let payload = {
            group_id: currentActiveGroup,
            content: null,
            iv: null,
            media_type: null,
            media_content: null,
            iv_media: null
          };

          // Шифруємо текст, якщо він є
          if (content) {
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, currentGroupKey, new TextEncoder().encode(content));
            payload.content = btoa(String.fromCharCode(...new Uint8Array(encrypted)));
            payload.iv = btoa(String.fromCharCode(...iv));
          }

          // Шифруємо файл, якщо він є
          if (file) {
            if (file.size > 7 * 1024 * 1024) { alert("❌ Файл занадто великий!"); return; }
            const buf = await file.arrayBuffer();
            const encFile = await encryptBase(buf, currentGroupKey); // Використовуємо існуючу функцію
            payload.media_type = verifiedMediaType;
            payload.media_content = encFile.data;
            payload.iv_media = encFile.iv;
          }

          await fetch("/api/groups/send", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
            body: JSON.stringify(payload)
          });

          // Малюємо в себе на екрані
          const div = document.createElement("div");
          div.classList.add("message", "my-message");
          if (content) div.innerHTML = `<strong>Я:</strong> ${escapeHTML(content)}`;

          if (file) {
            const url = URL.createObjectURL(file);
            if (file.type.startsWith("image/")) {
              const img = document.createElement("img"); img.src = url; img.style.maxWidth = "200px"; div.appendChild(img);
            } else {
              const a = document.createElement("a"); a.href = url; a.download = file.name; a.textContent = "Завантажити файл"; div.appendChild(a);
            }
          }

          document.getElementById("messages").appendChild(div);
          scrollToBottom();
          input.value = ""; mediaInput.value = "";
        } catch (err) { console.error("Помилка відправки в групу", err); }

        return;
      }
      // КІНЕЦЬ ЛОГІКИ ГРУПИ (далі йде старий код приватного чату)

      if (!receiver) {
        alert("❌ Виберіть контакт");
        return;
      }
      if (window.mitmAlert) {
        alert("❌ Зв’язок небезпечний");
        return;
      }

      try {
        // 1) Отримуємо ВСІ ключі отримувача і СВОЇ ключі
        const recKeys = await getSharedKeysForUser(receiver);
        const myKeys = await getSharedKeysForUser(currentUser);
        // ДОДАНО: Перевірка наявності ключів
        if (recKeys.length === 0) {
          alert(`❌ Користувач ${receiver} ще не авторизувався на жодному пристрої (немає ключів).`);
          return;
        }
        if (myKeys.length === 0) {
          alert(`❌ Ваших ключів немає на сервері. Перезавантажте сторінку.`);
          return;
        }
        let payload = { receiver, reply_to: replyInput.value || null };

        // — текст
        if (content) {
          const encRec = await encryptFanOut(content, recKeys);
          const encSen = await encryptFanOut(content, myKeys);
          payload.content_for_receiver = encRec.data; payload.iv_for_receiver = encRec.iv;
          payload.content_for_sender = encSen.data; payload.iv_for_sender = encSen.iv;
        } else {
          payload.content_for_sender = null; payload.iv_for_sender = null;
          payload.content_for_receiver = null; payload.iv_for_receiver = null;
        }

        // — файл
        if (file) {
          const buf = await file.arrayBuffer();
          const encRecBuf = await encryptArrayBufferFanOut(buf, recKeys);
          const encSenBuf = await encryptArrayBufferFanOut(buf, myKeys);
          payload.media_type = verifiedMediaType;
          payload.media_content_for_receiver = encRecBuf.data; payload.iv_media_for_receiver = encRecBuf.iv;
          payload.media_content_for_sender = encSenBuf.data; payload.iv_media_for_sender = encSenBuf.iv;
        } else {
          payload.media_type = null; payload.media_content_for_sender = null; payload.iv_media_for_sender = null;
          payload.media_content_for_receiver = null; payload.iv_media_for_receiver = null;
        }

        const res = await fetch("/api/send_message", { method: "POST", headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken }, body: JSON.stringify(payload) });
        if (!res.ok) { const err = await res.json(); alert("❌ " + err.error); return; }

        const div = document.createElement("div"); div.classList.add("message", "my-message");
        if (content) {
          const text = await decryptFanOut(payload.iv_for_sender, payload.content_for_sender, currentUser);
          div.innerHTML = `<strong>Я:</strong> ${escapeHTML(text)}`;
        }
        if (file) {
          const blob = await decryptToBlobFanOut(payload.iv_media_for_sender, payload.media_content_for_sender, currentUser, payload.media_type);
          const url = URL.createObjectURL(blob);
          if (payload.media_type.startsWith("image/")) {
            const img = document.createElement("img"); img.src = url; img.style.maxWidth = "200px"; div.appendChild(img);
          } else {
            const a = document.createElement("a"); a.href = url; a.download = `file_${Date.now()}`; a.textContent = "Завантажити файл"; div.appendChild(a);
          }
        }
        document.getElementById("messages").appendChild(div); scrollToBottom();
        input.value = ""; replyInput.value = ""; mediaInput.value = "";
      } catch (err) { console.error(err); alert("❌ Помилка відправки"); }
    });
  }




  // ===== Кнопка прикріплення медіа =====
  const mediaButton = document.getElementById("media-button");
  if (mediaButton) {
    mediaButton.addEventListener("click", () =>
      document.getElementById("media-input").click()
    );
  }

  // ===== Real-time через Socket.IO =====
  if (typeof io !== "undefined") {
    window.socket = io({ transports: ["websocket"] });
    socket.on("new_message", async data => {
      if (data.receiver !== currentUser) return;
      const chatUsername = document.getElementById("chat-username")?.textContent;
      if (chatUsername === data.sender) {
        let msgText = "[Неможливо прочитати]";
        if (data.iv && data.content) {
          try { msgText = await decryptFanOut(data.iv, data.content, data.sender); } catch(e){}
        } else msgText = data.content;

        const div = document.createElement("div"); div.classList.add("message", "other-message");
        div.innerHTML = `<strong>${escapeHTML(data.sender)}</strong>: ${escapeHTML(msgText)}`;

        if (data.media_content && data.iv_media) {
          try {
            const blob = await decryptToBlobFanOut(data.iv_media, data.media_content, data.sender, data.media_type);
            const url = URL.createObjectURL(blob);
            if (data.media_type.startsWith("image/")) {
              const img = document.createElement("img"); img.src = url; img.style.maxWidth = "200px"; div.appendChild(img);
            } else {
              const a = document.createElement("a"); a.href = url; a.download = `file_${Date.now()}`; a.textContent = "Завантажити файл"; div.appendChild(a);
            }
          } catch (err) {}
        }
        document.getElementById("messages").appendChild(div); scrollToBottom();
      } else {
        document.querySelectorAll("#contacts li").forEach(li => { if (li.innerText === data.sender) li.style.backgroundColor = "#ffd8d8"; });
      }
    });

    socket.on("new_group_message", async data => {
      if (currentActiveGroup === data.group_id && data.sender !== currentUser) {
        const div = document.createElement("div");
        div.classList.add("message", "other-message");

        try {
          // Текст
          if (data.content && data.iv) {
            const text = await decryptDirect({ iv: data.iv, data: data.content }, currentGroupKey);
            div.innerHTML = `<strong>${escapeHTML(data.sender)}:</strong> ${escapeHTML(text)}`;
          } else {
            div.innerHTML = `<strong>${escapeHTML(data.sender)}:</strong>`;
          }

          // Медіа (Real-time)
          if (data.media_content && data.iv_media) {
            const iv = Uint8Array.from(atob(data.iv_media), c => c.charCodeAt(0));
            const dat = Uint8Array.from(atob(data.media_content), c => c.charCodeAt(0));
            const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, currentGroupKey, dat);

            const blob = new Blob([decrypted], { type: data.media_type });
            const url = URL.createObjectURL(blob);
            if (data.media_type.startsWith("image/")) {
              const img = document.createElement("img"); img.src = url; img.style.maxWidth = "200px"; div.appendChild(img);
            } else {
              const a = document.createElement("a"); a.href = url; a.download = "file"; a.textContent = "Завантажити файл"; div.appendChild(a);
            }
          }

          document.getElementById("messages").appendChild(div);
          scrollToBottom();
        } catch(e) { console.error("Помилка дешифрування групи", e); }
      }
    });

    socket.on("user_online", data => console.log(`🟢 ${data.username} онлайн`));
    socket.on("user_offline", data => console.log(`🔴 ${data.username} офлайн`));
  }

  // ===== Обробник скролу для завантаження історії =====
  const messagesContainer = document.getElementById("messages");
  if (messagesContainer) {
      messagesContainer.addEventListener('scroll', () => {
          // Якщо докрутили до верху (залишилось 10 пікселів або менше)
          if (messagesContainer.scrollTop <= 10 && currentActiveContact && hasMoreMessages && !isLoadingMessages) {
              openChat(currentActiveContact, true);
          }
      });
  }
  // ===== Початкове завантаження контактів =====
  loadContacts();

  // ====================================================
  // ===== ГРУПОВІ ЧАТИ (Group Key E2E Магія) ===========
  // ====================================================
  let currentActiveGroup = null;
  let currentGroupKey = null;

  function loadGroups() {
    fetch("/api/groups").then(r => r.json()).then(data => {
      const ul = document.getElementById("groups");
      if (!ul) return; ul.innerHTML = "";
      (data.groups || []).forEach(g => {
        const li = document.createElement("li"); li.innerHTML = `👥 <strong>${g.name}</strong>`;
        li.style.cursor = "pointer"; li.addEventListener("click", () => openGroupChat(g.id, g.name, g.creator)); ul.appendChild(li);
      });
    });
  }
  loadGroups();

  const createGroupForm = document.getElementById("create-group-form");
  if (createGroupForm) {
    createGroupForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const groupName = document.getElementById("group-name").value.trim(), select = document.getElementById("group-members-select"), selectedMembers = Array.from(select.selectedOptions).map(opt => opt.value);
      if (!groupName || selectedMembers.length === 0) {
        alert("Введіть назву та оберіть хоча б одного учасника!"); return;
      }
      selectedMembers.push(currentUser);
      try {
        const groupKeyCrypto = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
        const groupKeyRaw = await crypto.subtle.exportKey("raw", groupKeyCrypto);
        const membersData = [];
        for (const member of selectedMembers) {
          const sharedKeys = await getSharedKeysForUser(member);
          const encGroupKey = await encryptArrayBufferFanOut(groupKeyRaw, sharedKeys);
          membersData.push({ username: member, encrypted_key: JSON.stringify({ iv: encGroupKey.iv, data: encGroupKey.data }) });
        }
        const res = await fetch("/api/groups/create", { method: "POST", headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken }, body: JSON.stringify({ name: groupName, members: membersData }) });
        if (res.ok) { alert("✅ Групу створено!"); document.getElementById("group-name").value = ""; loadGroups(); }
      } catch (err) { console.error(err); alert("❌ Помилка створення"); }
    });
  }

  async function openGroupChat(groupId, groupName, creatorUsername) {
    const leaveBtn = document.getElementById("leave-group-btn");
    leaveBtn.classList.remove("hidden");
    leaveBtn.onclick = async () => {
      if (!confirm(`Ви впевнені, що хочете вийти з групи "${groupName}"?`)) return;
      await fetch("/api/groups/leave", {
        method: "POST", headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
        body: JSON.stringify({ group_id: groupId })
      });

      document.getElementById("chat-window").classList.add("hidden");
      document.getElementById("empty-state").classList.remove("hidden");
      currentActiveGroup = null;
      currentGroupKey = null;

      loadGroups();
    };
    currentActiveContact = null; currentActiveGroup = groupId;
    document.getElementById("chat-username").textContent = `${groupName} (Група)`; document.getElementById("chat-window").classList.remove("hidden");
    document.getElementById("empty-state").classList.add("hidden");
    const messagesDiv = document.getElementById("messages"); messagesDiv.innerHTML = "<i>Розшифрування ключа кімнати...</i>";
    try {
      const res = await fetch(`/api/groups/${groupId}/key`);
      const data = await res.json(); const encData = JSON.parse(data.encrypted_key);
      const decryptedKeyRaw = await decryptFanOutBase(encData.iv, encData.data, creatorUsername, true);
      currentGroupKey = await crypto.subtle.importKey("raw", decryptedKeyRaw, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
      if (window.socket) window.socket.emit("join_group", { group_id: groupId });

      const histRes = await fetch(`/api/groups/messages?group_id=${groupId}&limit=50`);
      const histData = await histRes.json(); messagesDiv.innerHTML = "";
      for (const msg of histData.messages || []) {
        const div = document.createElement("div");
        const isMe = msg.sender_username === currentUser;
        div.classList.add("message", isMe ? "my-message" : "other-message");

        // 1. Розшифровуємо ТЕКСТ (якщо він є)
        if (msg.content && msg.iv) {
          try {
            const text = await decryptDirect({ iv: msg.iv, data: msg.content }, currentGroupKey);
            div.innerHTML = `<strong>${isMe ? "Я" : escapeHTML(msg.sender_username)}:</strong> ${escapeHTML(text)}`;
          } catch(e) {
            div.innerHTML = `<strong>${escapeHTML(msg.sender_username)}:</strong> [Помилка тексту]`;
          }
        } else {
            div.innerHTML = `<strong>${isMe ? "Я" : escapeHTML(msg.sender_username)}:</strong>`;
        }

        // 2. Розшифровуємо МЕДІА (якщо воно є)
        if (msg.media_content && msg.iv_media) {
          try {
            const iv = Uint8Array.from(atob(msg.iv_media), c => c.charCodeAt(0));
            const data = Uint8Array.from(atob(msg.media_content), c => c.charCodeAt(0));
            const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, currentGroupKey, data);

            const blob = new Blob([decrypted], { type: msg.media_type });
            const url = URL.createObjectURL(blob);

            if (msg.media_type.startsWith("image/")) {
              const img = document.createElement("img");
              img.src = url;
              img.style.maxWidth = "200px";
              img.style.display = "block";
              div.appendChild(img);
            } else {
              const a = document.createElement("a");
              a.href = url;
              a.download = `file_${msg.id}`;
              a.textContent = "📎 Завантажити файл";
              a.style.display = "block";
              div.appendChild(a);
            }
          } catch (err) { console.warn("Помилка медіа в групі", err); }
        }
        messagesDiv.appendChild(div);
      }
      scrollToBottom();
    } catch (err) { console.error(err); messagesDiv.innerHTML = "❌ Помилка доступу до групи."; }
  }

  // ====================================================
  // ===== ПЕРЕГЛЯД ПРОФІЛІВ ТА УЧАСНИКІВ ГРУПИ =========
  // ====================================================

  const chatUsernameEl = document.getElementById("chat-username");
  const userInfoModal = document.getElementById("user-info-modal");
  const groupMembersModal = document.getElementById("group-members-modal");

  // 1. Клік на ім'я чату (зверху)
  chatUsernameEl.addEventListener("click", async () => {
    if (currentActiveGroup) {
      // Якщо це група — завантажуємо список учасників
      try {
        const res = await fetch(`/api/groups/${currentActiveGroup}/members`);
        const data = await res.json();
        const ul = document.getElementById("modal-group-list");
        ul.innerHTML = "";

        data.members.forEach(member => {
          const li = document.createElement("li");
          li.textContent = member;
          li.style.padding = "8px";
          li.style.borderBottom = "1px solid #eee";
          li.style.cursor = "pointer";

          // При кліку на учасника групи — відкриваємо його профіль
          li.addEventListener("click", () => {
            groupMembersModal.classList.add("hidden");
            showUserProfile(member);
          });

          ul.appendChild(li);
        });
        groupMembersModal.classList.remove("hidden");
      } catch (err) { console.error("Помилка завантаження учасників", err); }

    } else if (currentActiveContact) {
      // Якщо це приватний чат — одразу відкриваємо профіль
      showUserProfile(currentActiveContact);
    }
  });

 // 2. Функція показу профілю (Оновлена з видаленням)
  async function showUserProfile(username) {
    try {
      const res = await fetch(`/api/user/${username}/info`);
      if (res.ok) {
        const info = await res.json();
        document.getElementById("modal-username").textContent = info.username;
        document.getElementById("modal-avatar").textContent = info.username[0].toUpperCase();
        document.getElementById("modal-email").textContent = info.email || "Приховано";
        document.getElementById("modal-phone").textContent = info.phone || "Приховано";

        const msgBtn = document.getElementById("modal-msg-btn");
        const deleteBtn = document.getElementById("modal-delete-btn");

        // Перевіряємо, чи є юзер у нас в контактах зараз
        const isContact = Array.from(document.querySelectorAll("#contacts li")).some(li => li.textContent === info.username);

        if (info.username === currentUser) {
          msgBtn.style.display = "none";
          deleteBtn.style.display = "none";
        } else {
          msgBtn.style.display = "block";

          // Якщо він наш контакт — показуємо кнопку видалення
          if (isContact) {
             deleteBtn.classList.remove("hidden");
             deleteBtn.style.display = "block";
          } else {
             deleteBtn.classList.add("hidden");
             deleteBtn.style.display = "none";
          }

          msgBtn.onclick = async () => {
            userInfoModal.classList.add("hidden");
            await fetch("/api/add_contact", {
              method: "POST", headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
              body: JSON.stringify({ username: info.username })
            });
            loadContacts();
            openChat(info.username);
          };

          // Логіка видалення
          deleteBtn.onclick = async () => {
            if (!confirm(`Ви точно хочете видалити ${info.username} з контактів? Ця дія взаємна.`)) return;
            userInfoModal.classList.add("hidden");
            await fetch("/api/remove_contact", {
              method: "POST", headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
              body: JSON.stringify({ username: info.username })
            });
            loadContacts(); // Оновлюємо список

            // Якщо чат з ним зараз відкритий — закриваємо його
            if (currentActiveContact === info.username) {
               document.getElementById("chat-window").classList.add("hidden");
               document.getElementById("empty-state").classList.remove("hidden");
            }
          };
        }

        userInfoModal.classList.remove("hidden");
      }
    } catch (err) { console.error("Помилка завантаження профілю", err); }
  }
// ===== ЗАКРИТТЯ МОДАЛЬНИХ ВІКОН =====
  document.querySelectorAll('.close-btn').forEach(btn => {
    btn.addEventListener('click', function() {
      // Знаходимо найближчий батьківський елемент з класом 'modal' і ховаємо його
      this.closest('.modal').classList.add('hidden');
    });
  });
});
