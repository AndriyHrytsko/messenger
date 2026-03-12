document.addEventListener("DOMContentLoaded", async () => {
  console.log("✅ JavaScript loaded");
  const currentUser = document.getElementById("app")?.dataset?.user || null;
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
        "jwk",
        storedPrivJwk,
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveKey"]
      );
      pubKeyCrypto = await crypto.subtle.importKey(
        "jwk",
        storedPubJwk,
        { name: "ECDH", namedCurve: "P-256" },
        false,
        []
      );
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
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key: pubJwk })
    });
    const result = await res.json();
    console.log("POST /api/public_key ➞", res.status, result);


    // 8) Використовуємо пару
    privKeyCrypto = pair.privateKey;
    pubKeyCrypto  = pair.publicKey;
  }




  // ===== Отримання спільного AES-GCM ключа через ECDH =====
  async function getSharedKey(otherUsername) {
    const cacheName = `shared_${otherUsername}`;

    // 1) Якщо вже є Uint8Array в IndexedDB — імпортуємо напряму
    const cached = await getKey(cacheName);
    if (cached instanceof Uint8Array) {
      return crypto.subtle.importKey(
        "raw",
        cached.buffer,
        { name: "AES-GCM" },
        true,
        ["encrypt","decrypt"]
      );
    }

    // 2) Інакше — отримуємо JWK вашого співрозмовника і робимо ECDH-deriveKey
    const resp = await fetch(`/api/public_key/${otherUsername}`);
    if (!resp.ok) {
      throw new Error("Не вдалося отримати публічний ключ для " + otherUsername);
    }
    const { data: { public_key: theirJwk } } = await resp.json();

    // Прибираємо key_ops, щоб importKey не конфліктував з JWK.key_ops§
    const { key_ops, ...jwkClean } = theirJwk;

    // Імпортуємо публічний ключ без жодних операцій
    const theirPub = await crypto.subtle.importKey(
      "jwk",
      jwkClean,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );

    // Генеруємо спільний ключ AES-GCM
    const sharedKey = await crypto.subtle.deriveKey(
      { name: "ECDH", public: theirPub },
      privKeyCrypto,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt","decrypt"]
    );

    // 3) Експортуємо raw-ключ та зберігаємо в IndexedDB як Uint8Array
    const rawKey= await crypto.subtle.exportKey("raw", sharedKey);
    const rawBytes= new Uint8Array(rawKey);
    await setKey(cacheName, rawBytes);

    return sharedKey;
  }


  // ===== Шифрування / Дешифрування =====
  async function encrypt(text, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      new TextEncoder().encode(text)
    );
    return {
      iv: btoa(String.fromCharCode(...iv)),
      data: btoa(String.fromCharCode(...new Uint8Array(encrypted)))
    };
  }

  async function decrypt(payload, key) {
    if (!payload?.iv || !payload?.data || !key) {
      throw new Error("Invalid decrypt parameters");
    }
    const iv   = Uint8Array.from(atob(payload.iv), c => c.charCodeAt(0));
    const data = Uint8Array.from(atob(payload.data), c => c.charCodeAt(0));
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      data
    );
    return new TextDecoder().decode(decrypted);
  }

    // encryptArrayBuffer: шифрує ArrayBuffer → { iv, data }
  async function encryptArrayBuffer(buffer, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      buffer
    );
    return {
      iv: btoa(String.fromCharCode(...iv)),
      data: btoa(String.fromCharCode(...new Uint8Array(encrypted)))
    };
  }

  // decryptToBlob: дешифрує в Blob для відображення/завантаження
  async function decryptToBlob(payload, key, type) {
    const iv   = Uint8Array.from(atob(payload.iv), c => c.charCodeAt(0));
    const data = Uint8Array.from(atob(payload.data), c => c.charCodeAt(0));
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      data
    );
    return new Blob([decrypted], { type });
  }


  // ===== Утиліти =====
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
  if (addFriendForm) {
    addFriendForm.addEventListener("submit", async e => {
      e.preventDefault();
      const username = document.getElementById("friend-username").value.trim();
      if (!username) { alert("❌ Введіть ім’я користувача"); return; }
      try {
        const res= await fetch("/api/add_contact", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username })
        });
        console.log("POST /api/public_key status:", res.status);
        console.log("Response:", await res.json());
        const result = await res.json();
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
        if (!ul) return;
        ul.innerHTML = "";
        (data.contacts || []).forEach(c => {
          const li = document.createElement("li");
          li.textContent = c;
          li.style.cursor = "pointer";
          li.addEventListener("click", () => openChat(c));
          ul.appendChild(li);
        });
      })
      .catch(err => console.error(err));
  }

  // ===== Відкриття чату =====
  async function openChat(username) {
    const chatWindow   = document.getElementById("chat-window");
    const chatUsername = document.getElementById("chat-username");
    const messagesDiv  = document.getElementById("messages");

    chatUsername.textContent = username;
    chatWindow.classList.remove("hidden");
    messagesDiv.innerHTML = "";

    // Позначити як прочитане
    await fetch("/api/mark_as_read", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sender: username })
    });

    // Перевірка fingerprint для MITM
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

    // Завантаження історії
    try {
      const sharedKey = await getSharedKey(username);
      console.log("🔑 sharedKey для", username, sharedKey);

      const resp = await fetch(`/api/messages?contact=${username}`);
      const data = await resp.json();

      for (const msg of data.messages || []) {
        const div     = document.createElement("div");
        let content   = "[Неможливо прочитати]";

        try {
          const isMe = msg.sender_username === currentUser;
          // вибираємо відповідні поля для decrypt
          const iv   = isMe ? msg.iv_for_sender   : msg.iv_for_receiver;
          const dat  = isMe ? msg.content_for_sender : msg.content_for_receiver;

          if (iv && dat) {
            content = await decrypt(
              { iv, data: dat },
              sharedKey
            );
          }

          div.classList.add(
            "message",
            isMe ? "my-message" : "other-message"
          );

        } catch (err) {
          console.warn("❌ Дешифрування не вдалося:", err);
        }

        // Відображаємо текст
        div.innerHTML = `<strong>${
          msg.sender_username === currentUser
            ? "Я"
            : escapeHTML(msg.sender_username)
        }:</strong> ${escapeHTML(content)}`;

        // Малюємо медіа, якщо є
        if (msg.media_content_for_receiver && msg.iv_media_for_receiver) {
          try {
            const blob = await decryptToBlob(
              {
                iv:   msg.iv_media_for_receiver,
                data: msg.media_content_for_receiver
              },
              sharedKey,
              msg.media_type
            );
            const url = URL.createObjectURL(blob);
            if (msg.media_type.startsWith("image/")) {
              const img = document.createElement("img");
              img.src = url;
              img.style.maxWidth = "200px";
              div.appendChild(img);
            } else {
              const a = document.createElement("a");
              a.href = url;
              a.download = `file_${msg.id}`;
              a.textContent = "Завантажити файл";
              div.appendChild(a);
            }
          } catch (err) {
            console.warn("Помилка дешифрування медіа:", err);
          }
        }

        messagesDiv.appendChild(div);
      }

      scrollToBottom();
      // — після scrollToBottom() або наприкінці openChat:
      if (window.socket) {
        const room = [currentUser, username].sort().join('_');
        socket.emit('join', { room });
      }

    } catch (err) {
      console.error("Не вдалося завантажити історію:", err);
    }
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

      // Перевірки: має бути хоча б текст або файл
      if (!content && !file) {
        alert("❌ Введіть текст або виберіть файл для відправки");
        return;
      }
      if (!receiver) {
        alert("❌ Виберіть контакт");
        return;
      }
      if (window.mitmAlert) {
        alert("❌ Зв’язок небезпечний");
        return;
      }

      try {
        // 1) Отримуємо спільний ключ
        const sharedKey = await getSharedKey(receiver);

        // 2) Формуємо payload
        let payload = { receiver, reply_to: replyInput.value || null };

        // — текст (якщо є)
        if (content) {
          const encSelf = await encrypt(content, sharedKey);
          const encRec = await encrypt(content, sharedKey);
          payload.content_for_sender = encSelf.data;
          payload.iv_for_sender = encSelf.iv;
          payload.content_for_receiver = encRec.data;
          payload.iv_for_receiver = encRec.iv;
        } else {
          payload.content_for_sender = null;
          payload.iv_for_sender  = null;
          payload.content_for_receiver = null;
          payload.iv_for_receiver = null;
        }

        // — файл (якщо є)
        if (file) {
          const buf = await file.arrayBuffer();
          const encBuf= await encryptArrayBuffer(buf, sharedKey);
          payload.media_type = file.type;
          payload.media_content_for_sender = encBuf.data;
          payload.iv_media_for_sender = encBuf.iv;
          payload.media_content_for_receiver = encBuf.data;
          payload.iv_media_for_receiver = encBuf.iv;
        } else {
          payload.media_type = null;
          payload.media_content_for_sender = null;
          payload.iv_media_for_sender = null;
          payload.media_content_for_receiver = null;
          payload.iv_media_for_receiver = null;
        }

        // 3) Надсилаємо на сервер
        const res = await fetch("/api/send_message", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        if (!res.ok) {
          const err = await res.json();
          alert("❌ " + err.error);
          return;
        }

        // 4) Відображаємо своє повідомлення
        const div = document.createElement("div");
        div.classList.add("message", "my-message");

        // — відображаємо текст
        if (content) {
          const text = await decrypt(
            { iv: payload.iv_for_sender, data: payload.content_for_sender },
            sharedKey
          );
          div.innerHTML = `<strong>Я:</strong> ${escapeHTML(text)}`;
        }

        // — відображаємо файл/картинку
        if (file) {
          const blob = await decryptToBlob(
            { iv: payload.iv_media_for_sender, data: payload.media_content_for_sender },
            sharedKey,
            payload.media_type
          );
          const url = URL.createObjectURL(blob);
          if (payload.media_type.startsWith("image/")) {
            const img = document.createElement("img");
            img.src = url;
            img.style.maxWidth = "200px";
            div.appendChild(img);
          } else {
            const a = document.createElement("a");
            a.href = url;
            a.download = `file_${Date.now()}`;
            a.textContent = "Завантажити файл";
            div.appendChild(a);
          }
        }

        document.getElementById("messages").appendChild(div);
        scrollToBottom();

        // 5) Очищаємо форму
        input.value = "";
        replyInput.value = "";
        mediaInput.value = "";
      } catch (err) {
        console.error(err);
        alert("❌ Помилка відправки");
      }
    });
  }




  // ===== Кнопка прикріплення медіа =====
  const mediaButton = document.getElementById("media-button");
  if (mediaButton) {
    mediaButton.addEventListener("click", () =>
      document.getElementById("media-input").click()
    );
  }

  // ===== Вихід (Logout) =====
  const logoutButton = document.getElementById("logoutButton");
  if (logoutButton) {
    logoutButton.addEventListener("click", async () => {
      if ((await fetch("/logout", { method: "POST" })).ok) {
        window.location.href = "/login";
      }
    });
  }

  // ===== Real-time через Socket.IO =====
  if (typeof io !== "undefined") {
    window.socket = io({ transports: ["websocket"] });
    socket.on("new_message", async data => {
      if (data.receiver !== currentUser) return;
      const chatUsername = document.getElementById("chat-username")?.textContent;
      if (chatUsername === data.sender) {
        let msgText = "[Неможливо прочитати]";
        if (data.iv && data.iv !== "no_iv_for_media") {
          const key = await getSharedKey(data.sender);
          msgText = await decrypt({ iv: data.iv, data: data.content }, key);
        } else {
          msgText = data.content;
        }
        const div = document.createElement("div");
        div.classList.add("message", "other-message");
        div.innerHTML = `<strong>${escapeHTML(data.sender)}</strong>: ` + `${escapeHTML(msgText)}`;
        if (data.media_content && data.iv_media) {
          try {
            const blob = await decryptToBlob(
              { iv: data.iv_media, data: data.media_content },
              await getSharedKey(data.sender),
              data.media_type
            );
            const url = URL.createObjectURL(blob);
            if (data.media_type.startsWith("image/")) {
              const img = document.createElement("img");
              img.src = url; img.style.maxWidth = "200px";
              div.appendChild(img);
            } else {
              const a = document.createElement("a");
              a.href = url; a.download = `file_from_${data.sender}`;
              a.textContent = "Завантажити файл";
              div.appendChild(a);
            }
          } catch (err) {
            console.warn("Не вдалось дешифрувати медіа в real-time:", err);
          }
        }
        document.getElementById("messages").appendChild(div);
        scrollToBottom();
      } else {
        document.querySelectorAll("#contacts li").forEach(li => {
          if (li.innerText === data.sender) li.style.backgroundColor = "#ffd8d8";
        });
      }
    });
    socket.on("user_online", data => console.log(`🟢 ${data.username} онлайн`));
    socket.on("user_offline", data => console.log(`🔴 ${data.username} офлайн`));
  }

  // ===== Початкове завантаження контактів =====
  loadContacts();
});
