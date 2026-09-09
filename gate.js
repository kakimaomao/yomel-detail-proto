(function(){
  var STORE = "yomel-proto-pw", ITER = 250000;
  var gate = document.getElementById("gate");
  var form = document.getElementById("gateForm");
  var pw   = document.getElementById("gatePw");
  var go   = document.getElementById("gateGo");
  var msg  = document.getElementById("gateMsg");
  var payloadCache = null;

  function say(t, bad){ msg.textContent = t || ""; msg.className = bad ? "msg bad" : "msg"; }

  if(!window.crypto || !window.crypto.subtle){
    say("この環境では復号できません。https で開いてください。", true);
    go.disabled = true; return;
  }

  function bytes(s){ return new TextEncoder().encode(s); }

  function fetchPayload(){
    if(payloadCache) return Promise.resolve(payloadCache);
    return fetch("payload.bin", {cache:"force-cache"}).then(function(r){
      if(!r.ok) throw new Error("payload " + r.status);
      return r.arrayBuffer();
    }).then(function(b){
      var u = new Uint8Array(b);
      if(String.fromCharCode(u[0],u[1],u[2],u[3]) !== "YMP1") throw new Error("format");
      payloadCache = u; return u;
    });
  }

  function unlock(pass){
    return fetchPayload().then(function(u){
      var salt = u.subarray(4, 20), iv = u.subarray(20, 32), body = u.subarray(32);
      return crypto.subtle.importKey("raw", bytes(pass), "PBKDF2", false, ["deriveKey"])
        .then(function(base){
          return crypto.subtle.deriveKey(
            {name:"PBKDF2", salt:salt, iterations:ITER, hash:"SHA-256"},
            base, {name:"AES-GCM", length:256}, false, ["decrypt"]);
        })
        .then(function(key){ return crypto.subtle.decrypt({name:"AES-GCM", iv:iv}, key, body); });
    }).then(function(plain){
      var p = new Uint8Array(plain);
      var n = new DataView(p.buffer, p.byteOffset, 4).getUint32(0);
      window.__DATA = JSON.parse(new TextDecoder().decode(p.subarray(4, 4 + n)));
      window.__AUDIO_BYTES = p.subarray(4 + n);
      try{ localStorage.setItem(STORE, pass); }catch(e){}
      open_();
    });
  }

  function open_(){
    if(gate) gate.parentNode.removeChild(gate);
    if(window.__AFTER_UNLOCK === "reveal"){
      document.getElementById("picker").hidden = false;
      return;
    }
    var s = document.createElement("script");
    s.src = "app.js";
    document.body.appendChild(s);
  }

  function attempt(pass, silent){
    go.disabled = true;
    say(silent ? "読み込み中…" : "確認中…");
    return unlock(pass).catch(function(e){
      go.disabled = false;
      if(String(e && e.message).indexOf("payload") === 0) say("ファイルを読み込めませんでした。", true);
      else if(silent) say("");                       /* 保存したパスワードが古いだけ */
      else { say("パスワードが違います。", true); pw.value = ""; pw.focus(); }
      if(silent) try{ localStorage.removeItem(STORE); }catch(e2){}
    });
  }

  form.addEventListener("submit", function(e){
    e.preventDefault();
    var v = pw.value.trim();
    if(!v){ pw.focus(); return; }
    attempt(v, false);
  });

  var saved = null;
  try{ saved = localStorage.getItem(STORE); }catch(e){}
  if(saved) attempt(saved, true);           /* 一度入れた端末では聞かない */
  else setTimeout(function(){ pw.focus(); }, 200);
})();
