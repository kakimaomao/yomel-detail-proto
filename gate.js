(function(){
  var STORE = "yomel-proto-pw", KSTORE = "yomel-proto-key", ITER = 250000;
  var gate = document.getElementById("gate");
  var form = document.getElementById("gateForm");
  var pw   = document.getElementById("gatePw");
  var go   = document.getElementById("gateGo");
  var msg  = document.getElementById("gateMsg");
  var VERIFY = window.__VERIFY || null;      /* 入口ページだけ。中身を落とさずに合否を出す */
  var payloadCache = null;

  function say(t, bad){ msg.textContent = t || ""; msg.className = bad ? "msg bad" : "msg"; }
  function silent(on){ gate.classList.toggle("silent", !!on); }

  if(!window.crypto || !window.crypto.subtle){
    say("この環境では復号できません。https で開いてください。", true);
    go.disabled = true; return;
  }

  function bytes(s){ return new TextEncoder().encode(s); }
  function unhex(s){
    var a = new Uint8Array(s.length / 2);
    for(var i = 0; i < a.length; i++) a[i] = parseInt(s.substr(i * 2, 2), 16);
    return a;
  }
  function hex(buf){
    return Array.prototype.map.call(new Uint8Array(buf), function(b){
      return ("0" + b.toString(16)).slice(-2);
    }).join("");
  }

  /* パスワードと salt から 256bit の鍵を作る。ここが一番重い（意図的に重くしてある） */
  function deriveBits(pass, salt){
    return crypto.subtle.importKey("raw", bytes(pass), "PBKDF2", false, ["deriveBits"])
      .then(function(base){
        return crypto.subtle.deriveBits(
          {name:"PBKDF2", salt:salt, iterations:ITER, hash:"SHA-256"}, base, 256);
      });
  }

  /* 一番重い PBKDF2 の結果を salt ごとに覚えておく。2ページ目以降は復号だけで開く。
     保存しているパスワードと同じ秘密なので、これで守りが弱くなることはない。 */
  function keyBits(pass, salt){
    var sh = hex(salt), got = null;
    try{ got = JSON.parse(localStorage.getItem(KSTORE) || "null"); }catch(e){}
    if(got && got.salt === sh && got.bits) return Promise.resolve(unhex(got.bits).buffer);
    return deriveBits(pass, salt).then(function(bits){
      try{ localStorage.setItem(KSTORE, JSON.stringify({salt:sh, bits:hex(bits)})); }catch(e){}
      return bits;
    });
  }

  function fetchPayload(){
    if(payloadCache) return Promise.resolve(payloadCache);
    return fetch("payload.bin", {cache:"force-cache"}).then(function(r){
      if(!r.ok) throw new Error("payload " + r.status);
      return r.arrayBuffer();
    }).then(function(b){
      var u = new Uint8Array(b);
      if(String.fromCharCode(u[0], u[1], u[2], u[3]) !== "YMP1") throw new Error("payload format");
      payloadCache = u; return u;
    });
  }

  /* 入口ページ: 検証用ハッシュと突き合わせるだけ。4.5MB は開いた後に裏で先読みする */
  function check(pass){
    return keyBits(pass, unhex(VERIFY.salt))
      .then(function(bits){
        var v = new Uint8Array(bits.byteLength + 6);
        v.set(new Uint8Array(bits), 0); v.set(bytes("verify"), bits.byteLength);
        return crypto.subtle.digest("SHA-256", v);
      })
      .then(function(h){
        if(hex(h) !== VERIFY.hash) throw new Error("bad password");
        try{ localStorage.setItem(STORE, pass); }catch(e){}
        open_();
        setTimeout(function(){ fetchPayload().catch(function(){}); }, 200);
      });
  }

  /* 各案のページ: payload を復号して中身を渡す */
  function unlock(pass){
    return fetchPayload().then(function(u){
      var salt = u.subarray(4, 20), iv = u.subarray(20, 32), body = u.subarray(32);
      return keyBits(pass, salt)
        .then(function(bits){
          return crypto.subtle.importKey("raw", bits, {name:"AES-GCM"}, false, ["decrypt"]);
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
    if(gate && gate.parentNode) gate.parentNode.removeChild(gate);
    if(VERIFY){ document.getElementById("picker").hidden = false; return; }
    var s = document.createElement("script");
    s.src = "app.js" + (window.__APPV ? "?v=" + window.__APPV : "");   /* 古いキャッシュを掴まないように */
    document.body.appendChild(s);
  }

  function attempt(pass, saved){
    go.disabled = true;
    silent(saved);                           /* 保存済みなら入力欄を見せない */
    say(saved ? "" : "確認中…");
    return (VERIFY ? check(pass) : unlock(pass)).catch(function(e){
      var m = String(e && e.message);
      go.disabled = false;
      silent(false);
      if(m.indexOf("payload") === 0){
        say("ファイルを読み込めませんでした。通信を確認してください。", true);
      } else if(saved){
        try{ localStorage.removeItem(STORE); localStorage.removeItem(KSTORE); }catch(e2){}
        say("パスワードが変わりました。入れ直してください。", true);
        pw.value = ""; pw.focus();
      } else {
        say("パスワードが違います。", true);
        pw.value = ""; pw.focus();
      }
    });
  }

  form.addEventListener("submit", function(e){
    e.preventDefault();
    var v = pw.value.trim();
    if(!v){ pw.focus(); return; }
    attempt(v, false);
  });

  var stored = null;
  try{ stored = localStorage.getItem(STORE); }catch(e){}
  /* 既定は splash（入力欄は隠れている）。保存が無い時に初めて入力欄を出すので、
     2回目以降にパスワード画面が点滅することがない。 */
  if(stored){
    attempt(stored, true);
  } else {
    silent(false);
    setTimeout(function(){ pw.focus(); }, 200);
  }
})();
