package cabinet

import (
	"bytes"
	"html/template"
	"net/http"
	"sreda/internal/machine"
)

type manualPageData struct {
	ID                        int64
	Code, CSRF, Nonce, Config string
	Parameters                machine.ManualParameters
}

func (a *App) renderManual(w http.ResponseWriter, status int, id int64, code string, params machine.ManualParameters) {
	csrf, nonce := randomToken(), randomToken()
	data := manualPageData{ID: id, Code: code, CSRF: csrf, Nonce: nonce, Parameters: params, Config: params.ConfigurationTemplate()}
	var body bytes.Buffer
	if err := manualPage.Execute(&body, data); err != nil {
		a.serverError(w, err)
		return
	}
	setCookie(w, csrfCookie, csrf, int(sessionLifetime.Seconds()))
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-"+nonce+"'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body.Bytes())
}

var manualPage = template.Must(template.New("manual").Parse(`<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>WireGuard — Среда</title><style>body{font:17px system-ui;max-width:850px;margin:40px auto;padding:0 24px;color:#16352b}input,button{font:inherit;padding:12px}button{background:#235c43;color:white;border:0;border-radius:8px}pre,code{overflow-wrap:anywhere;white-space:pre-wrap}label{display:block;margin:12px 0}section,details{border:1px solid #ccd9cf;padding:20px;margin:20px 0;border-radius:12px}</style><a href="/machines">Машины</a><h1>Ручной WireGuard</h1><p>Машина №{{.ID}}. Один конфиг используется для всех её публикаций. Приложение должно слушать назначенный адрес WireGuard; автоматической доставки к loopback без агента нет.</p>
{{if .Code}}<section id="enrollment" data-machine="{{.ID}}" data-code="{{.Code}}"><h2>Готовый конфиг</h2><p>Ключ создаётся в этом браузере. Сервер получит только публичный ключ. Сохраните скачанный файл перед закрытием страницы: сервер не хранит private key и не сможет повторить скачивание.</p><button id="generate" type="button">Создать и скачать конфиг</button><p id="result" role="status"></p><a id="download" hidden download="wg-sreda.conf">Скачать конфиг ещё раз</a><pre id="configuration"></pre></section>
<details><summary>Если браузер не поддерживает генерацию ключа</summary><p>На подключаемой машине установите wireguard-tools. Выполните локально:</p><pre>umask 077
wg genkey &gt; sreda-private.key
wg pubkey &lt; sreda-private.key &gt; sreda-public.key</pre><p>Вставьте сюда только содержимое sreda-public.key. Скачанный после регистрации шаблон дополните PrivateKey из sreda-private.key в локальном редакторе. Private key в кабинет не вводите.</p><form method="post" action="/machines/{{.ID}}/wireguard"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="code" value="{{.Code}}"><label>Публичный ключ <input name="public_key" autocomplete="off" required maxlength="44"></label><button>Зарегистрировать публичный ключ</button></form></details>
{{else}}<p>Параметры относятся к существующему подключению. Для замены утраченного private key используйте переподключение машины.</p>{{end}}
<section><h2>Настрою сам</h2><p><a href="/machines/{{.ID}}/wireguard">Открыть параметры подключения</a></p>{{if .Parameters.Address}}<dl><dt>Адрес машины</dt><dd><code>{{.Parameters.Address}}</code></dd><dt>Публичный ключ машины</dt><dd><code>{{.Parameters.PublicKey}}</code></dd><dt>Endpoint мамы</dt><dd><code>{{.Parameters.Tunnel.Endpoint}}</code></dd><dt>Публичный ключ мамы</dt><dd><code>{{.Parameters.Tunnel.GatewayPublicKey}}</code></dd><dt>AllowedIPs</dt><dd><code>{{.Parameters.Tunnel.GatewayAddress}}</code></dd><dt>PersistentKeepalive</dt><dd>25 секунд</dd></dl><p><a href="/machines/{{.ID}}/wireguard/template">Скачать шаблон без private key</a></p><pre>{{.Config}}</pre>{{else}}<p>Назначенный адрес появится после регистрации публичного ключа.</p>{{end}}<p>Состояние связи определяется последним WireGuard-handshake. Оно не подтверждает исправность приложения. Приватная связь с другими машинами запрещена шлюзом.</p></section>
{{if .Code}}<script nonce="{{.Nonce}}">
(()=>{
 const root=document.getElementById('enrollment'),button=document.getElementById('generate'),status=document.getElementById('result'),download=document.getElementById('download');
 let secrets=null,objectURL=null;
 const base64=bytes=>btoa(String.fromCharCode(...bytes));
 const decode=value=>Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-value.length%4)%4)),c=>c.charCodeAt(0));
 const line=value=>{if(typeof value!=='string'||/[\r\n]/.test(value))throw new Error('invalid parameter');return value;};
 button.addEventListener('click',async()=>{
  button.disabled=true;status.textContent='Подготовка подключения…';
  try{
   if(!secrets){
    if(!window.isSecureContext||!crypto.subtle)throw new Error('unsupported browser');
    const keys=await crypto.subtle.generateKey({name:'X25519'},true,['deriveBits']);
    const pub=new Uint8Array(await crypto.subtle.exportKey('raw',keys.publicKey));
    const jwk=await crypto.subtle.exportKey('jwk',keys.privateKey);
    if(jwk.kty!=='OKP'||jwk.crv!=='X25519'||typeof jwk.d!=='string')throw new Error('unsupported export');
    const raw=decode(jwk.d);if(raw.length!==32||pub.length!==32)throw new Error('invalid export');
    raw[0]&=248;raw[31]&=127;raw[31]|=64;
    const credential=base64(crypto.getRandomValues(new Uint8Array(32))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
    secrets={privateKey:base64(raw),publicKey:base64(pub),credential};raw.fill(0);
   }
   let response=await fetch('/api/agent/enroll',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:root.dataset.code,public_key:secrets.publicKey,credential:secrets.credential})});
   let parameters;
   if(response.status===401){
    response=await fetch('/machines/'+root.dataset.machine+'/wireguard',{headers:{'Accept':'application/json'}});
    if(!response.ok)throw new Error('enrollment incomplete');
    parameters=await response.json();if(parameters.public_key!==secrets.publicKey)throw new Error('different public key');
   }else{if(response.status!==201)throw new Error('enrollment incomplete');parameters=await response.json();}
   if(String(parameters.machine_id)!==root.dataset.machine)throw new Error('different machine');
   const address=line(parameters.address),tunnel=parameters.tunnel;
   if(!/^10\.203\.0\.(?:[2-9]|[1-9][0-9]|10[01])\/32$/.test(address))throw new Error('invalid address');
   const configuration='[Interface]\nPrivateKey = '+secrets.privateKey+'\nAddress = '+address+'\n\n[Peer]\nPublicKey = '+line(tunnel.gateway_public_key)+'\nEndpoint = '+line(tunnel.endpoint)+'\nAllowedIPs = '+line(tunnel.gateway_address)+'\nPersistentKeepalive = 25\n';
   if(objectURL)URL.revokeObjectURL(objectURL);
   objectURL=URL.createObjectURL(new Blob([configuration],{type:'text/plain'}));download.href=objectURL;download.hidden=false;download.click();
   document.getElementById('configuration').textContent=configuration;
   status.textContent='Конфиг создан. Сохраните его и установите на этой машине. Handshake появится после запуска WireGuard.';
  }catch(_){status.textContent='Не удалось подготовить конфиг. Можно повторить попытку; при отсутствии X25519 в браузере используйте локальную генерацию ниже.';button.disabled=false;}
 });
 window.addEventListener('pagehide',()=>{if(objectURL)URL.revokeObjectURL(objectURL);secrets=null;});
})();
</script>{{end}}</html>`))
