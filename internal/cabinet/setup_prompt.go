package cabinet

import (
	"bytes"
	"html/template"
	"net/http"
	"sreda/internal/setupprompt"
	"strconv"
)

func (a *App) machineSetupPrompt(w http.ResponseWriter, r *http.Request) {
	user, ok := a.currentUser(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	text, err := setupprompt.New(a.machines, a.publications).Machine(r.Context(), user.ID, id)
	if err != nil {
		a.machineError(w, err)
		return
	}
	a.renderSetupPrompt(w, text)
}
func (a *App) publicationSetupPrompt(w http.ResponseWriter, r *http.Request) {
	user, ok := a.currentUser(w, r)
	if !ok {
		return
	}
	text, err := setupprompt.New(a.machines, a.publications).Publication(r.Context(), user.ID, r.PathValue("id"))
	if err != nil {
		a.machineError(w, err)
		return
	}
	a.renderSetupPrompt(w, text)
}
func (a *App) renderSetupPrompt(w http.ResponseWriter, text string) {
	nonce := randomToken()
	var b bytes.Buffer
	if err := setupPromptPage.Execute(&b, struct{ Text, Nonce string }{text, nonce}); err != nil {
		a.serverError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-"+nonce+"'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	_, _ = w.Write(b.Bytes())
}

var setupPromptPage = template.Must(template.New("setup-prompt").Parse(`<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Промпт для настройки — Среда</title><style>body{font:17px system-ui;max-width:850px;margin:40px auto;padding:0 24px;color:#16352b}textarea{width:100%;min-height:32em;font:inherit}button{font:inherit;padding:12px;background:#235c43;color:white;border:0;border-radius:8px}</style><a href="/machines">Машины</a> · <a href="/publications">Публикации</a><h1>Промпт для настройки</h1><p>Добавьте описание и документацию приложения. Текст составлен из шаблона. Кнопка копирует его в буфер обмена; передать текст во внешнюю нейросеть вы можете самостоятельно.</p><label for="prompt">Текст промпта</label><textarea id="prompt">{{.Text}}</textarea><p><button type="button" id="copy">Скопировать промпт для настройки</button></p><p id="result" role="status" aria-live="polite"></p><script nonce="{{.Nonce}}">document.getElementById('copy').addEventListener('click',async()=>{const text=document.getElementById('prompt'),status=document.getElementById('result');try{await navigator.clipboard.writeText(text.value);status.textContent='Промпт скопирован.';}catch(_){text.focus();text.select();status.textContent='Не удалось скопировать автоматически. Текст выделен: скопируйте его вручную.';}});</script></html>`))
