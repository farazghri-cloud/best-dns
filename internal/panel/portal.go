package panel

import (
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/farazghri-cloud/best-dns/internal/store"
)

// register implements the one-click /ip/{token} flow: the client opens its
// private link from the console or phone browser and the address it is seen
// from becomes its bound address, so dynamic residential/mobile IPs keep
// working without the operator touching anything.
func (p *Panel) register(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.PathValue("token"))
	client, err := p.store.ClientByToken(token)
	if err != nil {
		p.portalMessage(w, r, http.StatusNotFound, "لینک نامعتبر است",
			"این لینک ثبت IP معتبر نیست یا باطل شده است. از پشتیبانی بخواه لینک جدید بفرستد.")
		return
	}
	if !client.Enabled {
		p.portalMessage(w, r, http.StatusForbidden, "حساب غیرفعال است",
			"اشتراک شما غیرفعال شده است. برای فعال‌سازی با پشتیبانی تماس بگیرید.")
		return
	}
	now := time.Now()
	if client.ExpiresAt != nil && now.After(*client.ExpiresAt) {
		p.portalMessage(w, r, http.StatusForbidden, "اشتراک منقضی شده",
			"تاریخ پایان اشتراک شما گذشته است. برای تمدید با پشتیبانی تماس بگیرید.")
		return
	}
	if client.QuotaBytes > 0 && client.UsedBytes >= client.QuotaBytes {
		p.portalMessage(w, r, http.StatusForbidden, "سقف ترافیک پر شده",
			"حجم مجاز اشتراک شما به پایان رسیده است. برای تمدید با پشتیبانی تماس بگیرید.")
		return
	}

	ip := clientIP(r)
	updated, err := p.store.BindIP(client.ID, ip)
	if err != nil {
		p.portalMessage(w, r, http.StatusInternalServerError, "خطا", "ثبت آدرس انجام نشد؛ دوباره تلاش کنید.")
		return
	}
	p.log.Info("client ip registered", "client", updated.Name, "ip", ip)

	wantJSON := r.URL.Query().Get("format") == "json" ||
		strings.Contains(r.Header.Get("Accept"), "application/json")
	hdr := http.Header{"Cache-Control": {"no-store"}}
	w.Header().Set("Cache-Control", hdr.Get("Cache-Control"))

	if wantJSON {
		writeJSON(w, 200, map[string]any{
			"ok":         true,
			"client":     updated.Name,
			"ip":         ip,
			"dns":        p.dns.PublicIP(),
			"expires_at": updated.ExpiresAt,
			"routes":     p.routeNames(updated),
		})
		return
	}

	routes := p.routeNames(updated)
	rows := ""
	for _, name := range routes {
		rows += fmt.Sprintf(`<li><span>%s</span><strong>فعال</strong></li>`, html.EscapeString(name))
	}
	if rows == "" {
		rows = `<li><span>مسیر</span><strong>—</strong></li>`
	}
	body := fmt.Sprintf(`
<div class="ok-badge">✓</div>
<h1>آدرس شما ثبت شد</h1>
<p class="muted">از این لحظه DNS شما فعال است. اگر IP اینترنت شما عوض شد، فقط همین صفحه را دوباره باز کنید.</p>
<div class="kv-card">
  <ul class="kv">
    <li><span>کلاینت</span><strong>%s</strong></li>
    <li><span>آدرس ثبت‌شده</span><strong>%s</strong></li>
    <li><span>آدرس DNS</span><strong>%s</strong></li>
    %s
  </ul>
</div>
<p class="hint">در تنظیمات شبکه (کامپیوتر، کنسول، موبایل یا روتر) مقدار DNS را روی <code>%s</code> بگذارید.</p>
<a class="btn primary block" href="/p/%s">مشاهدهٔ وضعیت اشتراک</a>`,
		html.EscapeString(updated.Name), html.EscapeString(ip), html.EscapeString(orDash(p.dns.PublicIP())),
		rows, html.EscapeString(orDash(p.dns.PublicIP())), html.EscapeString(client.Token))

	p.clientPage(w, "ثبت شد", body, 200)
}

// portal renders the read-only subscriber page.
func (p *Panel) portal(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.PathValue("token"))
	client, err := p.store.ClientByToken(token)
	if err != nil {
		p.portalMessage(w, r, http.StatusNotFound, "لینک نامعتبر",
			"این آدرس معتبر نیست. از پشتیبانی لینک جدید بخواهید.")
		return
	}
	status := "فعال"
	statusClass := "ok"
	if !client.Enabled {
		status, statusClass = "غیرفعال", "bad"
	} else if client.ExpiresAt != nil && time.Now().After(*client.ExpiresAt) {
		status, statusClass = "منقضی شده", "bad"
	} else if client.QuotaBytes > 0 && client.UsedBytes >= client.QuotaBytes {
		status, statusClass = "پایان حجم", "bad"
	}

	expiry := "بی‌نهایت"
	if client.ExpiresAt != nil {
		expiry = fmt.Sprintf("%s (%d روز)", faDate(*client.ExpiresAt), int(time.Until(*client.ExpiresAt).Hours()/24))
	}
	quota := "بی‌نهایت"
	if client.QuotaBytes > 0 {
		quota = fmt.Sprintf("%s از %s", humanBytes(client.UsedBytes), humanBytes(client.QuotaBytes))
	}
	routes := p.routeNames(client)
	routeList := ""
	for _, name := range routes {
		routeList += fmt.Sprintf(`<li><span>%s</span><strong>فعال</strong></li>`, html.EscapeString(name))
	}
	if routeList == "" {
		routeList = `<li><span>مسیر</span><strong>—</strong></li>`
	}
	ip := "ثبت نشده"
	if len(client.IPs) > 0 {
		ip = strings.Join(client.IPs, ", ")
	}

	body := fmt.Sprintf(`
<h1>%s</h1>
<p class="muted">وضعیت اشتراک شما در BESTPRIME DNS</p>
<div class="kv-card">
  <ul class="kv">
    <li><span>وضعیت</span><strong class="%s">%s</strong></li>
    <li><span>آدرس DNS</span><strong>%s</strong></li>
    <li><span>IP ثبت‌شده</span><strong>%s</strong></li>
    <li><span>انقضا</span><strong>%s</strong></li>
    <li><span>مصرف</span><strong>%s</strong></li>
    %s
  </ul>
</div>
<a class="btn primary block" href="/ip/%s">ثبت دوبارهٔ IP من</a>
<p class="hint">اگر IP اینترنت شما تغییر کرد، روی دکمهٔ بالا بزنید یا همین صفحه را در مرورگر باز کنید.</p>`,
		html.EscapeString(client.Name), statusClass, html.EscapeString(status),
		html.EscapeString(orDash(p.dns.PublicIP())), html.EscapeString(ip),
		html.EscapeString(expiry), html.EscapeString(quota), routeList,
		html.EscapeString(token))

	p.clientPage(w, "پورتال کلاینت", body, 200)
}

func (p *Panel) portalMessage(w http.ResponseWriter, r *http.Request, code int, title, msg string) {
	body := fmt.Sprintf(`<div class="ok-badge bad">!</div><h1>%s</h1><p class="muted">%s</p>`,
		html.EscapeString(title), html.EscapeString(msg))
	p.clientPage(w, title, body, code)
}

func (p *Panel) clientPage(w http.ResponseWriter, title, body string, code int) {
	page := fmt.Sprintf(`<!doctype html>
<html lang="fa" dir="rtl"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s · %s</title>
<link rel="stylesheet" href="/static/app.css">
<link rel="icon" href="/static/favicon.svg" type="image/svg+xml">
<style>
.portal-wrap{max-width:520px;margin:0 auto;padding:38px 18px 60px;display:flex;flex-direction:column;gap:16px}
.kv-card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px 18px}
.ok-badge{width:46px;height:46px;border-radius:14px;display:grid;place-items:center;font-size:22px;
  background:rgba(52,211,153,.16);color:var(--success);border:1px solid rgba(52,211,153,.3)}
.ok-badge.bad{background:rgba(251,113,133,.14);color:var(--danger);border-color:rgba(251,113,133,.3)}
.kv strong.ok{color:var(--success)} .kv strong.bad{color:var(--danger)}
h1{font-size:21px}
</style></head>
<body><main class="portal-wrap">%s
<footer class="tiny muted center" style="margin-top:18px">%s</footer>
</main></body></html>`,
		html.EscapeString(title), html.EscapeString(p.title()), body, html.EscapeString(p.title()))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(page))
}

func (p *Panel) routeNames(c store.Client) []string {
	byID := map[string]string{}
	for _, r := range p.store.Routes() {
		byID[r.ID] = r.Name
	}
	public := map[string]bool{}
	for _, r := range p.store.Routes() {
		if r.Public && r.Enabled {
			public[r.ID] = true
		}
	}
	out := make([]string, 0, len(c.RouteIDs))
	for _, id := range c.RouteIDs {
		if name, ok := byID[id]; ok {
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		for _, r := range p.store.Routes() {
			if r.Public && r.Enabled {
				out = append(out, r.Name)
			}
		}
	}
	return out
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func faDate(t time.Time) string {
	// Persian calendar conversion without external deps.
	gy, gm, gd := t.Date()
	j := gregorianToJalali(gy, int(gm), gd)
	return fmt.Sprintf("%04d/%02d/%02d", j[0], j[1], j[2])
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}

func gregorianToJalali(gy, gm, gd int) [3]int {
	gDaysInMonth := [12]int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
	jy := gy - 621
	gy2 := gy - 1600
	gm2 := gm - 1
	gd2 := gd - 1
	gDayNo := 365*gy2 + (gy2+3)/4 - (gy2+99)/100 + (gy2+399)/400
	for i := 0; i < gm2; i++ {
		gDayNo += gDaysInMonth[i]
	}
	if gm2 > 1 && ((gy%4 == 0 && gy%100 != 0) || gy%400 == 0) {
		gDayNo++
	}
	gDayNo += gd2
	jDayNo := gDayNo - 79
	jNp := jDayNo / 12053
	jDayNo %= 12053
	jy += 33 * jNp
	jy += 4 * (jDayNo / 1461)
	jDayNo %= 1461
	if jDayNo >= 366 {
		jy += (jDayNo - 1) / 365
		jDayNo = (jDayNo - 1) % 365
	}
	var jm, jd int
	if jDayNo < 186 {
		jm = 1 + jDayNo/31
		jd = 1 + jDayNo%31
	} else {
		jm = 7 + (jDayNo-186)/30
		jd = 1 + (jDayNo-186)%30
	}
	return [3]int{jy, jm, jd}
}
