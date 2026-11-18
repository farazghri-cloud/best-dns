# BESTPRIME DNS

**DNS هوشمند + رله SNI برای عبور دادن سایت‌ها، بازی‌ها و اپ‌ها از یک سرور شخصی.**
یک باینری مستقل، بدون وابستگی، با پنل وب فارسی.

> این پروژه از صفر نوشته شده و هیچ لیست آماده‌ای ندارد: **هیچ دامنه‌ای از سرور عبور نمی‌کند مگر خودت آن را به‌عنوان «مسیر» اضافه کنی.**

---

## این پروژه چه می‌کند؟

1. دستگاه‌ها (کامپیوتر، موبایل، کنسول، روتر) DNS خود را روی IP سرور شما می‌گذارند.
2. برای هر دامنه‌ای که در پنل «مسیر» ساخته باشید، سرور به‌جای IP واقعی، IP خودش را برمی‌گرداند.
3. ترافیک TCP آن دامنه به سرور می‌رسد، سرور از روی **SNI** (نام دامنه در TLS) مقصد واقعی را تشخیص می‌دهد و اتصال را لایه ۴ رله می‌کند — بدون رمزگشایی، بدون VPN روی دستگاه.
4. بقیهٔ اینترنت مثل قبل مستقیم resolve می‌شود؛ نه کندی، نه مصرف پهنای‌باند اضافه.

**تفاوت کلیدی با نسخه‌های دیگر:** دسته‌بندی پلتفرم‌ها (بازی/اپ/سایت) از پیش تعریف نشده. خودت مسیر می‌سازی، دامنه‌ها را وارد می‌کنی، و کلاینت‌ها را به همان مسیرها وصل می‌کنی. لیست کلاینت‌ها هم دقیقاً بر اساس همان مسیرها گروه‌بندی می‌شود.

---

## نصب با یک دستور (Ubuntu 22.04/24.04، Debian 12)

```bash
curl -fsSL https://cdn.jsdelivr.net/gh/farazghri-cloud/best-dns@v1.0.4/install.sh | sudo bash
```

> چرا jsDelivr؟ چون در ایران `raw.githubusercontent.com` معمولاً فیلتر است و jsDelivr از CDNهای در دسترس می‌خواند. تگ نسخه (`@v1.0.4`) نسخهٔ تأییدشده را قفل می‌کند تا آپدیت‌های بعدی نصب شما را وسط کار عوض نکنند. دو مسیر جایگزین:
>
> ```bash
> # مسیر دوم: API گیت‌هاب
> curl -fsSL -H "Accept: application/vnd.github.raw" \
>   https://api.github.com/repos/farazghri-cloud/best-dns/contents/install.sh | sudo bash
>
> # مسیر سوم: کلون و اجرا
> git clone https://github.com/farazghri-cloud/best-dns.git && cd best-dns && sudo ./install.sh
> ```

اسکریپت به‌صورت خودکار:

- آخرین نسخهٔ باینری لینوکس (amd64 / arm64 / armv7) را دانلود و checksum را بررسی می‌کند
- `/usr/local/bin/bestdns` را نصب و سرویس systemd را می‌سازد
- پورت‌های ۵۳ (UDP/TCP)، پورت پنل و پورت‌های رله را در ufw باز می‌کند
- کرنل را برای بار DNS تنظیم می‌کند (`sysctl`)
- یک رمز عبور تصادفی می‌سازد و آدرس پنل را چاپ می‌کند

> **پورت ۴۴۳ باید آزاد باشد.** اگر روی سرور وب‌سرور دارید (Nginx/Caddy روی ۴۴۳)، یا آن را خاموش کنید یا پورت رله را عوض کنید: `--panel-port` برای پنل و `BESTDNS_PROXY_PORTS=8443` برای رله. کلاینت‌ها فقط باید DNS را عوض کنند؛ رله روی هر پورتی که باز باشد کار می‌کند چون پاسخ DNS به همان IP سرور اشاره می‌کند.

گزینه‌ها (هم به‌صورت متغیر محیطی، هم به‌صورت فلگ):

```bash
# پورت پنل دلخواه + اجازه به کلاینت‌های ثبت‌نشده
curl -fsSL .../install.sh | sudo bash -s -- --panel-port 9090 --allow-all

# نسخهٔ مشخص
curl -fsSL .../install.sh | sudo bash -s -- --version v1.0.0

# بدون دست زدن به فایروال
curl -fsSL .../install.sh | sudo bash -s -- --no-firewall
```

| متغیر | پیش‌فرض | کار |
|---|---|---|
| `BESTDNS_PANEL_PORT` | `8080` | پورت پنل |
| `BESTDNS_PROXY_PORTS` | `443` | پورت‌های رله SNI |
| `BESTDNS_IP` | خودکار | IP عمومی که پاسخ مسیرها به آن اشاره می‌کند |
| `BESTDNS_ALLOW_ALL` | `0` | `1` = سرویس به هر IP (بدون کلاینت) |
| `BESTDNS_VERSION` | `latest` | تگ نسخه |

---

## سه قدم تا اولین عبور

### ۱) یک مسیر بساز

پنل → **مسیرها** → «مسیر جدید». فقط دو چیز لازم است: یک نام (مثلاً «تلگرام») و لیست دامنه‌ها.

قالب نوشتن دامنه:

| نوشته | معنی |
|---|---|
| `example.com` | خود دامنه + همهٔ ساب‌دامین‌ها |
| `*.example.com` | فقط ساب‌دامین‌ها (خود `example.com` نه) |
| `=example.com` | فقط همین دامنه، بدون ساب‌دامین |
| `keyword:telegram` | هر دامنه‌ای که این متن را داشته باشد |

آدرس کامل هم قبول است (`https://web.telegram.org/app`) و خودش به دامنه تبدیل می‌شود. خطوطی که با `#` شروع شوند نادیده گرفته می‌شوند.

### ۲) یک کلاینت بساز

پنل → **کلاینت‌ها** → «کلاینت جدید»: نام، مسیرهای موردنظر، تاریخ انقضا، سقف ترافیک.

بعد از ساخت، دو لینک به تو داده می‌شود:

- **لینک ثبت IP**: `https://your-panel/ip/<token>` — کاربر یک بار بازش می‌کند و IP همان لحظه‌اش ثبت می‌شود. اگر IP اینترنتش عوض شد، فقط همان لینک را دوباره باز می‌کند (بدون تماس با پشتیبانی).
- **لینک پورتال**: `https://your-panel/p/<token>` — صفحهٔ وضعیت: انقضا، مصرف، آدرس DNS.

> کلاینت‌ها در پنل **بر اساس مسیرهایی که ساختی** دسته‌بندی می‌شوند؛ هر کارت کلاینت زیر نام مسیرش می‌آید و کلاینتی که هیچ مسیری ندارد در گروه «بدون مسیر» می‌ماند.

### ۳) DNS دستگاه را عوض کن

آدرس DNS = IP همان سرور. در ویندوز/مک/اندروید/آی‌او‌اس/کنسول یا در تنظیمات روتر ست کن.

---

## دستورات روزمره

```bash
systemctl status bestdns        # وضعیت
journalctl -u bestdns -f        # لاگ زنده
systemctl restart bestdns       # ری‌استارت
bestdns passwd                  # رمز جدید (خودش تولید و چاپ می‌کند)
bestdns version
```

فایل‌ها:

| مسیر | چیست |
|---|---|
| `/var/lib/bestdns/state.json` | تنظیمات، مسیرها، کلاینت‌ها |
| `/var/lib/bestdns/state-first-login.txt` | رمز اولیه (بعد از تغییر رمز پاکش کن) |
| `/etc/systemd/system/bestdns.service` | سرویس |

از پنل → تنظیمات می‌توانی **نسخهٔ پشتیبان** بگیری یا بازیابی کنی.

---

## پنل پشت HTTPS (پیشنهاد جدی)

پنل به‌صورت پیش‌فرض روی HTTP است. با Caddy در ۳۰ ثانیه دامنه‌دار و HTTPS می‌شود:

```bash
apt-get install -y caddy
cat >/etc/caddy/Caddyfile <<'EOF'
panel.example.com {
    reverse_proxy 127.0.0.1:8080
}
EOF
sed -i 's/-panel :8080/-panel 127.0.0.1:8080/' /etc/systemd/system/bestdns.service
systemctl daemon-reload && systemctl restart bestdns caddy
```

با Nginx:

```nginx
server {
    listen 443 ssl http2;
    server_name panel.example.com;
    ssl_certificate     /etc/letsencrypt/live/panel.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/panel.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

بعد از این کار، `-panel 127.0.0.1:8080` را در یونیت نگه دار تا پنل از بیرون قابل دسترسی نباشد. (سرویس به `X-Forwarded-For` احترام می‌گذارد، پس ثبت IP و محدودیت نرخ درست کار می‌کند.)

---

## DNS-over-HTTPS (اختیاری)

در تنظیمات، «پورت DNS-over-HTTPS» را مثلاً `:8443` بگذار و سرویس را ری‌استارت کن. آدرس:

```
https://SERVER:8443/dns-query
```

در کلاینت‌هایی که DoH می‌خواهند (اندروید، iOS، مرورگر) همین را وارد کن.

---

## ساخت از سورس

```bash
git clone https://github.com/farazghri-cloud/best-dns.git
cd best-dns
make build                     # bin/bestdns
sudo ./install.sh              # نصب با باینری لوکال؟ نه: از --version استفاده کن
make release                   # ساخت همهٔ آرتیفکت‌های انتشار در dist/
```

اجرای دستی بدون systemd:

```bash
./bin/bestdns server -data ./data/state.json -dns :5353 -panel :8080 -proxy-ports 8443 -debug
```

---

## تنظیمات مهم پنل

| تنظیم | توضیح |
|---|---|
| **آدرس IP عمومی** | IPای که دامنه‌های مسیرشده به آن resolve می‌شوند. خالی = تشخیص خودکار (اگر شکست خورد، IP محلی که کوئری روی آن رسیده استفاده می‌شود). |
| **پورت‌های رله** | پیش‌فرض `443`. می‌توانی چند پورت بدهی (`443,8443`). مقصد همیشه `443` (TLS) یا `80` (HTTP) است. |
| **DNS بالادست** | Resolverهای واقعی. پیش‌فرض Cloudflare/Google/Quad9. |
| **اجازهٔ سرویس به کلاینت ثبت‌نشده** | خاموش = فقط IPهای ثبت‌شده پاسخ می‌گیرند. برای فروش/اشتراک، خاموش بگذار. |
| **حد نرخ کوئری هر IP** | جلوگیری از سیل کوئری یک دستگاه. |
| **تکه‌تکه کردن ClientHello** | برای عبور از DPI روی مسیر سرور→مقصد. |

---

## API (برای اتوماسیون)

همهٔ درخواست‌های تغییردهنده باید هدر `X-Requested-With: bestdns` و کوکی نشست داشته باشند.

| متد | مسیر | کار |
|---|---|---|
| `POST` | `/api/login` | ورود (`{"password":"…"}`) |
| `GET` | `/api/state` | تنظیمات + مسیرها + کلاینت‌ها |
| `GET` | `/api/stats` | آمار زنده |
| `POST` | `/api/routes` | ساخت مسیر |
| `PUT` | `/api/routes/{id}` | ویرایش مسیر |
| `DELETE` | `/api/routes/{id}` | حذف مسیر |
| `POST` | `/api/clients` | ساخت کلاینت |
| `PUT` | `/api/clients/{id}` | ویرایش کلاینت |
| `POST` | `/api/clients/{id}/rotate` | توکن جدید |
| `POST` | `/api/settings` | ذخیرهٔ تنظیمات |
| `GET` | `/api/backup` | دانلود پشتیبان |
| `GET` | `/ip/{token}` | ثبت IP کلاینت (عمومی) |
| `GET` | `/p/{token}` | پورتال کلاینت (عمومی) |
| `GET` | `/health` | سلامت سرویس |

نمونه:

```bash
curl -c jar -X POST http://SERVER:8080/api/login \
  -H 'Content-Type: application/json' -d '{"password":"…"}'

curl -b jar -X POST http://SERVER:8080/api/routes \
  -H 'Content-Type: application/json' -H 'X-Requested-With: bestdns' \
  -d '{"name":"تلگرام","domains":["telegram.org","t.me","*.telesco.pe"],"public":true}'
```

---

## عیب‌یابی

| نشانه | علت رایج |
|---|---|
| سایت هنوز باز نمی‌شود | دامنه در مسیر نیست، یا ساب‌دامین دیگری استفاده می‌شود. «پرتکرارترین دامنه‌ها» در داشبورد را ببین و دامنهٔ `مستقیم` را به مسیر اضافه کن. |
| `REFUSED` در پاسخ DNS | IP کلاینت ثبت نشده و «اجازه به ثبت‌نشده‌ها» خاموش است. لینک `/ip/<token>` را باز کن. |
| دسترسی به پنل نیست | فایروال ابری سرور (Security Group) پورت پنل را باز نکرده. |
| ترافیک رله می‌شود ولی سایت ارور می‌دهد | پورت رله در فایروال بسته است، یا دامنه از CDN دیگری لود می‌شود. |
| IP اشتباه در پاسخ‌ها | «آدرس IP عمومی» را دستی در تنظیمات ست کن. |

```bash
ss -lntup | grep -E ':53|:443|:8080'   # پورت‌های باز
dig @127.0.0.1 example.com +short     # تست DNS روی خود سرور
curl -s localhost:8080/health         # سلامت پنل
```

---

## امنیت

- رمز پنل با **PBKDF2-HMAC-SHA256** (۱۲۰هزار دور) ذخیره می‌شود؛ رمز خام هیچ‌جا نوشته نمی‌شود.
- نشست‌ها با HMAC-SHA256 امضا می‌شوند و کوکی `HttpOnly` + `SameSite=Strict` است.
- تلاش‌های ناموفق ورود محدود می‌شوند (۶ تلاش / ۱۰ دقیقه / IP).
- سرویس با کاربر غیرروت و فقط capability `CAP_NET_BIND_SERVICE` اجرا می‌شود.
- نام دامنه‌های کوئری‌شده هرگز روی دیسک نوشته نمی‌شوند؛ آمار فقط در حافظه است.
- `state.json` شامل توکن کلاینت‌هاست؛ دسترسی‌اش `0600` و مالکش کاربر سرویس است. پشتیبان را جای امن نگه دار.

---

## ساختار کد

```
cmd/bestdns/          ورودی برنامه (server، passwd، version)
internal/dnswire/     کدک پیام DNS (بدون وابستگی)
internal/dnsrv/       listenerها، تصمیم مسیردهی، کش، بالادست، DoH
internal/proxy/       رله SNI لایه ۴ + پارس ClientHello/Host
internal/store/       مدل داده، مچر دامنه، ذخیره‌سازی اتمیک JSON
internal/panel/       پنل، API، پورتال کلاینت، ثبت IP
internal/metrics/     شمارنده‌های زنده
internal/webui/       فایل‌های پنل (embed داخل باینری)
```

## مجوز

MIT
