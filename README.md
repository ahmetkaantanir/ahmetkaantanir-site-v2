# Log Intelligence Lab V5

**Güvenlik operasyonları için kanıt temelli log analizi ve Mini-SOC çalışma alanı.**

Python/Flask + SQLite + HTML/CSS/JavaScript. Proje, halka açık **eğitim ve demo** sayfası ile **özel SOC veri alanını** ayrı tutar.

## Neler çalışıyor?

- **Açıklanabilir tespit kuralları:** web saldırı göstergeleri, Windows audit log temizleme, IDS alarmı, 5 dakikalık başarısız giriş eşiği, password spraying göstergesi, başarısız giriş sonrası başarılı oturum açma, port taraması, yüksek web trafik hızı.
- **Log normalleştirme:** Windows Event JSON, Suricata EVE JSON, Sysmon provider JSON, Apache access, SSH auth, firewall kayıtları, generic JSON. Kaynak tarihinin saat dilimi bilinmiyorsa varsayım yapılmaz.
- **Delil ilişkisi:** her normalize olay için Event ID, ham kayıt ve kaynak satırı; analiz paketi SHA-256; vaka içindeki olay ID'leri ve zaman çizelgesi.
- **Vaka yönetimi:** new / investigating / resolved / false_positive, analist notları, işlem denetimi.
- **Log Explorer:** kaynak, IP ve ham metin filtreleri, en fazla 500 kayıt.
- **Yönetim paneli:** özet KPI, kaynak dağılımı, son paketler, vaka listesi, kurallar, audit.
- **Güvenlik:** API anahtarı, public/private ayrımı, statik kaynak kodu erişim kısıtlaması, HTML injection önleme, 5MB/10K satır sınırı, kayıt tekrar kontrolü.
- **Testler:** Python birim/entegrasyon testleri; GitHub Actions ve JavaScript sözdizimi denetimi.

**Bunlar henüz yok:** üretim-grade çok kullanıcılı oturum/RBAC, gerçek LLM analiz servisi, Sigma kural derleyici, UEBA model eğitimi, harici GeoIP/TI sağlayıcısı, syslog daemon, Kafka/queue, çok terabayt log indeksleme, canlı WAF/EDR/Cloud connector'ları. Bu projenin "kurumsal SIEM" sertifikası yoktur. Tekil tespit, kompromize kanıtı değildir.

## Adresler

| Yol | İşlev |
| --- | --- |
| / | Herkese açık demo ve eğitim |
| /soc | Özel SOC çalışma alanı |
| /api/health | Sağlık kontrolü |
| /api/soc/ingest | Yetkili log alımı |
| /api/soc/summary | İstatistikler |
| /api/soc/events | Olay filtreleme |
| /api/soc/cases | Vaka listesi |
| /api/soc/cases/<id> | Vaka güncelleme (PATCH) |
| /api/soc/cases/<id>/timeline | Kanıt olayları |
| /api/soc/cases/<id>/explain | **Deterministik** kanıt özeti (AI değil) |
| /api/soc/rules | Rule ID/MITRE |
| /api/soc/audit | İşlem günlüğü |

Tüm SOC API uçları, HTTP \`X-API-Key\` başlığında güçlü anahtar ister. \`LOG_LAB_API_KEY\` yoksa SOC API **503 döner ve veri kabul etmez**. Anahtar en az 24 karakterdir; depoya, JS kaynaklarına veya istemci loglarına yazılmaz.

## Yerel kurulum (Windows / Linux)

\`\`\`sh
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# Linux/macOS: source .venv/bin/activate
python -m pip install -r requirements.txt
\`\`\`

**Windows PowerShell:**
\`\`\`powershell
$env:LOG_LAB_API_KEY = "buraya-32-karakterden-uzun-rastgele-bir-anahtar"
$env:LOG_LAB_DB_PATH = ".\\private\\analysis.db"
python app.py
\`\`\`

**Linux:**
\`\`\`sh
export LOG_LAB_API_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(40))')"
export LOG_LAB_DB_PATH="./private/analysis.db"
python app.py
\`\`\`

Tarayıcıdan \`http://localhost:5000/soc\` açın. SOC başlığındaki API anahtarını girin (tarayıcı yerel depolamasına kaydetmez). **Gerçek kullanıcı verileri yerine önce anonim örnek logları deneyin.**

## Örnek API

\`\`\`sh
curl -X POST http://localhost:5000/api/soc/ingest \
  -H "X-API-Key: $LOG_LAB_API_KEY" \
  -H "Content-Type: application/json" \
  --data '{"raw_logs":"{\"timestamp\":\"2026-10-31T08:00:00Z\",\"EventID\":4625,\"ip\":\"192.0.2.42\",\"user\":\"test\"}"}'
\`\`\`

Sistem olayları parse eder, varsa tespitleri kanıt kayıtlarıyla birlikte kaydeder ve \`batch_id\`, \`sha256\`, \`risk\`, \`alert_count\` döndürür.

## Render / canlı yayın

Bu repo bir \`render.yaml\` tanımlar. Render Blueprint üzerinden oluşturulurken \`LOG_LAB_API_KEY\` otomatik rastgele üretilebilir. **Mevcut manuel Render servislerinde Blueprint değişikliğinin otomatik olarak uygulanacağı varsayılmamalıdır:** servis Dashboard → Environment bölümünden \`LOG_LAB_API_KEY\` ayarlanmalıdır.

- Bir dağıtım **GitHub main** dalını izliyorsa onaylanan merge ile otomatik deploy tetiklenebilir; bunu Render panelinden kontrol edin.
- Render'ın ücretsiz dosya sistemi **kalıcı veri depolama garantisi sunmaz**. Gerçek SOC olayları için kalıcı disk/veritabanı, TLS, ayrı servis kullanıcıları, düzenli yedekleme, veri saklama politikası ve erişim denetimi gerekir.
- \`LOG_LAB_DB_PATH\` kalıcı bir disk konumuna işaret edebilir. Disk yoksa servis yeniden dağıtımında log geçmişi silinebilir.
- Anahtar tarayıcıda sadece sekme belleğinde tutulur. API anahtarını herkese dağıtmayın.

## Güvenlik ve doğruluk kuralları

1. Tespitler *göstergedir*, başarılı istismar kanıtı değildir.
2. IP istihbaratı ve GeoIP yoksa **unknown** gösterilir; uydurma temiz/zararlı veya ülke puanı verilmez.
3. Saat dilimi bilinmeyen olaylar zamana dayalı korelasyonda kullanılmaz.
4. SOC çalışması gerçek kişisel veri içerebileceğinden yasal izin olmadan internete yüklemeyin.
5. Dış AI/tehdit istihbaratı çağrısı yapılmaz. \`/explain\` sabit, denetlenebilir öneriler üretir.
6. Şeffaf limitler: 5MB HTTP yükleme, 10.000 olay, 16.384 karakter/satır.

## Testler

\`\`\`sh
python -m pytest -q
python -m compileall -q app.py log_engine.py soc_engine.py soc_api.py
node --check script.js
node --check soc.js
\`\`\`

CI: [GitHub Actions](../../actions). Ayrıntılı sonraki modüller için [upgrade planı](./SECURITY_UPGRADE_ROADMAP.md).

## Proje yaklaşımı

Bu proje siber güvenlik ve adli bilişim öğrencileri için özgürce incelenebilir bir analiz laboratuvarı olarak tasarlanmıştır; güvenlik ürününe ait kurumsal garantiler sunmaz.
