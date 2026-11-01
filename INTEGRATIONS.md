# Log Intelligence Lab V6 — kurulum ve kapsam

Bu sürüm, [paylaşılan proje önerilerini](https://chatgpt.com/share/6ae71882-57b0-83ed-830e-23584de13b48) mevcut Flask/SQLite/MapLibre uygulaması üzerine uygular. Servis bağlantıları varsayılan olarak kapalıdır. Kimlik bilgileri tarayıcıya gönderilmez. Yeni modüller bağımsız bir gösterim veritabanı yerine aynı `soc_events`, vakalar ve ham kanıt paketlerini kullanır.

## Özelliklerin karşılığı

| Öneri | Uygulama | Sınır / dış gereksinim |
|---|---|---|
| Grafana + Loki + Alloy | [Compose](./deploy/compose.yaml), dosya toplama, Loki sorgu API'si, hazır Grafana dashboard'u | Docker sunucusunda başlatılmalı; kurulu servis gibi varsayılmaz |
| Live Log Monitor | Grafana 10 sn yenileme, SOC modüllerinde isteğe bağlı 10 sn sorgu | Polling; garantili gerçek zaman veya SSE değildir |
| Authentication / Firewall / Web / SOC / Timeline / Source Health | [Grafana dashboard](./deploy/grafana/dashboards/security-operations.json) ve mevcut SOC kaynak sağlığı | Kayıp ölçümü için kaynak sayaçları gerekir; gelen hacim kayıp sayısı değildir |
| Host Monitoring | Prometheus + node-exporter ve CPU/RAM/disk panelleri | Linux collector host'u; Docker Desktop'ta Linux VM. Her GNS3 cihazı için ayrıca exporter gerekir |
| GNS3 Network Lab | Projeler, gerçek düğüm/bağlantı topolojisi, cihazdan aynı host adına göre log inceleme | Ayrı GNS3 controller/VM ve lisanslı appliance'lar; web uygulaması cihaz çalıştırmaz |
| Cyber Threat Globe | Var olan küre, atmosfer, dönüş, endpoint bağlantıları, seviye/zaman filtreleri, oynatma | Son yüklenen olay sayfası; paket rotası değildir. Yeni marker'lar veri güncellemesinde yeniden çizilir; özel parçacık/3D yay motoru eklenmedi |
| Evidence / GeoIP / Simulation | Özgün koordinatlar, ayrı yerel GeoIP tahmini, açıkça işaretlenen sentetik SOC örneği | IP'den rastgele koordinat yok. GeoIP yerel feed gerektirir; simülasyon gerçek trafik değildir |
| Wazuh | Ajan durumu adaptörü ve Wazuh alert JSON normalleştirmesi | API token'ı/alert dosyaları ayrı kurulumdan gelir; ikinci bir Wazuh cluster kurulmaz |
| Zeek / Suricata | JSONL, Zeek TSV dönüştürme, Suricata EVE, flow/domain alanları | Protokol metaverisi; ham paket yakalama yapılmaz |
| Firewall | iptables ve IPv4 pfSense/OPNsense filterlog CSV | IPv6 filterlog CSV gibi bilinmeyen şemalar unknown kalır |
| ATT&CK + Sigma | MITRE referanslı kurallar ve kayıtlı kanıtta Sigma JSON alt kümesi denemesi | Tam Sigma motoru değildir; desteklenmeyen condition/modifier/wildcard reddedilir; kural otomatik yayına alınmaz |
| PCAP Forensics | tshark JSON dışa aktarımını JSONL metaverisine dönüştürme ve olay inceleme | Web sunucusunda tshark/subprocess çalıştırılmaz; özgün PCAP yerelde korunur |
| Cloud / AD / DNS / Web / Honeypot | Ayrı veri inceleme modülleri, CloudTrail/Cloudflare/Windows/DNS/Cowrie normalleştirme | Yetkili laboratuvardan gerçek kaynak gerekir; web uygulaması saldırı veya honeypot başlatmaz |
| Threat Intelligence | Yerel feed; açık onayla AbuseIPDB/VirusTotal IP sorgusu | Sağlayıcı API anahtarı/kotası gerekir; sorgulanan IP sağlayıcıya açıklanır; sonuç kesin hüküm değildir |
| Digital Forensics | Özgün UTF-8 paket, SHA-256 doğrulama, vaka notları/timeline, JSON kanıt ve rapor ihracı | Eski paketlerde özgün metin saklanmadıysa doğrulama unavailable. Hash kaynak kimliğini doğrulamaz |
| UEBA Lab | Kullanıcı/host için gözlenen günlerden deneysel hacim baz çizgisi | En az 4 gün; en son 2.000 kayıt. Tam davranış analitiği veya üretim ML modeli değildir |
| AI SOC Assistant | Mevcut deterministik açıklamalar + isteğe bağlı Ollama özet API'si | Yerel model kurulmalı. Kaynak ID'leri doğrulanır; model iddiaları analist tarafından doğrulanmalıdır. Otomatik vaka değişmez |
| Çok kullanıcılı erişim | Adlandırılmış API principal'ları: reader/analyst/collector/admin; audit aktörü | Tek SOC veri alanı, tenant izolasyonu ve web kullanıcı/parola/SSO sistemi değildir |
| Sürekli collector | SQLite outbox, işlem içinde checkpoint, gecikmeli tekrar, hash'li ACK | İlk sürüm dosya tail eder; doğrudan UDP/TCP syslog listener değildir. Syslog daemon dosyaya yazmalıdır |

## 1. Yerel servisler

Windows'ta otomatik hazırlık ve tüm yığını (uygulama + kalıcı collector dahil) başlatma:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File deploy/setup.ps1
```

Betik yalnızca ilk çalışmada `deploy/.env` içine birbirinden farklı SOC, collector ve Grafana gizli değerleri üretir; bu dosya Git ve Docker build içeriğinden hariç tutulur. Mevcut değerleri değiştirmez. Docker/WSL kurulduktan ve Engine başlatıldıktan sonra aynı komutla devam edilir. Sadece yapılandırmayı hazırlamak için `-PrepareOnly` ekleyin. SOC `http://127.0.0.1:5000/soc#platform`, Grafana `http://127.0.0.1:3000` olur. Bu yerel yığın Render sunucusuna kendiliğinden erişim sağlamaz.

Docker Engine/Compose gereklidir. PowerShell örneği:

```powershell
New-Item -ItemType Directory -Force deploy/logs
docker compose --env-file deploy/.env -f deploy/compose.yaml config --quiet
docker compose --env-file deploy/.env -f deploy/compose.yaml up -d --build
```

Grafana `http://127.0.0.1:3000` (kullanıcı `admin`), Loki `http://127.0.0.1:3100`, Prometheus `http://127.0.0.1:9090`. Portlar yalnızca loopback'e bağlanır. Grafana anonim erişimi kapalıdır; paneller kullanıcı oturumunda ayrı sekmede açılır. Gömmek için anonim panel gerekmez.

[Ortam örneğindeki](./.env.example) değişkenleri Flask'ın çalıştığı servis ortamına verin. Uygulama `.env` dosyasını otomatik yüklemez:

```powershell
$env:LOG_LAB_API_KEY = '<en-az-24-karakterlik-gizli-anahtar>'
$env:LAB_LOKI_URL = 'http://127.0.0.1:3100'
$env:LAB_GRAFANA_URL = 'http://127.0.0.1:3000'
& .venv/Scripts/python.exe app.py
```

Render'da `127.0.0.1` kendi servisidir; bilgisayarınızdaki Docker'a erişmez. Ayrı sunucu servisleri için erişilebilir HTTPS origin'leri ve uygun kimlik doğrulama kullanın. Özel ağ HTTP erişimi yalnızca yöneticinin `LAB_ALLOW_PRIVATE_HTTP=true` ayarıyla mümkündür. TLS doğrulaması kapatılmaz, upstream yönlendirmeler izlenmez, yanıtlar boyut/zaman sınırıyla alınır.

Loki 7 günlük saklama ve kalıcı volume kullanır; Alloy checkpoint'leri kendi volume'ündedir. IP/kullanıcı/host yüksek çeşitlilikli indeks etiketleri yapılmaz. `deploy/logs/auth.log` → `job=linux-auth`, `deploy/logs/*.jsonl` → `job=security`. Grafana host paneli kanonik JSON `hostname` alanını bekler; diğer şemalarda sorguyu uygun alana uyarlayın. Loki/Grafana sonuçları SOC'a kendiliğinden ikinci kez alınmaz.

Sürüm sabitlenmiş container dosyaları bu geliştirme ortamında Docker olmadığından çalıştırılmadı. Dağıtımda image çekme, Alloy yapılandırması, Loki sorguları, veri kalıcılığı ve metrik hedefleri ayrıca doğrulanmalı.

## 2. Roller ve collector

Canlı site için ayrı collector principal'ı yapılandırıldıysa `deploy/.env.cloud` içindeki `LAB_SOC_URL` ve `LAB_COLLECTOR_KEY` kullanılarak Docker gerekmeksizin Windows'tan iletim yapılabilir:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File deploy/run-cloud.ps1
```

Bu süreç yalnızca `deploy/logs/auth.log` ve `deploy/logs/security.jsonl` dosyalarını izler; Windows sistem olaylarını veya başka kişisel dosyaları kendiliğinden toplamaz. Kaynak dosyalar boşsa canlı SOC'a örnek/uydurma olay yazmaz. Ayrı outbox durumu `deploy/cloud-collector.db` içinde tutulur. `deploy/.env.cloud` ve DB dosyaları Git dışında tutulur.

Compose içindeki uygulama GNS3, Wazuh, Ollama ve istihbarat ayarlarını `deploy/.env` dosyasından da alır. [Ortam örneğindeki](./.env.example) ilgili `LAB_*` satırlarını bu dosyaya ekleyip kurulum betiğini yeniden çalıştırın. Yerel feed dosyalarını `deploy/feeds` altına koyun; uygulamadaki yollar `/feeds/<dosya>.json` olmalıdır. Bu dizin Git dışında tutulur. Yapılandırma satırı eklemek harici sunucuyu kurmaz veya sağlayıcı hesabı/API anahtarı oluşturmaz.

`LOG_LAB_API_KEY` geriye uyumlu owner/admin anahtarıdır. `LOG_LAB_PRINCIPALS` sunucu ortamında JSON dizi alır:

```json
[
  {"name":"analyst-1","role":"analyst","key":"her-kullanici-icin-farkli-24-karakterden-uzun-secret"},
  {"name":"log-forwarder","role":"collector","key":"collector-icin-baska-24-karakterden-uzun-secret"}
]
```

Reader kanıtları okuyabilir, audit okuyamaz/değişiklik yapamaz. Analyst içe alma, vaka/izleme listesi güncelleme, Sigma deneme ve açık onaylı model/istihbarat sorguları yapabilir. Collector yalnızca `/api/soc/ingest` çağırabilir. Anahtarlar tarayıcı belleğindedir; kullanıcı başına ayrı anahtar kullanılmalıdır.

```powershell
$env:LAB_SOC_URL = 'http://127.0.0.1:5000'
$env:LAB_COLLECTOR_KEY = '<collector-principal-anahtari>'
& .venv/Scripts/python.exe -m collectors.file_forwarder --file deploy/logs/security.jsonl --state collector-state.db
```

Günlük dosyasını hem Alloy hem bu collector okuyabilir: biri Loki'ye, diğeri SOC'a yazar. SOC outbox en fazla 1.000 bekleyen paket içerir, paket başına 500 satır/1 MB alır; dolduğunda checkpoint ilerlemez. Kaynak dosyalarını teslim gerçekleşmeden silmeyin. Tam satır yazılmadan checkpoint ilerlemez. Başarılı cevap aynı paket SHA-256'sını onaylamalıdır. ACK kaybında yeniden gönderilen **aynı paket** sunucuda ikinci kez yazılmaz.

Farklı collector'ların farklı paketleme/boşluklarla aynı olayları göndermesi genel olay deduplikasyonu sağlamaz. Kaynak başına bir SOC collector kullanın. Dosya kimliği değişimi ve boyut küçülmesi algılanır; aynı inode ve aynı/artan boyutta copytruncate gibi belirsiz rotasyonlarda kayıp önleme garantisi yoktur. Dosya rotasyon politikası ve kalıcı state volume'u işletim sorumluluğudur. Korelasyon şu anda paket içindeki 5 dakikalık pencereyi kullanır; farklı paket sınırlarını aşan korelasyon garantisi verilmez.

## 3. GNS3 laboratuvarı

### Canlı backend'e gerçekten bağlanma yolu

Servisler çalışan bir Linux sunucuda veya izin verilen yerel Hyper-V/Docker ortamında bulunmalıdır. Render'ın `127.0.0.1` adresi kullanıcının bilgisayarı değildir. Sunucu yoksa yalnızca ortam değişkeni eklemek bağlantı oluşturmaz.

Yerel servislerin dışarı port açmadan erişilebilmesi için [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/) kullanılabilir. Her servis için ayrı hostname ve Cloudflare Access uygulaması tanımlanır. Render'ın servis erişimi için **Service Auth** politikası ve ilgili `LAB_<SERVIS>_CF_ACCESS_CLIENT_ID` / `LAB_<SERVIS>_CF_ACCESS_CLIENT_SECRET` çifti kullanılır. Bunlar upstream'in kendi Basic/Bearer kimlik doğrulamasını değiştirmez ve tarayıcıya gönderilmez. Access koruması kurulmadan Loki/GNS3/Wazuh API'leri kamuya açılmamalıdır. [Resmî servis token protokolü](https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/).

Grafana için `LAB_GRAFANA_URL` backend'in ulaşabildiği origin, `LAB_GRAFANA_PUBLIC_URL` kullanıcının açacağı panel origin'idir. Compose bunları `http://grafana:3000` ve varsayılan `http://127.0.0.1:3000` olarak ayırır. Canlı tünel kurulumunda ilgili HTTPS hostname'leri kullanılır; tarayıcı erişimi için ayrıca kullanıcı Access oturumu tanımlanır.

Wazuh için kısa ömürlü token'ı elle kopyalamak yerine `LAB_WAZUH_USER` / `LAB_WAZUH_PASSWORD` ayarlanabilir. Adaptör `POST /security/user/authenticate` üzerinden JWT alır, bellekte en fazla beş dakika tutar ve GET isteğinde 401 gelirse bir kez yeniler. Statik `LAB_WAZUH_TOKEN` verilirse bu değer önceliklidir. Self-signed sertifika için `LAB_WAZUH_CA_FILE` ile güvenilen CA verilir; TLS doğrulaması kapatılmaz. [Resmî Wazuh kimlik doğrulama protokolü](https://documentation.wazuh.com/current/user-manual/api/getting-started.html).

Bağlandı sayılma ölçütü: canlı SOC'un bağlantı testinin 200 dönmesi, Grafana'da aynı kaynak kaydının sorgulanması, GNS3'te gerçek proje/düğüm listesinin ve Wazuh'ta gerçek ajan listesinin alınmasıdır. Yerel HTTP protokol testleri, üretimde bu servislerin kurulduğu anlamına gelmez.

Önerilen ayrı topoloji: WAN → OPNsense → switch → Windows, Linux, Suricata/Zeek. GNS3 yönetim erişimini özel ağda tutun. `LAB_GNS3_URL`, gerekiyorsa `LAB_GNS3_USER` / `LAB_GNS3_PASSWORD` ayarlayın. Adaptör `/v2/projects`, proje nodes ve links uçlarını **salt okunur** kullanır. GNS3 sürümünüz bu API/kimlik doğrulamasıyla uyumlu olmalıdır.

SOC → Entegrasyon ve Lab → Projeleri getir → Topolojiyi aç. Cihaz adına basmak Log Explorer'da `host` filtresini açar; logdaki host ile GNS3 node adı eşleşmelidir. Console URL'leri, appliance özellikleri ve parolaları tarayıcıya aktarılmaz. Grafana bağlantısı seçili olayın host ve ±5 dakika zaman aralığını taşır. Özel loglar URL'ye eklenmez; host adı panel URL'sinde yer alır.

İlk kabul senaryosu: izinli test Windows VM'inde 10 başarısız giriş kaydı üretin; aynı pakette `AUTH-001` bekleyin. Sonrasındaki 4624 için `AUTH-003`, 1102 için `WIN-001`, 4740 için `WIN-004` beklenir. Kaynak saat dilimini doğrulayın. Ağ saldırısı başlatmak gerekmez; sentetik loglar da aynı tespit hattını test eder.

## 4. Format dönüştürme

SOC'a UTF-8 JSONL yüklenir. `.json` kabulü bir JSON nesnesi/satır içindir; JSON dizisini doğrudan yüklemeyin. Zeek TSV veya yerelde Wireshark/tshark ile alınan JSON dışa aktarımı:

```powershell
& .venv/Scripts/python.exe -m collectors.convert --format zeek-tsv conn.log conn.jsonl
& .venv/Scripts/python.exe -m collectors.convert --format tshark-json packets.json packets.jsonl
```

Converter en fazla 50 MB/10.000 kayıt kabul eder. Tshark çıktısından IP/port/frame metaverisi seçilir; paket payload'ı yüklenmez. Dönüştürülen kayıtlardaki `derived_from_sha256` özgün dışa aktarımın hash'idir; özgün PCAP'ı ayrıca yerelde muhafaza edin. Yeni JSONL dosyasını SOC'a yükleyin veya collector'a verin. Zeek TSV'yi doğrudan SOC'a yüklemek desteklenmez.

## 5. GeoIP ve tehdit istihbaratı

Evidence modu logdaki ECS koordinatlarını gösterir. GeoIP modu ayrı yerel feed kullanır. `LAB_GEOIP_FEED` bir sunucu dosyasının yoludur:

```json
{"192.0.2.25":{"location":[29.0,41.0],"country":"TR","source":"synthetic training feed","updated_at":"2026-11-01"}}
```

Bu örnek belgelendirme IP'si ve sentetik koordinattır. Gerçek feed için lisanslı/verifiye kaynağı ve güncelliğini kaydedin. Yerel feed en fazla 1 MB okunur; lookup başına 50 IP. Kaynak bilgisi olmayan/geçersiz koordinatlar atlanır. GeoIP görünümünden **Kanıtı aç**, zenginleştirilmiş konumu kaynak kanıta eklemeden özgün logu açar.

`LAB_INTELLIGENCE_FEED` için `[ {"ip":"192.0.2.25","source":"training feed","note":"synthetic"} ]` biçiminde yerel JSON dizi kullanılabilir. Eşleşme yoksa reputation unknown'dır.

İsteğe bağlı `LAB_ABUSEIPDB_KEY` veya `LAB_VIRUSTOTAL_KEY` ayarlayın. Harici IP sorgusu yalnızca kullanıcının IP paylaşım kutusunu onaylayıp butona basmasıyla gönderilir. Yalnızca global IP kabul edilir. Sağlayıcıya loglar, SOC anahtarı veya vaka notları gönderilmez. API sonucu queried_at, provider ve açık belirsizlik uyarısıyla döner; otomatik vaka kararı üretmez.

## 6. AI ve tespit mühendisliği

Deterministik **Yorum** mevcut şekilde çalışır. İsteğe bağlı Ollama için ayrı sunucuda model kurup `LAB_OLLAMA_URL` ve `LAB_OLLAMA_MODEL` ayarlayın. **Yapılandırılmış modele özetlet** butonu açık çağrıdır: yalnızca vakaya bağlı en fazla 20 olayın seçili alanları modele gönderilir. Ham loglar, analist notları ve gizli anahtar gönderilmez. Uygulama model çalıştırmaz/indirmez. Yerel ağ model servisine kimlik doğrulama gerekiyorsa `LAB_OLLAMA_TOKEN` kullanın. Yanıt boyut/zaman sınırına tabidir; yavaş model erişimi unavailable dönebilir.

Modelin referans verdiği ID'ler kaynak olaylarla kontrol edilir. Doğru ID, yorumun doğru olduğunu garanti etmez; çıktı doğrulanmamış model özeti olarak etiketlenir. Model araç çalıştıramaz veya vakayı değiştiremez.

Sigma laboratuvarı JSON kuralında tek `selection` ve `condition: selection` destekler. Alanlar AND, değer listeleri OR; tam metin, `contains`, `endswith` karşılaştırılır. Wildcard, regex, aggregation, temporal Sigma, YAML yükleme ve birden fazla selection desteklenmez. Desteklenmeyen kurallar sessizce yanlış çalıştırılmaz; 400 döner. Deneme kayıtlı en son 2.000 olay üzerinde yapılır, üretim tespit kuralı yaratmaz.

## 7. Kanıt, rapor, sınırlar ve doğrulama

Yeni paketlerin özgün UTF-8 metni SOC içinde saklanır. Paket ihracı bu metnin SHA-256'sını yeniden hesaplar; vaka notlarını ve olayları birlikte verir. Önceki sürüm paketlerinde özgün metin yoksa bu açıkça belirtilir. SOC raporu güncel toplamlar ve en son 200 vakayı içerir; mevcut ana sayfa günlük/haftalık raporunu da korur.

Mevcut 5 MB HTTP/10.000 olay/16.384 karakter satır sınırları sürer. Modüller en son 2.000 olaydan en fazla 200 kayıt gösterir; Sigma eşleşmeleri en fazla 100 gösterilir. Küre son yüklenen olay sayfası üzerinde çalışır. UEBA yalnızca gözlenen günleri karşılaştırır, eksik toplanmış günleri gerçek sıfır trafik saymaz. Sabit günlük hacimde varyans yoksa istatistiksel sonuç üretilmez.

SQLite kanıt saklama süresini bu sürüm otomatik silmez; yetkili arşivleme/yedekleme işletmeci tarafından yapılır. DB, collector state ve Docker volume'leri hassas veri içerir. Render geçici dosya sistemi gerçek vaka saklama için uygun değildir. Bu mimari üretim ölçeği sertifikası veya çok tenant'lı SIEM değildir.

Yerel kontroller:

```powershell
& .venv/Scripts/python.exe -m pytest -q
node --test tests/pages_gate.test.mjs tests/geo.test.mjs
$env:PLAYWRIGHT_CHANNEL = 'msedge'
$env:SOC_TEST_KEY = '<yalnizca-izole-test-veritabani-anahtari>'
node tests/ui-browser.mjs
node tests/atlas-browser.mjs
node tests/platform-browser.mjs
```

Tarayıcı testleri varsayılan `http://127.0.0.1:5056` üzerinde izole bir Flask uygulaması bekler; `TEST_BASE_URL` değiştirilebilir. [Yeni testler](./tests/test_integrations.py) auth/rol, servis kapalı durumları, kanıt bütünlüğü, Sigma reddetme ve collector yeniden başlatma/ACK davranışını kapsar. GNS3, Wazuh, Docker ve model testlerinin mock bölümleri gerçek servis uyumluluğu doğrulaması değildir. Canlı sağlayıcı sorgusu bu geliştirme sırasında yapılmaz.
