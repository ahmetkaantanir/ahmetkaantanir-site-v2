# Log Intelligence Lab: araştırma, uygulama ve kalan kapsam

31 Ekim 2026. Bu rapor kaynak kodu incelemesi, resmi ürün dokümanları ve yerel test sonuçlarına dayanır. Eklenen işlevler aşağıda açıkça ayrılmıştır; kurumsal SIEM ölçeği veya tam üretici desteği iddia edilmez.

## Araştırmadan çıkan ürün kararları

| İncelenen kaynak | İlgili yaklaşım | Bu projeye uygulaması |
| --- | --- | --- |
| [Wazuh Threat Hunting](https://documentation.wazuh.com/current/getting-started/use-cases/threat-hunting.html) | Olay alanlarına göre filtreleme ve güvenlik incelemesi | Kullanıcı, host, aksiyon, sonuç, kaynak, IP ve zaman aralığı filtreleri |
| [Security Onion Hunt](https://docs.securityonion.net/en/2.4/hunt.html) | Genel özetten daha odaklı av sorguları | Altı açıklamalı av paketi; sorgudan ham olay kanıtına geçiş |
| [Microsoft 4720](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720) | Yeni kullanıcı hesabı olayı | WIN-002, onay ve oluşturan hesap incelemesi gerektiren gösterge |
| [Microsoft 4698](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698) | Zamanlanmış görev oluşturma | WIN-003, görev içeriği ve yürütülebilir dosya incelemesi |
| [MITRE PowerShell](https://attack.mitre.org/techniques/T1059/001/) | PowerShell ile komut yürütme | PROC-001; Windows/Sysmon CommandLine alanında encoded-command bayrağı |
| [CloudTrail kayıt alanları](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html) | Kimlik, kaynak IP, olay zamanı ve API adı | JSONL CloudTrail normalleştirmesi; ConsoleLogin Success/Failure |
| [MapLibre uydu katmanı](https://maplibre.org/maplibre-gl-js/docs/examples/display-a-satellite-map/) | Raster görüntülerin harita katmanı olarak sunulması | Gerçek uydu küresi, yakınlaştırma ve sokak katmanına geçiş |
| [EOX Maps](https://maps.eox.at/) | Sentinel-2 uydu mozaiği, atıflı uygulama kullanımı | Sentinel-2 cloudless 2020; kaynak azami zoom 13 |
| [OSM tile politikası](https://operations.osmfoundation.org/policies/tiles/) | Görünür atıf, standart URL, tarayıcı önbelleği, toplu indirme yasağı | OpenStreetMap sokak katmanı; normal tarayıcı cache'i; offline/prefetch yok |

## Bu sürümde çalışan özellikler

### Gerçek harita

- Çizim kıtalarının yerine MapLibre GL JS **5.24.0** raster globe. CSP uyumlu JS, worker, CSS ve lisans [vendor/maplibre](./vendor/maplibre) içinde yerel sunulur. Kaynak haritalar dış sağlayıcılardan alınır.
- Uzaktan uydu küresi; **Akıllı katman** modunda zoom 5 itibarıyla sokak/şehir haritası. Manuel uydu ve sokak seçimi.
- Mouse, dokunma, iki parmak zoom, klavye, pusula, ölçek, bölge seçimi, ülke/şehir seçimi, şehir zoom 11 ve sokak zoom 16 kısayolları.
- Kaynak görüntü tarihi ve sınırlaması görünür. Uydu mozaiği 2020'ye aittir; canlı uydu değildir. z13 üstü yeni uydu ayrıntısı üretmez; sokak verisi ayrı kaynaktır.
- 13 yaklaşık şehir referansı. Kürenin arkasındaki noktalar gizlenir. Noktalar olay veya saldırgan konumu olarak gösterilmez.
- 10 merkez için [AWS resmi bölge listesi](https://docs.aws.amazon.com/global-infrastructure/latest/regions/aws-regions.html) üzerinden doğrulanmış bölge kodu. Şehir koordinatı fiziksel tesis adresi değildir.
- Sekme veya harita görünmüyorsa otomatik dönüş durur. Hareket azaltma tercihi desteklenir. WebGL yoksa dürüst hata mesajı ve dış harita bağlantısı kalır.
- Harita isteklerine SOC anahtarı ve loglar eklenmez. Sağlayıcı yine ziyaretçi IP'sini ve görüntülenen coğrafi alanı görür. Bu davranış arayüzde açıklanır.
- Atıflar görünürdür. OSM/EOX ücretsiz servisleri SLA sunmaz; yoğun üretim trafiği için sözleşmeli veya kendi barındırılan tile kaynağı gerekir. Google Maps API, Street View ve Google fotoğrafları entegre edilmedi.

### İnceleme ve izleme

- **Threat Hunting:** başarısız girişler, PowerShell metni, yeni hesap, zamanlanmış görev, CloudTrail ve ayrıştırılamayan kayıtlar için altı hazır filtre paketi.
- **İzleme listesi:** SQLite'da kalıcı IP/kullanıcı/host kayıtları; eşleşme adedi ve son olay zamanı. Ekleme/çıkarma audit'e yazılır. En fazla 100 girdi. IP normalize edilir; kullanıcı ve host tam ve büyük/küçük harfe duyarlı eşleşir. Otomatik engelleme veya TI itibarı değildir.
- **Log Explorer:** IP, kaynak, ham metin, kullanıcı, host, aksiyon, sonuç, başlangıç/bitiş. Cihaz yerel zamanı UTC'ye çevrilir; API saat dilimsiz/bozuk zaman aralığını reddeder.
- **Sayfalama:** UI 100 kayıt, API en fazla 500. Toplam eşleşme ve sonraki sayfa bilgisi. Offset sayfalama canlı içe alma sırasında değişmez snapshot garantisi vermez.
- **Kanıt dışa aktarma:** yalnızca mevcut sayfanın JSON'u; sorgu filtreleri, UTC export zamanı, offset, kayıt adedi ve sentetik etiketi dahil. Tüm veritabanının dışa aktarımı değildir.
- **Kaynak görünürlüğü:** kaynak hacmi, eksik IP/zaman, son kaynak olayı ve son içe alma. Heartbeat olmadığı için online/offline durumları uydurulmaz.
- **Analitik:** son 24 dolu UTC saat dilimi, alarm önem dağılımı, veri eksiklerine göre deterministik inceleme önerileri.
- **IP inceleme:** en çok olay üreten 50 IP, IPv4/IPv6 kapsamı ve alarm sayısı; olaylara geçiş. İtibar ve GeoIP bağlı değilse bilinmiyor.

### Tespit ve normalleştirme

Mevcut brute force, spraying, başarısız giriş sonrası başarı, port tarama, yüksek HTTP hacmi, web göstergeleri, audit clear ve Suricata kurallarına üç kural eklendi:

| Kural | Koşul | Sınır |
| --- | --- | --- |
| PROC-001 / T1059.001 | Windows/Sysmon process komut satırında PowerShell/pwsh ve encoded-command bayrağı | Meşru otomasyon olabilir; payload çalıştırılmaz/çözülmez; tüm PowerShell kaçınmalarını kapsamaz |
| WIN-002 / T1136.001 | Düz Windows JSON EventID 4720 | Hesap açılması tek başına saldırı değildir |
| WIN-003 / T1053.005 | Düz Windows JSON EventID 4698 | Görev içeriği ve değişiklik onayı analist tarafından doğrulanır |

Web göstergeleri iki geçiş URL decode sonrasında da aranır. Ham kayıt değiştirilmez. Tespitler event ID'leriyle kanıta bağlanır. MITRE eşlemesi tek başına kapsam veya etkinlik sertifikası değildir.

## Kaynak destek matrisi

| Kaynak | Çalışan | Kalan eksik |
| --- | --- | --- |
| Apache/Nginx access benzeri | IP, UTC, yöntem/yol, durum, web göstergeleri | Özel log formatları, güvenilir proxy zinciri, response time/byte |
| Linux SSH | Failed/Accepted password, kullanıcı, IP | auditd, sudo, public key; yıl/saat dilimsiz syslog zamanı bilinmiyor |
| Windows | Düz EventID JSON; 4624/4625/4771/1102/4720/4698 | Yerel EVTX/XML, nested EventData; Subject/Target kullanıcı ayrımı |
| Sysmon | Provider etiketi, command line ve kodlanmış PowerShell göstergesi | Parent-child ProcessGuid zinciri, hash ve tüm ID şemaları |
| Suricata EVE | alert/DNS kaynak türü, IP/port | Signature severity, flow_id, DNS yanıtı/TLS alanları |
| Firewall | SRC/DPT metni | Üretici parser'ları, NAT ve allow/deny/byte normalleştirmesi |
| AWS CloudTrail | JSONL eventTime/eventName/sourceIPAddress/userIdentity; ConsoleLogin sonucu | AWS hesabına connector, toplu Records zarfı, IAM özel kuralları |
| DNS | EVE kaynak etiketi | NXDOMAIN, entropy, tunneling pencereleri |
| Entra / Azure / Kubernetes | Yalnızca genel JSON | Kaynağa özgü parser, connector ve kurallar |
| VPN / EDR / e-posta / WAF | Genel JSON kabulü; özel connector yok | Üretici kimlik doğrulaması, checkpoint, tekrar deneme ve şema |

## Kalan öncelikli işler

1. **P0 doğruluk:** farklı üreticilerin anonim fixture'ları, nested Windows normalleştirme, kullanıcı/host bazında ve paketler arasında korelasyon, eşik/allowlist ve false-positive ölçümü.
2. **P0 erişim/saklama:** SSO/RBAC, kullanıcı bazlı audit, retention, yedekten dönüş, kalıcı disk. Tek API anahtarı çok kullanıcılı yetkilendirme değildir.
3. **P1 gerçek konum:** lisanslı yerel GeoIP veritabanı, güncelleme tarihi, doğruluk yarıçapı ve unknown akışı. Özel IP'leri dış servise gönderme. IP konumu kişi konumu değildir.
4. **P1 operasyon:** TLS syslog, kalıcı queue, backpressure, gerçek source heartbeat ve collector ölçümleri.
5. **P1 hunting:** kaydedilen sorgular, vaka observables, süreç/ağ ilişki grafiği; yetkili, sınırlı tam rapor export.
6. **P2 ölçek:** veri hacmi hedefi ve ölçümlü yük testi sonrası OpenSearch/ClickHouse değerlendirmesi; mevcut SQLite'ı terabayt SIEM olarak sunma.
7. **P2 istihbarat:** açık tercih ve sağlayıcı koşullarıyla STIX/TAXII/TI; hata durumunda unknown. LLM özeti ayrı ve isteğe bağlı bir servis olmalı.

## Doğrulama

- Python: **99 test**; watchlist CRUD/yetki/audit, kaynak görünürlüğü, zaman dilimi aralığı, filtreler, pagination, yeni parser/kurallar, statik kaynak koruması.
- Pages testleri: harita dosyaları ve worker açık; paket kaynakları/source map kapalı; CSP'de unsafe-eval yok.
- [Tarayıcı regresyonu](./tests/soc-browser.cjs): 6 hunting paketi, filtrelenen 8 olayın JSON indirilmesi, kaynak kartları, gerçek harita tile yüklemesi, küre/sokak katmanı, mobil 390px taşma ve dokunma sürüklemesi.
- Harita kütüphanesi yerel sunulur; dış tile servislerinin erişilebilirliği ağ/sağlayıcıya bağlıdır.

```sh
.venv/Scripts/python.exe -m pytest -q
node --check soc.js
node --check atlas.js
node --test tests/pages_gate.test.mjs
```

Tarayıcı testi için Playwright ve bir Chromium tarayıcısı gerekir. `SOC_TEST_URL` varsayılanı `http://127.0.0.1:5000`; `SOC_MAP_ONLINE=1` tile yüklenmesini de bekler. `SOC_TEST_KEY` yalnızca **ayrı, boş test veritabanı** ile çalışan sunucuda ayarlanmalıdır: test sentetik olay ve izleme girdisi oluşturur. Üretim veritabanında çalıştırmayın. Windows'ta `PLAYWRIGHT_CHANNEL=msedge` kullanılabilir; kurulu Playwright farklı konumdaysa `PLAYWRIGHT_MODULE` tam modül yolunu alır.

Ek tarayıcı doğrulaması: ayrı test veritabanında API ile sentetik olay içe alma, host izleme kaydı ekleme, eşleşen tek olaya geçiş, kaynak görünürlüğünü yenileme ve izleme kaydını kaldırma başarıyla çalıştı. Son sonuç: **99 Python testi + 7 Pages testi**, JS sözdizimi kontrolleri ve masaüstü/mobil tarayıcı regresyonu geçti; sayfa JavaScript hatası gözlenmedi.

## Son kapanış kontrolü

Son incelemede hatalı JSON türleri ve ASCII dışı geçersiz API anahtarı için 500 yanıtı oluşmasını önleyen doğrulamalar eklendi. Milisaniyeli olaylar gerçek zamana göre sıralanır; vaka zaman çizelgesi de aynı sırayı korur. Yeniden bağlantıda önceki sonuçlar ve export belleği temizlenir; gecikmiş eski yanıtlar yeni bağlantı görünümüne uygulanmaz. Kullanıcının henüz göndermediği log girdisi korunur.

Son yerel sonuç: **99 Python + 7 Pages testi**, JS sözdizimi ve masaüstü/mobil E2E geçti. E2E; yetkili izleme listesi akışını, başarısız yeniden bağlantıyı, geç gelen yanıtı, filtreleme/export'u, gerçek tile yüklemesini ve mobil sürüklemeyi doğruladı.

Canlı `https://dev.ahmetkaantanir.com` üzerinde `/api/health`, `/atlas.js` ve `/soc` için otomatik HTTP kontrolleri **403** aldı. Bu kontrol canlı sürümün çalıştığını veya bozuk olduğunu kanıtlamaz; bu ortamdan doğrulama tamamlanamadı. Bu kontrol yayın öncesinde yapıldı; dağıtım sonucu GitHub Actions ve canlı endpoint kontrolleriyle ayrıca değerlendirilir.

**Kapanış kararı:** Mevcut eğitim/demo ve tek analist analiz kapsamı için yeni modül eklemeden sürüm kapanışı yapılabilir. Üretim SOC kabulü için canlı dağıtım doğrulaması, güçlü gizli anahtar yönetimi, kalıcı veritabanı/yedekleme/geri dönüş, kullanıcı bazlı yetki, retention ve hedef hacimde yük testleri halen gereklidir. GeoIP/TI, sürekli collector ve paketler arası korelasyon sonraki kapsamdır; mevcut arayüz bunların çalıştığını iddia etmez.
