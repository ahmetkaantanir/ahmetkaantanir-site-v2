'use strict';
// UI copy only. Evidence, uploaded logs, secrets and API values are never translated.
window.labEnglish = Object.fromEntries(`
Proje kapsamı|Project scope
Olay konumları ve kanıt kapsamı|Event locations & evidence coverage
Konum ve IP|Locations & IPs
Hedef|Destination
Kaynak + hedef|Source + destination
LOG → KONUM → KANIT|LOG → LOCATION → EVIDENCE
Bu dünya neyi gösteriyor?|What does this globe show?
Yalnızca logdaki açık kaynak/hedef koordinatları gösterilir. Bir noktaya tıklayıp dayandığı olayı açın; IP adresinden konum veya saldırı çıkarımı yapılmaz.|Only explicit source/destination coordinates in logs are shown. Select a point to open its evidence. IP addresses alone never imply a location or an attack.
Nasıl kullanılır?|How do I use it?
Log Explorer’ın son yüklenen sayfası haritaya aktarılır. ECS source.geo.location ve destination.geo.location alanları kullanılır. Çizgiler aynı olayın uçlarını birleştirir; gerçek paket rotası veya saldırı kanıtı değildir. Konumlar logu üreten sistemin beyanıdır.|The last loaded Log Explorer page supplies the map. It reads ECS source.geo.location and destination.geo.location fields. Lines connect endpoints reported in the same event, not actual packet routes or proven attacks. Locations are claims made by the log producer.
Koordinat yoksa harita kapsamı sıfır gösterilir. Coğrafi referans modu yalnızca eğitim ve yön bulmak içindir.|Without coordinates, map coverage is zero. Geographic reference mode is for learning and orientation only.
Görünüm|View
Log konumları|Log locations
Coğrafi referanslar|Geographic references
Konumlu log bekleniyor.|Awaiting logs with coordinates.
Olay filtresini aç|Open event filters
Analitik · Yerel harita|Analytical · Local basemap
Konumdan kanıta.|From location to evidence.
Çizgi: aynı olayın uçları|Line: endpoints in the same event
LOGDA BEYAN EDİLEN KONUM|LOCATION DECLARED IN LOG
Konum doğrulanmış fiziksel adres veya saldırgan kimliği değildir.|A location is not a verified physical address or an attacker's identity.
Kanıtı aç|Open evidence
Konum seçilmedi|No location selected
LOG KONUM KAPSAMI|LOG LOCATION COVERAGE
Koordinat bulunamadı.|No coordinates found.
Bir konum seçip dayandığı logu inceleyin.|Select a location to inspect the supporting log.
IP adresi tek başına konum değildir. ECS koordinat alanı olmayan kayıtlar haritaya yerleştirilmez.|An IP address alone is not a location. Records without ECS coordinate fields are not plotted.
Sentetik örnek · Gerçek trafik değildir.|Synthetic example · Not real traffic.
Son yüklenen olay sayfası · Tüm veri kümesi değildir.|Last loaded event page · Not the entire dataset.
YEREL ANALİTİK HARİTA · NATURAL EARTH|LOCAL ANALYTICAL BASEMAP · NATURAL EARTH
Yerel analitik harita · Natural Earth|Local analytical basemap · Natural Earth
Örnek SOC görünümünü deneyin veya koordinat içeren logları bağlayın.|Try the sample workspace or connect logs containing coordinates.
Seçili olay|Selected event
Aynı IP|Same IP
Aynı kullanıcı|Same user
Aynı host|Same host
Çevre olayları ±5 dk|Surrounding events ±5 min
Bağlam: seçili olayın 5 dakika öncesi ve sonrası, tüm kaynaklar.|Context: five minutes before and after the selected event, across all sources.
API anahtarı gerekli.|An API key is required.
Dosya 5 MB sınırını aşıyor.|The file exceeds the 5 MB limit.
Log girin veya dosya seçin.|Paste logs or choose a file.
Beklenmeyen sunucu yanıtı|Unexpected server response
Henüz veri bulunmuyor.|No data yet.
Zaman bilgisi olan olay bulunmuyor.|No events with timestamps found.
Log yükleyerek kaynak görünürlüğünü ve zaman dağılımını ölçün.|Upload logs to measure source coverage and event timing.
Web erişimi, DNS çözümleme ve TLS oturumlarını kaynak IP üzerinden ilişkilendirin.|Correlate web access, DNS resolution and TLS sessions by source IP.
Bulut kontrol düzlemi ve kullanıcı oturumlarında kimlik değişikliklerini araştırın.|Investigate identity changes in cloud control-plane events and user sessions.
Ağ akışları, hedef portlar ve izin/engelleme kararlarını birlikte değerlendirin.|Review network flows, destination ports and allow/block decisions together.
WAF alarmlarını HTTP yanıtı ve uygulama loglarıyla doğrulayın.|Verify WAF alerts against HTTP responses and application logs.
CloudTrail benzeri denetim izlerinde API çağrısı, kimlik ve kaynak değişimini inceleyin.|Review API calls, identities and resource changes in cloud audit trails such as CloudTrail.
VPN oturumlarını hesap, cihaz ve zaman bağlamında karşılaştırın.|Compare VPN sessions by account, device and time.
Web ve kimlik doğrulama olaylarının ortak IP ve kullanıcılarını araştırın.|Investigate shared IPs and users across web and authentication events.
Endpoint süreçleri ile DNS ve dış ağ bağlantılarını ilişkilendirin.|Correlate endpoint processes with DNS and external network connections.
Servis hesapları ve bulut yönetim işlemlerinde beklenmeyen değişiklikleri inceleyin.|Review unexpected changes to service accounts and cloud administration activity.
Yüksek istek hacmini HTTP sonuçları, kullanıcı ve zaman penceresiyle değerlendirin.|Assess high request volumes by HTTP outcome, user and time window.
EDR, Sysmon ve oturum kayıtlarında süreç başlangıçlarını karşılaştırın.|Compare process starts across EDR, Sysmon and session logs.
Kaynak zaman dilimi ve UTC normalizasyonunu kontrol edin.|Check source time zones and UTC normalization.
Kimlik, VPN ve sınır ağ kayıtlarını aynı zaman çizelgesinde inceleyin.|Investigate identity, VPN and perimeter network records on the same timeline.
UTF-8 · 5 MB · 10K satır|UTF-8 · 5 MB · 10K lines
Grafik yüklenemedi. Sayısal sonuçlar ve rapor kullanılabilir.|Charts are unavailable. Numeric results and reports are still available.
Loglarını anla.|Understand your logs.
Kanıtla ilerle.|Follow the evidence.
Log yükle, bulguları incele, raporunu indir. İlk kez kullanıyorsan örnek veriyle başla; daha derin inceleme için SOC Merkezi’ni keşfet.|Upload logs, investigate findings and download a report. Start with sample data, or explore the SOC workspace for deeper investigation.
Log analizi|Log analysis
SOC Merkezi|SOC workspace
Rehber ve detaylar|Guide & details
Harita ve SOC Merkezi →|Explore the SOC workspace →
Analizi Başlat|Run analysis
01 / LOG ANALİZİ|01 / LOG ANALYSIS
Bir logla başla.|Start with a log.
1. Dosya yükle veya örnek seç. 2. Analizi çalıştır. 3. Bulguları incele ve rapor al.|1. Upload a file or choose a sample. 2. Run the analysis. 3. Review findings and generate a report.
Örnek verilerle ücretsiz deneyin. Yüklediğiniz loglar analiz için sunucuya gönderilir; yalnızca paylaşmaya yetkili olduğunuz verileri kullanın.|Try sample data for free. Uploaded logs are sent to the server for analysis. Only use data you are authorized to share.
Apache Dataset|Apache sample
Auth Dataset|Authentication sample
Karışık Saldırı|Mixed attack sample
Log Toplama|Upload logs
.log, .txt ve .json formatları desteklenir. Maksimum dosya boyutu: 5 MB.|Supported formats: .log, .txt and .json. Maximum file size: 5 MB.
Dosyayı buraya sürükleyin|Drop your file here
veya|or
Dosya Seç|Choose file
API Simülasyonu|JSON input
(JSON satır)|(JSON lines)
API Verisini Ekle|Append JSON data
Ham Log Girişi|Raw log input
Log verisini buraya yapıştırın veya yukarıdan bir dataset seçin…|Paste logs here or choose a sample above…
Temizle|Clear
ANALİZ SONUÇLARI|ANALYSIS RESULTS
Bulguların, tek bakışta.|Your findings, at a glance.
Toplam İşlem|Total events
Error Oranı|Error rate
En Aktif IP|Most active IP
Trafik Grafiği (Saatlik)|Hourly traffic
En Aktif IP'ler|Most active IPs
Alarmlar|Alerts
Korelasyon|Correlation
Analiz çalıştırın.|Run an analysis to see results.
RAPOR|REPORT
Güvenlik raporu üret ve indir|Generate and download your report
Günlük Rapor|Daily report
Haftalık Rapor|Weekly report
Raporu İndir|Download report
Önce analiz çalıştırın, ardından rapor üretin…|Run an analysis, then generate a report…
02 / SOC MERKEZİ|02 / SOC WORKSPACE
Daha derine in.|Investigate further.
3D dünya, olay arama, tehdit avı ve vaka yönetimi. Anahtar olmadan örnek SOC görünümünü deneyebilirsin.|A 3D globe, event search, threat hunting and case management. Try the sample workspace without an API key.
Güvenlik merkezi|Security workspace
Bu bölüme geldiğinizde harita ve inceleme araçları yüklenir.|The map and investigation tools load when you reach this section.
SOC merkezini yükle|Load SOC workspace
Harita ve güvenlik araçları hazırlanıyor…|Preparing the map and security tools…
03 / REHBER|03 / GUIDE
Detaylar, ihtiyacın olduğunda.|Details, when you need them.
Desteklenen kaynaklar, çalışma mantığı ve kullanım sınırları.|Supported sources, how it works and usage limits.
Nasıl çalışır?|How does it work?
Desteklenen log kaynakları|Supported log sources
Log analizi rehberi|Log analysis guide
Güvenlik ve kullanım sınırları|Security & usage limits
Analiz geçmişim nerede?|Where is my analysis history?
Kalıcı geçmiş ve vaka yönetimi için SOC Merkezi’ne API anahtarınızla bağlanın. Örnek SOC görünümü gerçek kayıt içermez.|Connect to the SOC workspace with your API key for saved history and case management. The sample workspace contains synthetic data only.
1. Ana Mimari|Architecture
Uçtan uca veri akışı|End-to-end data flow
ELK yaklaşımından ilham alan; ingest, parsing, analytics, visualization, alert ve report katmanlarını kapsayan mimari.|An ELK-inspired workflow covering ingestion, parsing, analytics, visualization, alerts and reports.
Log Kaynağı|Log source
Toplama|Ingestion
İşleme|Processing
Analiz|Analysis
Görselleştirme|Visualization
Alarm|Alert
Rapor|Report
2. Log Kaynakları|Log sources
Desteklenen veri türleri ve hazır dataset'ler|Supported data types and samples
Web Logları|Web logs
Sistem Logları|System logs
Auth Logları|Authentication logs
Firewall Logları|Firewall logs
Apache/Nginx access ve error kayıtları, HTTP status kodları ve user-agent analizi.|Apache/Nginx access and error records, HTTP status codes and user agents.
Linux syslog servis ve çekirdek olayları, daemon kesintileri.|Linux syslog service and kernel events, daemon interruptions.
SSH login, failed auth ve brute force izleri üzerinden korelasyon.|Correlate SSH logins, failed authentication and brute-force indicators.
DROP/ACCEPT trafik kayıtları, port anomalileri ve IP engelleme izleri.|DROP/ACCEPT traffic records, port anomalies and IP blocking indicators.
7. Eğitim İçeriği|Learning resources
Derinlemesine konu başlıkları|Learn to investigate logs
Temel|Fundamentals
Log Analizi Nedir?|What is log analysis?
Kayıtlardan olay zamanı, aktör, hedef ve etkilenim analizini sistematik biçimde çıkarma metodolojisi.|A systematic approach to identifying event times, actors, targets and impact from records.
Apache Log Nasıl Okunur?|How to read Apache logs
Common Log Format alanları: IP, timestamp, request, status, bytes, referer ve user-agent ayrıntılı analizi.|Understand Common Log Format fields: IP, timestamp, request, status, bytes, referrer and user agent.
Güvenlik|Security
Brute Force Tespiti|Detecting brute-force attempts
Kısa zaman aralığında tekrarlayan failed login olayları ve IP yoğunluğu üzerinden tespit yaklaşımı.|Investigate repeated failed logins and concentrated IP activity within short time windows.
Saldırı|Attack indicators
SQL Injection Log'dan Nasıl Anlaşılır?|Identifying SQL injection in logs
OR 1=1, UNION SELECT, information_schema gibi imzaların request içinde aranması ve bağlamsal yorumlanması.|Look for request indicators such as OR 1=1, UNION SELECT and information_schema, then verify their context.
5 dk okuma|5 min read
6 dk okuma|6 min read
8 dk okuma|8 min read
10 dk okuma|10 min read
8. Platform Güvenliği & Stack|Platform security & stack
Savunma katmanı ve teknik altyapı|Security measures and technical foundation
Canlı ortamda TLS zorunlu, HSTS politikası önerilir.|TLS is required in production; an HSTS policy is recommended.
Upload Kontrolü|Upload validation
Uzantı, boyut (5 MB) ve içerik doğrulaması zorunlu olarak uygulanır.|File extension, size (5 MB) and content validation are enforced.
Zararlı Dosya Engeli|File safety checks
Script ve ikili içerikler filtrelenir, parser sandbox yaklaşımı.|Uploaded files are processed as text and are not executed.
API uç noktalarında dakikalık istek limitleri; analyze: 30, report: 40.|API rate limits per minute: analysis 30, reports 40.
Araç|Analyze
Panel|Workspace
Rehber|Guide
Güvenlik analitiği ve log istihbarat platformu.|Security analytics and log investigation workspace.
Açık tema|Light theme
Koyu tema|Dark theme
Açık temaya geç|Switch to light theme
Koyu temaya geç|Switch to dark theme
Menüyü aç/kapat|Toggle navigation
Log Intelligence Lab Ana Sayfa|Log Intelligence Lab home
Dosya sürükleyip bırakın veya tıklayın|Drop a file or click to choose
Log dosyası seç|Choose a log file
İşlenen Kayıt|Processed records
Üretilen Alarm|Generated alerts
Güncel Risk Seviyesi|Current risk level
Düşük|Low
Orta|Medium
Yüksek|High
Kritik|Critical
Sadece .log, .txt, .json dosyaları desteklenir.|Only .log, .txt and .json files are supported.
Dosya boyutu 5 MB'ı aşamaz.|The file must be smaller than 5 MB.
Dataset tanımı yok.|No sample is defined.
Dataset yüklenemedi. Flask sunucusu çalışıyor mu?|The sample could not be loaded. Please check the server connection and try again.
API simülasyon alanı boş.|Enter JSON data first.
Her satır geçerli JSON olmalı.|Each line must contain valid JSON.
Analiz için dosya yükleyin veya log girin.|Upload a file or paste logs to start.
Analiz sırasında hata oluştu.|Analysis failed. Please try again.
Önce analiz çalıştırın.|Run an analysis first.
Rapor oluşturulurken hata oluştu.|The report could not be generated. Please try again.
İndirmek için önce rapor üretin.|Generate a report before downloading.
Rapor indirildi.|Report downloaded.
Tüm alanlar temizlendi.|All fields cleared.
Alarm üretilmedi.|No alerts generated.
Korelasyon senaryosu tespit edilmedi.|No correlations detected.
Anormallik tespit edilmedi.|No anomalies detected.
IP verisi yok.|No IP data available.
Skor: bilinmiyor|Score: unknown
SOC çalışma alanı|SOC workspace
Genel Bakış|Overview
İzleme Listesi|Watchlist
Kaynak Görünürlüğü|Source coverage
Bir alarm kesin saldırı kanıtı değildir. Her bulguyu loglar ve sistem bağlamıyla doğrulayın.|An alert is not proof of an attack. Verify each finding against logs and system context.
Gerçek olayları görün. Tehditleri ilişkilendirin. Kanıtla karar verin.|Review events, connect indicators and make evidence-based decisions.
● Bağlı değil|● Not connected
← Ana platform|← Main platform
Güvenli bağlantı|Secure connection
SOC API erişimi|SOC API access
Bu özel çalışma alanı güçlü bir sunucu API anahtarı gerektirir. Anahtar tarayıcıda kaydedilmez.|This private workspace requires a strong server API key. The key is not saved in your browser.
SOC API anahtarı|SOC API key
Örnek SOC görünümü|Try sample workspace
Güvenli bağlan|Connect securely
Başlamak için API anahtarınızı girin. Hassas gerçek verileri yalnızca izinli ortamlarda analiz edin.|Enter your API key or try the sample workspace. Only analyze sensitive data in authorized environments.
TOPLAM OLAY|TOTAL EVENTS
Normalleştirilmiş kayıt|Normalized records
GÜVENLİK ALARMI|SECURITY ALERTS
Kural eşleşmesi|Rule matches
ANALİZ PAKETİ|ANALYSIS BATCHES
SHA-256 ile korunan kaynak|SHA-256 source digest
AÇIK VAKA|OPEN CASES
İnceleme bekliyor|Awaiting investigation
Kaynak dağılımı|Source distribution
Henüz işlenmiş veri bulunmuyor.|No processed data yet.
Son analizler|Recent analyses
Henüz analiz bulunmuyor.|No analyses yet.
Tehdit görünürlüğü|Investigation map
IP bağlamı, kanıt kapsamı ve log kalitesi.|IP context, evidence coverage and log quality.
Veri bekleniyor|Awaiting data
Veri bekleniyor.|Awaiting data.
Bölge seçimi|Choose region
Dünya|World
Avrupa|Europe
Asya|Asia
Amerika|Americas
Okyanusya|Oceania
Harita katmanı|Map layer
Akıllı katman|Automatic layer
Uydu · Sentinel-2|Satellite · Sentinel-2
Sokak · OpenStreetMap|Streets · OpenStreetMap
Uzaklaştır|Zoom out
Yakınlaştır|Zoom in
Görünümü sıfırla|Reset view
Etkileşimli uydu ve sokak haritası|Interactive satellite and street map
Harita hazırlanıyor…|Preparing map…
Küresel altyapıyı keşfet.|Explore the world.
Küre → ülke → şehir → sokak · Sürükle ve yakınlaştır|Globe → country → city → street · Drag and zoom
Otomatik dönüşü başlat|Start rotation
Otomatik dönüşü durdur|Pause rotation
Dönüşü durdur|Pause rotation
ÜLKE / REFERANS MERKEZİ|COUNTRY / REFERENCE CITY
Sabit coğrafi referanslar; canlı trafik, saldırı veya veri merkezi kapasitesi sıralaması değildir. Loglar henüz GeoIP ile eşleştirilmez.|Fixed geographic references, not live traffic, attacks or data-center rankings. Logs are not geolocated with GeoIP.
Veri kalitesi|Data quality
API bağlantısı veya örnek görünüm ile başlayın.|Connect to the API or try sample data.
Eksik alanlar görünürlük boşluğu oluşturur. Alarm bulunmaması güvenli olduğu anlamına gelmez.|Missing fields reduce visibility. No alerts does not mean a system is safe.
SEÇİLİ KONUM|SELECTED LOCATION
Şehri incele|Explore city
Sokak ayrıntısı|Street detail
Haritada aç ↗|Open map ↗
Uydu mozaiği: Sentinel-2 cloudless 2020 / EOX. Sokaklar: OpenStreetMap. Görüntüler canlı değildir. Harita yüklenirken sağlayıcılar IP adresinizi ve görüntülenen harita alanını alır; loglar ve SOC anahtarı gönderilmez.|Satellite mosaic: Sentinel-2 cloudless 2020 / EOX. Streets: OpenStreetMap. Imagery is not live. Map providers receive your IP and the viewed area; logs and SOC keys are never sent to them.
Olay zaman dağılımı|Events over time
Alarm öncelikleri|Alert priorities
İnceleme önerileri|Investigation guidance
IP inceleme masası|IP investigation
En çok olay üreten 50 IP. Kayıtları incelemek için bir IP seçin.|The 50 IPs with the most events. Select an IP to investigate its records.
KAPSAM|SCOPE
OLAY|EVENTS
ALARM|ALERTS
İTİBAR|REPUTATION
İNCELE|INVESTIGATE
Hipotezden kanıta|From hypothesis to evidence
Hazır sorgularla başlayın; kullanıcı, host, kaynak ve zaman alanlarını daraltarak inceleyin.|Start with a hunting query, then narrow by user, host, source and time.
6 av sorgusu|6 hunting queries
İzleme listesi|Watchlist
IP, kullanıcı veya host tanımlayın. Kayıtlı olaylardaki tam eşleşmeleri takip edin; listeye eklemek zararlılık kararı değildir.|Track exact IP, user or host matches in stored events. Adding an entity does not classify it as malicious.
Yenile|Refresh
↻ Yenile|↻ Refresh
Varlık türü|Entity type
IP adresi|IP address
Kullanıcı|User
Değer|Value
Analist etiketi|Analyst label
İnceleme gerekçesi|Reason for investigation
Listeye ekle|Add to watchlist
TÜR / DEĞER|TYPE / VALUE
ETİKET|LABEL
EŞLEŞEN OLAY|MATCHING EVENTS
SON OLAY (UTC)|LAST EVENT (UTC)
İŞLEM|ACTION
Bağlantı bekleniyor.|Awaiting connection.
En fazla 100 kayıt. IP adresleri normalleştirilir; kullanıcı ve host eşleşmesi büyük/küçük harfe duyarlıdır. Otomatik engelleme yapılmaz.|Up to 100 entries. IPs are normalized; user and host matching is case-sensitive. No automatic blocking.
Kaynak görünürlüğü|Source coverage
Kaynak başına kayıt hacmi, eksik alanlar ve son içe alma. Collector heartbeat bağlı olmadığından çevrimiçi/çevrimdışı kararı verilmez.|Review event volume, missing fields and last ingestion per source. Online/offline status is unavailable without collector heartbeats.
Logları güvenle incele|Investigate your logs
HAM LOG GİRDİSİ|RAW LOG INPUT
Dosya seç (.log, .txt, .json)|Choose file (.log, .txt, .json)
Örnek senaryo|Sample scenario
Analiz başlat →|Run analysis →
Orijinal kayıt SHA-256 özetiyle tanımlanır. Zaman dilimi bilinmeyen olaylar zaman korelasyonuna alınmaz. Dış tehdit istihbaratı veya yapay zekâ API'sine veri gönderilmez.|Original records have SHA-256 digests. Events with unknown time zones are excluded from time correlations. No data is sent to external AI or threat-intelligence APIs.
Olayları kaynağa, IP'ye veya ham içeriğe göre araştırın.|Investigate events by source, IP or raw content.
Kaynak IP|Source IP
Tüm kaynaklar|All sources
Log içeriğinde ara|Search log content
Kullanıcı (tam eşleşme)|User (exact match)
Host (tam eşleşme)|Host (exact match)
Sonuç|Outcome
Tüm sonuçlar|All outcomes
Başarısız|Failure
Başarılı|Success
Bilinmiyor|Unknown
Aksiyon (tam eşleşme)|Action (exact match)
Aksiyon|Action
Filtrele|Apply filters
Başlangıç (cihazın yerel saati)|From (your local time)
Bitiş (cihazın yerel saati)|To (your local time)
Filtreleri temizle|Clear filters
Bu sayfayı JSON indir|Export this page as JSON
Henüz sorgulanmadı.|No query yet.
← Önceki|← Previous
Sonraki →|Next →
ZAMAN (UTC)|TIME (UTC)
KAYNAK|SOURCE
AKSİYON|ACTION
SONUÇ|OUTCOME
Alarm kanıtları, vaka durumları ve analist notları.|Alert evidence, case status and analyst notes.
Tüm durumlar|All statuses
Yeni|New
İnceleniyor|Investigating
Çözüldü|Resolved
Yanlış pozitif|False positive
Henüz vaka bulunmuyor.|No cases yet.
Algılama kuralları|Detection rules
Açıklanabilir, kanıta bağlı ve MITRE ATT&CK referanslı kurallar.|Explainable, evidence-based rules with MITRE ATT&CK references.
İçe alımlar ve vaka değişikliklerinin işlem kaydı.|An audit trail of ingestions and case changes.
© Log Intelligence Lab · Eğitim ve araştırma amaçlı SOC analiz ortamı · Gerçek güvenlik denetiminin yerini almaz.|© Log Intelligence Lab · An educational and research SOC workspace · Not a substitute for a security assessment.
● Örnek veriler|● Sample data
● Güvenli bağlantı|● Securely connected
ÖRNEK MODU: 18 sentetik log, iki örnek alarm; hiçbir gerçek olay sunucuya yüklenmez. Gerçek analiz için Render API anahtarıyla bağlanın.|SAMPLE MODE: 18 synthetic events and two example alerts. No real events are uploaded. Connect with your server API key for real analysis.
Bağlantı hazır. Analizler özel SOC veritabanına kaydedilir; yalnızca izinli verileri yükleyin.|Connected. Analyses are stored in the private SOC database. Only upload authorized data.
SENTETİK ÖRNEK|SYNTHETIC SAMPLE
KAYITLI VERİ|STORED DATA
Toplam olay|Total events
Zamanı eksik|Missing time
IP eksik|Missing IP
Ayrıştırılamayan|Unparsed
Kaydet|Save
Zaman çizelgesi|Timeline
Yorum|Explanation
Analist notları|Analyst notes
Kanıt|Evidence
Kayıtları aç|View records
Olaylar|Events
Listeden çıkar|Remove
Kaynağı incele|Investigate source
KAYITLI KAYNAK|STORED SOURCE
Sorguyu çalıştır →|Run query →
Başarısız kimlik doğrulama|Failed authentication
IP, kullanıcı ve zaman aralığını daraltın. Tek başarısız oturum saldırı kanıtı değildir.|Narrow by IP, user and time. A single failed login is not proof of an attack.
PowerShell komutları|PowerShell commands
Komut satırı, parent process ve kodlama bayraklarını ham kanıt üzerinde karşılaştırın.|Compare command lines, parent processes and encoding flags against raw evidence.
Yeni Windows hesapları|New Windows accounts
Hesap açma olaylarını değişiklik onayı ve oluşturan kullanıcı bağlamında inceleyin.|Investigate account creation against change approvals and the creating user.
Zamanlanmış görevler|Scheduled tasks
Görev içeriğini ve çalıştırılan dosyayı inceleyin; meşru otomasyonu ayırın.|Inspect task content and executable files; distinguish legitimate automation.
Bulut kontrol düzlemi|Cloud control plane
AWS JSONL olaylarını kimlik, API aksiyonu, kaynak IP ve UTC zamanıyla araştırın.|Investigate AWS JSONL events by identity, API action, source IP and UTC time.
Görünürlük boşlukları|Visibility gaps
Ayrıştırılamayan kayıtları bulun. Eksik parser desteği tespit kapsamını azaltır.|Find unparsed records. Missing parser support reduces detection coverage.
Kritik ve yüksek alarmların ham kanıtını Incident Center üzerinden inceleyin.|Review raw evidence for critical and high alerts in the Incident Center.
Zaman ve kaynak alanları mevcut. Kullanıcı, host ve IP bağlamıyla bulguları doğrulayın.|Time and source fields are available. Verify findings with user, host and IP context.
Coğrafi referans noktaları olay konumu veya zararlılık göstergesi değildir.|Geographic reference points do not indicate event locations or malicious activity.
UYDU HARİTASI · GERÇEK COĞRAFYA|SATELLITE MAP · REAL GEOGRAPHY
UYDU MOZAIĞI · SENTINEL-2 / EOX|SATELLITE MOSAIC · SENTINEL-2 / EOX
SOKAK KATMANI · OPENSTREETMAP|STREET LAYER · OPENSTREETMAP
Harita verisi yüklenemedi. Ağ bağlantısını kontrol edin veya katman değiştirin.|Map data could not be loaded. Check your connection or switch layers.
Bu cihazda WebGL haritası açılamadı. Konum kartları ve dış harita bağlantısı kullanılabilir.|WebGL is unavailable on this device. Location cards and external map links are still available.
Gerçek harita için WebGL destekli bir tarayıcı ve internet bağlantısı gerekir.|The map requires a WebGL-enabled browser and an internet connection.
AWS BÖLGE REFERANSI|AWS REGION REFERENCE
Resmi bölge listesi ↗|Official region list ↗
Bir çalışma alanı bileşeni yüklenemedi.|A workspace component could not be loaded.
Çalışma alanı stilleri yüklenemedi.|Workspace styles could not be loaded.
Yeniden yükle|Try again
Özet|Overview
Güvenlik merkezinin etkileşimli araçları JavaScript gerektirir.|The interactive workspace requires JavaScript.
Mobil hızlı gezinme|Mobile navigation
Platform istatistikleri|Platform statistics
KPI metrikleri|Analysis metrics
Saatlik trafik grafiği|Hourly traffic chart
IP dağılım grafiği|IP distribution chart
Alarm listesi|Alert list
Korelasyon senaryoları|Correlations
Bağlandıktan sonra olaylar burada görüntülenir.|Events appear here after you connect.
Henüz veri yok.|No data yet.
Sokak ayrıntısı|Street detail
Örnek mod salt okunurdur. Gerçek log analizi için önce API anahtarıyla bağlanın veya ana sayfadaki halka açık analiz aracını kullanın.|Sample mode is read-only. Connect with your API key or use the public analysis tool to analyze real logs.
Önce API anahtarını girin.|Enter your API key first.
API anahtarı en az 24 karakter olmalıdır.|The API key must contain at least 24 characters.
Bağlantı kurulamadı.|Could not connect.
Örnek mod salt okunur. İzleme listesi için özel API bağlantısı gerekli.|Sample mode is read-only. A private API connection is required to edit the watchlist.
Varlık izleme listesinden çıkarıldı.|Entity removed from watchlist.
Varlık izleme listesine eklendi; kayıtlı olay eşleşmeleri hesaplandı.|Entity added to watchlist; stored event matches calculated.
Türkçe|Turkish
Güvenli dosya işleme|Safe file handling
Dosyalar metin olarak ayrıştırılır; yüklenen içerik çalıştırılmaz. Zararlılık kararı için kanıtları ayrıca doğrulayın.|Files are parsed as text; uploaded content is not executed. Verify evidence before drawing conclusions.
Kayıtlı olayları ve vakaları SOC Merkezi’nde inceleyin.|Review stored events and cases in the SOC workspace.
Bir tespit tek başına saldırı kanıtı değildir.|A detection alone is not proof of an attack.
İçerik özeti|Topic overview
Önce örnek seçebilir veya kendi logunu yükleyebilirsin.|Choose a sample or upload your own logs to begin.
Analiz tamamlandı.|Analysis complete.
Hazır|Ready
Bağlanıyor…|Connecting…
Analiz ediliyor…|Analyzing…
Dosya okunamadı.|The file could not be read.
Log alanı boş.|The log input is empty.
İşleniyor…|Processing…
Rapor hazır.|Report ready.
İndir|Download
Erişim anahtarı geçersiz.|Invalid API key.
Oturum veya API anahtarı gerekli.|A session or API key is required.
Sunucu meşgul. Biraz sonra yeniden deneyin.|The server is busy. Please try again shortly.
Bağlantı değişti; eski yanıt kullanılmadı.|The connection changed; the previous response was discarded.
Bu özellik örnek modda kullanılamaz.|This feature is unavailable in sample mode.
Sunucuya ulaşılamadı.|Could not reach the server.
Örnek kayıtlar yüklendi.|Sample records loaded.
Vaka güncellendi.|Case updated.
Log dosyası|Log file
Dosya|File
Manuel|Manual
Türkiye|Türkiye
Almanya|Germany
Birleşik Krallık|United Kingdom
Hollanda|Netherlands
Fransa|France
ABD|United States
Kanada|Canada
Brezilya|Brazil
Japonya|Japan
Singapur|Singapore
Hindistan|India
Güney Kore|South Korea
Avustralya|Australia
İstanbul|Istanbul
Londra|London
Sidney|Sydney
Seul|Seoul
Dokümantasyon|Documentation
Eşleme yok|Not mapped
Küre|Globe
Ülke|Country
Şehir|City
Sokak|Street
COĞRAFİ REFERANS|GEOGRAPHIC REFERENCE
KÜRE|GLOBE
ÜLKE|COUNTRY
ŞEHİR|CITY
SOKAK|STREET
AVRUPA|EUROPE
ASYA|ASIA
AMERİKA|AMERICAS
OKYANUSYA|OCEANIA
Sentinel-2 uydu mozaiği (2020, en fazla z13 kaynak ayrıntısı)|Sentinel-2 satellite mosaic (2020, native detail up to z13)
OpenStreetMap sokak haritası|OpenStreetMap street map
Son 24 dolu saat dilimi · UTC · Boş saatler gösterilmez.|Last 24 non-empty hours · UTC · Empty hours omitted.
Sentetik inceleme IP|Synthetic investigation IP
Sentetik örnek başarıyla yüklendi.|Synthetic sample loaded.
Henüz audit kaydı yok.|No audit entries yet.
Lütfen geçerli bir tarih aralığı seçin.|Please select a valid date range.
Başlangıç zamanı bitişten sonra olamaz.|The start time cannot be after the end time.
Paylaşmaya yetkili olduğunuz logları kullanın.|Only use logs you are authorized to share.
Tema|Theme
Dil|Language
Logları keşfet|Explore logs
Kaynaklar|Sources
Mimari|Architecture
Eğitim|Learning
Raporlama|Reports
Geçmiş|History
5. Analiz Geçmişi|Analysis history
Son 25 analiz kaydı|Last 25 analyses
Geçmiş Analizler|Analysis history
Geçmişi yenile|Refresh history
Tarih|Date
Kaynak|Source
Kayıt|Records
Risk|Risk
Yükleniyor…|Loading…
Kayıtlı analiz geçmişi artık güvenli SOC Workspace üzerinden görüntülenir.|Saved analysis history is available in the secure SOC workspace.
Uydu görünümü · Şehir noktaları yaklaşık referanslardır.|Satellite view · City markers are approximate references.
Analizden incelemeye, tek çalışma alanı.|One workspace, from analysis to investigation.
Küresel altyapıyı keşfet.|Explore the world.
Güvenlik merkezinin etkileşimli araçları JavaScript gerektirir.|Interactive security tools require JavaScript.
Log Kaynakları|Log sources
Analiz Aracı|Analysis tool
Eğitim + Analiz + Araç|Learn + Analyze + Investigate
Bu özel çalışma alanı güçlü bir sunucu API anahtarı gerektirir. Anahtar tarayıcıda kaydedilmez.|This private workspace requires a strong server API key. Your key is not saved in the browser.
İnceleme gerekçesi|Investigation reason
Analizi başlat|Run analysis
Bilgi|Information
Hata|Error
Uyarı|Warning
Başarılı|Success
İşlem tamamlandı.|Operation completed.
Sorgu sonucu bulunamadı.|No matching events found.
Olay bulunamadı.|No events found.
İzleme listesi boş.|Your watchlist is empty.
Dosyalar metin olarak işlenir ve çalıştırılmaz.|Files are processed as text and are never executed.
Raporları yalnızca yetkili kişilerle paylaşın.|Only share reports with authorized people.
Güvenlik analitiği ve log istihbarat platformu.|Security analytics and log investigation platform.
`.trim().split('\n').map(line => { const at=line.indexOf('|'); return [line.slice(0,at),line.slice(at+1)]; }));

Object.assign(window.labEnglish,{
  "Proje kapsamı ve sık sorulanlar": "Project scope & frequently asked questions",
  "Elastic ECS harita yaklaşımı ↗": "Elastic ECS mapping approach ↗",
  "Grafana log bağlamı ↗": "Grafana log context ↗",
  "Bu proje tam olarak nedir?": "What is this project?",
  "Dosya veya metin olarak verilen logları ayrıştıran, açıklanabilir kurallarla bulgu üreten ve kanıt incelemesi sunan bir log analiz laboratuvarı ve Mini-SOC çalışma alanıdır.": "A log analysis lab and Mini-SOC workspace that parses uploaded or pasted logs, generates findings using explainable rules and supports evidence investigation.",
  "3D dünyanın loglarla ilişkisi ne?": "How does the 3D globe relate to logs?",
  "SOC olaylarında açık ECS koordinatları varsa kaynak/hedef uçlarını gösterir. Noktadan ilgili ham kanıta geçilir. IP tek başına konum değildir; harita saldırganın kimliğini veya fiziksel adresini kanıtlamaz.": "It displays source/destination endpoints when SOC events contain explicit ECS coordinates. Points link to raw evidence. An IP alone does not identify a location; the map does not prove an attacker’s identity or physical address.",
  "Harita tüm kayıtları mı gösteriyor?": "Does the map show all records?",
  "Hayır. Son yüklenen Log Explorer sayfası kullanılır; en fazla 100 olaylık sayfanın konum kapsamı ayrıca gösterilir. Filtre veya sayfa değişince harita güncellenir. Genel analiz aracı ile özel SOC kayıtları birbirine karıştırılmaz.": "No. It uses the last loaded Log Explorer page, up to 100 events, with explicit location coverage. Changing the page or filters updates the map. Public analysis and private SOC records remain separate.",
  "Koordinat yoksa neden dünya yine görünüyor?": "Why is the globe visible without coordinates?",
  "Yerel dünya tabanı inceleme bağlamıdır; olay noktası veya bağlantı çizgisi uydurulmaz. Eğitim için ayrıca seçilebilen coğrafi referans noktaları gerçek olay değildir.": "The local basemap provides geographic context. Event points and connection lines are never fabricated. The optional geographic reference points are educational, not actual events.",
  "Örnek görünüm gerçek saldırı mı?": "Does sample mode show real attacks?",
  "Hayır. 18 olay ve iki vaka tamamen sentetiktir. Üç örnek olayda, haritadan kanıta geçişi öğretmek için açıkça işaretlenmiş kaynak/hedef koordinatları bulunur.": "No. All 18 events and two cases are synthetic. Three example events include explicitly labeled source/destination coordinates to demonstrate the map-to-evidence workflow.",
  "Bu bir yapay zekâ veya kurumsal SIEM mi?": "Is this AI or an enterprise SIEM?",
  "Hayır. Tespitler deterministik kurallara dayanır; dış LLM servisi çağrılmaz. Sürekli collector, otomatik engelleme, çok kullanıcılı RBAC ve üretim ölçeğinde indeksleme bu projenin mevcut kapsamı değildir.": "No. Detections use deterministic rules; no external LLM is called. Continuous collectors, automatic blocking, multi-user RBAC and production-scale indexing are outside the current scope.",
  "Her log türü destekleniyor mu?": "Is every log format supported?",
  "Hayır. Web, SSH/auth, firewall, Windows Event JSON, Sysmon, Suricata EVE ve CloudTrail JSONL gibi tanınan biçimler ve genel JSON işlenir. Tanınmayan satırlar görünürlük boşluğudur; tam ayrıştırma veya tespit kapsamı varmış gibi sunulmaz. Ayrıştırılamayan kayıtları ayrıca inceleyin.": "No. Recognized formats include web, SSH/auth, firewall, Windows Event JSON, Sysmon, Suricata EVE, CloudTrail JSONL and generic JSON. Unrecognized lines are visibility gaps, not evidence of complete coverage. Inspect unparsed records separately.",
  "Alarm çıkmadıysa sistem güvenli mi?": "Does no alert mean the system is safe?",
  "Hayır. Kurallar yalnızca kapsadıkları göstergeleri yakalar. Alarm da tek başına başarılı saldırı kanıtı değildir. Ham kayıt, zaman, kullanıcı, host ve diğer kaynaklarla doğrulama gerekir.": "No. Rules only detect the indicators they cover. An alert alone is not proof of a successful attack either. Verify raw records, timestamps, users, hosts and other sources.",
  "Loglarım nerede işleniyor ve saklanıyor?": "Where are my logs processed and stored?",
  "Genel analiz logları sunucuya gönderilir, kalıcı genel geçmişe yazılmaz. Özel SOC içe alımları yetkili API üzerinden SQLite veritabanına kaydedilir. Kalıcılık sunucudaki disk ayarına bağlıdır. Loglar ve API anahtarı tarayıcı depolamasına yazılmaz.": "Public analysis sends logs to the server without saving a public history. Authorized SOC ingestions are stored in SQLite. Persistence depends on server disk configuration. Logs and API keys are not written to browser storage.",
  "Harita sağlayıcısına loglar gidiyor mu?": "Are logs sent to map providers?",
  "Hayır. Harita noktaları tarayıcıda hesaplanır; dış döşeme isteklerine ham log veya SOC anahtarı eklenmez. Uydu/sokak sağlayıcıları ziyaretçi IP adresini ve görüntülenen alanı görebilir. Yerel analitik katman dış harita döşemesi istemez.": "No. Points are calculated in the browser; raw logs and SOC keys are not included in external tile requests. Satellite/street providers can see the visitor’s IP and viewed area. The local analytical layer requests no external map tiles.",
  "Hata veya bağlantı kesilirse ne olur?": "What happens if a service is unavailable?",
  "Harita ya da grafik yüklenemediğinde açıklama ve kullanılabilir alternatifler gösterilir. Yetkisiz SOC erişimi veri açmaz. Sunucu hatası bir güvenlik sonucu gibi sunulmaz; işlemi tekrar deneyebilirsiniz.": "If a map or chart cannot load, the interface explains the issue and offers usable alternatives. Unauthorized SOC requests expose no data. Server failures are not presented as security findings; operations can be retried."
});
