# Projenin amacı ve özelliklerin gerekçesi

Bu proje dosya/metin tabanlı log analizi, açıklanabilir tespit ve kanıt incelemesi sunan bir laboratuvar ve Mini-SOC'tur. “Her logu eksiksiz analiz eden kurumsal SIEM”, gerçek zamanlı saldırı takip servisi veya AI karar motoru olarak sunulmaz.

## Her araç hangi soruya cevap verir?

| Araç | Analistin sorusu | Gösterdiği kanıt / sınır |
| --- | --- | --- |
| Genel analiz | Bu logda hangi göstergeler var? | Girilen dosya/metin, kural bulguları ve indirilebilir rapor; kayıtlı özel SOC ile karışmaz. |
| Log Explorer | Hangi kayıt, kullanıcı, host ve zaman? | Filtrelenmiş olaylar, Event ID ve orijinal ham kayıt. |
| Harita | Açık koordinat içeren olaylar hangi uçları bildiriyor? | Son yüklenen sayfadaki ECS koordinatları; noktadan aynı olayın ham kanıtına geçiş. |
| ±5 dakika bağlamı | Bu olayın çevresinde ne olmuş? | Zaman dilimi bulunan olayın önceki/sonraki 5 dakikasındaki kayıtlar; UTC sorgusu, cihaz yerel saatinde filtre alanları. |
| Aynı IP/kullanıcı/host | Bu varlık başka nerede görünüyor? | Yeni, açıkça görünen filtrelerle olay araması; eşleşme zararlılık kararı değildir. |
| Threat Hunting | Bir hipotezi hangi sorguyla sınarım? | Düzenlenebilir alanlara uygulanan altı hazır sorgu; uydurma sonuç üretmez. |
| Veri kalitesi / kaynak görünürlüğü | Neyi göremiyorum? | Eksik zaman/IP, ayrıştırılamayan kayıtlar, kaynak hacmi; collector heartbeat yoksa online/offline iddiası yok. |
| Incident Center | Hangi bulguya hangi kanıtla karar verildi? | Vaka durumu, analist notu, ilişkilendirilen olaylar ve denetlenebilir açıklama. |
| Watchlist | Belirli varlıklar kayıtlarda var mı? | Kayıtlı olaylarla tam eşleşme; otomatik engelleme yok. |
| JSON dışa aktarma | İncelediğim kapsamı tekrar gösterebilir miyim? | Mevcut sayfa, filtreler, zaman, sentetik veri işareti; tüm veritabanı yedeği değildir. |

## Harita veri sözleşmesi

Harita `raw` JSON kaydındaki `source.geo.location` / `destination.geo.location` alanlarını okur. İç içe ECS nesneleri veya noktalı anahtarlar kabul edilir. Desteklenen koordinat biçimleri sayısal `[boylam, enlem]` veya `{ "lon": boylam, "lat": enlem }` nesnesidir. Sıfır geçerlidir; sayısal metin, boş değer, NaN, sonsuzluk ve geçersiz aralık reddedilir. Enlem −90…90, boylam −180…180 olmalıdır.

```json
{
  "synthetic": true,
  "source": { "ip": "192.0.2.25", "geo": { "location": [29, 41] } },
  "destination": { "ip": "198.51.100.10", "geo": { "location": [-74, 40.7] } }
}
```

- IP'den ülke veya konum tahmini yapılmaz. Otomatik GeoIP servisi veya gizli bir dış zenginleştirme çağrısı yoktur.
- Koordinatlar log üreticisinin beyanıdır; tarafımızdan doğrulanmış adres veya saldırgan kimliği değildir.
- Bir çizgi, aynı olayda bildirilen iki ucu bağlar; gerçek ağ rotası, paket ölçümü veya saldırı yönü değildir.
- Örnek modda 18 sentetik olayın 3'ünde koordinat vardır. Kalan 15 olay haritaya uydurma nokta olarak eklenmez.
- Harita bütün kayıtları toplamaz: son yüklenen, en fazla 100 olaylık Explorer sayfasını izler. Filtre veya sayfa değişince kapsam ve çizimler yenilenir.
- Aynı konumdaki kaynak ve hedefler birlikte gruplanır; sayı tekil olay sayısıdır. Karışık uçlar ayrı renkle gösterilir.
- Eğitim amaçlı coğrafi referanslar ayrı moddur; olay haritasına karıştırılmaz.
- Harita geometrisine ham log, API anahtarı veya IP özellikleri eklenmez; yalnızca koordinatlar ve yerel olay indeksleri kullanılır. Dış harita sağlayıcıları tile isteklerinden ziyaretçi IP'sini ve görüntülenen alanı görebilir.

## Görsel tercihlerin gerekçesi

Atmosfer ve kıyı çizgileri küreyi okunur kılar. Yerel Natural Earth tabanı dış tile servisleri olmasa da coğrafyayı gösterir. Dönüş kullanıcının yön bulmasına yardımcı olur; etkileşimde durur, görünmeyen sekmede/ekran dışında çalışmaz ve azaltılmış hareket tercihini izler. Kaynak, hedef ve karışık uç renkleri veri rolüdür; zararlı/temiz sınıflandırması değildir. Çizgiler saldırı simülasyonu olarak animasyonlandırılmaz.

## Araştırmadan uygulamaya

- [Elastic: network map data](https://www.elastic.co/docs/solutions/security/advanced-entity-analytics/configure-network-map-data): olay haritalamasının açık ECS konum alanlarına dayanması. Burada GeoIP servisi kopyalanmadı; yalnızca mevcut log koordinatları okunur.
- [Grafana: logs in Explore](https://grafana.com/docs/grafana/latest/visualizations/explore/logs-integration/): log ayrıntısı ve zaman bağlamına geçiş yaklaşımı. Burada mevcut olay API'siyle ±5 dakika ve varlık kısayolları eklendi; Loki/LogQL entegrasyonu iddia edilmez.
- [MapLibre: globe atmosphere](https://maplibre.org/maplibre-gl-js/docs/examples/display-a-globe-with-an-atmosphere/): atmosfer ayarı yerel 5.24.0 sürümünün desteklediği stil alanlarıyla uygulandı; kitaplık sürümü yükseltilmedi.
- [Natural Earth kullanım şartları](https://www.naturalearthdata.com/about/terms-of-use/): kamu malı düşük detaylı yerel taban, canlı uydu veya olay kanıtı değildir. [Veri kaynağı](./vendor/WORLD-DATA.md).

## Doğrulama

`node --test tests/geo.test.mjs` koordinat sınırları, eksik alanlar, uydurma GeoIP'nin önlenmesi, olay sayımı, veri mahremiyeti ve tarih değiştirme çizgisini kontrol eder.

`node tests/atlas-browser.mjs` yerel sunucuda konum kapsamını, noktadan kanıta geçişi, bağlam sorgusu/dışa aktarma filtrelerini, dil ve ekran genişliklerini ve WebGL kütüphanesi olmadan kanıt erişimini doğrular. Bu testler gerçek telefon/GPU ve bütün üretim ortamları için sıfır hata garantisi anlamına gelmez.
