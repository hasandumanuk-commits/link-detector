# Link Detector

Link Detector, Kick chat üzerinden gelen linkleri yakalamak, veritabanına kaydetmek ve panelde görüntülemek için hazırlanan bir projedir.

## Şu an çalışan kısımlar

- Render deploy çalışıyor
- PostgreSQL bağlantısı çalışıyor
- Ana sayfa çalışıyor
- `/links` paneli çalışıyor
- `/links/json` çalışıyor
- `/links/raw/:id` ham veri görüntüleme çalışıyor
- Kayıt silme çalışıyor
- Arama çalışıyor
- Broadcaster user id bulma çalışıyor
- OAuth temel akışı çalışıyor

## Şu an çalışmayan kısım

Kick event subscription kısmı henüz çalışmıyor.

Şu endpoint deneniyor:

`POST /public/v1/events/subscriptions`

Denenen payload:

```json
{"broadcaster_user_id":93350154,"events":[{"name":"chat.message.sent","version":1}]}
