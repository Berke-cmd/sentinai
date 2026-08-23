# 🛡️ SentinAI - Asynchronous Web Security & CVE Intelligence Engine

*SentinAI*, modern web hedeflerinin güvenlik yapılandırmalarını asenkron olarak denetleyen, eksik HTTP güvenlik başlıklarını tespit eden ve tespit edilen servis sürümlerini CVE istihbarat veritabanlarıyla eşleştiren yeni nesil bir güvenlik motorudur.

---

## ⚡ Temel Yetenekler
- *Asenkron Mimari:* aiohttp ve asyncio ile yüksek hızlı ve engellemesiz (non-blocking) istek yönetimi.
- *Header & SSL Auditing:* HSTS, CSP, X-Frame-Options gibi kritik savunma mekanizmalarının ve SSL geçerliliğinin anlık denetimi.
- *CVE Intelligence:* Server ve teknoloji banner'ları üzerinden bilinen aktif CVE/CVSS skorlarını otomatik getirme.
- *Tip Güvenliği & Raporlama:* Pydantic tabanlı veri modelleme ve CLI/JSON formatında yapılandırılmış rapor çıktısı.

---

## 🚀 Kurulum

```bash
git clone [https://github.com/Berke-cmd/sentinai.git](https://github.com/Berke-cmd/sentinai.git)
cd sentinai
pip install -r requirements.txt
