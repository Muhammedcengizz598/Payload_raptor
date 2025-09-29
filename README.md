# 🦖 Payload Raptor

<div align="center">

![Version](https://img.shields.io/badge/version-3.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.7+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Termux-lightgrey.svg)

**Gelişmiş Web Güvenlik Açığı Tarayıcısı**

*Eğitim ve Test Amaçlı Güvenlik Değerlendirme Aracı*

[Özellikler](#-özellikler) • [Kurulum](#-kurulum) • [Kullanım](#-kullanım) • [Yasal Uyarı](#-yasal-uyarı)

</div>

---

## 📋 İçindekiler

- [Hakkında](#-hakkında)
- [Özellikler](#-özellikler)
- [Sistem Gereksinimleri](#-sistem-gereksinimleri)
- [Kurulum](#-kurulum)
  - [Linux Kurulumu](#linux-kurulumu)
  - [Termux Kurulumu](#termux-kurulumu)
- [Kullanım](#-kullanım)
- [Desteklenen Zafiyet Türleri](#-desteklenen-zafiyet-türleri)
- [Yasal Uyarı](#-yasal-uyarı)
- [Katkıda Bulunma](#-katkıda-bulunma)
- [Lisans](#-lisans)
- [İletişim](#-i̇letişim)

---

## 🛡️ Hakkında

**Payload Raptor**, web uygulamalarında güvenlik açıklarını tespit etmek için geliştirilmiş kapsamlı bir güvenlik tarama aracıdır. Bu araç, penetrasyon testleri ve güvenlik değerlendirmeleri için tasarlanmış olup, **sadece eğitim ve test amaçlı** kullanılmalıdır.

### 👨‍💻 Geliştirici

**Muhammed Cengiz**
- GitHub: [@Muhammedcengizz598](https://github.com/Muhammedcengizz598/)
- Versiyon: 3.0.0
- Lisans: MIT

---

## ✨ Özellikler

- 🔍 **Kapsamlı Zafiyet Taraması**: 19 farklı güvenlik açığı türünü tespit eder
- 🚀 **Otomatik Kütüphane Yönetimi**: Eksik bağımlılıkları otomatik olarak yükler
- 🎯 **Akıllı Payload Sistemi**: 300+ özelleştirilmiş saldırı yükü
- 📊 **Detaylı Raporlama**: Şiddet seviyesi ve güven skorları ile sonuçlar
- ⚡ **Çoklu Thread Desteği**: Hızlı ve verimli tarama
- 🔐 **Güvenli Kullanım**: Timeout ve rate limiting özellikleri
- 📝 **Kapsamlı Loglama**: Tüm işlemler detaylı olarak kaydedilir
- 🎨 **Renkli Terminal Çıktısı**: Kullanıcı dostu arayüz

---

## 💻 Sistem Gereksinimleri

### Minimum Gereksinimler

- **İşletim Sistemi**: Linux (Ubuntu, Debian, Kali, Parrot) veya Termux (Android)
- **Python Versiyonu**: Python 3.7 veya üzeri
- **RAM**: En az 512 MB
- **Disk Alanı**: 100 MB boş alan
- **İnternet Bağlantısı**: Kütüphane kurulumu için gerekli

### Desteklenen Platformlar

- ✅ Linux (Ubuntu, Debian, Kali Linux, Parrot OS)
- ✅ Termux (Android)
- ✅ WSL (Windows Subsystem for Linux)

---

## 🚀 Kurulum

### Linux Kurulumu

#### 1. Depoyu Klonlayın

```bash
git clone https://github.com/Muhammedcengizz598/Payload_raptor.git
cd Payload_raptor
```

#### 2. Python ve pip'in Yüklü Olduğundan Emin Olun

```bash
# Python versiyonunu kontrol edin
python3 --version

# pip kurulumu (gerekirse)
sudo apt update
sudo apt install python3-pip -y
```

#### 3. Gerekli Kütüphaneleri Yükleyin

```bash
# Otomatik kurulum (önerilen)
python3 Payload_raptor.py

# Manuel kurulum
pip3 install -r requirements.txt
```

#### 4. Çalıştırma İzni Verin

```bash
chmod +x Payload_raptor.py
```

---

### Termux Kurulumu

#### 1. Termux'u Güncelleyin

```bash
pkg update && pkg upgrade -y
```

#### 2. Python ve Git Yükleyin

```bash
pkg install python git -y
```

#### 3. Depoyu Klonlayın

```bash
git clone https://github.com/Muhammedcengizz598/Payload_raptor.git
cd Payload_raptor
```

#### 4. Gerekli Kütüphaneleri Yükleyin

```bash
# Otomatik kurulum (önerilen)
python Payload_raptor.py

# Manuel kurulum
pip install -r requirements.txt
```

---

## 📖 Kullanım

### Temel Kullanım

```bash
# Linux
python3 Payload_raptor.py

# Termux
python Payload_raptor.py
```

### İlk Çalıştırma

Program ilk çalıştırıldığında:
1. Gerekli kütüphaneleri otomatik olarak kontrol eder
2. Eksik kütüphaneler varsa yükleme için onay ister
3. Tüm bağımlılıklar yüklendikten sonra kullanıma hazır hale gelir

### Örnek Kullanım Senaryoları

```bash
# Kütüphane kontrolü ve kurulumu
python3 Payload_raptor.py

# Program başarıyla başlatıldıktan sonra
# hedef URL ve parametreleri belirterek tarama yapabilirsiniz
```

---

## 🎯 Desteklenen Zafiyet Türleri

Payload Raptor aşağıdaki güvenlik açıklarını tespit edebilir:

| Zafiyet Türü | Açıklama | Şiddet |
|--------------|----------|--------|
| **XSS** | Cross-Site Scripting | Yüksek |
| **SQL Injection** | SQL Enjeksiyon Saldırıları | Kritik |
| **Command Injection** | Komut Enjeksiyonu | Kritik |
| **LFI** | Local File Inclusion | Yüksek |
| **RFI** | Remote File Inclusion | Kritik |
| **XXE** | XML External Entity | Yüksek |
| **SSTI** | Server-Side Template Injection | Kritik |
| **LDAP Injection** | LDAP Enjeksiyonu | Orta |
| **XPath Injection** | XPath Enjeksiyonu | Orta |
| **NoSQL Injection** | NoSQL Enjeksiyonu | Yüksek |
| **SSRF** | Server-Side Request Forgery | Yüksek |
| **IDOR** | Insecure Direct Object Reference | Orta |
| **CSRF** | Cross-Site Request Forgery | Orta |
| **Open Redirect** | Açık Yönlendirme | Düşük |
| **Clickjacking** | Tıklama Hırsızlığı | Düşük |
| **File Upload** | Güvensiz Dosya Yükleme | Yüksek |
| **Auth Bypass** | Kimlik Doğrulama Atlama | Kritik |
| **Misconfiguration** | Güvenlik Yanlış Yapılandırması | Orta |
| **Info Disclosure** | Bilgi İfşası | Düşük |

---

## ⚠️ YASAL UYARI

### 🚨 ÖNEMLİ UYARI

Bu araç **SADECE** aşağıdaki amaçlar için geliştirilmiştir:

- ✅ Eğitim ve öğrenme amaçlı kullanım
- ✅ Yetkili penetrasyon testleri
- ✅ Kendi sistemlerinizde güvenlik değerlendirmesi
- ✅ Yasal izin alınmış güvenlik denetimleri

### ❌ YASAK KULLANIM

- ❌ İzinsiz sistemlere saldırı
- ❌ Yetkisiz erişim denemeleri
- ❌ Kötü niyetli aktiviteler
- ❌ Yasadışı penetrasyon testleri

### 📜 Sorumluluk Reddi

- Bu aracın kullanımından doğacak **tüm sorumluluk kullanıcıya aittir**
- Geliştiriciler, aracın **yanlış veya kötüye kullanımından sorumlu tutulamaz**
- Kullanıcılar, test ettikleri sistemler için **uygun yasal izinlere sahip olmalıdır**
- Bu araç **sadece etik hacking ve eğitim amaçlıdır**

### ⚖️ Yasal Uyum

Kullanıcılar, bu aracı kullanırken:
- Yerel ve uluslararası yasalara uymalıdır
- Hedef sistemin sahibinden yazılı izin almalıdır
- Etik hacking prensiplerine uygun hareket etmelidir
- Sorumlu açıklama (responsible disclosure) politikalarına uymalıdır

**Unutmayın**: Yetkisiz erişim ve siber saldırılar ciddi yasal sonuçlar doğurabilir!

---

## 🤝 Katkıda Bulunma

Katkılarınızı bekliyoruz! Projeye katkıda bulunmak için:

1. Bu depoyu fork edin
2. Yeni bir branch oluşturun (`git checkout -b feature/YeniOzellik`)
3. Değişikliklerinizi commit edin (`git commit -m 'Yeni özellik eklendi'`)
4. Branch'inizi push edin (`git push origin feature/YeniOzellik`)
5. Pull Request oluşturun

### Katkı Kuralları

- Kod standartlarına uyun
- Değişikliklerinizi detaylı açıklayın
- Test edilmiş kod gönderin
- Dokümantasyonu güncelleyin

---

## 📄 Lisans

Bu proje MIT Lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

```
MIT License

Copyright (c) 2024 Muhammed Cengiz

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 📞 İletişim

### Geliştirici İletişim

- **GitHub**: [@Muhammedcengizz598](https://github.com/Muhammedcengizz598/)
- **Proje Deposu**: [Payload Raptor](https://github.com/Muhammedcengizz598/Payload_raptor)

### Destek ve Geri Bildirim

- 🐛 **Bug Bildirimi**: [Issues](https://github.com/Muhammedcengizz598/Payload_raptor/issues) sayfasını kullanın
- 💡 **Özellik İsteği**: [Issues](https://github.com/Muhammedcengizz598/Payload_raptor/issues) sayfasından öneride bulunun
- 📧 **Genel Sorular**: GitHub üzerinden iletişime geçin

---

## 🌟 Teşekkürler

Bu projeyi kullandığınız için teşekkür ederiz! Güvenli ve etik hacking yapın! 🛡️

### ⭐ Projeyi Beğendiniz mi?

Projeyi faydalı bulduysanız, lütfen GitHub'da ⭐ vererek destek olun!

---

<div align="center">

**Made with ❤️ by Muhammed Cengiz**

*Etik Hacking | Güvenlik Araştırması | Eğitim*

[⬆ Başa Dön](#-payload-raptor)

</div>
