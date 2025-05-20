## Cyber Vuln Scanner

Cyber Vuln Scanner, Flask framework-unden istifade edilerek yazilmish, SQL Injection, XSS ve server versiyalarina esaslanan web tehlukesizlik analizlerini yerine yetiren sade bir web proqramidir. 
Bu proqram test meqsedi ile istifade olunur.

## Meqsed

Bu layihənin əsas meqsedi aşağidakilardir:

Web tehlukesizlik zeifliklerini (SQLi, XSS) test etmek üçün sadə bir arayuz yaratmaq;

Server başıiqlarından versiya məlumatlarini analiz ederek potensial CVE-lere esaslanan zeiflikleri gösterme;

Flask, requests ve BeautifulSoup kimi Python kitabxanalarini real senarilerde tetbiq etmek;

Kibertəhlükəsizlik sahəsində yeni başlayanlar üçün təcrübə imkanları yaratmaq.


## Istifade olunan texnologiyalar

Python 3

Flask – web serverin yaradılması və HTTP sorğuların qarşılanması üçün

Requests – HTTP sorğuların göndərilməsi üçün

BeautifulSoup – HTML parsing üçün

HTML/CSS – sadə veb interfeys


Xüsusiyyetler

SQL Injection testi – URL parametrlerinde SQLi payload-larin testi

XSS testi – Sayt daxilindeki formalar üzərindən XSS payload-lar ile test

Server versiya analizi – HTTP response header-larindan "Server" ve "X-Powered-By" kimi bashliqlari analiz ederek potensial zəiflikləri gösterme

Web interfeys – sade ve anlasilan form üzerinden URL daxil ederek analiz etmek


## Quraşdırma

## 1. Layihenin yuklenmesi

git clone https://github.com/adilov4337757/Cyber-vuln-scanner.git
cd cyber-vuln-scanner

## 2. Tələb olunan kitabxanaların quraşdırılması

pip install -r requirements.txt

requirements.txt faylı bu cür görünə bilər:

Flask
requests
beautifulsoup4

## 3. Tətbiqin işə salınması

python3 cyber_scan.py

Sonra brauzer vasitəsilə aşağıdakı linkə daxil olun:

http://127.0.0.1:5000

## İstifadə qaydası

1. Açılan səhifədə URL daxil et: məsələn, http://example.com


2. "Scan" düyməsinə bas


3. SQLi, XSS və Server Version nəticələri aşağıda göstəriləcək



Fayl Strukturu

cyber-vuln-scanner/
├── app.py              # Flask tətbiqinin əsas Python faylı
├── templates/
│   └── index.html      # Veb interfeys üçün HTML səhifəsi
├── static/             # Əgər CSS və JS faylları varsa
├── requirements.txt    # Lazımi Python paketləri
└── README.md           # Layihə haqqında sənəd (bu sənəd)

## Təhlükəsizlik xəbərdarlığı

Bu layihə yalnız təhsil məqsədi ilə nəzərdə tutulub. İcazəsiz sistem və ya domenlər üzərində test aparmaq qanuni məsuliyyətə səbəb ola bilər. Yalnız şəxsi və ya icazə verilmiş serverlərdə istifadə edin!

## Gələcək planlar

SSRF, LFI kimi digər zəiflik tiplərinin əlavə edilməsi

CVE məlumat bazası ilə real zamanlı əlaqə

JSON formatlı API-lərin təhlili

Daha inkişaf etmiş istifadəçi interfeysi


## Müəllif haqqında

Ad: Rac

Peşə: Kibertəhlükəsizlik üzrə mütəxxəssisi

Layihə məqsədi: Öz biliklərini inkişaf etdirmək və başqalarına faydalı olmaq


Bu layihə açıq mənbəlidir və istənilən təhsil məqsədilə sərbəst şəkildə istifadə edilə bilər.


---

Əgər bu layihəni təkmilləşdirmək istəyirsənsə və ya sualların varsa, mənə müraciət edə bilərsən.
