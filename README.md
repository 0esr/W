# AppHub
منصة تطبيقات Android/iOS تعمل محلياً بـ Node.js + Express + JSON database.

## التشغيل
1. ثبّت Node.js 18+.
2. افتح المجلد في Terminal.
3. نفّذ:
   npm install
   npm start
4. افتح http://localhost:3000

## أول حساب Admin
لأمان المشروع لا يتم إنشاء Admin من التسجيل العام. بعد إنشاء أول حساب، افتح data/db.json وابحث عن المستخدم وغيّر role من user إلى admin، ثم سجّل الدخول من جديد.

## ملاحظات
- قاعدة البيانات التجريبية في data/db.json.
- ملفات APK والصور في data/uploads.
- للإنتاج الحقيقي استبدل JSON بقاعدة PostgreSQL/MongoDB واستخدم JWT_SECRET عشوائياً من متغيرات البيئة، وتخزين ملفات خارجياً (S3/Cloudinary ونحوها)، وHTTPS.
- iOS يدعم روابط App Store؛ لا يمكن للموقع تجاوز نظام Apple أو توزيع IPA غير المصرح به.
- المكتبات الخارجية عبر CDN: Font Awesome، Google Fonts، SweetAlert2.
