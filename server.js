const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'your_jwt_secret_key_change_me';

// إعداد قاعدة البيانات
const db = new Database('app_data.db');
db.pragma('journal_mode = WAL');

// إنشاء الجداول إذا لم تكن موجودة
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fullName TEXT NOT NULL,
    phone TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    dob TEXT,
    state TEXT,
    profilePicture TEXT DEFAULT '',
    backgroundColor TEXT DEFAULT '#f0f4f8'
  );

  CREATE TABLE IF NOT EXISTS social_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER NOT NULL,
    platformKey TEXT NOT NULL,
    url TEXT NOT NULL,
    FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(userId, platformKey)
  );

  CREATE TABLE IF NOT EXISTS bank_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER NOT NULL,
    bankName TEXT NOT NULL,
    branch TEXT NOT NULL,
    accountNumber TEXT NOT NULL,
    notificationNumber TEXT NOT NULL,
    FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// إعداد Express
app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// دوال مساعدة
function generateToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '30d' });
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'يرجى تسجيل الدخول' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'الجلسة منتهية' });
    req.userId = decoded.userId;
    next();
  });
}

// ==================== مسارات المستخدمين ====================

// تسجيل جديد
app.post('/api/register', (req, res) => {
  const { fullName, phone, email, password, dob, state } = req.body;
  if (!fullName || !phone || !email || !password || !dob || !state) {
    return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
  }
  if (password.length < 4) {
    return res.status(400).json({ error: 'كلمة السر يجب أن تكون 4 أحرف على الأقل' });
  }

  try {
    const hashedPassword = bcrypt.hashSync(password, 10);
    const stmt = db.prepare('INSERT INTO users (fullName, phone, email, password, dob, state) VALUES (?, ?, ?, ?, ?, ?)');
    const result = stmt.run(fullName, phone, email, hashedPassword, dob, state);
    const token = generateToken(result.lastInsertRowid);
    res.json({ token });
  } catch (err) {
    if (err.message.includes('UNIQUE constraint failed')) {
      return res.status(409).json({ error: 'البريد الإلكتروني مسجل مسبقاً' });
    }
    console.error(err);
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

// تسجيل الدخول
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'البريد وكلمة السر مطلوبان' });
  }

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) {
    return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
  }

  const valid = bcrypt.compareSync(password, user.password);
  if (!valid) {
    return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
  }

  const token = generateToken(user.id);
  res.json({ token });
});

// نسيت كلمة السر
app.post('/api/forgot-password', (req, res) => {
  const { email, phone, newPassword } = req.body;
  if (!email || !phone || !newPassword) {
    return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
  }
  if (newPassword.length < 4) {
    return res.status(400).json({ error: 'كلمة السر الجديدة قصيرة' });
  }

  const user = db.prepare('SELECT * FROM users WHERE email = ? AND phone = ?').get(email, phone);
  if (!user) {
    return res.status(404).json({ error: 'لم يتم العثور على حساب بهذا البريد والهاتف' });
  }

  const hashed = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashed, user.id);
  res.json({ message: 'تم تحديث كلمة السر بنجاح' });
});

// جلب بيانات المستخدم (للشاشة الرئيسية)
app.get('/api/me', authenticateToken, (req, res) => {
  const user = db.prepare('SELECT id, fullName, phone, email, dob, state, profilePicture, backgroundColor FROM users WHERE id = ?').get(req.userId);
  if (!user) {
    return res.status(404).json({ error: 'المستخدم غير موجود' });
  }

  const socialLinks = db.prepare('SELECT platformKey, url FROM social_links WHERE userId = ?').all(req.userId);
  const bankAccounts = db.prepare('SELECT id, bankName, branch, accountNumber, notificationNumber FROM bank_accounts WHERE userId = ?').all(req.userId);

  res.json({
    ...user,
    socialLinks: socialLinks.reduce((acc, link) => {
      acc[link.platformKey] = link.url;
      return acc;
    }, {}),
    bankAccounts
  });
});

// تغيير كلمة السر
app.put('/api/profile/password', authenticateToken, (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) {
    return res.status(400).json({ error: 'كلمة السر القديمة والجديدة مطلوبة' });
  }
  if (newPassword.length < 4) {
    return res.status(400).json({ error: 'كلمة السر الجديدة قصيرة' });
  }

  const user = db.prepare('SELECT password FROM users WHERE id = ?').get(req.userId);
  if (!bcrypt.compareSync(oldPassword, user.password)) {
    return res.status(400).json({ error: 'كلمة السر القديمة غير صحيحة' });
  }

  const hashed = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashed, req.userId);
  res.json({ message: 'تم تغيير كلمة السر' });
});

// تغيير لون الخلفية
app.put('/api/profile/background', authenticateToken, (req, res) => {
  const { backgroundColor } = req.body;
  if (!backgroundColor) return res.status(400).json({ error: 'اللون مطلوب' });
  db.prepare('UPDATE users SET backgroundColor = ? WHERE id = ?').run(backgroundColor, req.userId);
  res.json({ backgroundColor });
});

// تحديث صورة الملف الشخصي
app.put('/api/profile/picture', authenticateToken, (req, res) => {
  const { profilePicture } = req.body; // base64
  db.prepare('UPDATE users SET profilePicture = ? WHERE id = ?').run(profilePicture || '', req.userId);
  res.json({ profilePicture: profilePicture || '' });
});

// حذف صورة الملف
app.delete('/api/profile/picture', authenticateToken, (req, res) => {
  db.prepare('UPDATE users SET profilePicture = ? WHERE id = ?').run('', req.userId);
  res.json({ message: 'تمت إزالة الصورة' });
});

// ==================== روابط التواصل الاجتماعي ====================

// حفظ أو تحديث رابط لمنصة
app.put('/api/social-links/:platformKey', authenticateToken, (req, res) => {
  const platformKey = req.params.platformKey;
  const { url } = req.body;

  if (!url || !url.trim()) {
    // إذا كان الرابط فارغاً نحذف الرابط
    db.prepare('DELETE FROM social_links WHERE userId = ? AND platformKey = ?').run(req.userId, platformKey);
    return res.json({ message: 'تم حذف الرابط' });
  }

  // إدراج أو تحديث
  const existing = db.prepare('SELECT id FROM social_links WHERE userId = ? AND platformKey = ?').get(req.userId, platformKey);
  if (existing) {
    db.prepare('UPDATE social_links SET url = ? WHERE id = ?').run(url, existing.id);
  } else {
    db.prepare('INSERT INTO social_links (userId, platformKey, url) VALUES (?, ?, ?)').run(req.userId, platformKey, url);
  }

  res.json({ platformKey, url });
});

// حذف رابط (يمكن استخدام نفس النقطة مع URL فارغ، لكن نضيف للحذف الصريح)
app.delete('/api/social-links/:platformKey', authenticateToken, (req, res) => {
  const platformKey = req.params.platformKey;
  db.prepare('DELETE FROM social_links WHERE userId = ? AND platformKey = ?').run(req.userId, platformKey);
  res.json({ message: 'تم حذف الرابط' });
});

// ==================== الحسابات البنكية ====================

// إضافة حساب جديد
app.post('/api/bank-accounts', authenticateToken, (req, res) => {
  const { bankName, branch, accountNumber, notificationNumber } = req.body;
  if (!bankName || !branch || !accountNumber || !notificationNumber) {
    return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
  }

  const result = db.prepare('INSERT INTO bank_accounts (userId, bankName, branch, accountNumber, notificationNumber) VALUES (?, ?, ?, ?, ?)')
    .run(req.userId, bankName, branch, accountNumber, notificationNumber);

  const newAccount = db.prepare('SELECT * FROM bank_accounts WHERE id = ?').get(result.lastInsertRowid);
  res.status(201).json(newAccount);
});

// تعديل حساب
app.put('/api/bank-accounts/:id', authenticateToken, (req, res) => {
  const accountId = parseInt(req.params.id);
  const { bankName, branch, accountNumber, notificationNumber } = req.body;

  // التحقق من ملكية المستخدم
  const account = db.prepare('SELECT * FROM bank_accounts WHERE id = ? AND userId = ?').get(accountId, req.userId);
  if (!account) return res.status(404).json({ error: 'الحساب غير موجود' });

  db.prepare('UPDATE bank_accounts SET bankName=?, branch=?, accountNumber=?, notificationNumber=? WHERE id=?')
    .run(bankName, branch, accountNumber, notificationNumber, accountId);

  const updated = db.prepare('SELECT * FROM bank_accounts WHERE id = ?').get(accountId);
  res.json(updated);
});

// حذف حساب
app.delete('/api/bank-accounts/:id', authenticateToken, (req, res) => {
  const accountId = parseInt(req.params.id);
  const account = db.prepare('SELECT * FROM bank_accounts WHERE id = ? AND userId = ?').get(accountId, req.userId);
  if (!account) return res.status(404).json({ error: 'الحساب غير موجود' });

  db.prepare('DELETE FROM bank_accounts WHERE id = ?').run(accountId);
  res.json({ message: 'تم حذف الحساب' });
});

// تشغيل السيرفر
app.listen(PORT, () => {
  console.log(`الخادم يعمل على http://localhost:${PORT}`);
});