require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const PDFDocument = require('pdfkit');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new sqlite3.Database(path.join(dataDir, 'students.sqlite'));
db.serialize(() => {
  db.run('PRAGMA foreign_keys = ON');
  db.run(`CREATE TABLE IF NOT EXISTS students (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, grade TEXT NOT NULL,
    parent_email TEXT NOT NULL, access_code_hash TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL,
    kind TEXT NOT NULL, section TEXT DEFAULT '', subject TEXT DEFAULT '',
    title TEXT NOT NULL, detail TEXT DEFAULT '', score TEXT DEFAULT '',
    entry_date TEXT DEFAULT CURRENT_DATE, FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL,
    comment TEXT DEFAULT '', updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE
  )`);
});
const run = (sql, params=[]) => new Promise((resolve,reject)=>db.run(sql,params,function(e){e?reject(e):resolve({id:this.lastID,changes:this.changes})}));
const get = (sql, params=[]) => new Promise((resolve,reject)=>db.get(sql,params,(e,r)=>e?reject(e):resolve(r)));
const all = (sql, params=[]) => new Promise((resolve,reject)=>db.all(sql,params,(e,r)=>e?reject(e):resolve(r)));

app.set('view engine','ejs');
app.set('views',path.join(__dirname,'views'));
app.use(express.urlencoded({extended:true}));
app.use(express.static(path.join(__dirname,'public')));
app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: dataDir }),
  secret: process.env.SESSION_SECRET || 'dev-only-change-this-session-secret',
  resave:false, saveUninitialized:false,
  cookie:{ httpOnly:true, sameSite:'lax', secure:process.env.NODE_ENV==='production', maxAge:8*60*60*1000 }
}));
app.use(passport.initialize());
app.use(passport.session());
passport.serializeUser((user,done)=>done(null,user));
passport.deserializeUser((user,done)=>done(null,user));
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
    clientID:process.env.GOOGLE_CLIENT_ID,
    clientSecret:process.env.GOOGLE_CLIENT_SECRET,
    callbackURL:process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback'
  },(accessToken,refreshToken,profile,done)=>{
    const email=(profile.emails && profile.emails[0] && profile.emails[0].value || '').toLowerCase();
    if (!email) return done(null,false);
    return done(null,{role:'parent',email,name:profile.displayName||email});
  }));
}
function teacherOnly(req,res,next){ if(req.user?.role==='teacher') return next(); return res.redirect('/teacher/login'); }
function parentOnly(req,res,next){ if(req.user?.role==='parent') return next(); return res.redirect('/parent/login'); }
function safeText(v,max=4000){return String(v||'').trim().slice(0,max);}
app.get('/',(req,res)=>res.render('home',{user:req.user}));
app.get('/teacher/login',(req,res)=>res.render('teacher-login',{error:''}));
app.post('/teacher/login',(req,res)=>{
  const u=process.env.TEACHER_USERNAME||'fatihhoca', p=process.env.TEACHER_PASSWORD||'fatih45';
  if(req.body.username===u && req.body.password===p){req.session.regenerate(err=>{if(err)return res.status(500).send('Oturum oluşturulamadı');req.login({role:'teacher',name:'Fatih Hoca'},e=>e?res.status(500).send('Giriş hatası'):res.redirect('/teacher'));});}
  else res.status(401).render('teacher-login',{error:'Kullanıcı adı veya şifre hatalı.'});
});
app.post('/logout',(req,res)=>req.logout(()=>req.session.destroy(()=>res.redirect('/'))));

app.get('/teacher',teacherOnly,async(req,res)=>{
  const students=await all(`SELECT s.*, (SELECT COUNT(*) FROM entries e WHERE e.student_id=s.id) AS entry_count
    FROM students s ORDER BY s.name COLLATE NOCASE`);
  res.render('teacher-dashboard',{students});
});
app.get('/teacher/students/new',teacherOnly,(req,res)=>res.render('student-form',{student:null,error:''}));
app.post('/teacher/students',teacherOnly,async(req,res)=>{
  const name=safeText(req.body.name,120), grade=safeText(req.body.grade,20);
  const email=safeText(req.body.parent_email,254).toLowerCase(), code=safeText(req.body.access_code,100);
  if(!name||!grade||!email||!code) return res.status(400).render('student-form',{student:null,error:'Tüm alanları doldurun.'});
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).render('student-form',{student:null,error:'Geçerli bir veli Google e-posta adresi girin.'});
  const result=await run('INSERT INTO students(name,grade,parent_email,access_code_hash) VALUES(?,?,?,?)',[name,grade,email,bcrypt.hashSync(code,12)]);
  await run('INSERT INTO reports(student_id,comment) VALUES(?,?)',[result.id,'']);
  res.redirect('/teacher/students/'+result.id);
});
app.get('/teacher/students/:id',teacherOnly,async(req,res)=>{
  const student=await get('SELECT * FROM students WHERE id=?',[req.params.id]);
  if(!student)return res.status(404).send('Öğrenci bulunamadı.');
  const entries=await all('SELECT * FROM entries WHERE student_id=? ORDER BY entry_date DESC,id DESC',[student.id]);
  const report=await get('SELECT * FROM reports WHERE student_id=?',[student.id]);
  res.render('student-detail',{student,entries,report:report||{comment:''},error:'',query:req.query});
});
app.post('/teacher/students/:id/entries',teacherOnly,async(req,res)=>{
  const student=await get('SELECT id FROM students WHERE id=?',[req.params.id]); if(!student)return res.status(404).send('Öğrenci bulunamadı.');
  const kind=safeText(req.body.kind,30), title=safeText(req.body.title,200);
  if(!title)return res.status(400).send('Başlık/konu zorunludur.');
  await run(`INSERT INTO entries(student_id,kind,section,subject,title,detail,score,entry_date) VALUES(?,?,?,?,?,?,?,?)`,
    [student.id,kind,safeText(req.body.section,10),safeText(req.body.subject,100),title,safeText(req.body.detail,2000),safeText(req.body.score,100),safeText(req.body.entry_date,10)||new Date().toISOString().slice(0,10)]);
  res.redirect('/teacher/students/'+student.id);
});
app.post('/teacher/entries/:id/delete',teacherOnly,async(req,res)=>{
  const e=await get('SELECT student_id FROM entries WHERE id=?',[req.params.id]);
  if(e){await run('DELETE FROM entries WHERE id=?',[req.params.id]);return res.redirect('/teacher/students/'+e.student_id);}
  res.redirect('/teacher');
});
app.post('/teacher/students/:id/report',teacherOnly,async(req,res)=>{
  const student=await get('SELECT id FROM students WHERE id=?',[req.params.id]); if(!student)return res.status(404).send('Öğrenci bulunamadı.');
  const comment=safeText(req.body.comment,6000);
  await run(`INSERT INTO reports(student_id,comment,updated_at) VALUES(?,?,CURRENT_TIMESTAMP)
    ON CONFLICT(student_id) DO UPDATE SET comment=excluded.comment,updated_at=CURRENT_TIMESTAMP`,[student.id,comment]);
  // SQLite table's report row is initialized when the student is created.
  res.redirect('/teacher/students/'+student.id+'?saved=1');
});
app.get('/teacher/students/:id/pdf',teacherOnly,async(req,res)=>{
  const student=await get('SELECT * FROM students WHERE id=?',[req.params.id]); if(!student)return res.status(404).send('Öğrenci bulunamadı.');
  const entries=await all('SELECT * FROM entries WHERE student_id=? ORDER BY entry_date DESC,id DESC',[student.id]);
  const report=await get('SELECT * FROM reports WHERE student_id=?',[student.id]);
  res.setHeader('Content-Type','application/pdf');
  res.setHeader('Content-Disposition',`attachment; filename="ogrenci-raporu-${student.id}.pdf"`);
  const doc=new PDFDocument({size:'A4',margin:48,bufferPages:true});
  doc.pipe(res);
  // Built-in fonts may not render Turkish characters; use a local TTF if provided.
  const fontPath=path.join(__dirname,'public','fonts','DejaVuSans.ttf');
  const boldPath=path.join(__dirname,'public','fonts','DejaVuSans-Bold.ttf');
  if(fs.existsSync(fontPath)){doc.registerFont('TR',fontPath);doc.registerFont('TR-Bold',fs.existsSync(boldPath)?boldPath:fontPath);doc.font('TR');}
  doc.fontSize(20).text('Öğrenci Gelişim Raporu',{align:'center'}).moveDown();
  doc.fontSize(11).text(`Öğrenci: ${student.name}`).text(`Sınıf düzeyi: ${student.grade}`).text(`Rapor tarihi: ${new Date().toLocaleDateString('tr-TR')}`).moveDown();
  doc.fontSize(14).text('Ders, konu ve deneme takibi').moveDown(0.4);
  if(!entries.length)doc.fontSize(10).text('Henüz kayıt eklenmemiş.').moveDown();
  for(const e of entries){
    if(doc.y>720)doc.addPage();
    doc.fontSize(11).text(`${e.entry_date} | ${e.kind}${e.section?' / '+e.section:''}${e.subject?' | '+e.subject:''}`,{continued:false});
    doc.fontSize(10).text(`Konu/Başlık: ${e.title}`);
    if(e.score)doc.text(`Sonuç: ${e.score}`);
    if(e.detail)doc.text(`Not: ${e.detail}`);
    doc.moveDown(0.5);
  }
  doc.moveDown().fontSize(14).text('Öğretmen yorumu').moveDown(0.4).fontSize(10).text(report?.comment||'Henüz öğretmen yorumu eklenmemiş.',{lineGap:3});
  doc.end();
});
app.get('/parent/login',(req,res)=>res.render('parent-login',{error:req.query.error||''}));
app.get('/auth/google', (req,res,next)=>{
  if(!process.env.GOOGLE_CLIENT_ID||!process.env.GOOGLE_CLIENT_SECRET)return res.status(503).render('parent-login',{error:'Google girişi henüz ayarlanmadı. README.md dosyasındaki Google OAuth kurulumunu tamamlayın.'});
  passport.authenticate('google',{scope:['profile','email'],prompt:'select_account'})(req,res,next);
});
app.get('/auth/google/callback',passport.authenticate('google',{failureRedirect:'/parent/login?error=Google%20girişi%20başarısız',successRedirect:'/parent/child'}));
app.get('/parent/child',parentOnly,(req,res)=>res.render('parent-child',{error:'',userEmail:req.user.email}));
app.post('/parent/child',parentOnly,async(req,res)=>{
  const name=safeText(req.body.child_name,120), code=safeText(req.body.access_code,100);
  if(!name||!code)return res.status(400).render('parent-child',{error:'Çocuk adı ve öğretmenin verdiği erişim kodu gereklidir.'});
  const student=await get('SELECT * FROM students WHERE name=? COLLATE NOCASE AND parent_email=?',[name,req.user.email.toLowerCase()]);
  if(!student||!bcrypt.compareSync(code,student.access_code_hash))return res.status(403).render('parent-child',{error:'Bilgiler eşleşmedi. Öğretmeninizle iletişime geçin.'});
  req.session.childId=student.id;res.redirect('/parent/report');
});
app.get('/parent/report',parentOnly,async(req,res)=>{
  if(!req.session.childId)return res.redirect('/parent/child');
  const student=await get('SELECT * FROM students WHERE id=? AND parent_email=?',[req.session.childId,req.user.email.toLowerCase()]);
  if(!student){req.session.childId=null;return res.status(403).send('Bu öğrenci için erişim yetkiniz yok.');}
  const entries=await all('SELECT * FROM entries WHERE student_id=? ORDER BY entry_date DESC,id DESC',[student.id]);
  const report=await get('SELECT * FROM reports WHERE student_id=?',[student.id]);
  res.render('parent-report',{student,entries,report:report||{comment:''}});
});
app.use((err,req,res,next)=>{console.error(err);res.status(500).send('Beklenmeyen bir hata oluştu. Sunucu kayıtlarını kontrol edin.');});
app.listen(PORT,()=>console.log(`Uygulama hazır: http://localhost:${PORT}`));
