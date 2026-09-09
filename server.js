const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const db = new Database(path.join(ROOT, "data.sqlite"));
db.pragma("journal_mode = WAL");
fs.mkdirSync(path.join(ROOT, "uploads"), {recursive:true});

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'MEMBER',
 country TEXT DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 banned INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS materials(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 title TEXT NOT NULL,
 description TEXT DEFAULT '',
 category TEXT DEFAULT 'RESEARCH',
 author_id INTEGER NOT NULL,
 filename TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(author_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS comments(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 material_id INTEGER NOT NULL,
 user_id INTEGER NOT NULL,
 body TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(material_id) REFERENCES materials(id),
 FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

const bootstrapAdminUser = process.env.BOOTSTRAP_ADMIN_USER;
const bootstrapAdminPassword = process.env.BOOTSTRAP_ADMIN_PASSWORD;
if (bootstrapAdminUser && bootstrapAdminPassword) {
  const adminHash = bcrypt.hashSync(bootstrapAdminPassword, 10);
  db.prepare("INSERT OR IGNORE INTO users(username,password_hash,role,country) VALUES(?,?,'ADMIN','Global')").run(bootstrapAdminUser, adminHash);
}

app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:"1mb"}));
app.use(express.urlencoded({extended:true}));
app.use(session({
  secret: process.env.SESSION_SECRET || "change-this-secret-in-production",
  resave:false, saveUninitialized:false,
  cookie:{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:1000*60*60*8}
}));
app.use("/uploads", express.static(path.join(ROOT,"uploads")));
app.use(express.static(path.join(ROOT,"public")));

const upload = multer({
  storage: multer.diskStorage({
    destination:(req,file,cb)=>cb(null,path.join(ROOT,"uploads")),
    filename:(req,file,cb)=>{
      const safe = path.basename(file.originalname).replace(/[^a-zA-Z0-9._-]/g,"_");
      cb(null, `${Date.now()}_${safe}`);
    }
  }),
  limits:{fileSize:10*1024*1024}
});

function currentUser(req){
  if(!req.session.userId) return null;
  return db.prepare("SELECT id,username,role,country,banned FROM users WHERE id=?").get(req.session.userId);
}
function requireAuth(req,res,next){
  const u=currentUser(req);
  if(!u || u.banned) return res.status(401).json({error:"로그인이 필요합니다."});
  req.user=u; next();
}
function requireAdmin(req,res,next){
  const u=currentUser(req);
  if(!u || u.role!=="ADMIN") return res.status(403).json({error:"관리자 권한이 필요합니다."});
  req.user=u; next();
}

app.get("/api/me",(req,res)=>res.json({user:currentUser(req)}));
app.post("/api/register",(req,res)=>{
  const {username,password,country=""}=req.body;
  if(!username || !password || password.length<6) return res.status(400).json({error:"아이디와 6자 이상 비밀번호를 입력하세요."});
  if(!/^[A-Za-z0-9_가-힣]{2,24}$/.test(username)) return res.status(400).json({error:"아이디는 2~24자의 문자/숫자/밑줄을 사용하세요."});
  try{
    const hash=bcrypt.hashSync(password,10);
    const info=db.prepare("INSERT INTO users(username,password_hash,role,country) VALUES(?,?,'MEMBER',?)").run(username,hash,country);
    req.session.userId=info.lastInsertRowid;
    res.json({ok:true,user:currentUser(req)});
  }catch(e){res.status(409).json({error:"이미 사용 중인 아이디입니다."});}
});
app.post("/api/login",(req,res)=>{
  const u=db.prepare("SELECT * FROM users WHERE username=?").get(req.body.username||"");
  if(!u || u.banned || !bcrypt.compareSync(req.body.password||"",u.password_hash)) return res.status(401).json({error:"아이디 또는 비밀번호가 올바르지 않습니다."});
  req.session.userId=u.id;
  res.json({ok:true,user:currentUser(req)});
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/members",(req,res)=>res.json(db.prepare("SELECT id,username,role,country,created_at,banned FROM users ORDER BY role='ADMIN' DESC, id ASC").all()));
app.get("/api/materials",(req,res)=>{
  const q=(req.query.q||"").trim(), author=(req.query.author||"").trim();
  let sql=`SELECT m.id,m.title,m.description,m.category,m.filename,m.created_at,u.username AS author,u.id AS author_id FROM materials m JOIN users u ON u.id=m.author_id WHERE 1=1`;
  const params=[];
  if(q){sql+=" AND (m.title LIKE ? OR m.description LIKE ? OR m.category LIKE ? OR u.username LIKE ?)"; const x=`%${q}%`; params.push(x,x,x,x);}
  if(author){sql+=" AND u.username=?";params.push(author);}
  sql+=" ORDER BY m.id DESC";
  res.json(db.prepare(sql).all(...params));
});
app.post("/api/materials",requireAuth,upload.single("file"),(req,res)=>{
  const {title,description="",category="RESEARCH"}=req.body;
  if(!title) return res.status(400).json({error:"자료 제목을 입력하세요."});
  const info=db.prepare("INSERT INTO materials(title,description,category,author_id,filename) VALUES(?,?,?,?,?)").run(title,description,category.toUpperCase().slice(0,30),req.user.id,req.file?req.file.filename:null);
  res.json({ok:true,id:info.lastInsertRowid});
});
app.get("/api/materials/:id/comments",(req,res)=>res.json(db.prepare(`SELECT c.id,c.body,c.created_at,u.username AS author FROM comments c JOIN users u ON u.id=c.user_id WHERE c.material_id=? ORDER BY c.id ASC`).all(req.params.id)));
app.post("/api/materials/:id/comments",requireAuth,(req,res)=>{
  const body=(req.body.body||"").trim();
  if(!body) return res.status(400).json({error:"댓글 내용을 입력하세요."});
  db.prepare("INSERT INTO comments(material_id,user_id,body) VALUES(?,?,?)").run(req.params.id,req.user.id,body);
  res.json({ok:true});
});
app.get("/api/admin/stats",requireAdmin,(req,res)=>res.json({members:db.prepare("SELECT COUNT(*) n FROM users").get().n,materials:db.prepare("SELECT COUNT(*) n FROM materials").get().n,comments:db.prepare("SELECT COUNT(*) n FROM comments").get().n}));
app.patch("/api/admin/members/:id",requireAdmin,(req,res)=>{db.prepare("UPDATE users SET banned=? WHERE id=? AND role!='ADMIN'").run(req.body.banned?1:0,req.params.id);res.json({ok:true});});
app.delete("/api/admin/materials/:id",requireAdmin,(req,res)=>{const m=db.prepare("SELECT filename FROM materials WHERE id=?").get(req.params.id);if(m?.filename) try{fs.unlinkSync(path.join(ROOT,"uploads",m.filename));}catch{} db.prepare("DELETE FROM comments WHERE material_id=?").run(req.params.id);db.prepare("DELETE FROM materials WHERE id=?").run(req.params.id);res.json({ok:true});});

app.listen(PORT,"0.0.0.0",()=>console.log(`ILLUMINATI GLOBAL running on ${PORT}`));
