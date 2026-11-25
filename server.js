require("dotenv").config();
const express=require("express"), helmet=require("helmet"), rateLimit=require("express-rate-limit");
const bcrypt=require("bcryptjs"), jwt=require("jsonwebtoken"), fs=require("fs"), path=require("path");
const app=express(), PORT=Number(process.env.PORT||3000), SECRET=process.env.JWT_SECRET;
if(!SECRET||SECRET.length<32){console.error("JWT_SECRET .env faylida kamida 32 belgidan iborat bo‘lsin.");process.exit(1);}
if(!process.env.ADMIN_PASSWORD||process.env.ADMIN_PASSWORD.length<12){console.error("ADMIN_PASSWORD kamida 12 belgidan iborat bo‘lsin.");process.exit(1);}
const dir=path.join(__dirname,"data"), file=path.join(dir,"topfilm.json"); fs.mkdirSync(dir,{recursive:true});
function save(){fs.writeFileSync(file,JSON.stringify(db,null,2),"utf8");}
let db;
if(fs.existsSync(file)){db=JSON.parse(fs.readFileSync(file,"utf8"));}
else{db={nextId:2,admins:[{id:1,username:process.env.ADMIN_USERNAME||"admin",password_hash:bcrypt.hashSync(process.env.ADMIN_PASSWORD,12)}],movies:[]};save();}
const uname=process.env.ADMIN_USERNAME||"admin";
if(!db.admins.some(a=>a.username===uname)){db.admins.push({id:db.nextId++,username:uname,password_hash:bcrypt.hashSync(process.env.ADMIN_PASSWORD,12)});save();}
app.use(helmet({contentSecurityPolicy:false})); app.use(express.json({limit:"1mb"}));
app.use("/api",rateLimit({windowMs:15*60*1000,limit:300})); app.use(express.static(path.join(__dirname,"public")));
function auth(req,res,next){try{req.admin=jwt.verify((req.headers.authorization||"").replace(/^Bearer\s+/i,""),SECRET);next();}catch{return res.status(401).json({error:"Avval admin sifatida tizimga kiring."});}}
function clean(b){const m={};for(const k of ["title","original_title","genre","language","description","poster","video_url","trailer_url"])m[k]=String(b[k]||"").trim().slice(0,k==="description"?4000:1000);m.year=b.year?Number(b.year):null;m.featured=b.featured?1:0;if(!m.title)throw Error("Kino nomi majburiy.");if(m.year&&(!Number.isInteger(m.year)||m.year<1888||m.year>2100))throw Error("Yil noto‘g‘ri.");for(const k of ["poster","video_url","trailer_url"])if(m[k]&&!/^https?:\/\//i.test(m[k]))throw Error(k+" faqat http/https URL bo‘lsin.");return m;}
app.get("/api/movies",(req,res)=>{const q=String(req.query.q||"").trim().toLowerCase(),g=String(req.query.genre||"").trim();res.json(db.movies.filter(m=>(!q||[m.title,m.original_title,m.description].some(x=>String(x||"").toLowerCase().includes(q)))&&(!g||m.genre===g)).sort((a,b)=>b.featured-a.featured||b.id-a.id));});
app.get("/api/movies/:id",(req,res)=>{const m=db.movies.find(x=>x.id===Number(req.params.id));if(!m)return res.status(404).json({error:"Kino topilmadi."});res.json(m);});
app.post("/api/admin/login",rateLimit({windowMs:900000,limit:10}),(req,res)=>{const a=db.admins.find(x=>x.username===String(req.body.username||""));if(!a||!bcrypt.compareSync(String(req.body.password||""),a.password_hash))return res.status(401).json({error:"Login yoki parol noto‘g‘ri."});res.json({token:jwt.sign({id:a.id,username:a.username},SECRET,{expiresIn:"8h"})});});
app.post("/api/admin/movies",auth,(req,res)=>{try{const m=clean(req.body);m.id=db.nextId++;m.created_at=new Date().toISOString();db.movies.push(m);save();res.status(201).json({id:m.id});}catch(e){res.status(400).json({error:e.message});}});
app.put("/api/admin/movies/:id",auth,(req,res)=>{try{const i=db.movies.findIndex(x=>x.id===Number(req.params.id));if(i<0)return res.status(404).json({error:"Kino topilmadi."});db.movies[i]={...db.movies[i],...clean(req.body)};save();res.json({ok:true});}catch(e){res.status(400).json({error:e.message});}});
app.delete("/api/admin/movies/:id",auth,(req,res)=>{const n=db.movies.length;db.movies=db.movies.filter(x=>x.id!==Number(req.params.id));if(n===db.movies.length)return res.status(404).json({error:"Kino topilmadi."});save();res.json({ok:true});});
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log("TopFilm.uz ishga tushdi: http://localhost:"+PORT));
