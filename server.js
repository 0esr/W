const express=require("express");
const fs=require("fs"),path=require("path"),crypto=require("crypto");
const bcrypt=require("bcryptjs"),jwt=require("jsonwebtoken"),multer=require("multer");
const helmet=require("helmet"),rateLimit=require("express-rate-limit"),cors=require("cors");
const app=express(),PORT=process.env.PORT||3000;
const DATA=path.join(__dirname,"data"), DB=path.join(DATA,"db.json"), UP=path.join(DATA,"uploads");
fs.mkdirSync(UP,{recursive:true});
const SECRET=process.env.JWT_SECRET||"change-this-secret-in-production";
if(!fs.existsSync(DB)) fs.writeFileSync(DB,JSON.stringify({users:[],apps:[],reviews:[],favorites:[],notifications:[],logs:[]},null,2));
const read=()=>JSON.parse(fs.readFileSync(DB,"utf8")), write=d=>fs.writeFileSync(DB,JSON.stringify(d,null,2));
const id=()=>crypto.randomBytes(12).toString("hex");
const now=()=>new Date().toISOString();
app.use(helmet({crossOriginResourcePolicy:false}));
app.use(cors());
app.use(express.json({limit:"2mb"})); app.use(express.urlencoded({extended:true}));
app.use("/uploads",express.static(UP)); app.use(express.static(path.join(__dirname,"public")));
app.use("/api/",rateLimit({windowMs:15*60*1000,max:300,standardHeaders:true,legacyHeaders:false}));

const auth=(req,res,next)=>{try{const h=req.headers.authorization||"";if(!h.startsWith("Bearer "))return res.status(401).json({error:"تسجيل الدخول مطلوب"});req.user=jwt.verify(h.slice(7),SECRET);next()}catch(e){res.status(401).json({error:"جلسة غير صالحة"})}};
const role=(...roles)=>(req,res,next)=>roles.includes(req.user.role)?next():res.status(403).json({error:"لا تملك الصلاحية"});
const safe=u=>({id:u.id,username:u.username,name:u.name,email:u.email,role:u.role,avatar:u.avatar||"",createdAt:u.createdAt,banned:!!u.banned});
const log=(d,uid,action,meta={})=>{d.logs.push({id:id(),uid,action,meta,at:now()})};

const upload=multer({storage:multer.diskStorage({destination:UP,filename:(r,f)=>id()+path.extname(f.originalname).toLowerCase()}),limits:{fileSize:200*1024*1024},fileFilter:(r,f,cb)=>{
 const ok=[".png",".jpg",".jpeg",".webp",".apk",".aab"].includes(path.extname(f.originalname).toLowerCase()); cb(ok?null:new Error("نوع الملف غير مسموح"),ok)
}});

app.post("/api/auth/register",async(req,res)=>{
 const {username,name,email,password}=req.body;if(!username||!name||!email||!password||password.length<6)return res.status(400).json({error:"البيانات غير مكتملة أو كلمة المرور أقل من 6 أحرف"});
 const d=read(); if(d.users.some(u=>u.email.toLowerCase()===email.toLowerCase()||u.username.toLowerCase()===username.toLowerCase()))return res.status(409).json({error:"البريد أو اسم المستخدم مستخدم"});
 const u={id:id(),username,name,email,password:await bcrypt.hash(password,12),role:"user",createdAt:now(),banned:false,avatar:""};d.users.push(u);log(d,u.id,"register");write(d);
 const token=jwt.sign({id:u.id,role:u.role},SECRET,{expiresIn:"7d"});res.json({token,user:safe(u)});
});
app.post("/api/auth/login",async(req,res)=>{
 const {login,password}=req.body,d=read(),u=d.users.find(x=>x.email.toLowerCase()===String(login).toLowerCase()||x.username.toLowerCase()===String(login).toLowerCase());
 if(!u||!(await bcrypt.compare(password,u.password)))return res.status(401).json({error:"بيانات الدخول غير صحيحة"});
 if(u.banned)return res.status(403).json({error:"الحساب محظور"});
 const token=jwt.sign({id:u.id,role:u.role},SECRET,{expiresIn:"7d"});res.json({token,user:safe(u)});
});
app.get("/api/me",auth,(req,res)=>{const u=read().users.find(x=>x.id===req.user.id);res.json({user:safe(u)})});

app.get("/api/apps",(req,res)=>{const d=read();let a=d.apps.filter(x=>x.status==="published");if(req.query.q){let q=req.query.q.toLowerCase();a=a.filter(x=>(x.name+" "+x.description).toLowerCase().includes(q))}if(req.query.category)a=a.filter(x=>x.category===req.query.category);res.json({apps:a})});
app.get("/api/apps/:id",(req,res)=>{const d=read(),a=d.apps.find(x=>x.id===req.params.id);if(!a||a.status!=="published")return res.status(404).json({error:"التطبيق غير موجود"});const reviews=d.reviews.filter(r=>r.appId===a.id).map(r=>({...r,user:d.users.find(u=>u.id===r.userId)?.username||"مستخدم"}));res.json({app:a,reviews})});
app.post("/api/apps",auth,role("admin","moderator"),upload.fields([{name:"icon",maxCount:1},{name:"screenshots",maxCount:8},{name:"androidFile",maxCount:1}]),(req,res)=>{
 const {name,description,category,version,size,androidUrl,iosUrl}=req.body;if(!name||!description||!category)return res.status(400).json({error:"الاسم والوصف والتصنيف مطلوبة"});
 const d=read(),files=req.files||{},appx={id:id(),name,description,category,version:version||"1.0.0",size:size||"",androidUrl:androidUrl||"",iosUrl:iosUrl||"",icon:files.icon?.[0]?"/uploads/"+files.icon[0].filename:"",androidFile:files.androidFile?.[0]?"/uploads/"+files.androidFile[0].filename:"",screenshots:(files.screenshots||[]).map(f=>"/uploads/"+f.filename),publisherId:req.user.id,status:"pending",createdAt:now(),updatedAt:now(),downloads:0};
 d.apps.push(appx);log(d,req.user.id,"app.create",{appId:appx.id});write(d);res.json({app:appx});
});
app.patch("/api/apps/:id",auth,role("admin","moderator"),(req,res)=>{const d=read(),a=d.apps.find(x=>x.id===req.params.id);if(!a)return res.status(404).json({error:"غير موجود"});Object.assign(a,req.body,{updatedAt:now()});log(d,req.user.id,"app.update",{appId:a.id});write(d);res.json({app:a})});
app.delete("/api/apps/:id",auth,role("admin"),(req,res)=>{const d=read(),i=d.apps.findIndex(x=>x.id===req.params.id);if(i<0)return res.status(404).json({error:"غير موجود"});d.apps.splice(i,1);log(d,req.user.id,"app.delete",{appId:req.params.id});write(d);res.json({ok:true})});
app.post("/api/apps/:id/review-status",auth,role("admin","moderator"),(req,res)=>{const {status,reason}=req.body,d=read(),a=d.apps.find(x=>x.id===req.params.id);if(!a||!["published","rejected","pending"].includes(status))return res.status(400).json({error:"طلب غير صالح"});a.status=status;a.reviewReason=reason||"";a.updatedAt=now();d.notifications.push({id:id(),userId:a.publisherId,text:status==="published"?"تم قبول تطبيقك ونشره":"تم تحديث حالة تطبيقك",at:now()});log(d,req.user.id,"app.status",{appId:a.id,status});write(d);res.json({app:a})});

app.post("/api/apps/:id/review",auth,(req,res)=>{const {rating,text}=req.body,d=read(),a=d.apps.find(x=>x.id===req.params.id);if(!a||a.status!=="published"||rating<1||rating>5)return res.status(400).json({error:"بيانات غير صالحة"});if(d.reviews.some(r=>r.appId===a.id&&r.userId===req.user.id))return res.status(409).json({error:"لديك تقييم سابق"});const r={id:id(),appId:a.id,userId:req.user.id,rating:Number(rating),text:text||"",at:now()};d.reviews.push(r);write(d);res.json({review:r})});
app.post("/api/apps/:id/favorite",auth,(req,res)=>{const d=read(),i=d.favorites.findIndex(x=>x.userId===req.user.id&&x.appId===req.params.id);if(i>=0)d.favorites.splice(i,1);else d.favorites.push({userId:req.user.id,appId:req.params.id,at:now()});write(d);res.json({favorite:i<0})});

app.get("/api/profile/:username",(req,res)=>{const d=read(),u=d.users.find(x=>x.username===req.params.username);if(!u)return res.status(404).json({error:"غير موجود"});res.json({user:{id:u.id,username:u.username,name:u.name,avatar:u.avatar,createdAt:u.createdAt,role:u.role},apps:d.apps.filter(a=>a.publisherId===u.id&&a.status==="published")})});

app.get("/api/admin/summary",auth,role("admin"),(req,res)=>{const d=read();res.json({users:d.users.length,apps:d.apps.length,pending:d.apps.filter(a=>a.status==="pending").length,reviews:d.reviews.length,logs:d.logs.slice(-50).reverse()})});
app.get("/api/admin/users",auth,role("admin"),(req,res)=>{const d=read();res.json({users:d.users.map(safe)})});
app.patch("/api/admin/users/:id",auth,role("admin"),(req,res)=>{const d=read(),u=d.users.find(x=>x.id===req.params.id);if(!u)return res.status(404).json({error:"غير موجود"});if(req.body.role&&!["user","moderator","admin"].includes(req.body.role))return res.status(400).json({error:"دور غير صالح"});if(u.id===req.user.id&&req.body.role&&req.body.role!=="admin")return res.status(400).json({error:"لا تغيّر دور حسابك من هنا"});Object.assign(u,req.body);log(d,req.user.id,"user.update",{target:u.id});write(d);res.json({user:safe(u)})});

app.get("/api/admin/pending",auth,role("admin","moderator"),(req,res)=>{const d=read();res.json({apps:d.apps.filter(a=>a.status==="pending")})});
app.get("/api/notifications",auth,(req,res)=>{const d=read();res.json({notifications:d.notifications.filter(n=>n.userId===req.user.id).reverse()})});
app.get("/api/health",(req,res)=>res.json({ok:true,service:"AppHub",time:now()}));
app.use((err,req,res,next)=>{console.error(err);res.status(400).json({error:err.message||"خطأ في الطلب"})});
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`AppHub running on http://localhost:${PORT}`));