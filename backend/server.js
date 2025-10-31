const express=require("express");
const mongoose=require("mongoose");
const bcrypt=require("bcrypt");
const jwt=require("jsonwebtoken");
const cors=require("cors");
const User=require("./models/User");
require("dotenv").config();

const app=express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
.then(()=>console.log("mongodb connected"))
.catch(err=>console.log(err));

app.post("/register",async(req,res)=>{
    const {username,password}=req.body;

    const hash=await bcrypt.hash(password,10);

    try{
        await User.create({username,password:hash});
        res.send("user registerd");
    }catch(err){
        res.status(400).send("username already exists");
    }
});

app.post("/login",async(req,res)=>{

    const {username,password}=req.body;

    const user=await User.findOne({username});
    if(!user) return res.status(400).send("user not found");

    const match=await bcrypt.compare(password,user.password);
    if(!match)return res.status(400).send("invalid credentials");
    
    const token=jwt.sign({id:user._id},process.env.JWT_Secret);
    res.json({message:"login succesful",token});

});

function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1]; // Bearer <token>

  if (!token) return res.status(401).send("❌ No Token Provided");

  try {
    const data = jwt.verify(token, process.env.JWT_SECRET);
    req.user = data;
    next();
  } catch {
    res.status(401).send("❌ Invalid Token");
  }
}

app.get("/profile",auth,async(req,res)=>{
    const user=await User.findById(req.user.id).select("-password");
    res.json({message:"access granted",user});
});

app.listen(5000,()=>console.log("server running"));