const express = require("express")
const bcrypt = require("bcrypt")
const mongoose = require("mongoose")
const User = require("./model/User")
const jwt = require("jsonwebtoken")
const dotenv = require('dotenv')
const cors = require("cors")
dotenv.config()
const app = express()

app.use(express.json())
app.use(cors())
//Signup Route
app.post('/signup', async(req,res) =>{
    const {username,password} = req.body
    console.log(username)
    try{
        let user = await User.findOne({username})
         if(user){
             return res.status(400).json({message:"User exists"})
         }
        User.insertOne({username,password});
        res.status(201).json({message:"User created Successfully"})
    }
    catch(err){console.log(err)}
})
app.get('/login',async (req,res) =>{
    const {username,password} = req.body
    try{
        let user = await User.findOne({username})
        if(user){
            const isMatch = await bcrypt.compare(password,user.password)
            if(!isMatch) return res.status(400).json("Invalid Credentials")
            const token = jwt.sign({userId:user._id},process.env.JWT_secret,{expiresIn:'1h'})
            res.json({message:"Logged in",token:token})
        }
        else{
            res.send(400).json({"message":"User not found"})
        }
    }catch(err){
        console.log(err)    }

})
function verifyToken(req,res,next){
    const token = req.body.token
    jwt.verify(token,process.env.JWT_secret,(err,decoded)=>{
        if(err){ 
        res.sendStatus(403)
        return}
        else{
            req.user = decoded
            next();
        }
    })
}
app.get('/profile/:id',verifyToken,async(req,res)=>{
    console.log(req.params.id)
    const user = await User.findById(req.params.id).select('-password')

    res.json({message:"Welcome to ur profile", user})
})
app.post('/logout',(req,res)=>{
    res.json({message:"Successfully logged out"})
})
app.listen(process.env.PORT,() => {
    console.log("Server is working")
})
mongoose.connect(process.env.MONGO_URL)
.then(() => console.log("MongoDB Connected"))
.catch((err)=>console.log(err))