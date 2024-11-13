const express=require("express")
const mongoose=require("mongoose")
const sesssion=require('express-session')
const ejs=require("ejs")
const bodyparser=require("body-parser")
const cookieParser=require("cookie-parser")
const app=express()
const bcrypt=require('bcryptjs')
const authRoutes=require("./routes/auth")
const {authenticate}=require('./middleware/auth')


// mongodb connection
mongoose.connect('mongodb://localhost:27017/task')
        .then(()=>console.log("mongodb is connected"))
        .catch(err=>console.log("error in mongodb",err))
//
app.use(bodyparser.urlencoded({extended:false}))

// render the ejs file 
app.set("view engine","ejs")
app.set("views",'views')
// cookies
app.use(cookieParser())
// sessions
app.use(sesssion({
    secret:'key session',
    cookie:{maxAge:60000},
    secure:true,
    resave:false,
    saveUninitialized:false,
}))
// 
app.get("/",(req,res)=>{res.render('index')})
app.get("/login",(req,res)=>{res.render("Login")})
app.get("/reset",(req,res)=>{res.render("Password")})
app.get("/dashboard",authenticate,(req,res)=>{res.render("Dashboard")})
// 
app.use('/auth',authRoutes)
// 
app.listen(3000,()=>{
    console.log("server is going on 3000")
})