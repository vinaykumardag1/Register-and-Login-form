const mongoose=require("mongoose")
const bcrypt=require('bcryptjs')

const UserSchema=new mongoose.Schema({
    name:{
        type:String,
        required:true,
    },
    email:{
        type:String,
        unique:true,
        required:true,
        match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email address']
    },
    password:{
        type:String,
        required:true,
    }
})

UserSchema.pre("save",async function(next){
    //// Check if the password is already hashed (to avoid re-hashing on updates)
    if(!this.isModified("password")){
        return next()
    }
// creating salt and hashing
    const salt= await bcrypt.genSalt(10)
    this.password=await bcrypt.hash(this.password,salt)
    next();
    
})
const userModel=mongoose.model("form",UserSchema);
module.exports=userModel;