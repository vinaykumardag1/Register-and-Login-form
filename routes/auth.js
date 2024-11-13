const express=require('express')
const router=express.Router()
const authController=require("../controllers/auth")



router.post("/register",authController.Register)
router.post("/login",authController.Login)
router.get("/logout",authController.Logout)
router.post("/forgotpassword",authController.Forgotpassword)

module.exports=router;