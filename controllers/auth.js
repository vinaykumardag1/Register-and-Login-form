const bcrypt = require('bcryptjs');
const User = require("../models/User");
const jwt=require("jsonwebtoken")
require("dotenv").config()

exports.Register = async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Check if the user already exists
        const existingUser = await User.findOne({ email:email });
        if (existingUser) {
            return res.status(400).render({  message: 'User already exists!' });
        }

        // Hash the password
        const saltRounds = 10; // Recommended salt rounds
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Create a new user
        const newUser = new User({ name:name,email:email,password: hashedPassword});

        // Save the user to MongoDB
        await newUser.save();

        res.redirect("/login")
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ success: false, message: 'Error registering user!' });
    }
};

exports.Login = async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email:email });
        if (!user) {
            return res.status(404).json({ Success: "User not found with this email!" });
        }
      
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ Success: "Invalid credentials!" });
        }

       

        const token = jwt.sign(
            { id: user._id, email: user.email },
            process.env.JWT_SECRET || "fallback_secret",
            { expiresIn: '1d' }
        );

        res.cookie('authToken', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000,
        });
        
        // session attempt 
        req.session.user = user;
        res.redirect("/dashboard");
    } catch (error) {
        console.error("Error in login:", error);
        res.status(500).json({ Error: "An error occurred during login." });
    }
};

// reset Password
exports.Forgotpassword = async (req, res) => {
    try {
        const { email, password, c_password } = req.body

        // Find the user by email
        const user = await User.findOne({ email:email });
        if (!user) {
            return res.status(404).json({ Success: "This Email is not registered!" });
        }

        // Check if passwords match
        if (password !== c_password) {
            return res.status(400).json({ Success: "Passwords do not match! Both fields should be the same." });
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(password, 10); // 10 is the salt rounds

        // // Update user password and save
        user.password = hashedPassword;
       
        await user.save();

        // Redirect to login page
        res.redirect('/login');
    } catch (error) {
        console.error("Error in /forgotpassword route:", error);
        res.status(500).json({ Error: error.message || "An error occurred. Please try again later." });
    }
};


// logout module
exports.Logout = (req, res) => {
    try {
        // Clear the cookie
        res.clearCookie('authToken');
        req.session.destroy();
        // Redirect to login page
        res.redirect("/login");
    } catch (error) {
        console.error("Error during logout:", error);
        res.status(500).send("An error occurred during logout.");
    }
};
