const bcrypt = require('bcryptjs');
const User = require("../models/User");
const jwt=require("jsonwebtoken")
require("dotenv").config()

exports.Register = async (req, res) => {
    try {
        const { name, email, password, c_password } = req.body;

        const existingUser = await User.findOne({ email: email });
        if (existingUser) {
            return res.redirect("/login");
        }
        if (password !== c_password) {
            return res.redirect("/");
        }
        // decrypt the password
        const hashedPassword = await bcrypt.hash(password, 10);
        const userData = new User({ name:name, email:email, password:hashedPassword });
        await userData.save();

        // 
        res.redirect("/login");
    } catch (error) {
        console.error("Error in register:", error);
        res.status(500).send("An error occurred during registration.");
    }
};

exports.Login = async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user by email
        const user = await User.findOne({ email:email });
        if (!user) {
            return res.status(404).send('User not found');
        }

        // Compare password
        const isMatch = await bcrypt.compare(password, user.password);
        
        if (isMatch) {
            return res.status(401).send('Invalid credentials');
        }
        // Generate JWT token
        const token = jwt.sign(
            { id: user._id, email: user.email }, 
            process.env.JWT_SECRET, // Use a secure secret
            { expiresIn: '1d' } // Token valid for 1 day
        );

        // Set cookie with the token
        res.cookie('authToken', token, {
            httpOnly: true,          // Prevent client-side JavaScript from accessing the cookie
            secure: process.env.NODE_ENV === 'production', // Use HTTPS in production
            sameSite: 'strict',      // Mitigate CSRF attacks
            maxAge: 24 * 60 * 60 * 1000, // 1 day in milliseconds
        });

        // Optional: Add user session details
        req.session.user = user;

       
        // Redirect to the dashboard
        res.redirect("/dashboard");
    } catch (error) {
        console.error("Error in login:", error);
        res.status(500).send("An error occurred during login.");
    }
};
// reset Password


exports.Forgotpassword= async (req, res) => {
    try {
        const { email, password, c_password } = req.body;
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

        // Update user password and save
        user.password = hashedPassword; // Save the hashed password
        await user.save();
        res.redirect('/login')
    } catch (error) {
        console.error("Error in /forgetpass route:", error);
        res.status(500).json({ Error: "An error occurred. Please try again later." });
    }
}

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
