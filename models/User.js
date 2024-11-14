const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

// Define User Schema
const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, "Name is required"], // Descriptive error message
        trim: true, // Removes extra spaces
    },
    email: {
        type: String,
        unique: true,
        required: [true, "Email is required"],
        match: [/^\S+@\S+\.\S+$/, "Please enter a valid email address"], // Regex validation
        lowercase: true, // Converts to lowercase
    },
    password: {
        type: String,
        required: [true, "Password is required"],
        minlength: [6, "Password must be at least 6 characters long"], // Ensures secure password length
    },
});



// Create the User model
const User = mongoose.model("forms", UserSchema);

module.exports = User;
