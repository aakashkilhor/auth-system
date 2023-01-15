require('dotenv').config()
require("./config/database.js").connect()
const express = require("express")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcryptjs")
const cookieParser = require("cookie-parser")
// Import model
const User = require("./model/user")

const app = express()
app.use(express.json()) 
app.use(express.urlencoded({extended:true}))
app.use(cookieParser())

// Custom middleware
const auth = require("./middleware/auth")



app.get("/", (req,res)=>{res.send("Hello auth system")})

app.post("/register", async (req,res)=>{
   try {
    // Collecting all the information
    const {firstname, lastname, email, password} = req.body
    // Validate if data exists
    if (!(firstname && lastname && email && password)) {
        res.status(401).send("All fields are required")}

    // Check if email is in correct format
    
    // Check if user exists
    const existingUser = await User.findOne({email})  //{email:email} first one is variable
        //  second one is extraction from body we use {email} because javascript is smart
    if (existingUser) {
        res.status(401).send("User already exists")
    }
    // Encrypting the password
    const myEncryptPassword = await bcrypt.hash(password)
    
    // Creating entry in database
    const user = await User.create({   
        firstname,            // firstname:firstname, -Javascript is smart
        lastname,            // lastname:lastname,
        email,              // email:email,
        password:myEncryptPassword
    })
    // Create a token and send it to user
    const token = jwt.sign({
        id: user._id
    }, 'secret', {expiresIn: '2h'})

    user.token = token;
    // Don't want to send the password
    user.password = undefined

    res.status(201).json(user)

   } catch (error) {
    console.log(error);
    console.log("Error in response route");
   }   
})

app.post("/login", async(req,res)=>{
    try {
        // Collect information from frontend
        const { email, password} = req.body
        // Validate
        if (!(email&&password)) {
            res.status(401).send("Email & password are required")
        }
        // Check user existence
        const user = await User.findOne({email})

        // If user does not exist
        // Match the password Create and send the token
        if (user && (await bcrypt.compare(password, user.password))) {
            const token = jwt.sign({id:user._id,email},'secret',{expiresIn:'2h'})
        
            user.password = undefined
            user.token = token

        const options = {
            expires : new Date(Date.now() + 3*24*60*60*1000),
            httpOnly : true
        }

        res.status(200).cookie("token",token,options).json({
            success:true,
            token,
            user
        })
        }
        res.sendStatus(400).send("email or password is incorrect")
        
        
        
    } catch (error) {
        console.log(error)
        console.log("Error in login")
    }
})

app.get("/dashboard", (req,res) => {
    res.send("Welcome to dashboard")    
})


module.exports = app

