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
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', req.headers.origin);
    res.header('Access-Control-Allow-Credentials', true);
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    next();
  });

// import auth from ("./middleware/auth")
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
    const myEncryptPassword = await bcrypt.hash(password, 10)
    
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
            console.log("Hello")
            console.log(user)
            console.log("Hi")
            // If user does not exist
            // console.log(user._id)
            if (!user){
                res.send("User does not exist")
            }

            // Match the password Create and send the token
            if (user && (await bcrypt.compare(password, user.password))) {
                const token = jwt.sign({id:user._id,name:user.firstname,email},'secret',{expiresIn:'12h'})
            
                user.password = undefined
                console.log(token)
                // user.token = token

            // res.cookie("token", token, options);
            // console.log("Line 92");
            res.status(200).cookie("token",token).json({
                success:true,
                token,
                user
            })
            }
            // res.sendStatus(400).send("email or password is incorrect")
            
            
            
        } catch (error) {
            console.log(error)
            console.log("Error in login")
        }
    })

app.get("/dashboard", auth, (req,res) => {
    console.log(req.user.name)
    res.send(req.user.name)    
})


module.exports = app

