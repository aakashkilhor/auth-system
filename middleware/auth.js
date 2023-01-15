const jwt = require("jsonwebtoken")

const auth = (req,res,next)=>{
    console.log(req.cookies);
    const token = req.cookies

    if (!token) {
       return res.status(403).send("Token missing")
    }
    // Verify token
    try {
       const decode = jwt.verify(token,'secret')
       console.log(decode);
       req.user = decode

    //    Extract id from token and query the DB
    
    } catch (error) {
      res.status(403).send("Token invalid")
    }
    return next()
}

module.exports = auth