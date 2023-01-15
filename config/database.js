const mongoose = require("mongoose")
const MONGODB_URL = process.env.MONGODB_URL
mongoose.set('strictQuery', true);

exports.connect = () => {
    mongoose.connect(MONGODB_URL, {
        useNewUrlParser:true,
        useUnifiedTopology:true
    })
    .then(console.log("DB connected"))
    .catch((error)=>{
        console.log("Error in DB connection");
        console.log(error)
        process.exit(1)
    })
}