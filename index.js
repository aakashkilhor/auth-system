const app = require('./app')
const {PORT} = process.env



app.listen(PORT, ()=>{
    console.log(`app PORT is listening at ${PORT}`);
})