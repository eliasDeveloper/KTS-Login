const express = require("express")
const app = express()
const dotenv = require('dotenv')
const mongoose = require('mongoose')
const authRoute = require('./routes/auth')
dotenv.config()

//connect to db
mongoose.connect('mongodb+srv://rhino11:rhino11@cluster0.wz45u.mongodb.net/myFirstDatabase?retryWrites=true&w=majority',
()=> 
console.log('connected to db')
)

//Middleware
app.use(express.json())

app.use('/api/user', authRoute)

app.listen(3000, ()=> console.log('Server Up and running'))