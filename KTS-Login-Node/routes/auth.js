const router = require('express').Router()
const User = require('../model/User')
const jwt = require('jsonwebtoken')
const { registerValidation } = require('../validation')
const bcrypt = require('bcryptjs')
//VALIDATION
const Joi = require('@hapi/joi');
const schema = Joi.object({
    name: Joi.string().min(6).required(),
    email: Joi.string().min(6).required().email(),
    password: Joi.string() .min(6) .required()
 });

 const loginSchema = Joi.object({
    email: Joi.string().min(6).required().email(),
    password: Joi.string() .min(6) .required()
 });

router.post('/register', async (req, res)=> {
    const {error} = schema.validate(req.body);
    //const {error} = regsiterValidation(req.body);
    if(error){
        return res.status(400).send(error.details[0].message)
    }
    //Checking if the user is already in the db
    const emailExist = await User.findOne({email: req.body.email})
    if(emailExist){
        return res.status(400).send('email already exists')
    }
    //HASH the password
    const salt = await bcrypt.genSalt(10)
    const hashPassword = await bcrypt.hash(req.body.password, salt)
    //Create a new User
    const user = new User({
        name: req.body.name,
        email: req.body.email,
        password: hashPassword     
    })
    try{
        const savedUser = await user.save()
        res.send({user: user._id})
    }catch(err){
        res.status(400).send(err)
    }
 })

 //LOGIN
 router.post('/test',verifyToken, (req,res)=>{
     const token = req.header('auth-token')
     if(!token) return res.status(401)
     try{
        const verified = jwt.verify(req.token, 'secretkey', (err, authData )=>{
        err ? res.sendStatus(403) :
         res.json({
            message: 'Post created...',
            authData
        })

    })
    req.user = verified
    }
    catch(err){
        res.status(400).send('Invalid Token')
    }
    
})
 router.post('/login', async (req, res)=>{
     const { error } = loginSchema.validate(req.body)
     if(error){
         return res.status(400).send(error.details[0].message)
     }
     //Checking if the email is already in the db
    const user = await User.findOne({email: req.body.email})
    if(!user){
        return res.status(400).send('failed login: invalid credentials')
    }
    const validPass = await bcrypt.compare(req.body.password, user.password)
    if(!validPass){
        return res.status(400).send('failed login: invalid credentials')
    }
    //Crete and assign a token
    // const token = jwt.sign({_id: user._id}, 'sjkhfdjsdhfkkjwers')
    jwt.sign({user}, 'secretkey',{expiresIn: '60s'}, (err, token)=>{
        res.json({
            token
        })
    });
    res.header('auth-token', token).send(token)
    res.status(200).send(token)
    
 })
 
 function verifyToken(req, res, next){
    // Get auth header value
    const bearerHeader = req.headers['authorization'];
    if(typeof bearerHeader !== 'undefined'){
        // Split at the space
        const bearer = bearerHeader.split(' ')
        //Get Token from array
        const bearerToken = bearer[1];
        //Set the token
        req.token = bearerToken
        
        next()
    }
    else{
        res.sendStatus(403);
    }
}


module.exports = router;
// const app = express()

// app.listen(3000, ()=> console.log('Server Up and running'))