//VALIDATION
const Joi = require('@hapi/joi')

//Register Validation
const registerValidation = data =>{
    
    const schema = Joi.object({
        name: Joi.string().min(6).required(),
        email: Joi.string().min(6).required().email(),
        password: Joi.string() .min(6) .required()
     });
     return schema.validate(data,schema);
}

// //Register Validation
// const loginValidation = async (data) =>{

//     const schema = Joi.object({
//         email: Joi.string().min(6).required().email(),
//         password: Joi.string() .min(6) .required()
//      });
//      return schema.validate(data, schema);
// }

module.exports.registerValidation = registerValidation
// module.exports.loginValidation = loginValidation