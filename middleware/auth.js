const jwt = require('jsonwebtoken')
const User = require('../models/userDetails')
require('dotenv').config()

const authentication = (req, res, next)=>{
    try{
        const token = req.header('Authorization')
        console.log(token)
        const user = jwt.verify(token, 'HiToken!')
        console.log('UserId>>>>>', user.UserId)

        User.findByPk(user.UserId).then(user=>{
            console.log('user>>>>', user)
            console.log(JSON.stringify(user))
            req.user = user
            next()
        })
        .catch(err=>{
            console.log(err)
        })
    }
    catch(error){
        console.log(error)
        return res.status(401).json({success: false})
    }
}

module.exports = {authentication}