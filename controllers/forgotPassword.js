const path = require('path')
const uuid = require('uuid')
const SgMail = require('@sendgrid/mail')
require('dotenv').config()
const bcrypt = require('bcrypt')
const User = require('../models/userDetails')
const ForgotPassword = require('../models/resetPassDetails')


exports.fogetpassDetails =  (req, res, next) => {
    res.sendFile(path.join(__dirname, '../', 'views', 'forgotPassword.html'));
  }

exports.forgotPassword = async(req, res) =>{
    try{
        const {email} = req.body
        const user = await User.findOne({where:{email}})
        if(user){
            const id = uuid.v4()
            user.createForgotPassword({id, active: true})
            .catch(err=>{
                throw new Error(err)
            })
        const SendGridKey = process.env.SENGRID_API_KEY
        SgMail.setApiKey(SendGridKey)

        const msg = {
            to: email,
            from: 'Srivaishnavidurgapu023@gmail.com',
            subject: 'Reset Password',
            text: 'Please reset your password',
            html: `<a href="http://54.249.187.183:3000/password/resetpassword/${id}">Reset password</a>`
        }
        console.log(msg)
        SgMail
        .send(msg)
        .then((response)=>{
            console.log('Email sent....')
            return res.status(response[0].statusCode).json({message: 'Link to reset password sent to your mail ', sucess: true})
        })
        .catch((err)=>{
            throw new Error(err)
        })
        }
        else{
            throw new Error('User doesnot exist')
        }
    }
    catch(err){
        console.error(err)
    }

}

exports.resetpassword = (req, res) => {
    const id =  req.params.id;
    ForgotPassword.findOne({ where : { id }}).then(forgotpasswordrequest => {
        if(forgotpasswordrequest){
            forgotpasswordrequest.update({ active: false});
            res.status(200).send(`<html>
                                    <script>
                                        function formsubmitted(e){
                                            e.preventDefault();
                                            console.log('called')
                                        }
                                    </script>
                                    <form action="/password/updatepassword/${id}" method="GET">
                                        <label for="newpassword">Enter New password</label>
                                        <input name="newpassword" type="password" required></input>
                                        <button>reset password</button>
                                    </form>
                                </html>`
                                )
            res.end()

        }
    })
}

exports.updatepassword = (req, res) => {

    try {
        const { newpassword } = req.query;
        const { resetpasswordid } = req.params;
        ForgotPassword.findOne({ where : { id: resetpasswordid }}).then(resetpasswordrequest => {
            User.findOne({where: { id : resetpasswordrequest.UserId}}).then(user => {
                 console.log('userDetails', user)
                if(user) {
                    //encrypt the password

                    const saltRounds = 10;
                    bcrypt.genSalt(saltRounds, function(err, salt) {
                        if(err){
                            console.log(err);
                            throw new Error(err);
                        }
                        bcrypt.hash(newpassword, salt, function(err, hash) {
                            // Store hash in your password DB.
                            if(err){
                                console.log(err);
                                throw new Error(err);
                            }
                            user.update({ password: hash }).then(() => {
                                res.status(201).json({message: 'Successfuly update the new password'})
                            })
                        });
                    });
            } else{
                return res.status(404).json({ error: 'No user Exists', success: false})
            }
            })
        })
    } catch(error){
        return res.status(403).json({ error, success: false } )
    }

}

