const path = require('path')

const jwt = require('jsonwebtoken')

require('dotenv').config()

const Razorpay = require('razorpay');

const Order = require('../models/order');

const userController = require('./userDetails')


function generateToken(id, username, ispremiumuser){
    return jwt.sign({UserId: id, username: username, ispremiumuser}, 'HiToken!')
}



const purchasepremium =async (req, res) => {
    try {
        var rzp = new Razorpay({
            key_id: process.env.RAZORPAY_KEY_ID,
            key_secret: process.env.RAZORPAY_KEY_SECRET
        })
        const amount = 2500;

        rzp.orders.create({amount, currency: "INR"}, (err, order) => {
            if(err) {
                throw new Error(JSON.stringify(err));
            }
            req.user.createOrder({ orderid: order.id, status: 'PENDING'}).then(() => {
                return res.status(201).json({ order, key_id : rzp.key_id});

            }).catch(err => {
                throw new Error(err)
            })
        })
    } catch(err){
        console.log(err);
        res.status(403).json({ message: 'Something went wrong', error: err})
    }
}

const updateTransactionStatus = async (req, res ) => {
    try {
        
            // storing the id from user table
            const UserId = req.user.id; 
            // taking the details of payment id and order id
            const { payment_id, order_id} = req.body; 
             // finding the order using order id 
            const order  = await Order.findOne({where : {orderid : order_id}})
    
            if(payment_id == null){
                const promise1 = order.update({ status: 'FAILED'});
                const promise2 =  req.user.update({ ispremiumuser: false }) 
                Promise.all([promise1, promise2]).then(()=> {
                    return res.status(407).json({success: false, message: "Transaction Failed",token: generateToken(UserId, undefined , false)});
                }).catch((error ) => {
                    throw new Error(error)
                })
        
                
            }
            else{
                //updating the payment id and status only after the payment is successfull 
            const promise3 =  order.update({ paymentid: payment_id, status: 'SUCCESSFUL'}) 
    
            // Upon successfull payment and status is updated ,updating the user table as user is premium or not 
            const promise4 =  req.user.update({ ispremiumuser: true }) 
            
    
    
            // Now setting the promise and sending the satus as on which user above promises will be applied.
            Promise.all([promise3, promise4]).then(()=> {
                return res.status(202).json({success: true, message: "Transaction Successful",token: generateToken(UserId, undefined , true)});
            }).catch((error ) => {
                throw new Error(error)
            })
    
            }
                
    } catch (err) {
        console.log(err);
    }
}


module.exports = {purchasepremium, updateTransactionStatus}