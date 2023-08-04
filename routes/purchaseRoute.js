const path = require('path')
const purchase = require('../models/order')

const purchaseController = require('../controllers/purchase')
const userAuthentication = require('../middleware/auth')

const express = require('express')
const router = express.Router()


router.get('/premiumMembership', userAuthentication.authentication, purchaseController.purchasepremium)
router.post('/updatetransactionstatus', userAuthentication.authentication, purchaseController.updateTransactionStatus)

module.exports = router


