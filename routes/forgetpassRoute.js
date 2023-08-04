const express = require('express')
const forgotPasswordController = require('../controllers/forgotPassword')
const router = express.Router()
router.get('/password/forgotpassword', forgotPasswordController.fogetpassDetails)
router.use('/password/forgotpassword', forgotPasswordController.forgotPassword)
router.get('/password/resetpassword/:id', forgotPasswordController.resetpassword)
router.get('/password/updatepassword/:resetpasswordid', forgotPasswordController.updatepassword)
module.exports = router
