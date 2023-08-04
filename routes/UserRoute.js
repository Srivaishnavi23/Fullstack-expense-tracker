const path = require('path')
const User = require('../models/userDetails')

const userController = require('../controllers/userDetails')



const express = require('express')
const router = express.Router();

router.post('/users/signup', userController.signUp)
router.post('/users/login', userController.loginUser)
router.get('/users/getUser', userController.getUsers)

module.exports = router