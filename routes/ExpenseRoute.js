const path = require('path');
const User = require('../models/expenseDetails');

const expenseController = require('../controllers/Expense');
const userAuthentication = require('../middleware/auth')

const express = require('express');
const router = express.Router();



router.post('/get-user/:page', userAuthentication.authentication, expenseController.getExpenses);

router.post('/add-user',  userAuthentication.authentication, expenseController.postAddExpenses);


router.get('/download', userAuthentication.authentication, expenseController.downloadExpense)

router.get('/getAllUrl', userAuthentication.authentication, expenseController.getDownloadUrls)

router.delete('/delete-user/:userId', expenseController.deleteExpense);


module.exports = router;