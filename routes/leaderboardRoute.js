const leaderboardController = require('../controllers/leaderboard')
const auth = require('../middleware/auth')

const express = require('express')
const router = express.Router()

router.get('/premium/showLeaderBoard', auth.authentication, leaderboardController.getAllUsers)

module.exports = router
