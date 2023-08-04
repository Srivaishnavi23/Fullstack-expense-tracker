const Expense = require('../models/expenseDetails');
const User = require('../models/userDetails');
const sequelize = require('../Util/database');

 exports.getAllUsers = async (req, res, next)=>{

    try{
        const leaderboardofUsers = await User.findAll({
            attributes:['id', 'username',[sequelize.fn('sum', sequelize.col('Expenses.Number')), 'TotalCost']],
            include:[
                {
                    model:Expense,
                    attributes:[]
                }
            ],
            group:['Users.id'],
            order:[['TotalCost', 'DESC']]
        })
        res.status(201).json(leaderboardofUsers);
    } catch(err){
        console.log(err)
        res.status(500).json(err)
    }
    
 }