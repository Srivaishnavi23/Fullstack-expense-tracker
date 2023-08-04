const Sequelize = require('sequelize')

const sequelize = require('../Util/database')

const Expense = sequelize.define('Expense',{
 id: {
    type: Sequelize.INTEGER,
    autoIncrement: true,
    allowNull: false,
    primaryKey: true
 },
 Number: {
    type: Sequelize.INTEGER,
    allowNull: false
 },
 Description: {
    type: Sequelize.STRING,
    allowNull: false
 },
 Categories: {
    type: Sequelize.STRING,
    allowNull: false,
 }     
})

module.exports = Expense