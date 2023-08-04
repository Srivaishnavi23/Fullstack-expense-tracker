const Sequelize = require('sequelize')

const sequelize = require('../Util/database')

const forgotPassword = sequelize.define('forgotPassword',{
    id: {
        type: Sequelize.UUID,
        allowNull: false,
        primaryKey: true
    },
    active: Sequelize.BOOLEAN,
    expiresby: Sequelize.DATE
})

module.exports = forgotPassword