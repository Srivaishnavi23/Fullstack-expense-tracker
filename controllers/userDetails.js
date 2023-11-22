const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/userDetails');

// Secret key for encryption and decryption
const encryptionKey = crypto.randomBytes(32).toString('hex');

function generateRandomIV() {
  return crypto.randomBytes(16);
}

// Encrypt 
function encryptData(data) {
  const iv = generateRandomIV();
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(encryptionKey), iv);
  let encryptedData = cipher.update(data, 'utf-8', 'hex');
  encryptedData += cipher.final('hex');
  return { encryptedData, iv: iv.toString('hex') };
}

// Decrypt 
function decryptData(encryptedData, iv) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(encryptionKey), Buffer.from(iv, 'hex'));
  let decryptedData = decipher.update(encryptedData, 'hex', 'utf-8');
  decryptedData += decipher.final('utf-8');
  return decryptedData;
}

exports.signUp = async (req, res, next) => {
  console.log('Ready To Signup');

  try {
    const usernameData = encryptData(req.body.username);
    const emailData = encryptData(req.body.email);
    const password = req.body.password;

    bcrypt.hash(password, 10, async (err, hash) => {
      const data = await User.create({
        username: usernameData.encryptedData,
        email: emailData.encryptedData,
        usernameIV: usernameData.iv,
        emailIV: emailData.iv,
        password: hash
      });
      res.status(201).json({ newUserDetails: data });

    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: error });
  }
};

function generateToken(id, username, ispremiumuser) {
    return jwt.sign({ UserId: id, username: username, ispremiumuser }, 'HiToken!');
}

exports.loginUser = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = await User.findAll({ where: { email } });

    if (user.length > 0) {
      bcrypt.compare(password, user[0].password, (err, match) => {
        if (match) {
          const decryptedUsername = decryptData(user[0].username, user[0].usernameIV);
          const decryptedEmail = decryptData(user[0].email, user[0].emailIV);
          return res.status(201).json({
            message: 'Login Successful!',
            token: generateToken(user[0].id, decryptedUsername, user[0].ispremiumuser)
          });
        } else {
          return res.status(400).json({ message: 'wrong password' });
        }
      });
    } else {
      return res.status(207).json({ message: 'User not found' });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: error });
  }
};

exports.getUsers = async (req, res, next) => {
  console.log('Getting Users');
  try {
    const SignedUser = await User.findAll();
    res.status(201).json(data);
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: error });
  }
};








