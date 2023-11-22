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
// Modify the encryptData function
function encryptData(data) {
    try {
      const iv = generateRandomIV();
      const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(encryptionKey, 'hex'), iv);
      let encryptedData = cipher.update(data, 'utf-8', 'hex');
      encryptedData += cipher.final('hex');
      console.log('Encryption successful');
      return { encryptedData, iv: iv.toString('hex') };
    } catch (error) {
      console.error('Encryption error:', error);
      throw error;
    }
  }
  

// Decrypt 
// Modify the decryptData function
function decryptData(encryptedData, iv) {
    try {
      const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(encryptionKey, 'hex'), Buffer.from(iv, 'hex'));
      let decryptedData = decipher.update(encryptedData, 'hex', 'utf-8');
      decryptedData += decipher.final('utf-8');
      console.log('Decryption successful');
      return decryptedData;
    } catch (error) {
      console.error('Decryption error:', error);
      throw error;
    }
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
    console.log('Login route reached');
    const { email, password } = req.body;
    console.log('Email:', email);
    console.log('Password:', password);

    const user = await User.findAll({ where: { email } });
    console.log('User length:', user.length);

    if (user.length > 0) {
      bcrypt.compare(password, user[0].password, (err, match) => {
        console.log('bcrypt.compare callback reached');
        if (match) {
          console.log('Password matches');
          const decryptedUsername = decryptData(user[0].username, user[0].usernameIV);
          console.log('Decrypted Username:', decryptedUsername);
          // ... rest of the success logic
          return res.status(201).json({
            message: 'Login Successful!',
            token: generateToken(user[0].id, decryptedUsername, user[0].ispremiumuser)
          });
        } else {
          console.log('Password does not match');
          return res.status(400).json({ message: 'wrong password' });
        }
      });
    } else {
      console.log('User not found');
      return res.status(207).json({ message: 'User not found' });
    }
  } catch (error) {
    console.log('Error:', error);
    return res.status(500).json({ error: error });
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









