// server.js
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt')
const nodemailer = require('nodemailer');
const smtpTransport = require('nodemailer-smtp-transport');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

app.set("views", __dirname);
app.engine('html', require('ejs').renderFile);
app.set('view engine', 'html');

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/userRegdb');

// Define a user schema
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  resetToken: String,
  resetTokenExpiration: Date,
});

const User = mongoose.model('User', userSchema);

// Middleware to parse request body
app.use(bodyParser.urlencoded({ extended: true }));

// Serve HTML form for user registration
app.get('/',(req,res) => {
  res.render('index')
})

// Serve HTML form for user registration
app.get('/register', (req, res) => {
  res.render('register');
});

// Handle user registration form submission
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {

    // Check if the email is already registered
    const existingUser = await User.findOne({ email });
    let err = "";
    console.log(existingUser)
    if (existingUser) {
        err+='Email is already registered. Please choose a different email.\n';
    }
      
    // Check if the password meets the requirements
    const passwordRegex = /^(?=.*[A-Z])(?=.*[!@#$%^&*])(.{8,})$/;
    if (!passwordRegex.test(password)) {
      err+='Password must be 8 characters long with one special character and one capital letter.\n';
    }

    if(err!=""){
      return res.render("index",{"err":err});
    }

    // Hash the password before saving it to the database
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const newUser = new User({
      name,
      email,
      password: hashedPassword,
    });

    // Save user to MongoDB
    await newUser.save();

    res.redirect('/login')
  } catch (err) {
    res.status(500).send('Internal Server Error');
  }
});

app.get('/login', (req, res) => {     
  res.sendFile(__dirname + '/login.html');
});

// Handle user login form submission
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if user exists in the database
    const user = await User.findOne({ email });

    if (user) {
      // Compare the hashed password with the provided password
      const passwordMatch = await bcrypt.compare(password, user.password);
      if(passwordMatch) {
        res.redirect('/');
      } else {
      res.send('Invalid email or password');
        } 
      } else {
      res.send('Invalid email or password');
  } 
}catch (err) {
    res.status(500).send('Internal Server Error');
  }
});


// Configure nodemailer with your email service credentials
const transporter = nodemailer.createTransport(
  smtpTransport({
    service: 'gmail', // Update with your email service (e.g., 'gmail', 'yahoo', etc.)
    auth: {
      user: 'phatanibrahim71685@gmail.COM', // Update with your email address
      pass: 'yinw qilj frux mwqr', // Update with your email password
    },
  })
);

// Serve HTML form for password recovery
app.get('/forgot-password', (req, res) => {
  res.sendFile(__dirname + '/forgot-password.html');
});

function generateResetToken() {
  return new Promise((resolve, reject) => {
    // Generate a random token using crypto
    crypto.randomBytes(32, (err, buffer) => {
      if (err) {
        reject(err);
      } else {
        // Convert the buffer to a hex string
        const token = buffer.toString('hex');
        resolve(token);
      }
    });
  });
}



// Handle password recovery form submission
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    // Check if the user exists in the database
    const user = await User.findOne({ email });

    if (user) {

  
      // Generate a unique token for password reset
      const resetToken = await generateResetToken()
      .then((resetToken) => { return resetToken;
      })
      .catch((error) => {
        res.status(500).send(error);
      }); // Implement this function
      console.log(resetToken)
      // Update the user with the reset token and expiration time
      user.resetToken = resetToken;
      user.resetTokenExpiration = Date.now() + 3600000; // Token valid for 1 hour
      await user.save();

      // Compose the email message
      const mailOptions = {
        from: '"MNT-007 👻" <phatanibrahim71685@.gmailcom>',
        to: email,
        subject: 'Password Reset',
        html: `
            <div style="font-family: Arial; sans-serif; background-color: #f4f4f4; padding: 20px; text-align: center;">
                <h2 style="color: #333;">Password Reset</h2>
                <p style="color: #555;">
                    You are receiving this email because you (or someone else) have requested the reset of the password for your account.
                </p>
                <p style="color: #555;">
                    Please click on the Reset Password button to reset the password:
                </p>
                <a href="http://localhost:3000/reset-password/${resetToken}" style="color: #007bff; text-decoration: none; font-weight: bold;">
                    Reset Password
                </a>
                <p style="color: #555;">
                    If you did not request this, please ignore this email and your password will remain unchanged.
                </p>
            </div>
        `,
    };
    

      // Send the email
      await transporter.sendMail(mailOptions);

      res.send('Password reset instructions sent to your email.');
    } else {
      res.send('No user found with that email address.');
    }
  } catch (err) {
    console.log(err)
    res.status(500).send('Internal Server Error');
  }
});

// Serve HTML form for password reset
app.get('/reset-password/:token', (req, res) => {
  const resetToken = req.params.token;
  res.render('reset-password', {resetToken : resetToken });
});

// Handle password reset form submission
app.post('/reset-password/:token', async (req, res) => {
  const resetToken = req.params.token;
  const newPassword = req.body.password;

  try {
    // Find the user with the provided reset token
    const resetTokenExpiration = new Date().toISOString();
    const user = await User.findOne({
      resetToken,
      resetTokenExpiration: { $gt: resetTokenExpiration },
    });

    if (user) {
      // Hash the new password before saving it to the database
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      // Update the user's password and reset token fields
      user.password = hashedPassword;
      user.resetToken = resetToken;
      user.resetTokenExpiration = resetTokenExpiration;
      await user.save();

      res.redirect('/');
    } else {
      res.send('Invalid or expired reset token.');
    }
  } catch (err) {
    console.log(err)
    res.status(500).send('Internal Server Error');
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});