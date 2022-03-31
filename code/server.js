if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config()
}

const express = require('express')
const path = require("path")
const multer = require("multer")
const req = require('express/lib/request')
const app = express()
const crypto = require("crypto")
const bcrypt = require('bcrypt')
const passport = require('passport')
const flash = require('express-flash')
const session = require('express-session')
const methodOverride = require('method-override')
const fs = require('fs')

const initializePassport = require('./passport-config')

// Function finding user based on email, and passport configuring
initializePassport(
    passport,
    email => users.find(user => user.email === email),
    id => users.find(user => user.id === id)
)

const users = []

// ------------------------
// Crypto
// Generate key pair
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
})

// Print key pair
console.log(
	publicKey.export({
		type: "pkcs1",
		format: "pem",
	}),

	privateKey.export({
		type: "pkcs1",
		format: "pem",
	})
)
// Encrypt RSA
function encryptRSA(data) {
    const encryptedData = crypto.publicEncrypt(
        {
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        },
        Buffer.from(data)
    )
    return encryptedData
}

// Decrypt RSA
function decryptRSA(encryptedData) {
    const decryptedData = crypto.privateDecrypt(
        {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        },
        encryptedData
    )
    return decryptedData
}

// ------------------------

// Nodejs encryption with CTR
const algorithm = 'aes-256-cbc';
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

function encryptAES(text) {
    let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
}

function decryptAES(text) {
    let iv = Buffer.from(text.iv, 'hex');
    let encryptedText = Buffer.from(text.encryptedData, 'hex');
    let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}
// ------------------------
  
function base64_encode(file) {
    return "data:image/gif;base64,"+fs.readFileSync(file, 'base64');
}

// ------------------------

// Disk storage
var storage = multer.diskStorage({
    destination: function (req, file, cb) {

        // Uploads is the Upload_folder_name
        cb(null, "uploads/private")
    },
    filename: function (req, file, cb) {
      cb(null, file.fieldname + "-" + Date.now()+'.jpg')
    }
})

// Define the maximum size for uploading
const maxSize = 1 * 1000 * 1000 * 1000;    // picture i.e. 10 MB

var upload = multer({
    storage: storage,
    limits: { fileSize: maxSize },
    fileFilter: function (req, file, cb){

        // Set the filetypes, it is optional
        var filetypes = /jpg|jpeg|png/;
        var mimetype = filetypes.test(file.mimetype);

        var extname = filetypes.test(path.extname(
                    file.originalname).toLowerCase());

        if (mimetype && extname) {
            return cb(null, true);
        }

        cb("Error: File upload only supports the "
                + "following filetypes - " + filetypes);
      }

// mypic is the name of file attribute
}).single("pic");




// View engine setup
app.set("views", path.join(__dirname, "views"))
app.set('view-engine', 'ejs')

app.use(express.urlencoded({ extended: false }))
app.use(flash())
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: true,
    saveUninitialized: true

}))
app.use(passport.initialize())
app.use(passport.session())
app.use(methodOverride('_method'))
app.use(express.static("css"))


app.get('/', checkAuthenticated, (req, res) => {
    res.render('index.ejs', { name: req.user.name })
})

app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render('login.ejs')
})

app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
}))

app.get('/register', checkNotAuthenticated, (req, res) => {
    res.render('register.ejs')
})

app.get('/upload', checkAuthenticated, (req, res) => {
    res.render('upload.ejs')
})

app.post("/uploadProfilePicture", checkAuthenticated, function (req, res, next) {

    var myData = base64_encode('C:/Users/dvtie/OneDrive/Desktop/pic.jpg');
    console.log("Data: ", myData)
    var cipherText = encryptAES(myData);    console.log("Cipher Text: ", cipherText.encryptedData)

    console.log("AES Key: ", key.toString("base64"))
    var encryptedKey = encryptRSA(key);   console.log("Cipher key: ", encryptedKey.toString("base64"))

    var decryptedKey = decryptRSA(encryptedKey);    console.log("Original key: ", decryptedKey.toString("base64"))
    var decryptedText = decryptAES(cipherText); console.log("Original Text: ", decryptedText)

    console.log("\n")
    upload(req,res,function(err) {
        if(err) {
            // ERROR occured
            res.end(err)
        }
        else {
            res.end("Successfully uploaded!")
        }
    })

})

app.post('/register', checkNotAuthenticated, async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10)
        users.push({
            id: Date.now().toString(),
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword
        })
        res.redirect('/login')
    } catch {
        res.redirect('/register')
    }
    console.log(users)
})

app.delete('/logout', (req, res) => {
    req.logOut()
    res.redirect('/login')
})

function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next()
    }
    res.redirect('/login')
}

function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/')
    }

    next()
}

app.listen(3000,function(error) {
    if(error) throw error
        console.log("Server created Successfully!")
})
