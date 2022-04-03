const express = require('express')
const path = require('path')
const cookieSession = require('cookie-session')
const {body , validationResult} = require('express-validator')
const bcrypt = require('bcrypt')
const conn = require('./dbConn')

const app = express()
app.use(express.urlencoded({extended:false}))

app.set('views' , path.join(__dirname , 'views'))
app.set('view engine' , 'ejs')

app.use(cookieSession({
    name: 'session',
    keys: ['key1','key2'],
    maxAge: 3600 * 1000
}))

const ifNotLogIn = (req,res,next) =>{
    if(!req.session.Login){
        return res.render('login')
    }
    next()
}

app.get('/' , ifNotLogIn , (req,res) => {
    res.render('homepage' , {
        Fname: req.session.Fname,
        Lname: req.session.Lname
    })
})

app.get('/register' , (req,res) => {
    res.render('register')
})

app.post('/reg' , [
    body('fname' , 'Firstname is required').trim().not().isEmpty(),
    body('lname' , 'Lastname is required').trim().not().isEmpty(),
    body('username' , 'Username is required').trim().not().isEmpty().custom(value => {
        return conn.execute("SELECT username FROM account WHERE username = ?" , [value])
        .then(([rows]) => {
            if(rows.length > 0){
                return Promise.reject('Username is Already exist')
            }
        })
    }),
    body('password' , 'Password must be at least 6 characters').trim().isLength({min:6}),
] , (req,res) => {
    const stmt = validationResult(req)
    const {fname , lname , username , password} = req.body
    if(stmt.isEmpty()){
        bcrypt.hash(password , 12).then(passwordHash => {
            conn.execute('INSERT INTO account (fname , lname , username , password) VALUES(? , ? , ? , ?)',[fname , lname , username , passwordHash])
            .then(() => {
                res.render('login',{
                    regSuccess: 'Register successfully'
                })
            }).catch(err =>{
                if(err) throw err
            })
        }).catch(err =>{
            if(err) throw err
        })
    }else{
        const allErr = stmt.errors.map(err => {
            return err.msg
        })
        res.render('register' , {
            messageErr: allErr
        })
    }
})

app.post('/login' , [
    body('username','Username is required').trim().not().isEmpty(),
    body('password' , 'Password is required').trim().not().isEmpty(),
] , (req,res) => {
    const stmt = validationResult(req)
    const {username , password} = req.body
    if(stmt.isEmpty()){
        conn.execute('SELECT * FROM account WHERE username = ?', [username])
        .then(([rows]) => {
            if(rows.length === 0){
                res.render('login',{
                    messageErr: ['Invalid username']
                })
            }else{
                bcrypt.compare(password , rows[0].password)
                .then(result => {
                    if(result === true){
                        req.session.Login = true
                        req.session.Fname = rows[0].fname
                        req.session.Lname = rows[0].lname
                        res.redirect('/')
                    }else{
                        res.render('login',{
                            messageErr: ['Invalid password']
                        })
                    }
                }).catch(err => {
                    if(err) throw err
                })
            }
        }).catch(err => {
            if(err) throw err
        })
    }else{
        const allErr = stmt.errors.map(err => {
            return err.msg
        })
        res.render('login',{
            messageErr: allErr
        })
    }
})

app.get('/logout' , (req,res) => {
    req.session = null
    res.redirect('/')
})

app.use('/' , (req,res) => {
    res.status(404).send('<h1>404 Page not found</h1>')
})

app.listen(3000 , () => {
    console.log('Server Start')
})