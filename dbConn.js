const mysql = require('mysql2')

const conn = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'login_register_nodejs'
}).promise()

module.exports = conn;