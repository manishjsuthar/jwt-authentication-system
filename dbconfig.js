const { Pool } = require("pg");
const bcrypt = require("bcryptjs");

const pool = new Pool({
  user: "postgres",
  host: "localhost",
  password: "root",
  database: "testdb",
  port: 5432,
});

pool.connect().then(() => console.log("Connected"));
module.exports = pool;