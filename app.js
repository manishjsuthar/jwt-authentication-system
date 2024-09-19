const express = require("express");
const jwt = require("jsonwebtoken");
const pool = require("./dbconfig");
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json());

const SECRET_KEY = "veryverysecret";
const PORT = 3002;

function authenticateToken(req, res, next) {
  const token = req.header("Authorization")?.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      message: "Unauthorized user",
    });
  }
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(401).json({
        message: "Unauthorized user",
      });
    }
    console.log("user ", user);
    req.user = user;
    next();
  });
}

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (username.length <= 5) {
    return res.status(402).json({
      message: "Username must be greater than 5",
    });
  }
  if (password.length <= 5) {
    return res.status(402).json({
      message: "password must be greater than 5",
    });
  }
  try {
    const userExist = await pool.query(
      `SELECT * FROM users WHERE username=$1`,
      [username]
    );
    if (userExist.rows.length > 0) {
      return res.status(400).json({
        message: "User already exist",
      });
    }

    let salt = 10;
    const hashedPassword = await bcrypt.hash(password, salt);

    await pool.query(`INSERT INTO users (username, password) VALUES ($1, $2)`, [
      username,
      hashedPassword,
    ]).catch((e) => {
        console.log("error in creating user ", e)
    })
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(404).json({ message: "Server Error", error });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const userData = await pool.query(
      `SELECT * FROM users WHERE  username=$1`,
      [username]
    );

    if (userData.rows.length === 0) {
      return res.status(400).json({ message: "User not found" });
    }
    const user = userData.rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(400).json({ message: "Incorrect password" });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      SECRET_KEY,
      {
        expiresIn: "1h",
      }
    );

    return res.json({
      message: "Logged in successful",
      token,
    });
  } catch (error) {
    return res.status(400).json({ message: "Incorrect password" });
  }
});

//proteccted route
app.get("/profile", authenticateToken, (req, res) => {
  return res.json({
    message: "This is user profile data",
    user: req.user,
  });
});

app.listen(PORT, () => {
  console.log(`App is listening on PORT : ${PORT}`);
});
