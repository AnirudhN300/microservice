const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();

app.use(express.json());
app.use(cors());

const db = mysql.createConnection({
  host: "mysql",
  user: "root",
  password: "root123",
  database: "usersdb"
});

db.connect(err => {
  if (err) {
    console.log(err);
  } else {
    console.log("MySQL Connected");
  }
});

app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  db.query(
    "INSERT INTO users (email, password) VALUES (?, ?)",
    [email, hashedPassword],
    (err, result) => {
      if (err) return res.status(500).send(err);

      res.send("User Registered");
    }
  );
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) return res.status(500).send(err);

      if (results.length === 0) {
        return res.status(401).send("User not found");
      }

      const user = results[0];

      const valid = await bcrypt.compare(password, user.password);

      if (!valid) {
        return res.status(401).send("Invalid password");
      }

      const token = jwt.sign(
        { id: user.id, email: user.email },
        "secretkey",
        { expiresIn: "1h" }
      );

      res.json({ token });
    }
  );
});

app.listen(3000, () => {
  console.log("Auth Service running on port 3000");
});
