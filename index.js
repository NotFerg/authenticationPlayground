import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";

const app = express();
const port = 3000;
const saltRounds = 10;

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "secrets",
  password: "root",
  port: 5432,
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.post("/register", async (req, res) => {
  let userName = req.body.username;
  let password = req.body.password;
  try {
    const checkEmail = await db.query("SELECT * FROM users WHERE email = $1", [
      userName,
    ]);

    if (checkEmail.rows.length > 0) {
      res.send("Email already exists");
    } else {
      // Hash the password
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.log(err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email,password) VALUES ($1,$2)",
            [userName, hash]
          );
          res.render("secrets.ejs");
        }
      });
    }
  } catch (e) {
    console.log(e);
  }
});

app.post("/login", async (req, res) => {
  let userName = req.body.username;
  let loginPassword = req.body.password;

  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      userName,
    ]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashedPassword = user.password;

      bcrypt.compare(loginPassword, storedHashedPassword, (err, result) => {
        if (err) {
          console.log("Error comparing passwords", err);
        } 
        else {
          if (result) {
            res.render("secrets.ejs");
          } else {
            res.send("Incorrect password");
          }
        }
      });
    } else {
      res.send("user not found");
    }
  } catch (e) {
    console.log(e);
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
