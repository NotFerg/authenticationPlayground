import express from "express";
import pg from "pg";

const app = express();
const port = 3000;

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
      const result = await db.query(
        "INSERT INTO users (email,password) VALUES ($1,$2)",
        [userName, password]
      );
      res.render("secrets.ejs");
    }
  } catch (e) {
    console.log(e);
  }
});

app.post("/login", async (req, res) => {
  let userName = req.body.username;
  let password = req.body.password;

  try {
    const result = await db.query(
      "SELECT * FROM users WHERE email = $1 AND password = $2",
      [userName, password]
    );
    if (result.rows.length > 0) {
       const user = result.rows[0];
       const storedPassword = user.password;

       if(storedPassword === password){
         res.render("secrets.ejs");
       }else{
          res.send("password is incorrect");
       }
    } 
    else {
      res.send("user not found")
    }
  } catch (e) {
    console.log(e);
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
