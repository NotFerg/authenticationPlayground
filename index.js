import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized:true,
  cookie:{
    maxAge:1000 * 60 * 60 * 24,
  },
}));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
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

app.get("/secrets",(req,res)=>{
  console.log(req.user);
  if(req.isAuthenticated()){
    res.render("secrets.ejs");
  }else{
    res.redirect("/login");
  }
})

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
            "INSERT INTO users (email,password) VALUES ($1,$2) RETURNING *",
            [userName, hash]
          );
          const user = result.rows[0];
          req.login(user,(err)=>{
            console.log(err);
            res.redirect("/secrets");
          })
        }
      });
    }
  } catch (e) {
    console.log(e);
  }
});

app.post("/login", passport.authenticate("local",
  {  
    successRedirect: "/secrets",
    failureRedirect: "/login",
  }));

passport.use(new Strategy(
  async function verify(username,password,cb){
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
  
        bcrypt.compare(password, storedHashedPassword, (err, result) => {
          if (err) {
           return cb(err);
          } 
          else {
            if (result) {
              return cb(null,user);
            } else {
              return cb(null,false);
            }
          }
        });
      } else {
        return cb ("User not found");
      }
    } catch (e) {
      return cb(e);
    }
  }
));

passport.serializeUser((user,cb)=>{
  cb(null,user);
})

passport.deserializeUser((user,cb)=>{
  cb(null,user);
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
