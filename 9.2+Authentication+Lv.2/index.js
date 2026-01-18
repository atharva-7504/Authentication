import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";

const app = express();
const port = 3000;
const saltRounds = 10;

const db = new pg.Client({
  user:"postgres",
  host:"localhost",
  database:"secrets",
  password:"atharva_7504",
  port:5432,
})
db.connect();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

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
  const email = req.body.username;
  const password = req.body.password;
  try{
    // Condition to check whether email already exist in DB
    const CheckResult = await db.query("SELECT * FROM users WHERE email = $1;",[email]);
    //If present CheckResult.rows.length = 1
    if (CheckResult.rows.length > 0){
      res.send("Email Already Registered ! ,Try Logging in.");
    }else{  
      // Password hashing 
      bcrypt.hash(password,saltRounds, async (err,hash)=>{
        if(err){
          console.log("Error Hashing Password:",err);
        }else{
          const result = await db.query("INSERT INTO users (email,password) VALUES ($1,$2);" , [email,hash]);
          res.render("secrets.ejs");
        }
      });
    }
  }catch(error){
    console.log(error);
  }
});

app.post("/login", async (req, res) => {
  const email = req.body.username;
  const LoginPassword = req.body.password;
  try{
    const CheckResult = await db.query("SELECT * FROM users WHERE email= $1;",[email]);
    if (CheckResult.rows.length > 0){
      const user = CheckResult.rows[0];
      const storedHashedPassword = user.password;

      bcrypt.compare(LoginPassword,storedHashedPassword,(err,result)=>{
        if(err){
          console.log(err);
        }else{
            if(result){
              res.render("secrets.ejs");
            }else{
              res.send("Password Incorrect! Please Try Again.")
            }
        }
      })
      
    }else{
      res.send("Email Does not Exist,Try to register !")
    }
  }catch(error){
    console.log(error);
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
