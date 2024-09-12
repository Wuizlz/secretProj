import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import env from "dotenv";
import GoogleStrategy from "passport-google-oauth20"

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie:
    {
      maxAge: 1000 * 60 * 60 * 24
    }
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
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

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secrets", async (req, res) => {
  // console.log(req.user);
  if (req.isAuthenticated()) {
    try
    {

    const username = req.user.username
    const result = await db.query("SELECT text FROM users WHERE username = $1 ",
      [username]
    )
    if(result.rows[0].text)
    {
      res.render("secrets.ejs",
        {
          secret: result.rows[0].text
        })
    }
    else
    {
      res.render("secrets.ejs",
        {
          secret: "I dont have a secret!"
        }
      )
    }
     } catch (err)
      {
        console.log(err)
        console.error("Database query failed: ", err);
        res.status(500).send("Error retrieving secrets.");
      }
     } else {
    res.redirect("/login");
  }
});

app.get("/auth/google", passport.authenticate("google", {
  scope: ["profile", "email"],
  
})
)

app.get("/auth/google/secrets", passport.authenticate("google", 
  {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  }
))

app.get("/submit", (req,res) =>
{
  res.render("submit.ejs");
})

app.post("/submit", async (req,res) =>
{
  const user = req.user.username
  const text = req.body.secret
  try
  {
  const result = await db.query("UPDATE users SET text = $1 WHERE username = $2 RETURNING *",
    [text,user]
  )
   // Check if the query was successful
   if (result.rows.length > 0) {
    console.log("Secret updated for user:", user); // Debugging log
  } else {
    console.error("Failed to update secret for user:", user);
  }
  res.redirect("/secrets")
}
catch(err)
{
  console.log(err);
  console.error(err);
  res.send("An error occurred while submitting.");
}
})


app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE username = $1", [
      username,
    ]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *",
            [username, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
  
    console.log(err);
  }
});

passport.use("local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE username = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            //Error with password check
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              //Passed password check
              return cb(null, user);
            } else {
              //Did not pass password check
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);
passport.use("google", new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  async (accessToken, refreshToken, profile, cb) => {
    console.log(profile);
    try {
      // Corrected the query, added a comma after the query string
      const result = await db.query("SELECT * FROM users WHERE username = $1", [profile.emails[0].value]);

      if (result.rows.length === 0) {
        const newUser = await db.query(
          "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *",
          [profile.emails[0].value, "google"]
        );
        // Use parentheses for calling the callback
        return cb(null, newUser.rows[0]);
      } else {
        return cb(null, result.rows[0]);
      }
    } catch (err) {
      return cb(err);
    }
  }
));

passport.serializeUser((user, cb) => {
  cb(null, user);
});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`)
  })
