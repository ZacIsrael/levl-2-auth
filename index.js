// Import the Express framework to create the web server and handle routing
import express from "express";

// Import body-parser to parse incoming request bodies (used to read form input values from req.body)
import bodyParser from "body-parser";

// Import the PostgreSQL client module to interact with the PostgreSQL database
import pg from "pg";

// Import bcrypt to hash passwords securely (automatically adds a salt and hashes it)
import bcrypt from "bcrypt";

// Define the number of salt rounds to be used with bcrypt for hashing passwords
const saltRounds = 10;

// Import the dotenv library to load environment variables from a .env file into process.env
import dotenv from "dotenv";
dotenv.config(); // Load the environment variables as soon as the app starts

// Initialize the Express application
const app = express();

// Define the port the server will listen on
const port = 3000;

// Set EJS (Embedded JavaScript Templates) as the templating engine for rendering views
app.set("view engine", "ejs");

// Middleware to parse form data submitted through HTTP POST (extended: true allows for rich objects and arrays)
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files (like CSS, images, JS) from the "public" directory
app.use(express.static("public"));

// Initialize a new PostgreSQL client with credentials retrieved from environment variables
const db = new pg.Client({
  user: process.env.PG_USERNAME, // PostgreSQL username (stored in .env)
  host: "localhost", // database server address (localhost since it runs locally)
  database: "authentication-practice", // name of the database to connect to
  password: process.env.PG_PASSWORD, // PostgreSQL password (stored in .env)
  port: 5432, // default PostgreSQL port
});

// Connect to the PostgreSQL database
db.connect();

// Routes

// GET request to homepage route ("/") — renders home page
app.get("/", (req, res) => {
  res.render("home.ejs"); // Render the 'home.ejs' template
});

// GET request to "/login" — renders the login form
app.get("/login", (req, res) => {
  res.render("login.ejs"); // Render the 'login.ejs' template
});

// GET request to "/register" — renders the registration form
app.get("/register", (req, res) => {
  res.render("register.ejs"); // Render the 'register.ejs' template
});

// POST request to "/register" — handles new user registration logic
app.post("/register", async (req, res) => {
  const email = req.body.username; // Extract the email from the form field named 'username'
  const password = req.body.password; // Extract the password from the form field named 'password'

  try {
    // Check if a user with the same email already exists in the database
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      // Email is already in use — prompt user to log in instead
      res.send("Email already exists. Try logging in.");
    } else {
      // If the email doesn't exist, hash the user's password before saving it to the DB:
      // - password: the plain text password input from the user
      // - saltRounds: the cost factor that determines how computationally expensive the hashing process is
      //      • Higher numbers are more secure but take more time (default recommendation is 10)
      //      • bcrypt internally generates a random salt for you when you provide a saltRounds number
      // - callback: a function that receives either an error (err) or the resulting hashed password (hash)
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          // If bcrypt throws an error while hashing, log it for debugging
          console.error(`(/register) error hashing password: `, err.stack);
        } else {
          // Insert new user into the 'users' table with the hashed password
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)",
            [email, hash]
          );
          console.log(result); // Optional: log result of INSERT query
          res.render("secrets.ejs"); // After successful registration, render a protected page (secrets)
        }
      });
    }
  } catch (err) {
    // If there's an error with the DB query, log the error
    console.log(err);
  }
});

// POST request to "/login" — handles user login/authentication
app.post("/login", async (req, res) => {
  // Extract the email and password from the submitted login form
  const email = req.body.username;
  const password = req.body.password;

  try {
    // Look up the user in the database by their email
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (result.rows.length > 0) {
      // A user with the given email exists
      const user = result.rows[0];
      const storedHashedPassword = user.password; // This is the hashed password from the database

      // Compare the entered plain-text password with the hashed password from the database
      // bcrypt.compare() will:
      // - Hash the input password using the same salt that was used to generate the stored hash
      // - Return true if they match, false otherwise
      const passwordMatch = await bcrypt.compare(
        password,
        storedHashedPassword
      );

      if (passwordMatch) {
        // If the passwords match, login is successful — show the secrets page
        res.render("secrets.ejs");
      } else {
        // If the passwords don't match, send error message
        res.send("Incorrect Password");
      }
    } else {
      // If no user with that email exists, let the user know
      res.send("User not found");
    }
  } catch (err) {
    // Catch and log any errors that occur during the database lookup or password comparison
    console.log(err);
    res.send("An error occurred. Please try again later.");
  }
});

// Start the server and listen on the specified port
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
