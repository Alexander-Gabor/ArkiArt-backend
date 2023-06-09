import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import crypto from "crypto";
import bcrypt from "bcrypt";

const mongoUrl = process.env.MONGO_URL || "mongodb://127.0.0.1/ArkiArt";
mongoose.connect(mongoUrl, { useNewUrlParser: true, useUnifiedTopology: true });
mongoose.Promise = Promise;

// Defines the port the app will run on. Defaults to 8080, but can be overridden
// when starting the server. Example command to overwrite PORT env variable value:
// PORT=9000 npm start
const port = process.env.PORT || 8080;
const app = express();
const listEndpoints = require('express-list-endpoints');

// Add middlewares to enable cors and json body parsing
app.use(cors());
app.use(express.json());

// Middlewares 

const authenticateUser = async (req, res, next) => {
  const accessToken = req.header("Authorization");
  console.log("accessToken:", accessToken);
  try {
    const user = await User.findOne({ accessToken: accessToken });
    console.log("user:", user);
    if (user) {
      next();
    } else {
      res.status(403).json({
        success: false,
        response: null,
        message: "Please log in"
      });
    }
  } catch (e) {
    console.error("authenticateUser Error:", e);
    res.status(500).json({
      success: false,
      response: null,
      message: "Internal server error",
      error: e.errors
    });
  }
};

// Routes
// Start of routes
app.get("/", (req, res) => {
  res.json(listEndpoints(app));
});

// Register route

app.post("/register", async (req, res) => {
  console.log("Received POST /register with body:", req.body);
  const { username, password } = req.body;
  //to make sure a password is created
  if (!password) {
    return res.status(400).json({
      success: false,
      response: "Password is required",
    });
  }
 //ensure password is at least 6 characters long
  if (password.length < 6) { 
    return res.status(400).json({
      success: false,
      response: "Password needs to be at least 6 characters long",
    });
  }
  try {
    const salt = bcrypt.genSaltSync();
    const newUser = await new User({
      username: username,
      password: bcrypt.hashSync(password, salt), // obscure the password
    }).save();
    res.status(201).json({
      success: true,
      response: {
        username: newUser.username,
        id: newUser._id,
        accessToken: newUser.accessToken,
      },
      message: "User created successfully"
    });
  } catch (e) {
    res.status(400).json({
      success: false,
      response: "Could not create user", error: e.errors
    });
  }
});

// Login Route

app.post("/login", async (req, res) => {
  console.log("Received POST /login with body:", req.body);
  const { username, password } = req.body;
  try {
    // tell us if the password that user put is the same that we have in the data base
    const user = await User.findOne({ username: username });

    if (user && bcrypt.compareSync(password, user.password)) {
      res.status(200).json({
        success: true,
        response: {
          username: user.username,
          id: user._id,
          accessToken: user.accessToken,
        },
        message: "User logged in successfully"
      });
    } else {
      res.status(400).json({
        success: false,
        response: "Credentials do not match",
        message: "Credentials do not match",
        error: null
      });
    }
  } catch (e) {
    res.status(500).json({
      success: false,
      response: "Internal server error",
      message: "Internal server error",
      error: e.errors
    });
  }
});

// Logout Route

app.post("/logout", authenticateUser, async (req, res) => {
  console.log("Received POST /logout with body:", req.body);
  const accessToken = req.header("Authorization");
  try {
    const user = await User.findOne({ accessToken: accessToken });
    if (user) {
      user.accessToken = null;
      await user.save();
      res.status(200).json({
        success: true,
        response: null,
        message: "User logged out successfully"
      });
    } else {
      res.status(400).json({
        success: false,
        response: "Could not find user",
        message: "Could not find user",
        error: null
      });
    }
  } catch (e) {
    res.status(500).json({
      success: false,
      response: "Internal server error",
      message: "Internal server error",
      error: e.errors
    });
  }
});

// Models & schemas

// 1. User schema

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    minlength: 2,
    maxlength: 14
  },
  password: {
    type: String,
    required: true
  },
  accessToken: {
    type: String,
    default: () => crypto.randomBytes(128).toString("hex")
  }
});

const User = mongoose.model("User", userSchema);


// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
