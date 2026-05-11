require("dotenv").config();

const express = require("express");
const session = require("express-session");
const MongoDBStore = require("connect-mongodb-session")(session);
const bcrypt = require("bcrypt");
const Joi = require("joi");
const { MongoClient } = require("mongodb");

const app = express();

// Ejs & middleware
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
app.use(express.static("public"));

const store = new MongoDBStore({
  uri: `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}`,
  collection: "sessions",
});

store.on("error", (error) => console.log(error));

app.use(
  session({
    secret: process.env.NODE_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store,
    cookie: { maxAge: 1000 * 60 * 60 },
  }),
);

let db;

const client = new MongoClient(
  `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}`,
);

async function startServer() {
  await client.connect();
  db = client.db(process.env.MONGODB_DATABASE);
  console.log("MongoDB successfully connected.");

  const port = process.env.PORT || 3000;
  app.listen(port, () =>
    console.log(`Server running at http://localhost:${port}`),
  );
}

// Authorization helpers
function isLoggedIn(req) {
  return req.session && req.session.loggedIn;
}

function requireLogin(req, res, next) {
  if (!isLoggedIn(req)) return res.redirect("/");
  next();
}

function requireAdmin(req, res, next) {
  if (!isLoggedIn(req)) return res.redirect("/login");
  if (req.session.user_type !== "admin") {
    return res.status(403).render("403", {
      message: "Not authorized",
      active: "admin",
    });
  }
  next();
}

// Home
app.get("/", (req, res) => {
  if (!req.session.loggedIn) {
    return res.render("index", { loggedIn: false, active: "home" });
  }

  res.render("index", {
    loggedIn: true,
    name: req.session.name,
    active: "home",
  });
});

// Signup
app.get("/signup", (req, res) => {
  res.render("signup", { error: null, active: "signup" });
});

app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.render("signup", {
      error: "Sorry! You cannot leave any fields blank.",
      active: "signup",
    });
  }

  const schema = Joi.object({
    name: Joi.string().max(20).required(),
    email: Joi.string().email().max(50).required(),
    password: Joi.string().max(20).required(),
  });

  const validation = schema.validate({ name, email, password });
  if (validation.error) {
    return res.render("signup", { error: "Invalid input.", active: "signup" });
  }

  const users = db.collection("users");
  const hashedPassword = await bcrypt.hash(password, 10);

  await users.insertOne({
    name,
    email,
    password: hashedPassword,
    user_type: "user",
  });

  req.session.loggedIn = true;
  req.session.name = name;
  req.session.email = email;
  req.session.user_type = "user";

  res.redirect("/members");
});

// Login
app.get("/login", (req, res) => {
  res.render("login", { error: null, active: "login" });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.render("login", {
      error: "Email and password required.",
      active: "login",
    });
  }

  const schema = Joi.object({
    email: Joi.string().email().max(50).required(),
    password: Joi.string().max(20).required(),
  });

  const validation = schema.validate({ email, password });
  if (validation.error) {
    return res.render("login", { error: "Invalid input.", active: "login" });
  }

  const users = db.collection("users");
  const user = await users.findOne({ email });

  if (!user) {
    return res.render("login", {
      error: "Invalid email/password combination.",
      active: "login",
    });
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.render("login", {
      error: "Invalid email/password combination.",
      active: "login",
    });
  }

  req.session.loggedIn = true;
  req.session.name = user.name;
  req.session.email = user.email;
  req.session.user_type = user.user_type;

  res.redirect("/members");
});

// Members
app.get("/members", requireLogin, (req, res) => {
  const images = [
    "/images/bunny1.jpg",
    "/images/bunny2.jpg",
    "/images/bunny3.jpg",
  ];

  res.render("members", {
    name: req.session.name,
    images,
    active: "bunnies",
  });
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// Admin
app.get("/admin", requireAdmin, async (req, res) => {
  const usersCollection = db.collection("users");
  const users = await usersCollection.find({}).toArray();

  res.render("admin", { users, active: "admin" });
});

// Promote
app.get("/promote/:email", requireAdmin, async (req, res) => {
  const schema = Joi.string().email().max(50).required();
  const validation = schema.validate(req.params.email);
  if (validation.error) return res.redirect("/admin");

  const usersCollection = db.collection("users");
  await usersCollection.updateOne(
    { email: req.params.email },
    { $set: { user_type: "admin" } },
  );

  res.redirect("/admin");
});

// Demote
app.get("/demote/:email", requireAdmin, async (req, res) => {
  const schema = Joi.string().email().max(50).required();
  const validation = schema.validate(req.params.email);
  if (validation.error) return res.redirect("/admin");

  const usersCollection = db.collection("users");
  await usersCollection.updateOne(
    { email: req.params.email },
    { $set: { user_type: "user" } },
  );

  res.redirect("/admin");
});

// 404
app.use((req, res) => {
  res.status(404).render("404", { active: "404" });
});

startServer();
