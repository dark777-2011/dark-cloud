const express = require("express");
const cors = require("cors");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { v4: uuid } = require("uuid");

const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const DiscordStrategy = require("passport-discord").Strategy;
const session = require("express-session");

const app = express();

/* ================= CORS FIX ================= */
app.use(cors({
  origin: "https://dark-cloud-4.onrender.com",
  methods: ["GET", "POST", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json());
app.use(express.static(__dirname));

app.use(session({
  secret: "dark_secret",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((obj, done) => {
  done(null, obj);
});

/* ================= SECRET ================= */
const SECRET = process.env.SECRET || "my_secret_key";

/* ================= UPLOAD FOLDER ================= */
const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR);
}

/* ================= DATABASE (TEMP) ================= */
let users = [];
let files = [];

/* ================= AUTH ================= */
function auth(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).send("no token");
  }

  try {
    req.user = jwt.verify(token.split(" ")[1], SECRET);
    next();
  } catch (err) {
    return res.status(401).send("invalid token");
  }
}

/* ================= REGISTER ================= */
app.post("/register", async (req, res) => {
  const { user, pass } = req.body;

  if (!user || !pass) {
    return res.status(400).send("missing data");
  }

  const hash = await bcrypt.hash(pass, 10);

  users.push({
    id: uuid(),
    user,
    pass: hash,
    role: "user"
  });

  res.json({ ok: true });
});

/* ================= LOGIN ================= */
app.post("/login", async (req, res) => {
  const { user, pass } = req.body;

  const u = users.find(x => x.user === user);
  if (!u) return res.status(400).send("wrong");

  const ok = await bcrypt.compare(pass, u.pass);
  if (!ok) return res.status(400).send("wrong");

  const token = jwt.sign(
    { id: u.id, user: u.user, role: u.role },
    SECRET
  );

  res.json({ token });
});

/* ================= GOOGLE AUTH ================= */

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "https://dark-cloud-4.onrender.com/auth/google/callback"
  },
  (accessToken, refreshToken, profile, done) => {

    return done(null, {
      id: profile.id,
      name: profile.displayName,
      email: profile.emails?.[0]?.value
    });

  }
));

app.get("/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"]
  })
);

app.get("/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/"
  }),
  (req, res) => {

    res.redirect("https://dark-cloud-4.onrender.com/");

  }
);

/* ================= DISCORD AUTH ================= */

passport.use(new DiscordStrategy({
    clientID: "1509982149149724914",
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    callbackURL: "https://dark-cloud-4.onrender.com/auth/discord/callback",
    scope: ["identify", "email"]
  },
  (accessToken, refreshToken, profile, done) => {
    return done(null, {
      id: profile.id,
      name: profile.username
    });
  }
));

app.get("/auth/discord",
  passport.authenticate("discord")
);

app.get("/auth/discord/callback",
  passport.authenticate("discord", {
    failureRedirect: "/"
  }),
  (req, res) => {

    res.redirect("https://dark-cloud-4.onrender.com/");

  }
);

/* ================= MULTER ================= */
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  }
});

const upload = multer({ storage });

/* ================= UPLOAD (FIXED) ================= */
app.post("/upload", upload.single("file"), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).send("no file uploaded");
    }

    const id = uuid();

    const file = {
      id,
      name: req.file.originalname,
      file: req.file.filename,
      owner: "public",
      time: Date.now()
    };

    files.push(file);

    res.json({
      id,
      url: `/file/${id}`
    });

  } catch (err) {
    console.error(err);
    res.status(500).send("upload error");
  }
});

/* ================= GET USER FILES ================= */
app.get("/my-files", auth, (req, res) => {
  res.json(files);
});

/* ================= ADMIN ================= */
app.get("/admin", auth, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).send("no access");
  }

  res.json({ users, files });
});

/* ================= DOWNLOAD ================= */
app.get("/file/:id", (req, res) => {
  const file = files.find(f => f.id === req.params.id);

  if (!file) {
    return res.status(404).send("not found");
  }

  res.download(
    path.join(UPLOAD_DIR, file.file),
    file.name
  );
});

/* ================= START SERVER ================= */
const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log("🚀 running on port " + port);
});

