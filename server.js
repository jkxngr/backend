const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(
  cors({
    origin: "http://localhost:5173",
    methods: ["GET", "POST", "PUT", "DELETE"],
  })
);

let db;
const initializeDatabase = async () => {
  try {
    db = await mysql.createPool({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      waitForConnections: true,
      connectionLimit: 10000,
      queueLimit: 0,
    });
    console.log("Database connected");
  } catch (err) {
    console.error("Failed to connect to database:", err);
    process.exit(1);
  }
};

initializeDatabase();
app.get("/", (req, res) => {
  res.send("API is running");
});
const validateUserMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).send("Unauthorized");

  try {
    const decoded = jwt.verify(token, "your-secret-key");

    const [rows] = await db.query(
      "SELECT * FROM users WHERE id = ? AND status = 'active'",
      [decoded.userId]
    );

    if (rows.length === 0) {
      return res.status(403).send("User is blocked or does not exist");
    }

    req.user = rows[0];
    next();
  } catch (err) {
    res.status(401).send("Invalid token");
  }
};
app.get("/auth/validate", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).send("Unauthorized");
  }
  try {
    const decoded = jwt.verify(token, "your-secret-key");
    const [rows] = await db.query(
      "SELECT * FROM users WHERE id = ? AND status = 'active'",
      [decoded.userId]
    );
    if (rows.length === 0) {
      return res.status(403).send("Your account is blocked.");
    }
    res.status(200).send("User is valid");
  } catch (err) {
    res.status(401).send("Invalid token");
  }
});

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).send("Name, email, and password are required");
  }
  try {
    const registrationTime = new Date();
    await db.query(
      "INSERT INTO users (name, email, password, registration_time) VALUES (?, ?, ?, ?)",
      [name, email, password, registrationTime]
    );
    res.status(201).send("User registered successfully");
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") {
      return res.status(409).send("Email already in use");
    }
    console.error("Error during registration:", err);
    res.status(500).send("Error during registration");
  }
});
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).send("Email and password are required");
  }
  try {
    const [rows] = await db.query(
      "SELECT * FROM users WHERE email = ? AND password = ?",
      [email, password]
    );
    if (rows.length > 0) {
      const user = rows[0];
      if (user.status === "blocked") {
        return res.status(403).send("Your account is blocked");
      }
      const currentLoginTime = new Date();
      await db.query("UPDATE users SET last_login = ? WHERE id = ?", [
        currentLoginTime,
        user.id,
      ]);

      const token = jwt.sign({ userId: user.id }, "22f39c8400662f62ef2f6227e3526a44a1491686409f9b0d2ea64b4d551153d7", {
        expiresIn: "1h",
      });
      const { password: _, ...userData } = user;
      res.json({ token, user: userData });
    } else {
      res.status(401).send("Invalid credentials");
    }
  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).send("Error during login");
  }
});

app.get("/users", async (req, res) => {
  try {
    const [rows] = await db.query("SELECT * FROM users");
    res.json(rows);
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).send("Error fetching users");
  }
});
app.post("/block", validateUserMiddleware, async (req, res) => {
  const { userIds } = req.body;

  if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
    return res.status(400).send("No user IDs provided");
  }

  try {
    await db.query('UPDATE users SET status = "blocked" WHERE id IN (?)', [
      userIds,
    ]);
    res.status(200).send("Users blocked successfully");
  } catch (err) {
    console.error("Error blocking users:", err);
    res.status(500).send("Error blocking users");
  }
});
app.post("/unblock", validateUserMiddleware, async (req, res) => {
  const { userIds } = req.body;

  if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
    return res.status(400).send("No user IDs provided");
  }

  try {
    await db.query('UPDATE users SET status = "active" WHERE id IN (?)', [
      userIds,
    ]);
    res.status(200).send("Users unblocked successfully");
  } catch (err) {
    console.error("Error unblocking users:", err);
    res.status(500).send("Error unblocking users");
  }
});
app.post("/delete", validateUserMiddleware, async (req, res) => {
  const { userIds } = req.body;
  if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
    return res.status(400).send("No user IDs provided");
  }
  try {
    await db.query("DELETE FROM users WHERE id IN (?)", [userIds]);
    res.status(200).send("Users deleted successfully");
  } catch (err) {
    console.error("Error deleting users:", err);
    res.status(500).send("Error deleting users");
  }
});
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));
