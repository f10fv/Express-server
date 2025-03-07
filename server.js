const express = require("express");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcryptjs");
const auth = require("basic-auth");
require("dotenv").config();
const app = express();
const prisma = new PrismaClient();

app.use(express.json());

const authenticate = async (req, res, next) => {
  const credentials = auth(req);
  if (!credentials) return res.status(401).json({ error: "Unauthorized" });

  console.log("Received Credentials:", credentials); 

  const user = await prisma.user.findUnique({
    where: { username: credentials.name },
  });

  console.log("Existing User Found:", user); 

  if (!user) {
    return res.status(401).json({ error: "User not found" });
  }

  const passwordMatch = await bcrypt.compare(credentials.pass, user.password);
  if (!passwordMatch) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  next();
};

app.get("/", (req, res) => {
  res.send("Welcome to my Express API!");
});

app.get("/health", (req, res) => {
  res.json({ status: "OK" });
});


app.get("/users", authenticate, async (req, res) => {
  const users = await prisma.user.findMany({ select: { id: true, username: true} });
  res.json(users);
});

app.post("/users", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Missing fields" });

  const existingUser = await prisma.user.findUnique({
    where: { username },
  });

  console.log("Existing User Found:", existingUser);

  if (existingUser) {
    return res.status(400).json({ error: "Username already taken, choose another" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const newUser = await prisma.user.create({
      data: { username, password: hashedPassword },
    });
    res.status(201).json({ id: newUser.id, username: newUser.username });
  } catch (error) {
    console.error("Database Error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});


const PORT = process.env.PORT || 8080;
app.listen(PORT, "0.0.0.0", () => console.log(`Server running on port ${PORT}`));


