// index.js
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const app = express();
app.use(cors());
app.use(express.json());
const { ObjectId } = require("mongodb");

// ---------------- DB CONNECT ----------------
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
const db = mongoose.connection;
db.on("error", console.error.bind(console, "❌ MongoDB connection error:"));
db.once("open", () => console.log("✅ MongoDB connected"));

// Middlewares
app.use(
  cors({
    origin: "http://localhost:8081", // frontend origin
    credentials: true, // ✅ allow cookies
  })
);

// ---------------- USER MODEL ----------------
const userSchema = new mongoose.Schema({
  userid: String,
  email: { type: String, required: true, unique: true },
  password: String,
});
const User = mongoose.model("User", userSchema);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";

// ---------------- REGISTER ----------------
app.post("/api/register", async (req, res) => {
  try {
    const { userid, email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password required" });
    }

    // check if user exists
    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ error: "User already exists" });
    }

    // save user (plain password for now)
    const newUser = new User({ userid, email, password });
    await newUser.save();

    res.status(201).json({ message: "User registered", user: newUser });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------------- LOGIN ----------------
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password required" });
    }

    // find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: "Invalid Username" });
    }

    // check password (plain text for now)
    if (user.password !== password) {
      return res.status(400).json({ error: "Invalid Password" });
    }

    // generate JWT
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({ success: true, token, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------------- CREATE COLLECTION API ----------------
app.post("/api/create-collection", async (req, res) => {
  try {
    const { collection } = req.body;

    if (!collection) {
      return res.status(400).json({ error: "Table (collection) name is required" });
    }

    const safeCollection = collection.toLowerCase().replace(/[^a-z0-9_]/g, "");
    if (!safeCollection) {
      return res.status(400).json({ error: "Invalid collection name" });
    }

    // ✅ Check if collection already exists
    const collections = await mongoose.connection.db
      .listCollections({ name: safeCollection })
      .toArray();

    if (collections.length > 0) {
      return res.json({
        success: true,
        message: `Collection '${safeCollection}' already exists`,
      });
    }

    // 🚀 Create new collection
    await mongoose.connection.db.createCollection(safeCollection);

    res.status(201).json({
      success: true,
      message: `Collection '${safeCollection}' created successfully`,
    });
  } catch (err) {
    console.error("Collection create error:", err);
    res.status(500).json({ error: err.message });
  }
});


// ---------------- COMMON SAVE API ----------------
// CREATE
app.post("/api/save", async (req, res) => {
  try {
    const { collection, data } = req.body;
    if (!collection || !data) {
      return res.status(400).json({ error: "Collection and data are required" });
    }

    // Dynamic collection
    const Model = mongoose.connection.collection(collection);

    // Convert string IDs to ObjectId where needed
    const convertToObjectId = (val) => {
      if (typeof val === "string" && /^[0-9a-fA-F]{24}$/.test(val)) {
        return new ObjectId(val);
      }
      return val;
    };

    // Loop through all fields of data
    Object.keys(data).forEach((key) => {
      data[key] = convertToObjectId(data[key]);
    });

    // Insert document
    const result = await Model.insertOne(data);

    res.status(201).json({
      message: "Row inserted",
      insertedId: result.insertedId,
    });
  } catch (err) {
    console.error("Save API error:", err);
    res.status(500).json({ error: err.message });
  }
});

// READ
app.post("/api/read", async (req, res) => {
  try {
    const { collection, filter, fields } = req.body;

    if (!collection) {
      return res.status(400).json({ error: "Collection is required" });
    }

    // Default filter = {} (fetch all documents)
    const queryFilter = filter || {};
    const projection = fields || {}; // default = all fields

    const result = await db
      .collection(collection)
      .find(queryFilter, { projection })
      .toArray();

    res.json(result);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});




// ---------------- START SERVER ----------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
