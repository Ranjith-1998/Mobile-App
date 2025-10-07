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
//const { v4: uuidv4 } = require("uuid");


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

    // check password (plain text for now — should use bcrypt)
    if (user.password !== password) {
      return res.status(400).json({ error: "Invalid Password" });
    }

    // generate JWT with both userId and email
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      success: true,
      token,
      user: {
        _id: user._id,
        email: user.email,
      },
    });
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

    // ✅ Extract token from Authorization header
    const authHeader = req.headers["authorization"];
    if (!authHeader) {
      return res.status(401).json({ error: "Authorization header missing" });
    }

    const token = authHeader.split(" ")[1]; // Bearer <token>
    if (!token) {
      return res.status(401).json({ error: "Token missing" });
    }

    // ✅ Decode token
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }

    // ✅ Ensure user email is available
    const userEmail = decoded.email;
    if (!userEmail) {
      return res.status(401).json({ error: "Invalid token payload" });
    }

    // ✅ Dynamic collection
    const Model = mongoose.connection.collection(collection);

    // ✅ Convert ObjectId strings
    const convertToObjectId = (val) => {
      if (typeof val === "string" && /^[0-9a-fA-F]{24}$/.test(val)) {
        return new ObjectId(val);
      }
      return val;
    };
    Object.keys(data).forEach((key) => {
      data[key] = convertToObjectId(data[key]);
    });

    // ✅ Add audit fields
    const today = new Date();
    const created_on = new Date(Date.UTC(today.getFullYear(), today.getMonth(), today.getDate()));
    data.created_by = userEmail;
    data.modified_by = userEmail;
    data.created_on = created_on;
    data.modified_on = created_on;
    //data.versionid = uuidv4(); // Unique Version ID like Oracle UUID
    
    // ✅ Insert
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

//------------------REPORTING API-------------------
app.get("/api/report/:slug", async (req, res) => {
  try {
    const slug = req.params.slug;

    // 1️⃣ Find report by slug
    const report = await mongoose.connection
      .collection("reportsql")
      .findOne({ slug });

    if (!report) return res.status(404).json({ error: "Report not found" });

    // 2️⃣ Clone pipeline
    const pipeline = JSON.parse(JSON.stringify(report.pipeline));

    // 3️⃣ Collect placeholders
    const placeholders = [];
    function findPlaceholders(obj) {
      if (typeof obj !== "object" || obj === null) return;
      for (let key in obj) {
        if (typeof obj[key] === "string" && /^__.*__$/.test(obj[key])) {
          placeholders.push({ path: key, value: obj[key], parent: obj });
        } else if (typeof obj[key] === "object") {
          findPlaceholders(obj[key]);
        }
      }
    }
    pipeline.forEach(stage => findPlaceholders(stage));

    // 4️⃣ Replace placeholders
    for (let ph of placeholders) {
      const paramName = ph.value.replace(/__/g, "").toLowerCase(); // "__SD__" -> "sd"

      if (paramName === "date_range") {
        // Expect query params: sd=dd-mm-yyyy, ed=dd-mm-yyyy
        const { sd, ed } = req.query;
        if (!sd || !ed) {
          return res.status(400).json({
            error: "Please provide sd and ed query parameters (dd-mm-yyyy)"
          });
        }

        const parseDate = (str, endOfDay = false) => {
          const [day, month, year] = str.split(/[-\/]/);
          const d = new Date(Date.UTC(year, month - 1, day));
          if (endOfDay) d.setUTCHours(23, 59, 59, 999);
          return d;
        };

        const startDate = parseDate(sd);
        const endDate = parseDate(ed, true);

        ph.parent[ph.path] = { $gte: startDate, $lte: endDate };

      } else if (paramName === "sd" || paramName === "ed") {
        const paramValue = req.query[paramName];
        if (!paramValue) {
          return res.status(400).json({ error: `Please provide parameter: ${paramName}` });
        }
        const [day, month, year] = paramValue.split(/[-\/]/);
        const dateObj = new Date(Date.UTC(year, month - 1, day));
        if (paramName === "ed") dateObj.setUTCHours(23, 59, 59, 999);
        ph.parent[ph.path] = dateObj;

      } else {
        const paramValue = req.query[paramName];
        if (!paramValue) {
          return res.status(400).json({ error: `Please provide parameter: ${paramName}` });
        }
        ph.parent[ph.path] = paramValue;
      }
    }

    // 5️⃣ Run aggregation
    const result = await mongoose.connection
      .collection(report.baseCollection)
      .aggregate(pipeline)
      .toArray();

    // 6️⃣ Return response
    res.json({
      reportname: report.reportname,
      slug: report.slug,
      data: result
    });

  } catch (err) {
    console.error("Report error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Get User Info
app.get("/api/userinfo", async (req, res) => {
  try {
    const { email } = req.query; // or decode from JWT token

    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    const user = await db.collection("users").findOne({ email });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({
      firstname: user.firstname,
      department: user.department,
      location: user.location,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------------- EMPLOYEE STATUS API ----------------
app.get("/api/employeestatus", async (req, res) => {
  try {
    const token = req.headers["authorization"]?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Token missing" });

    // verify JWT
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }

    const dbCollection = db.collection("bcslbasic");

    // Aggregate counts by status
    const statusCounts = await dbCollection.aggregate([
      {
        $group: {
          _id: "$status",
          count: { $sum: 1 },
        },
      },
    ]).toArray();

    const result = {
      present: 0,
      absent: 0,
      half: 0,
    };

    statusCounts.forEach((item) => {
      const status = (item._id || "").toLowerCase();
      if (status === "present") result.present = item.count;
      else if (status === "absent") result.absent = item.count;
      else if (status === "half") result.half = item.count;
    });

    res.json(result);
  } catch (err) {
    console.error("Employee Status API error:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// ---------------- START SERVER ----------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
