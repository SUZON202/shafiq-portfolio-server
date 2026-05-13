const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken'); // 🔴 ১. JWT ইমপোর্ট করা হলো
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

// মিডলওয়্যার
app.use(cors());
app.use(express.json());

// কানেকশন ইউআরআই
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@suzon.e5swrmn.mongodb.net/?retryWrites=true&w=majority&appName=suzon`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    // ডাটাবেসের সাথে কানেক্ট করা
    await client.connect();
    
    // ডাটাবেস ঠিকমতো কানেক্ট হয়েছে কিনা তা চেক করা (Ping command)
    await client.db("admin").command({ ping: 1 });
    console.log("✅ Successfully connected to MongoDB!");
    
    // ডাটাবেস এবং কালেকশন
    const db = client.db("test"); 
    const usersCollection = db.collection("users");
    const projectsCollection = db.collection("projects");
    const messagesCollection = db.collection("messages");

    // ==========================================
    //      🔴 SECURITY MIDDLEWARES (তালা-চাবি)
    // ==========================================

    // টোকেন ভেরিফাই করার মিডলওয়্যার
    const verifyToken = (req, res, next) => {
        if (!req.headers.authorization) {
            return res.status(401).send({ message: 'unauthorized access' });
        }
        const token = req.headers.authorization.split(' ')[1];
        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
            if (err) {
                return res.status(401).send({ message: 'unauthorized access' });
            }
            req.decoded = decoded;
            next();
        })
    }

    // অ্যাডমিন ভেরিফাই করার মিডলওয়্যার (আপনার স্পেশাল রিকুয়েস্ট)
    const verifyAdmin = async (req, res, next) => {
        const email = req.decoded.email;
        const query = { email: email };
        const user = await usersCollection.findOne(query);
        const isAdmin = user?.role === 'admin';
        if (!isAdmin) {
            return res.status(403).send({ message: 'forbidden access' });
        }
        next();
    }

    // ==========================================
    //                JWT API
    // ==========================================
    app.post('/jwt', async (req, res) => {
        const user = req.body;
        const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
        res.send({ token });
    })

    // ==========================================
    //                  APIs
    // ==========================================

    // ১. ড্যাশবোর্ড স্ট্যাটাস দেখার API (লক করা হলো)
    app.get('/admin-stats', verifyToken, verifyAdmin, async (req, res) => {
        try {
            const users = await usersCollection.countDocuments();
            const projects = await projectsCollection.countDocuments();
            const messages = await messagesCollection.countDocuments();
            res.send({ users, projects, messages });
        } catch (error) {
            res.status(500).send({ message: "Error fetching stats" });
        }
    });

    // ২. সব ইউজার দেখার API (লক করা হলো)
    app.get('/users', verifyToken, verifyAdmin, async (req, res) => {
        try {
            const result = await usersCollection.find().toArray();
            res.send(result);
        } catch (error) {
            res.status(500).send({ message: "Error fetching users" });
        }
    });

    // ৩. নতুন ইউজার সেভ করার API
    app.post('/users', async (req, res) => {
        try {
            const user = req.body;
            const query = { email: user.email };
            const existingUser = await usersCollection.findOne(query);
            if (existingUser) {
                return res.send({ message: 'User already exists', insertedId: null });
            }
            const result = await usersCollection.insertOne(user);
            res.send(result);
        } catch (error) {
            res.status(500).send({ message: "Error saving user" });
        }
    });

    // ৪. এডমিন বানানোর API (লক করা হলো)
    app.patch('/users/admin/:id', verifyToken, verifyAdmin, async (req, res) => {
        try {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) };
            const updatedDoc = { $set: { role: 'admin' } }
            const result = await usersCollection.updateOne(filter, updatedDoc);
            res.send(result);
        } catch (error) {
            res.status(500).send({ message: "Error updating user to admin" });
        }
    });

    // ৫. ইউজার এডমিন কি না চেক করা (AdminRoute এর জন্য জরুরি)
    app.get('/users/admin/:email', verifyToken, async (req, res) => {
        try {
            const email = req.params.email;
            if (email !== req.decoded.email) {
                return res.status(403).send({ message: 'forbidden access' })
            }
            const query = { email: email };
            const user = await usersCollection.findOne(query);
            let admin = false;
            if (user) {
                admin = user?.role === 'admin';
            }
            res.send({ admin });
        } catch (error) {
            res.status(500).send({ message: "Error checking admin role" });
        }
    });

    // ৬. ইউজার ডিলিট করার API (লক করা হলো)
    app.delete('/users/:id', verifyToken, verifyAdmin, async (req, res) => {
        try {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await usersCollection.deleteOne(query);
            res.send(result);
        } catch (error) {
            res.status(500).send({ message: "Error deleting user" });
        }
    });

    // PROJECT APIS (লক করা হলো)
    app.get('/projects', async (req, res) => {
        try {
            const result = await projectsCollection.find().toArray();
            res.send(result);
        } catch (error) {
            res.status(500).send({ message: "Error fetching projects" });
        }
    });

    app.post('/projects', verifyToken, verifyAdmin, async (req, res) => {
        try {
            const project = req.body;
            const result = await projectsCollection.insertOne(project);
            res.send(result);
        } catch (error) {
            res.status(500).send({ message: "Error saving project" });
        }
    });

    app.delete('/projects/:id', verifyToken, verifyAdmin, async (req, res) => {
        try {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await projectsCollection.deleteOne(query);
            res.send(result);
        } catch (error) {
            res.status(500).send({ message: "Error deleting project" });
        }
    });

    // CONTACT MESSAGES APIS
    app.get('/messages', verifyToken, verifyAdmin, async (req, res) => {
        try {
            const result = await messagesCollection.find().toArray();
            res.send(result);
        } catch (error) {
            res.status(500).send({ message: "Error fetching messages" });
        }
    });

    app.post('/messages', async (req, res) => {
        try {
            const message = req.body;
            message.date = new Date().toLocaleString("en-GB", { 
                day: "numeric", month: "short", year: "numeric", 
                hour: "2-digit", minute: "2-digit" 
            }); 
            const result = await messagesCollection.insertOne(message);
            res.send(result);
        } catch (error) {
            res.status(500).send({ message: "Error sending message" });
        }
    });

    app.delete('/messages/:id', verifyToken, verifyAdmin, async (req, res) => {
        try {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await messagesCollection.deleteOne(query);
            res.send(result);
        } catch (error) {
            res.status(500).send({ message: "Error deleting message" });
        }
    });

  } finally {
    // কানেকশন খোলা থাকবে
  }
}
run().catch(console.dir);

app.get('/', (req, res) => {
    res.send('🚀 Shafiq Suzon Portfolio Server is running perfectly!');
});

app.listen(port, () => {
    console.log(`Server is running on port: ${port}`);
});