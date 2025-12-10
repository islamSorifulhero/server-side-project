const express = require('express');
const cors = require('cors');
const app = express();
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const stripe = require('stripe')(process.env.STRIPE_SECRET);
const crypto = require('crypto');
const admin = require("firebase-admin");

const port = process.env.PORT || 3000;

// -------------------- FIREBASE SETUP --------------------
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf8');
const serviceAccount = JSON.parse(decoded);

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

// -------------------- MIDDLEWARE --------------------
app.use(express.json());
app.use(cors());

// Firebase token verification
const verifyFBToken = async (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) return res.status(401).send({ message: 'unauthorized access' });

    try {
        const idToken = token.split(' ')[1];
        const decoded = await admin.auth().verifyIdToken(idToken);
        req.decoded_email = decoded.email;
        next();
    } catch (err) {
        return res.status(401).send({ message: 'unauthorized access' });
    }
};

// -------------------- DATABASE --------------------
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.maurhd8.mongodb.net/?retryWrites=true&w=majority`;
const client = new MongoClient(uri, {
    serverApi: { version: ServerApiVersion.v1, strict: true }
});

// Tracking ID generator
function generateTrackingId() {
    const prefix = "PRCL";
    const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
    const random = crypto.randomBytes(3).toString("hex").toUpperCase();
    return `${prefix}-${date}-${random}`;
}

// -------------------- MAIN FUNCTION --------------------
async function run() {
    await client.connect();
    const db = client.db('simpleUser');
    const userCollection = db.collection('users');
    const productsCollection = db.collection('products');
    const bookingsCollection = db.collection('bookings');
    const trackingsCollection = db.collection('trackings');


    // ---------------- ADMIN CHECK ----------------
    const verifyAdmin = async (req, res, next) => {
        const email = req.decoded_email;
        const user = await userCollection.findOne({ email });
        if (!user || user.role !== 'admin') {
            return res.status(403).send({ message: 'forbidden access' });
        }
        next();
    };

    app.post("/users", async(req, res) => {
        const userData = req.body
        const result = await userCollection.insertOne(userData)
        res.send(result);
    })

    // -------------------- USERS API --------------------
    // Get all users (Admin only) with search, filter, pagination
    app.get('/users/admin', verifyFBToken, verifyAdmin, async (req, res) => {
        const { page = 1, limit = 10, search = "", role = "" } = req.query;
        const query = {};
        if (search) query.$or = [
            { name: { $regex: search, $options: 'i' } },
            { email: { $regex: search, $options: 'i' } }
        ];
        if (role) query.role = role;

        const users = await userCollection.find(query)
            .skip((page - 1) * limit)
            .limit(parseInt(limit))
            .toArray();

        const total = await userCollection.countDocuments(query);
        res.send({ users, total });
    });

    // Update user role or suspend reason
    app.patch('/users/admin/:id', verifyFBToken, verifyAdmin, async (req, res) => {
        const id = req.params.id;
        const { role, suspendReason } = req.body;

        const updateDoc = {};
        if (role) updateDoc.role = role;
        if (suspendReason) updateDoc.suspendReason = suspendReason;

        const result = await userCollection.updateOne({ _id: new ObjectId(id) }, { $set: updateDoc });
        res.send(result);
    });

    // -------------------- PRODUCTS API --------------------
    // Get all products
    app.get('/products', async (req, res) => {
        const result = await productsCollection.find().sort({ createdAt: -1 }).toArray();
        console.log(result);
        res.send(result);
    });

    // Get single product
    app.get('/products/:id', async (req, res) => {
        const id = req.params.id;
        const product = await productsCollection.findOne({ _id: new ObjectId(id) });
        res.send(product);
    });

    // Admin/Manager: get all products with pagination, search, filter
    app.get('/products/admin', verifyFBToken, async (req, res) => {
        const { page = 1, limit = 10, search = "", category = "" } = req.query;
        const query = {};
        if (search) query.$or = [
            { name: { $regex: search, $options: 'i' } },
            { description: { $regex: search, $options: 'i' } }
        ];
        if (category) query.category = category;

        const products = await productsCollection.find(query)
            .skip((page - 1) * limit)
            .limit(parseInt(limit))
            .toArray();

        const total = await productsCollection.countDocuments(query);
        res.send({ products, total });
    });

    // Add product (Manager only)
    app.post('/products', verifyFBToken, async (req, res) => {
        const email = req.decoded_email;
        const user = await userCollection.findOne({ email });
        if (!user || user.role !== 'manager') return res.status(403).send({ message: 'forbidden' });

        const product = req.body;
        product.createdBy = email;
        product.createdAt = new Date();
        const result = await productsCollection.insertOne(product);
        res.send(result);
    });

    // Update product
    app.patch('/products/:id', verifyFBToken, async (req, res) => {
        const id = req.params.id;
        const updateDoc = req.body;
        const result = await productsCollection.updateOne({ _id: new ObjectId(id) }, { $set: updateDoc });
        res.send(result);
    });

    // Delete product
    app.delete('/products/:id', verifyFBToken, async (req, res) => {
        const id = req.params.id;
        const result = await productsCollection.deleteOne({ _id: new ObjectId(id) });
        res.send(result);
    });

    // -------------------- BOOKINGS API --------------------
    // Create booking
    app.post('/bookings', verifyFBToken, async (req, res) => {
        try {
            const booking = req.body;
            if (!booking.userEmail || !booking.productId || !booking.orderQty) {
                return res.status(400).send({ message: 'Missing required booking fields' });
            }

            // Check if user suspended
            const user = await userCollection.findOne({ email: booking.userEmail });
            if (user?.suspendReason) return res.status(403).send({ message: 'You are suspended: ' + user.suspendReason });

            booking.trackingId = generateTrackingId();
            booking.status = "pending";
            booking.createdAt = new Date();

            const result = await bookingsCollection.insertOne(booking);

            await trackingsCollection.insertOne({
                trackingId: booking.trackingId,
                status: "booking_created",
                createdAt: new Date()
            });

            res.send({
                message: "Booking created",
                insertedId: result.insertedId,
                trackingId: booking.trackingId
            });
        } catch (err) {
            console.log("BOOKING ERROR:", err);
            res.status(500).send({ message: "Internal server error" });
        }
    });

    // Get bookings for logged-in user
    app.get('/bookings', verifyFBToken, async (req, res) => {
        const email = req.decoded_email;
        const bookings = await bookingsCollection.find({ userEmail: email }).sort({ createdAt: -1 }).toArray();
        res.send(bookings);
    });

    // Admin/Manager: get all bookings with search, filter, pagination
    app.get('/bookings/admin', verifyFBToken, async (req, res) => {
        const { page = 1, limit = 10, status = "", search = "" } = req.query;
        const query = {};
        if (status) query.status = status;
        if (search) query.$or = [
            { productTitle: { $regex: search, $options: 'i' } },
            { userEmail: { $regex: search, $options: 'i' } }
        ];

        const bookings = await bookingsCollection.find(query)
            .skip((page - 1) * limit)
            .limit(parseInt(limit))
            .sort({ createdAt: -1 })
            .toArray();

        const total = await bookingsCollection.countDocuments(query);
        res.send({ bookings, total });
    });

    // -------------------- TRACKING API --------------------
    app.get('/trackings/:trackingId', verifyFBToken, async (req, res) => {
        const trackingId = req.params.trackingId;
        const trackings = await trackingsCollection.find({ trackingId }).sort({ createdAt: 1 }).toArray();
        res.send(trackings);
    });

    // -------------------- CREATE STRIPE CHECKOUT --------------------
    app.post('/create-checkout-session', async (req, res) => {
        try {
            const { cost, bookingId, productTitle, userEmail } = req.body;
            if (!cost || !bookingId || !productTitle || !userEmail) {
                return res.status(400).send({ message: 'Missing required fields' });
            }

            const session = await stripe.checkout.sessions.create({
                payment_method_types: ['card'],
                line_items: [
                    {
                        price_data: {
                            currency: 'usd',
                            product_data: { name: productTitle },
                            unit_amount: cost * 100,
                        },
                        quantity: 1,
                    }
                ],
                mode: "payment",
                success_url: `${process.env.CLIENT_URL}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
                cancel_url: `${process.env.CLIENT_URL}/dashboard/payment-cancelled`,
            });

            res.send({ url: session.url });
        } catch (err) {
            console.log("STRIPE ERROR:", err);
            res.status(500).send({ message: "Stripe session failed" });
        }
    });

    console.log("Database connected!");
}

run().catch(console.error);

// -------------------- ROOT ROUTE --------------------
app.get('/', (req, res) => {
    res.send('Server is running!');
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});