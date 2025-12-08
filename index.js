// server.js
const express = require('express')
const cors = require('cors');
const app = express();
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const stripe = require('stripe')(process.env.STRIPE_SECRET);
const crypto = require('crypto');
const admin = require("firebase-admin");

const port = process.env.PORT || 3000

// Firebase setup
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf8')
const serviceAccount = JSON.parse(decoded);
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
})

// Middleware
app.use(express.json());
app.use(cors());

// Firebase token verification
const verifyFBToken = async (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) return res.status(401).send({ message: 'unauthorized access' })

    try {
        const idToken = token.split(' ')[1];
        const decoded = await admin.auth().verifyIdToken(idToken);
        req.decoded_email = decoded.email;
        next();
    } catch (err) {
        return res.status(401).send({ message: 'unauthorized access' })
    }
}

// MongoDB setup
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.maurhd8.mongodb.net/?appName=Cluster0`
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

// Tracking ID generator
function generateTrackingId() {
    const prefix = "PRCL";
    const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
    const random = crypto.randomBytes(3).toString("hex").toUpperCase();
    return `${prefix}-${date}-${random}`;
}

async function run() {
    try {
        await client.connect();

        const db = client.db('simpleUser');
        const userCollection = db.collection('users');
        const parcelsCollection = db.collection('parcels');
        const paymentCollection = db.collection('payments');
        const ridersCollection = db.collection('riders');
        const trackingsCollection = db.collection('trackings');
        const productsCollection = db.collection('products');
        const bookingsCollection = db.collection('bookings');

        // Admin & Rider verification middleware
        const verifyAdmin = async (req, res, next) => {
            const email = req.decoded_email;
            const user = await userCollection.findOne({ email });
            if (!user || user.role !== 'admin') return res.status(403).send({ message: 'forbidden access' });
            next();
        }
        const verifyRider = async (req, res, next) => {
            const email = req.decoded_email;
            const user = await userCollection.findOne({ email });
            if (!user || user.role !== 'rider') return res.status(403).send({ message: 'forbidden access' });
            next();
        }

        // Log tracking
        const logTracking = async (trackingId, status) => {
            const log = { trackingId, status, details: status.split('_').join(' '), createdAt: new Date() }
            return await trackingsCollection.insertOne(log);
        }

        // ---------- PRODUCTS API ----------
        app.get('/products', async (req, res) => {
            const query = {};
            const { featured, limit, category, search } = req.query;

            if (featured === 'true') query.showOnHome = true;
            if (category) query.category = category;
            if (search) {
                query.$or = [
                    { name: { $regex: search, $options: 'i' } },
                    { shortDesc: { $regex: search, $options: 'i' } },
                    { category: { $regex: search, $options: 'i' } }
                ];
            }

            const cursor = productsCollection.find(query).sort({ createdAt: -1 });
            if (limit) cursor.limit(parseInt(limit));
            const result = await cursor.toArray();
            res.send(result);
        });

        app.get('/products/:id', async (req, res) => {
            const id = req.params.id;
            const product = await productsCollection.findOne({ _id: new ObjectId(id) });
            res.send(product);
        });

        app.post('/products', verifyFBToken, async (req, res) => {
            const product = req.body;
            product.createdAt = new Date();
            const result = await productsCollection.insertOne(product);
            res.send(result);
        });

        app.patch('/products/:id', verifyFBToken, async (req, res) => {
            const id = req.params.id;
            const updateInfo = req.body;
            const result = await productsCollection.updateOne({ _id: new ObjectId(id) }, { $set: updateInfo });
            res.send(result);
        });

        app.delete('/products/:id', verifyFBToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const result = await productsCollection.deleteOne({ _id: new ObjectId(id) });
            res.send(result);
        });

        // ---------- USERS API ----------
        app.get('/users', verifyFBToken, async (req, res) => {
            const searchText = req.query.searchText;
            const query = {};
            if (searchText) {
                query.$or = [
                    { displayName: { $regex: searchText, $options: 'i' } },
                    { email: { $regex: searchText, $options: 'i' } },
                ];
            }
            const cursor = userCollection.find(query).sort({ createdAt: -1 }).limit(5);
            const result = await cursor.toArray();
            res.send(result);
        });

        app.get('/users/:email/role', async (req, res) => {
            const email = req.params.email;
            const user = await userCollection.findOne({ email });
            res.send({ role: user?.role || 'user' });
        });

        app.post('/users', async (req, res) => {
            const user = req.body;
            user.role = 'user';
            user.createdAt = new Date();
            const email = user.email;
            const exists = await userCollection.findOne({ email });
            if (exists) return res.send({ message: 'user exists' });
            const result = await userCollection.insertOne(user);
            res.send(result);
        });

        app.patch('/users/:id/role', verifyFBToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const { role } = req.body;
            const result = await userCollection.updateOne({ _id: new ObjectId(id) }, { $set: { role } });
            res.send(result);
        });

        // ---------- BOOKINGS API ----------
        app.post('/bookings', verifyFBToken, async (req, res) => {
            try {
                const booking = req.body;

                // Validation
                if (!booking.userEmail || !booking.productId || !booking.orderQty) {
                    return res.status(400).send({ message: 'Missing required booking fields' });
                }

                // Generate tracking ID
                booking.trackingId = generateTrackingId();
                booking.status = 'pending';
                booking.createdAt = new Date();

                const result = await bookingsCollection.insertOne(booking);

                // Log initial tracking
                await trackingsCollection.insertOne({
                    trackingId: booking.trackingId,
                    status: 'booking_created',
                    details: 'Booking created',
                    createdAt: new Date()
                });

                res.send({
                    message: 'Booking created',
                    insertedId: result.insertedId,
                    trackingId: booking.trackingId
                });
            } catch (err) {
                console.log("Booking Error:", err);
                res.status(500).send({ message: 'Internal server error' });
            }
        });

        // ---------- OPTIONAL: Stripe Checkout ----------
        app.post('/create-checkout-session', async (req, res) => {
            const { cost, bookingId, productTitle } = req.body;

            if (!cost || !bookingId) {
                return res.status(400).send({ message: 'Missing cost or bookingId' });
            }

            const session = await stripe.checkout.sessions.create({
                payment_method_types: ['card'],
                line_items: [{
                    price_data: {
                        currency: 'usd',
                        product_data: { name: productTitle },
                        unit_amount: cost * 100,
                    },
                    quantity: 1
                }],
                mode: 'payment',
                success_url: `${process.env.CLIENT_URL}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
                cancel_url: `${process.env.CLIENT_URL}/dashboard/payment-cancelled`,
            });

            res.send({ url: session.url });
        });

        await client.db("admin").command({ ping: 1 });
        console.log("MongoDB connected successfully!");
    } finally {
        // optional: keep client connected
    }
}

run().catch(console.dir);

app.get('/', (req, res) => {
    res.send('Server is running!')
})

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
