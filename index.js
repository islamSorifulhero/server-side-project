const express = require('express');
const cors = require('cors');
const app = express();
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const stripe = require('stripe')(process.env.STRIPE_SECRET);
const crypto = require('crypto');
const admin = require("firebase-admin");

const port = process.env.PORT || 3000;

const decoded = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf8');
const serviceAccount = JSON.parse(decoded);

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

app.use(express.json());
app.use(cors());

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

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.maurhd8.mongodb.net/?retryWrites=true&w=majority`;
const client = new MongoClient(uri, {
    serverApi: { version: ServerApiVersion.v1, strict: true }
});

function generateTrackingId() {
    const prefix = "PRCL";
    const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
    const random = crypto.randomBytes(3).toString("hex").toUpperCase();
    return `${prefix}-${date}-${random}`;
}

async function run() {
    await client.connect();
    const db = client.db('simpleUser');
    const userCollection = db.collection('users');
    const productsCollection = db.collection('products');
    const bookingsCollection = db.collection('bookings');
    const trackingsCollection = db.collection('trackings');

    const verifyAdmin = async (req, res, next) => {
        const email = req.decoded_email;
        const user = await userCollection.findOne({ email });
        if (!user || user.role !== 'admin') {
            return res.status(403).send({ message: 'forbidden access' });
        }
        next();
    };

    app.post("/users", async (req, res) => {
        const userData = req.body
        const result = await userCollection.insertOne(userData)
        res.send(result);
    })

    app.get('/products', async (req, res) => {
        const result = await productsCollection.find().sort({ createdAt: -1 }).toArray();
        res.send(result);
    });

    app.get('/products/:id', async (req, res) => {
        const id = req.params.id;
        const product = await productsCollection.findOne({ _id: new ObjectId(id) });
        res.send(product);
    });

    app.post('/bookings', verifyFBToken, async (req, res) => {
        try {
            const booking = req.body;
            const userEmail = booking.userEmail;

            if (!userEmail || !booking.productId || !booking.orderQty) {
                return res.status(400).send({ message: 'Missing required booking fields' });
            }

            const user = await userCollection.findOne({ email: userEmail });
            if (!user) return res.status(404).send({ message: "User not found" });

            if (user.suspendReason) return res.status(403).send({ message: 'You are suspended: ' + user.suspendReason });

            if (user.role !== 'buyer') return res.status(403).send({ message: 'Only buyers can place orders' });

            const product = await productsCollection.findOne({ _id: new ObjectId(booking.productId) });
            if (!product) return res.status(404).send({ message: "Product not found" });

            const minOrder = product.minimumOrder ?? product.minOrder ?? 1;
            const available = product.availableQty ?? product.quantity ?? 0;

            if (booking.orderQty < minOrder) {
                return res.status(400).send({ message: `Order quantity cannot be less than ${minOrder}` });
            }
            if (booking.orderQty > available) {
                return res.status(400).send({ message: `Order quantity cannot exceed available quantity (${available})` });
            }

            booking.trackingId = generateTrackingId();
            booking.status = "pending";
            booking.createdAt = new Date();

            const result = await bookingsCollection.insertOne(booking);

            await productsCollection.updateOne(
                { _id: new ObjectId(booking.productId) },
                { $inc: { availableQty: -booking.orderQty } }
            );

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

    app.get('/bookings', verifyFBToken, async (req, res) => {
        const email = req.decoded_email;
        const bookings = await bookingsCollection.find({ userEmail: email }).sort({ createdAt: -1 }).toArray();
        res.send(bookings);
    });

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

    app.get('/trackings/:trackingId', verifyFBToken, async (req, res) => {
        const trackingId = req.params.trackingId;
        const trackings = await trackingsCollection.find({ trackingId }).sort({ createdAt: 1 }).toArray();
        res.send(trackings);
    });

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

app.get('/', (req, res) => {
    res.send('Server is running!');
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});