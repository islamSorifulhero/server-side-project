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
        console.log("Checking Admin Email:", email);
        const user = await userCollection.findOne({ email });
        console.log("Admin check failed for:", email);

        if (!user || user.role !== 'admin') {
            console.log("Admin check failed for:", email);
            return res.status(403).send({ message: 'forbidden access' });
        }
        next();
    };

    const verifyManager = async (req, res, next) => {
        const email = req.decoded_email;
        const user = await userCollection.findOne({ email });
        if (!user || (user.role !== 'admin' && user.role !== 'manager')) {
            return res.status(403).send({ message: 'forbidden access' });
        }
        next();
    };

    app.post("/users", async (req, res) => {
        const userData = req.body
        const result = await userCollection.insertOne(userData)
        res.send(result);
    })

    app.get('/users/:email', verifyFBToken, async (req, res) => {
        try {
            const email = req.params.email;
            if (req.decoded_email !== email) {
                return res.status(403).send({ message: "Forbidden: Cannot access other user profiles." });
            }

            const user = await userCollection.findOne({ email });

            if (!user) {
                return res.status(404).send({ message: "User not found in database." });
            }

            res.send(user);

        } catch (err) {
            console.error("Error fetching user profile:", err);
            res.status(500).send({ message: "Internal server error" });
        }
    });


    app.get('/get-users/all', verifyFBToken, verifyAdmin, async (req, res) => {
        try {
            const searchText = req.query.search || "";
            const query = {};
            if (searchText) {
                query.email = { $regex: searchText, $options: 'i' };
            }

            const users = await userCollection.find(query).sort({ role: 1, email: 1 }).toArray();

            console.log(`Users fetched for Manage Users (Search: ${searchText}): ${users.length}`);
            res.send(users);
        } catch (err) {
            console.error("Error fetching all users:", err);
            res.status(500).send({ message: "Failed to fetch users." });
        }
    });


    app.patch('/users/update/:id', verifyFBToken, verifyAdmin, async (req, res) => {
        try {
            const id = req.params.id;
            const { role, suspendReason } = req.body;
            if (!ObjectId.isValid(id)) {
                return res.status(400).send({ message: "Invalid User ID." });
            }

            const updateDoc = {};

            if (role && ['buyer', 'manager', 'admin'].includes(role)) {
                updateDoc.role = role;
            }

            if (typeof suspendReason === 'string') {
                if (suspendReason.length > 0) {
                    updateDoc.status = 'suspended';
                    updateDoc.suspendReason = suspendReason;
                } else {
                    updateDoc.status = 'approved';
                    updateDoc.suspendReason = null;
                }
            }

            if (Object.keys(updateDoc).length === 0) {
                return res.status(400).send({ message: "No valid update parameters provided." });
            }

            const updateResult = await userCollection.updateOne(
                { _id: new ObjectId(id) },
                { $set: updateDoc }
            );

            if (updateResult.modifiedCount === 0) {
                return res.status(404).send({ modifiedCount: 0, message: "User not found or no changes made." });
            }

            res.send(updateResult);
        } catch (err) {
            console.error("User update error:", err);
            res.status(500).send({ message: "Failed to update user role/status." });
        }
    });


    app.get('/products', async (req, res) => {
        const limit = parseInt(req.query.limit);

        let query = productsCollection.find().sort({ createdAt: -1 });

        if (!isNaN(limit) && limit > 0) {
            query = query.limit(limit);
        }

        const result = await query.toArray();
        res.send(result);
    });

    app.get('/products/:id', async (req, res) => {
        const id = req.params.id;
        const product = await productsCollection.findOne({ _id: new ObjectId(id) });
        res.send(product);
    });

    app.get('/manager/get-manager', verifyFBToken, verifyManager, async (req, res) => {
        try {
            const products = await productsCollection.find().sort({ createdAt: -1 }).toArray();
            res.send(products);
        } catch (err) {
            console.error("Error fetching manager products:", err);
            res.status(500).send({ message: "Internal server error." });
        }
    });

    app.post('/products', verifyFBToken, verifyManager, async (req, res) => {
        try {
            const productData = req.body;
            productData.createdAt = new Date();
            productData.price = parseFloat(productData.price) || 0;
            productData.availableQty = parseInt(productData.availableQty) || 0;
            productData.minimumOrder = parseInt(productData.minimumOrder) || 1;

            const result = await productsCollection.insertOne(productData);
            res.send(result);
        } catch (err) {
            console.error("Error adding product:", err);
            res.status(500).send({ message: "Failed to add product" });
        }
    });


    app.delete('/products/:id', verifyFBToken, verifyManager, async (req, res) => {
        try {
            const id = req.params.id;
            const result = await productsCollection.deleteOne({ _id: new ObjectId(id) });
            res.send(result);
        } catch (err) {
            console.error("Error deleting product:", err);
            res.status(500).send({ message: "Internal server error." });
        }
    });

    app.get('/get-products', verifyFBToken, verifyManager, async (req, res) => {
        const limit = parseInt(req.query.limit);

        let query = productsCollection.find().sort({ createdAt: -1 });

        if (!isNaN(limit) && limit > 0) {
            query = query.limit(limit);
        }

        const result = await query.toArray();
        res.send(result);
    });


    app.patch('/products/:id/toggle-home', verifyFBToken, verifyManager, async (req, res) => {
        try {
            const id = req.params.id;
            const { showOnHome } = req.body;

            if (!ObjectId.isValid(id) || typeof showOnHome !== 'boolean') {
                return res.status(400).send({ message: "Invalid Product ID or showOnHome value." });
            }

            const updateResult = await productsCollection.updateOne(
                { _id: new ObjectId(id) },
                { $set: { showOnHome: showOnHome } }
            );

            if (updateResult.modifiedCount === 0) {
                return res.status(404).send({ modifiedCount: 0, message: "Product not found or no change in status." });
            }

            res.send(updateResult);
        } catch (err) {
            console.error("Toggle Home Error:", err);
            res.status(500).send({ message: "Failed to toggle 'Show on Home'." });
        }
    });


    app.patch('/get-products/:id', verifyFBToken, verifyManager, async (req, res) => {
        try {
            const id = req.params.id;
            const updateData = req.body;

            if (!ObjectId.isValid(id)) {
                return res.status(400).send({ message: "Invalid Product ID." });
            }

            const setDoc = { ...updateData };

            if (setDoc.price !== undefined) setDoc.price = parseFloat(setDoc.price);
            if (setDoc.availableQty !== undefined) setDoc.availableQty = parseInt(setDoc.availableQty);

            const updateResult = await productsCollection.updateOne(
                { _id: new ObjectId(id) },
                { $set: setDoc }
            );

            if (updateResult.modifiedCount === 0) {
                return res.status(404).send({ modifiedCount: 0, message: "Product not found or no changes made." });
            }

            res.send(updateResult);
        } catch (err) {
            console.error("Product update error:", err);
            res.status(500).send({ message: "Failed to update product." });
        }
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


    app.delete('/bookings/:id', verifyFBToken, async (req, res) => {
        try {
            const id = req.params.id;
            const userEmail = req.decoded_email;

            if (!ObjectId.isValid(id)) {
                return res.status(400).send({ message: "Invalid Booking ID format." });
            }

            const bookingToDelete = await bookingsCollection.findOne({ _id: new ObjectId(id) });

            if (!bookingToDelete) {
                return res.status(404).send({ message: "Booking not found." });
            }

            if (bookingToDelete.userEmail !== userEmail) {
                return res.status(403).send({ message: "Forbidden: You can only cancel your own orders." });
            }

            if (bookingToDelete.status !== 'pending') {
                return res.status(400).send({ message: `Cannot cancel order with status: ${bookingToDelete.status}.` });
            }

            const deleteResult = await bookingsCollection.deleteOne({ _id: new ObjectId(id) });

            if (deleteResult.deletedCount === 0) {
                return res.status(404).send({ message: "Order not found or already deleted." });
            }

            await productsCollection.updateOne(
                { _id: new ObjectId(bookingToDelete.productId) },
                { $inc: { availableQty: bookingToDelete.orderQty } }
            );

            if (bookingToDelete.trackingId) {
                await trackingsCollection.insertOne({
                    trackingId: bookingToDelete.trackingId,
                    status: "order_cancelled_by_user",
                    createdAt: new Date(),
                    note: `Order cancelled by user: ${userEmail}`
                });
            }

            res.send({ deletedCount: 1, message: "Order cancelled successfully." });
        } catch (err) {
            console.error("Order Cancellation Error:", err);
            res.status(500).send({ message: "Failed to cancel order." });
        }
    });

    app.get('/get-booking/:id', verifyFBToken, async (req, res) => {
        try {
            const id = req.params.id;
            if (!ObjectId.isValid(id)) {
                return res.status(400).send({ message: "Invalid Booking ID format." });
            }

            const booking = await bookingsCollection.findOne({ _id: new ObjectId(id) });

            if (!booking) {
                return res.status(404).send({ message: "Booking not found." });
            }

            if (req.decoded_email !== booking.userEmail) {

                const user = await userCollection.findOne({ email: req.decoded_email });
                if (user.role === 'buyer') {
                    return res.status(403).send({ message: "Forbidden access to this booking." });
                }
            }

            const trackingHistory = await trackingsCollection.find({ trackingId: booking.trackingId }).sort({ createdAt: 1 }).toArray();

            res.send({
                ...booking,
                tracking: trackingHistory
            });

        } catch (err) {
            console.error("Error fetching single booking:", err);
            res.status(500).send({ message: "Internal server error" });
        }
    });

    app.get('/bookings/admin', verifyFBToken, verifyManager, async (req, res) => {
        const user = await userCollection.findOne({ email: req.decoded_email });
        if (!user || (user.role !== 'admin' && user.role !== 'manager')) {
            return res.status(403).send({ message: 'Forbidden access' });
        }

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

    app.patch('/bookings/:id/approve', verifyFBToken, verifyManager, async (req, res) => {
        try {
            const id = req.params.id;
            if (!ObjectId.isValid(id)) {
                return res.status(400).send({ message: "Invalid Order ID." });
            }

            const updateResult = await bookingsCollection.updateOne(
                { _id: new ObjectId(id), status: { $ne: 'paid' } },
                { $set: { status: 'approved', approvedAt: new Date() } }
            );

            if (updateResult.modifiedCount === 0) {
                return res.status(404).send({ modifiedCount: 0, message: "Order not found or already approved/paid." });
            }

            const booking = await bookingsCollection.findOne({ _id: new ObjectId(id) });
            if (booking && booking.trackingId) {
                await trackingsCollection.insertOne({
                    trackingId: booking.trackingId,
                    status: "order_approved",
                    createdAt: new Date(),
                    note: "Order confirmed and approved by manager."
                });
            }

            res.send(updateResult);
        } catch (err) {
            console.error("Approval Error:", err);
            res.status(500).send({ message: "Failed to approve order." });
        }
    });


    app.patch('/bookings/:id/reject', verifyFBToken, verifyManager, async (req, res) => {
        try {
            const id = req.params.id;
            const { reason } = req.body;
            if (!ObjectId.isValid(id)) {
                return res.status(400).send({ message: "Invalid Order ID." });
            }

            const bookingToReject = await bookingsCollection.findOne({ _id: new ObjectId(id) });

            if (!bookingToReject) {
                return res.status(404).send({ modifiedCount: 0, message: "Order not found." });
            }

            const updateResult = await bookingsCollection.updateOne(
                { _id: new ObjectId(id), status: { $nin: ['paid', 'shipped', 'rejected'] } },
                { $set: { status: 'rejected', rejectionReason: reason || "No reason provided." } }
            );

            if (updateResult.modifiedCount > 0) {
                await productsCollection.updateOne(
                    { _id: new ObjectId(bookingToReject.productId) },
                    { $inc: { availableQty: bookingToReject.orderQty } }
                );

                if (bookingToReject.trackingId) {
                    await trackingsCollection.insertOne({
                        trackingId: bookingToReject.trackingId,
                        status: "order_rejected",
                        createdAt: new Date(),
                        note: `Order rejected by manager. Reason: ${reason || 'N/A'}`
                    });
                }
            } else {
                return res.status(400).send({ modifiedCount: 0, message: "Order cannot be rejected (already rejected, paid, or shipped)." });
            }

            res.send(updateResult);
        } catch (err) {
            console.error("Rejection Error:", err);
            res.status(500).send({ message: "Failed to reject order." });
        }
    });


    app.patch('/bookings/:id/tracking', verifyFBToken, verifyManager, async (req, res) => {
        try {
            const id = req.params.id;
            const { status, location, note } = req.body;
            if (!ObjectId.isValid(id)) {
                return res.status(400).send({ message: "Invalid Order ID." });
            }

            const booking = await bookingsCollection.findOne({ _id: new ObjectId(id) });
            if (!booking) {
                return res.status(404).send({ modifiedCount: 0, message: "Booking not found." });
            }

            const updateDoc = {};
            if (status) {
                updateDoc.$set = { status: status.toLowerCase() };
                if (status.toLowerCase() === 'shipped') {
                } else if (status.toLowerCase() === 'delivered') {
                }
            }

            const updateResult = await bookingsCollection.updateOne(
                { _id: new ObjectId(id) },
                updateDoc
            );

            if (booking.trackingId) {
                await trackingsCollection.insertOne({
                    trackingId: booking.trackingId,
                    status: status?.toLowerCase() || 'in_progress',
                    location: location || 'Unknown Location',
                    note: note || '',
                    createdAt: new Date()
                });
            }

            res.send(updateResult);
        } catch (err) {
            console.error("Tracking Update Error:", err);
            res.status(500).send({ message: "Failed to update tracking." });
        }
    });

    app.get('/trackings/:trackingId', verifyFBToken, async (req, res) => {
        const trackingId = req.params.trackingId;
        const trackings = await trackingsCollection.find({ trackingId }).sort({ createdAt: 1 }).toArray();
        res.send(trackings);
    });


    app.post('/create-checkout-session', async (req, res) => {
        try {
            const { cost, bookingId, productTitle, userEmail } = req.body;

            const safeCost = parseFloat(cost);

            if (isNaN(safeCost) || safeCost <= 0) {
                return res.status(400).send({ message: 'Invalid or missing cost for payment.' });
            }

            const amountInCents = Math.max(50, Math.round(safeCost * 100));

            const session = await stripe.checkout.sessions.create({
                line_items: [
                    {
                        price_data: {
                            currency: 'usd',
                            product_data: { name: productTitle },
                            unit_amount: amountInCents,
                        },
                        quantity: 1,
                    }
                ],
                metadata: {
                    bookingId: bookingId,
                    userEmail: userEmail
                },
                mode: "payment",
                success_url: `${process.env.CLIENT_URL}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
                cancel_url: `${process.env.CLIENT_URL}/dashboard/payment-cancelled`,
            });


            res.send({ url: session.url });
        } catch (err) {
            console.log("STRIPE ERROR:", err.raw?.message || err.message || err);
            res.status(500).send({ message: "Stripe session failed" });
        }
    });


    app.get('/payment-success', verifyFBToken, async (req, res) => {
        const sessionId = req.query.session_id;

        if (!sessionId) {
            return res.status(400).send({ message: "Session ID missing." });
        }

        try {
            const session = await stripe.checkout.sessions.retrieve(sessionId);

            if (session.payment_status !== 'paid') {
                return res.status(400).send({ success: false, message: "Payment not completed or pending." });
            }

            const bookingId = session.metadata.bookingId;

            if (!bookingId) {
                return res.status(404).send({ message: "Booking ID not found in Stripe metadata." });
            }


            if (!ObjectId.isValid(bookingId)) {
                return res.status(400).send({ message: "Invalid Booking ID from Stripe metadata." });
            }

            const updateResult = await bookingsCollection.updateOne(
                { _id: new ObjectId(bookingId) },
                {
                    $set: {
                        status: 'paid',
                        transactionId: sessionId,
                        paymentMethod: 'Stripe'
                    }
                }
            );

            const booking = await bookingsCollection.findOne({ _id: new ObjectId(bookingId) });
            if (booking && booking.trackingId) {
                await trackingsCollection.insertOne({
                    trackingId: booking.trackingId,
                    status: "payment_received",
                    createdAt: new Date(),
                    note: `Payment via Stripe, Transaction ID: ${sessionId}`
                });
            }

            res.send({
                success: true,
                message: "Payment successful and booking status updated.",
                transactionId: sessionId,
                trackingId: booking?.trackingId || 'N/A'
            });

        } catch (err) {
            console.error("Payment Success Verification Error:", err);
            res.status(500).send({ message: "Failed to verify payment details." });
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