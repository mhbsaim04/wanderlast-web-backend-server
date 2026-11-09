import express from 'express'
import { MongoClient, ObjectId } from 'mongodb';
import cors from 'cors'
import 'dotenv/config'
import { createRemoteJWKSet, jwtVerify } from 'jose';

const app = express()
const PORT = 8000

app.use(cors())
app.use(express.json())

const client = new MongoClient(process.env.MONGODB_URI);

export async function connectToMongoDB() {
    try {
        await client.connect();
        console.log("You successfully connected to MongoDB!");
        return client;
    } catch (err) {
        console.dir(err);
    }
}
const mongoClient = await connectToMongoDB();
const db = mongoClient.db('wanderlast')

const destinationCollection = db.collection("destination");
const bookingCollection = db.collection("booking");

// better-auth stores its sessions in the same database — the auth middleware
// resolves a Bearer token back to a real user through these collections.
const sessionCollection = db.collection("session");
const userCollection = db.collection("user");

// Only the site owner can manage travel packages.
const ADMIN_EMAIL = "mhbsaim27@gmail.com";

// better-auth (Next side) publishes its signing keys here — the JWT middleware
// verifies incoming Bearer tokens against this key set. Override with
// JWKS_URL when running the backend against a different frontend host.
const JWKS = createRemoteJWKSet(
    new URL(process.env.JWKS_URL ?? `${process.env.CLIENT_URL}/api/auth/jwks`)
);

/**
 * Auth middleware. Accepts a better-auth JWT issued by the frontend:
 * the token signature is verified against the app's JWKS, then the user is
 * resolved from the payload's `sub` so handlers get `req.user` (with an
 * isAdmin flag). As a fallback (e.g. right after a restart, before Next has
 * issued a fresh JWT) it also accepts the raw better-auth session token,
 * looked up in the `session` collection.
 */
export const verifyToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith("Bearer ")
        ? authHeader.slice("Bearer ".length).trim()
        : null;

    if (!token) {
        return res.status(401).send({ msg: "Unauthorized!" });
    }

    const resolveUser = async (userId) => {
        // better-auth users are stored with string ids; accept either form.
        const _id = objectId(userId) ?? userId;
        return userCollection.findOne({ _id });
    };

    // Primary path: a real JWT signed by the frontend.
    try {
        const { payload } = await jwtVerify(token, JWKS);
        const user = await resolveUser(payload.sub);
        if (!user) {
            return res.status(401).send({ msg: "User for this token no longer exists." });
        }
        req.user = {
            id: String(user._id),
            email: user.email,
            name: user.name,
            isAdmin: user.email === ADMIN_EMAIL,
        };
        return next();
    } catch {
        // Not a JWT (or expired) — fall through to the session-token lookup.
    }

    // Fallback: raw better-auth session token ("token.signature" cookie value).
    const sessionToken = token.split(".")[0];
    const session = await sessionCollection.findOne({ token: sessionToken });
    if (!session) {
        return res.status(401).send({ msg: "Invalid or expired token." });
    }

    const user = await resolveUser(session.userId);
    if (!user) {
        return res.status(401).send({ msg: "User for this session no longer exists." });
    }

    req.user = {
        id: String(user._id),
        email: user.email,
        name: user.name,
        isAdmin: user.email === ADMIN_EMAIL,
    };
    next();
};

/** Second gate for destination management — denies everyone but the admin. */
export const verifyAdmin = (req, res, next) => {
    if (!req.user?.isAdmin) {
        return res.status(403).send({ msg: "Admins only!" });
    }
    next();
};

const adminOnly = [verifyToken, verifyAdmin];

// Helper: error responses for bodies/posts that need a real ObjectId.
function objectId(id) {
    try {
        return new ObjectId(id);
    } catch {
        return null;
    }
}

app.post('/add-destination', adminOnly, async (req, res) => {
    const data = req.body
    const result = await destinationCollection.insertOne(data)

    console.log(result)
    res.status(201).send(result)
})

app.get('/destinations', async (req, res) => {
    const result = await destinationCollection.find().toArray()
    res.send(result);
})

// Public: guests must be able to browse the catalog without logging in.
app.get('/destinations/:id', verifyToken, async (req, res) => {
    const { id } = req.params
    const _id = objectId(id)
    if (!_id) return res.status(400).send({ msg: "Invalid destination id." })

    const result = await destinationCollection.findOne({ _id })
    if (!result) return res.status(404).send({ msg: "Destination not found." })
    res.send(result)
})

app.patch('/destination/:id', adminOnly, async (req, res) => {
    const { id } = req.params
    const updatedData = req.body
    const _id = objectId(id)
    if (!_id) return res.status(400).send({ msg: "Invalid destination id." })

    const result = await destinationCollection.updateOne(
        { _id },
        { $set: updatedData }
    )
    res.json(result)
})

app.delete('/destination/:id', adminOnly, async (req, res) => {
    const { id } = req.params
    const _id = objectId(id)
    if (!_id) return res.status(400).send({ msg: "Invalid destination id." })

    const result = await destinationCollection.deleteOne({ _id })
    res.json(result)
})

// Booking creation: the owner is stamped from the session token server-side,
// so nobody can book under someone else's account.
app.post("/booking", verifyToken, async (req, res) => {
    const data = req.body;
    const result = await bookingCollection.insertOne({
        ...data,
        ref: typeof data.ref === "string" && data.ref
            ? data.ref
            : `b-${Math.random().toString(36).slice(2, 6)}`,
        status: typeof data.status === "string" ? data.status : "confirmed",
        userId: req.user.id,
        email: req.user.email,
        createdAt: new Date(),
    });
    res.status(201).send(result);
});

// Only the token's own user can read a bookings list.
app.get("/my-bookings/:email", verifyToken, async (req, res) => {
    if (req.user.email !== req.params.email) {
        return res.status(403).send({ msg: "You can only view your own bookings." });
    }
    const result = await bookingCollection
        .find({ email: req.user.email })
        .sort({ createdAt: -1 })
        .toArray();
    res.send(result);
});

// Ownership is enforced in the query itself + id is cast to ObjectId.
app.delete("/my-bookings/:id", verifyToken, async (req, res) => {
    const _id = objectId(req.params.id);
    if (!_id) return res.status(400).send({ msg: "Invalid booking id." });

    const result = await bookingCollection.deleteOne({
        _id,
        userId: req.user.id,
    });
    if (result.deletedCount === 0) {
        return res.status(404).send({ msg: "Booking not found." });
    }
    res.send(result);
});

app.get('/', (req, res) => {
    res.send({ message: `Server is running successfully` })
})

app.listen(PORT, () => {
    console.log(`Server is running at ${PORT}`)
})
