import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import sgMail from "@sendgrid/mail";
import dotenv from "dotenv";
import pool from "./db.js";

dotenv.config();



sgMail.setApiKey(process.env.SENDGRID_API_KEY); // Assurez-vous que votre clé API est dans vos variables d'environnement

const app = express();

const isDevelopment = process.env.NODE_ENV !== "production";

app.use((req, res, next) => {
    const csp = isDevelopment
        ? "default-src 'self'; script-src 'self' 'unsafe-eval'"
        : "default-src 'self'; script-src 'self'";
    res.setHeader("Content-Security-Policy", csp);
    next();
});


app.use(
    cors({
        origin: process.env.REACT_URL,
        methods: ["GET", "POST", "PUT"],
        allowedHeaders: ["Content-Type", "Authorization"],
    })
);
app.use(express.json());



// Middleware pour vérifier le token JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, "your_jwt_secret", (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Route pour obtenir un mot aléatoire
app.get("/api/word", async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT word FROM words ORDER BY RANDOM() LIMIT 1"
        );
        res.json(result.rows[0].word);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server Error");
    }
});

// Route pour traiter une tentative de mot
app.post("/api/guess", (req, res) => {
    const { guess, word } = req.body;

    if (!guess || !word || guess.length !== 5 || word.length !== 5) {
        return res.status(400).send("Invalid input");
    }

    let feedback = [];

    for (let i = 0; i < guess.length; i++) {
        if (guess[i] === word[i]) {
            feedback.push("green");
        } else if (word.includes(guess[i])) {
            feedback.push("yellow");
        } else {
            feedback.push("gray");
        }
    }

    res.json({ feedback });
});

// Route d'inscription
app.post("/api/register", async (req, res) => {
    const { name, email, password } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const result = await pool.query(
            "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id",
            [name, email, hashedPassword]
        );

        const userId = result.rows[0].id;

        const token = jwt.sign({ userId }, "your_jwt_secret", {
            expiresIn: "1h",
        });

        // Envoi de l'email de confirmation
        const msg = {
            to: email,
            from: "schmerberperraud@gmail.com",
            subject: "Confirmation d'inscription",
            text: `Bonjour ${name}, merci de vous être inscrit sur notre site !`,
            html: `<strong>Bonjour ${name}, merci de vous être inscrit sur notre site !</strong>`,
        };

        await sgMail.send(msg);
        console.log("Email envoyé avec succès");

        res.status(201).json({
            message: "User registered successfully. Confirmation email sent.",
            token,
        });
    } catch (err) {
        console.error("Erreur lors de l'envoi de l'email : ", err.message);
        res.status(500).send("Server Error");
    }
});


// Route de connexion
app.post("/api/login", async (req, res) => {
    const { email, password } = req.body;

    try {
        const result = await pool.query(
            "SELECT * FROM users WHERE email = $1",
            [email]
        );
        const user = result.rows[0];

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).send("Invalid credentials");
        }

        const token = jwt.sign({ userId: user.id }, "your_jwt_secret", {
            expiresIn: "1h",
        });
        res.json({ token });
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server Error");
    }
});

// Route pour récupérer le profil d'utilisateur
app.get("/api/profile", authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT name FROM users WHERE id = $1",
            [req.user.userId]
        );
        const user = result.rows[0];

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        res.json({ name: user.name });
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server Error");
    }
});

// Route pour mettre à jour le profil d'utilisateur
app.put("/api/profile", authenticateToken, async (req, res) => {
    const { name } = req.body;
    try {
        const result = await pool.query(
            "UPDATE users SET name = $1 WHERE id = $2 RETURNING name",
            [name, req.user.userId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: "User not found" });
        }

        res.status(200).json({
            message: "Profile updated successfully",
            name: result.rows[0].name,
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server Error");
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
