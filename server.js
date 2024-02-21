const express = require("express");
const mysql = require("mysql");
const bcrypt = require("bcrypt");
const session = require("express-session");
const app = express();
const port = 3000;

// Serve static files from the 'public' directory
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

// Set up express-session middleware
app.use(session({
    secret: '987654321',
    resave: true,
    saveUninitialized: true
}));

const db = mysql.createConnection({
    host: 'localhost',
    user: 'demo',
    password: 'demo1234',
    database: 'portfolio_db',
});

db.connect((err) => {
    if (err) {
        console.error("Database connection failed:", err);
    } else {
        console.log("Connected to database");
    }
});

// Serve the HTML file
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});

app.post('/register', (req, res) => {
    const { firstname, lastname, username, password, confirm_password } = req.body;

    // basic validation
    if (!firstname || !lastname || !username || !password || !confirm_password) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    if (password !== confirm_password) {
        return res.status(400).json({ message: 'Passwords do not match' });
    }

    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            console.error('Password hashing failed:', err);
            return res.status(500).json({ message: 'Registration failed' });
        }

        const sql = 'INSERT INTO users (firstname, lastname, username, password) VALUES (?, ?, ?, ?)';
        db.query(sql, [firstname, lastname, username, hashedPassword], (err, result) => {
            if (err) {
                console.error('Registration failed:', err);
                return res.status(500).json({ message: 'Registration failed' });
            }

            console.log('User registered successfully');
            // redirect to homepage
            res.sendFile(__dirname + '/public/index.html');
        });
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    const sql = 'SELECT * FROM users WHERE username = ?';
    db.query(sql, [username], (err, results) => {
        if (err) {
            console.error('Login failed:', err);
            return res.status(500).json({ message: 'Login failed' });
        }

        if (results.length === 0) {
            // User not found in the database
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        const user = results[0];

        // Compare the entered password with the hashed password from the database
        if (bcrypt.compareSync(password, user.password)) {
            // Authentication successful
            // Set user data in the session for future authentication
            req.session.user = { id: user.id, username: user.username };

            // Redirect to homepage.html after successful login
            res.sendFile(__dirname + '/public/homepage.html');
        } else {
            // Passwords do not match
            res.status(401).json({ message: 'Invalid username or password' });
        }
    });
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
