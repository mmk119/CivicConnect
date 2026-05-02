const path = require('path');

function registerMiscRoutes(app, { authenticateToken, frontendDir }) {
    app.get('/api/protected', authenticateToken, (req, res) => {
        res.json({ message: 'Access granted to protected resource', user: req.user });
    });

    app.get('/', (req, res) => {
        res.sendFile(path.join(frontendDir, 'landingpage.html'));
    });
}

module.exports = registerMiscRoutes;
