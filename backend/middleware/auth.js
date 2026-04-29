function createAuthenticateToken(jwt, jwtSecret) {
    return function authenticateToken(req, res, next) {
        const authHeader = req.headers.authorization;
        const token = authHeader && authHeader.split(' ')[1];
        if (!token) return res.sendStatus(401);

        jwt.verify(token, jwtSecret, (err, user) => {
            if (err) return res.sendStatus(403);
            req.user = user;
            next();
        });
    };
}

function requireAdmin(req, res, next) {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ error: 'Admin privileges required.' });
    }
    next();
}

module.exports = {
    createAuthenticateToken,
    requireAdmin
};
