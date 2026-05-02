const defaultAllowedOrigins = [
    'http://localhost:3000',
    'http://127.0.0.1:5500',
    'https://civicconnect-2.onrender.com',
    'https://CivicConnect-516m.onrender.com'
];

function parseAllowedOrigins(value) {
    return String(value || '')
        .split(',')
        .map(origin => origin.trim())
        .filter(Boolean);
}

function getAllowedOrigins(env = process.env) {
    const configured = parseAllowedOrigins(env.CORS_ORIGINS);
    return configured.length > 0 ? configured : defaultAllowedOrigins;
}

function createCorsOptions(env = process.env) {
    const allowedOrigins = getAllowedOrigins(env);

    return {
        origin: (origin, callback) => {
            if (!origin || allowedOrigins.includes(origin)) {
                return callback(null, true);
            }
            return callback(new Error('CORS not allowed from this origin: ' + origin));
        },
        credentials: true,
        methods: ['GET', 'POST', 'DELETE', 'PATCH'],
        allowedHeaders: ['Content-Type', 'Authorization']
    };
}

module.exports = {
    createCorsOptions,
    getAllowedOrigins
};
