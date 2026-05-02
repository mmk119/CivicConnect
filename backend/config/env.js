const path = require('path');
const dotenv = require('dotenv');

const envPath = path.join(__dirname, '..', '.env');

dotenv.config({ path: envPath });
dotenv.config();

module.exports = {
    envPath
};
