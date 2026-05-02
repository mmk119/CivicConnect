const fs = require('fs/promises');
const path = require('path');
require('../config/env');
const db = require('../db');

const migrationsDir = path.join(__dirname, '..', 'migrations');

// Parses SQL that may use DELIMITER directives (for stored procedures).
// Returns an array of individual SQL statements, without DELIMITER lines.
function splitStatements(sql) {
    const results = [];
    let delimiter = ';';
    let current = '';
    let i = 0;

    while (i < sql.length) {
        // Detect DELIMITER directive at beginning of a line
        const rest = sql.slice(i);
        const delimMatch = rest.match(/^DELIMITER[ \t]+(\S+)[ \t]*(?:\r?\n|$)/i);
        if (delimMatch) {
            // Flush any accumulated statement before the directive
            const stmt = current.trim();
            if (stmt) results.push(stmt);
            current = '';
            delimiter = delimMatch[1];
            i += delimMatch[0].length;
            continue;
        }

        // Check if current position starts the active delimiter
        if (sql.slice(i, i + delimiter.length) === delimiter) {
            const stmt = current.trim();
            if (stmt) results.push(stmt);
            current = '';
            i += delimiter.length;
            // Skip trailing whitespace/newlines after delimiter
            while (i < sql.length && /[ \t\r\n]/.test(sql[i])) i++;
            continue;
        }

        current += sql[i];
        i++;
    }

    const remaining = current.trim();
    if (remaining) results.push(remaining);

    return results;
}

async function ensureMigrationTable() {
    await db.execute(`
        CREATE TABLE IF NOT EXISTS SchemaMigrations (
            migration_name VARCHAR(255) PRIMARY KEY,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);
}

async function getAppliedMigrations() {
    const [rows] = await db.execute('SELECT migration_name FROM SchemaMigrations');
    return new Set(rows.map(row => row.migration_name));
}

async function runMigration(fileName) {
    const filePath = path.join(migrationsDir, fileName);
    const sql = await fs.readFile(filePath, 'utf8');
    const statements = splitStatements(sql);

    const connection = await db.getConnection();
    try {
        await connection.beginTransaction();
        for (const statement of statements) {
            try {
                await connection.query(statement);
            } catch (err) {
                // 1060 = ER_DUP_FIELDNAME, 1061 = ER_DUP_KEYNAME — safe to ignore
                if (err.errno === 1060 || err.errno === 1061) {
                    console.warn(`Warning (skipped): ${err.message}`);
                } else {
                    throw err;
                }
            }
        }
        await connection.execute(
            'INSERT INTO SchemaMigrations (migration_name) VALUES (?)',
            [fileName]
        );
        await connection.commit();
        console.log(`Applied ${fileName}`);
    } catch (err) {
        await connection.rollback();
        throw err;
    } finally {
        connection.release();
    }
}

async function main() {
    await ensureMigrationTable();
    const applied = await getAppliedMigrations();
    const files = (await fs.readdir(migrationsDir))
        .filter(file => /^\d+_.+\.sql$/.test(file))
        .sort();

    for (const file of files) {
        if (applied.has(file)) {
            console.log(`Skipping ${file}`);
            continue;
        }
        await runMigration(file);
    }

    await db.end();
}

main().catch(async err => {
    console.error('Migration failed:', err);
    await db.end();
    process.exit(1);
});
