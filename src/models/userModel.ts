import pool from '../db'
import { User } from '../interfaces'

export const createUser = async (user: User) => {
    const { username, email, password } = user;
    const result = await pool.query(
        'INSERT INTO auth.users(username, email, password) VALUES ($1, $2, $3) RETURNING *',
        [username, email, password]
    );
    return result.rows[0]
};

export const getUserByEmail = async (email: string) => {
    const result = await pool.query('SELECT * FROM auth.users WHERE email = $1', [email]);
    return result.rows[0]
};