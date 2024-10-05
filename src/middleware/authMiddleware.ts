import { RequestHandler } from "express";
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const SECRET = process.env.SECRET!;

export const authenticateToken: RequestHandler = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        res.status(401).json({ error: 'Token não fornecido'});
        return;
    }

    try {
        const decoded = jwt.verify(token, SECRET) as jwt.JwtPayload;
        req.user = { id: decoded.userId};
        next();
    } catch (error) {
        res.status(403).json({ error: 'Token inválido ou expirado'})
        return;
    }
};