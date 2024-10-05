import { RequestHandler } from 'express';
import { createUser, getUserByEmail } from '../models/userModel'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import dotenv from 'dotenv'

dotenv.config();

const SECRET = process.env.SECRET!;
const REFRESH_SECRET = process.env.REFRESH_SECRET!;

export const registerUser: RequestHandler = async (req, res, next) => {
    try {
        const { username, email, password } = req.body;

        const existingUser = await getUserByEmail(email);
        if (existingUser) {
            res.status(400).json({error: 'Email já cadastro'});
            return;
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await createUser({ username, email, password: hashedPassword});
        res.status(201).json(newUser);
        return;
    } catch (error) {
        next(error);
    }
};

export const loginUser: RequestHandler = async (req, res, next)  => {
    try {
        const { email, password } = req.body;
        const user = await getUserByEmail(email);
        if (!user) {
            res.status(404).json({ error: 'Usuário não encontrado'});
            return;
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            res.status(400).json({ error: 'Senha incorreta' });
            return;
        }

        const accessToken = jwt.sign({userId: user.id}, SECRET, {expiresIn: '3h'});
        const refreshToken = jwt.sign({userId: user.id}, REFRESH_SECRET, {expiresIn: '7d' });

        res.status(200).json({message: 'Login bem sucedido', refreshToken , accessToken });
        return;
    } catch (error) {
        next(error);
    }
};

export const refreshAccessToken: RequestHandler = (req, res, next) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        res.status(401).json({ error: 'Token de atualização não fornecido' });
        return;
    }

    try {
        const decoded = jwt.verify(refreshToken, REFRESH_SECRET) as jwt.JwtPayload;
        const accessToken = jwt.sign({ userId: decoded.userId }, SECRET, { expiresIn: '3h' });

        res.status(200).json({ accessToken });

    } catch (error) {
        res.status(403).json({ error: 'Refresh token inválido ou expirado' });
        return;
    }
}
