import { Request, Response, NextFunction, RequestHandler } from 'express';
import { createUser, getUserByEmail } from '../models/userModel'
import bcrypt from 'bcrypt'
const jwt = require('jsonwebtoken');
const SECRET = 'lucastoki'
const refresh_secret = 'lucastoki-refresh'

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

        const accessToken = jwt.sign({userId: user.id}, SECRET, {expiresIn: 10800})
        const refreshToken = jwt.sign({userId: user.id}, refresh_secret, {expiresIn: 604800 })

        res.status(200).json({message: 'Login bem sucedido', refreshToken , accessToken });
        return;
    } catch (error) {
        next(error);
    }
};

export function refreshAccessToken: RequestHandler = (req, res, next) => {

    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(401).json({ error: 'Token de atualização não fornecido' });
    }

    try {
        const decoded = jwt.verify(refreshToken, refresh_secret);
        const accessToken = jwt.sign({ userId: decoded.userId }, SECRET, { expiresIn: 10800 });

        res.status(200).json({ accessToken });

    } catch (error) {
        return res.status(403).json({ error: 'Refresh token inválido ou expirado' });
    }
}
