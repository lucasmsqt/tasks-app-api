import { Request, Response, NextFunction, RequestHandler } from 'express';
import { createUser, getUserByEmail } from '../models/userModel'
import bcrypt from 'bcrypt'

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
            res.status(404).json({ error: 'Usuário não encontrado '});
            return;
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            res.status(400).json({ error: 'Senha incorreta' });
            return;
        }

        res.status(200).json({message: 'Login bem sucedido', user });
        return;
    } catch (error) {
        next(error);
    }
};

