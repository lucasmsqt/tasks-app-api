import { Router } from 'express';
import { registerUser, loginUser, refreshAccessToken } from '../controllers/userController';
import { authenticateToken } from '../middleware/authMiddleware';

const router = Router();

router.post('/register', registerUser);
router.post('/login', loginUser);
router.post('/token', refreshAccessToken);

router.get('/profile', authenticateToken, (req, res) => {
    res.json({ message: 'Este é o perfil do usuário', userId: req.user?.id })
});

export default router;