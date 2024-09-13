import { Router, Request, Response } from 'express';
import { User } from '../models/user.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

export const login = async (req: Request, res: Response) => {
  const { username, password } = req.body;
  const user = await User.findOne({
    where: { username },
  });

  if (!user) {
    return res.status(401).json({ message: 'Authentication Failed'});
  }
  const passwordIsValidated = await bcrypt.compare(password, user.password);
  if (!passwordIsValidated) {
    return res.status(401).json({message: 'Authentication Failed'});
  }
  const secretKey = process.env.JWT_SECRET_KEY || '';
  const token = jwt.sign({ username }, secretKey, { expiresIn: '1h' });
  return res.json({ token });  
};
export const signUp = async (req: Request, res: Response) => {
  try {
    const { username, email, password } = req.body
    const newUser = await User.create({ username, email, password });
    console.log(newUser);
    const secretKey = process.env.JWT_SECRET_KEY || '';
    const token = jwt.sign({ username: newUser.username }, secretKey, { expiresIn: '1h' });
    res.json({ token }); 
  } catch (error: any) {
    res.status(400).json({ message: error.message });
  }
};
  // TODO: If the user exists and the password is correct, return a JWT token


const router = Router();

// POST /login - Login a user
router.post('/login', login);
router.post('/signup', signUp);


export default router;
