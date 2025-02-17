import express from 'express'
import { login, logOut, register, sendVerifyOtp, verifyEmail } from '../Controllers/authController.js';
import userAuth from '../middleWare/userAuth.js';

const authRouter = express.Router();

authRouter.post('/register', register);
authRouter.post('/login', login);
authRouter.post('/logout', logOut);
authRouter.post('/send-verify-otp', userAuth,sendVerifyOtp);
authRouter.post('/verify-account', userAuth,verifyEmail);

export default authRouter;