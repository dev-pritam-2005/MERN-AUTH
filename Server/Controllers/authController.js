import bcrypt from 'bcryptjs'
import jwt from "jsonwebtoken"
import userModel from '../models/userModel.js';

export const register = async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.json({ success: false, message: 'Missing details' });
    }

    try {
        const existingUser = await userModel.findOne({ email });

        if (existingUser) {
            return res.json({ success: false, message: 'Email already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new userModel({ name, email, password: hashedPassword });

        await user.save();

        // ✅ Fix the typo: expiresIn (not expiresIN)
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.json({ success: true });
        
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};

// export const register = async (req , res)=>{
//     const {name, email, password} = req.body;
//     if(!name|| !email ||!password){
//         return res.json({success: false , message: 'Missing details'})
//     }
//     try {

//         const exestingUser = await userModel.findOne({email})

//         if(exestingUser){
//             return res.json({success: false , message: 'Email already exists'}) 
//         }

//         const hashedPassword = await bcrypt.hash(password,10)

//         const user = new userModel({name, email , password:hashedPassword})
        
//         await user.save()
//         const token = jwt.sign({id:user._id},process.env.JWT_SECREAT, {expiresIn:'7d'});

//         res.cookie('token',token ,{
//             httpOnly:true,
//             secure: process.env.NODE_ENV === 'production',
//             sameSite: process.env.NODE_ENV === 'production'?'none' : 'strict',
//             maxAge: 7*24*60*60*1000

//         });
//         return res.json({success:true});
//         /*

// Code Breakdown:

// res.cookie('token', token, {
//     httpOnly: true,
//     secure: process.env.NODE_ENV === 'production',
//     sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
//     maxAge: 7 * 24 * 60 * 60 * 1000;
// }); 

// res.cookie('token', token, {...})

// res.cookie() is an Express.js method that sets a cookie on the client’s browser.

// 'token' is the cookie name.

// token is the cookie value, usually a JWT (JSON Web Token) for authentication.

// httpOnly: true	Prevents client-side JavaScript from accessing the cookie. Helps prevent XSS attacks.

// secure: process.env.NODE_ENV === 'production'	Ensures cookies are sent only over HTTPS in production (i.e., when NODE_ENV is 'production').
// sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict'	Controls cross-site cookie behavior:

// - 'strict' (default in development) allows cookies only from the same site.

// - 'none' (in production) allows cookies to be sent across different sites (important for cross-site authentication) but requires secure: true.

// maxAge: 7 * 24 * 60 * 60 * 1000	Sets the cookie expiration time in milliseconds (7 days).

// When to Use This?
// Authentication: Storing JWTs for user sessions.
// Security Best Practices: Protecting cookies from XSS & CSRF attacks.
// Cross-Origin Requests: Necessary when using APIs across different domain
//         */
        

//     } catch (error) {
//         res.json({success:false , message:error.message})
//     }
// }

export const login = async (req,res)=>{

    const{email,password}=req.body

    if(!email || !password){
        return res.json({success:false, message:'Email and password are requaired'})
    }
        try {
            const user = await userModel.findOne({email});

        
            if (!user) {
                return res.json({ success: false, message: 'Invalid email or password' });
            }

            const isMatch =await bcrypt.compare(password,user.password)

            if(!isMatch){
                return res.json({ success: false, message: 'Invalid  password' });
            }

        const token = jwt.sign({id:user._id},process.env.JWT_SECREAT, {expiresIn:'7d'});

        res.cookie('token',token ,{
            httpOnly:true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production'?'none' : 'strict',
            maxAge: 7*24*60*60*1000

        })
        return res.json({success:true});

            
        } catch (error) {
           return res.json({success:false , message:error.message});

        }
    
}



export const logOut = async(req,res)=>{
    try {
        res.clearCookie('token',{
            httpOnly:true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production'?'none' : 'strict',
            
        })

        return res.json({success:true , message:'Logged Out'})
    } catch (error) {
        return res.json({success:false , message:error.message});
    }

}