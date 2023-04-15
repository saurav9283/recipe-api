import express  from "express"
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'
import { UserModel } from "../models/Users.js"
const router=express.Router()

router.post("/register",async (req,res)=>{
    const {username,password}=req.body;
    const user= await UserModel.findOne({username});

    if(user)
    {
          return res.json({message:"User Already exist"});
    }
    const hashedPasssword= await bcrypt.hash(password,10);
    const newUser=new UserModel({username,password:hashedPasssword});
    await newUser.save()
     .then(item => {
          res.json({message:"User Register Successfully!"});
     })
     .catch(err => {
     res.status(400).send({message:"Unable to register!"});
     });
    
    
    

});
router.post("/login",async (req,res)=>{
     const {username,password}=req.body;
     const user= await UserModel.findOne({username});
     if(!user)
    {
          return res.json({message:"User Not found"});
    }

    const isPassword= await bcrypt.compare(password,user.password);
    if(!isPassword)
    {
          return res.json({message:"User password is Incorrect!"});
    }
    const token =jwt.sign({id:user._id},"secret");
    res.json({token,userID:user._id});
 
});

export {router as userRouter}; 

export const verifyToken=(req,res,next)=>{
      const token= req.headers.authorization;
      if(token)
      {
            jwt.verify(token,"secret",(err)=>{
                  if(err) return res.sendStatus(403);
                  next();
            });
      }
      else{
            res.sendStatus(401);
      }
}