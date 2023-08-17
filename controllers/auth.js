import { db } from "../connect.js";
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken";

export const register = (req,res)=>
{
    // CHECK IF USER EXIST
    const query = "SELECT * FROM users WHERE username = ?"

    db.query(query,[req.body.username], (err,data)=>{
        if(err)
            return res.status(500).send(err);

        if(data.length)
            return res.status(409).send("User already exists!")

        // CREATE A NEW USER
        // hash password
        const salt = bcrypt.genSaltSync(10);
        const hashedPassword = bcrypt.hashSync(req.body.password,salt);

        const query = "INSERT INTO users (username, email,password,name) value(?)"

        db.query(query,[req.body.username,req.body.email,hashedPassword,req.body.name], (err,data) =>{
            if(err)
                return res.status(200).send("User has been created!");
        });
    });
    
}

export const login = (req,res)=>
{
    const query = "SELECT * FROM users WHERE username=?";

    db.query(query,[req.body.username], (err,data)=>
    {
        if(err)
            return res.status(500).json(err);

        if(data.length === 0)
            return res.status(404).json("User not found!");

        const checkPassword = bcrypt.compareSync(req.body.password, data[0].password);

        if(!checkPassword)
            return res.status(400).json("Wrong password or username");

        /// take the user id. In this case data[0] is the user
        const token = jwt.sign({ id: data[0].id, },"secretkey");

        const { password, ...others } = data[0];

        res.cookie("accessToken", token,{
            httpOnly: true,
        }).status(200).json(others);
    })
}

export const logout = (req,res)=>
{
    res.clearCookie("accessToken",
    {
        secure:true,
        sameSite:"none"
    }).status(200).json("User has been logged out");
}