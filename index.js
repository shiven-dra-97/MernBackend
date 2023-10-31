const express = require("express")
const mongoose = require('mongoose');
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors")
require("dotenv").config()
const app = express()
app.use(cors())
app.use(express.json());

const port = process.env.PORT || 5000;
const uri = process.env.DATABASE;

main().catch(err => console.log(err));

async function main() {
    await mongoose.connect(uri, {
        useNewUrlParser: true,
        useUnifiedTopology: true
    });

    console.log("db connected")
}


const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String
});

const User = mongoose.model('User', userSchema);

const userTransactionSchema=new mongoose.Schema({
    user:{
       type:mongoose.Schema.Types.ObjectId,
       ref:'User',
       required: true
    },
    date: Date,
    category: String,
    spent_on: String,
    price: Number
})

const UserTransaction=mongoose.model('UserTransaction',userTransactionSchema)



const authenticateToken=(req,res,next)=>{
    let jwtToken
    const authHeader=req.headers["authorization"];
    if(authHeader!==undefined){
        jwtToken=authHeader.split(' ')[1];
    }
    if(jwtToken===undefined){
        res.status(401);
        res.send({error:"Invalid JWT Token"})
    }
    else{
        jwt.verify(jwtToken,"MY_SECRET_TOKEN",async(error,payload)=>{
           
            if(error){
                res.status(401);
                res.send({error:"Invalid JWT Token"});
            }
            else{
                req.email=payload.email;
                next()
            }
        })
    }
}

app.post("/login",async(req,res)=>{
    const {email,password}=req.body
    const selectUser=await User.findOne({email:email})
    if(selectUser===null){
        res.status(400)
        res.send({error:"Invalid User"})
    }else{
        const isPasswordMatched= await bcrypt.compare(password,selectUser.password);
        if(isPasswordMatched===true){
            const payload={
                email:email
            }
            const jwtToken=jwt.sign(payload,"MY_SECRET_TOKEN")
            res.send({jwtToken})
        }else{
            res.status(400)
            res.send({error:"Invalid password"})
        }

    }
}) 


app.post("/signup", async (req, res) => {
    const { name, email, password } = req.body
    if (!name.trim() || !email.trim() || !password.trim()) {
        res.status(400)
        return res.send({ error: "Please enter valid name, email, and password" });
    }
    const hashedPassword = await bcrypt.hash(password, 10)
    const checkUser = await User.findOne({ email: email });
    if (checkUser === null) {
        let user = new User()
        user.name = name
        user.email = email
        user.password = hashedPassword
        const doc = await user.save()
        res.send({message:"You have registered successfully"});
    }else{
        res.status(400)
        res.send({error:"Email already exists"})
    }
})

app.get("/profile",authenticateToken,async(req,res)=>{
    let {email}=req;
    const userObject=await User.findOne({email:email})
    res.send({name:userObject.name})
})

app.post('/transactions',authenticateToken,async(req,res)=>{
    let {email}=req
    const {date,category,spentOn,price}=req.body
    const user_id= await User.findOne({email:email})
    let transaction=new UserTransaction()
    transaction.user=user_id._id,
    transaction.date=date,
    transaction.category=category,
    transaction.spent_on=spentOn,
    transaction.price=price
    const saveTransaction=await transaction.save()
    res.send({message:"Transaction submitted successfully"});
})

app.get('/getTransactions',authenticateToken,async(req,res)=>{
    let {email}=req
    const user_object=await User.findOne({email:email})
    const personal_user_transaction=await UserTransaction.find().where({user:user_object._id}).sort({ date: -1 })
    res.send(personal_user_transaction)
})

app.delete('/deleteTransactions', authenticateToken,async(req,res)=>{
    try {
        const {transactionsIds}=req.body
        await UserTransaction.deleteMany({_id:{$in:transactionsIds}})
        res.send({ message: 'Transactions deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
    
})

app.listen(port, () => {
    console.log(`listening on port ${port}`)
}) 