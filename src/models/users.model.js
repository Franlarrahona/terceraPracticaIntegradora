import mongoose from "mongoose";

mongoose.pluralize(null);

const collection = 'users_index';


const schema = new mongoose.Schema({
    firstName: {type: String, required:true },
    lastName: {type: String, required:true },
    email: {type:String, required: true },
    password: {type: String, required:true},
    role: {type: String, enum:['admin','premium','user'], default: 'user'},
})

const model = mongoose.model(collection, schema);

export default model;