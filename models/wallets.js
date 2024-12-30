const mongoose = require('mongoose')

const WalletSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'user'}, 
    Bitcoin:{
        type:String
    },
    Ethereum:{
        type:String
    },
    USDT:{
        type:String
    },
})

module.exports =mongoose.model('wallets', WalletSchema)