const mongoose = require('mongoose');

const withdrawalSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    amount: {
        type: Number,
        required: true
    },
    withdrawId: {
        type: String,
        required: true
    },
    method: {
        type: String,
        enum: ['cryptocurrency', 'bankTransfer'], 
        required: true
    },
    walletAddress: {
        type: String,
        required: function() { return this.method === 'cryptocurrency'; } // Required if crypto method is chosen
    },
    walletName: {
        type: String,
        required: function() { return this.method === 'cryptocurrency'; } // Required if crypto method is chosen
    },
    bankName: {
        type: String,
        required: function() { return this.method === 'bankTransfer'; } // Required if bankTransfer method is chosen
    },
    accountNumber: {
        type: String,
        required: function() { return this.method === 'bankTransfer'; } // Required if bankTransfer method is chosen
    },
    routingNumber: {
        type: String,
        required: function() { return this.method === 'bankTransfer'; } // Required if bankTransfer method is chosen
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('Withdrawal', withdrawalSchema);



