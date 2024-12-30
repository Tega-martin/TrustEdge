const userModel = require('../models/userModel');
const investmentModel = require('../models/investmentModel');
const withdrawalModel = require('../models/witdrawalModel')
const schedule = require('node-schedule');
const transationModel = require('../models/transationModel')
const {withdrawalSuccessMail} = require ('../utils/mailTemplates')
const sendEmail= require('../middlewares/mail')

// // Schedule a job to run every day at midnight
// const job = schedule.scheduleJob('0 0 * * *', async () => {
//     // Check if 30 days have elapsed since the investment was made
//     const currentDate = new Date();
//     const endDate = new Date(investment.endDate);
//     const daysElapsed = Math.floor((currentDate - endDate) / (1000 * 60 * 60 * 24));

//     if (daysElapsed >= 30) {
//         // Add interest to the user's balance
//         user.balance += investment.expectedReturn - investment.amount;

//         // Save the updated user document
//         await user.save();

//         console.log(`Interest of ${investment.expectedReturn - investment.amount} added to user ${userId} after 30 days.`);
//     }
//});




const basicPlan = async (req, res) => {
    try {
        const { userId } = req.params;
        let { amount, scheduleType, scheduleTime, wallet } = req.body;

        // Find the user
        const user = await userModel.findById(userId);

         // Generate a random deposit number
         function generateRandomNumbers() {
            const randomNumbers = [];
            for (let i = 0; i < 6; i++) {
                randomNumbers.push(Math.floor(Math.random() * 10)); // Generates a random number between 0 and 9
            }
            const investmentNumber = randomNumbers.join(''); // Convert array to string
            return `#${investmentNumber}`; // Prepend "#" symbol to the ticket number
        }
      
       
        // Check if the user has sufficient balance in the selected wallet
        if (user[wallet] < amount) {
            return res.status(400).json({ message: 'Insufficient balance, please deposit' });
        }

        // Determine investment amount within the range of 2000 to 10000
        if (amount < 5000 || amount > 14999) {
            return res.status(400).json({ message: 'Investment amount must be between $5000 and $14999' });
        }

        // Validate the scheduleTime
        let scheduleDate;
        if (scheduleType === 'later') {
            // Parse the scheduleTime as a Date object
            scheduleDate = new Date(scheduleTime);

            // Validate scheduleTime is not in the past
            if (scheduleDate < new Date()) {
                return res.status(400).json({ message: 'Schedule time cannot be in the past' });
            }

            // Check if the parsing was successful and if the result is a valid date
            if (isNaN(scheduleDate.getTime())) {
                return res.status(400).json({ message: 'Invalid scheduleTime format. Must be a valid date and time.' });
            }

            // Calculate the time difference between now and the scheduled time
            const timeDifference = scheduleDate.getTime() - Date.now();

            // If the scheduled time is within 5 minutes, log a message
            if (timeDifference <= 5 * 60 * 1000) {
                console.log('Investment plan is about to start.');
            }
        } else {
            // Default to current date if not scheduled for later
            scheduleDate = new Date();
        }

        // //     // Deduct the investment amount from the selected wallet
        // //     // Deduct withdrawal amount from all wallets
        // const wallets = ['depositWallet', 'intrestWallet', 'referalWallet'];

        // for (let wallet of wallets) {
        //     if (user[wallet] > 0) {
        //         // Deduct from wallet if balance is not zero
        //         user[wallet] -= amount;
        //     }
        // }
        


       // Deduct the full investment amount from each of the three wallets
       const wallets = ['accountBalance','depositWallet', 'intrestWallet', 'referalWallet'];
       for (let wallet of wallets) {
           const deductionAmount = Math.min(amount, user[wallet]); // Deduct the minimum of amount or wallet balance
           user[wallet] -= deductionAmount;
       }
           
            //   user.accountBalance -= amount
              await user.save();
        // Create investment plan
        const investment = new investmentModel({
            userId,
            amount,
            scheduleType,
            plan: 'basic',
            wallet,
            startDate: scheduleDate,
            ongoing: true, // Set the ongoing status to true
            investmentId:generateRandomNumbers()
        
        });
        await investment.save();
        
          
    

        // Calculate profit (25% of the investment amount)
        const profitPerDay = amount * 0.25;
        const totalProfit = profitPerDay * 30;

        // Calculate the date when the balance should be updated (30 days from now or scheduled date)
        const updateBalanceDate = new Date(scheduleDate);
        updateBalanceDate.setDate(updateBalanceDate.getDate() + 30);

        // Schedule a job to update the balance after 30 days
        schedule.scheduleJob(updateBalanceDate, async () => {
            // Update the ongoing status to false
            investment.ongoing = false;
            await investment.save();

            // Add total profit to the user's balance after 30 days
            // user.intrestWallet += totalProfit;
            // user.accountBalance +=totalProfit
            user.referralCount += totalProfit
            
            await user.save();

            console.log(`Total profit of ${totalProfit} added to user ${userId} after 30 days.`);
        });
        const depositTransaction = new transationModel({
            Name:user.userName,
            type: 'investment',
            amount:amount ,
            userId: req.params.userId,
             Id:investment.investmentId
        });
        await depositTransaction.save();

        // Return investment details
        res.status(200).json({ 
            message: 'Investment  successfully', 
            investment: { userId, amount, plan: 'basic', scheduleType, scheduleTime },
            user,
            expectedReturn: amount + totalProfit,
            depositTransaction
        });
       
    } catch (error) {
        console.error('Error scheduling investment:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};






const proPlan = async (req, res) => {
    try {
        const { userId } = req.params;
        let { amount, scheduleType, scheduleTime,wallet } = req.body;

        // Find the user
        const user = await userModel.findById(userId);
      
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Check if the user has sufficient balance in the selected wallet
        if (user[wallet] < amount) {
            return res.status(400).json({ message: 'Insufficient balance, please deposit' });
        }

        // Determine investment amount within the range of 10000 to 50000
        if (amount < 15000 || amount > 24999) {
            return res.status(400).json({ message: 'Investment amount must be between $15000 and $24999' });
        }

        // Generate a random deposit number
        function generateRandomNumbers() {
            const randomNumbers = [];
            for (let i = 0; i < 6; i++) {
                randomNumbers.push(Math.floor(Math.random() * 10)); // Generates a random number between 0 and 9
            }
            const investmentNumber = randomNumbers.join(''); // Convert array to string
            return `#${investmentNumber}`; // Prepend "#" symbol to the ticket number
        }

        // Validate the scheduleTime
        let scheduleDate;
        if (scheduleType === 'later') {
            // Parse the scheduleTime as a Date object
            scheduleDate = new Date(scheduleTime);

            // Validate scheduleTime is not in the past
            if (scheduleDate < new Date()) {
                return res.status(400).json({ message: 'Schedule time cannot be in the past' });
            }

            // Check if the parsing was successful and if the result is a valid date
            if (isNaN(scheduleDate.getTime())) {
                return res.status(400).json({ message: 'Invalid scheduleTime format. Must be a valid date and time.' });
            }

            // Calculate the time difference between now and the scheduled time
            const timeDifference = scheduleDate.getTime() - Date.now();

            // If the scheduled time is within 5 minutes, log a message
            if (timeDifference <= 5 * 60 * 1000) {
                console.log('Investment plan is about to start.');
            }
        } else {
            // Default to current date if not scheduled for later
            scheduleDate = new Date();
        }

         // Deduct the full investment amount from each of the three wallets
         const wallets = ['accountBalance','depositWallet', 'intrestWallet', 'referalWallet'];
         for (let wallet of wallets) {
             const deductionAmount = Math.min(amount, user[wallet]); // Deduct the minimum of amount or wallet balance
             user[wallet] -= deductionAmount;
         }
             
              //   user.accountBalance -= amount
                await user.save();
        // Create investment plan
        const investment = new investmentModel({
            userId,
            amount,
            scheduleType,
            plan: 'pro',
            wallet,
            startDate: scheduleDate,
            ongoing: true,// Set the ongoing status to true
            investmentId:generateRandomNumbers()
        });
        await investment.save();

        // Calculate profit (25% of the investment amount)
        const profitPerDay = amount * 0.35;
        const totalProfit = profitPerDay * 30;

        // Calculate the date when the balance should be updated (30 days from now or scheduled date)
        const updateBalanceDate = new Date(scheduleDate);
        updateBalanceDate.setDate(updateBalanceDate.getDate() + 30);

        // Schedule a job to update the balance after 30 days
        schedule.scheduleJob(updateBalanceDate, async () => {
            // Update the ongoing status to false
            investment.ongoing = false;
            await investment.save();

           // Add total profit to the user's balance after 30 days
        //    user.intrestWallet += totalProfit;
        //    user.accountBalance +=totalProfit
        user.referralCount += totalProfit
           await user.save()

            console.log(`Total profit of ${totalProfit} added to user ${userId} after 30 days.`);
        });
        const depositTransaction = new transationModel({
            Name:user.userName,
            type: 'investment',
            amount:amount ,
            userId: req.params.userId,
             Id:investment.investmentId
        });
        await depositTransaction.save();

        // Return investment details
        res.status(200).json({ 
            message: 'Investment  successfully', 
            investment: { userId, amount, plan: 'basic', scheduleType, scheduleTime },
            user,
            expectedReturn: amount + totalProfit,
            depositTransaction
        });
    } catch (error) {
        console.error('Error scheduling investment:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};





const premiumPlan = async (req, res) => {
    try {
        const { userId } = req.params;
        let { amount, scheduleType, scheduleTime,wallet } = req.body;

        // Find the user
        const user = await userModel.findById(userId);
      
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Check if the user has sufficient balance in the selected wallet
        if (user[wallet] < amount) {
            return res.status(400).json({ message: 'Insufficient balance, please deposit' });
        }

         // Determine investment amount within the range of50000 to 100000
         
         if (amount < 25000 || amount > 49999) {
            return res.status(400).json({ message: 'Investment amount must be between $25000 and $49999' });
        }

        // Generate a random deposit number
        function generateRandomNumbers() {
            const randomNumbers = [];
            for (let i = 0; i < 6; i++) {
                randomNumbers.push(Math.floor(Math.random() * 10)); // Generates a random number between 0 and 9
            }
            const investmentNumber = randomNumbers.join(''); // Convert array to string
            return `#${investmentNumber}`; // Prepend "#" symbol to the ticket number
        }

        // Validate the scheduleTime
        let scheduleDate;
        if (scheduleType === 'later') {
            // Parse the scheduleTime as a Date object
            scheduleDate = new Date(scheduleTime);

            // Validate scheduleTime is not in the past
            if (scheduleDate < new Date()) {
                return res.status(400).json({ message: 'Schedule time cannot be in the past' });
            }

            // Check if the parsing was successful and if the result is a valid date
            if (isNaN(scheduleDate.getTime())) {
                return res.status(400).json({ message: 'Invalid scheduleTime format. Must be a valid date and time.' });
            }

            // Calculate the time difference between now and the scheduled time
            const timeDifference = scheduleDate.getTime() - Date.now();

            // If the scheduled time is within 5 minutes, log a message
            if (timeDifference <= 5 * 60 * 1000) {
                console.log('Investment plan is about to start.');
            }
        } else {
            // Default to current date if not scheduled for later
            scheduleDate = new Date();
        }

      // Deduct the full investment amount from each of the three wallets
      const wallets = ['accountBalance','depositWallet', 'intrestWallet', 'referalWallet'];
      for (let wallet of wallets) {
          const deductionAmount = Math.min(amount, user[wallet]); // Deduct the minimum of amount or wallet balance
          user[wallet] -= deductionAmount;
      }
          
           //   user.accountBalance -= amount
             await user.save();

        // Create investment plan
        const investment = new investmentModel({
            userId,
            amount,
            scheduleType,
            plan: 'premium',
            wallet,
            startDate: scheduleDate,
            ongoing: true, // Set the ongoing status to true
            investmentId:generateRandomNumbers()
        });
        await investment.save();

      // Calculate profit (25% of the investment amount)
      const profitPerDay = amount * 0.50;
      const totalProfit = profitPerDay * 30;

        // Calculate the date when the balance should be updated (30 days from now or scheduled date)
        const updateBalanceDate = new Date(scheduleDate);
        updateBalanceDate.setDate(updateBalanceDate.getDate() + 30);

        // Schedule a job to update the balance after 30 days
        schedule.scheduleJob(updateBalanceDate, async () => {
            // Update the ongoing status to false
            investment.ongoing = false;
            await investment.save();

          // Add total profit to the user's balance after 30 days
        //   user.intrestWallet += totalProfit;
        //   user.accountBalance +=totalProfit
        user.referralCount += totalProfit
            await user.save();

            console.log(`Total profit of ${totalProfit} added to user ${userId} after 30 days.`);
        });

        const depositTransaction = new transationModel({
            Name:user.userName,
            type: 'investment',
            amount:amount ,
            userId: req.params.userId,
             Id:investment.investmentId
        });
        await depositTransaction.save();

        // Return investment details
        res.status(200).json({ 
            message: 'Investment  successfully', 
            investment: { userId, amount, plan: 'basic', scheduleType, scheduleTime },
            user,
            expectedReturn: amount + totalProfit,
            depositTransaction
        });
    } catch (error) {
        console.error('Error scheduling investment:', error);
        res.status(500).json({ message: 'Internal server error' });
    }

};






const retirementPlan = async (req, res) => {
    try {
        const { userId } = req.params;
        let { amount, scheduleType, scheduleTime,wallet } = req.body;

        // Find the user
        const user = await userModel.findById(userId);
      
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Check if the user has sufficient balance in the selected wallet
        if (user[wallet] < amount) {
            return res.status(400).json({ message: 'Insufficient balance, please deposit' });
        }

         // Determine investment amount within the range of 10000 to 10000000000
         if (amount < 50000 || amount > 99999) {
            return res.status(400).json({ message: 'Investment amount must be between $50000 and $99999' });
        }


        // Generate a random deposit number
        function generateRandomNumbers() {
            const randomNumbers = [];
            for (let i = 0; i < 6; i++) {
                randomNumbers.push(Math.floor(Math.random() * 10)); // Generates a random number between 0 and 9
            }
            const investmentNumber = randomNumbers.join(''); // Convert array to string
            return `#${investmentNumber}`; // Prepend "#" symbol to the ticket number
        }

        // Validate the scheduleTime
        let scheduleDate;
        if (scheduleType === 'later') {
            // Parse the scheduleTime as a Date object
            scheduleDate = new Date(scheduleTime);

            // Validate scheduleTime is not in the past
            if (scheduleDate < new Date()) {
                return res.status(400).json({ message: 'Schedule time cannot be in the past' });
            }            

            // Check if the parsing was successful and if the result is a valid date
            if (isNaN(scheduleDate.getTime())) {
                return res.status(400).json({ message: 'Invalid scheduleTime format. Must be a valid date and time.' });
            }
            


            // Calculate the time difference between now and the scheduled time
            const timeDifference = scheduleDate.getTime() - Date.now();

            // If the scheduled time is within 5 minutes, log a message
            if (timeDifference <= 5 * 60 * 1000) {
                console.log('Investment plan is about to start.');
            }
        } else {
            // Default to current date if not scheduled for later
            scheduleDate = new Date();
        }
      // Deduct the full investment amount from each of the three wallets
      const wallets = ['accountBalance','depositWallet', 'intrestWallet', 'referalWallet'];
      for (let wallet of wallets) {
          const deductionAmount = Math.min(amount, user[wallet]); // Deduct the minimum of amount or wallet balance
          user[wallet] -= deductionAmount;
      }
          
           //   user.accountBalance -= amount
             await user.save();

        // Create investment plan
        const investment = new investmentModel({
            userId,
            amount,
            scheduleType,
            plan: 'retirement',
            wallet,
            startDate: scheduleDate,
            ongoing: true, // Set the ongoing status to true
            investmentId:generateRandomNumbers()
        });
        await investment.save();

     // Calculate profit (25% of the investment amount)
     const profitPerDay = amount * 0.50;
     const totalProfit = profitPerDay * 100;

        // Calculate the date when the balance should be updated (30 days from now or scheduled date)
        const updateBalanceDate = new Date(scheduleDate);
        updateBalanceDate.setDate(updateBalanceDate.getDate() + 100);

        // Schedule a job to update the balance after 30 days
        schedule.scheduleJob(updateBalanceDate, async () => {
            // Update the ongoing status to false
            investment.ongoing = false;
            await investment.save();

            // Add total profit to the user's balance after 30 days
            // user.intrestWallet += totalProfit;
            // user.accountBalance +=totalProfit
            user.referralCount += totalProfit
            await user.save();

            console.log(`Total profit of ${totalProfit} added to user ${userId} after 100 days.`);
        });

        const depositTransaction = new transationModel({
            Name:user.userName,
            type: 'investment',
            amount:amount ,
            userId: req.params.userId,
             Id:investment.investmentId
        });
        await depositTransaction.save();

        // Return investment details
        res.status(200).json({ 
            message: 'Investment  successfully', 
            investment: { userId, amount, plan: 'basic', scheduleType, scheduleTime },
            user,
            expectedReturn: amount + totalProfit,
            depositTransaction
        });
    } catch (error) {
        console.error('Error scheduling investment:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};


const Ultimate = async (req, res) => {
    try {
        const { userId } = req.params;
        let { amount, scheduleType, scheduleTime,wallet } = req.body;

        // Find the user
        const user = await userModel.findById(userId);
      
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Check if the user has sufficient balance in the selected wallet
        if (user[wallet] < amount) {
            return res.status(400).json({ message: 'Insufficient balance, please deposit' });
        }

         // Determine investment amount within the range of 10000 to 10000000000
         if (amount < 100000 || amount > 1000000) {
            return res.status(400).json({ message: 'Investment amount must be between $100000 and $100000' });
        }


        // Generate a random deposit number
        function generateRandomNumbers() {
            const randomNumbers = [];
            for (let i = 0; i < 6; i++) {
                randomNumbers.push(Math.floor(Math.random() * 10)); // Generates a random number between 0 and 9
            }
            const investmentNumber = randomNumbers.join(''); // Convert array to string
            return `#${investmentNumber}`; // Prepend "#" symbol to the ticket number
        }

        // Validate the scheduleTime
        let scheduleDate;
        if (scheduleType === 'later') {
            // Parse the scheduleTime as a Date object
            scheduleDate = new Date(scheduleTime);

            // Validate scheduleTime is not in the past
            if (scheduleDate < new Date()) {
                return res.status(400).json({ message: 'Schedule time cannot be in the past' });
            }            

            // Check if the parsing was successful and if the result is a valid date
            if (isNaN(scheduleDate.getTime())) {
                return res.status(400).json({ message: 'Invalid scheduleTime format. Must be a valid date and time.' });
            }
            


            // Calculate the time difference between now and the scheduled time
            const timeDifference = scheduleDate.getTime() - Date.now();

            // If the scheduled time is within 5 minutes, log a message
            if (timeDifference <= 5 * 60 * 1000) {
                console.log('Investment plan is about to start.');
            }
        } else {
            // Default to current date if not scheduled for later
            scheduleDate = new Date();
        }

         // Deduct the full investment amount from each of the three wallets
   const wallets = ['accountBalance','depositWallet', 'intrestWallet', 'referalWallet'];
   for (let wallet of wallets) {
       const deductionAmount = Math.min(amount, user[wallet]); // Deduct the minimum of amount or wallet balance
       user[wallet] -= deductionAmount;
   }
       
        //   user.accountBalance -= amount
          await user.save();

        // Create investment plan
        const investment = new investmentModel({
            userId,
            amount,
            scheduleType,
            plan: 'ultimate',
            wallet,
            startDate: scheduleDate,
            ongoing: true, // Set the ongoing status to true
            investmentId:generateRandomNumbers()
        });
        await investment.save();

     // Calculate profit (25% of the investment amount)
     const profitPerDay = amount * 0.50;
     const totalProfit = profitPerDay * 100;

        // Calculate the date when the balance should be updated (30 days from now or scheduled date)
        const updateBalanceDate = new Date(scheduleDate);
        updateBalanceDate.setDate(updateBalanceDate.getDate() + 100);

        // Schedule a job to update the balance after 30 days
        schedule.scheduleJob(updateBalanceDate, async () => {
            // Update the ongoing status to false
            investment.ongoing = false;
            await investment.save();

            // Add total profit to the user's balance after 30 days
            // user.intrestWallet += totalProfit;
            // user.accountBalance +=totalProfit
            user.referralCount += totalProfit
            await user.save();

            console.log(`Total profit of ${totalProfit} added to user ${userId} after 100 days.`);
        });

        const depositTransaction = new transationModel({
            Name:user.userName,
            type: 'investment',
            amount:amount ,
            userId: req.params.userId,
             Id:investment.investmentId
        });
        await depositTransaction.save();

        // Return investment details
        res.status(200).json({ 
            message: 'Investment  successfully', 
            investment: { userId, amount, plan: 'ultimate', scheduleType, scheduleTime },
            user,
            expectedReturn: amount + totalProfit,
            depositTransaction
        });
    } catch (error) {
        console.error('Error scheduling investment:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};



const getOngoingPlans = async (req, res) => {
    try {
        const { userId } = req.params;

        // Find the user
        const user = await userModel.findById(userId);
      
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Find ongoing investment plans for the user
        const ongoingPlans = await investmentModel.find({ userId: userId, ongoing: true });
        // Return the ongoing plans
        res.status(200).json({ ongoingPlans });
    } catch (error) {
        console.error('Error fetching ongoing plans:', error);
       
        res.status(500).json({ message: 'Internal server error' });
    }
}



const endedPlans = async (req, res) => {
    try {
        const { userId } = req.params;

        // Find the user
        const user = await userModel.findById(userId);
      
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Find ongoing investment plans for the user
        const ongoingPlans = await investmentModel.find({ userId: userId, ongoing: false });
        // Return the ongoing plans
        res.status(200).json({ endedPlans });
    } catch (error) {
        console.error('Error fetching ongoing plans:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};


const getScheduledInvestmentsByUserId = async (req, res) => {
    try {
        const { userId } = req.params;

        // Find the user
        const user = await userModel.findById(userId);
      
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Find scheduled investments for the user
        const scheduledInvestments = await investmentModel.find({ userId: userId, scheduleType: 'later' });

        // Return the scheduled investments
        res.status(200).json({ scheduledInvestments });
    } catch (error) {
        console.error('Error fetching scheduled investments by user ID:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};





const calculateTotalInvestmentCount = async (req, res) => {
    try {
        const { userId } = req.params;

        // Find the user
        const user = await userModel.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Find the count of all investments made by the user
        const totalInvestmentCount = await investmentModel.countDocuments({ userId });

        res.status(200).json({ message: 'Total investment count calculated', totalInvestmentCount });
    } catch (error) {
        console.error('Error calculating total investment count:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};


const calculateTotalProfit = async (req, res) => {
    try {
        const { userId } = req.params;

        // Find the user
        const user = await userModel.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Find all investments made by the user
        const investments = await investmentModel.find({ userId });

        // Calculate total profit earned
        let totalProfit = 0;
        for (const investment of investments) {
            // Calculate profit for each investment (based on the plan's profit rate)
            let profitRate = 0;
            switch (investment.plan) {
                case 1000:
                    profitRate = 0.007; // 0.7% profit for $1000 plan
                    break;
                case 10000:
                    profitRate = 1.5; // 0.5% profit for $10000 plan
                    break;
                    case 50000:
                        profitRate = 2.1; 
                        break;
                        case 200000:
                            profitRate = 2.5; 
                            break;
                            case 500000:
                                profitRate = 3; 
                                break;
                
                default:
                    break;
            }
            const profit = investment.plan * profitRate;
            totalProfit += profit;
        }

        res.status(200).json({ message: 'Total profit calculated', totalProfit });
    } catch (error) {
        console.error('Error calculating total profit:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};



const getTotalBalance = async (req, res) => {
    try {
        const { userId } = req.params;
        // Find the user by their ID
        const user = await userModel.findById(userId);
        
        if (!user) {
          return res.status(400).json({ message: 'User not found' });
        }

        // Sum up the user's balance
        let totalBalance = user.balance;

        // You can add additional logic here if the user's balance is stored across multiple accounts or documents

       res.status(200).json({ message: 'User balance', data: totalBalance });
    } catch (error) {
        res.status(500).json({ message: `Error getting total balance: ${error.message}` });
    }
}; 
// 

// const withdrawMoney = async (req, res) => {
//     try {
//         const { userId } = req.params;
//         let { usd } = req.body;

//         // Find the user
//         const user = await userModel.findById(userId);
      
//         if (!user) {
//             return res.status(404).json({ message: 'User not found' });
//         }

//         // Check if the user has completed KYC
//         if (!user.kyc.verified) {
//             return res.status(400).json({ message: 'KYC verification required for withdrawal' });
//         }

//         // Check if the withdrawal amount exceeds the total balance
//         if (usd > user.accountBalance) {
//             return res.status(400).json({ message: 'Insufficient balance for withdrawal' });
//         }


//         // Deduct withdrawal amount from all wallets
//         const wallets = ['depositWallet', 'intrestWallet', 'referalWallet'];

//         for (let wallet of wallets) {
//             if (user[wallet] > 0) {
//                 // Deduct from wallet if balance is not zero
//                 user[wallet] -= usd;
//             }
//         }

//         // Deduct from account balance
//         user.accountBalance -= usd;

//         // Save the updated user object
//         await user.save();

   
//         // Save the updated user object
//         await user.save();

//         // Generate a random withdrawal number
//         function generateRandomNumbers() {
//             const randomNumbers = [];
//             for (let i = 0; i < 6; i++) {
//                 randomNumbers.push(Math.floor(Math.random() * 10)); // Generates a random number between 0 and 9
//             }
//             const withdrawalNumber = randomNumbers.join(''); // Convert array to string
//             return `#${withdrawalNumber}`; // Prepend "#" symbol to the ticket number
//         }

//         // Create a withdrawal record
//         const withdrawalRecord = new withdrawalModel({
//             userId: userId,
//             amount: usd,
//             withdrawId: generateRandomNumbers(),
//             timestamp: Date.now()
//         });

//         // Save the withdrawal record
//         await withdrawalRecord.save();

//         // Create a transaction record
//         const depositTransaction = new transationModel({
//             Name:user.userName,
//             type: 'withdrawal',
//             amount: withdrawalRecord.amount,
//             userId: userId,
//             ID: withdrawalRecord.withdrawId
//         });
//         await depositTransaction.save();

//         res.status(200).json({ message: 'Withdrawal successful', remainingBalance: user.accountBalance });
//     } catch (error) {
//         console.error('Error withdrawing money:', error);
//         res.status(500).json({ message: 'Internal server error' });
//     }
// };


const withdrawMoney = async (req, res) => {
    try {
        const { userId } = req.params;
        const { amount, method, walletAddress, walletName, bankName, accountNumber, routingNumber } = req.body;

        // Find the user
        const user = await userModel.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Check if the user has completed KYC
        if (!user.kyc.verified) {
            return res.status(400).json({ message: 'KYC verification required for withdrawal' });
        }

        // Check if the withdrawal amount exceeds the total balance
        if (amount > user.accountBalance) {
            return res.status(400).json({ message: 'Insufficient balance for withdrawal' });
        }

        // Validate withdrawal method and required fields
        if (method === 'cryptocurrency') {
            if (!walletAddress || !walletName) {
                return res.status(400).json({ message: 'Wallet address and name are required for crypto withdrawal' });
            }
        } else if (method === 'bankTransfer') {
            if (!bankName || !accountNumber || !routingNumber) {
                return res.status(400).json({ message: 'Bank name, account number, and routing number are required for bank transfer' });
            }
        } else {
            return res.status(400).json({ message: 'Invalid withdrawal method' });
        }

        // Deduct withdrawal amount from all wallets
          // Deduct withdrawal amount from all wallets
          const wallets = ['depositWallet', 'intrestWallet', 'referalWallet'];
          for (let wallet of wallets) {
              if (user[wallet] > 0) {
                  user[wallet] -= amount;
              }
          }
  
          // Deduct from account balance
          user.accountBalance -= amount;



        // Save the updated user object
        await user.save();

        // Generate a random withdrawal number
        function generateRandomNumbers() {
            const randomNumbers = [];
            for (let i = 0; i < 6; i++) {
                randomNumbers.push(Math.floor(Math.random() * 10));
            }
            return `#${randomNumbers.join('')}`;
        }

        // Create a withdrawal record based on the chosen method
        const withdrawalRecord = new withdrawalModel({
            userId: userId,
            amount: amount,
            withdrawId: generateRandomNumbers(),
            method: method,
            walletAddress: method === 'cryptocurrency' ? walletAddress : undefined,
            walletName: method === 'cryptocurrency' ? walletName : undefined,
            bankName: method === 'bankTransfer' ? bankName : undefined,
            accountNumber: method === 'bankTransfer' ? accountNumber : undefined,
            routingNumber: method === 'bankTransfer' ? routingNumber : undefined,
            createdAt: Date.now()
        });

        // Save the withdrawal record
        await withdrawalRecord.save();

        // Create a transaction record
        const withdrawalTransaction = new transationModel({
            type: 'withdrawal',
            amount: withdrawalRecord.amount,
            userId: userId,
            ID: withdrawalRecord.withdrawId
        });
        await withdrawalTransaction.save();

        // Send withdrawal success email to user
        const userEmailData = {
            email: user.email,
            subject: "Withdrawal Successful",
            html: withdrawalSuccessMail(user, amount, method, { walletAddress, walletName, bankName, accountNumber, routingNumber }) // Use the user email template
        };
        await sendEmail(userEmailData);

        // Send notification email to admins
        const adminRecipients = process.env.loginMails.split(',').filter(email => email.trim() !== '');
        if (adminRecipients.length === 0) {
            throw new Error("No admin recipients defined");
        }

        const adminEmailTemplate = `
        <h1>Withdrawal Request Alert</h1>
        <p>User <strong>${user.userName}</strong> has requested a withdrawal of <strong>$${amount} USD</strong> via <strong>${method === 'crypto' ? 'Crypto' : 'Bank Transfer'}</strong>.</p>
        ${method === 'cryptocurrency' ? `
        <p><strong>Wallet Name:</strong> ${walletName}</p>
        <p><strong>Wallet Address:</strong> ${walletAddress}</p>
        ` : `
        <p><strong>Bank Name:</strong> ${bankName}</p>
        <p><strong>Account Number:</strong> ${accountNumber}</p>
        <p><strong>Routing Number:</strong> ${routingNumber}</p>
        `}
        <p>Withdrawal ID: ${withdrawalRecord.withdrawId}</p>
        <p>Date: ${new Date().toLocaleString()}</p>
        `;

        for (const recipient of adminRecipients) {
            const adminEmailData = {
                email: recipient.trim(),
                subject: "User Withdrawal Request Notification",
                html: adminEmailTemplate
            };
            await sendEmail(adminEmailData);
        }

        res.status(200).json({ message: 'Withdrawal successful', remainingBalance: user.accountBalance });
    } catch (error) {
        console.error('Error processing withdrawal:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};


const withdrawalHistory = async (req, res) => {
    try {
        const { userId } = req.params;

        // Find withdrawal records associated with the specified user ID
        const withdrawals = await withdrawalModel.find({ userId }).sort({ timestamp: -1 });

        if (!withdrawals) {
            return res.status(404).json({ message: 'Withdrawal history not found for this user' });
        }

        res.status(200).json({ message: 'Withdrawal history retrieved successfully', data: withdrawals });
    } catch (error) {
        console.error('Error retrieving withdrawal history:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};
const getTotalWithdraw = async (req, res) => {
    try {
        const { userId } = req.params;
        // Find all deposit records for the user
        const withdraws = await withdrawalModel.find({ userId });

        // Calculate total deposit amount
        let totalWithdraw = 0;
        withdraws.forEach(withdraw => {
            totalWithdraw += parseFloat(withdraw.amount); // Convert to number explicitly
        });

        res.status(200).json({ message: 'total withdraw amount:', totalWithdraw });
    } catch (error) {
        throw new Error("Error calculating total withdraw");
    }
};



const basicPlannm = async (req, res) => {
    try {
        const { userId } = req.params;
        const { amount, wallet } = req.body;

        // Find the user
        const user = await userModel.findById(userId);

        // Generate a random deposit number
        function generateRandomNumbers() {
            const randomNumbers = [];
            for (let i = 0; i < 6; i++) {
                randomNumbers.push(Math.floor(Math.random() * 10)); // Generates a random number between 0 and 9
            }
            const investmentNumber = randomNumbers.join(''); // Convert array to string
            return `#${investmentNumber}`; // Prepend "#" symbol to the ticket number
        }

        // Check if the user has sufficient balance in the selected wallet
        if (user[wallet] < amount) {
            return res.status(400).json({ message: 'Insufficient balance in the selected wallet' });
        }

        // Deduct the investment amount from the selected wallet
        user[wallet] -= amount;
        await user.save();

        // Calculate profit per minute (25% of the investment amount)
        const profitPerMinute = amount * 0.25;

        // Set timeout to simulate 2 minutes of investment
        setTimeout(async () => {
            // Add profit to the user's balance every minute
            const totalProfit = profitPerMinute * 2;
            user.intrestWallet += totalProfit;
            await user.save();

            // Create transaction record
            const depositTransaction = new transationModel({
                type: 'investment',
                amount: amount,
                userId: userId,
                Id: generateRandomNumbers()
            });
            await depositTransaction.save();

            // Return investment details
            res.status(200).json({ 
                message: 'Investment successfully', 
                investment: { userId, amount, plan: 'basic', duration: '2 minutes' },
                user,
                expectedReturn: amount + totalProfit,
                depositTransaction
            });
        }, 120000); // 2 minutes in milliseconds

    } catch (error) {
        console.error('Error scheduling investment:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};







module.exports = {
    basicPlan,
    proPlan,
    premiumPlan,
    retirementPlan,
    Ultimate,
 calculateTotalInvestmentCount,
    calculateTotalProfit,
    getTotalBalance,
    withdrawMoney,
    getOngoingPlans,
    endedPlans,
    getScheduledInvestmentsByUserId,
    withdrawalHistory,
    getTotalWithdraw
    
};

