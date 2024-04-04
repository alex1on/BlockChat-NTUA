import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import '../css/global.css';
import '../css/transaction.css';

const Transaction = () => {
    const [step, setStep] = useState(0);
    const [transactionType, setTransactionType] = useState('');
    const [details, setDetails] = useState('');
    const [selectedUser, setSelectedUser] = useState('');
    // const [sender, setSender] = useState(null);
    // const [users, setUsers] = useState(null);
    // Static users for testing purposes
    const [sender, setSender] = useState({id: '5', username: 'Sender'})
    const [users, setUsers] = useState([
        { id: '1', username: 'User1' },
        { id: '2', username: 'User2' },
        { id: '3', username: 'User3' },
    ]);
    const navigate = useNavigate();

    useEffect(() => {
        // Fetch all users
        const fetchUsers = async () => {
            try {
                const response = await fetch(`/getUsers`);
                const userData = await response.json();
                setUsers(userData);
            } catch (error) {
                console.error('Error fetching users:', error);
            }
        };

        fetchUsers();

        // Fetch current sender's details
        const fetchSender = async () => {
            try {
                // const email = getEmail();    TODO: Implement getEmail
                const email = '123@example.com';
                const response = await fetch(`/getUser?email=${email}`);
                const senderData = await response.json();
                setSender(senderData);
            } catch (error) {
                console.error('Error fetching current user:', error);
            }
        };

        // TODO: Remove sender from all users list

        fetchSender();
    }, []);

    const isNextEnabled = () => {
        if (step === 1) return transactionType !== '';
        if (step === 2) return details !== '';
        if (step === 3) return selectedUser !== '';
        return false;
    };

    const handleSubmit = async () => {
        const transactionInfo = {
            sender_id: sender?.id,
            receiver_id: selectedUser,
            type: transactionType,
            coins: transactionType === 'coins' ? parseInt(details, 10) : null,
            message: transactionType === 'message' ? details : null,
        };

        try {
            console.log('Submitting Transaction:', transactionInfo);
            const response = await fetch('/new_transaction', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(transactionInfo)
            });
            // Handle response here
            // const result = await response.json();
            navigate('/');
        } catch (error) {
            console.error('Error submitting transaction:', error);
        }
    };

    const stepTitles = ['Make a New Transaction', 'Choose Transaction Type', 'Enter Details', 'Select Recipient and Confirm'];

    return (
        <div className="Transaction">
            <h1>{stepTitles[step]}</h1>

            {step === 0 && (
                <button className="InitiateTransactionButton" onClick={() => setStep(1)}>Start a Transaction</button>
            )}

            {step >= 1 && (
                <div className="TransactionBox">
                    {step === 1 && (
                        <div className="TransactionStep">
                            <div className="TransactionOptions">
                                <button className={transactionType === 'coins' ? 'OptionButton Selected' : 'OptionButton'} onClick={() => setTransactionType('coins')}>Transfer Coins</button>
                                <span className="OrSeparator">or</span>
                                <button className={transactionType === 'message' ? 'OptionButton Selected' : 'OptionButton'} onClick={() => setTransactionType('message')}>Send a Message</button>
                            </div>
                        </div>
                    )}

                    {step === 2 && transactionType === 'coins' && (
                        <input className="InputField" type="number" placeholder="Number of coins" value={details} onChange={(e) => setDetails(e.target.value)} />
                    )}
                    {step === 2 && transactionType === 'message' && (
                        <input className="InputField" type="text" placeholder="Your message" value={details} onChange={(e) => setDetails(e.target.value)} />
                    )}

                    {step === 3 && (
                        <select className="UserSelect" value={selectedUser} onChange={(e) => setSelectedUser(e.target.value)}>
                            <option value="">Select User</option>
                            {users.map(user => (
                                <option key={user.id} value={user.id}>{user.username}</option>
                            ))}
                        </select>
                    )}

                    <div className="NavigationButtons">
                        {step > 1 && <button onClick={() => setStep(step - 1)}>Previous</button>}
                        {step < 3 && <button onClick={() => isNextEnabled() && setStep(step + 1)} disabled={!isNextEnabled()}>Next</button>}
                        {step === 3 && <button onClick={handleSubmit} disabled={!isNextEnabled()}>Confirm</button>}
                    </div>
                </div>
            )}
        </div>
    );
};

export default Transaction;
