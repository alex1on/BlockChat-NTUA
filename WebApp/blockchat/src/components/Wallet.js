import React, { useEffect, useState } from 'react';

import '../css/global.css';
import '../css/wallet.css'

const Wallet = () => {
    const [walletInfo, setWalletInfo] = useState({ balance: 0, username: '', public_key: '', private_key: '', nonce: 0 });

    useEffect(() => {
        const email = 'user@example.com';
        fetch(`/wallet?email=${email}`)
            .then(response => response.json())
            .then(data => {
                setWalletInfo({ balance: data.balance, 
                                username: data.username, 
                                public_key: data.public_key,  
                                private_key: data.private_key,
                                nonce: data.nonce
                            });
            })
            .catch(error => console.error('Error fetching wallet info:', error));
    }, []);

    return (
        <div className="Wallet">
            <h1>Welcome to BlockChat Wallet!</h1>
            <p>Here you can find information about your balance!</p>
            <div className="WalletInfo">
                <h2>Wallet Balance</h2>
                <p><strong>Username:</strong> {walletInfo.username}</p>
                <p><strong>Public key:</strong> {walletInfo.public_key}</p>
                <p><strong>Private key:</strong> {walletInfo.private_key}</p>
                <p><strong>Nonce:</strong> {walletInfo.nonce}</p>
                <p><strong>BlockChat Coins:</strong> {walletInfo.balance}</p>
            </div>
        </div>
    );
}

export default Wallet;
