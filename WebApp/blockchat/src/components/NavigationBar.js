import React from 'react';
import { Link } from 'react-router-dom';

import '../css/navigation_bar.css'
import '../css/global.css'

const NavigationBar = () => {
    return (
        <nav className='NavigationBar'>
            <h1>BlockChat</h1>
            <div className='links'>
                <Link to="/">Home</Link>
                <Link to="/wallet">Wallet</Link>
                <Link to="/transaction">Transaction</Link>
                <Link to="/history">History</Link>
            </div>
        </nav>
    )
}

export default NavigationBar;