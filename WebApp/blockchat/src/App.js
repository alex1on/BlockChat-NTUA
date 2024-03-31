import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';

// import components 
import NavigationBar from './components/NavigationBar';
import Home from './components/Home';
import Wallet from './components/Wallet';
import Transaction from './components/Transaction';
import History from './components/History';

const App = () => {
  return (
    <Router>
      <div>
        <NavigationBar />
        <Routes>
          <Route path="/wallet" element={<Wallet />} />
          <Route path="/transaction" element={<Transaction />} />
          <Route path="/history" element={<History />} />
          <Route path="/" element={<Home />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
