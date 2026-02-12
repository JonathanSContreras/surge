'use client';

import { useState } from 'react';
import { Navbar } from './_components/Navbar';
import { Dashboard } from './_pages/Dashboard';
import { Scans } from './_pages/Scans';
import { Exploits } from './_pages/Exploits';
import { Reports } from './_pages/Reports';
import { Settings } from './_pages/Settings';

export default function App() {
  const [activeTab, setActiveTab] = useState('Dashboard');

  const renderPage = () => {
    switch (activeTab) {
      case 'Dashboard':
        return <Dashboard />;
      case 'Scans':
        return <Scans />;
      case 'Exploits':
        return <Exploits />;
      case 'Reports':
        return <Reports />;
      case 'Settings':
        return <Settings />;
      default:
        return <Dashboard />;
    }
  };

  return (
    <div className="min-h-screen bg-[#0F1117] text-white">
      <Navbar activeTab={activeTab} onTabChange={setActiveTab} />
      
      <main className="pt-16">
        {renderPage()}
      </main>
    </div>
  );
}