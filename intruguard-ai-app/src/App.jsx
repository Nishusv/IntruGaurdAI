import React, { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, BarChart, Bar } from 'recharts';

// Main App Component
const App = () => {
  // State to manage the current page/module displayed
  const [currentPage, setCurrentPage] = useState('landing'); // 'landing', 'vapt', 'ids'
  // State to manage the current theme: 'dark' or 'light'
  const [theme, setTheme] = useState('dark');

  // Function to navigate to a specific module
  const navigateTo = (page) => {
    setCurrentPage(page);
  };

  // Function to toggle between dark and light themes
  const toggleTheme = () => {
    setTheme(prevTheme => (prevTheme === 'dark' ? 'light' : 'dark'));
  };

  return (
    // Apply theme-specific background and text colors to the root div
    <div className={`min-h-screen font-inter antialiased flex flex-col ${theme === 'dark' ? 'bg-gray-900 text-gray-100' : 'bg-gray-100 text-gray-900'}`}>
      {/* Navigation Bar */}
      <nav className={`${theme === 'dark' ? 'bg-gray-800' : 'bg-white'} p-4 shadow-lg`}>
        <div className="container mx-auto flex justify-between items-center">
          {/* Made the IntruGuardAI title clickable to navigate to the landing page */}
          <h1
            className={`text-3xl font-bold ${theme === 'dark' ? 'text-teal-400' : 'text-teal-600'} cursor-pointer hover:${theme === 'dark' ? 'text-teal-300' : 'text-teal-500'} transition-colors duration-200`}
            onClick={() => navigateTo('landing')}
          >
            IntruGuardAI
          </h1>
          <div className="flex space-x-4 items-center">
            {/* Theme Toggle Button */}
            <button
              onClick={toggleTheme}
              className={`px-3 py-1 rounded-full text-sm transition-colors duration-300
                ${theme === 'dark' ? 'bg-gray-700 text-gray-200 hover:bg-gray-600' : 'bg-gray-300 text-gray-800 hover:bg-gray-400'}`}
            >
              {theme === 'dark' ? '☀️ Light Mode' : '🌙 Dark Mode'}
            </button>

            {currentPage !== 'landing' && (
              <>
                <button
                  onClick={() => navigateTo('vapt')}
                  className={`px-4 py-2 rounded-lg transition-all duration-300 ${
                    currentPage === 'vapt'
                      ? (theme === 'dark' ? 'bg-teal-600 text-white shadow-md' : 'bg-teal-700 text-white shadow-md')
                      : (theme === 'dark' ? 'bg-gray-700 hover:bg-teal-500 text-gray-200 hover:text-white' : 'bg-gray-200 hover:bg-teal-200 text-gray-800 hover:text-teal-800')
                  }`}
                >
                  🔐 VAPT Module (Red Team)
                </button>
                <button
                  onClick={() => navigateTo('ids')}
                  className={`px-4 py-2 rounded-lg transition-all duration-300 ${
                    currentPage === 'ids'
                      ? (theme === 'dark' ? 'bg-teal-600 text-white shadow-md' : 'bg-teal-700 text-white shadow-md')
                      : (theme === 'dark' ? 'bg-gray-700 hover:bg-teal-500 text-gray-200 hover:text-white' : 'bg-gray-200 hover:bg-teal-200 text-gray-800 hover:text-teal-800')
                  }`}
                >
                  🤖 IDS Module (Blue Team)
                </button>
              </>
            )}
          </div>
        </div>
      </nav>

      {/* Main Content Area */}
      <main className="flex-grow container mx-auto p-6">
        {currentPage === 'landing' && <LandingPage navigateTo={navigateTo} theme={theme} />}
        {currentPage === 'vapt' && <VAPTModule theme={theme} />}
        {currentPage === 'ids' && <IDSModule theme={theme} />}
      </main>

      {/* Footer */}
      <footer className={`${theme === 'dark' ? 'bg-gray-800 text-gray-400' : 'bg-gray-200 text-gray-600'} p-4 text-center text-sm shadow-inner`}>
        &copy; {new Date().getFullYear()} IntruGuardAI. All rights reserved.
      </footer>
    </div>
  );
};

// Landing Page Component
const LandingPage = ({ navigateTo, theme }) => {
  return (
    <div className="flex flex-col items-center justify-center min-h-[calc(100vh-160px)] text-center">
      <h2 className={`text-5xl font-extrabold ${theme === 'dark' ? 'text-white' : 'text-gray-900'} mb-6 animate-fade-in-down`}>
        Welcome to <span className={`${theme === 'dark' ? 'text-teal-400' : 'text-teal-600'}`}>IntruGuardAI</span>
      </h2>
      <p className={`text-xl ${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'} mb-10 max-w-2xl animate-fade-in-up`}>
        Your integrated platform for advanced cybersecurity assessment and defense.
        Explore vulnerabilities or monitor for intrusions.
      </p>
      <div className="flex space-x-6 animate-fade-in-up delay-200">
        <button
          onClick={() => navigateTo('vapt')}
          className={`font-bold py-4 px-8 rounded-xl shadow-lg transform hover:scale-105 transition-all duration-300 flex items-center space-x-3
            ${theme === 'dark' ? 'bg-red-600 hover:bg-red-700 text-white' : 'bg-red-700 hover:bg-red-800 text-white'}`}
        >
          <span className="text-3xl">🔐</span>
          <span>Explore Vulnerability Assessment</span>
        </button>
        <button
          onClick={() => navigateTo('ids')}
          className={`font-bold py-4 px-8 rounded-xl shadow-lg transform hover:scale-105 transition-all duration-300 flex items-center space-x-3
            ${theme === 'dark' ? 'bg-blue-600 hover:bg-blue-700 text-white' : 'bg-blue-700 hover:bg-blue-800 text-white'}`}
        >
          <span className="text-3xl">🤖</span>
          <span>Launch Intrusion Detection System</span>
        </button>
      </div>

      {/* Project Overview Section */}
      <div className={`mt-16 p-8 rounded-xl shadow-2xl max-w-4xl w-full text-left
        ${theme === 'dark' ? 'bg-gray-800 border border-gray-700' : 'bg-white border border-gray-300'}`}>
        <h3 className={`text-3xl font-bold ${theme === 'dark' ? 'text-teal-400' : 'text-teal-600'} mb-6 border-b ${theme === 'dark' ? 'border-gray-700' : 'border-gray-300'} pb-3`}>
          IntruGuardAI: At a Glance
        </h3>

        <h4 className={`text-2xl font-semibold ${theme === 'dark' ? 'text-gray-200' : 'text-gray-800'} mb-4`}>Purpose of this Application:</h4>
        <p className={`${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'} mb-6 leading-relaxed`}>
  IntruGuardAI is a frontend-focused web application that combines <b>Vulnerability Assessment &amp; Penetration Testing (VAPT)</b> with an <b>AI-Powered Intrusion Detection System (IDS)</b>. 
  It allows users to switch between <b>Red Team (offensive)</b> and <b>Blue Team (defensive)</b> modules. 
  The VAPT module highlights common vulnerabilities like <b>SQL Injection</b>, <b>XSS</b>, and <b>weak authentication</b>, while the IDS uses <b>machine learning</b> to detect anomalies and visualize threats in real time.
</p>


      <h4 className={`text-2xl font-semibold ${theme === 'dark' ? 'text-gray-200' : 'text-gray-800'} mb-4`}>
  Application Advantages:
</h4>
<ul className={`list-disc list-inside space-y-2 ${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'}`}>
  <li>
    <b>Dual-Module Design:</b> Integrates Vulnerability Assessment &amp; Penetration Testing (VAPT) with an AI-powered Intrusion Detection System (IDS) in one platform.
  </li>
  <li>
    <b>Red &amp; Blue Team Simulation:</b> Enables users to experience both offensive (pentesting) and defensive (intrusion detection) cybersecurity practices.
  </li>
  <li>
    <b>Educational &amp; Interactive:</b> Designed primarily for learning and training, making complex cybersecurity concepts easier to understand.
  </li>
  <li>
    <b>Safe for Practice:</b> All operations are simulated, ensuring a risk-free environment while exploring vulnerabilities and defense mechanisms.
  </li>
  <li>
    <b>AI Integration:</b> Demonstrates how machine learning can enhance anomaly detection and support proactive defense strategies.
  </li>
  <li>
    <b>User-Friendly Interface:</b> Offers intuitive navigation with toggles to switch between modules, along with clear dashboards and reports.
  </li>
</ul>


      </div>
    </div>
  );
};

// VAPT Module Component
const VAPTModule = ({ theme }) => {
  // Simulated vulnerability data
  const vulnerabilities = [
    {
      id: 1,
      name: 'SQL Injection',
      severity: 'High',
      description: 'Allows attackers to interfere with the queries that an application makes to its database.',
      remediation: 'Use parameterized queries or prepared statements. Validate and sanitize all user input.',
      endpoint: '/api/products?id=1',
      payload: "' OR '1'='1"
    },
    {
      id: 2,
      name: 'Cross-Site Scripting (XSS)',
      severity: 'Medium',
      description: 'Enables attackers to inject client-side scripts into web pages viewed by other users.',
      remediation: 'Sanitize all user-supplied input. Implement Content Security Policy (CSP). Encode output.',
      endpoint: '/search?query=<script>alert("XSS")</script>',
      payload: "<script>alert('XSS Vulnerability Detected!');</script>"
    },
    {
      id: 3,
      name: 'Insecure Authentication',
      severity: 'High',
      description: 'Weak authentication mechanisms, such as predictable passwords or lack of brute-force protection.',
      remediation: 'Enforce strong password policies, implement multi-factor authentication (MFA), and rate-limit login attempts.',
      endpoint: '/login',
      payload: "admin'-- password='password"
    },
    {
      id: 4,
      name: 'Broken Access Control',
      severity: 'Medium',
      description: 'Users can act outside of their intended permissions, such as accessing admin functions.',
      remediation: 'Implement robust access control checks at every request. Deny by default.',
      endpoint: '/admin/users/123/delete',
      payload: "user_id=123&action=delete"
    },
    {
      id: 5,
      name: 'Security Misconfiguration',
      severity: 'Low',
      description: 'Improperly configured security settings, default credentials, or unnecessary features enabled.',
      remediation: 'Harden configurations, remove unused features, and change default credentials.',
      endpoint: '/config.bak',
      payload: ""
    }
  ];

  const [exploitationPayload, setExploitationPayload] = useState('');
  const [exploitationResult, setExploitationResult] = useState('');
  const [selectedVulnerability, setSelectedVulnerability] = useState(null);
  const [llmRemediation, setLlmRemediation] = useState('');
  const [llmLoading, setLlmLoading] = useState(false);
  const [llmPayloadLoading, setLlmPayloadLoading] = useState(false);

  // New state for website vulnerability suggestion
  const [websiteUrl, setWebsiteUrl] = useState('');
  const [llmWebsiteVulnerabilities, setLlmWebsiteVulnerabilities] = useState('');
  const [llmWebsiteVulnerabilitiesLoading, setLlmWebsiteVulnerabilitiesLoading] = useState(false);
  const [websiteVulnerabilityChartData, setWebsiteVulnerabilityChartData] = useState([]);

  // New state for detailed vulnerability explanation
  const [llmDetailedVulnerabilityExplanation, setLlmDetailedVulnerabilityExplanation] = useState('');
  const [llmDetailedVulnerabilityExplanationLoading, setLlmDetailedVulnerabilityExplanationLoading] = useState(false);


  // Gemini API configuration
  const apiKey = ""; // If you want to use models other than gemini-2.0-flash or imagen-3.0-generate-002, provide an API key here. Otherwise, leave this as-is.
  const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;

  // Handle manual exploitation simulation
  const handleExploitSimulation = () => {
    if (!exploitationPayload) {
      setExploitationResult('Please enter a payload to simulate.');
      return;
    }

    // Simulate different results based on payload content
    if (exploitationPayload.includes('SQL') || exploitationPayload.includes("' OR '1'='1")) {
      setExploitationResult(
        <div className={`${theme === 'dark' ? 'text-green-400' : 'text-green-700'}`}>
          <p className="font-bold">SQL Injection Successful!</p>
          <p>Database records potentially exposed. Simulated query: SELECT * FROM users WHERE username = '{exploitationPayload}'</p>
        </div>
      );
    } else if (exploitationPayload.includes('XSS') || exploitationPayload.includes('<script>')) {
      setExploitationResult(
        <div className={`${theme === 'dark' ? 'text-green-400' : 'text-green-700'}`}>
          <p className="font-bold">XSS Payload Executed!</p>
          <p>Client-side script injected. User session data could be compromised.</p>
        </div>
      );
    } else if (exploitationPayload.includes('admin') || exploitationPayload.includes('password')) {
      setExploitationResult(
        <div className={`${theme === 'dark' ? 'text-green-400' : 'text-green-700'}`}>
          <p className="font-bold">Insecure Authentication Exploited!</p>
          <p>Login bypassed or credentials guessed. Access granted to sensitive areas.</p>
        </div>
      );
    } else {
      setExploitationResult(
        <div className={`${theme === 'dark' ? 'text-yellow-400' : 'text-yellow-700'}`}>
          <p className="font-bold">Simulation Result:</p>
          <p>Payload processed. No immediate critical vulnerability detected with this input, but further testing is recommended.</p>
        </div>
      );
    }
  };

  // Function to load a vulnerability's example payload into the textarea
  const loadExamplePayload = (payload) => {
    setExploitationPayload(payload);
    setExploitationResult(''); // Clear previous result
  };

  // Function to get LLM-powered remediation advice
  const getLlmRemediation = async () => {
    if (!selectedVulnerability) return;

    setLlmLoading(true);
    setLlmRemediation(''); // Clear previous LLM remediation

    const prompt = `Provide detailed and actionable remediation steps for the following cybersecurity vulnerability:\n\nName: ${selectedVulnerability.name}\nDescription: ${selectedVulnerability.description}\n\nFocus on practical advice for developers and system administrators.`;

    let chatHistory = [];
    chatHistory.push({ role: "user", parts: [{ text: prompt }] });
    const payload = { contents: chatHistory };

    try {
      const response = await fetch(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const result = await response.json();

      if (result.candidates && result.candidates.length > 0 &&
          result.candidates[0].content && result.candidates[0].content.parts &&
          result.candidates[0].content.parts.length > 0) {
        const text = result.candidates[0].content.parts[0].text;
        setLlmRemediation(text);
      } else {
        setLlmRemediation('Could not retrieve LLM remediation advice. Please try again.');
      }
    } catch (error) {
      console.error('Error fetching LLM remediation:', error);
      setLlmRemediation('Error fetching LLM remediation advice.');
    } finally {
      setLlmLoading(false);
    }
  };

  // Function to generate an advanced exploitation payload using LLM
  const generateAdvancedPayload = async () => {
    setLlmPayloadLoading(true);
    setExploitationPayload(''); // Clear current payload
    setExploitationResult(''); // Clear previous result

    let prompt = `Generate a sophisticated and effective exploitation payload for a web application vulnerability.`;
    if (selectedVulnerability) {
      prompt += ` The vulnerability is: ${selectedVulnerability.name} - ${selectedVulnerability.description}. The affected endpoint is: ${selectedVulnerability.endpoint}.`;
    } else {
      prompt += ` Focus on a common web vulnerability like SQL Injection or Cross-Site Scripting (XSS). Provide only the payload string, no explanations.`;
    }
    prompt += ` Provide only the payload string, without any additional text or explanations.`;


    let chatHistory = [];
    chatHistory.push({ role: "user", parts: [{ text: prompt }] });
    const payload = { contents: chatHistory };

    try {
      const response = await fetch(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const result = await response.json();

      if (result.candidates && result.candidates.length > 0 &&
          result.candidates[0].content && result.candidates[0].content.parts &&
          result.candidates[0].content.parts.length > 0) {
        const text = result.candidates[0].content.parts[0].text;
        setExploitationPayload(text.trim()); // Set the generated payload
      } else {
        setExploitationResult('Could not generate payload. Please try again.');
      }
    } catch (error) {
      console.error('Error fetching LLM payload:', error);
      setExploitationResult('Error generating payload.');
    } finally {
      setLlmPayloadLoading(false);
    }
  };

  // Helper function to parse LLM text response into chart data
  const parseLlmVulnerabilitiesForChart = (llmText) => {
    const counts = {};
    const lines = llmText.split('\n');

    const vulnerabilityKeywords = {
      'SQL Injection': 'SQL Injection',
      'XSS': 'Cross-Site Scripting (XSS)',
      'Cross-Site Scripting': 'Cross-Site Scripting (XSS)', // Redundancy for better matching
      'Authentication': 'Insecure Authentication',
      'Broken Authentication': 'Insecure Authentication',
      'Access Control': 'Broken Access Control',
      'Misconfiguration': 'Security Misconfiguration',
      'Sensitive Data Exposure': 'Sensitive Data Exposure',
      'CSRF': 'Cross-Site Request Forgery (CSRF)',
      'Server-Side Request Forgery': 'SSRF',
      'SSRF': 'SSRF',
      'XML External Entities': 'XML External Entities (XXE)',
      'XXE': 'XML External Entities (XXE)',
      'Insecure Deserialization': 'Insecure Deserialization',
      'Known Vulnerabilities': 'Vulnerable Components',
      'Vulnerable Components': 'Vulnerable Components',
      'Insufficient Logging & Monitoring': 'Insufficient Logging & Monitoring',
      'DDoS': 'Denial of Service (DoS)', // Added for broader coverage
      'DoS': 'Denial of Service (DoS)',
      'Injection': 'Injection (General)', // General category for various injections
      'Broken Link': 'Broken Links/References',
      'Redirect': 'Open Redirect',
      'File Upload': 'Insecure File Upload',
      'API': 'Insecure API',
    };

    lines.forEach(line => {
      let foundMatch = false;
      for (const keyword in vulnerabilityKeywords) {
        if (line.toLowerCase().includes(keyword.toLowerCase())) {
          const standardName = vulnerabilityKeywords[keyword];
          counts[standardName] = (counts[standardName] || 0) + 1;
          foundMatch = true;
          break; // Found a match for this line, move to next line
        }
      }
      // If no specific keyword is found, but it looks like a vulnerability line, categorize as "Other"
      if (!foundMatch && line.trim().length > 10 && (line.includes(':') || line.includes('.'))) {
        counts['Other'] = (counts['Other'] || 0) + 1;
      }
    });

    // Convert counts to array for Recharts, sort by count descending
    return Object.keys(counts)
      .map(name => ({ name: name, count: counts[name] }))
      .sort((a, b) => b.count - a.count);
  };


  // Function to get LLM-powered website vulnerability suggestions
  const getLlmWebsiteVulnerabilities = async () => {
    if (!websiteUrl) {
      setLlmWebsiteVulnerabilities('Please enter a website URL.');
      setWebsiteVulnerabilityChartData([]); // Clear chart data
      return;
    }

    setLlmWebsiteVulnerabilitiesLoading(true);
    setLlmWebsiteVulnerabilities(''); // Clear previous LLM response
    setWebsiteVulnerabilityChartData([]); // Clear previous chart data

    const prompt = `Given the website URL "${websiteUrl}", suggest common web application vulnerabilities that might exist on such a site. Provide a brief explanation for each. List them clearly, perhaps with bullet points or numbered list. Do NOT attempt to scan or visit the URL. Base your suggestions on general knowledge of web application security and common attack patterns associated with URLs.`;

    let chatHistory = [];
    chatHistory.push({ role: "user", parts: [{ text: prompt }] });
    const payload = { contents: chatHistory };

    try {
      const response = await fetch(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const result = await response.json();

      if (result.candidates && result.candidates.length > 0 &&
          result.candidates[0].content && result.candidates[0].content.parts &&
          result.candidates[0].content.parts.length > 0) {
        const text = result.candidates[0].content.parts[0].text;
        setLlmWebsiteVulnerabilities(text);
        const chartData = parseLlmVulnerabilitiesForChart(text);
        setWebsiteVulnerabilityChartData(chartData);
      } else {
        setLlmWebsiteVulnerabilities('Could not retrieve LLM vulnerability suggestions. Please try again.');
      }
    } catch (error) {
      console.error('Error fetching LLM website vulnerabilities:', error);
      setLlmWebsiteVulnerabilities('Error fetching LLM website vulnerability suggestions.');
    } finally {
      setLlmWebsiteVulnerabilitiesLoading(false);
    }
  };

  // Function to get detailed explanation of a specific vulnerability from LLM
  const getLlmDetailedVulnerabilityExplanation = async () => {
    if (!selectedVulnerability) return;

    setLlmDetailedVulnerabilityExplanationLoading(true);
    setLlmDetailedVulnerabilityExplanation(''); // Clear previous explanation

    const prompt = `Explain the cybersecurity vulnerability "${selectedVulnerability.name}" in detail. Describe how it works, its common exploitation techniques, and provide a brief example of how it might be exploited. Focus on clarity and practical understanding.`;

    let chatHistory = [];
    chatHistory.push({ role: "user", parts: [{ text: prompt }] });
    const payload = { contents: chatHistory };

    try {
      const response = await fetch(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const result = await response.json();

      if (result.candidates && result.candidates.length > 0 &&
          result.candidates[0].content && result.candidates[0].content.parts &&
          result.candidates[0].content.parts.length > 0) {
        const text = result.candidates[0].content.parts[0].text;
        setLlmDetailedVulnerabilityExplanation(text);
      } else {
        setLlmDetailedVulnerabilityExplanation('Could not retrieve detailed explanation. Please try again.');
      }
    } catch (error) {
      console.error('Error fetching LLM detailed explanation:', error);
      setLlmDetailedVulnerabilityExplanation('Error fetching detailed explanation.');
    } finally {
      setLlmDetailedVulnerabilityExplanationLoading(false);
    }
  };


  return (
    <div className={`p-6 rounded-xl shadow-2xl ${theme === 'dark' ? 'bg-gray-800' : 'bg-white'}`}>
      <h2 className={`text-4xl font-extrabold ${theme === 'dark' ? 'text-red-400' : 'text-red-700'} mb-8 text-center`}>🔐 Vulnerability Assessment & Penetration Testing (VAPT)</h2>

      {/* Vulnerability Dashboard */}
      <section className="mb-10">
        <h3 className={`text-3xl font-bold ${theme === 'dark' ? 'text-gray-200' : 'text-gray-800'} mb-6 border-b ${theme === 'dark' ? 'border-gray-700' : 'border-gray-300'} pb-3`}>Discovered Issues</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {vulnerabilities.map((vuln) => (
            <div
              key={vuln.id}
              className={`p-6 rounded-lg shadow-lg border-t-4
                ${vuln.severity === 'High'
                  ? (theme === 'dark' ? 'bg-red-900 border-red-500' : 'bg-red-200 border-red-600')
                  : ''}
                ${vuln.severity === 'Medium'
                  ? (theme === 'dark' ? 'bg-yellow-900 border-yellow-500' : 'bg-yellow-200 border-yellow-600')
                  : ''}
                ${vuln.severity === 'Low'
                  ? (theme === 'dark' ? 'bg-green-900 border-green-500' : 'bg-green-200 border-green-600')
                  : ''}
                transition-transform transform hover:scale-105 cursor-pointer
              `}
              onClick={() => {
                setSelectedVulnerability(vuln);
                setLlmRemediation(''); // Clear LLM remediation when new vuln is selected
                setLlmDetailedVulnerabilityExplanation(''); // Clear detailed explanation
              }}
            >
              <h4 className={`text-xl font-semibold mb-2 ${theme === 'dark' ? 'text-white' : 'text-gray-900'}`}>{vuln.name}</h4>
              <p className={`text-sm font-bold mb-2 ${
                vuln.severity === 'High' ? (theme === 'dark' ? 'text-red-300' : 'text-red-700') : ''
              } ${
                vuln.severity === 'Medium' ? (theme === 'dark' ? 'text-yellow-300' : 'text-yellow-700') : ''
              } ${
                vuln.severity === 'Low' ? (theme === 'dark' ? 'text-green-300' : 'text-green-700') : ''
              }`}>
                Severity: {vuln.severity}
              </p>
              <p className={`${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'} text-sm mb-2`}>Endpoint: <code className={`${theme === 'dark' ? 'bg-gray-700' : 'bg-gray-300'} px-2 py-1 rounded`}>{vuln.endpoint}</code></p>
              <p className={`${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'} text-sm`}>{vuln.description.substring(0, 100)}...</p>
              <button
                onClick={(e) => { e.stopPropagation(); loadExamplePayload(vuln.payload); }}
                className={`${theme === 'dark' ? 'bg-gray-700 hover:bg-gray-600 text-gray-200' : 'bg-gray-300 hover:bg-gray-400 text-gray-800'} mt-4 text-sm py-2 px-4 rounded-full transition-colors`}
              >
                Load Example Payload
              </button>
            </div>
          ))}
        </div>
      </section>

      {/* Selected Vulnerability Details Modal/Panel */}
      {selectedVulnerability && (
        <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50 p-4">
          <div className={`${theme === 'dark' ? 'bg-gray-900' : 'bg-white'} p-8 rounded-xl shadow-2xl max-w-2xl w-full relative border ${theme === 'dark' ? 'border-gray-700' : 'border-gray-300'}`}>
            <button
              onClick={() => setSelectedVulnerability(null)}
              className={`absolute top-4 right-4 ${theme === 'dark' ? 'text-gray-400 hover:text-white' : 'text-gray-600 hover:text-gray-900'} text-2xl`}
            >
              &times;
            </button>
            <h3 className={`text-3xl font-bold ${theme === 'dark' ? 'text-red-400' : 'text-red-700'} mb-4`}>{selectedVulnerability.name}</h3>
            <p className={`text-lg font-bold mb-4 ${
                selectedVulnerability.severity === 'High' ? (theme === 'dark' ? 'text-red-300' : 'text-red-700') : ''
              } ${
                selectedVulnerability.severity === 'Medium' ? (theme === 'dark' ? 'text-yellow-300' : 'text-yellow-700') : ''
              } ${
                selectedVulnerability.severity === 'Low' ? (theme === 'dark' ? 'text-green-300' : 'text-green-700') : ''
              }`}>
              Severity: {selectedVulnerability.severity}
            </p>
            <p className={`${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'} mb-4`}><strong>Description:</strong> {selectedVulnerability.description}</p>
            <p className={`${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'} mb-4`}><strong>Remediation:</strong> {selectedVulnerability.remediation}</p>
            <p className={`${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'} mb-4`}><strong>Affected Endpoint:</strong> <code className={`${theme === 'dark' ? 'bg-gray-700' : 'bg-gray-300'} px-2 py-1 rounded`}>{selectedVulnerability.endpoint}</code></p>
            {selectedVulnerability.payload && (
              <p className={`${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'} mb-4`}>
                <strong>Example Payload:</strong> <code className={`${theme === 'dark' ? 'bg-gray-700' : 'bg-gray-300'} px-2 py-1 rounded break-all`}>{selectedVulnerability.payload}</code>
              </p>
            )}

            <div className="flex flex-col sm:flex-row space-y-4 sm:space-y-0 sm:space-x-4 mt-6">
              <button
                onClick={() => {
                  loadExamplePayload(selectedVulnerability.payload);
                  setSelectedVulnerability(null); // Close modal after loading payload
                }}
                className={`${theme === 'dark' ? 'bg-blue-600 hover:bg-blue-700 text-white' : 'bg-blue-700 hover:bg-blue-800 text-white'} font-bold py-3 px-6 rounded-lg shadow-md transition-colors flex-grow`}
              >
                Use this Payload in Simulation
              </button>
              <button
                onClick={getLlmRemediation}
                disabled={llmLoading}
                className={`${theme === 'dark' ? 'bg-purple-600 hover:bg-purple-700 text-white' : 'bg-purple-700 hover:bg-purple-800 text-white'} font-bold py-3 px-6 rounded-lg shadow-md transition-colors flex-grow disabled:opacity-50 disabled:cursor-not-allowed`}
              >
                {llmLoading ? 'Generating...' : 'Get LLM Remediation Advice ✨'}
              </button>
            </div>

            <button
              onClick={getLlmDetailedVulnerabilityExplanation}
              disabled={llmDetailedVulnerabilityExplanationLoading}
              className={`${theme === 'dark' ? 'bg-yellow-600 hover:bg-yellow-700 text-white' : 'bg-yellow-700 hover:bg-yellow-800 text-white'} font-bold py-3 px-6 rounded-lg shadow-md transition-colors w-full mt-4 disabled:opacity-50 disabled:cursor-not-allowed`}
            >
              {llmDetailedVulnerabilityExplanationLoading ? 'Explaining...' : 'Explain Vulnerability with AI ✨'}
            </button>

            {llmRemediation && (
              <div className={`mt-6 p-4 rounded-lg border ${theme === 'dark' ? 'bg-gray-800 border-gray-700' : 'bg-gray-100 border-gray-300'}`}>
                <h4 className={`text-xl font-semibold ${theme === 'dark' ? 'text-gray-200' : 'text-gray-800'} mb-2`}>AI-Powered Remediation:</h4>
                <p className={`${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'} whitespace-pre-wrap`}>{llmRemediation}</p>
              </div>
            )}

            {llmDetailedVulnerabilityExplanation && (
              <div className={`mt-6 p-4 rounded-lg border ${theme === 'dark' ? 'bg-gray-800 border-gray-700' : 'bg-gray-100 border-gray-300'}`}>
                <h4 className={`text-xl font-semibold ${theme === 'dark' ? 'text-gray-200' : 'text-gray-800'} mb-2`}>AI-Powered Explanation:</h4>
                <p className={`${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'} whitespace-pre-wrap`}>{llmDetailedVulnerabilityExplanation}</p>
              </div>
            )}
          </div>
        </div>
      )}


      {/* Manual Exploitation Simulation */}
      <section className="mb-10">
        <h3 className={`text-3xl font-bold ${theme === 'dark' ? 'text-gray-200' : 'text-gray-800'} mb-6 border-b ${theme === 'dark' ? 'border-gray-700' : 'border-gray-300'} pb-3`}>Manual Exploitation Simulation</h3>
        <div className={`${theme === 'dark' ? 'bg-gray-900' : 'bg-gray-50'} p-8 rounded-xl shadow-inner border ${theme === 'dark' ? 'border-gray-700' : 'border-gray-300'}`}>
          <label htmlFor="payload" className={`block text-lg font-medium ${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'} mb-3`}>
            Enter Payload for Simulation:
          </label>
          <textarea
            id="payload"
            className={`w-full p-4 rounded-lg text-gray-200 placeholder-gray-400 focus:ring-teal-500 focus:border-teal-500 outline-none transition-all duration-200
              ${theme === 'dark' ? 'bg-gray-700 border-gray-600 text-gray-200 placeholder-gray-400' : 'bg-gray-100 border-gray-300 text-gray-900 placeholder-gray-500'}`}
            rows="5"
            placeholder="e.g., ' OR '1'='1 --"
            value={exploitationPayload}
            onChange={(e) => setExploitationPayload(e.target.value)}
          ></textarea>
          <button
            onClick={handleExploitSimulation}
            className={`${theme === 'dark' ? 'bg-red-600 hover:bg-red-700 text-white' : 'bg-red-700 hover:bg-red-800 text-white'} mt-5 font-bold py-3 px-6 rounded-lg shadow-md transform hover:scale-105 transition-all duration-300`}
          >
            Simulate Exploitation
          </button>
          <button
            onClick={generateAdvancedPayload}
            disabled={llmPayloadLoading}
            className={`${theme === 'dark' ? 'bg-green-600 hover:bg-green-700 text-white' : 'bg-green-700 hover:bg-green-800 text-white'} mt-5 ml-4 font-bold py-3 px-6 rounded-lg shadow-md transform hover:scale-105 transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed`}
          >
            {llmPayloadLoading ? 'Generating...' : 'Generate Advanced Payload ✨'}
          </button>

          {exploitationResult && (
            <div className={`mt-6 p-4 rounded-lg border ${theme === 'dark' ? 'bg-gray-700 border-gray-600' : 'bg-gray-200 border-gray-400'}`}>
              <h4 className={`text-xl font-semibold ${theme === 'dark' ? 'text-gray-200' : 'text-gray-800'} mb-2`}>Simulation Result:</h4>
              <div className={`${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'}`}>{exploitationResult}</div>
            </div>
          )}
        </div>
      </section>

      {/* AI-Powered Website Vulnerability Suggestion */}
      <section className="mb-10">
        <h3 className={`text-3xl font-bold ${theme === 'dark' ? 'text-gray-200' : 'text-gray-800'} mb-6 border-b ${theme === 'dark' ? 'border-gray-700' : 'border-gray-300'} pb-3`}>AI-Powered Website Vulnerability Suggestion</h3>
        <div className={`${theme === 'dark' ? 'bg-gray-900' : 'bg-gray-50'} p-8 rounded-xl shadow-inner border ${theme === 'dark' ? 'border-gray-700' : 'border-gray-300'}`}>
          <label htmlFor="websiteUrl" className={`block text-lg font-medium ${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'} mb-3`}>
            Enter Website URL:
          </label>
          <input
            type="url"
            id="websiteUrl"
            className={`w-full p-4 rounded-lg text-gray-200 placeholder-gray-400 focus:ring-teal-500 focus:border-teal-500 outline-none transition-all duration-200
              ${theme === 'dark' ? 'bg-gray-700 border-gray-600 text-gray-200 placeholder-gray-400' : 'bg-gray-100 border-gray-300 text-gray-900 placeholder-gray-500'}`}
            placeholder="e.g., https://www.example.com"
            value={websiteUrl}
            onChange={(e) => setWebsiteUrl(e.target.value)}
          />
          <button
            onClick={getLlmWebsiteVulnerabilities}
            disabled={llmWebsiteVulnerabilitiesLoading}
            className={`${theme === 'dark' ? 'bg-blue-600 hover:bg-blue-700 text-white' : 'bg-blue-700 hover:bg-blue-800 text-white'} mt-5 font-bold py-3 px-6 rounded-lg shadow-md transform hover:scale-105 transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed`}
          >
            {llmWebsiteVulnerabilitiesLoading ? 'Suggesting...' : 'Suggest Vulnerabilities ✨'}
          </button>

          {llmWebsiteVulnerabilities && (
            <div className={`mt-6 p-4 rounded-lg border ${theme === 'dark' ? 'bg-gray-700 border-gray-600' : 'bg-gray-200 border-gray-400'}`}>
              <h4 className={`text-xl font-semibold ${theme === 'dark' ? 'text-gray-200' : 'text-gray-800'} mb-2`}>AI-Suggested Vulnerabilities:</h4>
              <p className={`${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'} whitespace-pre-wrap`}>{llmWebsiteVulnerabilities}</p>

              {websiteVulnerabilityChartData.length > 0 && (
                <div className="mt-6">
                  <h5 className={`text-lg font-semibold ${theme === 'dark' ? 'text-gray-200' : 'text-gray-800'} mb-2`}>Vulnerability Distribution:</h5>
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart
                      data={websiteVulnerabilityChartData}
                      margin={{ top: 20, right: 30, left: 20, bottom: 5 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke={theme === 'dark' ? '#4a5568' : '#cbd5e0'} />
                      <XAxis dataKey="name" stroke={theme === 'dark' ? '#cbd5e0' : '#4a5568'} angle={-30} textAnchor="end" height={80} />
                      <YAxis stroke={theme === 'dark' ? '#cbd5e0' : '#4a5568'} allowDecimals={false} />
                      <Tooltip
                        contentStyle={{ backgroundColor: theme === 'dark' ? '#2d3748' : '#f7fafc', border: 'none', borderRadius: '8px' }}
                        itemStyle={{ color: theme === 'dark' ? '#cbd5e0' : '#2d3748' }}
                      />
                      <Legend />
                      <Bar dataKey="count" fill={theme === 'dark' ? '#8884d8' : '#6663b8'} name="Count" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}

              <p className={`text-sm mt-4 ${theme === 'dark' ? 'text-yellow-300' : 'text-yellow-700'}`}>
                *Disclaimer: This is a simulated suggestion based on general knowledge and does not involve actual scanning of the provided URL. Chart data is derived heuristically from AI text output.
              </p>
            </div>
          )}
        </div>
      </section>


      {/* Safeguarding Guidelines for VAPT */}
      <section>
        <h3 className={`text-3xl font-bold ${theme === 'dark' ? 'text-gray-200' : 'text-gray-800'} mb-6 border-b ${theme === 'dark' ? 'border-gray-700' : 'border-gray-300'} pb-3`}>Safeguarding Guidelines (VAPT)</h3>
        <div className={`${theme === 'dark' ? 'bg-gray-900' : 'bg-gray-50'} p-8 rounded-xl shadow-inner border ${theme === 'dark' ? 'border-gray-700' : 'border-gray-300'}`}>
          <ul className={`list-disc list-inside space-y-3 ${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'}`}>
            <li><strong>Input Validation & Sanitization:</strong> Always validate and sanitize all user input on both the client and server sides to prevent injection attacks (SQLi, XSS, Command Injection). Use allow-lists for input where possible.</li>
            <li><strong>Parameterized Queries:</strong> For database interactions, always use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.</li>
            <li><strong>Output Encoding:</strong> Encode all user-supplied data before rendering it in HTML, JavaScript, or other contexts to prevent XSS attacks.</li>
            <li><strong>Strong Authentication & Session Management:</strong> Enforce strong, unique passwords. Implement multi-factor authentication (MFA). Use secure session management (e.g., HTTPS-only cookies, short session timeouts, proper session invalidation). Implement brute-force protection (rate limiting, CAPTCHAs).</li>
            <li><strong>Least Privilege Principle:</strong> Ensure users and processes only have the minimum necessary permissions to perform their functions. Implement robust access control checks at every request.</li>
            <li><strong>Security Configuration:</strong> Regularly review and harden configurations for all components (servers, databases, frameworks, libraries). Remove unnecessary features, services, and default credentials.</li>
            <li><strong>Error Handling:</strong> Implement proper error handling that avoids revealing sensitive information (e.g., stack traces, database errors) to users.</li>
            <li><strong>Regular Security Testing:</strong> Conduct regular VAPT, code reviews, and security audits to identify and remediate vulnerabilities proactively.</li>
            <li><strong>Keep Software Updated:</strong> Regularly patch and update all operating systems, frameworks, libraries, and applications to their latest secure versions.</li>
          </ul>
        </div>
      </section>
    </div>
  );
};

// IDS Module Component
const IDSModule = ({ theme }) => {
  // Simulated live logs data
  const [liveLogs, setLiveLogs] = useState([]);
  // Simulated anomaly data for graph
  const [anomalyData, setAnomalyData] = useState([]);
  // Simulated alert cards
  const [alertCards, setAlertCards] = useState([]);
  // State for LLM alert analysis
  const [analyzedAlertId, setAnalyzedAlertId] = useState(null);
  const [llmAlertAnalysis, setLlmAlertAnalysis] = useState('');
  const [llmLoadingAlert, setLlmLoadingAlert] = useState(false);
  // State for LLM threat intelligence
  const [threatIntelAlertId, setThreatIntelAlertId] = useState(null);
  const [llmThreatIntel, setLlmThreatIntel] = useState('');
  const [llmLoadingThreatIntel, setLlmLoadingThreatIntel] = useState(false);


  // Gemini API configuration
  const apiKey = ""; // If you want to use models other than gemini-2.0-flash or imagen-3.0-generate-002, provide an API key here. Otherwise, leave this as-is.
  const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;

  // Function to generate random log entries
  const generateLogEntry = () => {
    const ips = ['192.168.1.100', '10.0.0.5', '172.16.0.20', '203.0.113.45', '198.51.100.12'];
    const protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS'];
    const eventTypes = ['Connection Attempt', 'Packet Drop', 'Login Success', 'Login Failed', 'Data Transfer'];
    const statuses = ['Allowed', 'Blocked', 'Success', 'Failed'];
    const attackTypes = ['None', 'DoS', 'Probe', 'Brute Force', 'Malware', 'Phishing Attempt'];

    const isAnomaly = Math.random() < 0.2; // 20% chance of an anomaly
    const attackType = isAnomaly ? attackTypes[Math.floor(Math.random() * (attackTypes.length - 1)) + 1] : 'None'; // Ensure 'None' is less likely for anomalies

    return {
      id: Date.now() + Math.random(),
      timestamp: new Date().toLocaleTimeString(),
      source_ip: ips[Math.floor(Math.random() * ips.length)],
      dest_ip: ips[Math.floor(Math.random() * ips.length)],
      protocol: protocols[Math.floor(Math.random() * protocols.length)],
      event_type: eventTypes[Math.floor(Math.random() * eventTypes.length)],
      status: isAnomaly ? 'Blocked' : statuses[Math.floor(Math.random() * statuses.length)],
      attack_type: attackType,
      is_anomaly: isAnomaly,
      anomaly_score: isAnomaly ? (Math.random() * 0.5 + 0.5).toFixed(2) : (Math.random() * 0.4).toFixed(2), // Higher score for anomalies
    };
  };

  // Effect to simulate real-time log generation
  useEffect(() => {
    const interval = setInterval(() => {
      const newLog = generateLogEntry();
      setLiveLogs((prevLogs) => {
        const updatedLogs = [newLog, ...prevLogs.slice(0, 19)]; // Keep last 20 logs
        return updatedLogs;
      });

      // Update anomaly data for graph
      setAnomalyData((prevData) => {
        const newDataPoint = {
          name: new Date().toLocaleTimeString(),
          score: parseFloat(newLog.anomaly_score),
        };
        const updatedData = [...prevData, newDataPoint].slice(-30); // Keep last 30 data points
        return updatedData;
      });

      // If it's an anomaly, add to alert cards
      if (newLog.is_anomaly && newLog.attack_type !== 'None') {
        setAlertCards((prevAlerts) => [
          {
            id: newLog.id,
            type: newLog.attack_type,
            description: `Detected ${newLog.attack_type} from ${newLog.source_ip} to ${newLog.dest_ip}.`,
            timestamp: newLog.timestamp,
            severity: newLog.anomaly_score > 0.7 ? 'High' : 'Medium',
            source_ip: newLog.source_ip, // Add these for LLM analysis
            dest_ip: newLog.dest_ip,
            protocol: newLog.protocol,
            event_type: newLog.event_type,
            anomaly_score: newLog.anomaly_score
          },
          ...prevAlerts.slice(0, 9), // Keep last 10 alerts
        ]);
      }
    }, 1500); // Generate a new log every 1.5 seconds

    return () => clearInterval(interval); // Cleanup on unmount
  }, []);

  // Function to get LLM-powered alert analysis
  const analyzeAlertWithLlm = async (alert) => {
    setAnalyzedAlertId(alert.id);
    setLlmLoadingAlert(true);
    setLlmAlertAnalysis(''); // Clear previous analysis

    const prompt = `Analyze the following cybersecurity alert and provide a concise explanation of its potential implications and recommended immediate actions:\n\nAlert Type: ${alert.type}\nDescription: ${alert.description}\nSource IP: ${alert.source_ip}\nDestination IP: ${alert.dest_ip}\nProtocol: ${alert.protocol}\nEvent Type: ${alert.event_type}\nAnomaly Score: ${alert.anomaly_score}\n\nKeep the analysis brief and to the point.`;

    let chatHistory = [];
    chatHistory.push({ role: "user", parts: [{ text: prompt }] });
    const payload = { contents: chatHistory };

    try {
      const response = await fetch(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const result = await response.json();

      if (result.candidates && result.candidates.length > 0 &&
          result.candidates[0].content && result.candidates[0].content.parts &&
          result.candidates[0].content.parts.length > 0) {
        const text = result.candidates[0].content.parts[0].text;
        setLlmAlertAnalysis(text);
      } else {
        setLlmAlertAnalysis('Could not retrieve LLM analysis. Please try again.');
      }
    } catch (error) {
      console.error('Error fetching LLM alert analysis:', error);
      setLlmAlertAnalysis('Error fetching LLM alert analysis.');
    } finally {
      setLlmLoadingAlert(false);
    }
  };

  // Function to get LLM-powered threat intelligence summary
  const getLlmThreatIntelligence = async (alert) => {
    setThreatIntelAlertId(alert.id);
    setLlmLoadingThreatIntel(true);
    setLlmThreatIntel(''); // Clear previous threat intel

    const prompt = `Provide a brief threat intelligence summary for an attack of type "${alert.type}" originating from IP address "${alert.source_ip}". Include common characteristics, typical targets, and any notable associated campaigns if applicable. Keep it concise.`;

    let chatHistory = [];
    chatHistory.push({ role: "user", parts: [{ text: prompt }] });
    const payload = { contents: chatHistory };

    try {
      const response = await fetch(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const result = await response.json();

      if (result.candidates && result.candidates.length > 0 &&
          result.candidates[0].content && result.candidates[0].content.parts &&
          result.candidates[0].content.parts.length > 0) {
        const text = result.candidates[0].content.parts[0].text;
        setLlmThreatIntel(text);
      } else {
        setLlmThreatIntel('Could not retrieve LLM threat intelligence. Please try again.');
      }
    } catch (error) {
      console.error('Error fetching LLM threat intelligence:', error);
      setLlmThreatIntel('Error fetching LLM threat intelligence.');
    } finally {
      setLlmLoadingThreatIntel(false);
    }
  };


  return (
    <div className={`p-6 rounded-xl shadow-2xl ${theme === 'dark' ? 'bg-gray-800' : 'bg-white'}`}>
      <h2 className={`text-4xl font-extrabold ${theme === 'dark' ? 'text-blue-400' : 'text-blue-700'} mb-8 text-center`}>🤖 AI-Powered Intrusion Detection System (IDS)</h2>

      {/* Anomaly Graphs */}
      <section className="mb-10">
        <h3 className={`text-3xl font-bold ${theme === 'dark' ? 'text-gray-200' : 'text-gray-800'} mb-6 border-b ${theme === 'dark' ? 'border-gray-700' : 'border-gray-300'} pb-3`}>Anomaly Detection Graph</h3>
        <div className={`${theme === 'dark' ? 'bg-gray-900' : 'bg-gray-50'} p-6 rounded-xl shadow-inner border ${theme === 'dark' ? 'border-gray-700' : 'border-gray-300'} h-80`}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart
              data={anomalyData}
              margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke={theme === 'dark' ? '#4a5568' : '#cbd5e0'} />
              <XAxis dataKey="name" stroke={theme === 'dark' ? '#cbd5e0' : '#4a5568'} />
              <YAxis stroke={theme === 'dark' ? '#cbd5e0' : '#4a5568'} domain={[0, 1]} />
              <Tooltip
                contentStyle={{ backgroundColor: theme === 'dark' ? '#2d3748' : '#f7fafc', border: 'none', borderRadius: '8px' }}
                itemStyle={{ color: theme === 'dark' ? '#cbd5e0' : '#2d3748' }}
              />
              <Legend />
              <Line type="monotone" dataKey="score" stroke={theme === 'dark' ? '#38b2ac' : '#2d3748'} activeDot={{ r: 8 }} name="Anomaly Score" />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </section>

      {/* Alert Cards */}
      <section className="mb-10">
        <h3 className={`text-3xl font-bold ${theme === 'dark' ? 'text-gray-200' : 'text-gray-800'} mb-6 border-b ${theme === 'dark' ? 'border-gray-700' : 'border-gray-300'} pb-3`}>Recent Alerts</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {alertCards.length > 0 ? (
            alertCards.map((alert) => (
              <div
                key={alert.id}
                className={`p-6 rounded-lg shadow-lg border-t-4
                  ${alert.severity === 'High'
                    ? (theme === 'dark' ? 'bg-red-900 border-red-500' : 'bg-red-200 border-red-600')
                    : ''}
                  ${alert.severity === 'Medium'
                    ? (theme === 'dark' ? 'bg-yellow-900 border-yellow-500' : 'bg-yellow-200 border-yellow-600')
                    : ''}
                  ${alert.severity === 'Low'
                    ? (theme === 'dark' ? 'bg-green-900 border-green-500' : 'bg-green-200 border-green-600')
                    : ''}
                  flex flex-col
                `}
              >
                <h4 className={`text-xl font-semibold mb-2 ${theme === 'dark' ? 'text-white' : 'text-gray-900'}`}>{alert.type} Detected!</h4>
                <p className={`text-sm font-bold mb-2 ${
                  alert.severity === 'High' ? (theme === 'dark' ? 'text-red-300' : 'text-red-700') : ''
                } ${
                  alert.severity === 'Medium' ? (theme === 'dark' ? 'text-yellow-300' : 'text-yellow-700') : ''
                } ${
                  alert.severity === 'Low' ? (theme === 'dark' ? 'text-green-300' : 'text-green-700') : ''
                }`}>
                  Severity: {alert.severity}
                </p>
                <p className={`${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'} text-sm mb-2`}>{alert.description}</p>
                <p className={`${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'} text-xs`}>Time: {alert.timestamp}</p>

                <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-2 mt-4">
                  <button
                    onClick={() => analyzeAlertWithLlm(alert)}
                    disabled={llmLoadingAlert && analyzedAlertId === alert.id}
                    className={`${theme === 'dark' ? 'bg-purple-600 hover:bg-purple-700 text-white' : 'bg-purple-700 hover:bg-purple-800 text-white'} font-bold py-2 px-4 rounded-lg shadow-md transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex-grow`}
                  >
                    {llmLoadingAlert && analyzedAlertId === alert.id ? 'Analyzing...' : 'Analyze with AI ✨'}
                  </button>
                  <button
                    onClick={() => getLlmThreatIntelligence(alert)}
                    disabled={llmLoadingThreatIntel && threatIntelAlertId === alert.id}
                    className={`${theme === 'dark' ? 'bg-indigo-600 hover:bg-indigo-700 text-white' : 'bg-indigo-700 hover:bg-indigo-800 text-white'} font-bold py-2 px-4 rounded-lg shadow-md transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex-grow`}
                  >
                    {llmLoadingThreatIntel && threatIntelAlertId === alert.id ? 'Getting Intel...' : 'Get Threat Intel ✨'}
                  </button>
                </div>


                {analyzedAlertId === alert.id && llmAlertAnalysis && (
                  <div className={`mt-4 p-3 rounded-lg border ${theme === 'dark' ? 'bg-gray-700 border-gray-600' : 'bg-gray-200 border-gray-400'} text-sm ${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'} whitespace-pre-wrap`}>
                    <h5 className={`font-semibold ${theme === 'dark' ? 'text-gray-200' : 'text-gray-800'} mb-1`}>AI Analysis:</h5>
                    {llmAlertAnalysis}
                  </div>
                )}
                {threatIntelAlertId === alert.id && llmThreatIntel && (
                  <div className={`mt-4 p-3 rounded-lg border ${theme === 'dark' ? 'bg-gray-700 border-gray-600' : 'bg-gray-200 border-gray-400'} text-sm ${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'} whitespace-pre-wrap`}>
                    <h5 className={`font-semibold ${theme === 'dark' ? 'text-gray-200' : 'text-gray-800'} mb-1`}>Threat Intelligence:</h5>
                    {llmThreatIntel}
                  </div>
                )}
              </div>
            ))
          ) : (
            <p className={`${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'} col-span-full text-center`}>No recent alerts. System is clear.</p>
          )}
        </div>
      </section>

      {/* Live Logs Table */}
      <section className="mb-10">
        <h3 className={`text-3xl font-bold ${theme === 'dark' ? 'text-gray-200' : 'text-gray-800'} mb-6 border-b ${theme === 'dark' ? 'border-gray-700' : 'border-gray-300'} pb-3`}>Live Network Logs</h3>
        <div className={`${theme === 'dark' ? 'bg-gray-900' : 'bg-gray-50'} p-6 rounded-xl shadow-inner border ${theme === 'dark' ? 'border-gray-700' : 'border-gray-300'} overflow-x-auto`}>
          <table className={`min-w-full divide-y ${theme === 'dark' ? 'divide-gray-700' : 'divide-gray-300'}`}>
            <thead className={`${theme === 'dark' ? 'bg-gray-700' : 'bg-gray-200'}`}>
              <tr>
                <th scope="col" className={`px-6 py-3 text-left text-xs font-medium ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'} uppercase tracking-wider rounded-tl-lg`}>
                  Time
                </th>
                <th scope="col" className={`px-6 py-3 text-left text-xs font-medium ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'} uppercase tracking-wider`}>
                  Source IP
                </th>
                <th scope="col" className={`px-6 py-3 text-left text-xs font-medium ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'} uppercase tracking-wider`}>
                  Dest IP
                </th>
                <th scope="col" className={`px-6 py-3 text-left text-xs font-medium ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'} uppercase tracking-wider`}>
                  Protocol
                </th>
                <th scope="col" className={`px-6 py-3 text-left text-xs font-medium ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'} uppercase tracking-wider`}>
                  Event Type
                </th>
                <th scope="col" className={`px-6 py-3 text-left text-xs font-medium ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'} uppercase tracking-wider`}>
                  Status
                </th>
                <th
                  scope="col"
                  className={`px-6 py-3 text-left text-xs font-medium ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'} uppercase tracking-wider`}
                >
                  Attack Type
                </th>
                <th scope="col" className={`px-6 py-3 text-left text-xs font-medium ${theme === 'dark' ? 'text-gray-400' : 'text-gray-600'} uppercase tracking-wider rounded-tr-lg`}>
                  Anomaly Score
                </th>
              </tr>
            </thead>
            <tbody className={`${theme === 'dark' ? 'bg-gray-800 divide-gray-700' : 'bg-white divide-gray-300'} divide-y`}>
              {liveLogs.map((log) => (
                <tr key={log.id} className={`${log.is_anomaly ? (theme === 'dark' ? 'bg-red-950' : 'bg-red-100') : (theme === 'dark' ? 'hover:bg-gray-700' : 'hover:bg-gray-100')} transition-colors`}>
                  <td className={`px-6 py-4 whitespace-nowrap text-sm font-medium ${theme === 'dark' ? 'text-gray-200' : 'text-gray-800'}`}>{log.timestamp}</td>
                  <td className={`px-6 py-4 whitespace-nowrap text-sm ${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'}`}>{log.source_ip}</td>
                  <td className={`px-6 py-4 whitespace-nowrap text-sm ${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'}`}>{log.dest_ip}</td>
                  <td className={`px-6 py-4 whitespace-nowrap text-sm ${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'}`}>{log.protocol}</td>
                  <td className={`px-6 py-4 whitespace-nowrap text-sm ${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'}`}>{log.event_type}</td>
                  <td className={`px-6 py-4 whitespace-nowrap text-sm ${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'}`}>{log.status}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                    <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full
                      ${log.attack_type === 'DoS' ? (theme === 'dark' ? 'bg-red-600 text-white' : 'bg-red-700 text-white') : ''}
                      ${log.attack_type === 'Probe' ? (theme === 'dark' ? 'bg-orange-600 text-white' : 'bg-orange-700 text-white') : ''}
                      ${log.attack_type === 'Brute Force' ? (theme === 'dark' ? 'bg-purple-600 text-white' : 'bg-purple-700 text-white') : ''}
                      ${log.attack_type === 'Malware' ? (theme === 'dark' ? 'bg-pink-600 text-white' : 'bg-pink-700 text-white') : ''}
                      ${log.attack_type === 'Phishing Attempt' ? (theme === 'dark' ? 'bg-indigo-600 text-white' : 'bg-indigo-700 text-white') : ''}
                      ${log.attack_type === 'None' ? (theme === 'dark' ? 'bg-green-600 text-white' : 'bg-green-700 text-white') : ''}
                    `}>
                      {log.attack_type}
                    </span>
                  </td>
                  <td className={`px-6 py-4 whitespace-nowrap text-sm ${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'}`}>{log.anomaly_score}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Safeguarding Guidelines for IDS */}
      <section>
        <h3 className={`text-3xl font-bold ${theme === 'dark' ? 'text-gray-200' : 'text-gray-800'} mb-6 border-b ${theme === 'dark' ? 'border-gray-700' : 'border-gray-300'} pb-3`}>Safeguarding Guidelines (IDS)</h3>
        <div className={`${theme === 'dark' ? 'bg-gray-900' : 'bg-gray-50'} p-8 rounded-xl shadow-inner border ${theme === 'dark' ? 'border-gray-700' : 'border-gray-300'}`}>
          <ul className={`list-disc list-inside space-y-3 ${theme === 'dark' ? 'text-gray-300' : 'text-gray-700'}`}>
            <li><strong>Network Segmentation:</strong> Divide your network into smaller, isolated segments to limit the lateral movement of attackers in case of a breach.</li>
            <li><strong>Firewall Configuration:</strong> Implement strict firewall rules to control inbound and outbound traffic, allowing only necessary ports and protocols.</li>
            <li><strong>Regular Patching & Updates:</strong> Keep all network devices, operating systems, and applications patched and updated to protect against known vulnerabilities.</li>
            <li><strong>Strong Access Controls:</strong> Implement the principle of least privilege for network access. Use strong authentication mechanisms and multi-factor authentication (MFA) for all network devices and services.</li>
            <li><strong>Logging and Monitoring:</strong> Centralize logs from all network devices and systems. Regularly review logs for suspicious activities and anomalies.</li>
            <li><strong>Intrusion Prevention Systems (IPS):</strong> Deploy IPS alongside IDS to automatically block detected threats in real-time.</li>
            <li><strong>Incident Response Plan:</strong> Develop and regularly test a comprehensive incident response plan to quickly and effectively handle security incidents.</li>
            <li><strong>Employee Training:</strong> Educate employees about cybersecurity best practices, phishing awareness, and safe browsing habits.</li>
            <li><strong>Data Encryption:</strong> Encrypt sensitive data both in transit (e.g., HTTPS, VPNs) and at rest (e.g., disk encryption) to protect it from unauthorized access.</li>
            <li><strong>Regular Backups:</strong> Perform regular backups of critical data and systems, and test the restoration process to ensure business continuity in case of a cyberattack.</li>
          </ul>
        </div>
      </section>
    </div>
  );
};

export default App;
