import { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import axios from 'axios';
import { motion } from 'framer-motion';
import {
  ArrowPathIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ClockIcon,
  DocumentArrowDownIcon,
  GlobeAltIcon,
  ShieldExclamationIcon,
  CalendarIcon,
  ServerIcon,
  LockClosedIcon,
  DocumentTextIcon
} from '@heroicons/react/24/outline';

// Risk level badge component
const RiskBadge = ({ score }) => {
  let color, label;
  
  if (score >= 80) {
    color = 'red';
    label = 'High Risk';
  } else if (score >= 50) {
    color = 'yellow';
    label = 'Medium Risk';
  } else if (score >= 20) {
    color = 'blue';
    label = 'Low Risk';
  } else {
    color = 'green';
    label = 'Minimal Risk';
  }
  
  return (
    <span className={`badge badge-${color}`}>
      {label} ({score}/100)
    </span>
  );
};

export default function AnalysisPage() {
  // ChatGPT impact analysis state
  const [impact, setImpact] = useState(null);
  const [impactLoading, setImpactLoading] = useState(false);
  const [impactError, setImpactError] = useState(null);

  const { uploadId } = useParams();
  const navigate = useNavigate();
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [scanningVt, setScanningVt] = useState(false);
  const [scanMessage, setScanMessage] = useState('');
  const [scanProgress, setScanProgress] = useState(0);
  const [scanTimer, setScanTimer] = useState(null);
  const [generatingReport, setGeneratingReport] = useState(false);
  const [chatgptAnalysis, setChatgptAnalysis] = useState(null);
  const [loadingChatgpt, setLoadingChatgpt] = useState(false);
  const [chatgptError, setChatgptError] = useState(null);

  // Fetch analysis data
  useEffect(() => {
    const fetchAnalysis = async () => {
      setLoading(true);
      setError(null);
      
      try {
        // Check if this is a mock upload ID
        if (uploadId.startsWith('mock-')) {
          // Get mock data from localStorage
          const mockData = localStorage.getItem(`analysis_${uploadId}`);
          if (mockData) {
            setAnalysis(JSON.parse(mockData));
            console.log('Using mock data for analysis:', uploadId);
          } else {
            throw new Error('Mock data not found');
          }
        } else {
          // Try to get real data from the API
          const response = await axios.get(`/tools/takedowniq/api/analysis/${uploadId}`);
          setAnalysis(response.data);
        }
      } catch (error) {
        console.error('Error fetching analysis:', error);
        setError('Failed to load analysis data. Please try again.');
      } finally {
        setLoading(false);
      }
    };
    
    fetchAnalysis();
  }, [uploadId]);

  // Function to force a new VirusTotal scan
  const handleForceVtScan = async () => {
    if (!analysis || !analysis.domain || scanningVt) return;
    
    try {
      // Reset and start progress tracking
      setScanningVt(true);
      setScanProgress(0);
      setScanMessage('Submitting domain for scanning...');
      
      // Clear any existing timer
      if (scanTimer) {
        clearInterval(scanTimer);
      }
      
      // Start the progress simulation
      const timer = setInterval(() => {
        setScanProgress(prev => {
          // Simulate progress up to 90% (the last 10% will be when we get results)
          if (prev < 90) {
            // Slow down the progress as it gets higher
            const increment = prev < 30 ? 10 : prev < 60 ? 5 : 2;
            return Math.min(prev + increment, 90);
          }
          return prev;
        });
      }, 1000);
      
      setScanTimer(timer);
      
      // Make the API call with proper headers
      const apiConfig = {
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        }
      };
      
      // Log the API request for debugging
      console.log(`Attempting to force scan domain: ${analysis.domain}`);
      
      // Try multiple API paths to handle both development and production environments
      let response;
      const apiEndpoints = [
        '/tools/takedowniq/api/virustotal/force-scan',  // Production path with proxy
        '/virustotal/force-scan',                       // Direct backend path
        '/api/virustotal/force-scan'                    // Standard API path
      ];
      
      let lastError = null;
      
      // Try each endpoint until one works
      for (const endpoint of apiEndpoints) {
        try {
          console.log(`Trying API endpoint: ${endpoint}`);
          response = await axios.post(endpoint, {
            domain: analysis.domain
          }, apiConfig);
          console.log(`API endpoint succeeded: ${endpoint}`);
          // If we get here, the request was successful
          break;
        } catch (error) {
          console.log(`Error with endpoint ${endpoint}: ${error.message}`);
          console.log(error.response ? `Status: ${error.response.status}` : 'No response');
          lastError = error;
          // Continue to the next endpoint
        }
      }
      
      // If we've tried all endpoints and none worked, throw the last error
      if (!response) {
        console.log('All API endpoints failed');
        throw lastError;
      }
      
      if (response.data.error) {
        clearInterval(timer);
        setScanMessage(`Error: ${response.data.error}`);
        setScanProgress(0);
      } else {
        setScanMessage(
          'Scan requested successfully! Results will be available in a few minutes. ' +
          'Please refresh the page after a few minutes to see updated results.'
        );
        
        // Set progress to 95% to indicate scan was submitted successfully
        setScanProgress(95);
        
        // Set a timeout to refresh the analysis data after 10 seconds
        // This won't show the complete scan results yet, but might show scan in progress
        setTimeout(async () => {
          try {
            const refreshResponse = await axios.get(`/api/analysis/${uploadId}`);
            setAnalysis(refreshResponse.data);
            setScanProgress(100); // Complete the progress bar
            
            // Keep the progress bar visible for a moment before hiding
            setTimeout(() => {
              setScanningVt(false);
              clearInterval(timer);
              setScanTimer(null);
            }, 2000);
          } catch (err) {
            console.error('Error refreshing analysis:', err);
            setScanProgress(100); // Complete the progress bar anyway
            
            setTimeout(() => {
              setScanningVt(false);
              clearInterval(timer);
              setScanTimer(null);
            }, 2000);
          }
        }, 10000);
      }
    } catch (err) {
      setScanMessage(`Error: ${err.message || 'Failed to request scan'}`);
      setScanProgress(0);
      if (scanTimer) {
        clearInterval(scanTimer);
        setScanTimer(null);
      }
      setTimeout(() => {
        setScanningVt(false);
      }, 3000);
    }
  };
  
  // Clean up the timer when component unmounts
  useEffect(() => {
    return () => {
      if (scanTimer) {
        clearInterval(scanTimer);
      }
    };
  }, [scanTimer]);

  const fetchChatGPTImpact = async () => {
    try {
      setChatgptError(null);
      setChatgptAnalysis(null);
      if (!analysis) return;
      setLoadingChatgpt(true);
      
      // Prepare data for ChatGPT analysis (ensure all required fields are present)
      const data = {
        domain: analysis.domain || '',
        risk_score: analysis.risk_score || 0,
        whois_data: analysis.whois_data || {},
        dns_data: analysis.dns_data || {},
        ssl_data: analysis.ssl_data || {},
        virustotal_data: analysis.virustotal_data || {}
      };
      
      // Log the data being sent for debugging
      console.log('ChatGPT impact analysis request data:', JSON.stringify(data));
      
      // Determine the API endpoint to use
      // Try multiple endpoint configurations to handle different deployment scenarios
      const endpoints = [
        '/api/chatgpt-impact',                                // Direct API path
        '/chatgpt-impact',                                    // Root-relative path
        '/tools/takedowniq/api/chatgpt-impact',              // Proxy path for production
        window.location.origin + '/api/chatgpt-impact',       // Absolute URL with current origin
        'https://api.takedowniq.com/chatgpt-impact',          // Production API endpoint
        'http://localhost:12345/api/chatgpt-impact'           // Local development
      ];
      
      // Add the server IP if we're in a development environment
      if (process.env.NODE_ENV !== 'production') {
        endpoints.push('http://69.62.66.176:12345/api/chatgpt-impact');
      }
      
      // Try each endpoint until one works
      let response = null;
      let lastError = null;
      
      for (const endpoint of endpoints) {
        try {
          console.log(`Attempting to connect to endpoint: ${endpoint}`);
          response = await axios.post(endpoint, data, {
            timeout: 90000, // 90 second timeout (AI responses can take time)
            headers: {
              'Content-Type': 'application/json'
            }
          });
          
          console.log(`Successfully connected to ${endpoint}`);
          break; // Exit the loop if successful
        } catch (err) {
          console.warn(`Failed to connect to ${endpoint}:`, err.message);
          lastError = err;
          // Continue to the next endpoint
        }
      }
      
      // If all endpoints failed, throw the last error
      if (!response) {
        throw lastError || new Error('All API endpoints failed');
      }
      
      // Log the raw response for debugging
      console.log('ChatGPT impact analysis raw response:', response.data);
      
      // Check if the response contains an error
      if (response.data && response.data.error) {
        setChatgptError(response.data.error);
        setChatgptAnalysis(null);
        console.error('Error in ChatGPT analysis response:', response.data.error);
        return;
      }
      
      // Validate the response has the expected structure
      const requiredResponseFields = ['disruption_impact_score', 'news_impact_score', 'rationale'];
      const missingResponseFields = requiredResponseFields.filter(field => !response.data[field]);
      
      if (missingResponseFields.length > 0) {
        console.warn('ChatGPT response missing some fields:', missingResponseFields);
        
        // If critical fields are missing, try to normalize the data structure
        if (missingResponseFields.includes('disruption_impact_score') || 
            missingResponseFields.includes('news_impact_score')) {
          
          // If the response has a different structure, try to adapt it
          let normalizedResponse = { ...response.data };
          
          // If scores are missing but we have a numeric impact field, use that
          if (missingResponseFields.includes('disruption_impact_score') && 
              typeof response.data.impact === 'number') {
            normalizedResponse.disruption_impact_score = response.data.impact;
          }
          
          // If news_impact_score is missing but we have a numeric news_impact, use that
          if (missingResponseFields.includes('news_impact_score') && 
              typeof response.data.news_impact === 'number') {
            normalizedResponse.news_impact_score = response.data.news_impact;
          }
          
          // If rationale is missing but we have analysis or explanation, use that
          if (missingResponseFields.includes('rationale')) {
            normalizedResponse.rationale = response.data.analysis || 
                                          response.data.explanation || 
                                          response.data.summary || 
                                          'No detailed rationale provided';
          }
          
          // Ensure criteria exists
          if (!normalizedResponse.criteria) {
            normalizedResponse.criteria = {};
          }
          
          // Add disruption criteria if missing
          if (!normalizedResponse.criteria.disruption) {
            normalizedResponse.criteria.disruption = 
              response.data.disruption_details || 
              'No detailed disruption criteria provided';
          }
          
          // Add news criteria if missing
          if (!normalizedResponse.criteria.news) {
            normalizedResponse.criteria.news = 
              response.data.news_details || 
              'No detailed news impact criteria provided';
          }
          
          console.log('Normalized ChatGPT response:', normalizedResponse);
          setChatgptAnalysis(normalizedResponse);
        } else {
          // If only non-critical fields are missing, use the response as is
          setChatgptAnalysis(response.data);
        }
      } else {
        // All required fields are present
        setChatgptAnalysis(response.data);
      }
    } catch (err) {
      // Handle different types of errors
      if (err.response) {
        // The request was made and the server responded with a status code outside the 2xx range
        const statusCode = err.response.status;
        const errorData = err.response.data;
        
        console.error(`ChatGPT API error (${statusCode}):`, errorData);
        
        if (statusCode === 400) {
          setChatgptError(`Bad request: ${errorData.error || 'Invalid data provided'}`);
        } else if (statusCode === 401 || statusCode === 403) {
          setChatgptError('Authentication error with the AI service');
        } else if (statusCode === 429) {
          setChatgptError('AI service rate limit exceeded. Please try again later.');
        } else if (statusCode >= 500) {
          setChatgptError('AI service is currently unavailable. Please try again later.');
        } else {
          setChatgptError(`Error: ${errorData.error || err.message || 'Unknown error'}`);
        }
      } else if (err.request) {
        // The request was made but no response was received
        console.error('ChatGPT API no response error:', err.request);
        setChatgptError('No response from the server. Please check your network connection.');
      } else if (err.message && err.message.includes('timeout')) {
        // Request timed out
        console.error('ChatGPT API timeout error:', err);
        setChatgptError('Request timed out. The AI analysis is taking longer than expected.');
      } else {
        // Something else happened while setting up the request
        console.error('ChatGPT API unexpected error:', err);
        setChatgptError(`Failed to fetch ChatGPT analysis: ${err.message || 'Unknown error'}`);
      }
      
      setChatgptAnalysis(null);
      
      // As a fallback for production, provide a basic analysis when API fails
      if (process.env.NODE_ENV === 'production') {
        console.log('Providing fallback ChatGPT analysis due to API failure');
        setTimeout(() => {
          // Only do this in production as a temporary measure
          setChatgptError(null);
          setChatgptAnalysis({
            disruption_impact_score: Math.min(Math.round((analysis.risk_score || 50) / 10), 10),
            news_impact_score: Math.min(Math.round((analysis.risk_score || 50) / 15), 10),
            rationale: "This is an automated assessment based on the domain risk score. For a detailed AI analysis, please try again later.",
            criteria: {
              disruption: "Assessment based on domain risk factors and security indicators.",
              news: "Assessment based on domain profile and potential visibility."
            }
          });
        }, 1500);
      }
    } finally {
      setLoadingChatgpt(false);
    }
  };

  // Add a button to manually trigger ChatGPT analysis
  const handleGenerateChatGPTAnalysis = () => {
    fetchChatGPTImpact();
  };
  
  // Don't auto-fetch ChatGPT analysis on load to avoid unnecessary API calls

  // Generate PDF report
  const handleGenerateReport = async () => {
    setGeneratingReport(true);
    setError(null); // Clear any previous errors
    
    try {
      // For mock data, simulate report generation
      if (uploadId.startsWith('mock-')) {
        // Simulate API delay
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Create a mock report ID
        const mockReportId = 'mock-report-' + Math.random().toString(36).substring(2, 10);
        
        // Store mock report data in localStorage
        const mockReportData = {
          report_id: mockReportId,
          upload_id: uploadId,
          domain: analysis.domain,
          timestamp: new Date().toISOString(),
          status: 'completed',
          download_url: '#'
        };
        
        localStorage.setItem(`report_${mockReportId}`, JSON.stringify(mockReportData));
        
        // Navigate to the report page
        navigate(`/report/${mockReportId}`);
      } else {
        // For real data, try multiple API endpoints
        let response;
        let error;
        
        // First try the proxy endpoint
        try {
          console.log('Trying proxy endpoint: /tools/takedowniq/api/report/' + uploadId);
          response = await axios.post(`/tools/takedowniq/api/report/${uploadId}`);
        } catch (proxyErr) {
          console.error('Proxy endpoint failed:', proxyErr);
          error = proxyErr;
          
          // If proxy fails, try direct endpoint
          try {
            console.log('Trying direct endpoint with VITE_API_BASE_URL:', import.meta.env.VITE_API_BASE_URL);
            response = await axios.post(`${import.meta.env.VITE_API_BASE_URL}/api/report/${uploadId}`);
          } catch (directErr) {
            console.error('Direct endpoint failed:', directErr);
            
            // If both fail, try the hardcoded IP
            try {
              console.log('Trying hardcoded endpoint: http://69.62.66.176:12345/api/report/' + uploadId);
              response = await axios.post(`http://69.62.66.176:12345/api/report/${uploadId}`);
            } catch (hardcodedErr) {
              console.error('Hardcoded endpoint failed:', hardcodedErr);
              // If all attempts fail, throw the original error
              throw error;
            }
          }
        }
        
        console.log('Report generation successful:', response.data);
        
        if (response.data && response.data.report_id) {
          navigate(`/report/${response.data.report_id}`);
        } else {
          throw new Error('Invalid response from server: missing report_id');
        }
      }
    } catch (err) {
      console.error('Error generating report:', err);
      
      // Handle different error types
      if (err.message === 'Network Error') {
        setError('Network error. Please check your connection and try again. Make sure the backend server is running.');
      } else if (err.response) {
        // Server responded with an error status code
        const errorMessage = err.response.data?.detail || `Server error: ${err.response.status}`;
        setError(errorMessage);
      } else if (err.request) {
        // Request was made but no response received
        setError('No response from server. The server might be down or unreachable.');
      } else {
        // Something else went wrong
        setError(`Error: ${err.message}`);
      }
      
      setGeneratingReport(false);
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <ArrowPathIcon className="h-8 w-8 text-primary-600 animate-spin" />
        <span className="ml-2 text-lg text-gray-700">Analyzing domain...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-md bg-red-50 p-4 max-w-3xl mx-auto mt-8">
        <div className="flex">
          <ExclamationTriangleIcon className="h-5 w-5 text-red-400" aria-hidden="true" />
          <div className="ml-3">
            <h3 className="text-sm font-medium text-red-800">Error</h3>
            <div className="mt-2 text-sm text-red-700">
              <p>{error}</p>
            </div>
            <div className="mt-4">
              <Link to="/upload" className="btn-secondary text-sm">
                Return to Upload
              </Link>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-7xl">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        {/* Header */}
        <div className="border-b border-gray-200 pb-5 mb-6">
          <div className="flex flex-wrap items-baseline">
            <h1 className="text-2xl font-bold leading-7 text-gray-900 sm:truncate sm:text-3xl">
              Analysis Results: {analysis.domain}
            </h1>
            <div className="mt-1 flex flex-col sm:mt-0 sm:ml-4">
              <RiskBadge score={analysis.risk_score} />
            </div>
          </div>
          <div className="mt-1 flex flex-col sm:flex-row sm:flex-wrap sm:space-x-6">
            <div className="mt-2 flex items-center text-sm text-gray-500">
              <CalendarIcon className="mr-1.5 h-5 w-5 flex-shrink-0 text-gray-400" />
              Analyzed on {new Date(analysis.timestamp).toLocaleString()}
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Main content - left 2/3 */}
          <div className="md:col-span-2 space-y-6">
            {/* Domain Info */}
            <div className="card">
              <h2 className="text-xl font-semibold mb-4">Domain Information</h2>
              <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-6">
                <div>
                  <dt className="text-sm font-medium text-gray-500">Registration Date</dt>
                  <dd className="mt-1 text-sm text-gray-900">
                    {analysis.whois_data?.creation_date || 'Unknown'}
                  </dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Expiration Date</dt>
                  <dd className="mt-1 text-sm text-gray-900">
                    {analysis.whois_data?.expiration_date || 'Unknown'}
                  </dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Domain Age</dt>
                  <dd className="mt-1 text-sm text-gray-900">
                    {analysis.whois_data?.domain_age || 'Unknown'}
                  </dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Registrar</dt>
                  <dd className="mt-1 text-sm text-gray-900">
                    {analysis.whois_data?.registrar || 'Unknown'}
                  </dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Domain Status</dt>
                  <dd className="mt-1 text-sm text-gray-900">
                    {Array.isArray(analysis.whois_data?.status) ? (
                      <ul className="list-none space-y-1">
                        {analysis.whois_data.status.map((status, index) => (
                          <li key={`status-${index}`} className="font-mono">{status}</li>
                        ))}
                      </ul>
                    ) : typeof analysis.whois_data?.status === 'string' ? (
                      <ul className="list-none space-y-1">
                        <li className="font-mono">{analysis.whois_data.status}</li>
                      </ul>
                    ) : (
                      'Unknown'
                    )}
                  </dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Name Servers</dt>
                  <dd className="mt-1 text-sm text-gray-900">
                    {Array.isArray(analysis.dns_data?.ns_records) && analysis.dns_data.ns_records.length > 0 ? (
                      <ul className="list-none space-y-1">
                        {analysis.dns_data.ns_records.map((ns, index) => (
                          <li key={`ns-${index}`} className="font-mono">{ns}</li>
                        ))}
                      </ul>
                    ) : (
                      'Unknown'
                    )}
                  </dd>
                </div>
              </dl>
            </div>

            {/* VirusTotal Results */}
            <div className="card">
              <h2 className="text-xl font-semibold mb-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                    <span>VirusTotal Results</span>
                    {analysis.virustotal_data && analysis.virustotal_data.malicious_count > 0 && (
                      <span className="ml-2 badge badge-red">Threats Detected</span>
                    )}
                  </div>
                  <button 
                    onClick={handleForceVtScan}
                    disabled={scanningVt}
                    className={`px-3 py-1 text-sm rounded-md ${scanningVt ? 'bg-gray-300 cursor-not-allowed' : 'bg-blue-500 hover:bg-blue-600 text-white'}`}
                  >
                    {scanningVt ? 'Scanning...' : 'Force New Scan'}
                  </button>
                </div>
              </h2>
              
              {scanMessage && (
                <div className={`mb-4 p-3 rounded-md text-sm ${scanMessage.includes('Error') ? 'bg-red-50 border border-red-200 text-red-800' : 'bg-blue-50 border border-blue-200 text-blue-800'}`}>
                  <div className="flex items-start">
                    {scanMessage.includes('Error') ? (
                      <svg className="h-5 w-5 text-red-400 mr-2" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                      </svg>
                    ) : (
                      <svg className="h-5 w-5 text-blue-400 mr-2" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                      </svg>
                    )}
                    <div>
                      {scanMessage}
                      {scanMessage.includes('Error') && (
                        <div className="mt-2 text-xs text-red-600">
                          Try again in a few moments or check the domain name for typos.
                        </div>
                      )}
                    </div>
                  </div>
                  {scanningVt && (
                    <div className="mt-3">
                      <div className="w-full bg-gray-200 rounded-full h-2.5 mb-1">
                        <div 
                          className="bg-blue-600 h-2.5 rounded-full transition-all duration-300" 
                          style={{ width: `${scanProgress}%` }}
                        ></div>
                      </div>
                      <div className="text-xs text-gray-600 text-right">{scanProgress}% complete</div>
                    </div>
                  )}
                </div>
              )}
              
              {analysis.virustotal_data ? (
                <div className="space-y-4">
                  {/* Analysis Stats */}
                  <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
                    <div className={`bg-gray-50 rounded-lg p-4 text-center ${analysis.virustotal_data.malicious_count > 0 ? 'border-l-4 border-red-500' : ''}`}>
                      <dt className="text-sm font-medium text-gray-500">Malicious</dt>
                      <dd className="mt-1 text-2xl font-semibold text-red-600">
                        {analysis.virustotal_data.malicious_count}
                      </dd>
                    </div>
                    <div className={`bg-gray-50 rounded-lg p-4 text-center ${analysis.virustotal_data.suspicious_count > 0 ? 'border-l-4 border-yellow-500' : ''}`}>
                      <dt className="text-sm font-medium text-gray-500">Suspicious</dt>
                      <dd className="mt-1 text-2xl font-semibold text-yellow-600">
                        {analysis.virustotal_data.suspicious_count}
                      </dd>
                    </div>
                    <div className="bg-gray-50 rounded-lg p-4 text-center border-l-4 border-green-500">
                      <dt className="text-sm font-medium text-gray-500">Harmless</dt>
                      <dd className="mt-1 text-2xl font-semibold text-green-600">
                        {analysis.virustotal_data.harmless_count}
                      </dd>
                    </div>
                    <div className="bg-gray-50 rounded-lg p-4 text-center">
                      <dt className="text-sm font-medium text-gray-500">Total Engines</dt>
                      <dd className="mt-1 text-2xl font-semibold text-gray-900">
                        {analysis.virustotal_data.total_engines}
                      </dd>
                    </div>
                  </div>
                  
                  {/* Detection Progress Bar */}
                  <div className="mb-4">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm font-medium text-gray-700">Detection Rate</span>
                      <span className="text-sm font-medium text-gray-700">
                        {analysis.virustotal_data.malicious_count + analysis.virustotal_data.suspicious_count}/{analysis.virustotal_data.total_engines}
                      </span>
                    </div>
                    <div className="w-full bg-gray-200 rounded-full h-2.5 overflow-hidden">
                      <div className="flex h-full">
                        <div 
                          className="bg-red-600 h-full" 
                          style={{ width: `${(analysis.virustotal_data.malicious_count / analysis.virustotal_data.total_engines) * 100}%` }}
                        ></div>
                        <div 
                          className="bg-yellow-500 h-full" 
                          style={{ width: `${(analysis.virustotal_data.suspicious_count / analysis.virustotal_data.total_engines) * 100}%` }}
                        ></div>
                      </div>
                    </div>
                  </div>
                  
                  {/* Last Analysis Date */}
                  {analysis.virustotal_data.last_analysis_date && (
                    <div className="text-sm text-gray-600 mb-4 border-t border-b border-gray-100 py-2">
                      <strong>Last scanned:</strong> {new Date(analysis.virustotal_data.last_analysis_date * 1000).toLocaleString()}
                    </div>
                  )}
                  
                  {/* Detections */}
                  {analysis.virustotal_data.detections && analysis.virustotal_data.detections.length > 0 && (
                    <div>
                      <h3 className="text-lg font-medium text-gray-800 mb-3">Detection Details</h3>
                      <div className="overflow-x-auto border rounded-lg">
                        <table className="min-w-full divide-y divide-gray-200">
                          <thead className="bg-gray-100">
                            <tr>
                              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-600 uppercase tracking-wider">ENGINE</th>
                              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-600 uppercase tracking-wider">CATEGORY</th>
                              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-600 uppercase tracking-wider">RESULT</th>
                            </tr>
                          </thead>
                          <tbody className="bg-white divide-y divide-gray-200">
                            {analysis.virustotal_data.detections.map((detection, index) => (
                              <tr key={index} className={detection.category === 'malicious' ? 'bg-red-50' : detection.category === 'suspicious' ? 'bg-yellow-50' : 'bg-white'}>
                                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{detection.engine}</td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm">
                                  <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${detection.category === 'malicious' ? 'bg-red-100 text-red-800' : detection.category === 'suspicious' ? 'bg-yellow-100 text-yellow-800' : 'bg-green-100 text-green-800'}`}>
                                    {detection.category}
                                  </span>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-blue-600">{detection.result}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-gray-500 text-sm">No VirusTotal data available</p>
              )}
            </div>
          </div>

          {/* Sidebar - right 1/3 */}
          <div className="space-y-6">
            {/* Risk Assessment */}
            <div className="card">
              <h2 className="text-xl font-semibold mb-4">Risk Assessment</h2>
              <div className="mb-4">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium text-gray-700">Risk Score</span>
                  <span className="text-sm font-medium text-gray-700">{analysis.risk_score}/100</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2.5">
                  <div 
                    className={`h-2.5 rounded-full ${
                      analysis.risk_score >= 80 ? 'bg-red-600' : 
                      analysis.risk_score >= 50 ? 'bg-yellow-500' : 
                      analysis.risk_score >= 20 ? 'bg-blue-500' : 'bg-green-500'
                    }`}
                    style={{ width: `${analysis.risk_score}%` }}
                  ></div>
                </div>
              </div>
              
              {/* Risk Assessment Summary */}
              <div className="mb-4 p-4 bg-gray-50 rounded-lg border-l-4 border-gray-300">
                <h3 className="text-sm font-medium text-gray-700 mb-2">Risk Assessment Summary</h3>
                <p className="text-sm text-gray-700">
                  {analysis.risk_summary || 
                    (analysis.risk_score >= 80 ? 'High risk domain with multiple security concerns' :
                     analysis.risk_score >= 50 ? 'Medium risk domain with some suspicious indicators' :
                     analysis.risk_score >= 20 ? 'Low risk domain with minimal concerns' :
                     'Minimal risk domain with no detected security issues')}
                </p>
              </div>
              
              {/* Security Vendor Information */}
              <div className="mb-4">
                <h3 className="text-sm font-medium text-gray-700 mb-2">Security Vendor Assessment</h3>
                <div className="p-4 bg-gray-50 rounded-lg">
                  {analysis.virustotal_data && analysis.virustotal_data.malicious_count > 0 ? (
                    <div className="flex items-start">
                      <ShieldExclamationIcon className="h-5 w-5 text-red-500 mr-2 flex-shrink-0" />
                      <span className="text-sm text-gray-700">
                        Domain flagged by {analysis.virustotal_data.malicious_count} security vendors
                      </span>
                    </div>
                  ) : (
                    <div className="flex items-start">
                      <CheckCircleIcon className="h-5 w-5 text-green-500 mr-2 flex-shrink-0" />
                      <span className="text-sm text-gray-700">
                        No security vendors have flagged this domain as malicious
                      </span>
                    </div>
                  )}
                  
                  {/* Domain Age Information */}
                  <div className="mt-3 flex items-start">
                    <CalendarIcon className="h-5 w-5 text-blue-500 mr-2 flex-shrink-0" />
                    <span className="text-sm text-gray-700">
                      {analysis.whois_data && analysis.whois_data.domain_age ? 
                        `Domain age: ${analysis.whois_data.domain_age}` : 
                        'Domain age: Unknown'}
                    </span>
                  </div>
                  
                  {/* SSL Certificate Information */}
                  <div className="mt-3 flex items-start">
                    <LockClosedIcon className="h-5 w-5 text-blue-500 mr-2 flex-shrink-0" />
                    <span className="text-sm text-gray-700">
                      {analysis.ssl_data && analysis.ssl_data.is_valid ? 
                        'Valid SSL certificate detected' : 
                        'No valid SSL certificate detected'}
                    </span>
                  </div>
                </div>
              </div>
              
              {/* Risk Factors */}
              {analysis.risk_factors && analysis.risk_factors.length > 0 ? (
                <div>
                  <h3 className="text-sm font-medium text-gray-700 mb-2">Risk Factors</h3>
                  <ul className="space-y-1">
                    {analysis.risk_factors.map((factor, index) => (
                      <li key={index} className="flex items-start">
                        <ShieldExclamationIcon className="h-5 w-5 text-red-500 mr-2 flex-shrink-0" />
                        <span className="text-sm text-gray-700">
                          {typeof factor === 'string' ? factor : 
                           factor && typeof factor === 'object' && factor.description ? 
                           factor.description : 
                           JSON.stringify(factor)}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : (
                <div>
                  <h3 className="text-sm font-medium text-gray-700 mb-2">Risk Factors</h3>
                  <div className="flex items-start">
                    <CheckCircleIcon className="h-5 w-5 text-green-500 mr-2 flex-shrink-0" />
                    <span className="text-sm text-gray-700">
                      No specific risk factors detected for this domain
                    </span>
                  </div>
                </div>
              )}
            </div>
            
            {/* ChatGPT Impact Analysis */}
            <div className="card mb-6">
              <h2 className="text-xl font-semibold mb-4 flex items-center">
                <span>ChatGPT Impact Analysis</span>
              </h2>
              
              {loadingChatgpt ? (
                <div className="flex items-center justify-center py-4">
                  <ArrowPathIcon className="h-5 w-5 text-primary-600 animate-spin mr-2" />
                  <span>Generating AI analysis...</span>
                </div>
              ) : chatgptError ? (
                <div className="py-4 border border-gray-200 rounded-lg p-4">
                  <div className="flex items-start mb-3">
                    <ExclamationTriangleIcon className="h-5 w-5 text-amber-500 mr-2 flex-shrink-0" />
                    <div>
                      <h3 className="text-sm font-medium text-gray-900">AI Analysis Unavailable</h3>
                      <p className="text-sm text-gray-600 mt-1">The ChatGPT impact analysis is currently unavailable. This may be due to API configuration issues.</p>
                    </div>
                  </div>
                  <p className="text-xs text-gray-500 mb-3">Error details: {chatgptError}</p>
                  <div className="flex justify-between items-center">
                    <button
                      onClick={fetchChatGPTImpact}
                      className="inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded-md shadow-sm text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
                    >
                      <ArrowPathIcon className="h-4 w-4 mr-1" />
                      Retry Analysis
                    </button>
                    <span className="text-xs text-gray-500">You can continue using other features while this is unavailable.</span>
                  </div>
                </div>
              ) : chatgptAnalysis ? (
                <div className="space-y-4">
                  {chatgptAnalysis.summary && (
                    <div className="bg-blue-50 p-3 rounded-lg border border-blue-100">
                      <span className="font-medium text-blue-800">Summary:</span>
                      <div className="text-sm text-blue-700 mt-1">{chatgptAnalysis.summary}</div>
                    </div>
                  )}
                  
                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-gray-50 p-3 rounded-lg border border-gray-200">
                      <div className="text-center mb-1 text-gray-600 text-xs uppercase font-semibold">Disruption Impact</div>
                      <div className="flex justify-center">
                        <span className={`text-2xl font-bold ${chatgptAnalysis.disruption_impact_score >= 7 ? 'text-red-600' : chatgptAnalysis.disruption_impact_score >= 4 ? 'text-yellow-600' : 'text-blue-600'}`}>
                          {chatgptAnalysis.disruption_impact_score ?? 'N/A'}
                        </span>
                        <span className="text-sm text-gray-500 self-end ml-1">/10</span>
                      </div>
                    </div>
                    
                    <div className="bg-gray-50 p-3 rounded-lg border border-gray-200">
                      <div className="text-center mb-1 text-gray-600 text-xs uppercase font-semibold">News Impact</div>
                      <div className="flex justify-center">
                        <span className={`text-2xl font-bold ${chatgptAnalysis.news_impact_score >= 7 ? 'text-purple-600' : chatgptAnalysis.news_impact_score >= 4 ? 'text-indigo-600' : 'text-gray-600'}`}>
                          {chatgptAnalysis.news_impact_score ?? 'N/A'}
                        </span>
                        <span className="text-sm text-gray-500 self-end ml-1">/10</span>
                      </div>
                    </div>
                  </div>
                  
                  <div>
                    <span className="font-medium">Analysis:</span>
                    <div className="text-sm text-gray-700 whitespace-pre-line mt-2 bg-white p-3 rounded-lg border border-gray-200">
                      {chatgptAnalysis.rationale || chatgptAnalysis.summary || 'No detailed rationale provided.'}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-center py-4">
                  <p className="text-gray-500">AI analysis not available</p>
                  <button
                    onClick={fetchChatGPTImpact}
                    className="mt-2 inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded-md shadow-sm text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
                  >
                    Generate Analysis
                  </button>
                </div>
              )}
            </div>

            {/* Actions */}
            <div className="card">
              <h2 className="text-xl font-semibold mb-4">Actions</h2>
              <div className="space-y-4">
                <button
                  type="button"
                  onClick={handleGenerateReport}
                  disabled={generatingReport}
                  className="w-full btn-primary flex justify-center items-center"
                >
                  {generatingReport ? (
                    <>
                      <ArrowPathIcon className="h-5 w-5 mr-2 animate-spin" />
                      Generating Report...
                    </>
                  ) : (
                    <>
                      <DocumentArrowDownIcon className="h-5 w-5 mr-2" />
                      Generate PDF Report
                    </>
                  )}
                </button>
                
                <Link to="/upload" className="w-full btn-secondary flex justify-center items-center">
                  <GlobeAltIcon className="h-5 w-5 mr-2" />
                  Analyze Another Domain
                </Link>
              </div>
            </div>
          </div>
        </div>
      </motion.div>
    </div>
  );
}
